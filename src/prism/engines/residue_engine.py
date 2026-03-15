"""System residue scanner (R1-R10). Detects leftover files, configs, and persistence."""
import os
import platform
import re
import stat
import subprocess
from pathlib import Path
from typing import Optional

from ..models import Finding, Severity, Layer


AGENT_KEYWORDS = ["openclaw", "claude", "agent", "mcp", "skill", "anthropic", "cursor"]

KNOWN_RESIDUE_DIRS = [
    "openclaw", "claude-code", "claude", "cursor", "mcp", "agent-reach",
    "cline", "continue", "aider", "copilot",
]

SHELL_CONFIGS = {
    "critical": ["~/.zshenv"],
    "high": ["~/.bashrc", "~/.zshrc", "~/.profile", "~/.bash_profile",
             "~/.config/fish/config.fish"],
    "medium": ["~/.bash_logout", "~/.zlogout"],
}

SYSTEM_SHELL_CONFIGS = ["/etc/profile.d/"]


class ResidueEngine:
    """Scans the local system for agent/skill residue."""

    def scan_system(self) -> list[Finding]:
        findings = []
        is_mac = platform.system() == "Darwin"
        is_linux = platform.system() == "Linux"

        # R1: crontab
        findings.extend(self._check_crontab())

        # R2: LaunchAgents (macOS)
        if is_mac:
            findings.extend(self._check_launch_agents())

        # R3: systemd (Linux)
        if is_linux:
            findings.extend(self._check_systemd())

        # R4: macOS advanced persistence
        if is_mac:
            findings.extend(self._check_macos_advanced())

        # R5: Shell config pollution
        findings.extend(self._check_shell_configs())

        # R6: Git hooks
        findings.extend(self._check_git_hooks())

        # R7: Residue files/caches
        findings.extend(self._check_residue_dirs())

        # R8: Credential files + permissions
        findings.extend(self._check_credentials())

        # R9: Network config
        findings.extend(self._check_network_config())

        # R10: Global packages
        findings.extend(self._check_global_packages())

        return findings

    def _check_crontab(self) -> list[Finding]:
        """R1: Check crontab for suspicious entries."""
        findings = []
        try:
            result = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if any(kw in line.lower() for kw in AGENT_KEYWORDS):
                        findings.append(Finding(
                            rule_id="R1",
                            engine="residue",
                            layer=Layer.RESIDUE,
                            severity=Severity.HIGH,
                            confidence=0.8,
                            title="Suspicious crontab entry",
                            description="Crontab contains agent-related entry",
                            code_snippet=line[:120],
                            tags=["persistence", "crontab"],
                            remediation="Remove with: crontab -e",
                        ))
                    elif re.search(r"(/tmp/|/dev/shm/|\.cache/)", line):
                        findings.append(Finding(
                            rule_id="R1",
                            engine="residue",
                            layer=Layer.RESIDUE,
                            severity=Severity.MEDIUM,
                            confidence=0.6,
                            title="Crontab entry runs from temporary directory",
                            description="Crontab entry references tmp/cache path",
                            code_snippet=line[:120],
                            tags=["persistence", "crontab"],
                            remediation="Verify if this crontab entry is expected.",
                        ))
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
        return findings

    def _check_launch_agents(self) -> list[Finding]:
        """R2: Check LaunchAgents for suspicious plists."""
        findings = []
        la_dirs = [
            Path.home() / "Library" / "LaunchAgents",
            Path("/Library/LaunchDaemons"),
        ]
        for la_dir in la_dirs:
            if not la_dir.exists():
                continue
            for plist in la_dir.glob("*.plist"):
                name = plist.stem.lower()
                if any(kw in name for kw in AGENT_KEYWORDS):
                    findings.append(Finding(
                        rule_id="R2",
                        engine="residue",
                        layer=Layer.RESIDUE,
                        severity=Severity.HIGH,
                        confidence=0.85,
                        title=f"Suspicious LaunchAgent: {plist.name}",
                        description="LaunchAgent plist matches agent keyword",
                        file_path=str(plist),
                        tags=["persistence", "launch_agent"],
                        remediation=f"Remove: launchctl unload {plist} && rm {plist}",
                    ))
        return findings

    def _check_systemd(self) -> list[Finding]:
        """R3: Check systemd services."""
        findings = []
        sd_dirs = [
            Path("/etc/systemd/system"),
            Path.home() / ".config" / "systemd" / "user",
        ]
        for sd_dir in sd_dirs:
            if not sd_dir.exists():
                continue
            for svc in sd_dir.glob("*.service"):
                name = svc.stem.lower()
                if any(kw in name for kw in AGENT_KEYWORDS):
                    findings.append(Finding(
                        rule_id="R3",
                        engine="residue",
                        layer=Layer.RESIDUE,
                        severity=Severity.HIGH,
                        confidence=0.85,
                        title=f"Suspicious systemd service: {svc.name}",
                        description="systemd service matches agent keyword",
                        file_path=str(svc),
                        tags=["persistence", "systemd"],
                        remediation=f"Remove: systemctl disable {svc.stem} && rm {svc}",
                    ))
        return findings

    def _check_macos_advanced(self) -> list[Finding]:
        """R4: macOS advanced persistence points."""
        findings = []
        sudoers_d = Path("/etc/sudoers.d")
        if sudoers_d.exists():
            for f in sudoers_d.iterdir():
                if f.is_file() and any(kw in f.name.lower() for kw in AGENT_KEYWORDS):
                    findings.append(Finding(
                        rule_id="R4",
                        engine="residue",
                        layer=Layer.RESIDUE,
                        severity=Severity.CRITICAL,
                        confidence=0.95,
                        title=f"Suspicious sudoers modification: {f.name}",
                        description="File in /etc/sudoers.d/ matches agent keyword — may grant passwordless root",
                        file_path=str(f),
                        tags=["persistence", "privilege_escalation"],
                        remediation=f"IMMEDIATELY review and remove: sudo rm {f}",
                    ))
        return findings

    def _check_shell_configs(self) -> list[Finding]:
        """R5: Check shell configuration files for injected content."""
        findings = []
        suspicious_patterns = [
            (r"export\s+PATH=.*(?:agent|openclaw|skill|mcp)", "PATH modification"),
            (r"source\s+.*(?:agent|openclaw|skill|mcp)", "source injection"),
            (r"alias\s+.*(?:agent|openclaw|skill|mcp)", "alias override"),
            (r"eval\s+.*(?:curl|wget|http)", "eval with download"),
        ]

        for severity_name, paths in SHELL_CONFIGS.items():
            severity = {"critical": Severity.HIGH, "high": Severity.MEDIUM, "medium": Severity.LOW}[severity_name]
            for path_str in paths:
                path = Path(os.path.expanduser(path_str))
                if not path.exists():
                    continue
                try:
                    content = path.read_text(errors="replace")
                    for line_num, line in enumerate(content.splitlines(), 1):
                        for pattern, desc in suspicious_patterns:
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append(Finding(
                                    rule_id="R5",
                                    engine="residue",
                                    layer=Layer.RESIDUE,
                                    severity=severity,
                                    confidence=0.7,
                                    title=f"Shell config modification: {desc}",
                                    description=f"Suspicious content in {path_str}",
                                    file_path=str(path),
                                    line=line_num,
                                    code_snippet=line.strip()[:120],
                                    tags=["persistence", "shell_config"],
                                    remediation=f"Review and remove this line from {path_str}",
                                ))
                except OSError:
                    pass
        return findings

    def _check_git_hooks(self) -> list[Finding]:
        """R6: Check for non-standard git hooks in home directory projects."""
        findings = []
        # Search common project locations
        search_roots = [
            Path.home() / "Projects",
            Path.home() / "projects",
            Path.home() / "Developer",
            Path.home() / "dev",
            Path.home() / "code",
            Path.home() / "repos",
            Path.home() / "workspace",
            Path.home() / "Desktop",
            Path.cwd(),
        ]

        seen_hooks_dirs = set()
        STANDARD_HOOKS = {
            "applypatch-msg.sample", "commit-msg.sample", "fsmonitor-watchman.sample",
            "post-update.sample", "pre-applypatch.sample", "pre-commit.sample",
            "pre-merge-commit.sample", "pre-push.sample", "pre-rebase.sample",
            "pre-receive.sample", "prepare-commit-msg.sample", "push-to-checkout.sample",
            "update.sample",
        }

        for root in search_roots:
            if not root.exists():
                continue
            # Only go 3 levels deep to avoid scanning too much
            for hooks_dir in root.glob("**/.git/hooks"):
                if len(hooks_dir.parts) - len(root.parts) > 5:
                    continue
                hooks_str = str(hooks_dir)
                if hooks_str in seen_hooks_dirs:
                    continue
                seen_hooks_dirs.add(hooks_str)

                try:
                    for hook_file in hooks_dir.iterdir():
                        if not hook_file.is_file():
                            continue
                        if hook_file.name in STANDARD_HOOKS:
                            continue
                        if hook_file.name.endswith(".sample"):
                            continue

                        # Check if it's executable
                        if not os.access(hook_file, os.X_OK):
                            continue

                        # Read content and check for agent keywords
                        try:
                            content = hook_file.read_text(errors="replace")[:2000]
                            is_agent_related = any(kw in content.lower() for kw in AGENT_KEYWORDS)
                        except OSError:
                            is_agent_related = False

                        if is_agent_related:
                            findings.append(Finding(
                                rule_id="R6",
                                engine="residue",
                                layer=Layer.RESIDUE,
                                severity=Severity.MEDIUM,
                                confidence=0.7,
                                title=f"Agent-related git hook: {hook_file.name}",
                                description=f"Git hook contains agent-related keywords",
                                file_path=str(hook_file),
                                tags=["persistence", "git_hook"],
                                remediation=f"Review and remove if no longer needed: rm {hook_file}",
                            ))
                except OSError:
                    pass

        return findings

    def _check_residue_dirs(self) -> list[Finding]:
        """R7: Check for residual cache/config directories."""
        findings = []
        search_roots = [
            Path.home() / ".config",
            Path.home() / ".cache",
            Path.home() / ".local" / "share",
            Path.home() / ".local" / "state",
        ]
        for root in search_roots:
            if not root.exists():
                continue
            for item in root.iterdir():
                if item.is_dir() and item.name.lower() in KNOWN_RESIDUE_DIRS:
                    try:
                        size = sum(f.stat().st_size for f in item.rglob("*") if f.is_file())
                        size_mb = size / (1024 * 1024)
                    except OSError:
                        size_mb = 0
                    findings.append(Finding(
                        rule_id="R7",
                        engine="residue",
                        layer=Layer.RESIDUE,
                        severity=Severity.LOW,
                        confidence=0.9,
                        title=f"Residual directory: {item.name} ({size_mb:.1f} MB)",
                        description=f"Agent-related directory found at {item}",
                        file_path=str(item),
                        tags=["residue", "cache"],
                        remediation=f"If no longer needed: rm -rf {item}",
                    ))
        return findings

    def _check_credentials(self) -> list[Finding]:
        """R8: Check for residual credential files and their permissions."""
        findings = []
        cred_paths = [
            Path.home() / ".openclaw" / "credentials.json",
            Path.home() / ".openclaw" / "config.json",
            Path.home() / ".claude" / "credentials.json",
            Path.home() / ".config" / "claude-code" / "auth.json",
            Path.home() / ".netrc",
        ]
        for cred_path in cred_paths:
            if not cred_path.exists():
                continue
            try:
                mode = cred_path.stat().st_mode
                is_world_readable = mode & stat.S_IROTH
                severity = Severity.HIGH if is_world_readable else Severity.MEDIUM
                perms = oct(mode)[-3:]

                findings.append(Finding(
                    rule_id="R8",
                    engine="residue",
                    layer=Layer.RESIDUE,
                    severity=severity,
                    confidence=0.9,
                    title=f"Residual credentials: {cred_path.name} (perms: {perms})",
                    description=f"Credential file exists{' and is world-readable' if is_world_readable else ''}",
                    file_path=str(cred_path),
                    tags=["credential", "residue"],
                    remediation=f"Revoke tokens inside, then: chmod 600 {cred_path} or rm {cred_path}",
                ))
            except OSError:
                pass
        return findings

    def _check_network_config(self) -> list[Finding]:
        """R9: Check /etc/hosts for non-standard entries."""
        findings = []
        hosts_file = Path("/etc/hosts")
        if hosts_file.exists():
            try:
                standard_entries = {"localhost", "broadcasthost", "ip6-localhost", "ip6-loopback"}
                for line_num, line in enumerate(hosts_file.read_text().splitlines(), 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        hostname = parts[1].lower()
                        if hostname not in standard_entries and any(kw in hostname for kw in AGENT_KEYWORDS):
                            findings.append(Finding(
                                rule_id="R9",
                                engine="residue",
                                layer=Layer.RESIDUE,
                                severity=Severity.MEDIUM,
                                confidence=0.7,
                                title=f"Non-standard /etc/hosts entry: {hostname}",
                                description="Agent-related hostname in /etc/hosts",
                                file_path="/etc/hosts",
                                line=line_num,
                                code_snippet=line[:120],
                                tags=["network_config", "residue"],
                                remediation="Remove this entry if no longer needed.",
                            ))
            except OSError:
                pass
        return findings

    def _check_global_packages(self) -> list[Finding]:
        """R10: Check for globally installed agent-related packages."""
        findings = []

        # pip
        try:
            result = subprocess.run(
                ["pip3", "list", "--format=json", "--user"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                import json
                packages = json.loads(result.stdout)
                for pkg in packages:
                    name = pkg.get("name", "").lower()
                    if any(kw in name for kw in AGENT_KEYWORDS):
                        findings.append(Finding(
                            rule_id="R10",
                            engine="residue",
                            layer=Layer.RESIDUE,
                            severity=Severity.LOW,
                            confidence=0.9,
                            title=f"Residual pip package: {pkg['name']}=={pkg.get('version', '?')}",
                            description="Agent-related package still installed",
                            tags=["residue", "global_package"],
                            remediation=f"If no longer needed: pip uninstall {pkg['name']}",
                        ))
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError, json.JSONDecodeError):
            pass

        return findings
