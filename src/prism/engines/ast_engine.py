"""
AST-based static analysis engine for Python source files.
Implements detection rules S1-S14.
"""
import ast
import os
import re
from pathlib import Path
from typing import Optional

from ..models import Finding, Severity, Layer
from .taint import TaintContext, TaintLevel, TaintInfo, _get_call_name, _get_attribute_string


# Sensitive file paths for S2/S3
SENSITIVE_READ_PATHS = {
    "critical": [
        "~/.ssh/id_rsa", "~/.ssh/id_ed25519", "~/.ssh/id_dsa", "~/.ssh/id_ecdsa",
        "~/.aws/credentials", "~/.aws/config",
    ],
    "high": [
        "~/.config/gcloud/credentials.db", "~/.azure/credentials",
        "~/.kube/config", "~/.docker/config.json",
        "~/.npmrc", "~/.pypirc", "~/.netrc", "~/.env", ".env",
    ],
    "medium": [
        "~/.gitconfig", "~/.bash_history", "~/.zsh_history",
        "/etc/passwd", "/etc/shadow",
    ],
}

SENSITIVE_WRITE_PATHS_CRITICAL = [
    "~/.zshenv", "~/.bashrc", "~/.zshrc", "~/.profile", "~/.bash_profile",
    "/etc/hosts", "/etc/sudoers", "~/.ssh/authorized_keys",
    "~/Library/LaunchAgents/", "/Library/LaunchDaemons/",
    "/etc/systemd/system/", "/etc/profile.d/", "/etc/sudoers.d/",
]

# Internal network ranges for S9 SSRF
SSRF_BLACKLIST = [
    "169.254.169.254",  # cloud metadata
    "127.0.0.1", "localhost", "0.0.0.0",
]
SSRF_PRIVATE_PREFIXES = ["10.", "172.16.", "172.17.", "172.18.", "172.19.",
                          "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                          "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                          "172.30.", "172.31.", "192.168."]

# Shell execution sinks for S1
SHELL_SINKS = {
    "subprocess.run", "subprocess.call", "subprocess.Popen",
    "subprocess.check_output", "subprocess.check_call",
    "os.system", "os.popen", "os.execl", "os.execle", "os.execlp",
    "os.execv", "os.execvp", "os.execvpe",
}

# Dangerous eval/exec for S6
DYNAMIC_EXEC_SINKS = {"eval", "exec", "compile", "execfile"}

# Dynamic import for S7
DYNAMIC_IMPORT_FUNCS = {"importlib.import_module", "__import__"}

# Network sinks for S4/S8
NETWORK_SINKS = {
    "requests.post", "requests.put", "requests.patch", "requests.delete",
    "requests.get", "requests.head", "requests.options",
    "httpx.post", "httpx.put", "httpx.get",
    "urllib.request.urlopen",
    "socket.send", "socket.sendall", "socket.sendto",
}

NETWORK_SEND_SINKS = {
    "requests.post", "requests.put", "requests.patch",
    "httpx.post", "httpx.put",
    "socket.send", "socket.sendall", "socket.sendto",
}

# Unsafe deserialization for S12
DESER_SINKS = {
    "pickle.loads", "pickle.load", "cPickle.loads", "cPickle.load",
    "yaml.load", "yaml.unsafe_load",
    "marshal.loads", "marshal.load",
    "shelve.open",
}

# Persistence paths for S13
PERSISTENCE_PATHS = [
    "LaunchAgents", "LaunchDaemons", "launchctl",
    "systemctl", "systemd", ".service",
    "crontab", "/etc/cron",
    ".bashrc", ".zshrc", ".zshenv", ".profile", ".bash_profile",
    "autostart",
]

# System config paths for S14
SYSTEM_CONFIG_PATHS = [
    "/etc/hosts", "/etc/sudoers", "/etc/resolv.conf",
    "iptables", "ufw", "networksetup",
    "security add-trusted-cert",
]


def _get_code_snippet(source_lines: list[str], line: int, context: int = 1) -> str:
    """Extract a code snippet around the given line number."""
    start = max(0, line - 1 - context)
    end = min(len(source_lines), line + context)
    return "\n".join(source_lines[start:end]).strip()


def _check_shell_true(node: ast.Call) -> bool:
    """Check if a function call has shell=True keyword argument."""
    for kw in node.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _extract_string_value(node: ast.expr) -> Optional[str]:
    """Try to extract a constant string value from an AST node."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _string_contains_pattern(value: str, patterns: list[str]) -> bool:
    """Check if string contains any of the given patterns."""
    value_lower = value.lower()
    return any(p.lower() in value_lower for p in patterns)


class ASTEngine:
    """AST-based analysis engine implementing rules S1-S14."""

    def scan_file(self, file_path: str, project_root: str) -> list[Finding]:
        """Scan a single Python file and return findings."""
        if not file_path.endswith(".py"):
            return []

        try:
            source = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeDecodeError):
            return []

        try:
            tree = ast.parse(source, filename=file_path)
        except SyntaxError:
            return []

        source_lines = source.splitlines()
        rel_path = os.path.relpath(file_path, project_root)
        ctx = TaintContext()
        findings: list[Finding] = []

        # First pass: build taint map from assignments
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        taint = ctx.resolve_node(node.value)
                        ctx.set_taint(target.id, taint)
            elif isinstance(node, ast.AnnAssign) and node.value and isinstance(node.target, ast.Name):
                taint = ctx.resolve_node(node.value)
                ctx.set_taint(node.target.id, taint)

        # Second pass: check for dangerous sinks
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func_name = _get_call_name(node)
            if not func_name:
                continue

            # S1: Shell command execution
            if func_name in SHELL_SINKS or any(func_name.endswith("." + s.split(".")[-1]) for s in SHELL_SINKS):
                findings.extend(self._check_s1(node, func_name, ctx, rel_path, source_lines))

            # S4: Network outbound — require known module prefix to avoid dict.get() FPs
            _net_prefixes = ("requests.", "httpx.", "urllib.", "aiohttp.", "http.client.", "socket.", "grpc.")
            if func_name in NETWORK_SINKS or (
                any(func_name.endswith("." + s.split(".")[-1]) for s in NETWORK_SINKS)
                and any(func_name.startswith(p) or ("." in func_name and func_name.rsplit(".", 1)[0].endswith(
                    ("session", "client", "conn", "connection", "sock", "socket", "response"))) for p in _net_prefixes)
            ):
                findings.extend(self._check_s4(node, func_name, ctx, rel_path, source_lines))

            # S6: Dynamic code execution — exclude re.compile() which is regex, not code exec
            if (func_name in DYNAMIC_EXEC_SINKS or func_name.split(".")[-1] in DYNAMIC_EXEC_SINKS) and func_name != "re.compile":
                findings.extend(self._check_s6(node, func_name, ctx, rel_path, source_lines))

            # S7: Dynamic import
            if func_name in DYNAMIC_IMPORT_FUNCS or func_name.endswith("import_module"):
                findings.extend(self._check_s7(node, func_name, ctx, rel_path, source_lines))

            # S12: Unsafe deserialization (exclude safe variants)
            _safe_deser = {"json.loads", "json.load", "json.dumps", "json.dump"}
            _safe_open_prefixes = ("gzip.", "zipfile.", "tarfile.", "io.", "codecs.",
                                   "builtins.", "tempfile.", "pdfplumber.", "wave.", "aifc.")
            if func_name not in _safe_deser and (
                func_name in DESER_SINKS or any(func_name.endswith("." + s.split(".")[-1]) for s in DESER_SINKS)
            ):
                # Skip safe modules
                if not func_name.startswith("json.") and not any(func_name.startswith(p) for p in _safe_open_prefixes):
                    findings.extend(self._check_s12(node, func_name, ctx, rel_path, source_lines))

            # S2/S3: File operations
            if func_name in ("open", "builtins.open") or func_name.endswith(".open"):
                findings.extend(self._check_file_ops(node, ctx, rel_path, source_lines))

            # S5: Environment variable reads (standalone check)
            if func_name in ("os.getenv", "os.environ.get"):
                findings.extend(self._check_s5(node, func_name, ctx, rel_path, source_lines))

        # Check for S8 (data exfiltration) by analyzing combined taint flows
        findings.extend(self._check_s8(tree, ctx, rel_path, source_lines))

        # Check for S10 (download-and-execute) patterns in string literals
        findings.extend(self._check_s10_strings(tree, rel_path, source_lines))

        # Check for S13/S14 by scanning string literals for persistence/system paths
        findings.extend(self._check_persistence_and_sysconfig(tree, rel_path, source_lines))

        return findings

    def _check_s1(self, node: ast.Call, func_name: str, ctx: TaintContext,
                   rel_path: str, source_lines: list[str]) -> list[Finding]:
        """S1: Shell command execution."""
        findings = []
        has_shell_true = _check_shell_true(node)

        # Determine severity based on argument taint
        arg_taint = TaintInfo(level=TaintLevel.UNKNOWN)
        if node.args:
            arg_taint = ctx.resolve_node(node.args[0])
            if arg_taint.level == TaintLevel.LITERAL:
                severity = Severity.INFO if not has_shell_true else Severity.MEDIUM
                evidence = "Constant command argument"
            elif arg_taint.level == TaintLevel.EXTERNAL:
                severity = Severity.CRITICAL
                evidence = f"Unsanitized input from {arg_taint.source_desc} flows to {func_name}()"
            else:
                severity = Severity.HIGH if has_shell_true else Severity.MEDIUM
                evidence = f"Variable argument (origin: {arg_taint.level.value})"
        else:
            severity = Severity.MEDIUM
            evidence = "No arguments detected"

        if severity == Severity.INFO:
            return []  # Don't report constant safe commands

        findings.append(Finding(
            rule_id="S1",
            engine="ast",
            layer=Layer.BEHAVIOR,
            severity=severity,
            confidence=0.9 if arg_taint.level != TaintLevel.UNKNOWN else 0.7,
            title="Shell command execution" + (" (shell=True)" if has_shell_true else ""),
            description=f"Code calls {func_name}() which can execute arbitrary system commands",
            file_path=rel_path,
            line=node.lineno,
            code_snippet=_get_code_snippet(source_lines, node.lineno),
            evidence=evidence,
            tags=["execution", "shell"],
            remediation="Use subprocess.run() with explicit argument list. Avoid shell=True. Never pass untrusted input.",
            references=["MITRE T1059.004"],
        ))
        return findings

    def _check_s4(self, node: ast.Call, func_name: str, ctx: TaintContext,
                   rel_path: str, source_lines: list[str]) -> list[Finding]:
        """S4: Network outbound + S9: SSRF detection."""
        findings = []

        # Extract URL argument
        url_node = node.args[0] if node.args else None
        url_str = _extract_string_value(url_node) if url_node else None

        if url_str:
            # S9: Check for SSRF blacklist
            for blacklisted in SSRF_BLACKLIST:
                if blacklisted in url_str:
                    findings.append(Finding(
                        rule_id="S9",
                        engine="ast",
                        layer=Layer.BEHAVIOR,
                        severity=Severity.CRITICAL,
                        confidence=0.95,
                        title="SSRF: Request targets internal/metadata service",
                        description=f"Network request targets {blacklisted} which is a cloud metadata or internal service",
                        file_path=rel_path,
                        line=node.lineno,
                        code_snippet=_get_code_snippet(source_lines, node.lineno),
                        evidence=f"URL contains blacklisted target: {blacklisted}",
                        tags=["network", "ssrf"],
                        remediation="Never allow requests to metadata endpoints or internal services.",
                        references=["MITRE T1552.005"],
                    ))
                    return findings

            for prefix in SSRF_PRIVATE_PREFIXES:
                if prefix in url_str:
                    findings.append(Finding(
                        rule_id="S9",
                        engine="ast",
                        layer=Layer.BEHAVIOR,
                        severity=Severity.HIGH,
                        confidence=0.85,
                        title="SSRF: Request targets private network",
                        description="Network request targets private IP range",
                        file_path=rel_path,
                        line=node.lineno,
                        code_snippet=_get_code_snippet(source_lines, node.lineno),
                        evidence=f"URL targets private network range: {prefix}*",
                        tags=["network", "ssrf"],
                        remediation="Verify this internal request is expected.",
                        references=["MITRE T1552.005"],
                    ))
                    return findings

            # S4: Regular outbound request with hardcoded URL
            severity = Severity.MEDIUM
            evidence = f"Hardcoded URL: {url_str[:80]}"
        elif url_node:
            # URL is a variable — higher risk
            url_taint = ctx.resolve_node(url_node)
            if url_taint.level == TaintLevel.EXTERNAL:
                # S9: SSRF with external-controlled URL
                findings.append(Finding(
                    rule_id="S9",
                    engine="ast",
                    layer=Layer.BEHAVIOR,
                    severity=Severity.HIGH,
                    confidence=0.85,
                    title="SSRF: Request URL controlled by external input",
                    description=f"Network request URL comes from external source ({url_taint.source_desc})",
                    file_path=rel_path,
                    line=node.lineno,
                    code_snippet=_get_code_snippet(source_lines, node.lineno),
                    evidence=f"URL from {url_taint.source_desc} → {func_name}()",
                    tags=["network", "ssrf"],
                    remediation="Validate and allowlist URLs before making requests.",
                    references=["MITRE T1552.005", "CWE-918"],
                ))
                return findings
            severity = Severity.MEDIUM
            evidence = f"Variable URL (taint: {url_taint.level.value})"
        else:
            severity = Severity.LOW
            evidence = "Network call detected"

        findings.append(Finding(
            rule_id="S4",
            engine="ast",
            layer=Layer.BEHAVIOR,
            severity=severity,
            confidence=0.8,
            title="Outbound network request",
            description=f"Code makes outbound network request via {func_name}()",
            file_path=rel_path,
            line=node.lineno,
            code_snippet=_get_code_snippet(source_lines, node.lineno),
            evidence=evidence,
            tags=["network"],
            remediation="Verify the request target is expected and trusted.",
            references=["MITRE T1071.001"],
        ))
        return findings

    def _check_s5(self, node: ast.Call, func_name: str, ctx: TaintContext,
                   rel_path: str, source_lines: list[str]) -> list[Finding]:
        """S5: Environment variable reads."""
        env_name = ""
        if node.args:
            env_name = _extract_string_value(node.args[0]) or ""

        # Skip non-sensitive env vars
        safe_vars = {"HOME", "PATH", "LANG", "SHELL", "USER", "TERM", "EDITOR",
                     "LC_ALL", "LC_CTYPE", "PYTHONPATH", "VIRTUAL_ENV", "PWD"}
        if env_name.upper() in safe_vars:
            return []

        sensitive_patterns = ["KEY", "SECRET", "TOKEN", "PASSWORD", "CREDENTIAL",
                             "API_KEY", "AWS_", "OPENAI_", "ANTHROPIC_", "DATABASE_URL"]
        is_sensitive = any(p in env_name.upper() for p in sensitive_patterns)

        return [Finding(
            rule_id="S5",
            engine="ast",
            layer=Layer.BEHAVIOR,
            severity=Severity.MEDIUM if is_sensitive else Severity.LOW,
            confidence=0.8,
            title=f"Reads environment variable{': ' + env_name if env_name else ''}",
            description=f"Code reads environment variable via {func_name}()",
            file_path=rel_path,
            line=node.lineno,
            code_snippet=_get_code_snippet(source_lines, node.lineno),
            evidence=f"Reads {'sensitive ' if is_sensitive else ''}env var: {env_name}",
            tags=["env_var", "credential_access"] if is_sensitive else ["env_var"],
            remediation="Ensure this variable is used only for its intended purpose." if is_sensitive else None,
        )]

    def _check_s6(self, node: ast.Call, func_name: str, ctx: TaintContext,
                   rel_path: str, source_lines: list[str]) -> list[Finding]:
        """S6: Dynamic code execution (eval/exec/compile)."""
        if not node.args:
            return []

        arg_taint = ctx.resolve_node(node.args[0])

        if arg_taint.level == TaintLevel.LITERAL:
            severity = Severity.MEDIUM
            evidence = "Constant argument (not recommended but predictable)"
        elif arg_taint.level == TaintLevel.EXTERNAL:
            severity = Severity.CRITICAL
            evidence = f"External input from {arg_taint.source_desc} flows to {func_name}()"
        else:
            severity = Severity.HIGH
            evidence = f"Variable argument (origin: {arg_taint.level.value})"

        return [Finding(
            rule_id="S6",
            engine="ast",
            layer=Layer.BEHAVIOR,
            severity=severity,
            confidence=0.9 if arg_taint.level != TaintLevel.UNKNOWN else 0.7,
            title=f"Dynamic code execution via {func_name}()",
            description=f"Code uses {func_name}() to execute dynamically constructed code",
            file_path=rel_path,
            line=node.lineno,
            code_snippet=_get_code_snippet(source_lines, node.lineno),
            evidence=evidence,
            tags=["execution", "dynamic"],
            remediation=f"Use ast.literal_eval() for safe evaluation. Avoid {func_name}() with untrusted input.",
            references=["MITRE T1059.006"],
        )]

    def _check_s7(self, node: ast.Call, func_name: str, ctx: TaintContext,
                   rel_path: str, source_lines: list[str]) -> list[Finding]:
        """S7: Dynamic import."""
        if not node.args:
            return []

        arg_taint = ctx.resolve_node(node.args[0])

        if arg_taint.level == TaintLevel.LITERAL:
            return []  # Static module name is fine

        severity = Severity.CRITICAL if arg_taint.level == TaintLevel.EXTERNAL else Severity.HIGH
        evidence = (f"Module name from {arg_taint.source_desc}" if arg_taint.level == TaintLevel.EXTERNAL
                    else f"Variable module name (origin: {arg_taint.level.value})")

        return [Finding(
            rule_id="S7",
            engine="ast",
            layer=Layer.BEHAVIOR,
            severity=severity,
            confidence=0.85,
            title="Dynamic module import with variable name",
            description=f"Code dynamically imports a module via {func_name}()",
            file_path=rel_path,
            line=node.lineno,
            code_snippet=_get_code_snippet(source_lines, node.lineno),
            evidence=evidence,
            tags=["execution", "import"],
            remediation="Use an allowlist of permitted module names.",
            references=["MITRE T1129"],
        )]

    def _check_s12(self, node: ast.Call, func_name: str, ctx: TaintContext,
                    rel_path: str, source_lines: list[str]) -> list[Finding]:
        """S12: Unsafe deserialization."""
        # yaml.load with SafeLoader is ok
        if "yaml.load" in func_name:
            for kw in node.keywords:
                if kw.arg == "Loader":
                    loader_str = _extract_string_value(kw.value) or ""
                    if isinstance(kw.value, ast.Attribute):
                        loader_str = kw.value.attr
                    if "Safe" in loader_str or "safe" in loader_str:
                        return []

        arg_taint = TaintInfo(level=TaintLevel.UNKNOWN)
        if node.args:
            arg_taint = ctx.resolve_node(node.args[0])

        if arg_taint.level == TaintLevel.EXTERNAL:
            severity = Severity.CRITICAL
        elif arg_taint.level == TaintLevel.LITERAL:
            severity = Severity.MEDIUM
        else:
            severity = Severity.HIGH

        return [Finding(
            rule_id="S12",
            engine="ast",
            layer=Layer.BEHAVIOR,
            severity=severity,
            confidence=0.9,
            title=f"Unsafe deserialization via {func_name}()",
            description=f"Code uses {func_name}() which can execute arbitrary code during deserialization",
            file_path=rel_path,
            line=node.lineno,
            code_snippet=_get_code_snippet(source_lines, node.lineno),
            evidence=f"Data source taint: {arg_taint.level.value}",
            tags=["deserialization", "execution"],
            remediation="Replace pickle with JSON or MessagePack. Use yaml.safe_load() instead of yaml.load().",
            references=["MITRE T1059.006", "CWE-502"],
        )]

    def _check_file_ops(self, node: ast.Call, ctx: TaintContext,
                        rel_path: str, source_lines: list[str]) -> list[Finding]:
        """S2: Sensitive file reads, S3: Sensitive file writes."""
        findings = []
        if not node.args:
            return findings

        path_str = _extract_string_value(node.args[0])
        if not path_str:
            # Path is a variable — check taint
            path_taint = ctx.resolve_node(node.args[0])
            if path_taint.level == TaintLevel.EXTERNAL:
                findings.append(Finding(
                    rule_id="S3",
                    engine="ast",
                    layer=Layer.BEHAVIOR,
                    severity=Severity.HIGH,
                    confidence=0.8,
                    title="File operation with externally-controlled path",
                    description="File path comes from external input",
                    file_path=rel_path,
                    line=node.lineno,
                    code_snippet=_get_code_snippet(source_lines, node.lineno),
                    evidence=f"Path from {path_taint.source_desc}",
                    tags=["file_access", "path_injection"],
                    remediation="Validate and sanitize file paths. Use an allowlist of permitted directories.",
                    references=["CWE-22"],
                ))
            return findings

        # Determine if read or write
        mode = "r"
        if len(node.args) > 1:
            mode_val = _extract_string_value(node.args[1])
            if mode_val:
                mode = mode_val
        for kw in node.keywords:
            if kw.arg == "mode":
                mode_val = _extract_string_value(kw.value)
                if mode_val:
                    mode = mode_val

        is_write = any(c in mode for c in "wax")

        if is_write:
            # S3: Check against sensitive write paths
            for critical_path in SENSITIVE_WRITE_PATHS_CRITICAL:
                if critical_path.rstrip("/") in path_str or path_str.startswith(critical_path.rstrip("/")):
                    findings.append(Finding(
                        rule_id="S3",
                        engine="ast",
                        layer=Layer.BEHAVIOR,
                        severity=Severity.CRITICAL,
                        confidence=0.95,
                        title="Writes to critical system file",
                        description=f"Code writes to {path_str}",
                        file_path=rel_path,
                        line=node.lineno,
                        code_snippet=_get_code_snippet(source_lines, node.lineno),
                        evidence=f"Write target: {path_str}",
                        tags=["file_write", "system_modification"],
                        remediation="Do not modify system configuration files.",
                        references=["MITRE T1546.004"],
                    ))
                    break
        else:
            # S2: Check against sensitive read paths
            for sev_name, paths in SENSITIVE_READ_PATHS.items():
                for sensitive_path in paths:
                    if sensitive_path in path_str:
                        severity = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM}[sev_name]
                        findings.append(Finding(
                            rule_id="S2",
                            engine="ast",
                            layer=Layer.BEHAVIOR,
                            severity=severity,
                            confidence=0.95,
                            title=f"Reads sensitive file: {sensitive_path}",
                            description=f"Code reads {path_str} which may contain credentials",
                            file_path=rel_path,
                            line=node.lineno,
                            code_snippet=_get_code_snippet(source_lines, node.lineno),
                            evidence=f"Read target: {path_str}",
                            tags=["file_read", "credential_access"],
                            remediation="Remove direct access to sensitive files. Use a secrets manager or ssh-agent.",
                            references=["MITRE T1552.004"],
                        ))
                        return findings

        return findings

    def _check_s8(self, tree: ast.AST, ctx: TaintContext,
                   rel_path: str, source_lines: list[str]) -> list[Finding]:
        """S8: Detect source->sink chains where sensitive data flows to network."""
        findings = []
        # Look for network send calls where arguments contain tainted data
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func_name = _get_call_name(node)
            if func_name not in NETWORK_SEND_SINKS and not any(
                func_name.endswith("." + s.split(".")[-1]) for s in NETWORK_SEND_SINKS
            ):
                continue

            # Check keyword arguments (data=, json=, body=)
            for kw in node.keywords:
                if kw.arg in ("data", "json", "body", "content", "params"):
                    taint = ctx.resolve_node(kw.value)
                    if taint.level == TaintLevel.EXTERNAL and taint.source_type in ("env_var", "file_read"):
                        findings.append(Finding(
                            rule_id="S8",
                            engine="ast",
                            layer=Layer.BEHAVIOR,
                            severity=Severity.CRITICAL,
                            confidence=0.9,
                            title="Sensitive data exfiltration detected",
                            description=f"Sensitive data from {taint.source_desc} sent via {func_name}()",
                            file_path=rel_path,
                            line=node.lineno,
                            code_snippet=_get_code_snippet(source_lines, node.lineno),
                            evidence=f"{taint.source_desc} → {kw.arg}= → {func_name}()",
                            tags=["exfiltration", "network", "credential_access"],
                            remediation="Remove data exfiltration code. Report this skill as malicious.",
                            references=["MITRE T1041"],
                        ))

            # Check positional args (less common for POST data but possible)
            for i, arg in enumerate(node.args):
                if i == 0:
                    continue  # first arg is usually URL
                taint = ctx.resolve_node(arg)
                if taint.level == TaintLevel.EXTERNAL and taint.source_type in ("env_var", "file_read"):
                    findings.append(Finding(
                        rule_id="S8",
                        engine="ast",
                        layer=Layer.BEHAVIOR,
                        severity=Severity.CRITICAL,
                        confidence=0.85,
                        title="Sensitive data exfiltration detected",
                        description=f"Sensitive data from {taint.source_desc} sent via {func_name}()",
                        file_path=rel_path,
                        line=node.lineno,
                        code_snippet=_get_code_snippet(source_lines, node.lineno),
                        evidence=f"{taint.source_desc} → arg[{i}] → {func_name}()",
                        tags=["exfiltration", "network", "credential_access"],
                        remediation="Remove data exfiltration code.",
                        references=["MITRE T1041"],
                    ))

        return findings

    def _check_s10_strings(self, tree: ast.AST, rel_path: str,
                            source_lines: list[str]) -> list[Finding]:
        """S10: Detect download-and-execute patterns in string literals."""
        findings = []
        pipe_patterns = [
            r"curl\s+.*\|\s*(sh|bash|python|node)",
            r"wget\s+.*\|\s*(sh|bash|python|node)",
            r"wget\s+.*-O\s*-\s*\|\s*(sh|bash)",
            r'python\s+-c\s+["\'].*(?:urllib|requests|curl)',
        ]

        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                for pattern in pipe_patterns:
                    if re.search(pattern, node.value, re.IGNORECASE):
                        findings.append(Finding(
                            rule_id="S10",
                            engine="ast",
                            layer=Layer.BEHAVIOR,
                            severity=Severity.CRITICAL,
                            confidence=0.95,
                            title="Download-and-execute pattern in string",
                            description="String contains a pipe-to-shell pattern",
                            file_path=rel_path,
                            line=node.lineno,
                            code_snippet=_get_code_snippet(source_lines, node.lineno),
                            evidence=f"Pattern: {node.value[:100]}",
                            tags=["execution", "network", "supply_chain"],
                            remediation="Never execute downloaded content. Pin dependencies and verify checksums.",
                            references=["MITRE T1105", "MITRE T1059"],
                        ))
                        break
        return findings

    def _check_persistence_and_sysconfig(self, tree: ast.AST, rel_path: str,
                                          source_lines: list[str]) -> list[Finding]:
        """S13/S14: Check string literals for persistence and system config paths."""
        findings = []
        seen_lines: set[int] = set()

        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            if node.lineno in seen_lines:
                continue
            val = node.value

            # S13: Persistence paths
            for pattern in PERSISTENCE_PATHS:
                if pattern.lower() in val.lower() and len(val) > 3:
                    findings.append(Finding(
                        rule_id="S13",
                        engine="ast",
                        layer=Layer.BEHAVIOR,
                        severity=Severity.CRITICAL if any(p in val for p in ["LaunchAgent", "systemd", "crontab", ".zshenv"]) else Severity.HIGH,
                        confidence=0.75,
                        title="Persistence mechanism reference",
                        description=f"Code references persistence path: {val[:80]}",
                        file_path=rel_path,
                        line=node.lineno,
                        code_snippet=_get_code_snippet(source_lines, node.lineno),
                        evidence=f"String contains persistence indicator: {pattern}",
                        tags=["persistence"],
                        remediation="Skills should not install system services or modify startup configuration.",
                        references=["MITRE T1543.001"],
                    ))
                    seen_lines.add(node.lineno)
                    break

            # S14: System config paths
            for pattern in SYSTEM_CONFIG_PATHS:
                if pattern.lower() in val.lower() and node.lineno not in seen_lines:
                    findings.append(Finding(
                        rule_id="S14",
                        engine="ast",
                        layer=Layer.BEHAVIOR,
                        severity=Severity.CRITICAL if "sudoers" in val else Severity.HIGH,
                        confidence=0.75,
                        title="System configuration modification reference",
                        description=f"Code references system config: {val[:80]}",
                        file_path=rel_path,
                        line=node.lineno,
                        code_snippet=_get_code_snippet(source_lines, node.lineno),
                        evidence=f"String contains system config path: {pattern}",
                        tags=["system_modification"],
                        remediation="Skills must not modify system configuration.",
                        references=["MITRE T1548.003"],
                    ))
                    seen_lines.add(node.lineno)
                    break

        return findings
