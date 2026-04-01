"""Manifest and metadata analysis engine (M1-M7) with S11 install-script deep scanning."""
import json
import os
import re
from pathlib import Path
from typing import Optional

from ..models import Finding, Severity, Layer
from .ast_engine import ASTEngine


# M1: Capability-permission baselines per category
CAPABILITY_BASELINES = {
    "calculator": {"allowed": {"computation"}, "suspicious": {"network", "filesystem", "shell"}},
    "formatter": {"allowed": {"file_read", "file_write"}, "suspicious": {"network", "shell"}},
    "search": {"allowed": {"network_outbound"}, "suspicious": {"shell", "file_write", "persistence"}},
    "git": {"allowed": {"file_read", "file_write", "shell_git"}, "suspicious": {"credential_read", "persistence"}},
    "code_runner": {"allowed": {"shell", "file_read", "file_write"}, "suspicious": {"network", "persistence"}},
    "fetcher": {"allowed": {"network_outbound"}, "suspicious": {"shell", "file_write"}},
}

# Keywords used to auto-detect a skill's category from its description/README
_CATEGORY_KEYWORDS = {
    "calculator": ["calculator", "math", "compute", "arithmetic", "calculate"],
    "formatter": ["format", "formatter", "lint", "prettify", "beautify", "style"],
    "search": ["search", "find", "lookup", "query", "index"],
    "git": ["git", "commit", "branch", "merge", "repository", "repo"],
    "code_runner": ["run", "execute", "runner", "sandbox", "interpreter", "eval"],
    "fetcher": ["fetch", "download", "http", "request", "scrape", "crawl"],
}

# Dangerous tool names that a ClawHub skill should not request
_DANGEROUS_TOOL_REQUESTS = {
    "shell", "bash", "exec", "run_command", "system",
    "file_write", "write_file",
    "credential_read", "read_credentials",
    "env_read", "read_env",
}

# Prompt injection indicators in skill descriptions (P6 linkage)
_PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(previous|above|all)\s+(instructions?|prompts?|rules?)",
    r"you\s+are\s+now\s+(a|an)\s+",
    r"disregard\s+(any|all|previous)",
    r"system\s*:\s*",
    r"<\s*system\s*>",
    r"forget\s+(everything|all|your)",
    r"override\s+(your|the|all)\s+(instructions?|rules?|constraints?)",
    r"new\s+instructions?\s*:",
    r"act\s+as\s+(if|though)\s+you",
    r"pretend\s+(you|that|to)",
]


# M7: Debug artifacts and sensitive files that should not be in published packages.
# Inspired by the Anthropic Claude Code source map leak (March 2026) where a .map
# file in an npm package exposed 512,000 lines of internal source code.
_DEBUG_ARTIFACT_PATTERNS = [
    # Source maps — the exact Anthropic leak vector
    ("**/*.map", "Source map file", Severity.HIGH,
     "Source maps expose original unminified source code. This is how Claude Code's "
     "512K lines of internal code leaked via npm. Remove before publishing."),
    ("**/*.js.map", "JavaScript source map", Severity.HIGH,
     "Exposes original TypeScript/JavaScript source. Remove from published packages."),
    ("**/*.css.map", "CSS source map", Severity.MEDIUM,
     "Exposes original CSS/SCSS source. Remove from published packages."),

    # Environment/secret files
    (".env", "Environment variable file", Severity.CRITICAL,
     "Likely contains API keys and secrets. Add to .npmignore / .gitignore."),
    (".env.*", "Environment variable file (variant)", Severity.HIGH,
     "May contain secrets for specific environments."),
    ("**/.env", "Nested environment file", Severity.CRITICAL,
     "Environment file in subdirectory — may contain secrets."),

    # IDE and editor configs
    (".vscode/**", "VS Code configuration", Severity.MEDIUM,
     "May expose internal file paths, debug configs, and extension settings."),
    (".idea/**", "JetBrains IDE configuration", Severity.MEDIUM,
     "May expose internal paths, database connections, and run configs."),
    (".sublime-*", "Sublime Text config", Severity.LOW,
     "Editor configuration should not be in published packages."),

    # Private keys and certificates
    ("**/*.pem", "PEM key/certificate file", Severity.CRITICAL,
     "Private key material must never be distributed in packages."),
    ("**/*.key", "Private key file", Severity.CRITICAL,
     "Private key material must never be distributed."),
    ("**/*.p12", "PKCS12 certificate bundle", Severity.HIGH,
     "Certificate bundles should not be in published packages."),
    ("**/*.pfx", "PFX certificate file", Severity.HIGH,
     "Certificate files should not be in published packages."),
    ("**/*.keystore", "Java keystore file", Severity.HIGH,
     "Keystores should not be in published packages."),

    # Internal/draft documents
    ("**/internal-*", "Internal document", Severity.MEDIUM,
     "Files prefixed 'internal-' suggest non-public material."),
    ("**/draft-*", "Draft document", Severity.LOW,
     "Draft documents should be excluded from published packages."),
    ("**/INTERNAL_*", "Internal document", Severity.MEDIUM,
     "Internal documents should not be in published packages."),

    # Docker/CI credentials
    ("**/.docker/config.json", "Docker config", Severity.HIGH,
     "May contain registry authentication credentials."),
    ("**/.npmrc", "npm config", Severity.HIGH,
     "May contain npm registry auth tokens."),
    ("**/.pypirc", "PyPI config", Severity.CRITICAL,
     "Contains PyPI upload credentials."),

    # Debug/profiling artifacts
    ("**/*.prof", "Profiling data", Severity.LOW,
     "Profiling artifacts should not be in published packages."),
    ("**/*.heapsnapshot", "Heap snapshot", Severity.MEDIUM,
     "Memory snapshots may contain sensitive runtime data."),
    ("**/core", "Core dump file", Severity.MEDIUM,
     "Core dumps may contain sensitive memory contents."),
    ("**/*.dmp", "Memory dump file", Severity.MEDIUM,
     "Memory dumps may contain sensitive data."),
]

_SEVERITY_ESCALATION = {
    Severity.LOW: Severity.MEDIUM,
    Severity.MEDIUM: Severity.HIGH,
    Severity.HIGH: Severity.CRITICAL,
    Severity.CRITICAL: Severity.CRITICAL,
    Severity.INFO: Severity.LOW,
}


class ManifestEngine:
    """Analyzes project manifests for metadata risks."""

    @staticmethod
    def _elevate_severity(finding: Finding) -> Finding:
        """Bump severity by one level for install-time findings."""
        finding.severity = _SEVERITY_ESCALATION[finding.severity]
        if "install_time" not in finding.tags:
            finding.tags.append("install_time")
        return finding

    def _deep_scan_install_script(self, file_path: str, project_root: str) -> list[Finding]:
        """S11: Run ASTEngine on an install script file and elevate findings."""
        fpath = Path(file_path)
        if not fpath.exists() or not fpath.is_file():
            return []
        ast_engine = ASTEngine()
        raw_findings = ast_engine.scan_file(str(fpath), project_root)
        elevated = []
        for f in raw_findings:
            f.rule_id = f"S11/{f.rule_id}"
            f.description = f"[install-time] {f.description}"
            self._elevate_severity(f)
            elevated.append(f)
        return elevated

    def scan_project(self, project_root: str, actual_capabilities: set[str] | None = None) -> list[Finding]:
        findings = []
        root = Path(project_root)
        declared_capabilities: set[str] = set()

        # Detect platform and parse manifest
        if (root / "SKILL.md").exists():
            findings.extend(self._scan_clawhub(root))
        if (root / "package.json").exists():
            findings.extend(self._scan_npm(root))
        if (root / "setup.py").exists() or (root / "pyproject.toml").exists():
            findings.extend(self._scan_pip(root))
        if (root / "mcp.json").exists() or (root / "manifest.json").exists():
            mcp_findings, declared_capabilities = self._scan_mcp(root)
            findings.extend(mcp_findings)

        # M1: Capability-permission baseline check
        description_text = self._gather_description_text(root)
        findings.extend(self._check_capability_baseline(description_text, actual_capabilities or set(), root))

        # M2a: Declared vs actual capability cross-reference
        if actual_capabilities and declared_capabilities:
            manifest_file = "mcp.json" if (root / "mcp.json").exists() else "manifest.json"
            findings.extend(self.check_declared_vs_actual(declared_capabilities, actual_capabilities, manifest_file))

        # M7: Debug artifact and sensitive file detection
        findings.extend(self._scan_debug_artifacts(root))

        return findings

    def _scan_npm(self, root: Path) -> list[Finding]:
        """Scan package.json for M5 (install scripts) and M3 (dependencies)."""
        findings = []
        pkg_file = root / "package.json"
        try:
            pkg = json.loads(pkg_file.read_text())
        except (json.JSONDecodeError, OSError):
            return findings

        # M5: Install-time scripts
        scripts = pkg.get("scripts", {})
        dangerous_hooks = ["preinstall", "postinstall", "prepare", "prepublish"]
        for hook in dangerous_hooks:
            if hook in scripts:
                script_content = scripts[hook]
                severity = Severity.HIGH
                # Escalate if script downloads or executes
                if re.search(r"(curl|wget|sh|bash|node\s+-e|python\s+-c)", script_content, re.IGNORECASE):
                    severity = Severity.CRITICAL
                findings.append(Finding(
                    rule_id="M5",
                    engine="manifest",
                    layer=Layer.METADATA,
                    severity=severity,
                    confidence=0.9,
                    title=f"Install-time script: {hook}",
                    description=f"package.json contains {hook} script that executes during npm install",
                    file_path="package.json",
                    code_snippet=f'"{hook}": "{script_content[:100]}"',
                    tags=["install_script", "supply_chain"],
                    remediation=f"Review {hook} script carefully. Use --ignore-scripts flag during install.",
                    references=["MITRE T1195.002"],
                ))

                # S11: Deep scan referenced script files
                # Extract JS/Python file references from the script command
                file_refs = re.findall(r'[\w./-]+\.(?:js|mjs|cjs|py)\b', script_content)
                for ref in file_refs:
                    script_file = root / ref
                    if script_file.exists():
                        findings.extend(
                            self._deep_scan_install_script(str(script_file), str(root))
                        )

        # M4: Typo-squatting check for dependencies
        all_deps = {}
        for dep_key in ("dependencies", "devDependencies", "peerDependencies"):
            all_deps.update(pkg.get(dep_key, {}))

        findings.extend(self._check_typosquatting(all_deps.keys(), "package.json"))

        return findings

    def _scan_pip(self, root: Path) -> list[Finding]:
        """Scan setup.py / pyproject.toml for install scripts and dependencies."""
        findings = []

        # Check setup.py for cmdclass override
        setup_py = root / "setup.py"
        if setup_py.exists():
            try:
                content = setup_py.read_text()
                if "cmdclass" in content and ("install" in content or "develop" in content):
                    findings.append(Finding(
                        rule_id="M5",
                        engine="manifest",
                        layer=Layer.METADATA,
                        severity=Severity.HIGH,
                        confidence=0.85,
                        title="Custom install command in setup.py",
                        description="setup.py overrides install/develop cmdclass, code executes during pip install",
                        file_path="setup.py",
                        tags=["install_script", "supply_chain"],
                        remediation="Review setup.py install command. Custom cmdclass is a common attack vector.",
                        references=["MITRE T1195.002"],
                    ))
                    # S11: Deep scan setup.py with AST engine
                    findings.extend(
                        self._deep_scan_install_script(str(setup_py), str(root))
                    )
            except OSError:
                pass

        # Check requirements.txt for typo-squatting
        req_file = root / "requirements.txt"
        if req_file.exists():
            try:
                deps = []
                for line in req_file.read_text().splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        dep_name = re.split(r"[>=<!\[]", line)[0].strip()
                        if dep_name:
                            deps.append(dep_name)
                findings.extend(self._check_typosquatting(deps, "requirements.txt"))
            except OSError:
                pass

        return findings

    def _scan_clawhub(self, root: Path) -> list[Finding]:
        """Scan SKILL.md for ClawHub-specific metadata (M1/M2b/P6)."""
        findings = []
        skill_file = root / "SKILL.md"
        try:
            content = skill_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings

        lines = content.splitlines()

        # Extract tool declarations: lines like "## Tools", "- tool: ...", "### <tool_name>"
        declared_tools: list[str] = []
        in_tools_section = False
        for line in lines:
            stripped = line.strip()
            if re.match(r"^#{1,3}\s+tools?\b", stripped, re.IGNORECASE):
                in_tools_section = True
                continue
            if in_tools_section:
                if re.match(r"^#{1,3}\s+", stripped) and not re.match(r"^#{1,3}\s+tools?\b", stripped, re.IGNORECASE):
                    in_tools_section = False
                    continue
                # Detect tool list items: "- tool_name" or "- `tool_name`"
                tool_match = re.match(r"^[-*]\s+`?(\w[\w_.-]*)`?", stripped)
                if tool_match:
                    declared_tools.append(tool_match.group(1).lower())
                # Detect "### tool_name" sub-headings within tools section
                sub_match = re.match(r"^#{2,4}\s+`?(\w[\w_.-]*)`?", stripped)
                if sub_match:
                    declared_tools.append(sub_match.group(1).lower())

        # Check for dangerous tool requests
        for tool in declared_tools:
            if tool in _DANGEROUS_TOOL_REQUESTS:
                findings.append(Finding(
                    rule_id="M2b",
                    engine="manifest",
                    layer=Layer.METADATA,
                    severity=Severity.HIGH,
                    confidence=0.85,
                    title=f"Skill requests dangerous tool: {tool}",
                    description=f"SKILL.md declares a tool '{tool}' that grants powerful/dangerous capabilities",
                    file_path="SKILL.md",
                    tags=["dangerous_tool", "capability_escalation"],
                    remediation=f"Review whether the skill genuinely needs the '{tool}' tool.",
                    references=["CWE-250"],
                ))

        # P6 linkage: Check description for prompt injection patterns
        description_section = self._extract_section(content, "description") or content[:2000]
        for pattern in _PROMPT_INJECTION_PATTERNS:
            match = re.search(pattern, description_section, re.IGNORECASE)
            if match:
                # Find the line number
                line_num = None
                matched_text = match.group(0)
                for i, line in enumerate(lines, 1):
                    if matched_text.lower() in line.lower():
                        line_num = i
                        break
                findings.append(Finding(
                    rule_id="P6",
                    engine="manifest",
                    layer=Layer.METADATA,
                    severity=Severity.CRITICAL,
                    confidence=0.9,
                    title="Prompt injection detected in skill description",
                    description="SKILL.md description contains text that attempts to override LLM instructions",
                    file_path="SKILL.md",
                    line=line_num,
                    code_snippet=matched_text,
                    evidence=f"Matched pattern: {matched_text}",
                    tags=["prompt_injection", "social_engineering"],
                    remediation="Remove prompt injection text from skill description.",
                    references=["OWASP LLM01"],
                ))
                break  # One P6 finding is enough

        return findings

    def _extract_section(self, markdown: str, section_name: str) -> Optional[str]:
        """Extract a markdown section by heading name."""
        pattern = rf"^#{1,3}\s+{re.escape(section_name)}\s*$"
        lines = markdown.splitlines()
        start = None
        for i, line in enumerate(lines):
            if re.match(pattern, line.strip(), re.IGNORECASE):
                start = i + 1
                continue
            if start is not None and re.match(r"^#{1,3}\s+", line.strip()):
                return "\n".join(lines[start:i])
        if start is not None:
            return "\n".join(lines[start:])
        return None

    def _scan_mcp(self, root: Path) -> tuple[list[Finding], set[str]]:
        """Scan MCP manifest (mcp.json / manifest.json) for M2a and permission issues."""
        findings = []
        declared_capabilities: set[str] = set()

        manifest_file = root / "mcp.json"
        if not manifest_file.exists():
            manifest_file = root / "manifest.json"
        if not manifest_file.exists():
            return findings, declared_capabilities

        manifest_name = manifest_file.name
        try:
            manifest = json.loads(manifest_file.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError) as e:
            findings.append(Finding(
                rule_id="M6",
                engine="manifest",
                layer=Layer.METADATA,
                severity=Severity.MEDIUM,
                confidence=0.9,
                title=f"Malformed manifest: {manifest_name}",
                description=f"Could not parse {manifest_name}: {e}",
                file_path=manifest_name,
                tags=["manifest", "parse_error"],
                remediation="Fix JSON syntax in manifest file.",
            ))
            return findings, declared_capabilities

        # Extract declared tools
        tools = manifest.get("tools", [])
        if isinstance(tools, list):
            for tool in tools:
                if isinstance(tool, dict):
                    tool_name = tool.get("name", "")
                    if tool_name:
                        declared_capabilities.add(tool_name)
                elif isinstance(tool, str):
                    declared_capabilities.add(tool)

        # Extract declared resources
        resources = manifest.get("resources", [])
        if isinstance(resources, list):
            for res in resources:
                if isinstance(res, dict):
                    res_name = res.get("name", "")
                    if res_name:
                        declared_capabilities.add(res_name)

        # Check for overly broad tool permissions
        permissions = manifest.get("permissions", {})
        if isinstance(permissions, dict):
            # Detect wildcard or overly broad permissions
            for perm_key, perm_val in permissions.items():
                if perm_val == "*" or perm_val is True:
                    findings.append(Finding(
                        rule_id="M2b",
                        engine="manifest",
                        layer=Layer.METADATA,
                        severity=Severity.HIGH,
                        confidence=0.9,
                        title=f"Overly broad permission: {perm_key}",
                        description=f"Manifest declares wildcard/unrestricted permission for '{perm_key}'",
                        file_path=manifest_name,
                        tags=["permission", "overly_broad"],
                        remediation=f"Restrict the '{perm_key}' permission to specific resources.",
                        references=["CWE-250"],
                    ))
                # Check for broad filesystem or network access
                if isinstance(perm_val, (list, str)):
                    val_str = str(perm_val)
                    if perm_key in ("filesystem", "file", "fs") and ("/" == val_str or "~" in val_str or "*" in val_str):
                        findings.append(Finding(
                            rule_id="M2b",
                            engine="manifest",
                            layer=Layer.METADATA,
                            severity=Severity.HIGH,
                            confidence=0.85,
                            title=f"Broad filesystem permission: {perm_key}",
                            description=f"Manifest requests broad filesystem access: {val_str[:100]}",
                            file_path=manifest_name,
                            tags=["permission", "filesystem", "overly_broad"],
                            remediation="Restrict filesystem access to specific directories needed by the tool.",
                            references=["CWE-250"],
                        ))

        return findings, declared_capabilities

    def _scan_debug_artifacts(self, root: Path) -> list[Finding]:
        """M7: Detect debug artifacts and sensitive files that should not be published.

        Inspired by the Anthropic Claude Code leak (March 31, 2026) where a source map
        file accidentally included in an npm package exposed the entire internal codebase.
        Also covers .env files, private keys, IDE configs, and other files that should
        never appear in distributed packages.
        """
        findings = []
        seen_patterns: set[str] = set()  # Deduplicate by pattern

        for glob_pattern, desc, severity, remediation in _DEBUG_ARTIFACT_PATTERNS:
            matches = list(root.glob(glob_pattern))
            if not matches:
                continue

            # Skip matches inside excluded directories
            exclude_dirs = {"node_modules", ".git", "__pycache__", ".venv", "venv"}
            filtered = []
            for m in matches:
                rel = m.relative_to(root)
                if not any(part in exclude_dirs for part in rel.parts):
                    filtered.append(m)

            if not filtered:
                continue

            pattern_key = glob_pattern
            if pattern_key in seen_patterns:
                continue
            seen_patterns.add(pattern_key)

            # Report each matched file (up to 5 per pattern to avoid noise)
            for match_path in filtered[:5]:
                rel_path = str(match_path.relative_to(root))
                # Get file size for evidence
                try:
                    size = match_path.stat().st_size
                    size_str = (
                        f"{size / 1024 / 1024:.1f} MB" if size > 1024 * 1024
                        else f"{size / 1024:.1f} KB" if size > 1024
                        else f"{size} bytes"
                    )
                    evidence = f"File: {rel_path} ({size_str})"
                except OSError:
                    evidence = f"File: {rel_path}"

                findings.append(Finding(
                    rule_id="M7",
                    engine="manifest",
                    layer=Layer.METADATA,
                    severity=severity,
                    confidence=0.9,
                    title=f"Publishable package contains {desc.lower()}: {rel_path}",
                    description=(
                        f"Found '{rel_path}' which is a {desc.lower()}. "
                        f"This type of file should not be included in published packages."
                    ),
                    file_path=rel_path,
                    evidence=evidence,
                    tags=["debug_artifact", "publish_hygiene", "supply_chain"],
                    remediation=remediation,
                    references=["CWE-540"],
                ))

            # If more than 5 matches, add a summary finding
            if len(filtered) > 5:
                findings.append(Finding(
                    rule_id="M7",
                    engine="manifest",
                    layer=Layer.METADATA,
                    severity=severity,
                    confidence=0.9,
                    title=f"Multiple {desc.lower()} files found ({len(filtered)} total)",
                    description=f"Found {len(filtered)} files matching '{glob_pattern}'. Only first 5 are listed individually.",
                    evidence=f"Total: {len(filtered)} files matching {glob_pattern}",
                    tags=["debug_artifact", "publish_hygiene", "supply_chain"],
                    remediation=remediation,
                    references=["CWE-540"],
                ))

        return findings

    def _gather_description_text(self, root: Path) -> str:
        """Gather description text from SKILL.md, README, or package metadata."""
        texts = []
        for fname in ("SKILL.md", "README.md", "README.rst", "README.txt", "README"):
            f = root / fname
            if f.exists():
                try:
                    texts.append(f.read_text(encoding="utf-8", errors="replace")[:5000])
                except OSError:
                    pass
        # Also try package.json description
        pkg_file = root / "package.json"
        if pkg_file.exists():
            try:
                pkg = json.loads(pkg_file.read_text())
                desc = pkg.get("description", "")
                if desc:
                    texts.append(desc)
            except (json.JSONDecodeError, OSError):
                pass
        # Also try pyproject.toml description (simple extraction)
        pyproject = root / "pyproject.toml"
        if pyproject.exists():
            try:
                content = pyproject.read_text()
                match = re.search(r'description\s*=\s*"([^"]*)"', content)
                if match:
                    texts.append(match.group(1))
            except OSError:
                pass
        return "\n".join(texts).lower()

    def _detect_category(self, description: str) -> Optional[str]:
        """Guess a skill category from its description text."""
        description_lower = description.lower()
        best_category = None
        best_count = 0
        for category, keywords in _CATEGORY_KEYWORDS.items():
            count = sum(1 for kw in keywords if kw in description_lower)
            if count > best_count:
                best_count = count
                best_category = category
        return best_category if best_count > 0 else None

    def _check_capability_baseline(self, description: str, actual_capabilities: set[str],
                                    root: Path) -> list[Finding]:
        """M1: Check actual capabilities against expected baseline for the detected category."""
        findings = []
        category = self._detect_category(description)
        if not category or category not in CAPABILITY_BASELINES:
            return findings

        baseline = CAPABILITY_BASELINES[category]
        suspicious = baseline.get("suspicious", set())

        for cap in actual_capabilities:
            if cap in suspicious:
                findings.append(Finding(
                    rule_id="M1",
                    engine="manifest",
                    layer=Layer.METADATA,
                    severity=Severity.HIGH,
                    confidence=0.75,
                    title=f"Unexpected capability for {category} skill: {cap}",
                    description=(
                        f"A '{category}' skill would not normally require '{cap}' capability. "
                        f"Allowed capabilities for this category: {', '.join(sorted(baseline.get('allowed', set())))}"
                    ),
                    tags=["capability_mismatch", "suspicious"],
                    remediation=f"Review why a {category} skill needs {cap} access.",
                    references=["CWE-250"],
                ))

        return findings

    def check_declared_vs_actual(self, declared: set[str], actual: set[str],
                                  manifest_file: str) -> list[Finding]:
        """M2a/M2b: Cross-reference declared capabilities vs actually used capabilities.

        M2a: Actual capabilities not declared in manifest (undeclared behavior).
        M2b: Declared capabilities that are suspiciously broad.
        """
        findings = []

        # M2a: Capabilities found in code but NOT declared in manifest
        undeclared = actual - declared
        if undeclared:
            for cap in sorted(undeclared):
                findings.append(Finding(
                    rule_id="M2a",
                    engine="manifest",
                    layer=Layer.METADATA,
                    severity=Severity.HIGH,
                    confidence=0.8,
                    title=f"Undeclared capability: {cap}",
                    description=(
                        f"Code uses '{cap}' capability but it is not declared in {manifest_file}. "
                        f"This may indicate hidden behavior."
                    ),
                    file_path=manifest_file,
                    tags=["undeclared_capability", "transparency"],
                    remediation=f"Declare the '{cap}' capability in {manifest_file} or remove it from code.",
                    references=["CWE-284"],
                ))

        return findings

    def _check_typosquatting(self, dep_names, manifest_file: str) -> list[Finding]:
        """M4: Check dependencies for typo-squatting."""
        findings = []

        # Top 100 most common packages (subset for MVP)
        TOP_PACKAGES = {
            "requests", "numpy", "pandas", "flask", "django", "boto3", "scipy",
            "pillow", "matplotlib", "sqlalchemy", "celery", "redis", "pytest",
            "pyyaml", "cryptography", "paramiko", "beautifulsoup4", "lxml",
            "colorama", "click", "httpx", "fastapi", "uvicorn", "pydantic",
            "aiohttp", "scrapy", "tensorflow", "torch", "transformers",
            "openai", "anthropic", "langchain", "setuptools", "wheel", "pip",
            "jinja2", "markupsafe", "werkzeug", "itsdangerous", "certifi",
            "charset-normalizer", "idna", "urllib3", "six", "python-dateutil",
            "pytz", "packaging", "typing-extensions", "tomli", "exceptiongroup",
            # npm common packages
            "express", "react", "lodash", "axios", "moment", "webpack",
            "babel", "eslint", "prettier", "typescript", "next", "vue",
            "angular", "jquery", "underscore", "chalk", "commander",
            "inquirer", "dotenv", "cors", "body-parser", "mongoose",
        }

        for dep in dep_names:
            dep_lower = dep.lower().replace("-", "").replace("_", "")
            for top_pkg in TOP_PACKAGES:
                top_lower = top_pkg.lower().replace("-", "").replace("_", "")
                if dep_lower == top_lower:
                    break  # Exact match (ignoring separators)
                dist = _levenshtein(dep_lower, top_lower)
                if dist == 1:
                    findings.append(Finding(
                        rule_id="M4",
                        engine="manifest",
                        layer=Layer.METADATA,
                        severity=Severity.CRITICAL,
                        confidence=0.85,
                        title=f"Possible typo-squatting: \"{dep}\" (similar to \"{top_pkg}\")",
                        description=f"Dependency name is 1 edit away from popular package \"{top_pkg}\"",
                        file_path=manifest_file,
                        evidence="Levenshtein distance = 1",
                        tags=["typosquatting", "supply_chain"],
                        remediation=f"Verify this is the intended package. Did you mean \"{top_pkg}\"?",
                        references=["CWE-1357"],
                    ))
                    break

        return findings


def _levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]
