import time
from pathlib import Path
from .models import ScanTarget, ScanResult
from .scoring import compute_risk_score
from .suppression import SuppressionConfig
from .engines.ast_engine import ASTEngine
from .engines.pattern_engine import PatternEngine
from .engines.manifest_engine import ManifestEngine
from .engines.residue_engine import ResidueEngine


class PrismScanner:
    def __init__(self, engines: list[str] | None = None, offline: bool = False):
        self.offline = offline
        self.enabled_engines = engines or ["ast", "pattern", "manifest"]

    def scan(self, target: ScanTarget, include_residue: bool = False) -> ScanResult:
        start = time.monotonic()
        result = ScanResult(target=target)

        project_root = target.path
        suppression = SuppressionConfig(project_root)

        # Collect all Python/JS files to scan
        scan_files = self._collect_files(project_root)

        # Run engines
        if "ast" in self.enabled_engines:
            engine = ASTEngine()
            for fpath in scan_files:
                result.findings.extend(engine.scan_file(fpath, project_root))

        if "pattern" in self.enabled_engines:
            engine = PatternEngine()
            for fpath in scan_files:
                result.findings.extend(engine.scan_file(fpath, project_root))

        if "manifest" in self.enabled_engines:
            # Derive actual capabilities from behavior findings to cross-reference with manifest
            actual_capabilities = self._extract_capabilities(result.findings)
            engine = ManifestEngine()
            result.findings.extend(engine.scan_project(project_root, actual_capabilities=actual_capabilities))

        if include_residue or "residue" in self.enabled_engines:
            engine = ResidueEngine()
            result.findings.extend(engine.scan_system())

        # Apply suppressions
        for finding in result.findings:
            if suppression.is_suppressed(finding):
                finding.suppressed = True

        # Compute risk score
        compute_risk_score(result)

        result.scan_duration_ms = int((time.monotonic() - start) * 1000)
        return result

    def _extract_capabilities(self, findings: list) -> set[str]:
        """Derive high-level capability tags from behavior findings."""
        capabilities = set()
        # Map finding tags/rule_ids to capability names
        tag_to_capability = {
            "shell": "shell",
            "execution": "shell",
            "network": "network",
            "file_read": "file_read",
            "file_write": "file_write",
            "credential_access": "credential_read",
            "exfiltration": "network",
            "persistence": "persistence",
            "env_var": "env_read",
            "deserialization": "deserialization",
            "import": "dynamic_import",
            "system_modification": "system_modification",
        }
        rule_to_capability = {
            "S1": "shell",
            "S2": "file_read",
            "S3": "file_write",
            "S4": "network",
            "S5": "env_read",
            "S6": "shell",
            "S8": "network",
            "S9": "network",
            "S10": "shell",
            "S13": "persistence",
            "S14": "system_modification",
            "P1": "network",
            "P3": "credential_read",
        }
        for finding in findings:
            if finding.layer.value != "behavior":
                continue
            # Map by rule_id
            if finding.rule_id in rule_to_capability:
                capabilities.add(rule_to_capability[finding.rule_id])
            # Map by tags
            for tag in finding.tags:
                if tag in tag_to_capability:
                    capabilities.add(tag_to_capability[tag])
        return capabilities

    def _collect_files(self, root: str) -> list[str]:
        """Collect scannable source files, excluding common non-source dirs."""
        exclude_dirs = {
            "node_modules", ".git", "__pycache__", ".venv", "venv",
            "dist", "build", ".tox", ".mypy_cache", ".pytest_cache",
            ".egg-info",
        }
        extensions = {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".sh", ".bash", ".md"}
        files = []
        for p in Path(root).rglob("*"):
            if any(part in exclude_dirs for part in p.parts):
                continue
            if p.is_file() and p.suffix in extensions:
                files.append(str(p))
        return sorted(files)
