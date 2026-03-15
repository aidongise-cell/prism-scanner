import re
from pathlib import Path
from .models import Finding

INLINE_PATTERN = re.compile(r"#\s*prism:ignore\s+([\w,]+)")


class SuppressionConfig:
    def __init__(self, project_root: str):
        self.rules: list[tuple[str, str, int | None]] = []  # (rule_id, file_glob, line_or_none)
        self._load(project_root)

    def _load(self, root: str):
        ignore_file = Path(root) / ".prismignore"
        if not ignore_file.exists():
            return
        for line in ignore_file.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            rule_id = parts[0]
            file_glob = parts[1] if len(parts) > 1 else "*"
            line_num = int(parts[2]) if len(parts) > 2 else None
            self.rules.append((rule_id, file_glob, line_num))

    def is_suppressed(self, finding: Finding) -> bool:
        from fnmatch import fnmatch
        for rule_id, file_glob, line_num in self.rules:
            if finding.rule_id != rule_id:
                continue
            if file_glob == "*" or (finding.file_path and fnmatch(finding.file_path, file_glob)):
                if line_num is None or finding.line == line_num:
                    return True
        return False


def check_inline_suppression(code: str, line: int, rule_id: str) -> bool:
    """Check if a specific line has an inline prism:ignore comment."""
    lines = code.splitlines()
    if 0 < line <= len(lines):
        match = INLINE_PATTERN.search(lines[line - 1])
        if match:
            suppressed_rules = [r.strip() for r in match.group(1).split(",")]
            return rule_id in suppressed_rules
    return False
