"""
Risk grading engine for Prism Scanner.

Uses letter grades (A-F) based on the worst findings found,
with quantity as an escalation factor. No opaque point formulas.

Grade logic:
  F (Critical)  — Any CRITICAL finding, or 3+ HIGH
  D (Danger)    — 1-2 HIGH findings, or 5+ MEDIUM
  C (Caution)   — 1-4 MEDIUM findings
  B (Notice)    — Only LOW findings
  A (Safe)      — No findings or only INFO
"""
from .models import Finding, ScanResult, Severity

# Human-readable labels for each grade
GRADE_INFO = {
    "F": {"label": "Critical",  "recommendation": "DO NOT INSTALL — Critical security risks detected."},
    "D": {"label": "Danger",    "recommendation": "USE IN SANDBOX ONLY — Significant risks require isolation."},
    "C": {"label": "Caution",   "recommendation": "REVIEW BEFORE USE — Some concerns warrant manual inspection."},
    "B": {"label": "Notice",    "recommendation": "LIKELY SAFE — Minor observations, low risk."},
    "A": {"label": "Safe",      "recommendation": "SAFE TO USE — No significant security risks detected."},
}

# Tags derived from specific rule hits
TAG_MAP = {
    "S1": "executes_shell", "S2": "reads_secrets", "S3": "writes_system_files",
    "S4": "network_outbound", "S5": "reads_env_vars", "S6": "dynamic_execution",
    "S8": "exfiltrates_data", "S9": "ssrf_risk", "S10": "downloads_and_executes",
    "S11": "install_time_execution", "S12": "unsafe_deserialization",
    "S13": "installs_persistence", "S14": "modifies_system_config",
    "P9": "uses_obfuscation",
}


def compute_risk_score(result: ScanResult) -> None:
    """Compute and set grade, risk_level, key_risks, behavior_tags on result."""
    findings = result.active_findings
    if not findings:
        result.grade = "A"
        result.risk_level = "safe"
        result.key_risks = []
        result.behavior_tags = []
        return

    # Count by severity
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    n_critical = counts.get(Severity.CRITICAL, 0)
    n_high = counts.get(Severity.HIGH, 0)
    n_medium = counts.get(Severity.MEDIUM, 0)
    n_low = counts.get(Severity.LOW, 0)

    # Determine grade
    if n_critical >= 1 or n_high >= 3:
        grade = "F"
    elif n_high >= 1 or n_medium >= 5:
        grade = "D"
    elif n_medium >= 1:
        grade = "C"
    elif n_low >= 1:
        grade = "B"
    else:
        grade = "A"

    # Collect key risks — top findings sorted by severity, deduplicated by rule_id
    seen_rules = set()
    key_risks = []
    for f in sorted(findings, key=lambda x: x.severity_score, reverse=True):
        if f.rule_id not in seen_rules and f.severity != Severity.INFO:
            key_risks.append(f"{f.severity.value.upper()}: {f.title} ({f.rule_id})")
            seen_rules.add(f.rule_id)
        if len(key_risks) >= 5:
            break

    # Collect behavior tags
    tags = set()
    for f in findings:
        if f.rule_id in TAG_MAP:
            tags.add(TAG_MAP[f.rule_id])

    result.grade = grade
    result.risk_level = GRADE_INFO[grade]["label"].lower()
    result.key_risks = key_risks
    result.behavior_tags = sorted(tags)
