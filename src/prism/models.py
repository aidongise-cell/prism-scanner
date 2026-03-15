from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Layer(Enum):
    BEHAVIOR = "behavior"
    METADATA = "metadata"
    RESIDUE = "residue"


class TaintSource(Enum):
    LITERAL = "literal"       # constant string/value
    INTERNAL = "internal"     # internal variable, origin unclear
    EXTERNAL = "external"     # user input, env var, network response
    UNKNOWN = "unknown"


@dataclass
class Finding:
    rule_id: str              # e.g. "S1", "P7", "M4", "R5"
    engine: str               # "ast", "pattern", "manifest", "residue"
    layer: Layer
    severity: Severity
    confidence: float         # 0.0-1.0
    title: str
    description: str
    file_path: Optional[str] = None
    line: Optional[int] = None
    code_snippet: Optional[str] = None
    evidence: Optional[str] = None
    tags: list[str] = field(default_factory=list)
    remediation: Optional[str] = None
    references: list[str] = field(default_factory=list)
    suppressed: bool = False

    @property
    def severity_score(self) -> int:
        scores = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 5,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }
        return scores[self.severity]

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "engine": self.engine,
            "layer": self.layer.value,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "title": self.title,
            "description": self.description,
            "file_path": self.file_path,
            "line": self.line,
            "code_snippet": self.code_snippet,
            "evidence": self.evidence,
            "tags": self.tags,
            "remediation": self.remediation,
            "references": self.references,
            "suppressed": self.suppressed,
        }


@dataclass
class ScanTarget:
    path: str                 # local path to the scanned directory
    platform: Optional[str] = None  # "clawhub", "mcp", "npm", "pip", or None for auto-detect
    url: Optional[str] = None       # original URL if scanned from remote


@dataclass
class ScanResult:
    target: ScanTarget
    findings: list[Finding] = field(default_factory=list)
    grade: str = "A"              # A/B/C/D/F
    risk_level: str = "safe"      # safe/notice/caution/danger/critical
    key_risks: list[str] = field(default_factory=list)
    behavior_tags: list[str] = field(default_factory=list)
    scan_duration_ms: int = 0

    @property
    def active_findings(self) -> list[Finding]:
        return [f for f in self.findings if not f.suppressed]

    def to_dict(self) -> dict:
        return {
            "target": {"path": self.target.path, "platform": self.target.platform, "url": self.target.url},
            "grade": self.grade,
            "risk_level": self.risk_level,
            "key_risks": self.key_risks,
            "behavior_tags": self.behavior_tags,
            "findings": [f.to_dict() for f in self.findings],
            "scan_duration_ms": self.scan_duration_ms,
        }
