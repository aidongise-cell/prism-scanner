"""Pattern matching engine for P1-P9 detection rules."""
import base64
import hashlib
import math
import os
import re
from collections import Counter
from pathlib import Path
from typing import Optional

from ..models import Finding, Severity, Layer
from ..rules_loader import load_malicious_signatures, load_suspicious_domains, load_ioc_database


# P1: Credential patterns
SECRET_PATTERNS = [
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}", Severity.CRITICAL),
    ("AWS Secret Key", r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})", Severity.CRITICAL),
    ("GitHub Token", r"ghp_[A-Za-z0-9]{36}", Severity.CRITICAL),
    ("GitHub OAuth", r"gho_[A-Za-z0-9]{36}", Severity.CRITICAL),
    ("GitLab Token", r"glpat-[A-Za-z0-9\-]{20,}", Severity.CRITICAL),
    ("Stripe Secret Key", r"sk_live_[A-Za-z0-9]{24,}", Severity.CRITICAL),
    ("Stripe Publishable", r"pk_live_[A-Za-z0-9]{24,}", Severity.HIGH),
    ("Slack Webhook", r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+", Severity.HIGH),
    ("Slack Token", r"xox[baprs]-[A-Za-z0-9\-]+", Severity.CRITICAL),
    ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}", Severity.HIGH),
    ("Heroku API Key", r"[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}", Severity.HIGH),
    ("OpenAI API Key", r"sk-[A-Za-z0-9]{20,}", Severity.CRITICAL),
    ("Anthropic API Key", r"sk-ant-[A-Za-z0-9\-]{20,}", Severity.CRITICAL),
    ("Private Key Header", r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", Severity.CRITICAL),
    ("Generic Secret Assignment", r"(?i)(?:api[_\-]?key|secret[_\-]?key|access[_\-]?token|auth[_\-]?token|password)\s*[=:]\s*['\"][A-Za-z0-9+/=_\-]{16,}['\"]", Severity.HIGH),
]

# P4: Suspicious domain patterns
SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".buzz", ".click"]
DYNAMIC_DNS_PATTERNS = [
    r"\.ngrok\.io", r"\.ngrok-free\.app", r"\.duckdns\.org",
    r"\.no-ip\.com", r"\.ddns\.net", r"\.serveo\.net",
    r"\.localhost\.run", r"\.loca\.lt",
]

# P6: Prompt injection patterns
PROMPT_INJECTION_PATTERNS = [
    (r"(?i)ignore\s+(all\s+)?(previous|above|prior|earlier)\s+(instructions|prompts|rules)", Severity.HIGH),
    (r"(?i)you\s+are\s+now\s+(?:DAN|a\s+new|an?\s+unrestricted)", Severity.HIGH),
    (r"(?i)(?:system|developer)\s+mode\s+(?:enabled|activated|on)", Severity.HIGH),
    (r"(?i)jailbreak", Severity.MEDIUM),
    (r"(?i)forget\s+(?:all\s+)?(?:your|previous)\s+(?:instructions|rules|training)", Severity.HIGH),
    (r"(?i)(?:reveal|show|display|print)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions)", Severity.MEDIUM),
]

# P9: Obfuscation patterns
JS_OBFUSCATION_PATTERNS = [
    (r"_0x[a-fA-F0-9]{4,}", "hex-prefixed variables"),
    (r"atob\s*\(.*\)\s*;?\s*eval", "atob+eval pattern"),
    (r"new\s+Function\s*\(", "Function constructor"),
    (r"eval\s*\(\s*String\.fromCharCode", "eval+fromCharCode"),
]

PY_OBFUSCATION_PATTERNS = [
    (r"(?:chr\(\d+\)\s*\+\s*){5,}", "chr() chain"),
    (r"exec\s*\(\s*(?:bytes|b['\"].*['\"])\.decode\s*\(", "exec(bytes.decode())"),
    (r"exec\s*\(\s*__import__\s*\(\s*['\"]base64['\"]\s*\)", "exec(base64.decode)"),
]

# Placeholder patterns
PLACEHOLDER_PATTERNS = re.compile(
    r"(?i)(your[_\-]?api[_\-]?key|placeholder|example|xxxxxx|changeme|todo|insert[_\-]?here|dummy|fake|test[_\-]?key)"
)


def _shannon_entropy(s: str) -> float:
    if not s or len(s) < 2:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _is_uuid(s: str) -> bool:
    return bool(re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", s))


_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


class PatternEngine:
    """Regex and heuristic-based pattern matching engine (P1-P9)."""

    def __init__(self) -> None:
        self._signatures = load_malicious_signatures()
        self._domain_data = load_suspicious_domains()
        self._ioc_patterns = load_ioc_database()
        # Merge YAML-defined suspicious TLDs with hardcoded ones
        yaml_tlds = self._domain_data.get("suspicious_tlds", [])
        self._suspicious_tlds = list(set(SUSPICIOUS_TLDS + yaml_tlds))
        # Merge YAML-defined dynamic DNS patterns
        yaml_ddns = self._domain_data.get("dynamic_dns", [])
        self._dynamic_dns_regexes = list(DYNAMIC_DNS_PATTERNS)
        for ddns in yaml_ddns:
            # Convert glob "*.ngrok.io" → regex r"\.ngrok\.io"
            regex = re.escape(ddns.lstrip("*")).replace(r"\.", ".")
            if regex not in self._dynamic_dns_regexes:
                self._dynamic_dns_regexes.append(regex)

    def scan_file(self, file_path: str, project_root: str) -> list[Finding]:
        try:
            content = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        rel_path = os.path.relpath(file_path, project_root)
        lines = content.splitlines()
        findings: list[Finding] = []

        # Skip test/example files for P1 (reduce false positives)
        is_test = any(p in rel_path.lower() for p in ["test", "example", "sample", "mock", "fixture"])

        for line_num, line in enumerate(lines, 1):
            # P1: Hardcoded credentials
            for name, pattern, severity in SECRET_PATTERNS:
                if re.search(pattern, line):
                    # Check for placeholders
                    if PLACEHOLDER_PATTERNS.search(line):
                        continue
                    actual_severity = Severity.INFO if is_test else severity
                    if actual_severity == Severity.INFO:
                        continue
                    findings.append(Finding(
                        rule_id="P1",
                        engine="pattern",
                        layer=Layer.BEHAVIOR,
                        severity=actual_severity,
                        confidence=0.9,
                        title=f"Hardcoded credential: {name}",
                        description=f"Found {name} pattern in source code",
                        file_path=rel_path,
                        line=line_num,
                        code_snippet=line.strip()[:120],
                        tags=["credential", "hardcoded_secret"],
                        remediation="Move to environment variable or secrets manager.",
                        references=["CWE-798"],
                    ))
                    break  # One finding per line for P1

            # P2: Base64 suspicious content
            b64_matches = re.findall(r"['\"]([A-Za-z0-9+/]{40,}={0,2})['\"]", line)
            for b64_str in b64_matches:
                try:
                    decoded = base64.b64decode(b64_str).decode("utf-8", errors="replace")
                    is_suspicious = False
                    severity = Severity.MEDIUM

                    if re.search(r"(curl|wget|sh|bash|python|node|chmod|rm\s)", decoded, re.IGNORECASE):
                        severity = Severity.CRITICAL
                        is_suspicious = True
                    elif re.search(r"https?://", decoded):
                        severity = Severity.HIGH
                        is_suspicious = True
                    elif re.search(r"(import|require|eval|exec|Function)", decoded):
                        severity = Severity.HIGH
                        is_suspicious = True

                    if is_suspicious:
                        findings.append(Finding(
                            rule_id="P2",
                            engine="pattern",
                            layer=Layer.BEHAVIOR,
                            severity=severity,
                            confidence=0.85,
                            title="Base64 encoded suspicious content",
                            description="Base64 string decodes to potentially malicious content",
                            file_path=rel_path,
                            line=line_num,
                            code_snippet=line.strip()[:120],
                            evidence=f"Decoded: {decoded[:100]}",
                            tags=["obfuscation", "encoded_payload"],
                            remediation="Remove obfuscated content. Use plain text.",
                        ))
                except Exception:
                    pass

            # P3: Hex/Unicode escape sequences
            hex_count = len(re.findall(r"\\x[0-9a-fA-F]{2}", line))
            unicode_count = len(re.findall(r"\\u[0-9a-fA-F]{4}", line))
            if hex_count >= 5 or unicode_count >= 5:
                total_escapes = hex_count + unicode_count
                try:
                    decoded = line.encode().decode("unicode_escape")
                    evidence = f"Decoded: {decoded.strip()[:80]}"
                except Exception:
                    evidence = f"{total_escapes} escape sequences"

                findings.append(Finding(
                    rule_id="P3",
                    engine="pattern",
                    layer=Layer.BEHAVIOR,
                    severity=Severity.MEDIUM,
                    confidence=0.7,
                    title="Hex/Unicode escape obfuscation",
                    description=f"Line contains {total_escapes} escape sequences, possible obfuscation",
                    file_path=rel_path,
                    line=line_num,
                    code_snippet=line.strip()[:120],
                    evidence=evidence,
                    tags=["obfuscation"],
                    remediation="Use plain text strings. Obfuscation is a red flag.",
                ))

            # P4: Hardcoded IPs
            ip_matches = re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", line)
            for ip in ip_matches:
                # Skip common safe IPs
                if ip.startswith(("127.", "0.0.", "255.")):
                    continue
                if ip.startswith(("10.", "192.168.", "172.")):
                    continue  # Private IPs are usually fine
                severity = Severity.MEDIUM
                findings.append(Finding(
                    rule_id="P4",
                    engine="pattern",
                    layer=Layer.BEHAVIOR,
                    severity=severity,
                    confidence=0.7,
                    title=f"Hardcoded public IP: {ip}",
                    description="Public IP address found in source code",
                    file_path=rel_path,
                    line=line_num,
                    code_snippet=line.strip()[:120],
                    tags=["network", "hardcoded_ip"],
                    remediation="Use domain names with verified ownership instead of bare IPs.",
                ))

            # P4: Suspicious domains
            for pattern in self._dynamic_dns_regexes:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        rule_id="P4",
                        engine="pattern",
                        layer=Layer.BEHAVIOR,
                        severity=Severity.HIGH,
                        confidence=0.85,
                        title="Dynamic DNS domain detected",
                        description="Code references a dynamic DNS service commonly used for C2",
                        file_path=rel_path,
                        line=line_num,
                        code_snippet=line.strip()[:120],
                        tags=["network", "suspicious_domain"],
                        remediation="Verify this domain is legitimate.",
                    ))
                    break

            # P6: Prompt injection patterns (in .md files and strings)
            for pattern, severity in PROMPT_INJECTION_PATTERNS:
                if re.search(pattern, line):
                    findings.append(Finding(
                        rule_id="P6",
                        engine="pattern",
                        layer=Layer.BEHAVIOR,
                        severity=severity,
                        confidence=0.8,
                        title="Prompt injection pattern detected",
                        description="Text contains a known prompt injection pattern",
                        file_path=rel_path,
                        line=line_num,
                        code_snippet=line.strip()[:120],
                        tags=["prompt_injection"],
                        remediation="Remove prompt injection content.",
                        references=["OWASP LLM01"],
                    ))
                    break

        # P5: Known malicious signatures (YAML-driven)
        findings.extend(self._check_p5_signatures(content, rel_path, file_path))

        # P7: High entropy strings (file-level scan)
        findings.extend(self._check_entropy(content, lines, rel_path))

        # P8: IOC matching (C2 domains, malicious infrastructure)
        findings.extend(self._check_p8_ioc(content, lines, rel_path))

        # P9: Obfuscation patterns
        findings.extend(self._check_obfuscation(content, lines, rel_path, file_path))

        return findings

    def _check_p5_signatures(self, content: str, rel_path: str, file_path: str) -> list[Finding]:
        """P5: Match file content against known malicious signature database."""
        findings = []
        file_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        lines = content.splitlines()

        for sig in self._signatures:
            sig_id = sig.get("id", "unknown")
            sig_name = sig.get("name", "Unknown signature")
            severity = _SEVERITY_MAP.get(sig.get("severity", "high"), Severity.HIGH)
            tags = sig.get("tags", [])
            refs = sig.get("references", [])
            pattern = sig.get("pattern", "")

            if not pattern:
                continue

            # Check if signature is multiline
            is_multiline = sig.get("multiline", False)
            flags = re.IGNORECASE | (re.DOTALL if is_multiline else 0)

            try:
                match = re.search(pattern, content, flags)
            except re.error:
                continue

            if match:
                # Find line number of match
                line_num = content[:match.start()].count("\n") + 1
                snippet = lines[line_num - 1].strip()[:120] if line_num <= len(lines) else ""

                findings.append(Finding(
                    rule_id="P5",
                    engine="pattern",
                    layer=Layer.BEHAVIOR,
                    severity=severity,
                    confidence=0.9,
                    title=f"Malicious signature: {sig_name}",
                    description=f"Matched known malicious signature {sig_id}: {sig_name}",
                    file_path=rel_path,
                    line=line_num,
                    code_snippet=snippet,
                    evidence=f"Signature {sig_id} matched (SHA256: {file_hash[:16]}...)",
                    tags=["malicious_signature"] + tags,
                    remediation="This file matches a known malicious pattern. Do not install or execute.",
                    references=refs,
                ))

        return findings

    def _check_p8_ioc(self, content: str, lines: list[str], rel_path: str) -> list[Finding]:
        """P8: Match URLs and domains against known IOC database."""
        findings = []

        # Extract all URLs from content
        url_pattern = re.compile(r'https?://[^\s\'"<>)\]]+', re.IGNORECASE)

        for line_num, line in enumerate(lines, 1):
            urls = url_pattern.findall(line)
            for url in urls:
                # Check against C2 patterns from YAML
                for ioc in self._ioc_patterns:
                    ioc_pattern = ioc.get("pattern", "")
                    if not ioc_pattern:
                        continue
                    try:
                        if re.search(ioc_pattern, url, re.IGNORECASE):
                            ioc_severity = _SEVERITY_MAP.get(
                                ioc.get("severity", "high"), Severity.HIGH
                            )
                            ioc_desc = ioc.get("description", "Known IOC match")
                            findings.append(Finding(
                                rule_id="P8",
                                engine="pattern",
                                layer=Layer.BEHAVIOR,
                                severity=ioc_severity,
                                confidence=0.9,
                                title=f"IOC match: {ioc_desc}",
                                description=f"URL matches known malicious infrastructure pattern",
                                file_path=rel_path,
                                line=line_num,
                                code_snippet=line.strip()[:120],
                                evidence=f"URL: {url[:100]}",
                                tags=["ioc", "network", "c2"],
                                remediation="This URL matches known malicious infrastructure. Remove immediately.",
                            ))
                            break  # One IOC finding per URL
                    except re.error:
                        continue

                # Check for suspicious TLDs in URLs
                for tld in self._suspicious_tlds:
                    # Match TLD at the end of the domain portion
                    if re.search(re.escape(tld) + r'(?:[:/\s]|$)', url, re.IGNORECASE):
                        findings.append(Finding(
                            rule_id="P8",
                            engine="pattern",
                            layer=Layer.BEHAVIOR,
                            severity=Severity.MEDIUM,
                            confidence=0.7,
                            title=f"URL with suspicious TLD: {tld}",
                            description=f"URL uses TLD '{tld}' frequently associated with malicious activity",
                            file_path=rel_path,
                            line=line_num,
                            code_snippet=line.strip()[:120],
                            evidence=f"URL: {url[:100]}",
                            tags=["ioc", "network", "suspicious_tld"],
                            remediation="Verify this domain is legitimate.",
                        ))
                        break  # One TLD finding per URL

        return findings

    def _check_entropy(self, content: str, lines: list[str], rel_path: str) -> list[Finding]:
        """P7: High-entropy string detection."""
        findings = []
        # Extract quoted strings
        string_pattern = re.compile(r"['\"]([A-Za-z0-9+/=_\-]{20,})['\"]")

        for line_num, line in enumerate(lines, 1):
            for match in string_pattern.finditer(line):
                s = match.group(1)
                if _is_uuid(s):
                    continue
                if PLACEHOLDER_PATTERNS.search(s):
                    continue
                # Skip if already caught by P1
                if any(re.search(p, s) for _, p, _ in SECRET_PATTERNS):
                    continue

                entropy = _shannon_entropy(s)
                if entropy > 4.5 and len(s) > 20:
                    findings.append(Finding(
                        rule_id="P7",
                        engine="pattern",
                        layer=Layer.BEHAVIOR,
                        severity=Severity.MEDIUM,
                        confidence=0.6,
                        title=f"High-entropy string (entropy={entropy:.1f})",
                        description="String has high randomness, possibly a secret or encoded payload",
                        file_path=rel_path,
                        line=line_num,
                        code_snippet=line.strip()[:120],
                        evidence=f"String length={len(s)}, entropy={entropy:.2f} (threshold=4.5)",
                        tags=["entropy", "possible_secret"],
                        remediation="If this is a secret, move to environment variable or secrets manager.",
                    ))
        return findings

    def _check_obfuscation(self, content: str, lines: list[str],
                            rel_path: str, file_path: str) -> list[Finding]:
        """P9: Code obfuscation detection."""
        findings = []
        is_js = file_path.endswith((".js", ".mjs", ".cjs"))
        is_py = file_path.endswith(".py")

        patterns = JS_OBFUSCATION_PATTERNS if is_js else PY_OBFUSCATION_PATTERNS if is_py else []

        for pattern, desc in patterns:
            for match in re.finditer(pattern, content):
                # Find line number
                line_num = content[:match.start()].count("\n") + 1
                findings.append(Finding(
                    rule_id="P9",
                    engine="pattern",
                    layer=Layer.BEHAVIOR,
                    severity=Severity.HIGH,
                    confidence=0.8,
                    title=f"Code obfuscation: {desc}",
                    description="Obfuscation pattern detected, common in malicious code",
                    file_path=rel_path,
                    line=line_num,
                    code_snippet=lines[line_num - 1].strip()[:120] if line_num <= len(lines) else "",
                    tags=["obfuscation"],
                    remediation="Request unobfuscated source. Obfuscation in skills is a strong malice indicator.",
                ))

        # Check for extremely long lines (>5000 chars) — common in minified malicious code
        for line_num, line in enumerate(lines, 1):
            if len(line) > 5000:
                findings.append(Finding(
                    rule_id="P9",
                    engine="pattern",
                    layer=Layer.BEHAVIOR,
                    severity=Severity.MEDIUM,
                    confidence=0.6,
                    title="Extremely long line (possible minified/obfuscated code)",
                    description=f"Line is {len(line)} characters long",
                    file_path=rel_path,
                    line=line_num,
                    code_snippet=line[:100] + "...",
                    tags=["obfuscation"],
                    remediation="Review if code minification is expected.",
                ))

        return findings
