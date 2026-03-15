"""HTML report generator for Prism Scanner."""
import html
from datetime import datetime
from pathlib import Path

from .models import ScanResult, Finding, Severity, Layer


def _severity_color(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "#ff4757",
        Severity.HIGH: "#ff6b35",
        Severity.MEDIUM: "#ffa502",
        Severity.LOW: "#747d8c",
        Severity.INFO: "#57606f",
    }.get(severity, "#57606f")


def _grade_color(grade: str) -> str:
    return {
        "F": "#ff4757",
        "D": "#ff6b35",
        "C": "#ffa502",
        "B": "#a0d468",
        "A": "#2ed573",
    }.get(grade, "#747d8c")


def _grade_info(grade: str) -> tuple[str, str]:
    """Return (label, recommendation) for a grade."""
    from .scoring import GRADE_INFO
    info = GRADE_INFO.get(grade, {"label": grade, "recommendation": ""})
    return info["label"], info["recommendation"]


def _render_finding(f: Finding) -> str:
    sev_color = _severity_color(f.severity)
    sev_label = html.escape(f.severity.value.upper())
    rule_id = html.escape(f.rule_id)
    title = html.escape(f.title)
    description = html.escape(f.description)

    location = ""
    if f.file_path:
        location = html.escape(f.file_path)
        if f.line:
            location += f":{f.line}"

    snippet_html = ""
    if f.code_snippet:
        snippet_html = f"""
        <div class="code-block">
            <pre><code>{html.escape(f.code_snippet)}</code></pre>
        </div>"""

    evidence_html = ""
    if f.evidence:
        evidence_html = f"""
        <div class="evidence">
            <strong>Evidence:</strong> {html.escape(f.evidence)}
        </div>"""

    remediation_html = ""
    if f.remediation:
        remediation_html = f"""
        <div class="remediation">
            <strong>Remediation:</strong> {html.escape(f.remediation)}
        </div>"""

    tags_html = ""
    if f.tags:
        tag_spans = "".join(
            f'<span class="tag">{html.escape(t)}</span>' for t in f.tags
        )
        tags_html = f'<div class="finding-tags">{tag_spans}</div>'

    refs_html = ""
    if f.references:
        ref_items = "".join(
            f"<li>{html.escape(r)}</li>" for r in f.references
        )
        refs_html = f"""
        <div class="references">
            <strong>References:</strong>
            <ul>{ref_items}</ul>
        </div>"""

    return f"""
    <details class="finding">
        <summary>
            <span class="severity-badge" style="background:{sev_color}">{sev_label}</span>
            <span class="rule-id">{rule_id}</span>
            <span class="finding-title">{title}</span>
            {f'<span class="location">{location}</span>' if location else ''}
        </summary>
        <div class="finding-body">
            <p class="description">{description}</p>
            {snippet_html}
            {evidence_html}
            {tags_html}
            {remediation_html}
            {refs_html}
        </div>
    </details>"""


def _render_layer_section(label: str, layer_num: int, findings: list[Finding]) -> str:
    if not findings:
        return ""

    sorted_findings = sorted(findings, key=lambda x: x.severity_score, reverse=True)
    findings_html = "\n".join(_render_finding(f) for f in sorted_findings)

    counts_parts = []
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    for sev in ["critical", "high", "medium", "low", "info"]:
        if sev in counts:
            color = _severity_color(Severity(sev))
            counts_parts.append(
                f'<span class="severity-badge small" style="background:{color}">'
                f'{counts[sev]} {sev}</span>'
            )

    return f"""
    <div class="layer-section">
        <details open>
            <summary class="layer-header">
                <span class="layer-num">[{layer_num}/3]</span>
                <span class="layer-label">{html.escape(label)}</span>
                <span class="layer-counts">{' '.join(counts_parts)}</span>
            </summary>
            <div class="findings-list">
                {findings_html}
            </div>
        </details>
    </div>"""


def generate_html_report(result: ScanResult) -> str:
    """Generate a standalone HTML report from scan results."""

    findings = result.active_findings
    behavior = [f for f in findings if f.layer == Layer.BEHAVIOR]
    metadata = [f for f in findings if f.layer == Layer.METADATA]
    residue = [f for f in findings if f.layer == Layer.RESIDUE]

    # Count by severity
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

    target_name = html.escape(Path(result.target.path).name)
    target_path = html.escape(result.target.path)
    platform = html.escape(result.target.platform or "auto-detected")
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    risk_color = _grade_color(result.grade)
    grade_label, recommendation_text = _grade_info(result.grade)
    risk_level_label = html.escape(grade_label.upper())
    recommendation = html.escape(recommendation_text)

    # Severity count badges for summary
    severity_order = ["critical", "high", "medium", "low", "info"]
    count_badges = ""
    for sev in severity_order:
        c = counts.get(sev, 0)
        if c > 0:
            color = _severity_color(Severity(sev))
            count_badges += (
                f'<div class="count-item">'
                f'<span class="count-num" style="color:{color}">{c}</span>'
                f'<span class="count-label">{sev}</span>'
                f'</div>'
            )

    # Key risks
    drivers_html = ""
    if result.key_risks:
        driver_items = "\n".join(
            f"<li>{html.escape(d)}</li>" for d in result.key_risks[:8]
        )
        drivers_html = f"""
    <div class="card">
        <h2>Key Risks</h2>
        <ul class="drivers-list">{driver_items}</ul>
    </div>"""

    # Behavior tags
    tags_html = ""
    if result.behavior_tags:
        tag_spans = "".join(
            f'<span class="behavior-tag">{html.escape(t)}</span>'
            for t in result.behavior_tags
        )
        tags_html = f"""
    <div class="card">
        <h2>Behavior Profile</h2>
        <div class="tags-container">{tag_spans}</div>
    </div>"""

    # Layer sections
    layers_html = ""
    layers_html += _render_layer_section("Behavior Analysis", 1, behavior)
    layers_html += _render_layer_section("Metadata Analysis", 2, metadata)
    layers_html += _render_layer_section("Residue Scan", 3, residue)

    if not layers_html:
        layers_html = """
    <div class="card" style="text-align:center;padding:2rem">
        <p style="color:#2ed573;font-size:1.1rem">No findings detected.</p>
    </div>"""

    # Build full HTML
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Prism Scanner Report — {target_name}</title>
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
body{{
    background:#1a1a2e;
    color:#e0e0e0;
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
    line-height:1.6;
    min-height:100vh;
}}
.container{{max-width:960px;margin:0 auto;padding:1.5rem}}

/* Header */
.header{{
    border-bottom:2px solid #00d2ff;
    padding-bottom:1rem;
    margin-bottom:1.5rem;
}}
.logo{{
    font-size:1.6rem;font-weight:700;
    background:linear-gradient(135deg,#00d2ff,#7b2ff7);
    -webkit-background-clip:text;-webkit-text-fill-color:transparent;
    background-clip:text;
    letter-spacing:.5px;
}}
.header-meta{{color:#747d8c;font-size:.85rem;margin-top:.4rem}}
.header-meta span{{margin-right:1.2rem}}

/* Cards */
.card{{
    background:#16213e;
    border-radius:8px;
    padding:1.25rem;
    margin-bottom:1rem;
    border:1px solid #1e3054;
}}
.card h2{{
    font-size:1rem;
    color:#00d2ff;
    margin-bottom:.75rem;
    text-transform:uppercase;
    letter-spacing:.8px;
    font-weight:600;
}}

/* Executive Summary */
.summary-grid{{display:grid;grid-template-columns:auto 1fr;gap:1.5rem;align-items:center}}
.score-display{{text-align:center;min-width:140px}}
.score-ring{{
    width:120px;height:120px;
    border-radius:50%;
    display:flex;flex-direction:column;
    align-items:center;justify-content:center;
    margin:0 auto .5rem;
    position:relative;
}}
.score-ring::before{{
    content:'';position:absolute;inset:0;border-radius:50%;
    border:6px solid #1e3054;
}}
.score-ring::after{{
    content:'';position:absolute;inset:0;border-radius:50%;
    border:6px solid transparent;border-top-color:var(--ring-color);
    transform:rotate(-90deg);
}}
.score-num{{font-size:3.2rem;font-weight:700;line-height:1}}
.risk-badge{{
    display:inline-block;
    padding:.2rem .7rem;
    border-radius:4px;
    font-size:.8rem;font-weight:600;
    text-transform:uppercase;letter-spacing:.5px;
}}
.summary-details{{display:flex;flex-direction:column;gap:.75rem}}
.recommendation{{
    padding:.6rem .8rem;
    border-left:3px solid var(--rec-color);
    background:rgba(0,0,0,.2);
    border-radius:0 4px 4px 0;
    font-size:.9rem;
}}
.counts-row{{display:flex;gap:1rem;flex-wrap:wrap}}
.count-item{{text-align:center}}
.count-num{{display:block;font-size:1.4rem;font-weight:700}}
.count-label{{font-size:.7rem;text-transform:uppercase;color:#747d8c}}

/* Drivers */
.drivers-list{{list-style:none;padding:0}}
.drivers-list li{{
    padding:.35rem 0;
    border-bottom:1px solid rgba(255,255,255,.05);
    font-size:.9rem;
}}
.drivers-list li::before{{content:'\\25B8';color:#00d2ff;margin-right:.5rem}}

/* Tags */
.tags-container{{display:flex;flex-wrap:wrap;gap:.5rem}}
.behavior-tag{{
    background:rgba(0,210,255,.12);
    color:#00d2ff;
    padding:.25rem .6rem;
    border-radius:12px;
    font-size:.8rem;
    border:1px solid rgba(0,210,255,.25);
}}

/* Layer sections */
.layer-section{{margin-bottom:1rem}}
.layer-header{{
    background:#16213e;
    padding:.8rem 1rem;
    border-radius:8px;
    border:1px solid #1e3054;
    cursor:pointer;
    list-style:none;
    display:flex;align-items:center;gap:.6rem;
    font-weight:600;
}}
.layer-header::-webkit-details-marker{{display:none}}
.layer-header::before{{
    content:'\\25B6';font-size:.65rem;color:#00d2ff;
    transition:transform .15s;
}}
details[open]>.layer-header::before{{transform:rotate(90deg)}}
.layer-num{{color:#747d8c;font-size:.85rem}}
.layer-label{{flex:1}}
.layer-counts{{display:flex;gap:.3rem}}
.severity-badge{{
    display:inline-block;
    padding:.15rem .5rem;
    border-radius:3px;
    font-size:.7rem;font-weight:600;
    color:#fff;text-transform:uppercase;
}}
.severity-badge.small{{font-size:.65rem;padding:.1rem .4rem}}

/* Findings */
.findings-list{{padding:.5rem 0 0 0}}
.finding{{margin:.4rem 0}}
.finding>summary{{
    list-style:none;
    padding:.5rem .75rem;
    background:rgba(0,0,0,.2);
    border-radius:6px;
    cursor:pointer;
    display:flex;align-items:center;gap:.5rem;
    font-size:.88rem;
    border:1px solid transparent;
    transition:border-color .15s;
}}
.finding>summary:hover{{border-color:#1e3054}}
.finding>summary::-webkit-details-marker{{display:none}}
.finding>summary::before{{
    content:'\\25B6';font-size:.55rem;color:#747d8c;
    transition:transform .15s;
}}
.finding[open]>summary::before{{transform:rotate(90deg)}}
.rule-id{{color:#747d8c;font-family:monospace;font-size:.8rem;min-width:2.5rem}}
.finding-title{{flex:1;color:#e0e0e0}}
.location{{color:#57606f;font-family:monospace;font-size:.78rem}}
.finding-body{{padding:.75rem 1rem;font-size:.88rem}}
.description{{margin-bottom:.6rem;color:#a0a8b4}}
.code-block{{
    background:#0d1117;
    border-radius:6px;
    padding:.7rem .9rem;
    margin:.5rem 0;
    overflow-x:auto;
    border:1px solid #1e3054;
}}
.code-block pre{{margin:0}}
.code-block code{{
    font-family:"SF Mono",Monaco,Consolas,"Liberation Mono",monospace;
    font-size:.8rem;color:#c9d1d9;
    white-space:pre;
}}
.evidence{{
    background:rgba(255,165,2,.06);
    border-left:3px solid #ffa502;
    padding:.4rem .7rem;
    border-radius:0 4px 4px 0;
    margin:.5rem 0;
    font-size:.85rem;
}}
.remediation{{
    background:rgba(46,213,115,.06);
    border-left:3px solid #2ed573;
    padding:.4rem .7rem;
    border-radius:0 4px 4px 0;
    margin:.5rem 0;
    font-size:.85rem;
}}
.finding-tags{{display:flex;flex-wrap:wrap;gap:.3rem;margin:.5rem 0}}
.tag{{
    background:rgba(116,125,140,.15);
    color:#a0a8b4;
    padding:.1rem .45rem;
    border-radius:3px;
    font-size:.72rem;
}}
.references{{margin:.5rem 0;font-size:.82rem}}
.references ul{{padding-left:1.2rem;margin-top:.2rem}}
.references li{{color:#747d8c}}

/* Footer */
.footer{{
    text-align:center;
    padding:1.5rem 0;
    color:#57606f;
    font-size:.78rem;
    border-top:1px solid #1e3054;
    margin-top:1.5rem;
}}
.footer a{{color:#00d2ff;text-decoration:none}}

/* Responsive */
@media(max-width:640px){{
    .summary-grid{{grid-template-columns:1fr}}
    .score-display{{margin-bottom:.5rem}}
    .counts-row{{justify-content:center}}
    .container{{padding:1rem}}
}}
</style>
</head>
<body>
<div class="container">

    <!-- Header -->
    <div class="header">
        <div class="logo">&#9670; Prism Scanner</div>
        <div class="header-meta">
            <span>v0.1.0</span>
            <span>Scanned: {html.escape(scan_time)}</span>
            <span>Target: {target_name}</span>
            <span>Platform: {platform}</span>
            {f'<span>Duration: {result.scan_duration_ms}ms</span>' if result.scan_duration_ms else ''}
        </div>
    </div>

    <!-- Executive Summary -->
    <div class="card">
        <h2>Executive Summary</h2>
        <div class="summary-grid">
            <div class="score-display">
                <div class="score-ring" style="--ring-color:{risk_color}">
                    <span class="score-num" style="color:{risk_color}">{html.escape(result.grade)}</span>
                </div>
                <span class="risk-badge" style="background:{risk_color};color:#fff">{risk_level_label}</span>
            </div>
            <div class="summary-details">
                <div class="recommendation" style="--rec-color:{risk_color}">
                    {recommendation}
                </div>
                <div class="counts-row">
                    {count_badges}
                </div>
            </div>
        </div>
    </div>

    {drivers_html}
    {tags_html}

    <!-- Findings -->
    {layers_html}

    <!-- Footer -->
    <div class="footer">
        Generated by <a href="#">Prism Scanner</a> &middot; {html.escape(scan_time)}
    </div>

</div>
</body>
</html>"""
