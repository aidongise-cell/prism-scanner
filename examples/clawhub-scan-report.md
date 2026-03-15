# ClawHub Skill Security Scan Report

**Scanner**: Prism Scanner v0.1.0
**Date**: 2026-03-15
**Scope**: 13 popular ClawHub skills (8 prompt-only + 5 code-containing)
**Method**: Automated static analysis, no code was executed

---

## Executive Summary

We scanned 13 popular skills from ClawHub, OpenClaw's public skill registry (13,700+ skills).

| Grade | Count | Percentage |
|-------|-------|------------|
| **A (Safe)** | 8 | 62% |
| **C (Caution)** | 1 | 8% |
| **D (Danger)** | 4 | 31% |
| **F (Critical)** | 0 | 0% |

**Key finding: 31% of code-containing skills exhibit behaviors that warrant sandbox isolation.**

Among the 5 skills that contain actual Python code, **4 out of 5 (80%) were rated D (Danger)**, primarily due to:
- Undisclosed outbound network requests
- Reading sensitive environment variables (API keys)
- Hardcoded public IP addresses
- System configuration modification references
- Permission baseline violations

The 8 prompt-only skills (SKILL.md configurations without executable code) all received grade A.

---

## Detailed Results

### Grade A — Safe (8 skills)

These are pure prompt/configuration skills with no executable code:

| Skill | Author | Type | Notes |
|-------|--------|------|-------|
| capability-evolver | navijan | Prompt | Most installed skill on ClawHub (35K+) |
| capability-evolver-turbo | xiaoyinqu | Prompt | Enhanced version |
| self-improving | ivangdavila | Prompt | Self-improvement prompting |
| self-improving-pro | xiaoyinqu | Prompt | Enhanced version |
| super-self-improving | bombfuock | Prompt | Enhanced version |
| agent-browser-0 | kdegeek | Prompt | Browser automation |
| agent-browser-3 | tekkenkk | Prompt | Browser automation |
| doc-summarize-pro | xueyetianya | Prompt | Document summarization |

### Grade C — Caution (1 skill)

| Skill | Author | Findings | Key Issues |
|-------|--------|----------|------------|
| **memos** | fty4 | 1 MEDIUM, 1 LOW | Reads MEMOS_TOKEN from environment |

This skill accesses an API token via environment variable. The behavior is expected for a memo service integration, but users should be aware their token is being read.

### Grade D — Danger (4 skills)

#### aliyun-oss (jixsonwang) — Cloud Storage Uploader

| Metric | Value |
|--------|-------|
| Grade | **D (Danger)** |
| Findings | 1 HIGH, 13 MEDIUM |
| Python files | 8 |

Key risks:
- **S14 HIGH**: References system configuration modification patterns
- **S4 MEDIUM x13**: 13 outbound network requests across multiple files
- Multiple network endpoints contacted without clear documentation

**Recommendation**: Review network destinations before use. Only run in sandboxed environment.

#### hoseo-lms (acogkr) — University LMS Automation

| Metric | Value |
|--------|-------|
| Grade | **D (Danger)** |
| Findings | 26 MEDIUM |
| Python files | 3 |

Key risks:
- **S4 MEDIUM x25**: 25 outbound network requests (auto-attendance, summary functions)
- **P4 MEDIUM**: Hardcoded public IP address (131.0.0.0)
- Extensive network activity for an attendance automation tool

**Recommendation**: Unusually high number of network calls. Verify all endpoints are legitimate university servers.

#### gold (jisuapi) — Gold Price API

| Metric | Value |
|--------|-------|
| Grade | **D (Danger)** |
| Findings | 7 MEDIUM |

Key risks:
- **S4 MEDIUM x6**: Multiple outbound API calls
- **S5 MEDIUM**: Reads JISU_API_KEY from environment

**Recommendation**: Expected behavior for an API client, but the 5+ MEDIUM threshold triggers grade D. Review API endpoints.

#### isbn (jisuapi) — ISBN Lookup

| Metric | Value |
|--------|-------|
| Grade | **D (Danger)** |
| Findings | 1 HIGH, 14 MEDIUM |

Key risks:
- **M1 HIGH**: Permission baseline violation — classified as "formatter" but uses network access
- **S4 MEDIUM x13**: 13 outbound network requests
- **S5 MEDIUM**: Reads JISU_API_KEY from environment

**Recommendation**: Skill description doesn't match behavior. Claims to be a formatter but makes extensive network calls.

---

## Observations

### 1. Prompt-only skills are inherently safer

All 8 prompt-only skills received grade A. This is expected — they contain no executable code, only natural language instructions. However, prompt injection risks (P6) still apply and are checked.

### 2. Code-containing skills need scrutiny

4 out of 5 code-containing skills were rated D. The most common issues:
- **Undisclosed network activity** (S4) — Skills make network requests without clearly documenting where data goes
- **API key reading** (S5) — Skills read environment variables containing credentials
- **Permission mismatches** (M1) — Skill descriptions don't match actual capabilities

### 3. No critical (Grade F) findings in this sample

None of the scanned skills exhibited:
- Data exfiltration chains (S8)
- Download-and-execute patterns (S10)
- Persistence mechanisms (S13)
- Known malware signatures (P5)

This is encouraging for the top skills, but a broader scan of the 13,700+ skill registry may reveal more serious issues.

### 4. The 80% danger rate for code skills is concerning

While Grade D doesn't mean "malicious," it means "proceed with caution." Users installing these skills should understand what network endpoints are being contacted and what credentials are being accessed.

---

## Methodology

- **Scanner**: Prism Scanner v0.1.0 (open source, Apache 2.0)
- **Engines used**: AST analysis with taint tracking, pattern matching, manifest analysis
- **What was NOT done**: No code was executed. No dynamic analysis. No network traffic capture.
- **Limitations**: Static analysis can miss runtime-only behaviors and obfuscated payloads.

---

## How to Reproduce

```bash
pip install prism-scanner
prism scan https://github.com/openclaw/skills/tree/main/skills/<author>/<skill>
```

Or scan any local skill directory:

```bash
prism scan ./my-downloaded-skill/
```

---

*Report generated by [Prism Scanner](https://github.com/aidongise-cell/prism-scanner) — Security scanner for AI Agent skills, plugins, and MCP servers.*
