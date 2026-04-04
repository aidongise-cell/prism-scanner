# Changelog

All notable changes to Prism Scanner will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2026-04-03

### Fixed — False Positive Reduction

Systematic false positive reduction based on real-world validation against ClawHub Top-100 skills. Tested on 3 representative skills with severe FP issues: findings reduced 47-93%, grades improved from F to D.

- **S1 suffix matching**: `uvicorn.run()`, `asyncio.run()`, `app.run()`, `flask.run()` no longer trigger shell execution alerts. S1 now requires known shell module prefixes (`subprocess.`, `os.`).
- **S12 deserialization (reversed logic)**: `path.open("rb")`, `gzip.open()`, `csv.writer()` no longer trigger unsafe deserialization. Instead of excluding safe modules (unbounded), S12 now only fires on known dangerous prefixes (`pickle.`, `yaml.`, `marshal.`, `shelve.`).
- **S8 exfiltration suffix matching**: Applied the same prefix guard as S4 to prevent false matches on non-network `.post()`/`.send()` calls.
- **P5 MAL-010 (env var exfiltration)**: `os.environ.get()` for config + `requests.get()` elsewhere in the file no longer triggers CRITICAL. Pattern tightened from whole-file multiline to same-line proximity matching.
- **P5 MAL-011 (SSH key exfiltration)**: Same multiline-to-proximity fix as MAL-010.
- **P5 MAL-012 (browser credential theft)**: `"local state"` in comments + `sqlite3` hundreds of lines away no longer triggers CRITICAL. Same proximity fix.
- **P3 hex/unicode escape**: Regex character classes (`[\x00-\x1f]`), binary magic bytes (PNG/JPEG/ZIP headers), and `re.compile()` patterns no longer trigger obfuscation alerts. Threshold raised from 5 to 8 escapes.
- **P4 hardcoded IP**: Version numbers (`4.1.6.14`), RFC 5737 documentation IPs (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`), and invalid IPs (octet > 255) are now filtered. Lines containing "version" are skipped.
- **S5 noise reduction**: Non-sensitive environment variable reads (e.g., `WECHAT_TOOL_*`, `APP_MODE`) downgraded from LOW to INFO, no longer affecting risk grade. Sensitive patterns (`*_KEY`, `*_SECRET`, `*_TOKEN`) remain MEDIUM.
- **M7 core directory**: Python package directories named `core/` no longer flagged as core dump files. M7 now skips directories, only flags actual files.

### Added

- 9 new regression tests covering all FP fixes (both false-positive elimination and true-positive preservation), bringing the total to **97 tests**.

### Validation Results (Real ClawHub Skills)

| Skill | v0.1.3 | v0.2.1 | Reduction | Grade |
|-------|--------|--------|-----------|-------|
| pensieve (blockchain) | 211 | 18 | -91% | F → D |
| invassistant (finance) | 179 | 12 | -93% | F → D |
| em-intel (engineering) | 118 | 62 | -47% | F → F* |

*em-intel remains F due to a genuine S8 data exfiltration chain (TELEGRAM_BOT_TOKEN → requests.post()), correctly identified.

## [0.2.0] - 2026-03-31

### Added

- **P10: Agent Psychological Manipulation Detection** — detects 6 manipulation tactic categories (gaslighting, guilt-tripping, authority impersonation, urgency/safety bypass, emotional manipulation, contradictory instructions) with 22 regex patterns. Based on Northeastern/Harvard/MIT research.
- **M7: Debug Artifact & Publish Hygiene Detection** — catches source maps, .env files, private keys, IDE configs, and other debug artifacts before they ship. Inspired by the Anthropic Claude Code source map leak (2026-03-31).
- Scanner now collects `.md` files for P10 analysis of skill descriptions.
- 14 new tests (81 total at time of release).

## [0.1.3] - 2026-03-29

### Fixed
- **Colored terminal output**: Integrated `rich` library for colored CLI output — severity levels are now color-coded (CRITICAL/HIGH in red, MEDIUM in yellow), grades are highlighted (A in green, F in white-on-red), and the overall layout uses panels and rules for better readability. Previously, `rich` was declared as a dependency but never imported, resulting in plain text output on all platforms.
- **Windows encoding error**: Fixed `UnicodeDecodeError: 'gbk'` on Windows with Chinese locale by adding explicit `encoding="utf-8"` to YAML rule file loading in `rules_loader.py`.
- **S4 false positives**: Network request detection now requires the receiver object to belong to a known HTTP client module (`requests`, `httpx`, `urllib`, `aiohttp`), eliminating false positives from `dict.get()`, `os.environ.get()`, etc.
- **S6 false positives**: Excluded `re.compile()` from dynamic code execution sinks — regex compilation is not code execution.
- **S12 false positives**: Excluded safe `.open()` callers (`gzip`, `zipfile`, `io`, `codecs`, `pdfplumber`) from unsafe deserialization detection.

## [0.1.0] - 2026-03-15

### Added
- Initial release of Prism Scanner
- 39 detection rules across 3 layers:
  - **Behavior** (S1-S14): Shell execution, data exfiltration, SSRF, persistence, unsafe deserialization, download-and-execute, dynamic eval, credential reads, system file writes, env var access, install-time execution, system config modification
  - **Metadata** (M1-M6, P1-P9): Hardcoded credentials, typo-squatting, install script deep scanning, capability-permission baseline analysis, obfuscated payloads, suspicious domains, prompt injection, base64-encoded commands, Shannon entropy anomaly detection
  - **Residue** (R1-R10): LaunchAgents, crontab, systemd, shell config pollution, orphaned agent data, credential leaks, login items, PATH hijacking
- Lightweight intra-file taint analysis engine tracking source-to-sink data flows
- Letter-grade risk assessment (A-F) with transparent, readable grading logic
- CLI with 4 output formats: terminal (rich), JSON, HTML (standalone), SARIF
- Remote scanning via `git clone` with depth-limited, size-limited security safeguards
- Platform auto-detection for ClawHub, MCP, npm, and pip packages
- System residue scanner with safe cleanup workflow: `scan` -> `plan` -> `apply` -> `rollback`
- CI/CD integration with `--fail-on` severity gating (exit code 1 on threshold breach)
- `.prismignore` suppression support for known/accepted findings
- Offline mode (`--offline`) for air-gapped environments
- 67 automated tests covering all engines, scoring, and CLI behavior
