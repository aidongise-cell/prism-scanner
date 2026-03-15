# Changelog

All notable changes to Prism Scanner will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
