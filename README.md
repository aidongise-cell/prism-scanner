# :large_blue_diamond: Prism Scanner

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776ab?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square)](LICENSE)
[![Tests: 67 passed](https://img.shields.io/badge/tests-67%20passed-brightgreen?style=flat-square)]()
[![Version: 0.1.0](https://img.shields.io/badge/version-0.1.0-7b2ff7?style=flat-square)]()
[![Awesome](https://img.shields.io/badge/Awesome-AI%20Security-fc60a8?style=flat-square&logo=awesomelists&logoColor=white)](https://github.com/TalEliyahu/Awesome-AI-Security)

**Security scanner for AI Agent skills, plugins, and MCP servers.**

<!-- mcp-name: io.github.aidongise-cell/prism-scanner -->

Prism analyzes code for malicious behavior *before* you install it — and checks your system for leftover threats *after* you uninstall.

> Unlike marketplace-only trust scores, Prism gives you full lifecycle coverage with code-level transparency — pre-install, runtime, and post-uninstall — across every platform, completely open source.

---

## Why Prism?

|                    | Marketplace Trust Scores | **Prism Scanner** |
|--------------------|:------------------------:|:-----------------:|
| **Pre-install**    | :white_check_mark: Reputation score    | :white_check_mark: Deep code analysis         |
| **Post-uninstall** | :x:                      | :white_check_mark: Residue & persistence scan |
| **Inspection**     | Black-box rating         | Code-level, rule-by-rule |
| **Platforms**      | Single ecosystem         | ClawHub, MCP, npm, pip   |
| **Source**         | Closed                   | Open (Apache 2.0)        |
| **Execution**      | Requires upload          | Local-first, offline OK  |

---

## Quick Start

```bash
pip install prism-scanner

# Scan a local skill directory
prism scan ./my-skill/

# Scan a GitHub repo directly
prism scan https://github.com/user/skill-repo

# Check your system for agent residue
prism clean --scan

# Generate a cleanup plan (non-destructive)
prism clean --plan

# Execute cleanup with automatic backups
prism clean --apply
```

### Homebrew (macOS)

```bash
brew tap prismlab/tools
brew install prism-scanner
```

### npx (no install needed)

```bash
npx prism-scanner scan https://github.com/user/skill-repo
```

### GitHub Action (CI/CD)

Add Prism to your CI pipeline — findings appear in GitHub's Security tab:

```yaml
# .github/workflows/prism-scan.yml
name: Prism Security Scan
on: [push, pull_request]

permissions:
  security-events: write
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: aidongise-cell/prism-scanner@main
        with:
          path: '.'
          fail-on: 'high'
```

### MCP Server (Claude Desktop / Cursor / VS Code)

Prism Scanner can run as an MCP server, giving AI assistants direct access to security scanning tools.

```bash
pip install "prism-scanner[mcp]"
```

Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "prism-scanner": {
      "command": "prism-mcp"
    }
  }
}
```

Or for Claude Code:

```bash
claude mcp add prism-scanner prism-mcp
```

This exposes 4 tools: `prism_scan`, `prism_grade`, `prism_clean_scan`, `prism_clean_plan`.

### Docker

```bash
# Build the image
docker build -t prism-scanner .

# Scan a local directory
docker run -v $(pwd)/my-skill:/workspace/target:ro prism-scanner scan /workspace/target

# Scan a remote repo
docker run prism-scanner scan https://github.com/user/skill-repo

# Generate HTML report
docker run -v $(pwd):/workspace/output prism-scanner scan https://github.com/user/repo --format html -o /workspace/output/report.html
```

Or use the published image:
```bash
docker run ghcr.io/prismlab/prism-scanner scan <target>
```

---

## What It Detects

Prism operates across **3 analysis layers**, each targeting a different phase of the agent lifecycle:

| Layer | Focus | Rules | Examples |
|-------|-------|:-----:|---------|
| **1. Code Behavior** (S1-S14) | What the code *does* | 14 | Shell execution, data exfiltration, SSRF, persistence mechanisms, unsafe deserialization, download-and-execute |
| **2. Metadata** (M1-M6, P1-P9) | What the package *claims* vs. *contains* | 15 | Hardcoded credentials, typo-squatting, install scripts, obfuscated payloads, prompt injection, suspicious domains |
| **3. System Residue** (R1-R10) | What was *left behind* | 10 | LaunchAgents, crontab entries, shell config pollution, orphaned credentials, systemd units, login items |

**Total: 39 detection rules** with lightweight intra-file taint analysis.

---

## Example Output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Prism Scanner v0.1.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Target: evil_skill
  Platform: clawhub
  Duration: 42ms

[1/3] Behavior Analysis
  ✗ CRITICAL  S8    Data exfiltration: secrets sent to external endpoint  evil_skill.py:10
  ✗ CRITICAL  S10   Download and execute: fetches remote payload          evil_skill.py:24
  ✗ HIGH      S1    Shell execution with untrusted input                  evil_skill.py:14
  ✗ HIGH      S13   Persistence: writes LaunchAgent plist                 evil_skill.py:36
  ⚠ MEDIUM    S6    Dynamic code execution (eval/exec)                    evil_skill.py:21

[2/3] Metadata Analysis
  ✗ CRITICAL  P1    Hardcoded credential: AWS Access Key                  evil_skill.py:47
  ⚠ MEDIUM    P2    Base64-encoded executable content                     evil_skill.py:50
  ⚠ MEDIUM    P6    Prompt injection pattern in string literal            evil_skill.py:53

[3/3] Residue Scan
  (skipped — use `prism clean --scan` for system-level checks)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Grade: F (Critical)

  Key Risks:
    ▸ CRITICAL: Data exfiltration to external endpoint (S8)
    ▸ CRITICAL: Download and execute remote payload (S10)
    ▸ CRITICAL: Hardcoded AWS credential (P1)
    ▸ HIGH: Shell execution with user input (S1)
    ▸ HIGH: Persistence mechanism installed (S13)

  Behavior Profile:
    exfiltrates_data, executes_shell, downloads_and_executes, installs_persistence

  Recommendation: DO NOT INSTALL — Critical security risks detected.

  Findings: 3 critical, 2 high, 3 medium
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## Grading System

| Grade | Label | Meaning | Recommendation |
|:-----:|-------|---------|----------------|
| **A** | Safe | No findings or only informational | Safe to use |
| **B** | Notice | Only LOW severity findings | Likely safe — minor observations |
| **C** | Caution | 1-4 MEDIUM findings | Review before use — warrants manual inspection |
| **D** | Danger | 1-2 HIGH, or 5+ MEDIUM | Use in sandbox only — significant risks |
| **F** | Critical | Any CRITICAL, or 3+ HIGH | **Do not install** — critical security risks |

---

## Output Formats

```bash
# Rich terminal output (default)
prism scan ./skill/

# Machine-readable JSON
prism scan ./skill/ --format json

# Standalone HTML report
prism scan ./skill/ --format html -o report.html

# SARIF for GitHub Code Scanning
prism scan ./skill/ --format sarif -o results.sarif
```

---

## CI/CD Integration

Add Prism to your GitHub Actions workflow to gate deployments on security findings:

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  prism-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install Prism Scanner
        run: pip install prism-scanner

      - name: Run security scan
        run: prism scan . --format sarif -o results.sarif --fail-on high

      - name: Upload SARIF results
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

The `--fail-on` flag exits with code 1 if any finding meets or exceeds the specified severity (`critical`, `high`, or `medium`), failing the CI pipeline.

---

## Key Features

- **Taint Analysis** — Tracks data flow from sources (env vars, user input) to sinks (shell, network) within each file
- **Multi-Platform** — Scans ClawHub skills, MCP servers, npm packages, and pip packages with platform-aware rules
- **Zero Dependencies on Target** — Pure static analysis; never executes scanned code
- **Residue Scanner** — Detects persistence mechanisms, shell config pollution, and credential leaks left by uninstalled tools
- **Safe Cleanup** — Three-tier workflow (`scan` -> `plan` -> `apply`) with automatic backup and `--rollback`
- **Suppression** — Use `.prismignore` to suppress known findings by rule ID with justification
- **Offline Mode** — Run with `--offline` to skip all external lookups

---

## Adding Custom Rules

Detection rules are defined in YAML files under the `rules/` directory:

```
rules/
├── malicious_signatures.yaml   # Known malicious code signatures and hashes
├── permissions.yaml            # Permission baseline definitions
└── suspicious_domains.yaml     # C2 domains, dynamic DNS, disposable TLDs
```

The pattern engine (`P1-P9`) and manifest engine (`M1-M6`) load rules from these files at scan time. Add entries to extend detection without modifying Python code.

---

## Project Structure

```
src/prism/
├── cli.py                  # CLI entry point and output formatting
├── scanner.py              # Orchestrator — runs engines, collects findings
├── models.py               # Finding, ScanResult, Severity, Layer data models
├── scoring.py              # Letter-grade risk assessment (A-F)
├── report.py               # HTML report generator
├── fetcher.py              # Git clone / URL fetching with security guards
├── cleaner.py              # System cleanup: plan, apply, rollback
├── suppression.py          # .prismignore parsing
├── rules_loader.py         # YAML rule loading
└── engines/
    ├── ast_engine.py       # AST-based analysis (S1-S14)
    ├── pattern_engine.py   # Regex pattern matching (P1-P9)
    ├── manifest_engine.py  # Metadata & manifest analysis (M1-M6)
    ├── residue_engine.py   # System residue scanner (R1-R10)
    └── taint.py            # Intra-file taint tracking
```

---

## Contributing

Contributions are welcome. Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on:

- Adding new detection rules
- Writing and running tests
- Code style and commit conventions

---

## License

[Apache License 2.0](LICENSE) — free for commercial and personal use.

---

## Prism Verified Badge

Show that your project has been scanned by Prism. Add a badge to your README:

**Grade A (Safe):**
```markdown
[![Prism Grade A](https://img.shields.io/badge/Prism-Grade%20A-brightgreen?style=flat-square&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0id2hpdGUiPjxwYXRoIGQ9Ik0xMiAxTDMgNXY2YzAgNS41NSAzLjg0IDEwLjc0IDkgMTIgNS4xNi0xLjI2IDktNi40NSA5LTEyVjVsLTktNHoiLz48L3N2Zz4=)](https://github.com/aidongise-cell/prism-scanner)
```

**All grades:**

| Grade | Badge |
|:-----:|-------|
| A | `![Prism Grade A](https://img.shields.io/badge/Prism-Grade%20A-brightgreen?style=flat-square)` |
| B | `![Prism Grade B](https://img.shields.io/badge/Prism-Grade%20B-green?style=flat-square)` |
| C | `![Prism Grade C](https://img.shields.io/badge/Prism-Grade%20C-yellow?style=flat-square)` |
| D | `![Prism Grade D](https://img.shields.io/badge/Prism-Grade%20D-orange?style=flat-square)` |
| F | `![Prism Grade F](https://img.shields.io/badge/Prism-Grade%20F-red?style=flat-square)` |

Preview:

[![Prism Grade A](https://img.shields.io/badge/Prism-Grade%20A-brightgreen?style=flat-square)](https://github.com/aidongise-cell/prism-scanner) [![Prism Grade B](https://img.shields.io/badge/Prism-Grade%20B-green?style=flat-square)](https://github.com/aidongise-cell/prism-scanner) [![Prism Grade C](https://img.shields.io/badge/Prism-Grade%20C-yellow?style=flat-square)](https://github.com/aidongise-cell/prism-scanner) [![Prism Grade D](https://img.shields.io/badge/Prism-Grade%20D-orange?style=flat-square)](https://github.com/aidongise-cell/prism-scanner) [![Prism Grade F](https://img.shields.io/badge/Prism-Grade%20F-red?style=flat-square)](https://github.com/aidongise-cell/prism-scanner)

---

## Acknowledgments

Prism Scanner is developed by **Prism Lab** to address a gap in the AI agent ecosystem: the lack of transparent, code-level security tooling that works across platforms and covers the full agent lifecycle. We believe developers deserve to understand exactly what a skill or plugin does before trusting it with their system.
