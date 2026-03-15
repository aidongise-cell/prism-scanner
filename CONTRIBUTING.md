# Contributing to Prism Scanner

Thank you for your interest in contributing to Prism Scanner! Whether you are adding a new
detection rule, fixing a bug, or improving documentation, this guide will help you get
started.

## Getting Started

```bash
git clone https://github.com/prismlab/prism-scanner.git
cd prism-scanner
pip install -e ".[dev]"
python tests/test_scanner.py
```

All tests should pass before you begin making changes.

## Development Setup

- **Python 3.10+** is required.
- Install in editable mode with dev dependencies: `pip install -e ".[dev]"`
- Run the test suite: `python tests/test_scanner.py`

## Project Structure

```
src/prism/
  __main__.py          # Entry point (python -m prism)
  cli.py               # Command-line interface
  scanner.py           # Top-level scan orchestration
  models.py            # Data models (Finding, ScanResult, etc.)
  scoring.py           # Risk score calculation
  rules_loader.py      # Loads YAML rule definitions
  fetcher.py           # Git clone / package download
  cleaner.py           # Temporary directory cleanup
  report.py            # HTML / JSON report generation
  suppression.py       # Finding suppression logic
  engines/
    ast_engine.py      # AST-based behavioral analysis
    pattern_engine.py  # Regex pattern matching
    manifest_engine.py # Package manifest / metadata checks
    residue_engine.py  # Filesystem residue detection
    taint.py           # Taint tracking utilities
rules/
  malicious_signatures.yaml   # Known malicious code signatures
  permissions.yaml            # Dangerous permission patterns
  suspicious_domains.yaml     # Suspicious network destinations
tests/
  test_scanner.py      # Main test suite
  fixtures/            # Sample packages for testing
```

## Adding a New Detection Rule

This is the most common type of contribution. Follow these steps:

### 1. Choose the Right Engine

| Engine     | File                    | Use when detecting...                              |
| ---------- | ----------------------- | -------------------------------------------------- |
| **AST**    | `ast_engine.py`         | Code behavior: function calls, imports, data flows |
| **Pattern**| `pattern_engine.py`     | Text patterns: suspicious strings, obfuscation     |
| **Manifest** | `manifest_engine.py`  | Package metadata: install scripts, dependencies    |
| **Residue**| `residue_engine.py`     | System artifacts: hidden files, compiled binaries  |

### 2. Add the Detection Logic

Open the appropriate engine file under `src/prism/engines/` and add your detection
function or extend an existing one. Each detection should produce a `Finding` (see
`models.py`) with:

- **rule_id** --- unique identifier (see naming convention below)
- **title** --- short human-readable name
- **description** --- what was found and why it matters
- **severity** --- `critical`, `high`, `medium`, or `low`
- **file_path** --- the file where the issue was found
- **line_number** --- if applicable

### 3. Add a Test Case

Add at least two tests to `tests/test_scanner.py`:

- **True positive** --- a fixture that should trigger the rule.
- **False positive** --- a benign fixture that should *not* trigger the rule.

Place any fixture files in `tests/fixtures/`.

### 4. Update YAML Rules (if applicable)

If your rule is pattern-based and can be expressed as a YAML entry, add it to the
appropriate file under `rules/`:

- `malicious_signatures.yaml` --- known malicious code patterns
- `permissions.yaml` --- dangerous permission or capability patterns
- `suspicious_domains.yaml` --- C2 servers, exfiltration endpoints

### 5. Document the Rule

Include a comment or docstring with:

- **Rule ID** (e.g., `S012`)
- **Description** of what it detects
- **Severity logic** --- why it is rated at that level
- **Example** --- a minimal code snippet that triggers the rule

## Adding YAML Rules

YAML rules live in the `rules/` directory. Each entry typically follows this structure:

```yaml
- id: P015
  title: Base64-encoded shell command
  pattern: "base64\\.b64decode\\(.*sh\\s+-c"
  severity: high
  description: >
    Detects base64-decoded strings being piped to a shell,
    a common technique for hiding malicious commands.
```

Fields:

| Field         | Required | Description                                |
| ------------- | -------- | ------------------------------------------ |
| `id`          | Yes      | Unique rule ID (see naming convention)     |
| `title`       | Yes      | Short name                                 |
| `pattern`     | Yes      | Regex pattern (Python `re` syntax)         |
| `severity`    | Yes      | `critical`, `high`, `medium`, or `low`     |
| `description` | Yes      | Explanation of what and why                 |

After adding a YAML rule, run the tests to make sure the rule loads without errors and
matches the expected fixtures.

## Rule Naming Convention

Rule IDs use a prefix letter followed by a sequential number:

| Prefix | Engine   | Example |
| ------ | -------- | ------- |
| `S`    | AST (Static/behavioral) | `S001` |
| `P`    | Pattern (regex)         | `P001` |
| `M`    | Manifest (metadata)     | `M001` |
| `R`    | Residue (filesystem)    | `R001` |

Check existing rules to find the next available number in the sequence.

## Code Style

- **Python 3.10+** --- use modern syntax (match statements, `X | Y` union types, etc.)
- **Type hints** --- annotate all function signatures.
- **Docstrings** --- required for all public classes and methods.
- **Line length** --- 100 characters soft limit.
- **Imports** --- standard library first, then third-party, then local. One blank line
  between groups.

## Testing

- Run the full suite: `python tests/test_scanner.py`
- Every new detection rule must have at least one true-positive and one false-positive test.
- Test fixtures go in `tests/fixtures/`. Use minimal examples --- just enough code to
  trigger (or not trigger) the rule.
- If your change affects scoring, verify that overall risk scores still make sense for the
  existing fixtures.

## Pull Request Process

1. **Fork** the repository and create a feature branch from `main`.
2. **Make your changes** following the guidelines above.
3. **Run all tests** and confirm they pass.
4. **Open a Pull Request** against `main` with:
   - A clear title (e.g., "Add rule S012: detect eval of environment variables")
   - A description explaining what the rule detects and why
   - Links to any related issues
5. A maintainer will review your PR. We may request changes --- this is normal and
   collaborative, not adversarial.
6. Once approved, a maintainer will merge your PR.

## Questions?

Open a discussion on GitHub or reach out to the maintainers. We are happy to help you land
your first contribution.
