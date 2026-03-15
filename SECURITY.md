# Security Policy

Prism Scanner is a security tool designed to detect malicious code in open-source packages.
We take the security of this project seriously --- a vulnerability in the scanner itself
could undermine the trust of every user who depends on it.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

**Do NOT open a public GitHub Issue for security vulnerabilities.**

Please report vulnerabilities by emailing **security@prismlab.dev** with:

- A clear description of the vulnerability
- Steps to reproduce or a proof-of-concept
- The impact you believe this has
- Any suggested fix (optional but appreciated)

### Response Timeline

| Stage           | Commitment     |
| --------------- | -------------- |
| Acknowledgement | Within 48 hours |
| Assessment      | Within 7 days   |
| Fix (critical)  | Within 14 days  |
| Fix (moderate)  | Within 30 days  |
| Public advisory | After fix ships |

We will keep you informed of our progress throughout the process.

## What to Report

- **Vulnerabilities in the scanner itself** --- e.g., a crafted package that causes code
  execution during scanning, denial of service, or information disclosure.
- **False negatives** --- known malicious patterns or techniques that Prism fails to
  detect. If you find malware in the wild that slips past the scanner, we want to know.
- **Detection bypass** --- ways to obfuscate or structure malicious code so that it evades
  one or more detection engines (AST, Pattern, Manifest, Residue).
- **Path traversal or file-write issues** --- any way a scanned package could write files
  outside the temporary scan directory.
- **Report injection** --- ways to inject misleading content into HTML or JSON reports
  through crafted package metadata.

## What NOT to Report via This Channel

| Instead of emailing security@ | Do this                        |
| ------------------------------ | ------------------------------ |
| Feature requests               | Open a GitHub Issue            |
| General bugs                   | Open a GitHub Issue            |
| Questions about usage          | Use GitHub Discussions         |
| Detection rule suggestions     | Open a GitHub Issue or PR      |

## Scanner Self-Security

Prism Scanner is designed with a defense-in-depth approach to ensure that scanning a
malicious package never compromises the host system:

- **No code execution.** Prism never imports, evaluates, or executes any code from scanned
  packages. All analysis is performed through static inspection (AST parsing, regex
  matching, manifest reading, and filesystem checks).
- **Safe git clone.** Repositories are cloned with `--depth 1` into isolated temporary
  directories. No post-clone hooks are executed.
- **Path traversal prevention.** All file paths are resolved and validated to stay within
  the scan working directory. Symlinks pointing outside the scan boundary are not followed.
- **HTML output escaping.** All package metadata and detection results are escaped before
  being inserted into HTML reports, preventing cross-site scripting (XSS) via crafted
  package names, descriptions, or file contents.
- **Temporary file cleanup.** Scanned repositories are cleaned up after analysis completes,
  leaving no residual attacker-controlled content on disk.

## Disclosure Policy

We follow a **coordinated disclosure** model:

1. The reporter emails **security@prismlab.dev** with the vulnerability details.
2. We acknowledge receipt within 48 hours and begin assessment.
3. We work on a fix privately and coordinate with the reporter on timing.
4. We aim to release a fix within the timelines stated above.
5. After the fix is released, we publish a security advisory on GitHub.
6. The reporter is credited (unless they prefer to remain anonymous).

We ask that reporters give us a **90-day window** from the initial report before public
disclosure. If we have not addressed the issue within 90 days, the reporter is free to
disclose publicly.

## Hall of Fame

We gratefully acknowledge security researchers who have helped improve Prism Scanner
through responsible disclosure.

*No entries yet --- be the first!*

---

Thank you for helping keep Prism Scanner and its users safe.
