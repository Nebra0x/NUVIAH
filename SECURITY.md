# Security Policy

NUVIAH takes security defects seriously. This document explains which versions are supported, what should be reported, how to submit a private report, and which behaviors are expected during security research.

Last updated: 2026-08-13

## Supported Versions

| Version | Supported |
|---|:---:|
| `1.0.5` | Yes |
| Earlier versions | No |

Security fixes, when required, will be released in a new version with an updated checksum.

## Reporting a Vulnerability

Please report security vulnerabilities through **GitHub Private Vulnerability Reporting** for the NUVIAH repository:

```text
https://github.com/Nebra0x/nuviah/security
```

After the repository is published and private vulnerability reporting is enabled, use:

```text
Security → Advisories → Report a vulnerability
```

Do **not** disclose security-sensitive details through:

- public GitHub issues;
- pull requests;
- Discussions;
- social media;
- screenshots containing secrets or personal data.

If the private reporting form is temporarily unavailable, open a minimal public issue titled:

```text
Security contact request
```

Do not include vulnerability details in that issue. The repository owner will provide an appropriate private channel.

## Information to Include

A useful report should contain:

- a concise vulnerability title;
- the affected NUVIAH version;
- Linux distribution and version;
- Bash, `curl`, and Python versions;
- the exact command that triggered the issue;
- clear reproduction steps;
- the expected and observed behavior;
- the potential security impact;
- a minimal proof of concept using benign test data;
- sanitized terminal output or report excerpts;
- any suggested mitigation.

Remove or redact:

- access tokens;
- API keys;
- private usernames;
- personal data;
- private report contents;
- IP addresses that are not required to reproduce the issue.

## Vulnerabilities That Are In Scope

Examples include:

- command injection or unintended shell execution;
- arbitrary code execution;
- path traversal;
- arbitrary file creation, overwrite, or deletion;
- unsafe symbolic-link handling;
- temporary-file race conditions;
- exposure of `GITHUB_TOKEN` or other secrets;
- credentials passed to unintended child processes;
- unsafe parsing of untrusted HTTP content;
- report-generation flaws that can lead to code execution or dangerous file behavior;
- bypasses of response-size, request-budget, timeout, or cleanup safeguards;
- checksum or integrity-verification defects;
- privilege-related behavior that occurs without explicit operator authorization.

## Reports That Are Not Security Vulnerabilities

The following are normally expected platform or operational behaviors, not NUVIAH security defects:

- LinkedIn returning HTTP `999`;
- Reddit returning HTTP `403`;
- Internet Archive returning HTTP `429`;
- login walls, CAPTCHA pages, anti-bot responses, or rate limits;
- `BLOCKED`, `INCONCLUSIVE`, or `MANUAL CHECK` classifications;
- false positives or false negatives caused by third-party page changes;
- unavailable, private, renamed, suspended, or deleted third-party accounts;
- vulnerabilities in GitHub, Instagram, TikTok, LinkedIn, or any other external service;
- unsupported operating systems;
- feature requests or requests for additional platforms;
- issues reproducible only in modified, unofficial, or redistributed NUVIAH copies.

Ordinary bugs that do not expose a security risk may be reported through the public issue tracker after removing personal data.

## Research and Testing Rules

Security testing must be limited to:

- the official, unmodified NUVIAH release;
- systems and accounts owned by the researcher;
- environments for which the researcher has explicit authorization;
- benign public test accounts and local test fixtures.

Do not:

- test against third-party infrastructure without authorization;
- evade authentication, CAPTCHA, anti-bot controls, or rate limits;
- perform denial-of-service or high-volume request testing;
- access private accounts or restricted data;
- expose personal data;
- use stolen, shared, or unauthorized credentials;
- redistribute modified or vulnerable copies of NUVIAH;
- publish exploit details before coordinated disclosure is complete.

This policy does not authorize testing of external platforms and does not override their terms, applicable law, or the NUVIAH license.

## Disclosure and Remediation Process

Reports are reviewed on a best-effort basis.

Target response times:

| Stage | Target |
|---|---:|
| Acknowledgement | Within 7 calendar days |
| Initial assessment | Within 14 calendar days |
| Remediation timeline | Determined by severity and complexity |

These are targets, not guaranteed service-level commitments.

When a report is accepted:

1. Nebra0x validates the issue.
2. Severity and affected versions are assessed.
3. A fix is prepared privately.
4. Offline tests and relevant regression tests are run.
5. A new release and checksum are published when required.
6. Public disclosure is coordinated with the reporter.

Do not disclose the vulnerability publicly until a fix is available or written authorization is provided by Nebra0x. Disclosure timing will be agreed case by case.

Reporter credit may be included in release notes or a security advisory unless anonymity is requested.

## No Bug Bounty

NUVIAH does not currently operate a paid bug-bounty program. Submission of a report does not create an entitlement to payment, compensation, commercial rights, or licensing rights.

## License and Copyright

NUVIAH is source-available under the **PolyForm Strict License 1.0.0**.

```text
Copyright © 2026 Nebra0x
```

Security reporting does not grant permission to:

- modify NUVIAH;
- redistribute NUVIAH;
- create derivative works;
- sell or sublicense NUVIAH;
- use NUVIAH commercially.

Any rights not expressly granted by the `LICENSE` file remain reserved by Nebra0x.

## Security Contact

Repository owner:

```text
Nebra0x
https://github.com/Nebra0x
```

Preferred channel:

```text
GitHub Private Vulnerability Reporting
```
