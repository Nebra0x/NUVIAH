# Changelog

All notable public changes to NUVIAH are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html) for public releases.

Development-only builds created before the first public release are intentionally omitted.

## [Unreleased]

No unreleased changes are currently documented.

## [1.0.5] - 2026-08-13

### Added

- Initial stable public release of NUVIAH.
- Exact username analysis across 12 configured public sources.
- Source-specific Strong API, API/JSON, heuristic, limited, and manual verification methods.
- Conservative result model with the following terminal states:
  - `CONFIRMED`
  - `PROBABLE`
  - `NOT FOUND`
  - `BLOCKED`
  - `INCONCLUSIVE`
  - `ERROR`
  - `MANUAL CHECK`
- Optional controlled similar-username discovery with configurable similarity threshold and variant limit.
- Optional public historical snapshot checks through Wayback availability queries.
- TXT, CSV, JSON, and branded PDF report generation.
- Executive summary, evidence register, methodology, and result legend in PDF reports.
- Dynamically centered NUVIAH terminal branding.
- English-language terminal interface, help text, errors, reports, and documentation.
- General CLI help, scan-specific help, result legend, platform list, dependency checks, and offline self-tests.
- Optional GitHub API authentication through the `GITHUB_TOKEN` environment variable.
- Configurable request timeout, connection timeout, delay, request budget, and User-Agent.
- Manual Discord profile-link support when a known numeric user ID is supplied.

### Security

- Enabled strict Bash execution with `set -Eeuo pipefail`.
- Applied private default permissions to generated reports through `umask 077`.
- Added temporary-directory cleanup on normal exit and termination signals.
- Added an 8 MiB maximum response-body size per request.
- Added request-budget validation before scans are executed.
- Added validation and canonical decimal handling for numeric CLI options.
- Added conservative authentication-wall, anti-bot, redirect, and ambiguous-response handling.
- Added protection against newline injection in custom User-Agent and GitHub token values.
- Isolated the optional GitHub token from child-process environments.
- Added CSV field hardening and safe report filenames.
- Added verification that every requested report is created and non-empty.

### Documentation

- Added a professional English README with installation, usage, CLI reference, methodology, safeguards, known limitations, responsible-use guidance, and commercial-use terms.
- Added responsive NUVIAH header artwork for GitHub light and dark themes.
- Added an approved demonstration PDF and report preview.
- Added PolyForm Strict License 1.0.0 licensing materials and copyright attribution to Nebra0x.
- Added repository ignore rules to prevent accidental publication of operational reports, secrets, temporary files, backups, and local build artifacts.

### Known limitations

- Platform HTML, redirects, login walls, anti-bot systems, and rate limits may change without notice.
- LinkedIn may return non-standard responses such as HTTP `999`, resulting in `INCONCLUSIVE`.
- Reddit may restrict its public JSON endpoint, including HTTP `403` responses.
- Wayback availability requests may be rate-limited with HTTP `429`.
- Discord and BeReal remain manual sources for username-only verification.
- Telegram endpoints do not independently establish whether the public entity is a user, bot, channel, or group.
- Similar usernames and endpoint availability do not establish identity correlation.

[Unreleased]: https://github.com/Nebra0x/nuviah/compare/v1.0.5...HEAD
[1.0.5]: https://github.com/Nebra0x/nuviah/releases/tag/v1.0.5
