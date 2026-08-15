# Contributing to NUVIAH

Thank you for your interest in NUVIAH.

NUVIAH uses an **issue-first, authorization-based contribution model**. It is source-available under the PolyForm Strict License 1.0.0 and is not an open-source collaborative project.

The public license permits noncommercial use of the official, unmodified software. It does not grant permission to modify, redistribute, publish derivative versions, resell, sublicense, or use NUVIAH commercially.

Last updated: 2026-08-13

## Quick Summary

### Contributions Welcome Without Prior Authorization

You may submit:

- reproducible bug reports;
- platform-behavior observations;
- compatibility reports;
- documentation error reports;
- security reports through the private security channel;
- feature suggestions described at a high level.

### Prior Written Authorization Required

Do not submit code or documentation changes unless Nebra0x has explicitly authorized the contribution in writing.

Authorization is required before:

- modifying NUVIAH source code;
- preparing or submitting a pull request;
- implementing a feature;
- modifying project documentation;
- creating a port, package, integration, or derivative implementation;
- publishing or redistributing an altered copy;
- using NUVIAH in a commercial or revenue-generating context.

Unsolicited pull requests may be closed without review.

## Why This Contribution Model Exists

Nebra0x is the creator and copyright holder of NUVIAH.

The project currently prioritizes:

- a stable official implementation;
- consistent security behavior;
- controlled releases and checksums;
- accurate documentation;
- clear copyright ownership;
- protection against unofficial or misleading derivatives.

Suggestions and reports are valuable, but changes to the official project must remain controlled by the copyright holder.

## Reporting a Bug

Before reporting a bug:

1. Confirm that you are using the official, unmodified NUVIAH release.
2. Run:

   ```bash
   nuviah --version
   nuviah --self-test
   ```

3. Check that the behavior is not already documented as a known platform limitation.
4. Remove usernames, tokens, IP addresses, personal data, and private report contents.

A useful bug report should include:

- NUVIAH version;
- Linux distribution and version;
- Bash version;
- `curl` version;
- Python version;
- ReportLab version, when PDF generation is involved;
- exact command executed;
- expected behavior;
- observed behavior;
- the report `Reason` field, when available;
- minimal sanitized terminal output;
- clear reproduction steps.

Use public test accounts or accounts you own. Do not include operational research data.

## Platform-Behavior Reports

Third-party platforms may change their:

- HTML structure;
- public endpoints;
- redirects;
- login walls;
- anti-bot responses;
- rate limits;
- status codes;
- JavaScript rendering.

A platform-behavior report should include:

- platform name;
- date and UTC time observed;
- NUVIAH version;
- result classification;
- HTTP status;
- effective URL;
- sanitized `Reason` field;
- whether the behavior was reproducible.

The following may be expected platform behavior rather than NUVIAH defects:

- LinkedIn HTTP `999`;
- Reddit HTTP `403`;
- Internet Archive HTTP `429`;
- authentication walls;
- CAPTCHA pages;
- anti-bot responses;
- `BLOCKED`, `INCONCLUSIVE`, or `MANUAL CHECK` outcomes.

## Documentation Corrections

Documentation corrections are welcome as issue reports.

Please provide:

- file name;
- section heading;
- current wording;
- proposed wording;
- reason for the correction;
- supporting technical evidence, when relevant.

Do not submit a documentation pull request unless Nebra0x has first provided written authorization.

## Feature Suggestions

Feature suggestions may be submitted as issues.

A good suggestion explains:

- the problem being solved;
- the expected user benefit;
- the proposed behavior;
- security and privacy implications;
- likely platform limitations;
- whether the feature changes report formats or CLI compatibility.

Do not implement the feature or publish a modified build unless authorization has been granted.

NUVIAH v1.0.5 is currently in a stability-focused phase. Feature expansion is not a priority unless it addresses a verified operational requirement.

## Security Vulnerabilities

Do not report security vulnerabilities through a public issue or pull request.

Follow the instructions in [`SECURITY.md`](SECURITY.md) and use GitHub Private Vulnerability Reporting after it has been enabled for the repository.

Security research does not grant permission to:

- modify or redistribute NUVIAH;
- test third-party systems without authorization;
- bypass authentication or anti-bot controls;
- perform denial-of-service testing;
- access private data;
- publish exploit details before coordinated disclosure.

## Requesting Contribution Authorization

To request authorization, open a minimal issue titled:

```text
Contribution authorization request
```

Include:

- the type of proposed contribution;
- the affected files;
- a concise scope;
- the reason the change is needed;
- whether the work involves code, documentation, packaging, or integration;
- whether any commercial use is involved.

Do not attach modified source code at this stage.

Authorization is valid only when provided explicitly in writing by Nebra0x. Silence, issue discussion, repository access, or the ability to fork the repository does not constitute authorization.

## Authorized Contribution Workflow

When written authorization is granted, Nebra0x will define the permitted scope and submission process.

Authorized contributors must:

- work only within the approved scope;
- use the official current source as the base;
- keep changes minimal and reviewable;
- preserve project branding and copyright notices;
- avoid secrets and personal data;
- keep all user-facing text in English;
- run `bash -n nuviah.sh`;
- run `./nuviah.sh --self-test`;
- update relevant documentation and tests when requested;
- avoid changing the version number, license, checksum policy, or release metadata unless instructed.

Authorization for one contribution does not authorize unrelated changes, future modifications, redistribution, or commercial use.

## Copyright and Contributor Terms

Copyright in the original NUVIAH project remains with:

```text
Copyright © 2026 Nebra0x
```

Before an authorized code or documentation contribution can be merged, the contributor may be required to complete a separate written contributor agreement.

That agreement may require assignment of copyright in the accepted contribution to Nebra0x, to the extent permitted by applicable law, so that the official NUVIAH project can retain clear and centralized ownership.

No contribution will be merged solely because it was submitted. Submission does not guarantee acceptance, payment, attribution beyond agreed credit, commercial rights, or licensing rights.

Do not include third-party code, text, assets, or data unless you have the necessary rights and have disclosed the applicable license and provenance.

## Pull Request Requirements

Pull requests are accepted only after prior written authorization.

An authorized pull request should:

- reference the authorization issue;
- contain one focused change;
- explain the technical rationale;
- include reproduction steps for fixes;
- include test results;
- avoid unrelated formatting changes;
- contain no generated operational reports;
- contain no tokens, credentials, private usernames, or personal data;
- preserve the PolyForm Strict license notice and Nebra0x copyright header.

The repository owner may request changes, decline the contribution, or close the pull request.

## Privacy and Test Data

Use only:

- public demonstration accounts;
- accounts you own;
- synthetic fixtures;
- authorized laboratory data.

Never commit:

- private research reports;
- access tokens;
- credentials;
- personal contact details;
- private usernames;
- sensitive URLs;
- unredacted IP addresses;
- third-party personal data.

The repository `.gitignore` reduces accidental inclusion of generated reports and secrets, but contributors remain responsible for reviewing every staged file.

## Commercial Proposals

The public license does not grant commercial-use rights.

Commercial use, paid services, resale, redistribution, integration into a revenue-generating product, or commercial licensing proposals must be discussed separately with Nebra0x.

Do not open a public issue containing confidential business terms. Use the repository owner's published contact channel when available.

## Communication Standards

Keep reports:

- factual;
- concise;
- reproducible;
- respectful;
- free of personal data;
- focused on the official unmodified release.

Harassment, threats, impersonation, doxxing, or attempts to use NUVIAH against individuals are not accepted.

## License

NUVIAH is source-available under the PolyForm Strict License 1.0.0.

Nothing in this document expands the permissions granted by the [`LICENSE`](LICENSE) file. If this document and the license differ, the license governs.

## Contact

Project owner and copyright holder:

```text
Nebra0x
https://github.com/Nebra0x
```
