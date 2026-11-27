# Security policy

## Reporting a vulnerability

Use the private GitHub Security Advisory form at [Report a vulnerability](https://github.com/draarivpatel-ui/querycage/security/advisories/new). Do not open a public issue, pull request or discussion with exploit details.

Never include a live secret, token, cookie, private key, victim hostname or proprietary payload in a report. Use synthetic values and redacted transcripts.

## Supported versions

| Version | Status |
| --- | --- |
| 1.x | Supported |

Security fixes are applied to the latest release line.

## Scope

This policy covers query string parsing, auditing, sanitizing, canonical serialization and REST API query controls.

In scope:

- A prototype pollution, NoSQL operator, HTTP parameter pollution or parser differential bypass.
- A sparse array, nesting, size or decoding bound bypass that causes excessive work or memory use.
- A sanitizer or serializer result that remains unsafe after its own success report.
- A finding, error or CLI output path that echoes secret parameter values.

Out of scope:

- SQL or NoSQL injection caused by an application that bypasses parameterized queries after validation.
- Authorization or schema failures outside the query parsing boundary.
- Attacks that require modifying Node.js or the runtime platform.

## Coordinated disclosure

- Acknowledgment: within 48 hours.
- Initial assessment: within 7 calendar days.
- Fix or mitigation plan: within 30 calendar days for confirmed high-impact reports.
- Coordinated public disclosure: up to 90 days by default, adjusted by mutual agreement when exploitation or user risk requires a different date.
