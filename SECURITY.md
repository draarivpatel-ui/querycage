# Security policy

## Scope

`querycage` is a defensive parser and auditor for URL query strings and REST API query parameters. It is designed to reduce exposure to HTTP Parameter Pollution, prototype pollution, NoSQL operator smuggling, sparse-array memory pressure, mass assignment, pagination abuse, sort injection, field projection abuse, secret leakage in URLs, terminal control injection, and parser differential attacks.

The library does not replace parameterized queries, authorization checks, schema validation, or output encoding. Applications must still enforce their own data model and access control rules.

## Reporting

Do not open a public issue for a vulnerability that can plausibly be exploited. Report it privately through the repository owner's GitHub security contact path when available. Include a minimal query input, the policy used, the expected result, the actual result, and whether the issue requires a specific downstream parser or database driver.

## Hardening commitments

- No runtime dependencies.
- Deterministic linear parsing with bounded iterative record traversal.
- Null-prototype object output.
- Raw query text decoded exactly once, with repeated encoding inspected but never flattened.
- Deeply frozen policies and reports.
- No attacker-controlled values in findings or errors.
- Secret values redacted from CLI output.
- Fail-closed policy validation.
- Generated CommonJS checked for byte parity in CI.
- Canonical serialization validates representable trees and rejects cycles, accessors, empty containers, control text, and ambiguous keys.
- TypeScript declaration checks on Linux and Windows.

## Supported versions

Security fixes are applied to the latest published minor version.
