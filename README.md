# querycage

Zero-dependency URL query-string security firewall for Node.js APIs.

`querycage` parses and audits query strings before application code, query builders, or database layers can interpret hostile input. It is built for Express, Fastify, Next.js, Hono, and plain Node HTTP services that need deterministic handling for HTTP Parameter Pollution, prototype pollution, NoSQL operator smuggling, sparse array denial of service, mass assignment, pagination abuse, sort injection, and sparse field projection abuse.

The package has no runtime dependencies. It ships native ESM, generated CommonJS, complete TypeScript declarations, policy presets, typed errors, a CLI, and deterministic canonicalization.

## Install

```sh
npm install querycage
```

Node.js 18 or newer is required.

## Quick start

```js
import { parseQuery, auditQuery, QueryCageError } from 'querycage';

try {
  const query = parseQuery('page=1&limit=20', 'strict');
  console.log(query.page);
} catch (error) {
  if (error instanceof QueryCageError) {
    console.log(error.code, error.param);
  }
}

const report = auditQuery('role=user&role=admin', 'strict');
console.log(report.safe, report.findings);
```

`parseQuery` throws a typed `QueryCageError` for the first error finding. `auditQuery` does not throw for hostile query text. It returns a deeply frozen report with machine-readable findings. Findings never include attacker-controlled parameter values.

## What is blocked

### HTTP Parameter Pollution

Duplicate scalar keys are rejected by default.

```text
role=user&role=admin
id=1&id=2
```

Configurable duplicate policies are available.

- `reject` makes duplicates unsafe.
- `first` deterministically keeps the first value and emits a warning.
- `last` deterministically keeps the last value and emits a warning.
- `allowlist` collects duplicates for named top-level parameters into arrays.

The parser also detects scalar and structured shape confusion such as `id=1&id[]=2`, semicolon delimiter smuggling such as `a=1;b=2`, and normalization collisions such as `id=1&%69d=2`.

### Prototype pollution and path injection

Bracket and optional dot-notation paths are parsed into objects created with `Object.create(null)`. Dangerous object prototype keys are rejected at every nesting level, including percent-encoded and repeatedly percent-encoded forms.

Blocked segments include `__proto__`, `constructor`, `prototype`, `toString`, `valueOf`, `hasOwnProperty`, `__defineGetter__`, `__defineSetter__`, `__lookupGetter__`, and `__lookupSetter__`.

The safe query subset supports scalar arrays. Sparse indexes, negative indexes, non-canonical indexes such as `001`, index explosion, excessive depth, malformed brackets, and arrays of objects are rejected.

### NoSQL operators and secrets in query strings

Every decoded key segment beginning with `$` is rejected when NoSQL protection is enabled. This blocks inputs such as `filter[$ne]=1`, `user[$gt]=`, and `where[$regex]=.*` before they reach a database query builder.

Credential-like parameter names such as `password`, `token`, `access_token`, `api_key`, `client_secret`, `authorization`, `jwt`, `session_id`, and `private_key` are rejected by default. Their values are never copied into findings, error messages, or CLI output.

### Hostile characters and encoding

The decoder is strict. It rejects malformed percent triplets, invalid UTF-8, invalid Unicode surrogates, NUL bytes, CRLF, C0 and C1 controls, bidirectional format controls, Unicode `Cf` format characters, U+2028, and U+2029. Repeated percent encoding is rejected by default.

## REST API pagination, sort, and fields

```js
import { auditPagination, auditSort, auditFields, createPolicy } from 'querycage';

const policy = createPolicy('restApi', { maxLimit: 50, maxOffset: 5000 });
const pagination = auditPagination('page=1&limit=20&offset=0', policy);
const sort = auditSort('-created_at,name', ['created_at', 'name'], policy);
const fields = auditFields('id,name,email', ['id', 'name', 'email'], policy);
```

`auditPagination` accepts canonical non-negative decimal offsets and positive decimal page and limit values. It rejects signs, floats, scientific notation, non-canonical zero-padded values, non-finite numbers, conflicting `limit` and `per_page` values, excessive limits, and excessive offsets. `offset=0` is valid because it is the normal first page offset.

`auditSort` supports both `-created_at,name` and `name:asc` directional forms. Every field must exactly match an explicit allowlist. SQL fragments, expressions, private columns, empty items, duplicates, excessive field counts, malformed directions, and mixed decoration are rejected.

`auditFields` applies the same explicit allowlist model to sparse field projections and caps the number of requested fields.

## Sanitization and canonicalization

```js
import { sanitizeQuery } from 'querycage';

const result = sanitizeQuery('ok=1&__proto__[x]=2&filter[$ne]=1', 'restApi');
console.log(result.query);
console.log(result.params);
console.log(result.removedParams);
```

`sanitizeQuery` removes or neutralizes hostile parameters, serializes the remaining tree in deterministic key order, re-audits the canonical output, and fails closed to an empty query if a safe result cannot be proven. It returns a canonical query string without a leading question mark, a frozen null-prototype parsed map, a fresh audit report, removed top-level parameter names, and a `changed` flag.

Canonical output uses bracket notation for nested objects, repeated empty brackets for scalar arrays, sorted object keys, and uppercase RFC 3986 percent encoding.

## Policies

```js
import { createPolicy, getPolicy } from 'querycage';

const strict = getPolicy('strict');
const api = createPolicy('restApi', {
  allowedParams: ['page', 'limit', 'sort', 'fields', 'ids', 'filter'],
  arrayParamAllowlist: ['ids'],
  maxLimit: 50,
  maxOffset: 5000
});
```

Presets are deeply frozen.

| Preset | Behavior |
| --- | --- |
| `strict` | Flat keys only, duplicate rejection, no arrays, no brackets, tight byte and count caps. |
| `restApi` | Bounded depth of at most 2, scalar arrays only when the root is in `arrayParamAllowlist`, API abuse defenses enabled. |
| `search` | Bounded filter brackets with depth of at most 3, arrays allowed, prototype and NoSQL defenses still enabled. |
| `oauthCallback` | Flat strict RFC 3986 unreserved keys, duplicate and secret rejection, no arrays or nesting. |

Important policy fields include `maxBytes`, `maxParams`, `maxKeyLength`, `maxValueLength`, `maxDepth`, `maxArrayIndex`, `maxArrayLength`, `maxFindings`, `duplicatePolicy`, `duplicateAllowlist`, `allowedParams`, `blockedParams`, `arrayParamAllowlist`, `maxLimit`, `maxOffset`, `maxSortFields`, and `maxProjectionFields`.

Setting `maxFindings` to zero is rejected. A zero cap would hide findings and fail open, so policy validation fails closed instead.

## API summary

| Function | Returns | Throws |
| --- | --- | --- |
| `parseQuery(input, policy)` | Frozen null-prototype query object | Yes, `QueryCageError` on error findings |
| `auditQuery(input, policy)` | Deeply frozen audit report | Only for invalid input types or invalid policies |
| `validateQuery(input, policy)` | `{ valid, value, report }` | Only for invalid input types or invalid policies |
| `isSafeQuery(input, policy)` | Boolean | No |
| `sanitizeQuery(input, policy)` | Canonical safe query result | Only for invalid input types or invalid policies |
| `auditPagination(params, policy)` | Pagination report | Only for invalid input types or invalid policies |
| `auditSort(sort, allowedFields, policy)` | Sort report | For an invalid allowlist or policy |
| `auditFields(fields, allowedFields, policy)` | Field projection report | For an invalid allowlist or policy |
| `serializeQueryTree(tree)` | Canonical query string | No |
| `createPolicy(base, overrides)` | Deeply frozen merged policy | For invalid policy values |
| `getPolicy(name)` | Deeply frozen preset | For an unknown preset |

Supported input forms are raw query strings with or without one leading question mark, URLSearchParams-compatible objects, and plain record objects containing scalar values, scalar arrays, and plain nested objects.

## CLI

```sh
querycage audit 'a=1&b=2'
querycage parse 'a=1&b=2' --json
querycage sanitize 'ok=1&filter[$ne]=2' --policy restApi
querycage audit-sort '-created_at,name' --allowed-fields created_at,name
querycage audit-pagination 'page=1&limit=20' --json
```

When input is not supplied positionally, the CLI reads at most one mebibyte from standard input and decodes it as strict UTF-8. It does not trim hostile whitespace. Output is neutralized against terminal control, ANSI escape, bidirectional, and Unicode separator injection. Credential values are redacted even when a custom policy permits secret-like keys.

## Errors

`QueryCageError` exposes `code`, `detail`, and optionally `param`. Error codes use the `QUERYCAGE_` prefix. Error details deliberately describe classes of violations without echoing attacker-controlled values.

## Security model

This library is a pre-parser and validation boundary. It does not replace parameterized database queries, server-side authorization, output encoding, or schema validation. Use it before framework query parsing or instead of permissive nested query parsers, then pass only the returned frozen structure or canonical string downstream.

See `SECURITY.md` for the threat model and coordinated disclosure process.
