# Contributing

## Requirements

Use Node.js 18 or newer. The package intentionally has no runtime dependencies. `fast-check` is the only development dependency and is used only for property-based fuzz tests.

## Verification

Run these commands before sending a change:

```sh
node scripts/run-tests.mjs
node scripts/build-cjs.mjs --check
node scripts/check-types.mjs
node scripts/cli-smoke.mjs
npm pack --dry-run
```

If `src/` changes, regenerate the CommonJS bundle with:

```sh
node scripts/build-cjs.mjs
```

The generated bundle must be committed. Do not edit `cjs/index.cjs` directly.

## Rules

- Keep the package free of runtime dependencies.
- Keep parsing deterministic and linear.
- Do not echo attacker-controlled values in findings or errors.
- Add regression tests for every security fix.
- Preserve Node.js 18 compatibility.
- Preserve Windows compatibility in scripts and CI.
- Use ASCII punctuation in source and documentation.
