import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);
const esm = await import(pathToFileURL(path.join(root, 'src', 'index.mjs')).href);
const cjs = require(path.join(root, 'cjs', 'index.cjs'));

const exportNames = [
  'QUERYCAGE_VERSION',
  'QUERYCAGE_SEVERITY',
  'QUERYCAGE_ERROR_CODES',
  'CODE',
  'QueryCageError',
  'QUERYCAGE_DEFAULT_POLICY',
  'QUERYCAGE_POLICIES',
  'createPolicy',
  'getPolicy',
  'parseQuery',
  'auditQuery',
  'validateQuery',
  'isSafeQuery',
  'auditPagination',
  'auditSort',
  'auditFields',
  'sanitizeQuery',
  'serializeQueryTree',
  'neutralizeTerminal'
];

for (const name of exportNames) {
  test('CJS exposes ESM export: ' + name, () => {
    assert.equal(typeof cjs[name], typeof esm[name]);
    assert.notEqual(cjs[name], undefined);
  });
}

test('CJS default export object exists', () => {
  assert.equal(typeof cjs.default, 'object');
  assert.equal(cjs.default.QUERYCAGE_VERSION, esm.QUERYCAGE_VERSION);
});

const parityQueries = [
  'a=1&b=2',
  'role=user&role=admin',
  '__proto__[x]=1',
  'filter[$ne]=1',
  'a[999999]=1',
  'a=1;b=2',
  'id=1&%69d=2',
  'token=SENTINEL-SECRET',
  'a=%00',
  'a=%ff'
];

for (const query of parityQueries) {
  test('CJS and ESM audit parity: ' + query, () => {
    const left = esm.auditQuery(query, 'search');
    const right = cjs.auditQuery(query, 'search');
    assert.deepEqual(JSON.parse(JSON.stringify(left)), JSON.parse(JSON.stringify(right)));
  });
}

test('CJS and ESM parse parity for safe query', () => {
  assert.deepEqual(JSON.parse(JSON.stringify(cjs.parseQuery('a=1', 'strict'))), JSON.parse(JSON.stringify(esm.parseQuery('a=1', 'strict'))));
});

test('CJS and ESM sanitize parity', () => {
  const left = esm.sanitizeQuery('ok=1&token=SENTINEL-SECRET', 'strict');
  const right = cjs.sanitizeQuery('ok=1&token=SENTINEL-SECRET', 'strict');
  assert.deepEqual(JSON.parse(JSON.stringify(left)), JSON.parse(JSON.stringify(right)));
});

test('CJS and ESM pagination parity', () => {
  const left = esm.auditPagination('page=1&limit=20', 'restApi');
  const right = cjs.auditPagination('page=1&limit=20', 'restApi');
  assert.deepEqual(JSON.parse(JSON.stringify(left)), JSON.parse(JSON.stringify(right)));
});

test('CJS and ESM sort parity', () => {
  const left = esm.auditSort('-created_at', ['created_at'], 'restApi');
  const right = cjs.auditSort('-created_at', ['created_at'], 'restApi');
  assert.deepEqual(JSON.parse(JSON.stringify(left)), JSON.parse(JSON.stringify(right)));
});

test('CJS typed errors have matching code', () => {
  assert.throws(() => cjs.parseQuery('a=1&a=2', 'strict'), (error) => error instanceof cjs.QueryCageError && error.code === cjs.CODE.DUPLICATE_PARAMETER);
});

function repoFiles(directory = root, output = []) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (entry.name === '.git' || entry.name === 'node_modules') continue;
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) repoFiles(full, output);
    else if (entry.isFile()) output.push(full);
  }
  return output;
}

test('repository contains no em dash or en dash bytes', () => {
  const offenders = [];
  for (const file of repoFiles()) {
    const bytes = fs.readFileSync(file);
    if (bytes.includes(Buffer.from([0xe2, 0x80, 0x94])) || bytes.includes(Buffer.from([0xe2, 0x80, 0x93]))) offenders.push(path.relative(root, file));
  }
  assert.deepEqual(offenders, []);
});

test('repository contains no local user filesystem paths', () => {
  const needle = Buffer.from('/' + 'Users' + '/');
  const offenders = [];
  for (const file of repoFiles()) {
    if (fs.readFileSync(file).includes(needle)) offenders.push(path.relative(root, file));
  }
  assert.deepEqual(offenders, []);
});

test('repository contains no personal mailbox fragments', () => {
  const fragments = [
    'someone' + '@' + 'gmail',
    'handle-redacted' + '286' + '@' + 'gmail'
  ];
  const offenders = [];
  for (const file of repoFiles()) {
    const text = fs.readFileSync(file, 'utf8');
    for (const fragment of fragments) {
      if (text.includes(fragment)) offenders.push(path.relative(root, file));
    }
  }
  assert.deepEqual(offenders, []);
});

test('repository contains no coauthor trailer marker', () => {
  const needle = 'Co-Authored-' + 'By';
  const offenders = [];
  for (const file of repoFiles()) {
    if (fs.readFileSync(file, 'utf8').includes(needle)) offenders.push(path.relative(root, file));
  }
  assert.deepEqual(offenders, []);
});

test('repository uses LF line endings in text files', () => {
  const offenders = [];
  for (const file of repoFiles()) {
    if (fs.readFileSync(file).includes(Buffer.from([0x0d]))) offenders.push(path.relative(root, file));
  }
  assert.deepEqual(offenders, []);
});

test('package keeps runtime dependencies empty and fast-check development-only', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  assert.deepEqual(pkg.dependencies, {});
  assert.deepEqual(pkg.devDependencies, { 'fast-check': '4.10.3' });
});

test('package is unscoped and named querycage', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  assert.equal(pkg.name, 'querycage');
  assert.equal(pkg.name.startsWith('@'), false);
});

test('package declares Node 18 minimum', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  assert.equal(pkg.engines.node, '>=18.0.0');
});

test('package exposes ESM CJS and types', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  assert.equal(pkg.type, 'module');
  assert.equal(pkg.main, './cjs/index.cjs');
  assert.equal(pkg.module, './src/index.mjs');
  assert.equal(pkg.types, './types/index.d.ts');
  assert.equal(pkg.exports['.'].import, './src/index.mjs');
  assert.equal(pkg.exports['.'].require, './cjs/index.cjs');
  assert.equal(pkg.exports['.'].types, './types/index.d.ts');
});

test('package files list includes runtime documentation and examples', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  for (const required of ['bin', 'src', 'cjs', 'types', 'examples', 'README.md', 'SECURITY.md', 'CONTRIBUTING.md', 'CHANGELOG.md', 'LICENSE']) {
    assert.equal(pkg.files.includes(required), true, required);
  }
});

test('package is marked free of side effects', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  assert.equal(pkg.sideEffects, false);
});

test('generated CJS file exists and carries generated marker', () => {
  const text = fs.readFileSync(path.join(root, 'cjs', 'index.cjs'), 'utf8');
  assert.equal(text.includes('Generated by scripts/build-cjs.mjs'), true);
  assert.equal(text.includes('module.exports'), true);
});

test('CI uses ubuntu and windows across four Node versions', () => {
  const text = fs.readFileSync(path.join(root, '.github', 'workflows', 'ci.yml'), 'utf8');
  assert.equal(text.includes('os: [ubuntu-24.04, windows-latest]'), true);
  assert.equal(text.includes('node: [18, 20, 22, 24]'), true);
});

test('CI runs tests CJS types CLI and package checks', () => {
  const text = fs.readFileSync(path.join(root, '.github', 'workflows', 'ci.yml'), 'utf8');
  for (const command of ['npm test', 'node scripts/build-cjs.mjs --check', 'node scripts/check-types.mjs', 'node scripts/cli-smoke.mjs', 'npm pack --dry-run']) {
    assert.equal(text.includes(command), true, command);
  }
});

test('TypeScript declaration has no any type', () => {
  const text = fs.readFileSync(path.join(root, 'types', 'index.d.ts'), 'utf8');
  assert.equal(/\bany\b/u.test(text), false);
});

for (const name of ['parseQuery', 'auditQuery', 'validateQuery', 'isSafeQuery', 'sanitizeQuery', 'auditPagination', 'auditSort', 'auditFields']) {
  test('TypeScript declaration declares ' + name, () => {
    const text = fs.readFileSync(path.join(root, 'types', 'index.d.ts'), 'utf8');
    assert.equal(text.includes('function ' + name + '('), true);
  });
}

for (const file of ['README.md', 'SECURITY.md', 'CONTRIBUTING.md', 'CHANGELOG.md', 'LICENSE', 'CODE_OF_CONDUCT.md']) {
  test('required repository document exists: ' + file, () => {
    assert.equal(fs.statSync(path.join(root, file)).isFile(), true);
    assert.equal(fs.statSync(path.join(root, file)).size > 0, true);
  });
}

for (const file of ['basic.mjs', 'rest-api.mjs', 'middleware.mjs']) {
  test('runnable example exists: ' + file, () => {
    const full = path.join(root, 'examples', file);
    assert.equal(fs.statSync(full).isFile(), true);
    assert.equal(fs.readFileSync(full, 'utf8').includes('../src/index.mjs'), true);
  });
}

test('license is MIT', () => {
  const text = fs.readFileSync(path.join(root, 'LICENSE'), 'utf8');
  assert.equal(text.includes('MIT License'), true);
});

test('README documents security boundary and secret redaction', () => {
  const text = fs.readFileSync(path.join(root, 'README.md'), 'utf8');
  assert.equal(text.includes('never copied into findings'), true);
  assert.equal(text.includes('HTTP Parameter Pollution'), true);
  assert.equal(text.includes('prototype pollution'), true);
});

test('bin file has executable shebang', () => {
  const text = fs.readFileSync(path.join(root, 'bin', 'querycage.mjs'), 'utf8');
  assert.equal(text.startsWith('#!/usr/bin/env node'), true);
});

test('repository scripts exist', () => {
  for (const file of ['build-cjs.mjs', 'check-types.mjs', 'cli-smoke.mjs', 'run-tests.mjs']) {
    assert.equal(fs.statSync(path.join(root, 'scripts', file)).isFile(), true, file);
  }
});

test('no vendor shaped credential placeholders are present', () => {
  const offenders = [];
  const patterns = [
    /tskey-[A-Za-z0-9_-]/u,
    /sk-[A-Za-z0-9]/u,
    /ghp_[A-Za-z0-9]/u,
    /github_pat_[A-Za-z0-9_]/u,
    /AKIA[A-Z0-9]/u,
    /xox[baprs]-[A-Za-z0-9-]/u,
    /AIza[A-Za-z0-9_-]/u
  ];
  for (const file of repoFiles()) {
    const text = fs.readFileSync(file, 'utf8');
    for (const pattern of patterns) {
      if (pattern.test(text)) offenders.push(path.relative(root, file));
    }
  }
  assert.deepEqual(offenders, []);
});
