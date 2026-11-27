import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const cli = path.join(root, 'bin', 'querycage.mjs');

function run(args, input = '') {
  return spawnSync(process.execPath, [cli, ...args], {
    cwd: root,
    input,
    encoding: 'utf8',
    timeout: 10000
  });
}

function runBuffer(args, input) {
  return spawnSync(process.execPath, [cli, ...args], {
    cwd: root,
    input,
    encoding: 'utf8',
    timeout: 10000
  });
}

test('CLI version prints package version', () => {
  const result = run(['--version']);
  assert.equal(result.status, 0);
  assert.equal(result.stdout.trim(), 'querycage 1.0.0');
});

test('CLI help exits successfully', () => {
  const result = run(['--help']);
  assert.equal(result.status, 0);
  assert.equal(result.stdout.includes('querycage audit'), true);
});

test('CLI with no command exits as usage error', () => {
  const result = run([]);
  assert.equal(result.status, 2);
});

test('CLI unknown command exits as usage error', () => {
  const result = run(['missing']);
  assert.equal(result.status, 2);
});

test('CLI unknown option exits as usage error', () => {
  const result = run(['audit', '--missing']);
  assert.equal(result.status, 2);
});

const auditCases = [
  ['a=1&b=2', 0],
  ['role=user&role=admin', 1],
  ['__proto__[x]=1', 1],
  ['filter[$ne]=1', 1],
  ['a[999999]=1', 1],
  ['token=SENTINEL-SECRET', 1],
  ['a=%ff', 1],
  ['a=%00', 1],
  ['a=1;b=2', 1]
];

for (const [query, status] of auditCases) {
  test('CLI audit exit matrix: ' + query, () => {
    const result = run(['audit', query]);
    assert.equal(result.status, status, result.stderr);
  });
}

test('CLI audit reads stdin when positional input is absent', () => {
  const result = run(['audit'], 'a=1&b=2');
  assert.equal(result.status, 0);
});

test('CLI audit positional input wins over stdin', () => {
  const result = run(['audit', 'a=1'], 'role=user&role=admin');
  assert.equal(result.status, 0);
});

test('CLI audit json is parseable', () => {
  const result = run(['audit', 'a=1', '--json']);
  assert.equal(result.status, 0);
  const parsed = JSON.parse(result.stdout);
  assert.equal(parsed.safe, true);
});

test('CLI audit json reports attack without value echo', () => {
  const result = run(['audit', 'token=SENTINEL-SECRET', '--json']);
  assert.equal(result.status, 1);
  const parsed = JSON.parse(result.stdout);
  assert.equal(parsed.safe, false);
  assert.equal(result.stdout.includes('SENTINEL-SECRET'), false);
});

test('CLI audit human output reports unsafe', () => {
  const result = run(['audit', 'role=user&role=admin']);
  assert.equal(result.status, 1);
  assert.equal(result.stdout.includes('unsafe'), true);
});

test('CLI parse prints redacted JSON object', () => {
  const result = run(['parse', 'a=1&b=2', '--json']);
  assert.equal(result.status, 0);
  const parsed = JSON.parse(result.stdout);
  assert.equal(parsed.a, '1');
  assert.equal(parsed.b, '2');
});

test('CLI parse exits nonzero for hostile input', () => {
  const result = run(['parse', '__proto__[x]=1']);
  assert.equal(result.status, 1);
});

test('CLI sanitize outputs canonical query', () => {
  const result = run(['sanitize', 'z=1&a=2']);
  assert.equal(result.status, 0);
  assert.equal(result.stdout.trim(), 'a=2&z=1');
});

test('CLI sanitize json contains report and params', () => {
  const result = run(['sanitize', 'a=1', '--json']);
  assert.equal(result.status, 0);
  const parsed = JSON.parse(result.stdout);
  assert.equal(parsed.query, 'a=1');
  assert.equal(parsed.report.safe, true);
});

test('CLI sanitize never echoes secret values', () => {
  const result = run(['sanitize', 'ok=1&token=SENTINEL-SECRET', '--json']);
  assert.equal(result.status, 0);
  assert.equal(result.stdout.includes('SENTINEL-SECRET'), false);
  assert.equal(result.stderr.includes('SENTINEL-SECRET'), false);
});

test('CLI audit-sort accepts allowlisted sort', () => {
  const result = run(['audit-sort', '-created_at,name', '--allowed-fields', 'created_at,name']);
  assert.equal(result.status, 0);
});

test('CLI audit-sort rejects private field probing', () => {
  const result = run(['audit-sort', 'password_hash', '--allowed-fields', 'created_at,name']);
  assert.equal(result.status, 1);
  assert.equal(result.stdout.includes('password_hash'), false);
});

test('CLI audit-sort json is parseable', () => {
  const result = run(['audit-sort', 'name:asc', '--allowed-fields', 'name', '--json']);
  assert.equal(result.status, 0);
  assert.equal(JSON.parse(result.stdout).safe, true);
});

test('CLI audit-sort requires allowed fields', () => {
  const result = run(['audit-sort', 'name']);
  assert.equal(result.status, 2);
});

test('CLI audit-pagination accepts bounded pagination', () => {
  const result = run(['audit-pagination', 'page=1&limit=20']);
  assert.equal(result.status, 0);
});

test('CLI audit-pagination rejects offset denial of service', () => {
  const result = run(['audit-pagination', 'offset=1000000000']);
  assert.equal(result.status, 1);
});

test('CLI audit-pagination json is parseable', () => {
  const result = run(['audit-pagination', 'page=1&limit=20', '--json']);
  assert.equal(result.status, 0);
  const parsed = JSON.parse(result.stdout);
  assert.equal(parsed.pagination.page, 1);
});

test('CLI invalid UTF-8 stdin exits as usage error', () => {
  const result = runBuffer(['audit'], Buffer.from([0xff]));
  assert.equal(result.status, 2);
});

test('CLI does not trim hostile trailing newline', () => {
  const result = run(['audit'], 'a=1\n');
  assert.equal(result.status, 1);
});

test('CLI does not trim hostile leading newline', () => {
  const result = run(['audit'], '\na=1');
  assert.equal(result.status, 1);
});

test('CLI bounded stdin rejects input over one mebibyte', () => {
  const oversized = Buffer.alloc(1024 * 1024 + 1, 97);
  const result = runBuffer(['audit'], oversized);
  assert.equal(result.status, 2);
});

test('CLI accepts stdin at small bounded size', () => {
  const result = run(['audit'], 'a=' + 'x'.repeat(100));
  assert.equal(result.status, 0);
});

test('CLI output neutralizes encoded bidi control in key finding', () => {
  const result = run(['audit', 'a%e2%80%8eb=x', '--json']);
  assert.equal(result.status, 1);
  assert.equal(result.stdout.includes('\u200e'), false);
});

test('CLI output neutralizes Unicode line separator in key finding', () => {
  const result = run(['audit', 'a%e2%80%a8b=x', '--json']);
  assert.equal(result.status, 1);
  assert.equal(result.stdout.includes('\u2028'), false);
});

test('CLI stderr does not echo unknown option values with terminal escape', () => {
  const result = run(['audit', '--bad' + String.fromCharCode(27)]);
  assert.equal(result.status, 2);
  assert.equal(result.stderr.includes(String.fromCharCode(27)), false);
});

test('CLI policy preset flag is honored', () => {
  const result = run(['audit', 'a[b]=1', '--policy', 'restApi']);
  assert.equal(result.status, 0);
});

test('CLI strict policy rejects bracket nesting', () => {
  const result = run(['audit', 'a[b]=1', '--policy', 'strict']);
  assert.equal(result.status, 1);
});

test('CLI unknown policy exits as usage error', () => {
  const result = run(['audit', 'a=1', '--policy', 'missing']);
  assert.equal(result.status, 2);
});

test('CLI empty stdin audit is safe empty query', () => {
  const result = run(['audit'], '');
  assert.equal(result.status, 0);
});
