import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const cli = path.join(root, 'bin', 'querycage.mjs');

function run(args, input = '') {
  return spawnSync(process.execPath, [cli, ...args], { cwd: root, input, encoding: 'utf8', timeout: 10000 });
}

assert.equal(run(['--version']).stdout.trim(), 'querycage 1.0.0');
assert.equal(run(['audit', 'a=1&b=2']).status, 0);
assert.equal(run(['audit', 'role=user&role=admin']).status, 1);
assert.equal(run(['parse', 'a=1', '--json']).status, 0);
assert.equal(JSON.parse(run(['sanitize', 'a=1;b=2', '--json']).stdout).report.safe, true);
assert.equal(run(['audit-sort', '-created_at,name', '--allowed-fields', 'created_at,name']).status, 0);
assert.equal(run(['audit-sort', 'password_hash', '--allowed-fields', 'created_at,name']).status, 1);
assert.equal(run(['audit-pagination', 'page=1&limit=20']).status, 0);
assert.equal(run(['audit-pagination', 'offset=1000000000']).status, 1);
process.stdout.write('querycage CLI smoke passed\n');
