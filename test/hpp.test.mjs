import test from 'node:test';
import assert from 'node:assert/strict';
import { CODE, auditQuery, createPolicy, parseQuery } from '../src/index.mjs';
import { assertHasCode, assertNoCode } from './helpers.mjs';

const duplicatePairs = [
  'role=user&role=admin',
  'id=1&id=2',
  'x=&x=1',
  'x=1&x=',
  'a=true&a=false',
  'name=alice&name=bob',
  'page=1&page=2',
  'sort=a&sort=b',
  'filter=x&filter=y',
  'tokenized=value&tokenized=other'
];

for (const query of duplicatePairs) {
  test('reject duplicate policy blocks ' + query, () => {
    const report = auditQuery(query, 'strict');
    assert.equal(report.safe, false);
    assertHasCode(report, CODE.DUPLICATE_PARAMETER);
  });

  test('first duplicate policy keeps first value for ' + query, () => {
    const policy = createPolicy('strict', { duplicatePolicy: 'first' });
    const firstValue = query.slice(query.indexOf('=') + 1, query.indexOf('&'));
    assert.equal(parseQuery(query, policy)[query.slice(0, query.indexOf('='))], firstValue);
  });

  test('last duplicate policy keeps last value for ' + query, () => {
    const policy = createPolicy('strict', { duplicatePolicy: 'last' });
    const key = query.slice(0, query.indexOf('='));
    const lastValue = query.slice(query.lastIndexOf('=') + 1);
    assert.equal(parseQuery(query, policy)[key], lastValue);
  });

  test('first and last duplicate policies emit warnings not errors for ' + query, () => {
    for (const duplicatePolicy of ['first', 'last']) {
      const report = auditQuery(query, createPolicy('strict', { duplicatePolicy }));
      assert.equal(report.safe, true);
      assert.equal(report.counts.errors, 0);
      assert.equal(report.counts.warnings, 1);
      assertHasCode(report, CODE.DUPLICATE_PARAMETER);
    }
  });
}

test('duplicate allowlist collects scalar values into an array', () => {
  const policy = createPolicy('strict', {
    duplicatePolicy: 'allowlist',
    duplicateAllowlist: ['role'],
    allowArrays: true
  });
  const parsed = parseQuery('role=user&role=admin', policy);
  assert.deepEqual(Array.from(parsed.role), ['user', 'admin']);
});

test('duplicate allowlist emits a warning when collecting', () => {
  const policy = createPolicy('strict', {
    duplicatePolicy: 'allowlist',
    duplicateAllowlist: ['role'],
    allowArrays: true
  });
  const report = auditQuery('role=user&role=admin', policy);
  assert.equal(report.safe, true);
  assert.equal(report.counts.warnings, 1);
});

test('duplicate allowlist rejects non allowlisted roots', () => {
  const policy = createPolicy('strict', {
    duplicatePolicy: 'allowlist',
    duplicateAllowlist: ['role'],
    allowArrays: true
  });
  const report = auditQuery('id=1&id=2', policy);
  assert.equal(report.safe, false);
  assertHasCode(report, CODE.DUPLICATE_PARAMETER);
});

test('independent duplicate groups each produce findings', () => {
  const report = auditQuery('a=1&a=2&b=1&b=2', 'strict');
  const duplicateCount = report.findings.filter((finding) => finding.code === CODE.DUPLICATE_PARAMETER).length;
  assert.equal(duplicateCount, 2);
});

test('duplicate detection is case sensitive and deterministic', () => {
  const report = auditQuery('Role=user&role=admin', 'strict');
  assertNoCode(report, CODE.DUPLICATE_PARAMETER);
  assert.equal(report.safe, true);
});

const arrayPolicy = createPolicy('search', { arrayParamAllowlist: null, maxDepth: 3 });

for (const query of [
  'a[0]=x&a[0]=y',
  'a[1]=x&a[1]=y',
  'a[0]=x&a%5b0%5d=y',
  'a[]=x&a[0]=y'
]) {
  test('array index overlap or duplicate is blocked: ' + query, () => {
    const report = auditQuery(query, arrayPolicy);
    assert.equal(report.safe, false);
    assert.equal(
      report.findings.some((finding) => finding.code === CODE.DUPLICATE_PARAMETER),
      true,
      'expected duplicate overlap finding'
    );
  });
}

test('explicit index followed by append is deterministic', () => {
  const parsed = parseQuery('a[0]=x&a[]=y', arrayPolicy);
  assert.deepEqual(Array.from(parsed.a), ['x', 'y']);
});

test('non overlapping explicit indexes parse in order', () => {
  const parsed = parseQuery('a[0]=x&a[1]=y', arrayPolicy);
  assert.deepEqual(Array.from(parsed.a), ['x', 'y']);
});

test('array append values preserve input order', () => {
  const parsed = parseQuery('a[]=x&a[]=y&a[]=z', arrayPolicy);
  assert.deepEqual(Array.from(parsed.a), ['x', 'y', 'z']);
});

const shapeCases = [
  'id=1&id[]=2',
  'id[]=1&id=2',
  'a=1&a[b]=2',
  'a[b]=1&a=2',
  'a[b]=1&a[b][c]=2',
  'a[b][c]=1&a[b]=2',
  'a[]=1&a[b]=2',
  'a[b]=1&a[]=2'
];

for (const query of shapeCases) {
  test('scalar and structured shape conflict blocked: ' + query, () => {
    const report = auditQuery(query, arrayPolicy);
    assert.equal(report.safe, false);
    assertHasCode(report, CODE.SHAPE_CONFLICT);
  });
}

test('dot path and scalar shape conflict is blocked when dot notation enabled', () => {
  const policy = createPolicy('search', { allowDotNotation: true, arrayParamAllowlist: null });
  const report = auditQuery('a.b=1&a=2', policy);
  assertHasCode(report, CODE.SHAPE_CONFLICT);
});

test('reverse dot path and scalar shape conflict is blocked', () => {
  const policy = createPolicy('search', { allowDotNotation: true, arrayParamAllowlist: null });
  const report = auditQuery('a=1&a.b=2', policy);
  assertHasCode(report, CODE.SHAPE_CONFLICT);
});

test('equivalent dot and bracket scalar paths are duplicates', () => {
  const policy = createPolicy('search', { allowDotNotation: true, arrayParamAllowlist: null });
  const report = auditQuery('a.b=1&a[b]=2', policy);
  assertHasCode(report, CODE.DUPLICATE_PARAMETER);
});

const semicolonCases = [
  'a=1;b=2',
  'a=1;b',
  'a=1;b=2&c=3',
  'a;b=1',
  ';a=1',
  'a=1;',
  'a=%31;b=2',
  'a=1;b=%32',
  'a=1%3Bb=2;b=3',
  'a=1;filter[$ne]=2'
];

for (const query of semicolonCases) {
  test('semicolon delimiter smuggling is rejected: ' + query, () => {
    const report = auditQuery(query, 'strict');
    assert.equal(report.safe, false);
    assertHasCode(report, CODE.SEMICOLON_DELIMITER);
  });
}

test('encoded semicolon is data rather than a raw delimiter', () => {
  const report = auditQuery('a=1%3Bb%3D2', 'strict');
  assert.equal(report.safe, true);
  assertNoCode(report, CODE.SEMICOLON_DELIMITER);
});

test('semicolon can be treated as data only when explicitly configured', () => {
  const policy = createPolicy('strict', { rejectSemicolons: false });
  const parsed = parseQuery('a=1;b=2', policy);
  assert.equal(parsed.a, '1;b=2');
});

test('semicolon finding never includes the parameter value', () => {
  const report = auditQuery('a=1;secretish=VALUE-SENTINEL', 'strict');
  assert.equal(JSON.stringify(report).includes('VALUE-SENTINEL'), false);
});

const collisionCases = [
  ['id=1&%69d=2', true],
  ['%69d=1&id=2', true],
  ['filter=x&%66ilter=y', true],
  ['a=1&%61=2', true],
  ['abc=1&%61bc=2', true],
  ['abc=1&ab%63=2', true],
  ['x-y=1&%78-y=2', true],
  ['x_y=1&x%5fy=2', true],
  ['a[b]=1&a%5bb%5d=2', true],
  ['a=1&b=2', false]
];

for (const [query, expected] of collisionCases) {
  test('encoded key collision matrix: ' + query, () => {
    const report = auditQuery(query, arrayPolicy);
    if (expected) {
      assert.equal(report.safe, false);
      assertHasCode(report, CODE.KEY_COLLISION);
      assertHasCode(report, CODE.DUPLICATE_PARAMETER);
    } else {
      assertNoCode(report, CODE.KEY_COLLISION);
    }
  });
}

test('double encoded normalized key collision is blocked twice', () => {
  const report = auditQuery('id=1&%2569d=2', 'strict');
  assertHasCode(report, CODE.DOUBLE_ENCODING);
  assertHasCode(report, CODE.KEY_COLLISION);
});

test('key collision check can be downgraded only by explicit policy', () => {
  const policy = createPolicy('strict', {
    rejectKeyCollisions: false,
    duplicatePolicy: 'first'
  });
  const report = auditQuery('id=1&%69d=2', policy);
  assert.equal(report.safe, true);
  assert.equal(report.counts.errors, 0);
  assert.equal(report.counts.warnings >= 1, true);
});

test('same key text repeated is duplicate without key collision', () => {
  const report = auditQuery('id=1&id=2', 'strict');
  assertNoCode(report, CODE.KEY_COLLISION);
  assertHasCode(report, CODE.DUPLICATE_PARAMETER);
});

test('different keys sharing a prefix are not collisions', () => {
  const report = auditQuery('id=1&idx=2', 'strict');
  assert.equal(report.safe, true);
});

test('duplicate resolution remains stable across repeated audits', () => {
  const policy = createPolicy('strict', { duplicatePolicy: 'last' });
  for (let index = 0; index < 10; index += 1) {
    assert.equal(parseQuery('x=1&x=2', policy).x, '2');
  }
});

for (const query of [
  'a=1&a=2&a=3',
  'a=1&%61=2&%2541=3',
  'x=&x=&x=',
  'role=user&role=admin&role=owner'
]) {
  test('multi occurrence HPP is detected: ' + query, () => {
    const report = auditQuery(query, 'strict');
    assert.equal(report.safe, false);
    assertHasCode(report, CODE.DUPLICATE_PARAMETER);
  });
}
