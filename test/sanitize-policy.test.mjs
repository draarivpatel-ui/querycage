import test from 'node:test';
import assert from 'node:assert/strict';
import {
  CODE,
  QUERYCAGE_POLICIES,
  QueryCageError,
  auditQuery,
  createPolicy,
  getPolicy,
  isSafeQuery,
  parseQuery,
  sanitizeQuery,
  serializeQueryTree
} from '../src/index.mjs';
import { assertHasCode, assertFrozenDeep } from './helpers.mjs';

const removalCases = [
  ['role=user&role=admin', 'role', 'strict'],
  ['ok=1&a=1;b=2', 'a', 'strict'],
  ['ok=1&__proto__[x]=2', '__proto__', 'restApi'],
  ['ok=1&constructor[prototype][x]=2', 'constructor', 'restApi'],
  ['ok=1&filter[$ne]=2', 'filter', 'restApi'],
  ['ok=1&token=SENTINEL-SECRET', 'token', 'strict'],
  ['ok=1&a[999999]=1', 'a', 'search'],
  ['ok=1&a[0]=x&a[2]=z', 'a', 'search'],
  ['ok=1&%ff=1', '%ff', 'strict'],
  ['ok=1&a=%00', 'a', 'strict']
];

for (const [query, removed, preset] of removalCases) {
  test('sanitize drops hostile parameter root: ' + query, () => {
    const result = sanitizeQuery(query, preset);
    assert.equal(result.report.safe, true);
    assert.equal(Object.prototype.hasOwnProperty.call(result.params, removed), false);
    assert.equal(result.query.includes('SENTINEL-SECRET'), false);
  });
}

test('sanitize preserves independent safe parameters', () => {
  const result = sanitizeQuery('ok=1&token=SENTINEL-SECRET&also=2', 'strict');
  assert.equal(result.params.ok, '1');
  assert.equal(result.params.also, '2');
});

test('sanitize drops duplicate conflict rather than choosing first under reject', () => {
  const result = sanitizeQuery('role=user&role=admin&ok=1', 'strict');
  assert.equal(result.query, 'ok=1');
  assert.equal(Object.prototype.hasOwnProperty.call(result.params, 'role'), false);
});

test('sanitize records removed top level params without values', () => {
  const result = sanitizeQuery('role=user&role=admin&token=SENTINEL-SECRET&ok=1', 'strict');
  assert.equal(result.removedParams.includes('role'), true);
  assert.equal(result.removedParams.includes('token'), true);
  assert.equal(JSON.stringify(result).includes('SENTINEL-SECRET'), false);
});

test('sanitize empty fallback is safe when every parameter is hostile', () => {
  const result = sanitizeQuery('role=user&role=admin', 'strict');
  assert.equal(result.query, '');
  assert.deepEqual(Object.keys(result.params), []);
  assert.equal(result.report.safe, true);
});

test('sanitize output is deeply frozen', () => {
  const result = sanitizeQuery('a=1', 'strict');
  assertFrozenDeep(result);
});

test('sanitize params object has null prototype', () => {
  const result = sanitizeQuery('a=1', 'strict');
  assert.equal(Object.getPrototypeOf(result.params), null);
});

test('sanitize canonicalizes root key order', () => {
  const result = sanitizeQuery('z=1&a=2&m=3', 'strict');
  assert.equal(result.query, 'a=2&m=3&z=1');
});

test('sanitize canonicalizes nested object keys', () => {
  const result = sanitizeQuery('z=1&a[b]=2&m=3', 'restApi');
  assert.equal(result.query, 'a[b]=2&m=3&z=1');
});

test('sanitize preserves scalar array order', () => {
  const policy = createPolicy('restApi', { arrayParamAllowlist: ['ids'] });
  const result = sanitizeQuery('ids[]=2&ids[]=1', policy);
  assert.equal(result.query, 'ids[]=2&ids[]=1');
});

test('sanitize percent encodes spaces canonically', () => {
  const result = sanitizeQuery('a=x+y z', 'strict');
  assert.equal(result.query, 'a=x%20y%20z');
});

test('sanitize percent encodes semicolons inside remaining safe values', () => {
  const policy = createPolicy('strict', { rejectSemicolons: false });
  const result = sanitizeQuery('a=x;y', policy);
  assert.equal(result.query, 'a=x%3By');
});

test('sanitize is idempotent', () => {
  const input = 'z=1&a[b]=2&token=SENTINEL-SECRET';
  const first = sanitizeQuery(input, 'restApi');
  const second = sanitizeQuery(first.query, 'restApi');
  assert.equal(second.query, first.query);
  assert.equal(second.report.safe, true);
});

test('sanitize changed flag false for already canonical safe input', () => {
  const result = sanitizeQuery('a=1', 'strict');
  assert.equal(result.query, 'a=1');
  assert.equal(result.changed, false);
});

test('sanitize changed flag true after hostile input removal', () => {
  const result = sanitizeQuery('a=1&token=SENTINEL-SECRET', 'strict');
  assert.equal(result.changed, true);
});

test('sanitize truncates deterministic roots to satisfy byte cap', () => {
  const policy = createPolicy('strict', { maxBytes: 3 });
  const result = sanitizeQuery('a=1&b=2', policy);
  assert.equal(result.report.safe, true);
  assert.equal(result.query.length <= 3, true);
});

test('sanitize truncates deterministic roots to satisfy param cap', () => {
  const policy = createPolicy('strict', { maxParams: 1 });
  const result = sanitizeQuery('a=1&b=2', policy);
  assert.equal(result.report.safe, true);
  assert.equal(Object.keys(result.params).length <= 1, true);
});

test('serializeQueryTree emits sorted deterministic output', () => {
  const tree = Object.create(null);
  tree.z = '1';
  tree.a = Object.create(null);
  tree.a.b = '2';
  tree.m = '3';
  assert.equal(serializeQueryTree(tree), 'a[b]=2&m=3&z=1');
});

test('serializeQueryTree emits scalar arrays as repeated empty brackets', () => {
  const tree = Object.create(null);
  tree.ids = ['1', '2'];
  assert.equal(serializeQueryTree(tree), 'ids[]=1&ids[]=2');
});

test('serializeQueryTree encodes RFC 3986 characters', () => {
  const tree = Object.create(null);
  tree['a key'] = "x!'()";
  const output = serializeQueryTree(tree);
  assert.equal(output.includes(' '), false);
  assert.equal(output.includes("'"), false);
});

test('strict preset is flat only', () => {
  assert.equal(auditQuery('a[b]=1', 'strict').safe, false);
  assert.equal(auditQuery('a=1', 'strict').safe, true);
});

test('strict preset rejects duplicates', () => {
  assertHasCode(auditQuery('a=1&a=2', 'strict'), CODE.DUPLICATE_PARAMETER);
});

test('strict preset rejects semicolons', () => {
  assertHasCode(auditQuery('a=1;b=2', 'strict'), CODE.SEMICOLON_DELIMITER);
});

test('strict preset rejects secrets', () => {
  assertHasCode(auditQuery('token=x', 'strict'), CODE.SECRET_IN_QUERY);
});

test('restApi bounded nesting depth is two', () => {
  assert.equal(QUERYCAGE_POLICIES.restApi.maxDepth, 2);
  assert.equal(auditQuery('a[b][c]=1', 'restApi').safe, true);
  assert.equal(auditQuery('a[b][c][d]=1', 'restApi').safe, false);
});

test('restApi array parameters require allowlist entries', () => {
  assert.equal(auditQuery('ids[]=1', 'restApi').safe, false);
  const policy = createPolicy('restApi', { arrayParamAllowlist: ['ids'] });
  assert.equal(auditQuery('ids[]=1', policy).safe, true);
});

test('search preset allows bounded filters', () => {
  assert.equal(auditQuery('filter[status]=active', 'search').safe, true);
  assert.equal(QUERYCAGE_POLICIES.search.maxDepth, 3);
});

test('search preset still blocks prototype pollution and NoSQL operators', () => {
  assertHasCode(auditQuery('filter[__proto__]=1', 'search'), CODE.PROTOTYPE_POLLUTION);
  assertHasCode(auditQuery('filter[$ne]=1', 'search'), CODE.NOSQL_OPERATOR);
});

test('oauthCallback accepts strict unreserved keys', () => {
  assert.equal(auditQuery('code=abc&state=xyz-123_', 'oauthCallback').safe, true);
});

for (const query of ['redirect uri=x', 'a[b]=x', 'a[]=x', 'code=1&code=2', 'access_token=x']) {
  test('oauthCallback rejects unsafe input: ' + query, () => {
    assert.equal(auditQuery(query, 'oauthCallback').safe, false);
  });
}

test('presets are deeply frozen', () => {
  assertFrozenDeep(QUERYCAGE_POLICIES);
  assert.equal(Object.isFrozen(getPolicy('strict')), true);
});

test('createPolicy merges overrides without mutating them', () => {
  const arrays = ['ids'];
  const overrides = { arrayParamAllowlist: arrays };
  const policy = createPolicy('restApi', overrides);
  assert.equal(policy.arrayParamAllowlist.includes('ids'), true);
  assert.equal(Object.isFrozen(overrides), false);
  assert.equal(Object.isFrozen(arrays), false);
});

test('createPolicy copies arrays rather than retaining caller arrays', () => {
  const arrays = ['ids'];
  const policy = createPolicy('restApi', { arrayParamAllowlist: arrays });
  arrays.push('evil');
  assert.equal(policy.arrayParamAllowlist.includes('evil'), false);
});

test('getPolicy returns independent frozen copies', () => {
  const first = getPolicy('strict');
  assert.throws(() => {
    first.maxParams = 1;
  }, TypeError);
  const second = getPolicy('strict');
  assert.equal(second.maxParams, 32);
});

test('unknown policy preset throws typed error', () => {
  assert.throws(() => getPolicy('missing'), (error) => error instanceof QueryCageError && error.code === CODE.UNKNOWN_POLICY);
});

test('invalid duplicate policy throws typed error', () => {
  assert.throws(() => createPolicy('strict', { duplicatePolicy: 'merge' }), (error) => error instanceof QueryCageError && error.code === CODE.INVALID_POLICY);
});

test('maxFindings zero fails closed during policy validation', () => {
  assert.throws(() => createPolicy('strict', { maxFindings: 0 }), (error) => error instanceof QueryCageError && error.code === CODE.INVALID_POLICY);
});

test('unknown policy field fails closed during policy validation', () => {
  assert.throws(() => createPolicy('strict', { maxbytes: 10 }), (error) => error instanceof QueryCageError && error.code === CODE.INVALID_POLICY);
});

for (const override of [
  { maxBytes: 0 },
  { maxParams: 0 },
  { maxKeyLength: 0 },
  { maxValueLength: 0 },
  { maxDepth: -1 },
  { maxArrayIndex: -1 },
  { duplicatePolicy: 'bad' },
  { allowArrays: 'yes' },
  { duplicateAllowlist: [1] },
  { allowedParams: [null] }
]) {
  test('invalid policy override rejected: ' + JSON.stringify(override), () => {
    assert.throws(() => createPolicy('strict', override), QueryCageError);
  });
}

test('allowedParams mass assignment allowlist blocks hidden parameter', () => {
  const policy = createPolicy('strict', { allowedParams: ['page', 'limit'] });
  const report = auditQuery('page=1&isAdmin=true', policy);
  assertHasCode(report, CODE.PARAMETER_NOT_ALLOWED);
});

test('allowedParams mass assignment allowlist permits listed parameter', () => {
  const policy = createPolicy('strict', { allowedParams: ['page', 'limit'] });
  assert.equal(auditQuery('page=1&limit=20', policy).safe, true);
});

test('blockedParams blocks named root even when no allowlist exists', () => {
  const policy = createPolicy('strict', { blockedParams: ['debug'] });
  assertHasCode(auditQuery('debug=true', policy), CODE.PARAMETER_NOT_ALLOWED);
});

test('sanitize removes mass assignment hidden parameters', () => {
  const policy = createPolicy('strict', { allowedParams: ['page'] });
  const result = sanitizeQuery('page=1&isAdmin=true', policy);
  assert.equal(result.query, 'page=1');
});

test('arrayParamAllowlist null allows arrays in search preset', () => {
  assert.equal(auditQuery('ids[]=1', 'search').safe, true);
});

test('dot notation remains disabled unless explicitly enabled', () => {
  assert.equal(parseQuery('a.b=1', 'strict')['a.b'], '1');
});

test('custom dot notation can be enabled', () => {
  const policy = createPolicy('strict', { allowDotNotation: true, maxDepth: 1 });
  assert.equal(parseQuery('a.b=1', policy).a.b, '1');
});

test('finding cap truncates and report fails closed', () => {
  const policy = createPolicy('search', { maxFindings: 1, arrayParamAllowlist: null });
  const report = auditQuery('__proto__[x]=1&filter[$ne]=1&a[999]=1', policy);
  assert.equal(report.stats.truncated, true);
  assert.equal(report.safe, false);
});

test('isSafeQuery returns false for invalid policy instead of throwing', () => {
  assert.equal(isSafeQuery('a=1', { maxFindings: 0 }), false);
});

test('sanitize drops duplicate root for plain record input', () => {
  const input = { 'a.b': '1', a: { b: '2' }, ok: '1' };
  const policy = createPolicy('search', { allowDotNotation: true, arrayParamAllowlist: null });
  const result = sanitizeQuery(input, policy);
  assert.equal(result.query.includes('ok=1'), true);
  assert.equal(JSON.stringify(result.params).includes('isAdmin'), false);
});

test('plain record nested secret does not poison sibling data during sanitization', () => {
  const result = sanitizeQuery({ user: { password: 'SENTINEL-SECRET' }, ok: '1' }, 'restApi');
  assert.equal(result.query, 'ok=1');
  assert.equal(JSON.stringify(result).includes('SENTINEL-SECRET'), false);
});

test('sanitize handles many parameters in bounded iterations', () => {
  const parts = [];
  for (let index = 0; index < 100; index += 1) parts.push('k' + index + '=v');
  const policy = createPolicy('strict', { maxParams: 10, maxBytes: 4096, maxKeyLength: 96 });
  const result = sanitizeQuery(parts.join('&'), policy);
  assert.equal(result.report.safe, true);
  assert.equal(Object.keys(result.params).length <= 10, true);
});
