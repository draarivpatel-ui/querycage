import test from 'node:test';
import assert from 'node:assert/strict';
import {
  CODE,
  QueryCageError,
  auditQuery,
  createPolicy,
  parseQuery,
  sanitizeQuery,
  serializeQueryTree
} from '../src/index.mjs';
import { assertHasCode, assertNoCode } from './helpers.mjs';

test('raw fragment delimiter is rejected with a dedicated code', () => {
  for (const query of ['a=1#&b=2', '?a=1#&b=2', 'a=1#fragment', 'a=1#']) {
    const report = auditQuery(query, 'strict');
    assert.equal(report.safe, false);
    assertHasCode(report, CODE.FRAGMENT_IN_QUERY);
  }
});

test('sanitize removes the parameter implicated by a raw fragment', () => {
  const result = sanitizeQuery('ok=1&a=1#fragment', 'strict');
  assert.equal(result.query, 'ok=1');
  assert.equal(result.params.a, undefined);
});

test('encoded fragment sign remains valid query data', () => {
  assert.equal(parseQuery('a=1%23fragment', 'strict').a, '1#fragment');
});

test('malformed dot paths are rejected even when dot notation is disabled', () => {
  for (const query of ['.user=1', 'user.=1', 'user..password=1']) {
    const report = auditQuery(query, 'strict');
    assert.equal(report.safe, false, query);
    assertHasCode(report, CODE.MALFORMED_KEY);
  }
});

test('ordinary dotted names remain literal keys when dot notation is disabled', () => {
  assert.equal(parseQuery('user.password=1', 'strict')['user.password'], '1');
});

test('duplicate allowlist cannot create arrays when arrays are disabled', () => {
  const policy = createPolicy('strict', {
    duplicatePolicy: 'allowlist',
    duplicateAllowlist: ['role']
  });
  const report = auditQuery('role=user&role=admin', policy);
  assert.equal(report.safe, false);
  assertHasCode(report, CODE.ARRAY_NOT_ALLOWED);
});

test('URLSearchParams input is not decoded a second time', () => {
  const input = new URLSearchParams();
  input.set('literal', '%61');
  input.set('%61', 'key');
  const parsed = parseQuery(input, 'strict');
  assert.equal(parsed.literal, '%61');
  assert.equal(parsed['%61'], 'key');
  assert.equal(parsed.a, undefined);
});

test('raw query decoding preserves exactly one layer when double encoding is allowed', () => {
  const policy = createPolicy('strict', { rejectDoubleEncoding: false });
  const parsed = parseQuery('%2561=%2562', policy);
  assert.equal(parsed['%61'], '%62');
});

test('hidden double encoded prototype and operator keys remain blocked', () => {
  const proto = auditQuery('%255f%255fproto%255f%255f=1', 'strict');
  assertHasCode(proto, CODE.DOUBLE_ENCODING);
  assertHasCode(proto, CODE.PROTOTYPE_POLLUTION);
  const operator = auditQuery('filter[%2524where]=1', 'restApi');
  assertHasCode(operator, CODE.DOUBLE_ENCODING);
  assertHasCode(operator, CODE.NOSQL_OPERATOR);
});

test('finding params never carry line breaks or terminal control data', () => {
  const report = auditQuery('a%0ab=x', 'strict');
  assert.equal(report.safe, false);
  for (const finding of report.findings) {
    if (typeof finding.param === 'string') {
      assert.equal(finding.param.includes('\n'), false);
      assert.equal(finding.param.includes('\r'), false);
      assert.equal(finding.param.includes(String.fromCharCode(27)), false);
    }
  }
});

test('throwing getter in record input is rejected without invoking the getter', () => {
  const input = {};
  let invoked = false;
  Object.defineProperty(input, 'boom', {
    enumerable: true,
    get() {
      invoked = true;
      throw new Error('getterboom');
    }
  });
  const report = auditQuery(input, 'restApi');
  assert.equal(invoked, false);
  assert.equal(report.safe, false);
  assertHasCode(report, CODE.INVALID_INPUT);
});

test('deep record input is rejected without recursion failure', () => {
  const input = {};
  let node = input;
  for (let depth = 0; depth < 20000; depth += 1) {
    node.x = {};
    node = node.x;
  }
  node.leaf = '1';
  const report = auditQuery(input, 'restApi');
  assert.equal(report.safe, false);
  assertHasCode(report, CODE.NESTING_TOO_DEEP);
});

test('shared object references in record input are rejected as non tree data', () => {
  const shared = { leaf: '1' };
  const report = auditQuery({ a: shared, b: shared }, 'restApi');
  assert.equal(report.safe, false);
  assertHasCode(report, CODE.INVALID_INPUT);
});

test('empty nested objects and arrays are rejected instead of silently disappearing', () => {
  for (const input of [{ a: {} }, { a: [] }]) {
    const report = auditQuery(input, 'restApi');
    assert.equal(report.safe, false);
    assertHasCode(report, CODE.INVALID_INPUT);
  }
});

test('wide record input stops at the configured parameter budget', () => {
  const input = {};
  for (let index = 0; index < 10000; index += 1) input['k' + index] = 'v';
  const report = auditQuery(input, 'search');
  assert.equal(report.safe, false);
  assertHasCode(report, CODE.TOO_MANY_PARAMS);
});

function assertInvalidSerializerTree(tree, label) {
  assert.throws(
    () => serializeQueryTree(tree),
    (error) => error instanceof QueryCageError && error.code === CODE.INVALID_INPUT,
    label
  );
}

test('serializer rejects unrepresentable or unsafe tree shapes', () => {
  const emptyKey = Object.create(null);
  emptyKey[''] = 'x';
  assertInvalidSerializerTree(emptyKey, 'empty key');

  const bracketKey = Object.create(null);
  bracketKey['a]b'] = 'x';
  assertInvalidSerializerTree(bracketKey, 'bracket key');

  for (const value of [undefined, null, function value() {}, [['x']], [{ x: '1' }]]) {
    const tree = Object.create(null);
    tree.a = value;
    assertInvalidSerializerTree(tree, 'invalid scalar or array shape');
  }

  const cyclic = Object.create(null);
  cyclic.self = cyclic;
  assertInvalidSerializerTree(cyclic, 'cyclic tree');
});

test('serializer rejects control text instead of emitting non round trippable canonical data', () => {
  const tree = Object.create(null);
  tree.a = 'x\ny';
  assertInvalidSerializerTree(tree, 'control value');
});

test('serializer encoded delimiters cannot split query pairs', () => {
  const tree = Object.create(null);
  tree['a&b'] = 'x=y#z';
  const output = serializeQueryTree(tree);
  assert.equal(output, 'a%26b=x%3Dy%23z');
  assert.equal(output.includes('#'), false);
});

test('parser generated trees round trip through canonical serialization', () => {
  const policy = createPolicy('restApi', { arrayParamAllowlist: ['ids'] });
  const parsed = parseQuery('z=1&a[b]=2&ids[]=1&ids[]=2', policy);
  const canonical = serializeQueryTree(parsed);
  assert.equal(auditQuery(canonical, policy).safe, true);
  assert.equal(serializeQueryTree(parseQuery(canonical, policy)), canonical);
});

test('oversized raw queries fail before decoding the oversized body', () => {
  const report = auditQuery('a=' + 'x'.repeat(1024 * 1024), 'strict');
  assert.equal(report.safe, false);
  assertHasCode(report, CODE.QUERY_TOO_LARGE);
  assertNoCode(report, CODE.VALUE_TOO_LONG);
});
