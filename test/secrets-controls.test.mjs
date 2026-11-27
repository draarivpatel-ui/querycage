import test from 'node:test';
import assert from 'node:assert/strict';
import { CODE, auditQuery, createPolicy, parseQuery, sanitizeQuery, validateQuery } from '../src/index.mjs';
import { assertHasCode } from './helpers.mjs';

const secretKeys = [
  'password',
  'passwd',
  'token',
  'access_token',
  'id_token',
  'refresh_token',
  'api_key',
  'apikey',
  'secret',
  'client_secret',
  'authorization',
  'jwt',
  'session_id',
  'private_key',
  'accessToken',
  'clientSecret',
  'sessionId'
];

for (const key of secretKeys) {
  test('secret-like flat key is blocked: ' + key, () => {
    const report = auditQuery(key + '=SENTINEL-SECRET', 'strict');
    assertHasCode(report, CODE.SECRET_IN_QUERY);
  });

  test('secret-like nested key is blocked: ' + key, () => {
    const report = auditQuery('user[' + key + ']=SENTINEL-SECRET', 'restApi');
    assertHasCode(report, CODE.SECRET_IN_QUERY);
  });

  test('secret-like deep key is blocked: ' + key, () => {
    const report = auditQuery('auth[user][' + key + ']=SENTINEL-SECRET', 'restApi');
    assertHasCode(report, CODE.SECRET_IN_QUERY);
  });
}

test('similar non secret key is not blocked', () => {
  const report = auditQuery('tokenized=value', 'strict');
  assert.equal(report.safe, true);
});

test('secret detection can be disabled only explicitly', () => {
  const policy = createPolicy('strict', { rejectSecrets: false });
  const parsed = parseQuery('token=SENTINEL-SECRET', policy);
  assert.equal(parsed.token, 'SENTINEL-SECRET');
});

test('audit report never echoes secret value', () => {
  const report = auditQuery('token=SENTINEL-SECRET&ok=1', 'strict');
  const serialized = JSON.stringify(report);
  assert.equal(serialized.includes('SENTINEL-SECRET'), false);
  assert.equal(serialized.includes('token'), true);
});

test('parse error never echoes secret value', () => {
  let text = '';
  try {
    parseQuery('password=SENTINEL-SECRET', 'strict');
  } catch (error) {
    text = [error.name, error.code, error.message, error.detail, error.param].join('|');
  }
  assert.notEqual(text, '');
  assert.equal(text.includes('SENTINEL-SECRET'), false);
});

test('validate report never echoes secret value', () => {
  const result = validateQuery('client_secret=SENTINEL-SECRET', 'strict');
  assert.equal(JSON.stringify(result).includes('SENTINEL-SECRET'), false);
});

test('sanitize removes secret parameter under default defense', () => {
  const result = sanitizeQuery('ok=1&token=SENTINEL-SECRET', 'strict');
  assert.equal(result.query.includes('SENTINEL-SECRET'), false);
  assert.equal(Object.prototype.hasOwnProperty.call(result.params, 'token'), false);
});

test('all findings for secret matrix avoid value echo', () => {
  for (const key of secretKeys) {
    const report = auditQuery('wrap[' + key + ']=SENTINEL-SECRET', 'restApi');
    assert.equal(JSON.stringify(report).includes('SENTINEL-SECRET'), false, key);
  }
});

const controlEncodings = [
  ['nul', '%00'],
  ['cr', '%0d'],
  ['lf', '%0a'],
  ['crlf', '%0d%0a'],
  ['tab', '%09'],
  ['escape', '%1b'],
  ['delete', '%7f'],
  ['c1 nel', '%c2%85'],
  ['arabic letter mark', '%d8%9c'],
  ['left to right mark', '%e2%80%8e'],
  ['right to left mark', '%e2%80%8f'],
  ['line separator', '%e2%80%a8'],
  ['paragraph separator', '%e2%80%a9'],
  ['byte order mark', '%ef%bb%bf'],
  ['bidi isolate', '%e2%81%a6'],
  ['zero width space', '%e2%80%8b']
];

for (const [label, encoded] of controlEncodings) {
  test('control character rejected in value: ' + label, () => {
    const report = auditQuery('a=x' + encoded + 'y', 'strict');
    assertHasCode(report, CODE.CONTROL_CHARACTER);
  });

  test('control character rejected in key: ' + label, () => {
    const report = auditQuery('a' + encoded + 'b=x', 'strict');
    assertHasCode(report, CODE.CONTROL_CHARACTER);
  });
}

test('direct control character in input is rejected', () => {
  const report = auditQuery('a=x' + String.fromCharCode(1) + 'y', 'strict');
  assertHasCode(report, CODE.CONTROL_CHARACTER);
});

test('direct bidi character in input is rejected', () => {
  const report = auditQuery('a=x' + String.fromCodePoint(0x200e) + 'y', 'strict');
  assertHasCode(report, CODE.CONTROL_CHARACTER);
});

test('direct line separator in input is rejected', () => {
  const report = auditQuery('a=x' + String.fromCodePoint(0x2028) + 'y', 'strict');
  assertHasCode(report, CODE.CONTROL_CHARACTER);
});

const invalidUtf8 = [
  '%ff',
  '%c0',
  '%c0%af',
  '%c1%bf',
  '%e0%80%80',
  '%ed%a0%80',
  '%f0%80%80%80',
  '%f4%90%80%80',
  '%80',
  '%bf',
  '%c2',
  '%e2%82',
  '%f0%9f%98',
  '%f8%88%80%80%80'
];

for (const encoded of invalidUtf8) {
  test('invalid UTF-8 rejected in value: ' + encoded, () => {
    const report = auditQuery('a=' + encoded, 'strict');
    assertHasCode(report, CODE.INVALID_ENCODING);
  });

  test('invalid UTF-8 rejected in key: ' + encoded, () => {
    const report = auditQuery(encoded + '=x', 'strict');
    assertHasCode(report, CODE.INVALID_ENCODING);
  });
}

const malformedPercents = [
  '%',
  '%1',
  '%z',
  '%zz',
  'abc%',
  'abc%1',
  'abc%xz',
  '%g0',
  '%0g',
  '%%32'
];

for (const encoded of malformedPercents) {
  test('malformed percent sequence rejected: ' + encoded, () => {
    const report = auditQuery('a=' + encoded, 'strict');
    assertHasCode(report, CODE.INVALID_ENCODING);
  });
}

test('double encoded NUL is rejected as double encoding and control data', () => {
  const report = auditQuery('a=%2500', 'strict');
  assertHasCode(report, CODE.DOUBLE_ENCODING);
});

test('double encoded operator key is rejected', () => {
  const report = auditQuery('filter[%2524where]=1', 'restApi');
  assertHasCode(report, CODE.DOUBLE_ENCODING);
  assertHasCode(report, CODE.NOSQL_OPERATOR);
});

test('double encoding can be allowed only by explicit policy', () => {
  const policy = createPolicy('strict', { rejectDoubleEncoding: false });
  const parsed = parseQuery('a=%2561', policy);
  assert.equal(parsed.a, '%61');
});

test('triple encoded input remains bounded and blocked', () => {
  const report = auditQuery('a=%252541', 'strict');
  assertHasCode(report, CODE.DOUBLE_ENCODING);
});

test('literal percent encoded once is accepted', () => {
  const parsed = parseQuery('a=100%25', 'strict');
  assert.equal(parsed.a, '100%');
});

test('lone surrogate in key is rejected', () => {
  const report = auditQuery('a' + String.fromCharCode(0xd800) + '=x', 'strict');
  assertHasCode(report, CODE.INVALID_ENCODING);
});

test('lone surrogate in value is rejected', () => {
  const report = auditQuery('a=x' + String.fromCharCode(0xdc00), 'strict');
  assertHasCode(report, CODE.INVALID_ENCODING);
});

test('valid astral Unicode is accepted', () => {
  const parsed = parseQuery('a=%F0%9F%9A%80', 'strict');
  assert.equal(parsed.a, '🚀');
});
