import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createPolicy,
  parseQuery,
  auditQuery,
  validateQuery,
  isSafeQuery,
  QueryCageError,
  CODE
} from '../src/index.mjs';
import { assertFindinglessSafe, assertFrozenDeep, assertHasCode } from './helpers.mjs';

const validFlatCases = [
  ['a=1', 'a', '1'],
  ['a=', 'a', ''],
  ['a', 'a', ''],
  ['a=1=2', 'a', '1=2'],
  ['a+b=1', 'a b', '1'],
  ['a=1+2', 'a', '1 2'],
  ['%61=1', 'a', '1'],
  ['a=%31', 'a', '1'],
  ['a%20b=x', 'a b', 'x'],
  ['a=x%20y', 'a', 'x y'],
  ['a.b=1', 'a.b', '1'],
  ['a-b=1', 'a-b', '1'],
  ['a_b=1', 'a_b', '1'],
  ['a~=1', 'a~', '1'],
  ['caf%C3%A9=1', 'café', '1'],
  ['a=caf%C3%A9', 'a', 'café'],
  ['x=alpha%2Cbeta', 'x', 'alpha,beta'],
  ['x=%24value', 'x', '$value'],
  ['x=%5fvalue', 'x', '_value'],
  ['x=100%25', 'x', '100%'],
  ['x=%E2%82%AC', 'x', '€'],
  ['x=%F0%9F%98%80', 'x', '😀'],
  ['x=0', 'x', '0'],
  ['x=false', 'x', 'false'],
  ['x=null', 'x', 'null']
];

for (const [query, key, expected] of validFlatCases) {
  test('parses valid flat query ' + query, () => {
    const parsed = parseQuery(query, 'strict');
    assert.equal(parsed[key], expected);
    assert.equal(Object.getPrototypeOf(parsed), null);
  });
}

test('accepts one leading question mark', () => {
  assert.equal(parseQuery('?a=1', 'strict').a, '1');
});

test('empty query parses to an empty object', () => {
  assert.deepEqual(Object.keys(parseQuery('', 'strict')), []);
});

test('question mark only parses to an empty object', () => {
  assert.deepEqual(Object.keys(parseQuery('?', 'strict')), []);
});

test('empty separators are ignored deterministically', () => {
  const parsed = parseQuery('&&a=1&&b=2&', 'strict');
  assert.equal(parsed.a, '1');
  assert.equal(parsed.b, '2');
});

test('later question marks are query data', () => {
  assert.equal(parseQuery('a=?x', 'strict').a, '?x');
});

test('audit report is safe for a simple query', () => {
  assertFindinglessSafe(auditQuery('a=1&b=2', 'strict'));
});

test('validateQuery returns value when valid', () => {
  const result = validateQuery('a=1', 'strict');
  assert.equal(result.valid, true);
  assert.equal(result.value.a, '1');
});

test('validateQuery returns null value when invalid', () => {
  const result = validateQuery('a=1&a=2', 'strict');
  assert.equal(result.valid, false);
  assert.equal(result.value, null);
});

test('isSafeQuery true for valid input', () => {
  assert.equal(isSafeQuery('a=1', 'strict'), true);
});

test('isSafeQuery false for hostile input', () => {
  assert.equal(isSafeQuery('a=1&a=2', 'strict'), false);
});

test('parseQuery throws typed error with code and param', () => {
  assert.throws(
    () => parseQuery('role=user&role=admin', 'strict'),
    (error) => error instanceof QueryCageError && error.code === CODE.DUPLICATE_PARAMETER && error.param === 'role'
  );
});

for (const maxBytes of [1, 2]) {
  test('maxBytes rejects oversized query at cap ' + maxBytes, () => {
    const report = auditQuery('a=1', createPolicy('strict', { maxBytes }));
    assert.equal(report.safe, false);
    assertHasCode(report, CODE.QUERY_TOO_LARGE);
  });
}

for (const maxBytes of [3, 4, 10]) {
  test('maxBytes accepts bounded query at cap ' + maxBytes, () => {
    const report = auditQuery('a=1', createPolicy('strict', { maxBytes }));
    assert.equal(report.safe, true);
  });
}

for (const maxParams of [1, 2, 3]) {
  test('maxParams cap ' + maxParams + ' is enforced', () => {
    const query = 'a=1&b=2&c=3&d=4';
    const report = auditQuery(query, createPolicy('strict', { maxParams }));
    assert.equal(report.safe, false);
    assertHasCode(report, CODE.TOO_MANY_PARAMS);
  });
}

for (const maxKeyLength of [1, 2, 3]) {
  test('maxKeyLength cap ' + maxKeyLength + ' is enforced', () => {
    const report = auditQuery('abcd=1', createPolicy('strict', { maxKeyLength }));
    assert.equal(report.safe, false);
    assertHasCode(report, CODE.KEY_TOO_LONG);
  });
}

for (const maxValueLength of [1, 2, 3]) {
  test('maxValueLength cap ' + maxValueLength + ' is enforced', () => {
    const report = auditQuery('a=1234', createPolicy('strict', { maxValueLength }));
    assert.equal(report.safe, false);
    assertHasCode(report, CODE.VALUE_TOO_LONG);
  });
}

for (const maxDepth of [0, 1, 2]) {
  test('maxDepth cap ' + maxDepth + ' is enforced', () => {
    const policy = createPolicy('strict', {
      maxDepth,
      allowBrackets: true,
      allowArrays: true,
      arrayParamAllowlist: null
    });
    const report = auditQuery('a[b][c][d]=1', policy);
    assert.equal(report.safe, false);
    assertHasCode(report, CODE.NESTING_TOO_DEEP);
  });
}

for (const maxArrayIndex of [0, 1, 5]) {
  test('maxArrayIndex cap ' + maxArrayIndex + ' is enforced', () => {
    const policy = createPolicy('strict', {
      maxDepth: 1,
      allowBrackets: true,
      allowArrays: true,
      arrayParamAllowlist: null,
      maxArrayIndex,
      maxArrayLength: maxArrayIndex + 1
    });
    const query = 'a[' + String(maxArrayIndex + 1) + ']=x';
    const report = auditQuery(query, policy);
    assert.equal(report.safe, false);
    assertHasCode(report, CODE.ARRAY_INDEX_TOO_LARGE);
  });
}

test('URLSearchParams input parses entries', () => {
  const parsed = parseQuery(new URLSearchParams('a=1&b=2'), 'strict');
  assert.equal(parsed.a, '1');
  assert.equal(parsed.b, '2');
});

test('URLSearchParams duplicate entries are audited', () => {
  const report = auditQuery(new URLSearchParams('a=1&a=2'), 'strict');
  assertHasCode(report, CODE.DUPLICATE_PARAMETER);
});

test('URLSearchParams encoded prototype key is audited after decoding', () => {
  const report = auditQuery(new URLSearchParams('__proto__=1'), 'strict');
  assertHasCode(report, CODE.PROTOTYPE_POLLUTION);
});

test('plain record input parses flat scalar values', () => {
  const parsed = parseQuery({ a: '1', b: 2, c: true, d: null }, 'strict');
  assert.equal(parsed.a, '1');
  assert.equal(parsed.b, '2');
  assert.equal(parsed.c, 'true');
  assert.equal(parsed.d, '');
});

test('plain record input parses nested plain objects', () => {
  const parsed = parseQuery({ a: { b: '1' } }, 'restApi');
  assert.equal(parsed.a.b, '1');
});

test('plain record input parses scalar arrays', () => {
  const policy = createPolicy('restApi', { arrayParamAllowlist: ['ids'] });
  const parsed = parseQuery({ ids: ['1', '2'] }, policy);
  assert.deepEqual(Array.from(parsed.ids), ['1', '2']);
});

test('plain record sparse arrays are rejected', () => {
  const value = ['a'];
  const sparse = [];
  sparse[2] = value[0];
  const report = auditQuery({ a: sparse }, createPolicy('restApi', { arrayParamAllowlist: ['a'] }));
  assertHasCode(report, CODE.SPARSE_ARRAY);
});

test('plain record rejects NaN scalar values', () => {
  const report = auditQuery({ a: Number.NaN }, 'strict');
  assertHasCode(report, CODE.INVALID_INPUT);
});

test('plain record rejects Infinity scalar values', () => {
  const report = auditQuery({ a: Number.POSITIVE_INFINITY }, 'strict');
  assertHasCode(report, CODE.INVALID_INPUT);
});

test('plain record rejects cyclic objects without hanging', () => {
  const input = {};
  input.self = input;
  const report = auditQuery(input, 'restApi');
  assertHasCode(report, CODE.INVALID_INPUT);
});

for (const value of [undefined, Symbol('x')]) {
  test('plain record rejects unsupported scalar type ' + String(typeof value), () => {
    const report = auditQuery({ a: value }, 'strict');
    assertHasCode(report, CODE.INVALID_INPUT);
  });
}

const malformedKeys = [
  'a[[b]=1',
  'a[b=1',
  'a]b[=1',
  '[a]=1',
  'a[]=1',
  'a[0][b]=1',
  'a[][b]=1',
  'a[b][=1',
  'a[b]]=1',
  'a[[b]]=1'
];

for (const query of malformedKeys) {
  test('malformed or unsupported bracket form is rejected: ' + query, () => {
    const report = auditQuery(query, 'restApi');
    assert.equal(report.safe, false);
  });
}

test('dot notation is opt in', () => {
  const parsed = parseQuery('a.b=1', 'strict');
  assert.equal(parsed['a.b'], '1');
});

test('dot notation creates nested null-prototype objects when enabled', () => {
  const policy = createPolicy('strict', { allowDotNotation: true, maxDepth: 2 });
  const parsed = parseQuery('a.b=1', policy);
  assert.equal(parsed.a.b, '1');
  assert.equal(Object.getPrototypeOf(parsed.a), null);
});

test('encoded dots participate in dot notation when enabled', () => {
  const policy = createPolicy('strict', { allowDotNotation: true, maxDepth: 2 });
  const parsed = parseQuery('a%2eb=1', policy);
  assert.equal(parsed.a.b, '1');
});

test('empty dot segments are rejected', () => {
  const policy = createPolicy('strict', { allowDotNotation: true, maxDepth: 2 });
  const report = auditQuery('a..b=1', policy);
  assertHasCode(report, CODE.MALFORMED_KEY);
});

test('parse output is deeply frozen', () => {
  const policy = createPolicy('search', { arrayParamAllowlist: null });
  const parsed = parseQuery('a[b]=1&ids[]=1&ids[]=2', policy);
  assertFrozenDeep(parsed);
});

test('parse output objects have null prototypes', () => {
  const parsed = parseQuery('a[b][c]=1', 'restApi');
  assert.equal(Object.getPrototypeOf(parsed), null);
  assert.equal(Object.getPrototypeOf(parsed.a), null);
  assert.equal(Object.getPrototypeOf(parsed.a.b), null);
});

test('audit reports are deeply frozen', () => {
  const report = auditQuery('a=1&a=2', 'strict');
  assertFrozenDeep(report);
});

test('validate results are deeply frozen', () => {
  const result = validateQuery('a=1', 'strict');
  assertFrozenDeep(result);
});

test('caller record object is not frozen by validation', () => {
  const input = { a: '1' };
  validateQuery(input, 'strict');
  assert.equal(Object.isFrozen(input), false);
});

test('caller policy override object is not frozen by createPolicy', () => {
  const overrides = { maxParams: 2 };
  createPolicy('strict', overrides);
  assert.equal(Object.isFrozen(overrides), false);
});

test('bigint record scalar values are converted deterministically', () => {
  assert.equal(parseQuery({ a: 12n }, 'strict').a, '12');
});

test('negative record numbers are converted as scalar data', () => {
  assert.equal(parseQuery({ a: -2 }, 'strict').a, '-2');
});

test('scientific record numbers are data rather than query syntax', () => {
  assert.equal(parseQuery({ a: 1e3 }, 'strict').a, '1000');
});

for (const input of [1, null, true, [], new Date(0)]) {
  test('invalid top-level input type throws: ' + Object.prototype.toString.call(input), () => {
    assert.throws(() => auditQuery(input, 'strict'), (error) => error instanceof QueryCageError && error.code === CODE.INVALID_INPUT);
  });
}
