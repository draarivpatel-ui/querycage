import test from 'node:test';
import assert from 'node:assert/strict';
import { CODE, auditQuery, createPolicy, parseQuery } from '../src/index.mjs';
import { assertHasCode } from './helpers.mjs';

const forbiddenKeys = [
  '__proto__',
  'constructor',
  'prototype',
  'toString',
  'valueOf',
  'hasOwnProperty',
  '__defineGetter__',
  '__defineSetter__',
  '__lookupGetter__',
  '__lookupSetter__'
];

const searchPolicy = createPolicy('search', { arrayParamAllowlist: null, maxDepth: 3 });
const dotPolicy = createPolicy('search', { arrayParamAllowlist: null, maxDepth: 4, allowDotNotation: true });

function percentEncodeText(value) {
  let output = '';
  for (let index = 0; index < value.length; index += 1) {
    output += '%' + value.charCodeAt(index).toString(16).toUpperCase().padStart(2, '0');
  }
  return output;
}

function doubleEncodeText(value) {
  return percentEncodeText(percentEncodeText(value));
}

for (const key of forbiddenKeys) {
  test('prototype key blocked as flat key: ' + key, () => {
    const report = auditQuery(key + '=1', searchPolicy);
    assertHasCode(report, CODE.PROTOTYPE_POLLUTION);
  });

  test('prototype key blocked as nested key: ' + key, () => {
    const report = auditQuery('a[' + key + ']=1', searchPolicy);
    assertHasCode(report, CODE.PROTOTYPE_POLLUTION);
  });

  test('prototype key blocked as root with child: ' + key, () => {
    const report = auditQuery(key + '[x]=1', searchPolicy);
    assertHasCode(report, CODE.PROTOTYPE_POLLUTION);
  });

  test('prototype key blocked at deep nesting: ' + key, () => {
    const report = auditQuery('a[b][' + key + ']=1', searchPolicy);
    assertHasCode(report, CODE.PROTOTYPE_POLLUTION);
  });

  test('prototype key blocked in dot notation: ' + key, () => {
    const report = auditQuery('a.' + key + '=1', dotPolicy);
    assertHasCode(report, CODE.PROTOTYPE_POLLUTION);
  });

  test('single encoded prototype key blocked: ' + key, () => {
    const report = auditQuery(percentEncodeText(key) + '=1', searchPolicy);
    assertHasCode(report, CODE.PROTOTYPE_POLLUTION);
  });

  test('double encoded prototype key blocked: ' + key, () => {
    const report = auditQuery(doubleEncodeText(key) + '=1', searchPolicy);
    assertHasCode(report, CODE.DOUBLE_ENCODING);
    assertHasCode(report, CODE.PROTOTYPE_POLLUTION);
  });
}

test('specified proto pollution payload is blocked', () => {
  const report = auditQuery('__proto__[isAdmin]=true', searchPolicy);
  assertHasCode(report, CODE.PROTOTYPE_POLLUTION);
});

test('specified constructor prototype pollution payload is blocked', () => {
  const report = auditQuery('constructor[prototype][role]=admin', searchPolicy);
  assertHasCode(report, CODE.PROTOTYPE_POLLUTION);
});

test('specified encoded proto payload is blocked', () => {
  const report = auditQuery('%5f%5fproto%5f%5f[isAdmin]=true', searchPolicy);
  assertHasCode(report, CODE.PROTOTYPE_POLLUTION);
});

test('specified double encoded proto payload is blocked', () => {
  const report = auditQuery('%255f%255fproto%255f%255f%5bisAdmin%5d=true', searchPolicy);
  assertHasCode(report, CODE.DOUBLE_ENCODING);
  assertHasCode(report, CODE.PROTOTYPE_POLLUTION);
});

test('case variant of constructor is blocked conservatively', () => {
  const report = auditQuery('Constructor[prototype][x]=1', searchPolicy);
  assertHasCode(report, CODE.PROTOTYPE_POLLUTION);
});

test('whitespace padded proto segment is blocked conservatively', () => {
  const report = auditQuery('%20__proto__%20[x]=1', searchPolicy);
  assertHasCode(report, CODE.PROTOTYPE_POLLUTION);
});

test('parser does not mutate Object prototype after attack input', () => {
  const before = Object.prototype.pollutedQueryCageProbe;
  auditQuery('__proto__[pollutedQueryCageProbe]=yes', searchPolicy);
  assert.equal(Object.prototype.pollutedQueryCageProbe, before);
});

test('parser output objects are null-prototype even near blocked input', () => {
  const parsed = parseQuery('a[b]=1', 'restApi');
  assert.equal(Object.getPrototypeOf(parsed.a), null);
});

const operators = [
  '$ne',
  '$gt',
  '$gte',
  '$lt',
  '$lte',
  '$in',
  '$nin',
  '$regex',
  '$where',
  '$expr',
  '$or',
  '$and',
  '$exists',
  '$elemMatch',
  '$lookup',
  '$function'
];

for (const operator of operators) {
  test('NoSQL operator blocked as flat key: ' + operator, () => {
    const report = auditQuery(operator + '=1', searchPolicy);
    assertHasCode(report, CODE.NOSQL_OPERATOR);
  });

  test('NoSQL operator blocked in filter bracket: ' + operator, () => {
    const report = auditQuery('filter[' + operator + ']=1', searchPolicy);
    assertHasCode(report, CODE.NOSQL_OPERATOR);
  });

  test('NoSQL operator blocked at deep nesting: ' + operator, () => {
    const report = auditQuery('user[filter][' + operator + ']=1', searchPolicy);
    assertHasCode(report, CODE.NOSQL_OPERATOR);
  });
}

test('encoded dollar operator is blocked', () => {
  const report = auditQuery('filter[%24ne]=1', searchPolicy);
  assertHasCode(report, CODE.NOSQL_OPERATOR);
});

test('double encoded dollar operator is blocked', () => {
  const report = auditQuery('filter[%2524ne]=1', searchPolicy);
  assertHasCode(report, CODE.DOUBLE_ENCODING);
  assertHasCode(report, CODE.NOSQL_OPERATOR);
});


test('whitespace padded dollar operator is blocked conservatively', () => {
  const report = auditQuery('filter[%20$ne]=1', searchPolicy);
  assertHasCode(report, CODE.NOSQL_OPERATOR);
});

test('unknown dollar prefixed segment is blocked conservatively', () => {
  const report = auditQuery('filter[$custom]=1', searchPolicy);
  assertHasCode(report, CODE.NOSQL_OPERATOR);
});

test('dollar inside a value is not an operator key', () => {
  const report = auditQuery('filter[value]=$ne', searchPolicy);
  assert.equal(report.safe, true);
});

test('NoSQL operator check can be disabled only explicitly', () => {
  const policy = createPolicy('search', { rejectNoSqlOperators: false, arrayParamAllowlist: null });
  const report = auditQuery('filter[$ne]=1', policy);
  assert.equal(report.safe, true);
});

const explosiveIndexes = [100, 999, 999999, 10000000];
for (const index of explosiveIndexes) {
  test('index explosion blocked for a[' + index + ']', () => {
    const report = auditQuery('a[' + String(index) + ']=1', searchPolicy);
    assertHasCode(report, CODE.ARRAY_INDEX_TOO_LARGE);
  });
}

for (const index of ['-1', '-10', '001', '00', '01', '000001']) {
  test('negative or non canonical array index blocked: ' + index, () => {
    const report = auditQuery('a[' + index + ']=1', searchPolicy);
    assertHasCode(report, CODE.SPARSE_ARRAY);
  });
}

for (const query of [
  'a[2]=x',
  'a[0]=x&a[2]=z',
  'a[1]=x&a[3]=z',
  'a[5]=x',
  'a[]=x&a[3]=z'
]) {
  test('sparse array shape blocked: ' + query, () => {
    const report = auditQuery(query, searchPolicy);
    assertHasCode(report, CODE.SPARSE_ARRAY);
  });
}

test('maximum contiguous small array accepted', () => {
  const parsed = parseQuery('a[0]=x&a[1]=y', searchPolicy);
  assert.deepEqual(Array.from(parsed.a), ['x', 'y']);
});

test('strict preset rejects arrays entirely', () => {
  const report = auditQuery('a[]=1', 'strict');
  assert.equal(report.safe, false);
  assert.equal(
    report.findings.some((finding) => finding.code === CODE.ARRAY_NOT_ALLOWED || finding.code === CODE.NESTING_NOT_ALLOWED),
    true
  );
});

test('restApi rejects arrays outside arrayParamAllowlist', () => {
  const report = auditQuery('ids[]=1', 'restApi');
  assertHasCode(report, CODE.ARRAY_NOT_ALLOWED);
});

test('restApi accepts arrays inside arrayParamAllowlist', () => {
  const policy = createPolicy('restApi', { arrayParamAllowlist: ['ids'] });
  const report = auditQuery('ids[]=1&ids[]=2', policy);
  assert.equal(report.safe, true);
});

const malformed = [
  'a[[b]=1',
  'a[b=1',
  'a]x=1',
  '[a]=1',
  'a[b]]=1',
  'a[[b]]=1',
  'a[]x=1',
  'a[0][b]=1',
  'a[][b]=1',
  'a[[]]=1'
];
for (const query of malformed) {
  test('malformed bracket attack rejected: ' + query, () => {
    const report = auditQuery(query, searchPolicy);
    assert.equal(report.safe, false);
  });
}

for (const depth of [4, 5, 6, 8]) {
  test('depth bomb rejected at depth ' + depth, () => {
    let key = 'a';
    for (let index = 0; index < depth; index += 1) key += '[x]';
    const report = auditQuery(key + '=1', searchPolicy);
    assertHasCode(report, CODE.NESTING_TOO_DEEP);
  });
}

test('bounded nesting at depth three is accepted by search preset', () => {
  const report = auditQuery('a[b][c][d]=1', 'search');
  assert.equal(report.safe, true);
});

test('restApi depth cap is two', () => {
  assert.equal(auditQuery('a[b][c]=1', 'restApi').safe, true);
  const report = auditQuery('a[b][c][d]=1', 'restApi');
  assertHasCode(report, CODE.NESTING_TOO_DEEP);
});

test('array length cap is enforced for append input', () => {
  const policy = createPolicy('search', { arrayParamAllowlist: null, maxArrayIndex: 2, maxArrayLength: 2 });
  const report = auditQuery('a[]=1&a[]=2&a[]=3', policy);
  assertHasCode(report, CODE.SPARSE_ARRAY);
});

test('array length cap is enforced for indexed input', () => {
  const policy = createPolicy('search', { arrayParamAllowlist: null, maxArrayIndex: 2, maxArrayLength: 2 });
  const report = auditQuery('a[0]=1&a[1]=2&a[2]=3', policy);
  assertHasCode(report, CODE.SPARSE_ARRAY);
});
