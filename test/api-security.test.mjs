import test from 'node:test';
import assert from 'node:assert/strict';
import { CODE, auditFields, auditPagination, auditSort, createPolicy, QueryCageError } from '../src/index.mjs';
import { assertHasCode, assertFrozenDeep } from './helpers.mjs';

const validPagination = [
  ['page=1', { page: 1 }],
  ['page=2', { page: 2 }],
  ['limit=1', { limit: 1 }],
  ['limit=100', { limit: 100 }],
  ['per_page=10', { limit: 10 }],
  ['limit=20&per_page=20', { limit: 20 }],
  ['offset=0', { offset: 0 }],
  ['offset=1', { offset: 1 }],
  ['offset=10000', { offset: 10000 }],
  ['page=1&limit=20&offset=0', { page: 1, limit: 20, offset: 0 }],
  ['cursor=abc', { cursor: 'abc' }],
  ['cursor=opaque-cursor_123', { cursor: 'opaque-cursor_123' }],
  ['page=1&cursor=abc', { page: 1, cursor: 'abc' }],
  ['', {}],
  ['other=value', {}]
];

for (const [query, expected] of validPagination) {
  test('valid pagination accepted: ' + (query || 'empty'), () => {
    const report = auditPagination(query, 'restApi');
    assert.equal(report.safe, true, JSON.stringify(report.findings));
    for (const key of Object.keys(expected)) assert.equal(report.pagination[key], expected[key]);
    assertFrozenDeep(report);
  });
}

const invalidPaginationValues = [
  '0',
  '-1',
  '+1',
  '01',
  '1.0',
  '1.5',
  '1e3',
  '1E3',
  'NaN',
  'Infinity',
  '-Infinity',
  'abc',
  '',
  ' 1',
  '1 ',
  '1_000',
  '0x10',
  '1,000',
  '999999999999999999999999'
];

for (const value of invalidPaginationValues) {
  test('invalid page value rejected: ' + JSON.stringify(value), () => {
    const report = auditPagination('page=' + encodeURIComponent(value), 'restApi');
    assert.equal(report.safe, false);
  });

  test('invalid limit value rejected: ' + JSON.stringify(value), () => {
    const report = auditPagination('limit=' + encodeURIComponent(value), 'restApi');
    assert.equal(report.safe, false);
  });

  test('invalid offset value rejected: ' + JSON.stringify(value), () => {
    if (value === '0') return;
    const report = auditPagination('offset=' + encodeURIComponent(value), 'restApi');
    assert.equal(report.safe, false);
  });
}

test('offset zero is valid first page offset', () => {
  const report = auditPagination('offset=0', 'restApi');
  assert.equal(report.safe, true);
  assert.equal(report.pagination.offset, 0);
});

for (const offset of [10001, 100000, 1000000000]) {
  test('offset denial of service cap rejects offset ' + offset, () => {
    const report = auditPagination('offset=' + String(offset), 'restApi');
    assert.equal(report.safe, false);
    assertHasCode(report, CODE.INVALID_PAGINATION);
  });
}

for (const limit of [101, 1000, 1000000]) {
  test('limit cap rejects limit ' + limit, () => {
    const report = auditPagination('limit=' + String(limit), 'restApi');
    assert.equal(report.safe, false);
  });
}

test('custom maxLimit is enforced', () => {
  const policy = createPolicy('restApi', { maxLimit: 10 });
  assert.equal(auditPagination('limit=10', policy).safe, true);
  assert.equal(auditPagination('limit=11', policy).safe, false);
});

test('custom maxOffset is enforced', () => {
  const policy = createPolicy('restApi', { maxOffset: 10 });
  assert.equal(auditPagination('offset=10', policy).safe, true);
  assert.equal(auditPagination('offset=11', policy).safe, false);
});

test('custom maxPage is enforced', () => {
  const policy = createPolicy('restApi', { maxPage: 10 });
  assert.equal(auditPagination('page=10', policy).safe, true);
  assert.equal(auditPagination('page=11', policy).safe, false);
});

test('conflicting limit and per_page are rejected', () => {
  const report = auditPagination('limit=10&per_page=20', 'restApi');
  assert.equal(report.safe, false);
  assertHasCode(report, CODE.INVALID_PAGINATION);
});

test('matching limit and per_page are accepted', () => {
  const report = auditPagination('limit=20&per_page=20', 'restApi');
  assert.equal(report.safe, true);
  assert.equal(report.pagination.limit, 20);
});

test('duplicate pagination scalar is rejected by query audit', () => {
  const report = auditPagination('page=1&page=2', 'restApi');
  assert.equal(report.safe, false);
  assertHasCode(report, CODE.DUPLICATE_PARAMETER);
});

test('empty cursor is rejected', () => {
  const report = auditPagination('cursor=', 'restApi');
  assert.equal(report.safe, false);
});

test('array shaped pagination value is rejected', () => {
  const policy = createPolicy('restApi', { arrayParamAllowlist: ['page'] });
  const report = auditPagination('page[]=1', policy);
  assert.equal(report.safe, false);
});

test('record input pagination accepts canonical strings', () => {
  const report = auditPagination({ page: '1', limit: '20', offset: '0' }, 'restApi');
  assert.equal(report.safe, true);
  assert.equal(report.pagination.page, 1);
});

test('record input pagination rejects NaN before normalization', () => {
  const report = auditPagination({ page: Number.NaN }, 'restApi');
  assert.equal(report.safe, false);
});

test('record input pagination rejects Infinity before normalization', () => {
  const report = auditPagination({ offset: Number.POSITIVE_INFINITY }, 'restApi');
  assert.equal(report.safe, false);
});

test('pagination canonical output is deterministic', () => {
  const first = auditPagination('page=1&limit=20&offset=0', 'restApi').canonical;
  const second = auditPagination('offset=0&limit=20&page=1', 'restApi').canonical;
  assert.equal(first, second);
});

test('pagination findings never echo hostile values', () => {
  const sentinel = 'HOSTILE-VALUE-SENTINEL';
  const report = auditPagination('page=' + sentinel, 'restApi');
  assert.equal(JSON.stringify(report).includes(sentinel), false);
});

const sortAllowlist = ['created_at', 'name', 'email', 'id'];
const validSorts = [
  ['name', [{ field: 'name', direction: 'asc' }], 'name'],
  ['-created_at', [{ field: 'created_at', direction: 'desc' }], '-created_at'],
  ['+name', [{ field: 'name', direction: 'asc' }], 'name'],
  ['name:asc', [{ field: 'name', direction: 'asc' }], 'name'],
  ['name:desc', [{ field: 'name', direction: 'desc' }], '-name'],
  ['-created_at,name', [{ field: 'created_at', direction: 'desc' }, { field: 'name', direction: 'asc' }], '-created_at,name'],
  ['id,name,email', [{ field: 'id', direction: 'asc' }, { field: 'name', direction: 'asc' }, { field: 'email', direction: 'asc' }], 'id,name,email']
];

for (const [input, expected, canonical] of validSorts) {
  test('valid sort accepted: ' + input, () => {
    const report = auditSort(input, sortAllowlist, 'restApi');
    assert.equal(report.safe, true, JSON.stringify(report.findings));
    assert.deepEqual(JSON.parse(JSON.stringify(report.sort)), expected);
    assert.equal(report.canonical, canonical);
    assertFrozenDeep(report);
  });
}

const invalidSorts = [
  '',
  ',',
  'name,',
  ',name',
  'name,,id',
  '-',
  '+',
  '--name',
  'name:',
  ':asc',
  'name:ASC',
  'name:DESC',
  'name:sideways',
  'name:asc:extra',
  '-name:desc',
  ' password',
  'name ',
  'password_hash',
  'secret',
  'created_at; DROP TABLE users',
  '(CASE WHEN 1=1 THEN name END)',
  'name/**/desc',
  'name|id',
  'name\\',
  'name--',
  'name\x00',
  '1;DELETE FROM users',
  'unknown_column'
];

for (const input of invalidSorts) {
  test('invalid or hostile sort rejected: ' + JSON.stringify(input), () => {
    const report = auditSort(input, sortAllowlist, 'restApi');
    assert.equal(report.safe, false);
    assertHasCode(report, CODE.INVALID_SORT);
  });
}

test('duplicate sort field is rejected', () => {
  const report = auditSort('name,-name', sortAllowlist, 'restApi');
  assert.equal(report.safe, false);
});

test('sort field count cap is enforced', () => {
  const policy = createPolicy('restApi', { maxSortFields: 2 });
  const report = auditSort('id,name,email', sortAllowlist, policy);
  assert.equal(report.safe, false);
});

test('sort field count within cap is accepted', () => {
  const policy = createPolicy('restApi', { maxSortFields: 2 });
  const report = auditSort('id,name', sortAllowlist, policy);
  assert.equal(report.safe, true);
});

for (const input of [null, undefined, 1, true, [], {}]) {
  test('non string sort input rejected: ' + Object.prototype.toString.call(input), () => {
    const report = auditSort(input, sortAllowlist, 'restApi');
    assert.equal(report.safe, false);
  });
}

test('sort rejection does not echo probed private column', () => {
  const report = auditSort('password_hash', sortAllowlist, 'restApi');
  assert.equal(JSON.stringify(report).includes('password_hash'), false);
});

test('sort rejection does not echo SQL injection text', () => {
  const sentinel = 'DROP TABLE users';
  const report = auditSort('name; ' + sentinel, sortAllowlist, 'restApi');
  assert.equal(JSON.stringify(report).includes(sentinel), false);
});

test('invalid sort allowlist type throws typed policy error', () => {
  assert.throws(() => auditSort('name', null, 'restApi'), (error) => error instanceof QueryCageError && error.code === CODE.INVALID_POLICY);
});

test('invalid sort allowlist entry throws typed policy error', () => {
  assert.throws(() => auditSort('name', ['name '], 'restApi'), (error) => error instanceof QueryCageError && error.code === CODE.INVALID_POLICY);
});

const fieldAllowlist = ['id', 'name', 'email', 'created_at'];
const validFields = [
  ['id', ['id']],
  ['id,name', ['id', 'name']],
  ['id,name,email', ['id', 'name', 'email']],
  ['created_at', ['created_at']]
];

for (const [input, expected] of validFields) {
  test('valid sparse field projection accepted: ' + input, () => {
    const report = auditFields(input, fieldAllowlist, 'restApi');
    assert.equal(report.safe, true);
    assert.deepEqual(report.fields, expected);
    assert.equal(report.canonical, expected.join(','));
  });
}

const invalidFields = [
  '',
  ',',
  'id,',
  ',id',
  'id,,name',
  'id,id',
  'password',
  'password_hash',
  'secret',
  'token',
  'unknown',
  ' id',
  'id ',
  'id;DROP TABLE users',
  '(select password)',
  'id\x00'
];

for (const input of invalidFields) {
  test('invalid or hostile field projection rejected: ' + JSON.stringify(input), () => {
    const report = auditFields(input, fieldAllowlist, 'restApi');
    assert.equal(report.safe, false);
    assertHasCode(report, CODE.INVALID_FIELD);
  });
}

test('field projection count cap is enforced', () => {
  const policy = createPolicy('restApi', { maxProjectionFields: 2 });
  const report = auditFields('id,name,email', fieldAllowlist, policy);
  assert.equal(report.safe, false);
});

test('field projection count within cap is accepted', () => {
  const policy = createPolicy('restApi', { maxProjectionFields: 2 });
  const report = auditFields('id,name', fieldAllowlist, policy);
  assert.equal(report.safe, true);
});

for (const input of [null, undefined, 1, true, [], {}]) {
  test('non string fields input rejected: ' + Object.prototype.toString.call(input), () => {
    const report = auditFields(input, fieldAllowlist, 'restApi');
    assert.equal(report.safe, false);
  });
}

test('field rejection does not echo probed private field', () => {
  const report = auditFields('password_hash', fieldAllowlist, 'restApi');
  assert.equal(JSON.stringify(report).includes('password_hash'), false);
});

test('invalid fields allowlist type throws typed policy error', () => {
  assert.throws(() => auditFields('id', null, 'restApi'), (error) => error instanceof QueryCageError && error.code === CODE.INVALID_POLICY);
});

test('invalid fields allowlist entry throws typed policy error', () => {
  assert.throws(() => auditFields('id', ['id '], 'restApi'), (error) => error instanceof QueryCageError && error.code === CODE.INVALID_POLICY);
});
