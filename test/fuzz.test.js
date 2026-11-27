import test from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';

import {
  CODE,
  QueryCageError,
  auditQuery,
  parseQuery,
  sanitizeQuery,
} from '../src/index.mjs';

const propertyOptions = { seed: 20261127, numRuns: 120 };
const keyArbitrary = fc.stringMatching(/^q[a-z0-9_]{0,12}$/);
const valueArbitrary = fc.stringMatching(/^[A-Za-z0-9][A-Za-z0-9._-]{0,24}$/);

test('benign scalar parameters parse exactly once into null-prototype output', () => {
  fc.assert(
    fc.property(keyArbitrary, valueArbitrary, (key, value) => {
      const parsed = parseQuery(`${key}=${value}`, 'strict');
      assert.equal(parsed[key], value);
      assert.equal(Object.getPrototypeOf(parsed), null);
    }),
    propertyOptions,
  );
});

test('duplicate scalar parameters remain hard parameter pollution failures', () => {
  fc.assert(
    fc.property(keyArbitrary, valueArbitrary, valueArbitrary, (key, first, second) => {
      assert.throws(
        () => parseQuery(`${key}=${first}&${key}=${second}`, 'strict'),
        (error) => error instanceof QueryCageError && error.code === CODE.DUPLICATE_PARAMETER && error.param === key,
      );
    }),
    propertyOptions,
  );
});

test('generated NoSQL operator keys are reported before database use', () => {
  const operator = fc.constantFrom('$ne', '$gt', '$gte', '$regex', '$where', '$function');
  fc.assert(
    fc.property(operator, valueArbitrary, (operatorKey, value) => {
      const report = auditQuery(`${operatorKey}=${value}`, 'strict');
      assert.equal(report.safe, false);
      assert.ok(report.findings.some((finding) => finding.code === CODE.NOSQL_OPERATOR));
    }),
    propertyOptions,
  );
});

test('generated prototype path keys are reported without polluting object prototypes', () => {
  const prototypeKey = fc.constantFrom('__proto__', 'constructor', 'prototype', 'toString', 'valueOf');
  const before = Object.prototype.querycageFuzzPollution;
  fc.assert(
    fc.property(prototypeKey, valueArbitrary, (key, value) => {
      const report = auditQuery(`${key}[querycageFuzzPollution]=${value}`, 'restApi');
      assert.equal(report.safe, false);
      assert.ok(report.findings.some((finding) => finding.code === CODE.PROTOTYPE_POLLUTION));
      assert.equal(Object.prototype.querycageFuzzPollution, before);
    }),
    propertyOptions,
  );
});

test('sanitizer keeps generated benign input and removes hostile top-level parameters', () => {
  fc.assert(
    fc.property(keyArbitrary, valueArbitrary, (key, value) => {
      const result = sanitizeQuery(`${key}=${value}&filter[$ne]=1&__proto__[polluted]=true`, 'restApi');
      assert.equal(result.report.safe, true);
      assert.equal(result.params[key], value);
      assert.equal(result.query, `${key}=${value}`);
      assert.deepEqual(Object.keys(result.params), [key]);
      assert.ok(result.removedParams.includes('filter'));
      assert.ok(result.removedParams.includes('__proto__'));
    }),
    propertyOptions,
  );
});
