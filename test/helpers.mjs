import assert from 'node:assert/strict';

function codes(report) {
  return report.findings.map((finding) => finding.code);
}

function hasCode(report, code) {
  return codes(report).includes(code);
}

function assertHasCode(report, code) {
  assert.equal(hasCode(report, code), true, 'expected ' + code + ' in ' + codes(report).join(','));
}

function assertNoCode(report, code) {
  assert.equal(hasCode(report, code), false, 'did not expect ' + code);
}

function assertFindinglessSafe(report) {
  assert.equal(report.safe, true);
  assert.equal(report.findings.length, 0);
  assert.equal(report.counts.errors, 0);
}

function assertFrozenDeep(value) {
  if (value === null || typeof value !== 'object') return;
  assert.equal(Object.isFrozen(value), true);
  if (Array.isArray(value)) {
    for (const item of value) assertFrozenDeep(item);
    return;
  }
  for (const key of Object.keys(value)) assertFrozenDeep(value[key]);
}

function serializedReportText(value) {
  return JSON.stringify(value, null, 2);
}

export {
  codes,
  hasCode,
  assertHasCode,
  assertNoCode,
  assertFindinglessSafe,
  assertFrozenDeep,
  serializedReportText
};
