import { QueryCageError, CODE } from './errors.mjs';
import { resolvePolicy } from './policy.mjs';
import { deepFreezeCopy, firstForbiddenControl, utf8ByteLength } from './utils.mjs';

function validateAllowlist(allowedFields, policy, kind) {
  if (!Array.isArray(allowedFields)) {
    throw new QueryCageError(CODE.INVALID_POLICY, kind + ' allowedFields must be an array of field names', 'allowedFields');
  }
  const copy = [];
  for (const field of allowedFields) {
    if (typeof field !== 'string' || field.length === 0 || utf8ByteLength(field) > policy.maxKeyLength || firstForbiddenControl(field) !== null) {
      throw new QueryCageError(CODE.INVALID_POLICY, kind + ' allowlist entries must be bounded clean strings', 'allowedFields');
    }
    if (field.indexOf(',') !== -1 || field.indexOf(':') !== -1 || field.indexOf(';') !== -1 || field.indexOf('(') !== -1 || field.indexOf(')') !== -1 || field !== field.trim()) {
      throw new QueryCageError(CODE.INVALID_POLICY, kind + ' allowlist entries must be canonical field names', 'allowedFields');
    }
    if (!copy.includes(field)) copy.push(field);
  }
  return copy;
}

function addFinding(findings, policy, code, message, param) {
  if (findings.length >= policy.maxFindings) return false;
  const finding = { code, severity: 'error', message };
  if (typeof param === 'string') finding.param = param;
  findings.push(finding);
  return true;
}

function splitComma(input) {
  const parts = [];
  let start = 0;
  for (let position = 0; position <= input.length; position += 1) {
    if (position === input.length || input[position] === ',') {
      parts.push(input.slice(start, position));
      start = position + 1;
    }
  }
  return parts;
}

function finishReport(findings, policy, extra) {
  const truncated = findings.length >= policy.maxFindings;
  const errors = findings.filter((finding) => finding.severity === 'error').length;
  const warnings = findings.length - errors;
  const base = {
    safe: errors === 0 && !truncated,
    findings,
    counts: { errors, warnings },
    stats: { truncated }
  };
  for (const key of Object.keys(extra)) base[key] = extra[key];
  return deepFreezeCopy(base);
}

function parseSortItem(item) {
  if (item.length === 0) return null;
  const colonCount = item.split(':').length - 1;
  if (colonCount > 1) return null;
  if (colonCount === 1) {
    if (item[0] === '-' || item[0] === '+') return null;
    const colon = item.indexOf(':');
    const field = item.slice(0, colon);
    const direction = item.slice(colon + 1);
    if (field.length === 0 || (direction !== 'asc' && direction !== 'desc')) return null;
    return { field, direction };
  }
  if (item[0] === '-') {
    const field = item.slice(1);
    if (field.length === 0 || field[0] === '-') return null;
    return { field, direction: 'desc' };
  }
  if (item[0] === '+') {
    const field = item.slice(1);
    if (field.length === 0) return null;
    return { field, direction: 'asc' };
  }
  return { field: item, direction: 'asc' };
}

function auditSort(sortParam, allowedFields, policyInput) {
  const policy = resolvePolicy(policyInput, 'restApi');
  const allowlist = validateAllowlist(allowedFields, policy, 'sort');
  const findings = [];
  const normalized = [];
  if (typeof sortParam !== 'string') {
    addFinding(findings, policy, CODE.INVALID_SORT, 'sort parameter must be a single string', 'sort');
    return finishReport(findings, policy, { sort: normalized, canonical: '' });
  }
  if (sortParam.length === 0 || utf8ByteLength(sortParam) > policy.maxValueLength || firstForbiddenControl(sortParam) !== null) {
    addFinding(findings, policy, CODE.INVALID_SORT, 'sort parameter must be non empty, bounded, and clean', 'sort');
    return finishReport(findings, policy, { sort: normalized, canonical: '' });
  }
  const items = splitComma(sortParam);
  if (items.length > policy.maxSortFields) {
    addFinding(findings, policy, CODE.INVALID_SORT, 'sort parameter exceeds the configured field count', 'sort');
  }
  const seen = new Set();
  const limited = items.slice(0, policy.maxSortFields);
  for (const item of limited) {
    const parsed = parseSortItem(item);
    if (parsed === null) {
      addFinding(findings, policy, CODE.INVALID_SORT, 'sort item has invalid directional syntax', 'sort');
      continue;
    }
    if (!allowlist.includes(parsed.field)) {
      addFinding(findings, policy, CODE.INVALID_SORT, 'sort field is outside the explicit allowlist', 'sort');
      continue;
    }
    if (seen.has(parsed.field)) {
      addFinding(findings, policy, CODE.INVALID_SORT, 'sort field is duplicated', 'sort');
      continue;
    }
    seen.add(parsed.field);
    normalized.push({ field: parsed.field, direction: parsed.direction });
  }
  const canonical = normalized.map((item) => item.direction === 'desc' ? '-' + item.field : item.field).join(',');
  return finishReport(findings, policy, { sort: normalized, canonical });
}

function auditFields(fieldsParam, allowedFields, policyInput) {
  const policy = resolvePolicy(policyInput, 'restApi');
  const allowlist = validateAllowlist(allowedFields, policy, 'fields');
  const findings = [];
  const normalized = [];
  if (typeof fieldsParam !== 'string') {
    addFinding(findings, policy, CODE.INVALID_FIELD, 'fields parameter must be a single string', 'fields');
    return finishReport(findings, policy, { fields: normalized, canonical: '' });
  }
  if (fieldsParam.length === 0 || utf8ByteLength(fieldsParam) > policy.maxValueLength || firstForbiddenControl(fieldsParam) !== null) {
    addFinding(findings, policy, CODE.INVALID_FIELD, 'fields parameter must be non empty, bounded, and clean', 'fields');
    return finishReport(findings, policy, { fields: normalized, canonical: '' });
  }
  const items = splitComma(fieldsParam);
  if (items.length > policy.maxProjectionFields) {
    addFinding(findings, policy, CODE.INVALID_FIELD, 'fields parameter exceeds the configured field count', 'fields');
  }
  const seen = new Set();
  const limited = items.slice(0, policy.maxProjectionFields);
  for (const item of limited) {
    if (item.length === 0) {
      addFinding(findings, policy, CODE.INVALID_FIELD, 'fields parameter contains an empty field', 'fields');
      continue;
    }
    if (!allowlist.includes(item)) {
      addFinding(findings, policy, CODE.INVALID_FIELD, 'requested field is outside the explicit allowlist', 'fields');
      continue;
    }
    if (seen.has(item)) {
      addFinding(findings, policy, CODE.INVALID_FIELD, 'requested field is duplicated', 'fields');
      continue;
    }
    seen.add(item);
    normalized.push(item);
  }
  return finishReport(findings, policy, { fields: normalized, canonical: normalized.join(',') });
}

export {
  auditSort,
  auditFields
};
