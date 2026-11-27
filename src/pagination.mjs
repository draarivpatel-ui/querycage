import { CODE } from './errors.mjs';
import { resolvePolicy } from './policy.mjs';
import { analyzeQuery } from './parser.mjs';
import { serializeQueryTree } from './serializer.mjs';
import { deepFreezeCopy, firstForbiddenControl, nullObject } from './utils.mjs';

function addPagedFinding(findings, policy, code, message, param) {
  if (findings.length >= policy.maxFindings) return false;
  const finding = { code, severity: 'error', message };
  if (typeof param === 'string') finding.param = param;
  findings.push(finding);
  return true;
}

function scalarValue(value) {
  if (typeof value === 'string') return value;
  return null;
}

function integerText(value) {
  if (typeof value !== 'string' || value.length === 0) return null;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 48 || code > 57) return null;
  }
  if (value.length > 1 && value[0] === '0') return null;
  const numeric = Number(value);
  if (!Number.isSafeInteger(numeric)) return null;
  return numeric;
}

function validatePositiveInteger(tree, name, maximum, findings, policy, allowZero) {
  if (!Object.prototype.hasOwnProperty.call(tree, name)) return { present: false, valid: true, value: undefined };
  const raw = scalarValue(tree[name]);
  if (raw === null) {
    addPagedFinding(findings, policy, CODE.INVALID_PAGINATION, name + ' must be a scalar integer string', name);
    return { present: true, valid: false, value: undefined };
  }
  const numeric = integerText(raw);
  if (numeric === null || (!allowZero && numeric === 0) || numeric > maximum) {
    addPagedFinding(findings, policy, CODE.INVALID_PAGINATION, name + ' must be a canonical bounded integer without scientific notation', name);
    return { present: true, valid: false, value: undefined };
  }
  return { present: true, valid: true, value: numeric };
}

function copyQueryFindings(report, findings, policy) {
  let truncated = false;
  for (const finding of report.findings) {
    if (findings.length >= policy.maxFindings) {
      truncated = true;
      break;
    }
    findings.push({ ...finding });
  }
  if (report.stats.truncated) truncated = true;
  return truncated;
}

function auditPagination(params, policyInput) {
  const policy = resolvePolicy(policyInput, 'restApi');
  const analysis = analyzeQuery(params, policy, 'restApi');
  const findings = [];
  let truncated = copyQueryFindings(analysis.report, findings, policy);
  const tree = analysis.tree;
  const page = validatePositiveInteger(tree, 'page', policy.maxPage, findings, policy, false);
  const limit = validatePositiveInteger(tree, 'limit', policy.maxLimit, findings, policy, false);
  const perPage = validatePositiveInteger(tree, 'per_page', policy.maxLimit, findings, policy, false);
  const offset = validatePositiveInteger(tree, 'offset', policy.maxOffset, findings, policy, true);
  let cursorValid = true;
  let cursorValue;
  if (Object.prototype.hasOwnProperty.call(tree, 'cursor')) {
    const raw = scalarValue(tree.cursor);
    if (raw === null || raw.length === 0 || firstForbiddenControl(raw) !== null) {
      addPagedFinding(findings, policy, CODE.INVALID_PAGINATION, 'cursor must be a non empty opaque scalar string', 'cursor');
      cursorValid = false;
    } else {
      cursorValue = raw;
    }
  }
  let effectiveLimit;
  if (limit.valid && limit.present) effectiveLimit = limit.value;
  if (perPage.valid && perPage.present) effectiveLimit = perPage.value;
  if (limit.present && perPage.present && limit.valid && perPage.valid && limit.value !== perPage.value) {
    addPagedFinding(findings, policy, CODE.INVALID_PAGINATION, 'limit and per_page conflict', 'limit');
  }
  if (findings.length >= policy.maxFindings) truncated = true;
  const errorCount = findings.filter((finding) => finding.severity === 'error').length;
  const warningCount = findings.length - errorCount;
  const normalized = nullObject();
  if (page.present && page.valid) normalized.page = String(page.value);
  if (effectiveLimit !== undefined) normalized.limit = String(effectiveLimit);
  if (offset.present && offset.valid) normalized.offset = String(offset.value);
  if (cursorValid && cursorValue !== undefined) normalized.cursor = cursorValue;
  const pagination = nullObject();
  if (page.present && page.valid) pagination.page = page.value;
  if (effectiveLimit !== undefined) pagination.limit = effectiveLimit;
  if (offset.present && offset.valid) pagination.offset = offset.value;
  if (cursorValid && cursorValue !== undefined) pagination.cursor = cursorValue;
  const safe = errorCount === 0 && !truncated;
  return deepFreezeCopy({
    safe,
    findings,
    counts: { errors: errorCount, warnings: warningCount },
    pagination,
    canonical: serializeQueryTree(normalized),
    stats: { truncated }
  });
}

export {
  auditPagination
};
