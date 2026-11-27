import { QUERYCAGE_VERSION, QUERYCAGE_SEVERITY } from './constants.mjs';
import { QUERYCAGE_ERROR_CODES, CODE, QueryCageError } from './errors.mjs';
import { QUERYCAGE_DEFAULT_POLICY, QUERYCAGE_POLICIES, createPolicy, getPolicy } from './policy.mjs';
import { parseQuery, auditQuery, validateQuery, isSafeQuery } from './parser.mjs';
import { auditPagination } from './pagination.mjs';
import { auditSort, auditFields } from './api-security.mjs';
import { sanitizeQuery } from './sanitize.mjs';
import { serializeQueryTree } from './serializer.mjs';
import { neutralizeTerminal } from './utils.mjs';

const querycage = Object.freeze({
  QUERYCAGE_VERSION,
  QUERYCAGE_SEVERITY,
  QUERYCAGE_ERROR_CODES,
  CODE,
  QueryCageError,
  QUERYCAGE_DEFAULT_POLICY,
  QUERYCAGE_POLICIES,
  createPolicy,
  getPolicy,
  parseQuery,
  auditQuery,
  validateQuery,
  isSafeQuery,
  auditPagination,
  auditSort,
  auditFields,
  sanitizeQuery,
  serializeQueryTree,
  neutralizeTerminal
});

export {
  QUERYCAGE_VERSION,
  QUERYCAGE_SEVERITY,
  QUERYCAGE_ERROR_CODES,
  CODE,
  QueryCageError,
  QUERYCAGE_DEFAULT_POLICY,
  QUERYCAGE_POLICIES,
  createPolicy,
  getPolicy,
  parseQuery,
  auditQuery,
  validateQuery,
  isSafeQuery,
  auditPagination,
  auditSort,
  auditFields,
  sanitizeQuery,
  serializeQueryTree,
  neutralizeTerminal
};

export default querycage;
