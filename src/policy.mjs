import { QueryCageError, CODE } from './errors.mjs';
import { deepFreezeCopy, copyStringArray } from './utils.mjs';

const BASE_POLICY = {
  maxBytes: 8192,
  maxParams: 64,
  maxKeyLength: 128,
  maxValueLength: 1024,
  maxDepth: 2,
  maxArrayIndex: 99,
  maxArrayLength: 100,
  maxFindings: 100,
  duplicatePolicy: 'reject',
  duplicateAllowlist: [],
  allowBrackets: true,
  allowDotNotation: false,
  allowArrays: true,
  arrayParamAllowlist: null,
  rejectNoSqlOperators: true,
  rejectSecrets: true,
  rejectSemicolons: true,
  rejectDoubleEncoding: true,
  rejectKeyCollisions: true,
  strictKeyNames: false,
  allowedParams: null,
  blockedParams: [],
  maxLimit: 100,
  maxOffset: 10000,
  maxPage: 100000,
  maxSortFields: 8,
  maxProjectionFields: 32
};

const PRESETS = {
  strict: {
    ...BASE_POLICY,
    maxBytes: 4096,
    maxParams: 32,
    maxKeyLength: 96,
    maxValueLength: 512,
    maxDepth: 0,
    maxArrayIndex: 20,
    maxArrayLength: 20,
    allowBrackets: false,
    allowDotNotation: false,
    allowArrays: false,
    duplicatePolicy: 'reject'
  },
  restApi: {
    ...BASE_POLICY,
    maxBytes: 8192,
    maxParams: 80,
    maxKeyLength: 128,
    maxValueLength: 1024,
    maxDepth: 2,
    maxArrayIndex: 99,
    maxArrayLength: 100,
    allowBrackets: true,
    allowDotNotation: false,
    allowArrays: true,
    arrayParamAllowlist: [],
    duplicatePolicy: 'reject'
  },
  search: {
    ...BASE_POLICY,
    maxBytes: 12288,
    maxParams: 96,
    maxKeyLength: 128,
    maxValueLength: 1024,
    maxDepth: 3,
    maxArrayIndex: 99,
    maxArrayLength: 100,
    allowBrackets: true,
    allowDotNotation: false,
    allowArrays: true,
    arrayParamAllowlist: null,
    duplicatePolicy: 'reject'
  },
  oauthCallback: {
    ...BASE_POLICY,
    maxBytes: 4096,
    maxParams: 24,
    maxKeyLength: 96,
    maxValueLength: 2048,
    maxDepth: 0,
    maxArrayIndex: 0,
    maxArrayLength: 1,
    allowBrackets: false,
    allowDotNotation: false,
    allowArrays: false,
    duplicatePolicy: 'reject',
    strictKeyNames: true
  }
};

function integerInRange(value, minimum, maximum) {
  return Number.isSafeInteger(value) && value >= minimum && value <= maximum;
}

function booleanOrUndefined(value) {
  return typeof value === 'boolean';
}

const POLICY_KEYS = new Set([
  'maxBytes',
  'maxParams',
  'maxKeyLength',
  'maxValueLength',
  'maxDepth',
  'maxArrayIndex',
  'maxArrayLength',
  'maxFindings',
  'duplicatePolicy',
  'duplicateAllowlist',
  'allowBrackets',
  'allowDotNotation',
  'allowArrays',
  'arrayParamAllowlist',
  'rejectNoSqlOperators',
  'rejectSecrets',
  'rejectSemicolons',
  'rejectDoubleEncoding',
  'rejectKeyCollisions',
  'strictKeyNames',
  'allowedParams',
  'blockedParams',
  'maxLimit',
  'maxOffset',
  'maxPage',
  'maxSortFields',
  'maxProjectionFields'
]);

function validatePolicy(policy) {
  for (const key of Object.keys(policy)) {
    if (!POLICY_KEYS.has(key)) {
      throw new QueryCageError(CODE.INVALID_POLICY, 'unknown policy field', key);
    }
  }
  const positiveIntegers = [
    'maxBytes',
    'maxParams',
    'maxKeyLength',
    'maxValueLength',
    'maxArrayLength',
    'maxFindings',
    'maxLimit',
    'maxPage',
    'maxSortFields',
    'maxProjectionFields'
  ];
  for (const key of positiveIntegers) {
    if (!integerInRange(policy[key], 1, 1000000)) {
      throw new QueryCageError(CODE.INVALID_POLICY, key + ' must be a positive safe integer', key);
    }
  }
  if (!integerInRange(policy.maxDepth, 0, 64)) {
    throw new QueryCageError(CODE.INVALID_POLICY, 'maxDepth must be a safe integer from 0 to 64', 'maxDepth');
  }
  if (!integerInRange(policy.maxArrayIndex, 0, 100000)) {
    throw new QueryCageError(CODE.INVALID_POLICY, 'maxArrayIndex must be a safe integer from 0 to 100000', 'maxArrayIndex');
  }
  if (!integerInRange(policy.maxOffset, 0, 1000000000)) {
    throw new QueryCageError(CODE.INVALID_POLICY, 'maxOffset must be a safe integer', 'maxOffset');
  }
  if (policy.maxFindings === 0) {
    throw new QueryCageError(CODE.INVALID_POLICY, 'maxFindings zero would hide findings and is fail closed', 'maxFindings');
  }
  if (!['reject', 'first', 'last', 'allowlist'].includes(policy.duplicatePolicy)) {
    throw new QueryCageError(CODE.INVALID_POLICY, 'duplicatePolicy must be reject, first, last, or allowlist', 'duplicatePolicy');
  }
  const booleanKeys = [
    'allowBrackets',
    'allowDotNotation',
    'allowArrays',
    'rejectNoSqlOperators',
    'rejectSecrets',
    'rejectSemicolons',
    'rejectDoubleEncoding',
    'rejectKeyCollisions',
    'strictKeyNames'
  ];
  for (const key of booleanKeys) {
    if (!booleanOrUndefined(policy[key])) {
      throw new QueryCageError(CODE.INVALID_POLICY, key + ' must be boolean', key);
    }
  }
  const duplicateAllowlist = copyStringArray(policy.duplicateAllowlist, []);
  const blockedParams = copyStringArray(policy.blockedParams, []);
  if (duplicateAllowlist === null || blockedParams === null) {
    throw new QueryCageError(CODE.INVALID_POLICY, 'policy string lists must contain only strings');
  }
  if (policy.arrayParamAllowlist !== null) {
    const values = copyStringArray(policy.arrayParamAllowlist, []);
    if (values === null) throw new QueryCageError(CODE.INVALID_POLICY, 'arrayParamAllowlist must contain only strings', 'arrayParamAllowlist');
  }
  if (policy.allowedParams !== null) {
    const values = copyStringArray(policy.allowedParams, []);
    if (values === null) throw new QueryCageError(CODE.INVALID_POLICY, 'allowedParams must contain only strings', 'allowedParams');
  }
  if (policy.maxArrayLength > policy.maxArrayIndex + 1) {
    throw new QueryCageError(CODE.INVALID_POLICY, 'maxArrayLength cannot exceed maxArrayIndex plus one', 'maxArrayLength');
  }
}

function getPolicy(name) {
  if (typeof name !== 'string' || !Object.prototype.hasOwnProperty.call(PRESETS, name)) {
    throw new QueryCageError(CODE.UNKNOWN_POLICY, 'unknown querycage policy preset', typeof name === 'string' ? name : undefined);
  }
  const copy = deepFreezeCopy(PRESETS[name]);
  validatePolicy(copy);
  return deepFreezeCopy(copy);
}

function createPolicy(base, overrides) {
  let baseName = 'strict';
  let baseObject = null;
  if (typeof base === 'string') {
    baseName = base;
  } else if (base && typeof base === 'object') {
    baseObject = deepFreezeCopy(base);
  } else if (base !== undefined) {
    throw new QueryCageError(CODE.INVALID_POLICY, 'policy base must be a preset name or object');
  }
  const merged = baseObject === null ? { ...getPolicy(baseName) } : { ...baseObject };
  if (overrides !== undefined) {
    if (!overrides || typeof overrides !== 'object' || Array.isArray(overrides)) {
      throw new QueryCageError(CODE.INVALID_POLICY, 'policy overrides must be an object');
    }
    const copied = deepFreezeCopy(overrides);
    for (const key of Object.keys(copied)) {
      if (key !== 'preset') merged[key] = copied[key];
    }
  }
  validatePolicy(merged);
  return deepFreezeCopy(merged);
}

function resolvePolicy(input, defaultBase) {
  const baseName = typeof defaultBase === 'string' ? defaultBase : 'strict';
  if (input === undefined) return getPolicy(baseName);
  if (typeof input === 'string') return getPolicy(input);
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new QueryCageError(CODE.INVALID_POLICY, 'policy must be a preset name or object');
  }
  const preset = typeof input.preset === 'string' ? input.preset : baseName;
  return createPolicy(preset, input);
}

const QUERYCAGE_POLICIES = deepFreezeCopy({
  strict: getPolicy('strict'),
  restApi: getPolicy('restApi'),
  search: getPolicy('search'),
  oauthCallback: getPolicy('oauthCallback')
});
const QUERYCAGE_DEFAULT_POLICY = getPolicy('strict');

export {
  QUERYCAGE_DEFAULT_POLICY,
  QUERYCAGE_POLICIES,
  createPolicy,
  getPolicy,
  resolvePolicy
};
