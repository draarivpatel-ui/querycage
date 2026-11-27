import querycage, {
  QUERYCAGE_VERSION,
  CODE,
  QueryCageError,
  createPolicy,
  getPolicy,
  parseQuery,
  auditQuery,
  validateQuery,
  isSafeQuery,
  sanitizeQuery,
  auditPagination,
  auditSort,
  auditFields,
  serializeQueryTree,
  neutralizeTerminal,
  type QueryInputObject,
  type QueryPolicy
} from '../types/index.js';

const version: string = QUERYCAGE_VERSION;
const input: QueryInputObject = {
  page: '1',
  filter: { status: 'active' },
  ids: ['1', '2']
};
const custom: QueryPolicy = {
  preset: 'restApi',
  maxParams: 20,
  arrayParamAllowlist: ['ids'],
  duplicatePolicy: 'reject'
};
const policy = createPolicy('restApi', custom);
const strict = getPolicy('strict');
const parsed = parseQuery(input, policy);
const audit = auditQuery('a=1', strict);
const validation = validateQuery('a=1', policy);
const safe: boolean = isSafeQuery('a=1', custom);
const sanitized = sanitizeQuery('a=1', custom);
const pagination = auditPagination('page=1&limit=20', custom);
const sorted = auditSort('-created_at,name', ['created_at', 'name'], custom);
const fields = auditFields('id,name', ['id', 'name'], custom);
const canonical: string = serializeQueryTree(parsed);
const terminal: string = neutralizeTerminal(canonical);
const failure = new QueryCageError(CODE.INVALID_INPUT, 'invalid input');
if (validation.valid) {
  const value = validation.value;
  if (value !== null) void value;
}
void version;
void audit;
void safe;
void sanitized;
void pagination;
void sorted;
void fields;
void terminal;
void failure;

void querycage;
