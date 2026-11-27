export const QUERYCAGE_VERSION: string;
export const QUERYCAGE_SEVERITY: {
  readonly ERROR: 'error';
  readonly WARNING: 'warning';
};

export const QUERYCAGE_ERROR_CODES: {
  readonly INVALID_INPUT: 'QUERYCAGE_INVALID_INPUT';
  readonly INVALID_POLICY: 'QUERYCAGE_INVALID_POLICY';
  readonly UNKNOWN_POLICY: 'QUERYCAGE_UNKNOWN_POLICY';
  readonly QUERY_TOO_LARGE: 'QUERYCAGE_QUERY_TOO_LARGE';
  readonly TOO_MANY_PARAMS: 'QUERYCAGE_TOO_MANY_PARAMS';
  readonly KEY_TOO_LONG: 'QUERYCAGE_KEY_TOO_LONG';
  readonly VALUE_TOO_LONG: 'QUERYCAGE_VALUE_TOO_LONG';
  readonly NESTING_TOO_DEEP: 'QUERYCAGE_NESTING_TOO_DEEP';
  readonly ARRAY_INDEX_TOO_LARGE: 'QUERYCAGE_ARRAY_INDEX_TOO_LARGE';
  readonly ARRAY_NOT_ALLOWED: 'QUERYCAGE_ARRAY_NOT_ALLOWED';
  readonly NESTING_NOT_ALLOWED: 'QUERYCAGE_NESTING_NOT_ALLOWED';
  readonly MALFORMED_KEY: 'QUERYCAGE_MALFORMED_KEY';
  readonly INVALID_ENCODING: 'QUERYCAGE_INVALID_ENCODING';
  readonly FRAGMENT_IN_QUERY: 'QUERYCAGE_FRAGMENT_IN_QUERY';
  readonly DOUBLE_ENCODING: 'QUERYCAGE_DOUBLE_ENCODING';
  readonly CONTROL_CHARACTER: 'QUERYCAGE_CONTROL_CHARACTER';
  readonly SEMICOLON_DELIMITER: 'QUERYCAGE_SEMICOLON_DELIMITER';
  readonly DUPLICATE_PARAMETER: 'QUERYCAGE_DUPLICATE_PARAMETER';
  readonly SHAPE_CONFLICT: 'QUERYCAGE_SHAPE_CONFLICT';
  readonly KEY_COLLISION: 'QUERYCAGE_KEY_COLLISION';
  readonly PROTOTYPE_POLLUTION: 'QUERYCAGE_PROTOTYPE_POLLUTION';
  readonly NOSQL_OPERATOR: 'QUERYCAGE_NOSQL_OPERATOR';
  readonly SECRET_IN_QUERY: 'QUERYCAGE_SECRET_IN_QUERY';
  readonly SPARSE_ARRAY: 'QUERYCAGE_SPARSE_ARRAY';
  readonly PARAMETER_NOT_ALLOWED: 'QUERYCAGE_PARAMETER_NOT_ALLOWED';
  readonly INVALID_PAGINATION: 'QUERYCAGE_INVALID_PAGINATION';
  readonly INVALID_SORT: 'QUERYCAGE_INVALID_SORT';
  readonly INVALID_FIELD: 'QUERYCAGE_INVALID_FIELD';
  readonly INCOMPLETE_AUDIT: 'QUERYCAGE_INCOMPLETE_AUDIT';
  readonly INVALID_CLI_ARGUMENT: 'QUERYCAGE_INVALID_CLI_ARGUMENT';
};

export const CODE: typeof QUERYCAGE_ERROR_CODES;
export type QueryCageErrorCode = typeof QUERYCAGE_ERROR_CODES[keyof typeof QUERYCAGE_ERROR_CODES];

export class QueryCageError extends Error {
  readonly name: 'QueryCageError';
  readonly code: QueryCageErrorCode;
  readonly detail: string;
  readonly param?: string;
  constructor(code: QueryCageErrorCode, detail?: string, param?: string);
}

export type QueryScalarInput = string | number | boolean | bigint | null;
export type QueryInputValue = QueryScalarInput | readonly QueryInputValue[] | QueryInputObject;
export interface QueryInputObject {
  readonly [key: string]: QueryInputValue;
}

export interface QuerySearchParamsLike {
  entries(): IterableIterator<readonly [string, string]>;
  [Symbol.iterator](): IterableIterator<readonly [string, string]>;
}

export type QueryInput = string | QuerySearchParamsLike | QueryInputObject;
export type QueryOutputValue = string | readonly QueryOutputValue[] | QueryOutputObject;
export interface QueryOutputObject {
  readonly [key: string]: QueryOutputValue;
}

export type DuplicatePolicy = 'reject' | 'first' | 'last' | 'allowlist';
export type QueryPolicyPresetName = 'strict' | 'restApi' | 'search' | 'oauthCallback';

export interface QueryPolicy {
  readonly preset?: QueryPolicyPresetName;
  readonly maxBytes?: number;
  readonly maxParams?: number;
  readonly maxKeyLength?: number;
  readonly maxValueLength?: number;
  readonly maxDepth?: number;
  readonly maxArrayIndex?: number;
  readonly maxArrayLength?: number;
  readonly maxFindings?: number;
  readonly duplicatePolicy?: DuplicatePolicy;
  readonly duplicateAllowlist?: readonly string[];
  readonly allowBrackets?: boolean;
  readonly allowDotNotation?: boolean;
  readonly allowArrays?: boolean;
  readonly arrayParamAllowlist?: readonly string[] | null;
  readonly rejectNoSqlOperators?: boolean;
  readonly rejectSecrets?: boolean;
  readonly rejectSemicolons?: boolean;
  readonly rejectDoubleEncoding?: boolean;
  readonly rejectKeyCollisions?: boolean;
  readonly strictKeyNames?: boolean;
  readonly allowedParams?: readonly string[] | null;
  readonly blockedParams?: readonly string[];
  readonly maxLimit?: number;
  readonly maxOffset?: number;
  readonly maxPage?: number;
  readonly maxSortFields?: number;
  readonly maxProjectionFields?: number;
}

export interface ResolvedQueryPolicy {
  readonly maxBytes: number;
  readonly maxParams: number;
  readonly maxKeyLength: number;
  readonly maxValueLength: number;
  readonly maxDepth: number;
  readonly maxArrayIndex: number;
  readonly maxArrayLength: number;
  readonly maxFindings: number;
  readonly duplicatePolicy: DuplicatePolicy;
  readonly duplicateAllowlist: readonly string[];
  readonly allowBrackets: boolean;
  readonly allowDotNotation: boolean;
  readonly allowArrays: boolean;
  readonly arrayParamAllowlist: readonly string[] | null;
  readonly rejectNoSqlOperators: boolean;
  readonly rejectSecrets: boolean;
  readonly rejectSemicolons: boolean;
  readonly rejectDoubleEncoding: boolean;
  readonly rejectKeyCollisions: boolean;
  readonly strictKeyNames: boolean;
  readonly allowedParams: readonly string[] | null;
  readonly blockedParams: readonly string[];
  readonly maxLimit: number;
  readonly maxOffset: number;
  readonly maxPage: number;
  readonly maxSortFields: number;
  readonly maxProjectionFields: number;
}

export type QueryPolicyInput = QueryPolicyPresetName | QueryPolicy | ResolvedQueryPolicy;

export type QueryCageSeverity = 'error' | 'warning';
export interface QueryFinding {
  readonly code: QueryCageErrorCode;
  readonly severity: QueryCageSeverity;
  readonly message: string;
  readonly param?: string;
  readonly index?: number;
}

export interface QueryFindingCounts {
  readonly errors: number;
  readonly warnings: number;
}

export interface QueryAuditStats {
  readonly bytes: number;
  readonly params: number;
  readonly entries: number;
  readonly maxDepthObserved: number;
  readonly truncated: boolean;
}

export interface QueryAuditReport {
  readonly safe: boolean;
  readonly findings: readonly QueryFinding[];
  readonly counts: QueryFindingCounts;
  readonly stats: QueryAuditStats;
}

export interface QueryValidationResult {
  readonly valid: boolean;
  readonly value: QueryOutputObject | null;
  readonly report: QueryAuditReport;
}

export interface SanitizeQueryResult {
  readonly query: string;
  readonly params: QueryOutputObject;
  readonly report: QueryAuditReport;
  readonly removedParams: readonly string[];
  readonly changed: boolean;
}

export interface PaginationValues {
  readonly page?: number;
  readonly limit?: number;
  readonly offset?: number;
  readonly cursor?: string;
}

export interface PaginationAuditReport {
  readonly safe: boolean;
  readonly findings: readonly QueryFinding[];
  readonly counts: QueryFindingCounts;
  readonly pagination: PaginationValues;
  readonly canonical: string;
  readonly stats: { readonly truncated: boolean };
}

export interface SortFieldRule {
  readonly field: string;
  readonly direction: 'asc' | 'desc';
}

export interface SortAuditReport {
  readonly safe: boolean;
  readonly findings: readonly QueryFinding[];
  readonly counts: QueryFindingCounts;
  readonly sort: readonly SortFieldRule[];
  readonly canonical: string;
  readonly stats: { readonly truncated: boolean };
}

export interface FieldsAuditReport {
  readonly safe: boolean;
  readonly findings: readonly QueryFinding[];
  readonly counts: QueryFindingCounts;
  readonly fields: readonly string[];
  readonly canonical: string;
  readonly stats: { readonly truncated: boolean };
}

export const QUERYCAGE_DEFAULT_POLICY: ResolvedQueryPolicy;
export const QUERYCAGE_POLICIES: {
  readonly strict: ResolvedQueryPolicy;
  readonly restApi: ResolvedQueryPolicy;
  readonly search: ResolvedQueryPolicy;
  readonly oauthCallback: ResolvedQueryPolicy;
};

export function getPolicy(name: QueryPolicyPresetName): ResolvedQueryPolicy;
export function createPolicy(base?: QueryPolicyPresetName | ResolvedQueryPolicy, overrides?: QueryPolicy): ResolvedQueryPolicy;
export function parseQuery(input: QueryInput, policy?: QueryPolicyInput): QueryOutputObject;
export function auditQuery(input: QueryInput, policy?: QueryPolicyInput): QueryAuditReport;
export function validateQuery(input: QueryInput, policy?: QueryPolicyInput): QueryValidationResult;
export function isSafeQuery(input: QueryInput, policy?: QueryPolicyInput): boolean;
export function sanitizeQuery(input: QueryInput, policy?: QueryPolicyInput): SanitizeQueryResult;
export function auditPagination(params: QueryInput, policy?: QueryPolicyInput): PaginationAuditReport;
export function auditSort(sortParam: unknown, allowedFields: readonly string[], policy?: QueryPolicyInput): SortAuditReport;
export function auditFields(fieldsParam: unknown, allowedFields: readonly string[], policy?: QueryPolicyInput): FieldsAuditReport;
export function serializeQueryTree(tree: QueryOutputObject): string;
export function neutralizeTerminal(value: string): string;

export interface QueryCageApi {
  readonly QUERYCAGE_VERSION: typeof QUERYCAGE_VERSION;
  readonly QUERYCAGE_SEVERITY: typeof QUERYCAGE_SEVERITY;
  readonly QUERYCAGE_ERROR_CODES: typeof QUERYCAGE_ERROR_CODES;
  readonly CODE: typeof CODE;
  readonly QueryCageError: typeof QueryCageError;
  readonly QUERYCAGE_DEFAULT_POLICY: typeof QUERYCAGE_DEFAULT_POLICY;
  readonly QUERYCAGE_POLICIES: typeof QUERYCAGE_POLICIES;
  readonly createPolicy: typeof createPolicy;
  readonly getPolicy: typeof getPolicy;
  readonly parseQuery: typeof parseQuery;
  readonly auditQuery: typeof auditQuery;
  readonly validateQuery: typeof validateQuery;
  readonly isSafeQuery: typeof isSafeQuery;
  readonly auditPagination: typeof auditPagination;
  readonly auditSort: typeof auditSort;
  readonly auditFields: typeof auditFields;
  readonly sanitizeQuery: typeof sanitizeQuery;
  readonly serializeQueryTree: typeof serializeQueryTree;
  readonly neutralizeTerminal: typeof neutralizeTerminal;
}

declare const querycage: QueryCageApi;
export default querycage;
