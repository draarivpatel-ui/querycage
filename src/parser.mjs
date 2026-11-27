import { QueryCageError, CODE } from './errors.mjs';
import { resolvePolicy } from './policy.mjs';
import {
  nullObject,
  isPlainRecord,
  utf8ByteLength,
  hasInvalidUnicode,
  decodeComponentRepeated,
  firstForbiddenControl,
  normalizeSecurityName,
  normalizeSecretName,
  deepFreezeCopy,
  freezeTree,
  neutralizeTerminal
} from './utils.mjs';

const FORBIDDEN_KEY_SEGMENTS = new Set([
  '__proto__',
  'constructor',
  'prototype',
  'tostring',
  'valueof',
  'hasownproperty',
  '__definegetter__',
  '__definesetter__',
  '__lookupgetter__',
  '__lookupsetter__'
]);

const SECRET_KEY_SEGMENTS = new Set([
  'password',
  'passwd',
  'token',
  'accesstoken',
  'idtoken',
  'refreshtoken',
  'apikey',
  'secret',
  'clientsecret',
  'authorization',
  'jwt',
  'sessionid',
  'privatekey'
]);

function safeParam(value) {
  if (typeof value !== 'string') return undefined;
  return Array.from(neutralizeTerminal(value)).slice(0, 160).join('');
}

function addFinding(state, code, severity, message, param, index) {
  if (state.findings.length >= state.policy.maxFindings) {
    state.truncatedFindings = true;
    return;
  }
  const finding = { code, severity, message };
  const cleanParam = safeParam(param);
  if (cleanParam !== undefined) finding.param = cleanParam;
  if (Number.isSafeInteger(index)) finding.index = index;
  state.findings.push(finding);
}

function errorFinding(state, code, message, param, index) {
  addFinding(state, code, 'error', message, param, index);
}

function warningFinding(state, code, message, param, index) {
  addFinding(state, code, 'warning', message, param, index);
}

function isSearchParamsLike(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  return typeof value.entries === 'function' && typeof value[Symbol.iterator] === 'function';
}

function strictKeyChar(code) {
  return (code >= 65 && code <= 90) ||
    (code >= 97 && code <= 122) ||
    (code >= 48 && code <= 57) ||
    code === 45 || code === 46 || code === 95 || code === 126;
}

function validStrictKey(value) {
  if (value.length === 0) return false;
  for (let index = 0; index < value.length; index += 1) {
    if (!strictKeyChar(value.charCodeAt(index))) return false;
  }
  return true;
}

function isDigits(value) {
  if (value.length === 0) return false;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 48 || code > 57) return false;
  }
  return true;
}

function splitDotSegment(segment, output, state, param, index) {
  if (segment.indexOf('.') === -1) {
    output.push({ type: 'key', value: segment });
    return true;
  }
  let start = 0;
  for (let position = 0; position <= segment.length; position += 1) {
    if (position === segment.length || segment[position] === '.') {
      const part = segment.slice(start, position);
      if (part.length === 0) {
        errorFinding(state, CODE.MALFORMED_KEY, 'dot notation contains an empty path segment', param, index);
        return false;
      }
      output.push({ type: 'key', value: part });
      start = position + 1;
    }
  }
  return true;
}

function parseIndexSegment(content, state, param, index) {
  if (content[0] === '-') {
    errorFinding(state, CODE.SPARSE_ARRAY, 'negative array indices are not allowed', param, index);
    return null;
  }
  if (!isDigits(content)) return undefined;
  if (content.length > 1 && content[0] === '0') {
    errorFinding(state, CODE.SPARSE_ARRAY, 'non canonical array indices are not allowed', param, index);
    return null;
  }
  const numeric = Number(content);
  if (!Number.isSafeInteger(numeric)) {
    errorFinding(state, CODE.ARRAY_INDEX_TOO_LARGE, 'array index is not a safe integer', param, index);
    return null;
  }
  if (numeric > state.policy.maxArrayIndex) {
    errorFinding(state, CODE.ARRAY_INDEX_TOO_LARGE, 'array index exceeds the configured maximum', param, index);
    return null;
  }
  return numeric;
}

function parseKeyPath(key, state, param, index) {
  if (key.length === 0) {
    errorFinding(state, CODE.MALFORMED_KEY, 'empty parameter keys are not allowed', param, index);
    return null;
  }
  const hasBracket = key.indexOf('[') !== -1 || key.indexOf(']') !== -1;
  if (hasBracket && !state.policy.allowBrackets) {
    errorFinding(state, CODE.NESTING_NOT_ALLOWED, 'bracket notation is disabled by this policy', param, index);
    return null;
  }
  const firstOpen = key.indexOf('[');
  const baseEnd = firstOpen === -1 ? key.length : firstOpen;
  const base = key.slice(0, baseEnd);
  if (base.length === 0) {
    errorFinding(state, CODE.MALFORMED_KEY, 'bracket paths must have a top level key', param, index);
    return null;
  }
  if (firstOpen === -1 && key.indexOf(']') !== -1) {
    errorFinding(state, CODE.MALFORMED_KEY, 'unbalanced closing bracket in parameter key', param, index);
    return null;
  }
  const rawSegments = [{ kind: 'key', value: base }];
  let position = baseEnd;
  while (position < key.length) {
    if (key[position] !== '[') {
      errorFinding(state, CODE.MALFORMED_KEY, 'unexpected text after bracket segment', param, index);
      return null;
    }
    const close = key.indexOf(']', position + 1);
    if (close === -1) {
      errorFinding(state, CODE.MALFORMED_KEY, 'unbalanced opening bracket in parameter key', param, index);
      return null;
    }
    const content = key.slice(position + 1, close);
    if (content.indexOf('[') !== -1 || content.indexOf(']') !== -1) {
      errorFinding(state, CODE.MALFORMED_KEY, 'nested or malformed brackets in parameter key', param, index);
      return null;
    }
    if (content.length === 0) {
      rawSegments.push({ kind: 'append', value: '' });
    } else {
      const numeric = parseIndexSegment(content, state, param, index);
      if (numeric === null) return null;
      if (typeof numeric === 'number') {
        rawSegments.push({ kind: 'index', value: String(numeric), numeric });
      } else {
        rawSegments.push({ kind: 'key', value: content });
      }
    }
    position = close + 1;
  }
  const segments = [];
  for (const raw of rawSegments) {
    if (raw.kind === 'key') {
      if (state.policy.allowDotNotation) {
        if (!splitDotSegment(raw.value, segments, state, param, index)) return null;
      } else {
        segments.push({ type: 'key', value: raw.value });
      }
    } else {
      segments.push({ type: raw.kind, value: raw.value, numeric: raw.numeric });
    }
  }
  for (let segmentIndex = 0; segmentIndex < segments.length; segmentIndex += 1) {
    const segment = segments[segmentIndex];
    if ((segment.type === 'append' || segment.type === 'index') && segmentIndex !== segments.length - 1) {
      errorFinding(state, CODE.MALFORMED_KEY, 'arrays of objects are outside the safe query subset', param, index);
      return null;
    }
  }
  const depth = segments.length - 1;
  if (depth > state.policy.maxDepth) {
    errorFinding(state, CODE.NESTING_TOO_DEEP, 'parameter nesting exceeds the configured maximum depth', param, index);
    return null;
  }
  const usesArray = segments.some((segment) => segment.type === 'append' || segment.type === 'index');
  if (usesArray && !state.policy.allowArrays) {
    errorFinding(state, CODE.ARRAY_NOT_ALLOWED, 'array parameters are disabled by this policy', param, index);
    return null;
  }
  if (depth > 0 && !state.policy.allowBrackets && hasBracket) {
    errorFinding(state, CODE.NESTING_NOT_ALLOWED, 'nested parameters are disabled by this policy', param, index);
    return null;
  }
  if (state.policy.strictKeyNames) {
    for (const segment of segments) {
      if (segment.type === 'key' && !validStrictKey(segment.value)) {
        errorFinding(state, CODE.MALFORMED_KEY, 'key is outside the strict RFC 3986 unreserved character subset', param, index);
        return null;
      }
    }
  }
  return { segments, depth, usesArray };
}

function inspectSegments(entry, parsed, state) {
  const segments = parsed.segments;
  const root = segments[0].type === 'key' ? segments[0].value : '';
  let stopped = false;
  if (state.policy.allowedParams !== null && !state.policy.allowedParams.includes(root)) {
    errorFinding(state, CODE.PARAMETER_NOT_ALLOWED, 'parameter is outside the configured allowlist', entry.key, entry.ordinal);
    stopped = true;
  }
  if (state.policy.blockedParams.includes(root)) {
    errorFinding(state, CODE.PARAMETER_NOT_ALLOWED, 'parameter is explicitly blocked by policy', entry.key, entry.ordinal);
    stopped = true;
  }
  if (parsed.usesArray && state.policy.arrayParamAllowlist !== null && !state.policy.arrayParamAllowlist.includes(root)) {
    errorFinding(state, CODE.ARRAY_NOT_ALLOWED, 'array parameter is outside the configured allowlist', entry.key, entry.ordinal);
    stopped = true;
  }
  for (const segment of segments) {
    if (segment.type !== 'key') continue;
    const securityName = normalizeSecurityName(segment.value);
    if (FORBIDDEN_KEY_SEGMENTS.has(securityName)) {
      errorFinding(state, CODE.PROTOTYPE_POLLUTION, 'forbidden object prototype key segment detected', entry.key, entry.ordinal);
      stopped = true;
    }
    if (securityName[0] === '$' && state.policy.rejectNoSqlOperators) {
      errorFinding(state, CODE.NOSQL_OPERATOR, 'dollar prefixed query operator key segment detected', entry.key, entry.ordinal);
      stopped = true;
    }
    if (SECRET_KEY_SEGMENTS.has(normalizeSecretName(segment.value)) && state.policy.rejectSecrets) {
      errorFinding(state, CODE.SECRET_IN_QUERY, 'sensitive credential parameter detected and its value was redacted', entry.key, entry.ordinal);
      stopped = true;
    }
  }
  return !stopped;
}

function validateDecodedText(entry, state) {
  if (hasInvalidUnicode(entry.key) || hasInvalidUnicode(entry.value)) {
    errorFinding(state, CODE.INVALID_ENCODING, 'parameter contains invalid Unicode surrogate data', entry.key, entry.ordinal);
    return false;
  }
  const keyControl = firstForbiddenControl(entry.key);
  if (keyControl !== null) {
    errorFinding(state, CODE.CONTROL_CHARACTER, 'parameter key contains a control or format character', entry.key, entry.ordinal);
    return false;
  }
  const valueControl = firstForbiddenControl(entry.value);
  if (valueControl !== null) {
    errorFinding(state, CODE.CONTROL_CHARACTER, 'parameter value contains a control or format character', entry.key, entry.ordinal);
    return false;
  }
  if (utf8ByteLength(entry.key) > state.policy.maxKeyLength) {
    errorFinding(state, CODE.KEY_TOO_LONG, 'parameter key exceeds the configured byte length', entry.key, entry.ordinal);
    return false;
  }
  if (utf8ByteLength(entry.value) > state.policy.maxValueLength) {
    errorFinding(state, CODE.VALUE_TOO_LONG, 'parameter value exceeds the configured byte length', entry.key, entry.ordinal);
    return false;
  }
  return true;
}

function decodeRawEntry(entry, state) {
  const decodedKey = decodeComponentRepeated(entry.rawKey, true);
  if (!decodedKey.ok) {
    errorFinding(state, CODE.INVALID_ENCODING, 'parameter key is not valid strict UTF-8 percent encoding', entry.rawKey, entry.ordinal);
    return false;
  }
  const decodedValue = decodeComponentRepeated(entry.rawValue, true);
  if (!decodedValue.ok) {
    errorFinding(state, CODE.INVALID_ENCODING, 'parameter value is not valid strict UTF-8 percent encoding', entry.rawKey, entry.ordinal);
    return false;
  }
  entry.key = decodedKey.value;
  entry.value = decodedValue.value;
  if ((decodedKey.layers > 1 || decodedValue.layers > 1 || decodedKey.exhausted || decodedValue.exhausted) && state.policy.rejectDoubleEncoding) {
    errorFinding(state, CODE.DOUBLE_ENCODING, 'multiple layers of percent encoding are not allowed', entry.key, entry.ordinal);
  }
  return true;
}

function prepareEntry(entry, state) {
  if (!entry.direct && !decodeRawEntry(entry, state)) return null;
  if (!validateDecodedText(entry, state)) return null;
  const parsed = parseKeyPath(entry.key, state, entry.key, entry.ordinal);
  if (parsed === null) return null;
  entry.path = parsed.segments;
  entry.depth = parsed.depth;
  entry.usesArray = parsed.usesArray;
  entry.rootKey = entry.path[0].type === 'key' ? entry.path[0].value : '';
  if (!inspectSegments(entry, parsed, state)) return null;
  state.maxDepthObserved = Math.max(state.maxDepthObserved, parsed.depth);
  return entry;
}

function consumeRawString(input, state) {
  let source = input;
  if (source[0] === '?') source = source.slice(1);
  state.bytes = utf8ByteLength(source);
  if (state.bytes > state.policy.maxBytes) {
    errorFinding(state, CODE.QUERY_TOO_LARGE, 'query byte length exceeds the configured maximum');
  }
  const entries = [];
  let position = 0;
  let ordinal = 0;
  while (position <= source.length) {
    const amp = source.indexOf('&', position);
    const end = amp === -1 ? source.length : amp;
    const segment = source.slice(position, end);
    position = end + 1;
    if (segment.length === 0) {
      if (amp === -1) break;
      continue;
    }
    ordinal += 1;
    state.params = ordinal;
    if (ordinal > state.policy.maxParams) {
      errorFinding(state, CODE.TOO_MANY_PARAMS, 'query parameter count exceeds the configured maximum');
      break;
    }
    const equal = segment.indexOf('=');
    const rawKey = equal === -1 ? segment : segment.slice(0, equal);
    const rawValue = equal === -1 ? '' : segment.slice(equal + 1);
    const hasSemicolon = segment.indexOf(';') !== -1;
    if (state.policy.rejectSemicolons && hasSemicolon) {
      errorFinding(state, CODE.SEMICOLON_DELIMITER, 'semicolon delimiters create parser differential risk', rawKey, ordinal);
    }
    entries.push({ ordinal, rawKey, rawValue, direct: false, originalKey: rawKey, hasSemicolon });
    if (amp === -1) break;
  }
  return entries;
}

function consumeSearchParams(input, state) {
  const entries = [];
  let ordinal = 0;
  let bytes = 0;
  for (const pair of input.entries()) {
    ordinal += 1;
    state.params = ordinal;
    if (ordinal > state.policy.maxParams) {
      errorFinding(state, CODE.TOO_MANY_PARAMS, 'query parameter count exceeds the configured maximum');
      break;
    }
    const rawKey = String(pair[0]);
    const rawValue = String(pair[1]);
    bytes += utf8ByteLength(rawKey) + utf8ByteLength(rawValue) + 1;
    entries.push({ ordinal, rawKey, rawValue, direct: false, originalKey: rawKey });
  }
  state.bytes = bytes;
  if (bytes > state.policy.maxBytes) {
    errorFinding(state, CODE.QUERY_TOO_LARGE, 'query byte length exceeds the configured maximum');
  }
  return entries;
}

function scalarToString(value) {
  if (typeof value === 'string') return { ok: true, value };
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) return { ok: false, value: '' };
    return { ok: true, value: String(value) };
  }
  if (typeof value === 'boolean') return { ok: true, value: value ? 'true' : 'false' };
  if (value === null) return { ok: true, value: '' };
  if (typeof value === 'bigint') return { ok: true, value: value.toString(10) };
  return { ok: false, value: '' };
}

function displayObjectPath(parts) {
  let output = '';
  let firstKey = true;
  for (const part of parts) {
    if (typeof part === 'string') {
      if (firstKey) {
        output += part;
        firstKey = false;
      } else {
        output += '[' + part + ']';
      }
    } else if (part && typeof part === 'object' && Number.isSafeInteger(part.arrayIndex)) {
      output += '[' + String(part.arrayIndex) + ']';
    }
  }
  return output;
}

function collectObjectEntries(value, pathParts, state, entries, activeObjects) {
  if (!isPlainRecord(value)) {
    errorFinding(state, CODE.INVALID_INPUT, 'record input must contain only plain objects, arrays, and scalar values');
    return;
  }
  if (activeObjects.has(value)) {
    errorFinding(state, CODE.INVALID_INPUT, 'record input must not contain cyclic object references');
    return;
  }
  activeObjects.add(value);
  for (const key of Object.keys(value)) {
    const child = value[key];
    const childPath = pathParts.concat([key]);
    if (Array.isArray(child)) {
      if (child.length > state.policy.maxArrayLength) {
        errorFinding(state, CODE.SPARSE_ARRAY, 'array input exceeds the configured maximum length', key);
      }
      for (let index = 0; index < child.length; index += 1) {
        if (!Object.prototype.hasOwnProperty.call(child, index)) {
          errorFinding(state, CODE.SPARSE_ARRAY, 'sparse array input is not allowed', key);
          continue;
        }
        const scalar = scalarToString(child[index]);
        if (!scalar.ok) {
          errorFinding(state, CODE.INVALID_INPUT, 'array values must be scalar query values', key);
          continue;
        }
        entries.push({
          ordinal: entries.length + 1,
          rawKey: displayObjectPath(childPath.concat([{ arrayIndex: index }])),
          rawValue: scalar.value,
          direct: true,
          objectPath: childPath.concat([{ arrayIndex: index }])
        });
      }
      continue;
    }
    if (isPlainRecord(child)) {
      collectObjectEntries(child, childPath, state, entries, activeObjects);
      continue;
    }
    const scalar = scalarToString(child);
    if (!scalar.ok) {
      errorFinding(state, CODE.INVALID_INPUT, 'record values must be scalar query values, arrays, or plain objects', key);
      continue;
    }
    entries.push({
      ordinal: entries.length + 1,
      rawKey: displayObjectPath(childPath),
      rawValue: scalar.value,
      direct: true,
      objectPath: childPath
    });
  }
  activeObjects.delete(value);
}

function consumeRecordInput(input, state) {
  const entries = [];
  collectObjectEntries(input, [], state, entries, new Set());
  state.params = entries.length;
  if (entries.length > state.policy.maxParams) {
    errorFinding(state, CODE.TOO_MANY_PARAMS, 'query parameter count exceeds the configured maximum');
    entries.length = state.policy.maxParams;
    state.params = state.policy.maxParams + 1;
  }
  let bytes = 0;
  for (const entry of entries) bytes += utf8ByteLength(entry.rawKey) + utf8ByteLength(entry.rawValue) + 1;
  state.bytes = bytes;
  if (bytes > state.policy.maxBytes) {
    errorFinding(state, CODE.QUERY_TOO_LARGE, 'query byte length exceeds the configured maximum');
  }
  return entries;
}

function combineObjectPath(entry, state) {
  const parts = entry.objectPath;
  const segments = [];
  const displayKey = displayObjectPath(parts);
  let usesArray = false;
  for (const part of parts) {
    if (typeof part === 'string') {
      const pseudoState = state;
      const parsed = parseKeyPath(part, pseudoState, part, entry.ordinal);
      if (parsed === null) return null;
      for (const segment of parsed.segments) {
        segments.push(segment);
        if (segment.type !== 'key') usesArray = true;
      }
    } else if (part && typeof part === 'object' && Number.isSafeInteger(part.arrayIndex)) {
      if (part.arrayIndex > state.policy.maxArrayIndex) {
        errorFinding(state, CODE.ARRAY_INDEX_TOO_LARGE, 'array index exceeds the configured maximum', displayKey, entry.ordinal);
        return null;
      }
      segments.push({ type: 'index', value: String(part.arrayIndex), numeric: part.arrayIndex });
      usesArray = true;
    }
  }
  const depth = segments.length - 1;
  if (depth > state.policy.maxDepth) {
    errorFinding(state, CODE.NESTING_TOO_DEEP, 'parameter nesting exceeds the configured maximum depth', displayKey, entry.ordinal);
    return null;
  }
  if (usesArray && !state.policy.allowArrays) {
    errorFinding(state, CODE.ARRAY_NOT_ALLOWED, 'array parameters are disabled by this policy', displayKey, entry.ordinal);
    return null;
  }
  entry.key = displayKey;
  entry.value = entry.rawValue;
  entry.path = segments;
  entry.depth = depth;
  entry.usesArray = usesArray;
  entry.rootKey = segments.length > 0 && segments[0].type === 'key' ? segments[0].value : '';
  return entry;
}

function prepareObjectEntry(entry, state) {
  if (!validateDecodedText({ key: entry.rawKey, value: entry.rawValue, ordinal: entry.ordinal }, state)) return null;
  const combined = combineObjectPath(entry, state);
  if (combined === null) return null;
  if (!inspectSegments(entry, { segments: entry.path, usesArray: entry.usesArray }, state)) return null;
  state.maxDepthObserved = Math.max(state.maxDepthObserved, entry.depth);
  return entry;
}

function pathKeyFor(entry) {
  const parts = [];
  for (const segment of entry.path) {
    parts.push(segment.type + ':' + segment.value);
  }
  return parts.join('\u0001');
}

function isArraySegment(segment) {
  return segment.type === 'append' || segment.type === 'index';
}

function prepareDuplicates(entries, state) {
  const groups = new Map();
  const direct = [];
  for (const entry of entries) {
    const finalSegment = entry.path[entry.path.length - 1];
    if (finalSegment.type === 'append') {
      direct.push(entry);
      continue;
    }
    const key = pathKeyFor(entry);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(entry);
  }
  const selected = [];
  for (const group of groups.values()) {
    if (group.length === 1) {
      selected.push(group[0]);
      continue;
    }
    const first = group[0];
    const variants = new Set();
    for (const entry of group) variants.add(entry.originalKey);
    if (variants.size > 1) {
      const severity = state.policy.rejectKeyCollisions ? 'error' : 'warning';
      addFinding(state, CODE.KEY_COLLISION, severity, 'different encoded key forms normalize to the same parameter', first.key, first.ordinal);
    }
    if (state.policy.duplicatePolicy === 'first') {
      warningFinding(state, CODE.DUPLICATE_PARAMETER, 'duplicate parameter resolved to the first value', first.key, first.ordinal);
      selected.push(first);
    } else if (state.policy.duplicatePolicy === 'last') {
      warningFinding(state, CODE.DUPLICATE_PARAMETER, 'duplicate parameter resolved to the last value', first.key, first.ordinal);
      selected.push(group[group.length - 1]);
    } else if (state.policy.duplicatePolicy === 'allowlist' && state.policy.duplicateAllowlist.includes(first.rootKey)) {
      warningFinding(state, CODE.DUPLICATE_PARAMETER, 'allowlisted duplicate parameter collected as an array', first.key, first.ordinal);
      first.values = group.map((entry) => entry.value);
      selected.push(first);
    } else {
      errorFinding(state, CODE.DUPLICATE_PARAMETER, 'duplicate parameter key creates HTTP parameter pollution risk', first.key, first.ordinal);
      selected.push(first);
    }
  }
  for (const entry of direct) selected.push(entry);
  selected.sort((left, right) => left.ordinal - right.ordinal);
  return selected;
}

function shapeMismatch(value, wantArray) {
  if (wantArray) return !Array.isArray(value);
  return value === null || typeof value !== 'object' || Array.isArray(value);
}

function insertEntry(tree, entry, state) {
  let node = tree;
  const values = Array.isArray(entry.values) ? entry.values : [entry.value];
  for (let index = 0; index < entry.path.length; index += 1) {
    const segment = entry.path[index];
    const final = index === entry.path.length - 1;
    if (segment.type === 'key') {
      if (Array.isArray(node)) {
        errorFinding(state, CODE.SHAPE_CONFLICT, 'parameter shape conflicts between object and array forms', entry.key, entry.ordinal);
        return;
      }
      if (final) {
        if (Object.prototype.hasOwnProperty.call(node, segment.value)) {
          errorFinding(state, CODE.SHAPE_CONFLICT, 'parameter shape conflicts with an existing nested value', entry.key, entry.ordinal);
          return;
        }
        node[segment.value] = values.length === 1 ? values[0] : values.slice();
        return;
      }
      const next = entry.path[index + 1];
      const wantArray = isArraySegment(next);
      if (!Object.prototype.hasOwnProperty.call(node, segment.value)) {
        node[segment.value] = wantArray ? [] : nullObject();
      } else if (shapeMismatch(node[segment.value], wantArray)) {
        errorFinding(state, CODE.SHAPE_CONFLICT, 'scalar and structured parameter shapes conflict', entry.key, entry.ordinal);
        return;
      }
      node = node[segment.value];
      continue;
    }
    if (!Array.isArray(node)) {
      errorFinding(state, CODE.SHAPE_CONFLICT, 'scalar and array parameter shapes conflict', entry.key, entry.ordinal);
      return;
    }
    if (!final) {
      errorFinding(state, CODE.MALFORMED_KEY, 'arrays of objects are outside the safe query subset', entry.key, entry.ordinal);
      return;
    }
    if (segment.type === 'append') {
      if (node.length + values.length > state.policy.maxArrayLength) {
        errorFinding(state, CODE.SPARSE_ARRAY, 'array parameter exceeds the configured maximum length', entry.key, entry.ordinal);
        return;
      }
      for (const value of values) node.push(value);
      return;
    }
    const arrayIndex = segment.numeric;
    if (arrayIndex >= state.policy.maxArrayLength) {
      errorFinding(state, CODE.SPARSE_ARRAY, 'array parameter exceeds the configured maximum length', entry.key, entry.ordinal);
      return;
    }
    if (Object.prototype.hasOwnProperty.call(node, arrayIndex)) {
      errorFinding(state, CODE.DUPLICATE_PARAMETER, 'array append and explicit index overlap ambiguously', entry.key, entry.ordinal);
      return;
    }
    node[arrayIndex] = values[0];
  }
}

function validateArrayTree(node, state, label) {
  if (Array.isArray(node)) {
    if (node.length > state.policy.maxArrayLength) {
      errorFinding(state, CODE.SPARSE_ARRAY, 'array parameter exceeds the configured maximum length', label);
      return;
    }
    let sparse = false;
    for (let index = 0; index < node.length; index += 1) {
      if (!Object.prototype.hasOwnProperty.call(node, index)) sparse = true;
    }
    if (sparse) errorFinding(state, CODE.SPARSE_ARRAY, 'sparse array indexes are not allowed', label);
    return;
  }
  if (node !== null && typeof node === 'object') {
    for (const key of Object.keys(node)) validateArrayTree(node[key], state, key);
  }
}

function countFindings(findings) {
  let errors = 0;
  let warnings = 0;
  for (const finding of findings) {
    if (finding.severity === 'error') errors += 1;
    if (finding.severity === 'warning') warnings += 1;
  }
  return { errors, warnings };
}

function publicReport(state) {
  const counts = countFindings(state.findings);
  const safe = counts.errors === 0 && !state.truncatedFindings;
  return deepFreezeCopy({
    safe,
    findings: state.findings,
    counts,
    stats: {
      bytes: state.bytes,
      params: state.params,
      entries: state.entries,
      maxDepthObserved: state.maxDepthObserved,
      truncated: state.truncatedFindings
    }
  });
}

function analyzeQuery(input, policyInput, defaultBase) {
  const policy = resolvePolicy(policyInput, defaultBase);
  const state = {
    policy,
    findings: [],
    bytes: 0,
    params: 0,
    entries: 0,
    maxDepthObserved: 0,
    truncatedFindings: false
  };
  let rawEntries;
  if (typeof input === 'string') {
    rawEntries = consumeRawString(input, state);
  } else if (isSearchParamsLike(input)) {
    rawEntries = consumeSearchParams(input, state);
  } else if (isPlainRecord(input)) {
    rawEntries = consumeRecordInput(input, state);
  } else {
    throw new QueryCageError(CODE.INVALID_INPUT, 'query input must be a string, URLSearchParams like object, or plain record object');
  }
  const prepared = [];
  for (const entry of rawEntries) {
    const result = entry.direct ? prepareObjectEntry(entry, state) : prepareEntry(entry, state);
    if (result !== null) prepared.push(result);
  }
  state.entries = prepared.length;
  const selected = prepareDuplicates(prepared, state);
  const tree = nullObject();
  for (const entry of selected) insertEntry(tree, entry, state);
  validateArrayTree(tree, state, undefined);
  const report = publicReport(state);
  return { tree, report, findings: state.findings, state, policy };
}

function firstError(analysis) {
  for (const finding of analysis.findings) {
    if (finding.severity === 'error') return finding;
  }
  if (analysis.report.stats.truncated) {
    return {
      code: CODE.INCOMPLETE_AUDIT,
      message: 'finding cap was reached, so the audit is incomplete',
      param: undefined
    };
  }
  return null;
}

function parseQuery(input, policyInput) {
  const analysis = analyzeQuery(input, policyInput, 'strict');
  const failure = firstError(analysis);
  if (failure !== null) throw new QueryCageError(failure.code, failure.message, failure.param);
  return freezeTree(analysis.tree);
}

function auditQuery(input, policyInput) {
  return analyzeQuery(input, policyInput, 'strict').report;
}

function validateQuery(input, policyInput) {
  const analysis = analyzeQuery(input, policyInput, 'strict');
  const valid = analysis.report.safe;
  const result = {
    valid,
    value: valid ? freezeTree(analysis.tree) : null,
    report: analysis.report
  };
  return deepFreezeCopy(result);
}

function isSafeQuery(input, policyInput) {
  try {
    return auditQuery(input, policyInput).safe;
  } catch {
    return false;
  }
}

export {
  analyzeQuery,
  parseQuery,
  auditQuery,
  validateQuery,
  isSafeQuery
};
