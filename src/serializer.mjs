import { QueryCageError, CODE } from './errors.mjs';
import {
  compareStrings,
  encodeRFC3986,
  firstForbiddenControl,
  hasInvalidUnicode,
  isPlainRecord
} from './utils.mjs';

const MAX_SERIALIZE_DEPTH = 65;
const MAX_SERIALIZE_ARRAY_LENGTH = 100001;

function invalidTree(message) {
  throw new QueryCageError(CODE.INVALID_INPUT, message);
}

function validateText(value, kind) {
  if (hasInvalidUnicode(value)) invalidTree(kind + ' contains invalid Unicode surrogate data');
  if (firstForbiddenControl(value) !== null) invalidTree(kind + ' contains a control or format character');
}

function validateKey(key) {
  if (key.length === 0) invalidTree('query tree keys must not be empty');
  if (key.indexOf('[') !== -1 || key.indexOf(']') !== -1) {
    invalidTree('query tree keys containing brackets cannot be canonicalized unambiguously');
  }
  validateText(key, 'query tree key');
}

function dataProperty(object, key) {
  const descriptor = Object.getOwnPropertyDescriptor(object, key);
  if (descriptor === undefined || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) {
    invalidTree('query tree objects must use data properties without accessors');
  }
  return descriptor.value;
}

function validateNode(value, depth, seen) {
  if (depth > MAX_SERIALIZE_DEPTH) invalidTree('query tree exceeds the maximum canonical depth');
  if (typeof value === 'string') {
    validateText(value, 'query tree value');
    return;
  }
  if (Array.isArray(value)) {
    if (seen.has(value)) invalidTree('query tree must not contain shared or cyclic references');
    seen.add(value);
    if (value.length === 0) invalidTree('empty arrays cannot be represented in a query string');
    if (value.length > MAX_SERIALIZE_ARRAY_LENGTH) invalidTree('query tree array exceeds the maximum canonical length');
    for (let index = 0; index < value.length; index += 1) {
      if (!Object.prototype.hasOwnProperty.call(value, index)) invalidTree('sparse arrays cannot be canonicalized');
      if (typeof value[index] !== 'string') invalidTree('query tree arrays must contain only strings');
      validateText(value[index], 'query tree array value');
    }
    return;
  }
  if (!isPlainRecord(value)) invalidTree('query tree values must be strings, string arrays, or plain objects');
  if (seen.has(value)) invalidTree('query tree must not contain shared or cyclic references');
  seen.add(value);
  const keys = Object.keys(value);
  if (depth > 0 && keys.length === 0) invalidTree('empty nested objects cannot be represented in a query string');
  for (const key of keys) {
    validateKey(key);
    validateNode(dataProperty(value, key), depth + 1, seen);
  }
}

function validateQueryTree(tree) {
  if (!isPlainRecord(tree)) invalidTree('query tree must be a plain object');
  validateNode(tree, 0, new Set());
}

function serializeScalarPair(prefix, value, pairs) {
  pairs.push(prefix + '=' + encodeRFC3986(value));
}

function serializeNode(prefix, value, pairs) {
  if (typeof value === 'string') {
    serializeScalarPair(prefix, value, pairs);
    return;
  }
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      serializeScalarPair(prefix + '[]', value[index], pairs);
    }
    return;
  }
  const keys = Object.keys(value).sort(compareStrings);
  for (const key of keys) {
    serializeNode(prefix + '[' + encodeRFC3986(key) + ']', value[key], pairs);
  }
}

function serializeQueryTree(tree) {
  validateQueryTree(tree);
  const pairs = [];
  const keys = Object.keys(tree).sort(compareStrings);
  for (const key of keys) {
    serializeNode(encodeRFC3986(key), tree[key], pairs);
  }
  return pairs.join('&');
}

function cloneQueryTree(value) {
  if (value === undefined || value === null || typeof value !== 'object') return value;
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) {
    const copy = new Array(value.length);
    for (let index = 0; index < value.length; index += 1) copy[index] = cloneQueryTree(value[index]);
    return copy;
  }
  const copy = Object.create(null);
  for (const key of Object.keys(value)) copy[key] = cloneQueryTree(value[key]);
  return copy;
}

export {
  serializeQueryTree,
  cloneQueryTree
};
