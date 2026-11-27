import { compareStrings, encodeRFC3986 } from './utils.mjs';

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
      if (typeof value[index] === 'string') serializeScalarPair(prefix + '[]', value[index], pairs);
    }
    return;
  }
  if (value !== null && typeof value === 'object') {
    const keys = Object.keys(value).sort(compareStrings);
    for (const key of keys) {
      serializeNode(prefix + '[' + encodeRFC3986(key) + ']', value[key], pairs);
    }
  }
}

function serializeQueryTree(tree) {
  const pairs = [];
  if (tree === null || typeof tree !== 'object') return '';
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
