const CF_PATTERN = /\p{Cf}/u;
const MAX_DECODE_LAYERS = 4;
const fatalDecoder = new TextDecoder('utf-8', { fatal: true });

function nullObject() {
  return Object.create(null);
}

function isPlainRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function utf8ByteLength(value) {
  let bytes = 0;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 0x80) {
      bytes += 1;
    } else if (code < 0x800) {
      bytes += 2;
    } else if (code >= 0xd800 && code <= 0xdbff) {
      if (index + 1 < value.length) {
        const next = value.charCodeAt(index + 1);
        if (next >= 0xdc00 && next <= 0xdfff) {
          bytes += 4;
          index += 1;
        } else {
          bytes += 3;
        }
      } else {
        bytes += 3;
      }
    } else {
      bytes += 3;
    }
  }
  return bytes;
}

function hasInvalidSurrogates(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      if (index + 1 >= value.length) return true;
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function pushUtf8Bytes(codePoint, bytes) {
  if (codePoint < 0x80) {
    bytes.push(codePoint);
  } else if (codePoint < 0x800) {
    bytes.push(0xc0 | (codePoint >> 6));
    bytes.push(0x80 | (codePoint & 0x3f));
  } else if (codePoint < 0x10000) {
    bytes.push(0xe0 | (codePoint >> 12));
    bytes.push(0x80 | ((codePoint >> 6) & 0x3f));
    bytes.push(0x80 | (codePoint & 0x3f));
  } else {
    bytes.push(0xf0 | (codePoint >> 18));
    bytes.push(0x80 | ((codePoint >> 12) & 0x3f));
    bytes.push(0x80 | ((codePoint >> 6) & 0x3f));
    bytes.push(0x80 | (codePoint & 0x3f));
  }
}

function hexValue(char) {
  if (char >= '0' && char <= '9') return char.charCodeAt(0) - 48;
  if (char >= 'a' && char <= 'f') return char.charCodeAt(0) - 87;
  if (char >= 'A' && char <= 'F') return char.charCodeAt(0) - 55;
  return -1;
}

function decodeComponentOnce(encoded, plusAsSpace) {
  const bytes = [];
  for (let index = 0; index < encoded.length; index += 1) {
    const char = encoded[index];
    if (char === '%') {
      if (index + 2 >= encoded.length) throw new Error('truncated percent sequence');
      const high = hexValue(encoded[index + 1]);
      const low = hexValue(encoded[index + 2]);
      if (high < 0 || low < 0) throw new Error('invalid percent sequence');
      bytes.push((high << 4) | low);
      index += 2;
      continue;
    }
    if (char === '+' && plusAsSpace) {
      bytes.push(0x20);
      continue;
    }
    const code = encoded.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      if (index + 1 >= encoded.length) throw new Error('lone surrogate');
      const next = encoded.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) throw new Error('lone surrogate');
      const codePoint = 0x10000 + ((code - 0xd800) << 10) + (next - 0xdc00);
      pushUtf8Bytes(codePoint, bytes);
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new Error('lone surrogate');
    } else {
      pushUtf8Bytes(code, bytes);
    }
  }
  try {
    return fatalDecoder.decode(new Uint8Array(bytes));
  } catch {
    throw new Error('invalid utf-8 sequence');
  }
}

function hasPercentTriplet(value) {
  for (let index = 0; index + 2 < value.length; index += 1) {
    if (value[index] !== '%') continue;
    if (hexValue(value[index + 1]) >= 0 && hexValue(value[index + 2]) >= 0) return true;
  }
  return false;
}

function decodeComponentRepeated(encoded, plusAsSpace) {
  let value = encoded;
  let layers = 0;
  let first = true;
  while (layers < MAX_DECODE_LAYERS) {
    let decoded;
    try {
      decoded = decodeComponentOnce(value, first && plusAsSpace);
    } catch {
      return { ok: false, value: '', layers, exhausted: false };
    }
    layers += 1;
    value = decoded;
    first = false;
    if (!hasPercentTriplet(value)) return { ok: true, value, layers, exhausted: false };
  }
  return { ok: true, value, layers, exhausted: hasPercentTriplet(value) };
}

function isForbiddenControlCodePoint(codePoint) {
  if (codePoint <= 0x1f) return true;
  if (codePoint >= 0x7f && codePoint <= 0x9f) return true;
  if (codePoint === 0x2028 || codePoint === 0x2029) return true;
  return CF_PATTERN.test(String.fromCodePoint(codePoint));
}

function firstForbiddenControl(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    let codePoint = code;
    if (code >= 0xd800 && code <= 0xdbff && index + 1 < value.length) {
      const next = value.charCodeAt(index + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        codePoint = 0x10000 + ((code - 0xd800) << 10) + (next - 0xdc00);
        index += 1;
      }
    }
    if (isForbiddenControlCodePoint(codePoint)) return { index, codePoint };
  }
  return null;
}

function hasInvalidUnicode(value) {
  return hasInvalidSurrogates(value);
}

function normalizeSecurityName(value) {
  return value.trim().toLowerCase();
}

function normalizeSecretName(value) {
  return normalizeSecurityName(value).replace(/[_.\-\[\]]/g, '');
}

function deepFreezeCopy(value) {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) {
    const copy = new Array(value.length);
    for (let index = 0; index < value.length; index += 1) copy[index] = deepFreezeCopy(value[index]);
    return Object.freeze(copy);
  }
  const copy = nullObject();
  for (const key of Object.keys(value)) copy[key] = deepFreezeCopy(value[key]);
  return Object.freeze(copy);
}

function deepFreezeExisting(value, seen) {
  if (value === null || typeof value !== 'object') return value;
  if (seen.has(value)) return value;
  seen.add(value);
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) deepFreezeExisting(value[index], seen);
  } else {
    for (const key of Object.keys(value)) deepFreezeExisting(value[key], seen);
  }
  return Object.freeze(value);
}

function freezeTree(value) {
  return deepFreezeExisting(value, new Set());
}

function compareStrings(left, right) {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

function encodeRFC3986(value) {
  return encodeURIComponent(value).replace(/[!'()*]/g, (char) => {
    return '%' + char.charCodeAt(0).toString(16).toUpperCase();
  });
}

function neutralizeTerminal(value) {
  let output = '';
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    let codePoint = code;
    let width = 1;
    if (code >= 0xd800 && code <= 0xdbff && index + 1 < value.length) {
      const next = value.charCodeAt(index + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        codePoint = 0x10000 + ((code - 0xd800) << 10) + (next - 0xdc00);
        width = 2;
      }
    }
    const loneSurrogate = (code >= 0xd800 && code <= 0xdbff && width === 1) || (code >= 0xdc00 && code <= 0xdfff);
    if (loneSurrogate || (isForbiddenControlCodePoint(codePoint) && codePoint !== 0x0a)) {
      output += '\ufffd';
    } else {
      output += value.slice(index, index + width);
    }
    index += width - 1;
  }
  return output;
}

function copyStringArray(values, fallback) {
  if (values === undefined) return fallback.slice();
  if (!Array.isArray(values)) return null;
  const copy = [];
  for (const value of values) {
    if (typeof value !== 'string') return null;
    if (!copy.includes(value)) copy.push(value);
  }
  return copy;
}

function clampedJson(value) {
  try {
    return JSON.stringify(value);
  } catch {
    return '';
  }
}

export {
  MAX_DECODE_LAYERS,
  nullObject,
  isPlainRecord,
  utf8ByteLength,
  hasInvalidUnicode,
  decodeComponentRepeated,
  firstForbiddenControl,
  isForbiddenControlCodePoint,
  normalizeSecurityName,
  normalizeSecretName,
  deepFreezeCopy,
  freezeTree,
  compareStrings,
  encodeRFC3986,
  neutralizeTerminal,
  copyStringArray,
  clampedJson
};
