#!/usr/bin/env node
import {
  QUERYCAGE_VERSION,
  QueryCageError,
  CODE,
  parseQuery,
  auditQuery,
  sanitizeQuery,
  auditSort,
  auditPagination,
  serializeQueryTree,
  neutralizeTerminal
} from '../src/index.mjs';

const STDIN_LIMIT = 1024 * 1024;
const SECRET_NAMES = new Set([
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

function secretName(value) {
  return value.trim().toLowerCase().replace(/[_.\-\[\]]/g, '');
}

function redactTree(value) {
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) return value.map((item) => redactTree(item));
  const copy = Object.create(null);
  for (const key of Object.keys(value)) {
    copy[key] = SECRET_NAMES.has(secretName(key)) ? '[redacted]' : redactTree(value[key]);
  }
  return copy;
}

function writeStdout(text) {
  process.stdout.write(neutralizeTerminal(text) + '\n');
}

function writeStderr(text) {
  process.stderr.write(neutralizeTerminal(text) + '\n');
}

function usage() {
  return [
    'querycage ' + QUERYCAGE_VERSION,
    'usage:',
    '  querycage audit [query] [--policy name] [--json]',
    '  querycage parse [query] [--policy name] [--json]',
    '  querycage sanitize [query] [--policy name] [--json]',
    '  querycage audit-sort [sort] --allowed-fields a,b [--json]',
    '  querycage audit-pagination [query] [--policy name] [--json]'
  ].join('\n');
}

function parseArgs(argv) {
  const result = { positional: [], json: false, policy: undefined, allowedFields: undefined, help: false, version: false };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--json') {
      result.json = true;
    } else if (arg === '--help' || arg === '-h') {
      result.help = true;
    } else if (arg === '--version' || arg === '-v') {
      result.version = true;
    } else if (arg === '--policy') {
      index += 1;
      if (index >= argv.length) throw new QueryCageError('QUERYCAGE_INVALID_CLI_ARGUMENT', '--policy requires a value');
      result.policy = argv[index];
    } else if (arg.startsWith('--policy=')) {
      result.policy = arg.slice('--policy='.length);
    } else if (arg === '--allowed-fields') {
      index += 1;
      if (index >= argv.length) throw new QueryCageError('QUERYCAGE_INVALID_CLI_ARGUMENT', '--allowed-fields requires a value');
      result.allowedFields = argv[index];
    } else if (arg.startsWith('--allowed-fields=')) {
      result.allowedFields = arg.slice('--allowed-fields='.length);
    } else if (arg.startsWith('--')) {
      throw new QueryCageError('QUERYCAGE_INVALID_CLI_ARGUMENT', 'unknown option', arg);
    } else {
      result.positional.push(arg);
    }
  }
  return result;
}

async function readStdinBounded() {
  const chunks = [];
  let total = 0;
  for await (const chunk of process.stdin) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += buffer.length;
    if (total > STDIN_LIMIT) throw new QueryCageError('QUERYCAGE_INVALID_CLI_ARGUMENT', 'standard input exceeds the one mebibyte safety cap');
    chunks.push(buffer);
  }
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks));
  } catch {
    throw new QueryCageError('QUERYCAGE_INVALID_CLI_ARGUMENT', 'standard input is not valid UTF-8');
  }
}

async function inputFromArgs(options, startIndex) {
  if (options.positional.length > startIndex) return options.positional.slice(startIndex).join(' ');
  return readStdinBounded();
}

function printJson(value) {
  writeStdout(JSON.stringify(value, null, 2));
}

function printReportHuman(label, report) {
  const lines = [label + ': ' + (report.safe ? 'safe' : 'unsafe')];
  const limit = Math.min(report.findings.length, 10);
  for (let index = 0; index < limit; index += 1) {
    const finding = report.findings[index];
    lines.push(finding.severity + ' ' + finding.code + (finding.param ? ' ' + finding.param : ''));
  }
  if (report.findings.length > limit) lines.push('additional findings omitted');
  writeStdout(lines.join('\n'));
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.version) {
    writeStdout('querycage ' + QUERYCAGE_VERSION);
    return 0;
  }
  if (options.help || options.positional.length === 0) {
    writeStdout(usage());
    return options.help ? 0 : 2;
  }
  const command = options.positional[0];
  if (command === 'audit') {
    const input = await inputFromArgs(options, 1);
    const report = auditQuery(input, options.policy);
    if (options.json) printJson(report);
    else printReportHuman('audit', report);
    return report.safe ? 0 : 1;
  }
  if (command === 'parse') {
    const input = await inputFromArgs(options, 1);
    let parsed;
    try {
      parsed = parseQuery(input, options.policy);
    } catch (error) {
      if (error instanceof QueryCageError && error.code !== CODE.INVALID_POLICY && error.code !== CODE.UNKNOWN_POLICY) {
        writeStderr(error.code + (error.param ? ' ' + error.param : '') + ': ' + error.detail);
        return 1;
      }
      throw error;
    }
    const redacted = redactTree(parsed);
    if (options.json) printJson(redacted);
    else printJson(redacted);
    return 0;
  }
  if (command === 'sanitize') {
    const input = await inputFromArgs(options, 1);
    const result = sanitizeQuery(input, options.policy);
    const redactedParams = redactTree(result.params);
    const redactedQuery = serializeQueryTree(redactedParams);
    if (options.json) {
      printJson({
        query: redactedQuery,
        params: redactedParams,
        removedParams: result.removedParams,
        changed: result.changed,
        report: result.report
      });
    } else {
      writeStdout(redactedQuery);
    }
    return result.report.safe ? 0 : 1;
  }
  if (command === 'audit-sort') {
    if (typeof options.allowedFields !== 'string' || options.allowedFields.length === 0) {
      throw new QueryCageError('QUERYCAGE_INVALID_CLI_ARGUMENT', 'audit-sort requires --allowed-fields');
    }
    const input = await inputFromArgs(options, 1);
    const report = auditSort(input, options.allowedFields.split(','), options.policy);
    if (options.json) printJson(report);
    else printReportHuman('sort', report);
    return report.safe ? 0 : 1;
  }
  if (command === 'audit-pagination') {
    const input = await inputFromArgs(options, 1);
    const report = auditPagination(input, options.policy);
    if (options.json) printJson(report);
    else printReportHuman('pagination', report);
    return report.safe ? 0 : 1;
  }
  throw new QueryCageError('QUERYCAGE_INVALID_CLI_ARGUMENT', 'unknown command', command);
}

main().then((status) => {
  process.exitCode = status;
}).catch((error) => {
  if (error instanceof QueryCageError) {
    writeStderr(error.code + (error.param ? ' ' + error.param : '') + ': ' + error.detail);
  } else {
    writeStderr('QUERYCAGE_INVALID_CLI_ARGUMENT: unexpected CLI failure');
  }
  process.exitCode = 2;
});
