import { auditQuery, parseQuery, isSafeQuery } from '../src/index.mjs';

const safeQuery = parseQuery('page=1&limit=20');
console.log('parsed safe query', safeQuery);

const attackReport = auditQuery('role=user&role=admin&__proto__[isAdmin]=true', 'restApi');
console.log('attack safe', attackReport.safe);
console.log('finding codes', attackReport.findings.map((finding) => finding.code));
console.log('boolean check', isSafeQuery('a=1&b=2'));
