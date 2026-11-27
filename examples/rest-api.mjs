import {
  createPolicy,
  auditFields,
  auditPagination,
  auditSort,
  sanitizeQuery
} from '../src/index.mjs';

const policy = createPolicy('restApi', {
  allowedParams: ['page', 'limit', 'offset', 'sort', 'fields', 'ids', 'filter'],
  arrayParamAllowlist: ['ids'],
  maxLimit: 50,
  maxOffset: 5000
});

const input = 'page=1&limit=20&sort=-created_at&fields=id,name&ids[]=1&ids[]=2&filter[status]=active';
const clean = sanitizeQuery(input, policy);
console.log('canonical query', clean.query);

const pagination = auditPagination(input, policy);
const sort = auditSort('-created_at', ['created_at', 'name'], policy);
const fields = auditFields('id,name', ['id', 'name', 'email'], policy);
console.log('pagination', pagination.pagination);
console.log('sort', sort.sort);
console.log('fields', fields.fields);
