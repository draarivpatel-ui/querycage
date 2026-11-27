import { createPolicy, parseQuery, QueryCageError } from '../src/index.mjs';

const policy = createPolicy('restApi', {
  allowedParams: ['page', 'limit', 'sort', 'ids'],
  arrayParamAllowlist: ['ids']
});

function queryFirewall(request, response, next) {
  try {
    request.safeQuery = parseQuery(request.queryString, policy);
    next();
  } catch (error) {
    if (error instanceof QueryCageError) {
      response.status = 400;
      response.body = { error: error.code, param: error.param };
      return;
    }
    throw error;
  }
}

const request = { queryString: 'page=1&limit=20&ids[]=10&ids[]=20' };
const response = {};
queryFirewall(request, response, () => {
  console.log('middleware accepted', request.safeQuery);
});
