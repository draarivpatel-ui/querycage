import { resolvePolicy } from './policy.mjs';
import { analyzeQuery } from './parser.mjs';
import { serializeQueryTree, cloneQueryTree } from './serializer.mjs';
import { compareStrings, deepFreezeCopy, neutralizeTerminal, nullObject } from './utils.mjs';

function rootForParam(param, policy) {
  if (typeof param !== 'string' || param.length === 0) return '';
  let end = param.length;
  for (let index = 0; index < param.length; index += 1) {
    const char = param[index];
    if (char === '[' || (policy.allowDotNotation && char === '.')) {
      end = index;
      break;
    }
  }
  return param.slice(0, end);
}

function removeImplicatedRoots(tree, findings, policy) {
  let removed = false;
  for (const finding of findings) {
    if (finding.severity !== 'error' || typeof finding.param !== 'string') continue;
    const root = rootForParam(finding.param, policy);
    if (root.length > 0 && Object.prototype.hasOwnProperty.call(tree, root)) {
      delete tree[root];
      removed = true;
    }
  }
  return removed;
}

function collectImplicatedParams(analysis, policy) {
  const names = new Set();
  for (const key of Object.keys(analysis.tree)) names.add(key);
  for (const finding of analysis.findings) {
    if (typeof finding.param !== 'string') continue;
    const root = rootForParam(finding.param, policy);
    if (root.length > 0) names.add(root);
  }
  return names;
}

function sanitizeQuery(input, policyInput) {
  const policy = resolvePolicy(policyInput, 'strict');
  const initial = analyzeQuery(input, policy, 'strict');
  const implicated = collectImplicatedParams(initial, policy);
  let tree = cloneQueryTree(initial.tree);
  removeImplicatedRoots(tree, initial.findings, policy);
  const initialCanonical = serializeQueryTree(tree);
  let canonical = '';
  let analysis = null;
  const maxIterations = 64;
  for (let iteration = 0; iteration < maxIterations; iteration += 1) {
    canonical = serializeQueryTree(tree);
    analysis = analyzeQuery(canonical, policy, 'strict');
    if (analysis.report.safe) break;
    const removed = removeImplicatedRoots(tree, analysis.findings, policy);
    if (!removed) {
      const keys = Object.keys(tree).sort(compareStrings);
      if (keys.length === 0) break;
      const removeCount = Math.max(1, Math.ceil(keys.length / 2));
      for (let index = keys.length - removeCount; index < keys.length; index += 1) delete tree[keys[index]];
    }
  }
  if (analysis === null || !analysis.report.safe) {
    tree = nullObject();
    canonical = '';
    analysis = analyzeQuery('', policy, 'strict');
  }
  const finalKeys = new Set(Object.keys(analysis.tree));
  const removedParams = [];
  for (const name of implicated) {
    if (!finalKeys.has(name)) removedParams.push(neutralizeTerminal(name));
  }
  removedParams.sort(compareStrings);
  return deepFreezeCopy({
    query: canonical,
    params: analysis.tree,
    report: analysis.report,
    removedParams,
    changed: canonical !== initialCanonical || removedParams.length > 0
  });
}

export {
  sanitizeQuery
};
