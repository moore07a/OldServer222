'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const repositoryRoot = path.resolve(__dirname, '..');
const legacyFile = path.join(repositoryRoot, 'old.js');
const activeFiles = [
  path.join(repositoryRoot, 'server.js'),
  ...findJavaScriptFiles(path.join(repositoryRoot, 'modules')),
];

function findJavaScriptFiles(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const absolutePath = path.join(directory, entry.name);
    if (entry.isDirectory()) return findJavaScriptFiles(absolutePath);
    return entry.isFile() && entry.name.endsWith('.js') ? [absolutePath] : [];
  });
}

function readSource(file) {
  return fs.readFileSync(file, 'utf8');
}

function callableNames(source) {
  const names = new Set();
  const declarations = /\b(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(/g;
  const assignedArrows = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>/g;

  for (const pattern of [declarations, assignedArrows]) {
    for (const match of source.matchAll(pattern)) names.add(match[1]);
  }
  return names;
}

function literalRouteKeys(source) {
  const routes = new Set();
  const registrations = /\bapp\.(get|post|put|delete|patch|head|options|all|use)\(\s*(["'])(.*?)\2/gs;
  for (const match of source.matchAll(registrations)) {
    routes.add(`${match[1].toUpperCase()} ${match[3]}`);
  }
  return routes;
}

function unionFromActiveFiles(extractor) {
  const values = new Set();
  for (const file of activeFiles) {
    for (const value of extractor(readSource(file))) values.add(value);
  }
  return values;
}

test('server.js and modules retain every named callable from old.js', () => {
  const legacyCallables = callableNames(readSource(legacyFile));
  const activeCallables = unionFromActiveFiles(callableNames);
  const missing = [...legacyCallables].filter((name) => !activeCallables.has(name)).sort();

  assert.ok(legacyCallables.size > 450, 'legacy callable scan unexpectedly found too few symbols');
  assert.deepEqual(missing, [], `legacy callables missing from the active implementation: ${missing.join(', ')}`);
});

test('server.js and modules retain every literal route registration from old.js', () => {
  const legacyRoutes = literalRouteKeys(readSource(legacyFile));
  const activeRoutes = unionFromActiveFiles(literalRouteKeys);
  const missing = [...legacyRoutes].filter((route) => !activeRoutes.has(route)).sort();

  assert.ok(legacyRoutes.size >= 50, 'legacy route scan unexpectedly found too few registrations');
  assert.deepEqual(missing, [], `legacy literal routes missing from the active implementation: ${missing.join(', ')}`);
});
