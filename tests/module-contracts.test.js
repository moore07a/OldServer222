'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const repositoryRoot = path.resolve(__dirname, '..');
const modulesRoot = path.join(repositoryRoot, 'modules');

function findJavaScriptFiles(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const absolutePath = path.join(directory, entry.name);
    if (entry.isDirectory()) return findJavaScriptFiles(absolutePath);
    return entry.isFile() && entry.name.endsWith('.js') ? [absolutePath] : [];
  });
}

function repositoryPath(absolutePath) {
  return path.relative(repositoryRoot, absolutePath).split(path.sep).join('/');
}

function localRequires(file) {
  const source = fs.readFileSync(file, 'utf8');
  return [...source.matchAll(/require\(\s*['"](\.[^'"]+)['"]\s*\)/g)].map((match) => ({
    request: match[1],
    resolved: require.resolve(path.resolve(path.dirname(file), match[1])),
  }));
}

const moduleFiles = findJavaScriptFiles(modulesRoot).sort();
const sourceFiles = [path.join(repositoryRoot, 'server.js'), ...moduleFiles];

test('every local JavaScript import resolves and every module is reachable from server.js', () => {
  const dependencyGraph = new Map();

  for (const file of sourceFiles) {
    const dependencies = localRequires(file);
    dependencyGraph.set(file, dependencies.map(({ resolved }) => resolved));
    for (const { request, resolved } of dependencies) {
      assert.ok(
        fs.statSync(resolved).isFile(),
        `${repositoryPath(file)} imports ${request}, but it does not resolve to a file`,
      );
    }
  }

  const reachable = new Set();
  const pending = [path.join(repositoryRoot, 'server.js')];
  while (pending.length > 0) {
    const file = pending.pop();
    if (reachable.has(file)) continue;
    reachable.add(file);
    for (const dependency of dependencyGraph.get(file) || []) {
      if (dependencyGraph.has(dependency)) pending.push(dependency);
    }
  }

  const orphanedModules = moduleFiles.filter((file) => !reachable.has(file)).map(repositoryPath);
  assert.deepEqual(orphanedModules, [], `modules not imported by the application: ${orphanedModules.join(', ')}`);
});

test('every module publishes a usable CommonJS contract', () => {
  const objectExportKeys = {
    'modules/runtime-routes/adminThrottle.js': [
      'adminHits',
      'ADMIN_HIT_TTL_MS',
      'ADMIN_HIT_WINDOW_MS',
      'pruneAdminHits',
    ],
    'modules/runtime-utils/runtimeConfig.js': [
      'DEFAULT_MAX_TIMER_MS',
      'MAX_TIMER_MS',
      'readMaxTimerMsEnv',
      'clampMs',
      'readMsEnv',
      'readPositiveIntEnv',
      'evictOldestMapEntry',
      'boundedMapSet',
    ],
  };

  for (const file of moduleFiles) {
    const relativePath = repositoryPath(file);
    const published = require(file);
    const expectedKeys = objectExportKeys[relativePath];

    if (!expectedKeys) {
      assert.equal(typeof published, 'function', `${relativePath} must export its factory or helper function`);
      assert.ok(published.name, `${relativePath} must export a named function`);
      continue;
    }

    assert.deepEqual(Object.keys(published).sort(), expectedKeys.sort(), `${relativePath} has an unexpected export surface`);
    for (const key of expectedKeys) {
      assert.notEqual(published[key], undefined, `${relativePath} does not define the exported helper ${key}`);
    }
  }
});

test('destructured local imports only request helpers that their modules export', () => {
  const destructuredRequire = /const\s*\{([^}]+)\}\s*=\s*require\(\s*['"](\.[^'"]+)['"]\s*\)/g;

  for (const file of sourceFiles) {
    const source = fs.readFileSync(file, 'utf8');
    for (const match of source.matchAll(destructuredRequire)) {
      const published = require(require.resolve(path.resolve(path.dirname(file), match[2])));
      const importedKeys = match[1].split(',').map((binding) => binding.trim().split(/\s*:\s*/)[0]);
      for (const key of importedKeys) {
        assert.ok(
          Object.hasOwn(published, key),
          `${repositoryPath(file)} imports missing helper ${key} from ${match[2]}`,
        );
      }
    }
  }
});
