"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const fs = require("node:fs/promises");
const path = require("node:path");
const os = require("node:os");
const { spawn } = require("node:child_process");
const createStore = require("../modules/runtime-utils/analyticsCheckpointStore.js");

async function setup(t, options = {}) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "analytics-checkpoint-"));
  const stores = [];
  const create = (extra = {}) => {
    const store = createStore({ directory, namespace: "test", flushIntervalMs: 60000, ...options, ...extra });
    stores.push(store);
    return store;
  };
  t.after(async () => {
    await Promise.all(stores.map(store => store.close()));
    await fs.rm(directory, { recursive: true, force: true });
  });
  return { directory, create };
}

test("checkpoints survive a graceful restart with private permissions and isolated returned data", async t => {
  const { directory, create } = await setup(t);
  const store = create();
  assert.equal(await store.ready, true);
  assert.equal(store.getData(), null);
  const value = { total: { requests: 20 }, dedupe: ["opaque-hash"] };
  assert.equal(await store.save(value, { urgent: true }), true);
  value.total.requests = -1;
  const loaded = store.getData();
  assert.equal(loaded.total.requests, 20);
  loaded.total.requests = -2;
  assert.equal(store.getData().total.requests, 20);
  const filename = path.join(directory, "test.json");
  const stat = await fs.stat(filename);
  assert.equal(stat.mode & 0o777, 0o600);
  const envelope = JSON.parse(await fs.readFile(filename, "utf8"));
  assert.equal(envelope.version, 1);
  assert.equal(envelope.namespace, "test");
  assert.ok(Number.isFinite(Date.parse(envelope.savedAt)));
  assert.equal(await store.close(), true);
  const restarted = create();
  assert.equal(await restarted.ready, true);
  assert.deepEqual(restarted.getData(), { total: { requests: 20 }, dedupe: ["opaque-hash"] });
  assert.equal(restarted.getStatus().lastSaveAt, envelope.savedAt);
});

test("only one process can own a namespace while different namespaces remain independent", async t => {
  const { create } = await setup(t);
  const first = create();
  assert.equal(await first.ready, true);
  const contender = create();
  assert.equal(await contender.ready, false);
  assert.equal(contender.getStatus().lastError, "locked");
  assert.equal(contender.getStatus().canWrite, false);
  assert.equal(await contender.save({ count: 99 }, { urgent: true }), false);
  const other = create({ namespace: "another" });
  assert.equal(await other.ready, true);
  assert.equal(await other.save({ count: 7 }, { urgent: true }), true);
  assert.equal(first.getData(), null);
  await first.close();
  const following = create();
  assert.equal(await following.ready, true);
});

test("pending saves coalesce and urgent saves wait for the newest included generation", async t => {
  const { directory, create } = await setup(t);
  const store = create();
  assert.equal(await store.ready, true);
  for (let count = 0; count < 100; count += 1) assert.equal(await store.save({ count }), true);
  await assert.rejects(fs.stat(path.join(directory, "test.json")), { code: "ENOENT" });
  const first = store.flush();
  assert.equal(await store.save({ count: 101 }), true);
  const urgent = store.save({ count: 102 }, { urgent: true });
  assert.equal(await first, true);
  assert.equal(await urgent, true);
  assert.equal(store.getData().count, 102);
  assert.equal(store.getStatus().pending, false);
  assert.equal(store.getStatus().pendingBytes, 0);
  assert.deepEqual((await fs.readdir(directory)).sort(), ["test.json", "test.lock"]);
});

test("startup must complete before state can be queued, and close flushes a pending checkpoint", async t => {
  const { create } = await setup(t);
  const store = create();
  assert.equal(store.getStatus().canWrite, false);
  assert.equal(await store.save({ beforeStartup: true }), false);
  assert.equal(await store.ready, true);
  assert.equal(store.getStatus().canWrite, true);
  assert.equal(await store.save({ final: 42 }), true);
  const closing = store.close();
  assert.equal(store.getStatus().canWrite, false);
  assert.equal(store.close(), closing);
  assert.equal(await store.save({ afterClose: true }), false);
  assert.equal(await closing, true);
  const restarted = create();
  assert.equal(await restarted.ready, true);
  assert.deepEqual(restarted.getData(), { final: 42 });
});

test("corrupt, oversized, and mismatched checkpoints are preserved and reject mutation", async t => {
  for (const [body, code] of [
    ["{invalid", "invalid_checkpoint"],
    [JSON.stringify({ version: 2, namespace: "test", savedAt: new Date().toISOString(), data: {} }), "invalid_checkpoint"],
    [JSON.stringify({ version: 1, namespace: "wrong", savedAt: new Date().toISOString(), data: {} }), "invalid_checkpoint"],
    ["x".repeat(1025), "checkpoint_too_large"]
  ]) {
    const { directory, create } = await setup(t, { maxBytes: 1024 });
    const filename = path.join(directory, "test.json");
    await fs.writeFile(filename, body, { mode: 0o600 });
    const store = create();
    assert.equal(await store.ready, false);
    assert.equal(store.getStatus().lastError, code);
    assert.equal(store.getStatus().canWrite, false);
    assert.equal(await store.save({ overwrite: true }, { urgent: true }), false);
    assert.equal(await fs.readFile(filename, "utf8"), body);
  }
});

test("oversized, cyclic, nonfinite, executable, and deeply nested input cannot replace a good checkpoint", async t => {
  const { create } = await setup(t, { maxBytes: 1024 });
  const store = create();
  assert.equal(await store.ready, true);
  assert.equal(await store.save({ good: true }, { urgent: true }), true);
  const cyclic = {}; cyclic.self = cyclic;
  let nested = {}; for (let count = 0; count < 40; count += 1) nested = { nested };
  for (const value of [{ tooBig: "x".repeat(2000) }, cyclic, { x: NaN }, { x: Infinity }, { x: () => {} }, nested]) {
    assert.equal(await store.save(value, { urgent: true }), false);
    assert.equal(store.getStatus().lastError, "invalid_data");
    assert.deepEqual(store.getData(), { good: true });
  }
});

test("symlink directories, lock files, and checkpoint files are rejected without modifying their targets", async t => {
  const { directory, create } = await setup(t);
  const target = path.join(directory, "target");
  await fs.writeFile(target, "private-original", { mode: 0o600 });
  await fs.symlink(target, path.join(directory, "test.json"));
  const fileLink = create();
  assert.equal(await fileLink.ready, false);
  assert.equal(fileLink.getStatus().lastError, "unsafe_file");
  assert.equal(await fs.readFile(target, "utf8"), "private-original");
  await fileLink.close();
  await fs.unlink(path.join(directory, "test.json"));
  await fs.unlink(path.join(directory, "test.lock"));
  await fs.symlink(target, path.join(directory, "test.lock"));
  const lockLink = create();
  assert.equal(await lockLink.ready, false);
  assert.equal(lockLink.getStatus().lastError, "unsafe_file");
  const actual = path.join(directory, "actual");
  await fs.mkdir(actual, { mode: 0o700 });
  const linked = path.join(directory, "linked");
  await fs.symlink(actual, linked);
  const directoryLink = create({ directory: linked });
  assert.equal(await directoryLink.ready, false);
  assert.equal(directoryLink.getStatus().lastError, "unsafe_directory");
});

test("failed replacement preserves the last good checkpoint and reports a safe recoverable error", async t => {
  const { directory, create } = await setup(t);
  const store = create();
  assert.equal(await store.ready, true);
  assert.equal(await store.save({ count: 1 }, { urgent: true }), true);
  const filename = path.join(directory, "test.json");
  const saved = await fs.readFile(filename, "utf8");
  await fs.rename(filename, `${filename}.preserved`);
  await fs.mkdir(filename, { mode: 0o700 });
  assert.equal(await store.save({ count: 2 }, { urgent: true }), false);
  assert.equal(store.getStatus().lastError, "unsafe_file");
  assert.equal(await fs.readFile(`${filename}.preserved`, "utf8"), saved);
  assert.deepEqual(store.getData(), { count: 1 });
  assert.doesNotMatch(JSON.stringify(store.getStatus()), /analytics-checkpoint-|\/tmp|preserved/);
  await fs.rmdir(filename);
  await fs.rename(`${filename}.preserved`, filename);
  assert.equal(await store.flush(), true);
  assert.deepEqual(store.getData(), { count: 2 });
  assert.equal(store.getStatus().lastError, null);
});

test("missing flock fails safely without creating an unlocked checkpoint", async t => {
  const { directory, create } = await setup(t);
  const store = create({ flockPath: path.join(directory, "missing-flock") });
  assert.equal(await store.ready, false);
  assert.equal(store.getStatus().lastError, "lock_unavailable");
  assert.equal(await store.save({ unsafe: true }, { urgent: true }), false);
  await assert.rejects(fs.stat(path.join(directory, "test.json")), { code: "ENOENT" });
});

test("a killed parent releases its worker lock so a new process restores its durable checkpoint", { timeout: 6000 }, async t => {
  const { directory, create } = await setup(t);
  const modulePath = require.resolve("../modules/runtime-utils/analyticsCheckpointStore.js");
  const source = `const create=require(${JSON.stringify(modulePath)});(async()=>{const store=create({directory:${JSON.stringify(directory)},namespace:'test'});if(!await store.ready)process.exit(1);if(!await store.save({count:77},{urgent:true}))process.exit(2);process.stdout.write('READY');setInterval(()=>{},1000)})()`;
  const parent = spawn(process.execPath, ["-e", source], { stdio: ["ignore", "pipe", "pipe"] });
  t.after(() => { try { parent.kill("SIGKILL"); } catch (_) {} });
  await new Promise((resolve, reject) => {
    let output = "";
    parent.stdout.on("data", chunk => { output += chunk; if (output.includes("READY")) resolve(); });
    parent.once("error", reject);
    parent.once("exit", code => { if (!output.includes("READY")) reject(new Error(`Parent exited ${code}`)); });
  });
  parent.kill("SIGKILL");
  await new Promise(resolve => parent.once("exit", resolve));
  // The worker observes IPC disconnection asynchronously. A contender may
  // briefly see the still-owned lock; retry only after each contender exits.
  let restored;
  for (let attempt = 0; attempt < 10; attempt += 1) {
    restored = create();
    if (await restored.ready) break;
    assert.equal(restored.getStatus().lastError, "locked");
    await restored.close();
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  assert.equal(restored.getStatus().ready, true);
  assert.deepEqual(restored.getData(), { count: 77 });
});

test("orphaned private temporaries from a killed writer are cleaned without touching unrelated files", async t => {
  const { directory, create } = await setup(t);
  const orphan = ".test.aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.tmp";
  await fs.writeFile(path.join(directory, orphan), "interrupted", { mode: 0o600 });
  await fs.writeFile(path.join(directory, "unrelated.tmp"), "keep", { mode: 0o600 });
  await fs.writeFile(path.join(directory, ".other.aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.tmp"), "keep", { mode: 0o600 });
  const store = create();
  assert.equal(await store.ready, true);
  await assert.rejects(fs.stat(path.join(directory, orphan)), { code: "ENOENT" });
  assert.equal(await fs.readFile(path.join(directory, "unrelated.tmp"), "utf8"), "keep");
  assert.equal(await fs.readFile(path.join(directory, ".other.aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.tmp"), "utf8"), "keep");
});

test("startup and unacknowledged writes have finite deadlines and stop their worker", { timeout: 4000 }, async t => {
  const { directory, create } = await setup(t);
  const stalledStartup = path.join(directory, "stalled-startup");
  await fs.writeFile(stalledStartup, "#!/usr/bin/env node\nsetInterval(() => {}, 1000);\n", { mode: 0o700 });
  const starting = create({ flockPath: stalledStartup, operationTimeoutMs: 300 });
  const startedAt = Date.now();
  assert.equal(await starting.ready, false);
  assert.equal(starting.getStatus().lastError, "operation_timeout");
  assert.ok(Date.now() - startedAt < 2000);
  assert.equal(await starting.close(), false);
  const stalledWrite = path.join(directory, "stalled-write");
  await fs.writeFile(stalledWrite,
    "#!/usr/bin/env node\nprocess.send({type:'ready',ok:true,body:null});process.on('message',()=>{});setInterval(()=>{},1000);\n",
    { mode: 0o700 });
  const writing = create({ flockPath: stalledWrite, operationTimeoutMs: 300 });
  assert.equal(await writing.ready, true);
  assert.equal(await writing.save({ uncertain: true }, { urgent: true }), false);
  assert.equal(writing.getStatus().lastError, "operation_timeout");
  assert.equal(writing.getStatus().ready, false);
  assert.equal(writing.getStatus().canWrite, false);
  assert.equal(await writing.close(), false);
});
