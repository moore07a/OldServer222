"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { spawn } = require("node:child_process");
const checkpointWorker = require("./analyticsCheckpointWorker.js");
const io = fs.promises;
const MAXIMUM_BYTES = 1024 * 1024;
const SAFE_ERRORS = new Set([
  "locked", "lock_unavailable", "unsafe_directory", "unsafe_file", "invalid_checkpoint",
  "checkpoint_too_large", "read_failed", "write_failed", "worker_exited", "operation_timeout", "invalid_data"
]);

function createAnalyticsCheckpointStore({
  directory = "/data/analytics", namespace = "oldserver222", flushIntervalMs = 5000,
  maxBytes = MAXIMUM_BYTES, operationTimeoutMs = 2000, now = Date.now,
  flockPath = "/usr/bin/flock"
} = {}) {
  if (typeof directory !== "string" || !path.isAbsolute(directory)) throw new TypeError("Analytics directory must be absolute");
  if (typeof namespace !== "string" || !/^[A-Za-z0-9:_-]{1,80}$/.test(namespace)) throw new TypeError("Invalid analytics namespace");
  maxBytes = Number.isInteger(maxBytes) && maxBytes >= 256 && maxBytes <= MAXIMUM_BYTES ? maxBytes : MAXIMUM_BYTES;
  operationTimeoutMs = Math.min(2000, Math.max(50, Number(operationTimeoutMs) || 2000));
  const lockFile = path.join(directory, `${namespace}.lock`);
  let child = null;
  let initialized = false;
  let unavailable = false;
  let closing = false;
  let pending = null;
  let active = null;
  let generation = 0;
  let savedGeneration = 0;
  let lastBody = null;
  let lastSaveAt = null;
  let lastError = null;
  let interval = null;
  let closePromise = null;
  let finishReady;
  let readySettled = false;
  const ready = new Promise(resolve => { finishReady = resolve; });

  function settleReady(value) {
    if (readySettled) return;
    readySettled = true;
    clearTimeout(initializationTimer);
    finishReady(value);
  }

  function safeError(value, fallback) { return SAFE_ERRORS.has(value) ? value : fallback; }

  function stopWorker() {
    unavailable = true;
    if (child && child.exitCode === null && child.signalCode === null) {
      try { child.kill("SIGKILL"); } catch (_) {}
    }
  }

  function fail(code) {
    lastError = code;
    unavailable = true;
    settleReady(false);
    if (active) {
      clearTimeout(active.timer);
      active.resolve(false);
      active = null;
    }
  }

  const initializationTimer = setTimeout(() => {
    fail("operation_timeout");
    stopWorker();
  }, operationTimeoutMs);

  async function prepareDirectory() {
    // Inspect every path component; mkdir({recursive:true}) would follow a
    // symlink in an ancestor before we could reject it.
    let current = path.parse(directory).root;
    for (const component of path.resolve(directory).slice(current.length).split(path.sep).filter(Boolean)) {
      current = path.join(current, component);
      try { await io.mkdir(current, { mode: 0o700 }); }
      catch (error) { if (error.code !== "EEXIST") throw error; }
      const stat = await io.lstat(current);
      if (!stat.isDirectory() || stat.isSymbolicLink()) throw Object.assign(new Error(), { safeCode: "unsafe_directory" });
    }
    const final = await io.lstat(directory);
    if (final.mode & 0o077) throw Object.assign(new Error(), { safeCode: "unsafe_directory" });
    let lock;
    try {
      lock = await io.open(lockFile, fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_NOFOLLOW, 0o600);
      const stat = await lock.stat();
      if (!stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o077)) {
        throw Object.assign(new Error(), { safeCode: "unsafe_file" });
      }
    } finally { if (lock) await lock.close(); }
  }

  void (async () => {
    if (process.platform !== "linux") { fail("lock_unavailable"); return; }
    try { await prepareDirectory(); }
    catch (error) { fail(error.safeCode || (error.code === "ELOOP" ? "unsafe_file" : "write_failed")); return; }
    if (unavailable || closing) return;
    try {
      child = spawn(flockPath, ["--exclusive", "--nonblock", "--no-fork", lockFile,
        process.execPath, checkpointWorker.filename, directory, namespace, String(maxBytes)],
      { stdio: ["ignore", "ignore", "ignore", "ipc"] });
    } catch (_) { fail("lock_unavailable"); return; }
    child.on("error", () => { fail("lock_unavailable"); stopWorker(); });
    child.on("exit", (code) => {
      if (!closing && !unavailable) fail(!initialized && code === 1 ? "locked" : "worker_exited");
    });
    child.on("message", (message) => {
      if (!message || typeof message !== "object") return;
      if (message.type === "ready" && !readySettled) {
        if (!message.ok) {
          fail(safeError(message.error, "read_failed"));
          stopWorker();
          return;
        }
        if (message.body !== null && (typeof message.body !== "string" || Buffer.byteLength(message.body) > maxBytes)) {
          fail("invalid_checkpoint"); stopWorker(); return;
        }
        lastBody = message.body;
        if (lastBody !== null) lastSaveAt = JSON.parse(lastBody).savedAt;
        initialized = true;
        lastError = null;
        settleReady(true);
        if (!closing) {
          interval = setInterval(() => { void flush(); }, Math.max(50, Number(flushIntervalMs) || 5000));
          interval.unref();
        }
      } else if (message.type === "saved" && active && message.id === active.generation) {
        const current = active;
        clearTimeout(current.timer);
        active = null;
        if (message.ok) {
          savedGeneration = current.generation;
          lastBody = current.body;
          lastSaveAt = JSON.parse(current.body).savedAt;
          lastError = null;
        } else {
          lastError = safeError(message.error, "write_failed");
          if (!pending || pending.generation < current.generation) pending = current;
        }
        current.resolve(!!message.ok);
      }
    });
  })().catch(() => { fail("write_failed"); stopWorker(); });

  function getData() {
    if (!initialized || lastBody === null) return null;
    return JSON.parse(lastBody).data;
  }

  // Accept only ordinary finite JSON, and bound traversal before stringify.
  // Callers retain responsibility for their versioned data schema and privacy.
  function encode(data) {
    let nodes = 0;
    let bytes = 0;
    const seen = new Set();
    function visit(value, depth) {
      if (++nodes > 32768 || depth > 32) throw new Error();
      if (value === null || typeof value === "boolean") { bytes += 5; return; }
      if (typeof value === "number") { if (!Number.isFinite(value)) throw new Error(); bytes += 24; return; }
      if (typeof value === "string") { bytes += Buffer.byteLength(value) + 2; if (bytes > maxBytes) throw new Error(); return; }
      if (typeof value !== "object" || seen.has(value) || (!Array.isArray(value) && Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) throw new Error();
      seen.add(value);
      if (Array.isArray(value) && value.length > 32768) throw new Error();
      for (const key of Object.keys(value)) {
        bytes += Buffer.byteLength(key) + 4;
        if (bytes > maxBytes || !Object.hasOwn(Object.getOwnPropertyDescriptor(value, key), "value")) throw new Error();
        visit(value[key], depth + 1);
      }
      seen.delete(value);
    }
    visit(data, 0);
    const body = JSON.stringify({ version: 1, namespace, savedAt: new Date(now()).toISOString(), data });
    if (Buffer.byteLength(body) > maxBytes) throw new Error();
    return body;
  }

  function save(data, { urgent = false } = {}) {
    if (!initialized || unavailable || closing) return Promise.resolve(false);
    let body;
    try { body = encode(data); }
    catch (_) { lastError = "invalid_data"; return Promise.resolve(false); }
    const target = ++generation;
    pending = { generation: target, body };
    return urgent ? flush().then(ok => ok && savedGeneration >= target) : Promise.resolve(true);
  }

  function startWrite() {
    const current = pending;
    pending = null;
    let resolve;
    const promise = new Promise(complete => { resolve = complete; });
    active = { ...current, promise, resolve, timer: null };
    active.timer = setTimeout(() => { fail("operation_timeout"); stopWorker(); }, operationTimeoutMs);
    try {
      child.send({ type: "save", id: current.generation, body: current.body }, error => {
        if (error) { fail("worker_exited"); stopWorker(); }
      });
    } catch (_) { fail("worker_exited"); stopWorker(); }
    return promise;
  }

  async function flush() {
    if (!initialized || unavailable) return false;
    const target = generation;
    // At entry there can only be an older active snapshot and the coalesced
    // latest snapshot. Two acknowledgments cover this target without looping
    // indefinitely when new observations keep arriving.
    for (let attempt = 0; attempt < 2; attempt += 1) {
      if (savedGeneration >= target) return true;
      if (unavailable || (!active && !pending)) return false;
      const ok = await (active ? active.promise : startWrite());
      if (!ok) return false;
    }
    return savedGeneration >= target;
  }

  function getStatus() {
    return { configured: true, backend: "disk", namespace,
      ready: initialized && !unavailable && !closing && !lastError,
      lastSaveAt, pending: !!(pending || active),
      pendingBytes: (pending ? Buffer.byteLength(pending.body) : 0) + (active ? Buffer.byteLength(active.body) : 0),
      maxBytes, lastError };
  }

  function close() {
    if (closePromise) return closePromise;
    closing = true;
    if (interval) clearInterval(interval);
    closePromise = new Promise(resolve => {
      let settled = false;
      const finish = value => { if (!settled) { settled = true; clearTimeout(timer); resolve(value); } };
      const timer = setTimeout(() => { stopWorker(); finish(false); }, operationTimeoutMs);
      void (async () => {
        await ready;
        const ok = initialized && !unavailable ? await flush() : false;
        if (!child || child.exitCode !== null || child.signalCode !== null) { finish(ok); return; }
        child.once("exit", () => finish(ok));
        // No worker remains after close; process exit releases flock even if
        // the parent crashes before the close promise resolves.
        child.disconnect();
      })().catch(() => { stopWorker(); finish(false); });
    });
    return closePromise;
  }

  return { ready, getData, save, flush, getStatus, close };
}

module.exports = createAnalyticsCheckpointStore;
