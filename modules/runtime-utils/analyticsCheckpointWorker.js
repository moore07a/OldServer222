"use strict";

// Launched beneath util-linux flock --no-fork. The worker owns the advisory
// lock until exit, including when the parent disappears during a disk write.
const fs = require("node:fs");
const path = require("node:path");
const { randomUUID } = require("node:crypto");
const io = fs.promises;
function runAnalyticsCheckpointWorker() {
const [directory, namespace, rawMaximum] = process.argv.slice(2);
const maximum = Number(rawMaximum);
const file = path.join(directory, `${namespace}.json`);
let busy = false;

function errorCode(error, fallback) {
  if (error && error.code === "ELOOP") return "unsafe_file";
  return fallback;
}

function envelopeValid(body) {
  if (typeof body !== "string" || Buffer.byteLength(body) > maximum) return false;
  try {
    const value = JSON.parse(body);
    return value && typeof value === "object" && !Array.isArray(value) &&
      Object.keys(value).length === 4 && value.version === 1 && value.namespace === namespace &&
      typeof value.savedAt === "string" && Number.isFinite(Date.parse(value.savedAt)) &&
      Object.hasOwn(value, "data");
  } catch (_) { return false; }
}

function send(message) {
  if (!process.connected) return;
  try { process.send(message, () => {}); } catch (_) {}
}

async function load() {
  let handle;
  try {
    handle = await io.open(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const stat = await handle.stat();
    if (!stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o077)) return { ok: false, error: "unsafe_file" };
    if (stat.size > maximum) return { ok: false, error: "checkpoint_too_large" };
    // Allocate at most the configured maximum plus one byte, even if a file
    // grows between fstat and reading it.
    const buffer = Buffer.alloc(maximum + 1);
    let size = 0;
    while (size <= maximum) {
      const { bytesRead } = await handle.read(buffer, size, buffer.length - size, size);
      if (!bytesRead) break;
      size += bytesRead;
      if (size > maximum) return { ok: false, error: "checkpoint_too_large" };
    }
    let body;
    try { body = new TextDecoder("utf-8", { fatal: true }).decode(buffer.subarray(0, size)); }
    catch (_) { return { ok: false, error: "invalid_checkpoint" }; }
    return envelopeValid(body) ? { ok: true, body } : { ok: false, error: "invalid_checkpoint" };
  } catch (error) {
    return error.code === "ENOENT" ? { ok: true, body: null } : { ok: false, error: errorCode(error, "read_failed") };
  } finally { if (handle) await handle.close().catch(() => {}); }
}

async function cleanOrphanedTemporaries() {
  // A killed worker can leave its one temporary file behind. The next worker
  // already owns flock, so these names cannot belong to an active peer. Never
  // sweep unrelated files, symlinks, or an unbounded directory tree.
  const pattern = new RegExp(`^\\.${namespace}\\.[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\\.tmp$`);
  let scanned = 0;
  let removed = 0;
  try {
    const entries = await io.opendir(directory);
    for await (const entry of entries) {
      if (++scanned > 2048) return false;
      if (!pattern.test(entry.name)) continue;
      if (++removed > 128) return false;
      const temporary = path.join(directory, entry.name);
      const stat = await io.lstat(temporary);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || (stat.mode & 0o077)) return false;
      await io.unlink(temporary);
    }
    return true;
  } catch (_) { return false; }
}

async function write(body) {
  if (!envelopeValid(body)) return { ok: false, error: "invalid_data" };
  const temporary = path.join(directory, `.${namespace}.${randomUUID()}.tmp`);
  let handle;
  try {
    // Do not replace symlinks, special files, or a file installed with unsafe
    // access permissions since startup.
    try {
      const existing = await io.lstat(file);
      if (!existing.isFile() || existing.isSymbolicLink() || existing.nlink !== 1 || (existing.mode & 0o077)) {
        return { ok: false, error: "unsafe_file" };
      }
    } catch (error) { if (error.code !== "ENOENT") throw error; }
    handle = await io.open(temporary,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    await handle.writeFile(body, "utf8");
    await handle.sync();
    await handle.close();
    handle = null;
    await io.rename(temporary, file);
    const parent = await io.open(directory, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
    try { await parent.sync(); } finally { await parent.close(); }
    return { ok: true };
  } catch (error) {
    return { ok: false, error: errorCode(error, "write_failed") };
  } finally {
    if (handle) await handle.close().catch(() => {});
    await io.unlink(temporary).catch(() => {});
  }
}

process.on("disconnect", () => process.exit(0));
process.on("message", async (message) => {
  if (!message || message.type !== "save" || busy) return;
  busy = true;
  const result = await write(message.body);
  busy = false;
  send({ type: "saved", id: message.id, ...result });
});

void (async () => {
  if (!process.send || !path.isAbsolute(directory || "") || !/^[A-Za-z0-9:_-]{1,80}$/.test(namespace || "") ||
      !Number.isInteger(maximum) || maximum < 256 || maximum > 1024 * 1024) process.exit(1);
  if (!await cleanOrphanedTemporaries()) { send({ type: "ready", ok: false, error: "read_failed" }); return; }
  const result = await load();
  send({ type: "ready", ...result });
  if (!result.ok) process.exitCode = 1;
})().catch(() => { send({ type: "ready", ok: false, error: "read_failed" }); process.exitCode = 1; });
}

runAnalyticsCheckpointWorker.filename = __filename;
module.exports = runAnalyticsCheckpointWorker;
if (require.main === module) runAnalyticsCheckpointWorker();
