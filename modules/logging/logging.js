"use strict";

function createLogging(dependencies) {
  const {
    LOG_AGGREGATION_MAX_ENTRIES,
    SCANNER_AGG_ALERT_THRESHOLD,
    boundedMapSet,
    clampMs,
    formatLocal,
    fs,
    openSockets,
    os,
    path,
    readPositiveIntEnv,
    runtimeStats,
    safeLogValue,
    sanitizeOneLine,
    summarizeError
  } = dependencies;

// ================== LOGGING SYSTEM ==================
const LOG_TO_FILE   = process.env.LOG_TO_FILE === "1";
const LOG_FILE      = process.env.LOG_FILE || path.join(process.cwd(), "visitors.log");
const LOG_FILE_MAX_BYTES = readPositiveIntEnv("LOG_FILE_MAX_BYTES", 50 * 1024 * 1024);
const LOG_FILE_MAX_FILES = Math.min(100, readPositiveIntEnv("LOG_FILE_MAX_FILES", 5));
const MAX_LOG_LINES = readPositiveIntEnv("MAX_LOG_LINES", 2000);
const BACKLOG_ON_CONNECT = parseInt(process.env.BACKLOG_ON_CONNECT || "200", 10);
const RUNTIME_DIAG_DIR = process.env.RUNTIME_DIAG_DIR || process.env.LOG_DIR || path.join(process.cwd(), "runtime-diagnostics");
const RUNTIME_INCIDENT_FILE = process.env.RUNTIME_INCIDENT_FILE || path.join(RUNTIME_DIAG_DIR, "incidents.ndjson");
const NPM_DEBUG_LOG_DIR = process.env.NPM_CONFIG_LOGS_DIR || path.join(os.homedir(), ".npm", "_logs");
const RUNTIME_INCIDENT_HISTORY_LIMIT = Math.max(1, parseInt(process.env.RUNTIME_INCIDENT_HISTORY_LIMIT || "25", 10));
const RUNTIME_INCIDENT_NPM_LOG_LIMIT = Math.max(0, parseInt(process.env.RUNTIME_INCIDENT_NPM_LOG_LIMIT || "5", 10));
const RUNTIME_INCIDENT_READ_MAX_BYTES = Math.max(64 * 1024, parseInt(process.env.RUNTIME_INCIDENT_READ_MAX_BYTES || String(1024 * 1024), 10));
const RAILWAY_RUNTIME_ENV_KEYS = [
  "RAILWAY_DEPLOYMENT_ID",
  "RAILWAY_REPLICA_ID",
  "RAILWAY_REPLICA_REGION",
  "RAILWAY_SERVICE_ID",
  "RAILWAY_SERVICE_NAME",
  "RAILWAY_ENVIRONMENT_ID",
  "RAILWAY_ENVIRONMENT_NAME",
  "RAILWAY_PROJECT_ID",
  "RAILWAY_PROJECT_NAME",
  "RAILWAY_SNAPSHOT_ID",
  "RAILWAY_VOLUME_NAME",
  "RAILWAY_VOLUME_MOUNT_PATH",
  "RAILWAY_GIT_COMMIT_SHA",
  "RAILWAY_GIT_BRANCH",
  "RAILWAY_GIT_REPO_NAME",
  "RAILWAY_GIT_REPO_OWNER",
  "RAILWAY_DEPLOYMENT_OVERLAP_SECONDS",
  "RAILWAY_DEPLOYMENT_DRAINING_SECONDS"
];

function getRailwayRuntimeMetadata() {
  const out = {};
  for (const key of RAILWAY_RUNTIME_ENV_KEYS) {
    const value = process.env[key];
    if (value != null && value !== "") out[key] = safeLogValue(value, 160);
  }
  return out;
}

function formatRailwayRuntimeLine(metadata = getRailwayRuntimeMetadata()) {
  const entries = Object.entries(metadata);
  if (!entries.length) return "[RAILWAY] runtime metadata unavailable (not running on Railway or env vars not injected)";
  return `[RAILWAY] ${entries.map(([key, value]) => `${key}=${value}`).join(" ")}`;
}

function getRuntimeCorrelationMetadata() {
  const railway = getRailwayRuntimeMetadata();
  return {
    bootId: runtimeStats.bootId,
    deploymentId: railway.RAILWAY_DEPLOYMENT_ID || null,
    replicaId: railway.RAILWAY_REPLICA_ID || null,
    serviceId: railway.RAILWAY_SERVICE_ID || null,
    gitCommitSha: railway.RAILWAY_GIT_COMMIT_SHA || null
  };
}

function formatRuntimeCorrelationSuffix() {
  const ctx = getRuntimeCorrelationMetadata();
  return [
    `bootId=${ctx.bootId}`,
    ctx.deploymentId ? `deploymentId=${ctx.deploymentId}` : null,
    ctx.replicaId ? `replicaId=${ctx.replicaId}` : null,
    ctx.serviceId ? `serviceId=${ctx.serviceId}` : null,
    ctx.gitCommitSha ? `gitCommit=${String(ctx.gitCommitSha).slice(0, 12)}` : null
  ].filter(Boolean).join(" ");
}

const LOGS = [];
const LOG_IDS = [];
let LOG_SEQ = 0;
const LOG_LISTENERS = new Set();
let logFileWriteErrorAt = 0;
let logFileDropWarnAt = 0;
const LOG_FILE_QUEUE_MAX_LINES = Math.max(500, parseInt(process.env.LOG_FILE_QUEUE_MAX_LINES || "5000", 10));
const LOG_FILE_QUEUE_MAX_BYTES = Math.max(256 * 1024, parseInt(process.env.LOG_FILE_QUEUE_MAX_BYTES || String(2 * 1024 * 1024), 10));
let logFileStream = null;
let logFileQueue = [];
let logFileQueueBytes = 0;
let logFileDrainPending = false;
let logFileDroppedLines = 0;
let logFileWriterClosed = false;
let logFileClosePromise = null;
let logFileRetryAt = 0;
let logFileLastError = null;
let logFileLastOpenedAt = null;
let logFileBytes = 0;
let logFileRotationPending = false;
let logFileRotationPromise = null;
let logFileRotations = 0;
const LOG_FILE_RETRY_DELAY_MS = Math.max(250, parseInt(process.env.LOG_FILE_RETRY_DELAY_MS || "1000", 10));

const OPEN_SOCKETS_WARN_THRESHOLD = Math.max(50, parseInt(process.env.OPEN_SOCKETS_WARN_THRESHOLD || "400", 10));
const SSE_LISTENERS_WARN_THRESHOLD = Math.max(10, parseInt(process.env.SSE_LISTENERS_WARN_THRESHOLD || "120", 10));
const LOG_FILE_QUEUE_WARN_BYTES = Math.max(128 * 1024, parseInt(process.env.LOG_FILE_QUEUE_WARN_BYTES || String(1024 * 1024), 10));
let lastRuntimeGaugeAlertAt = 0;

function getRuntimeResourceGauges() {
  return {
    openSockets: typeof openSockets === "object" && openSockets ? openSockets.size : 0,
    sseListeners: LOG_LISTENERS.size,
    logFileQueueLines: logFileQueue.length,
    logFileQueueBytes,
    logFileDroppedLines,
    logFileDrainPending,
    logFileStreamReady: Boolean(logFileStream),
    logFilePath: LOG_FILE,
    logFileBytes,
    logFileMaxBytes: LOG_FILE_MAX_BYTES,
    logFileRotationEnabled: LOG_TO_FILE,
    logFileRotationPending,
    logFileRotations,
    logFileLastOpenedAt,
    logFileLastError
  };
}

function maybeEmitRuntimeGaugeAlerts(now = Date.now()) {
  if ((now - lastRuntimeGaugeAlertAt) < 60000) return;
  const gauges = getRuntimeResourceGauges();
  const alerts = [];

  if (gauges.openSockets >= OPEN_SOCKETS_WARN_THRESHOLD) {
    alerts.push(`openSockets=${gauges.openSockets}>=${OPEN_SOCKETS_WARN_THRESHOLD}`);
  }
  if (gauges.sseListeners >= SSE_LISTENERS_WARN_THRESHOLD) {
    alerts.push(`sseListeners=${gauges.sseListeners}>=${SSE_LISTENERS_WARN_THRESHOLD}`);
  }
  if (gauges.logFileQueueBytes >= LOG_FILE_QUEUE_WARN_BYTES) {
    alerts.push(`logQueueBytes=${gauges.logFileQueueBytes}>=${LOG_FILE_QUEUE_WARN_BYTES}`);
  }
  if (gauges.logFileDroppedLines > 0) {
    alerts.push(`droppedLogLines=${gauges.logFileDroppedLines}`);
  }

  if (!alerts.length) return;
  lastRuntimeGaugeAlertAt = now;
  addLog(`[ALERT:RUNTIME] ${alerts.join(" ")} queueLines=${gauges.logFileQueueLines} drainPending=${gauges.logFileDrainPending}`);
  addSpacer();
}

function ensureParentDirectoryForFile(filePath, label) {
  const dir = path.dirname(filePath);
  if (!dir || dir === ".") return true;

  try {
    fs.mkdirSync(dir, { recursive: true });
    return true;
  } catch (err) {
    const message = summarizeError(err);
    if (label === "log") {
      logFileLastError = { at: new Date().toISOString(), message };
    }
    console.error(`[${String(label || "file").toUpperCase()}] unable to create parent dir=${dir} file=${filePath} err=${safeLogValue(message, 180)}`);
    return false;
  }
}

function pruneLogArchives(filePath = LOG_FILE, maxFiles = LOG_FILE_MAX_FILES) {
  const directory = path.dirname(filePath);
  const baseName = path.basename(filePath);
  const prefix = `${baseName}.`;

  let entries;
  try {
    entries = fs.readdirSync(directory);
  } catch (_) {
    return;
  }

  for (const entry of entries) {
    if (!entry.startsWith(prefix)) continue;
    const suffix = entry.slice(prefix.length);
    if (!/^\d+$/.test(suffix) || Number(suffix) <= maxFiles) continue;
    fs.rmSync(path.join(directory, entry), { force: true });
  }
}

function rotateLogFiles(filePath = LOG_FILE, maxFiles = LOG_FILE_MAX_FILES) {
  pruneLogArchives(filePath, maxFiles);
  if (!fs.existsSync(filePath)) return;

  fs.rmSync(`${filePath}.${maxFiles}`, { force: true });

  for (let index = maxFiles - 1; index >= 1; index -= 1) {
    const source = `${filePath}.${index}`;
    if (!fs.existsSync(source)) continue;
    fs.renameSync(source, `${filePath}.${index + 1}`);
  }

  fs.renameSync(filePath, `${filePath}.1`);
}

function appendLogChunksSync(chunks, filePath = LOG_FILE, maxBytes = LOG_FILE_MAX_BYTES, maxFiles = LOG_FILE_MAX_FILES) {
  if (!Array.isArray(chunks) || chunks.length === 0) return 0;
  ensureParentDirectoryForFile(filePath, "log");

  let existing = fs.existsSync(filePath) ? fs.statSync(filePath) : null;
  let size = existing && existing.isFile() ? existing.size : 0;
  if (size >= maxBytes) {
    rotateLogFiles(filePath, maxFiles);
    size = 0;
  }

  for (const rawChunk of chunks) {
    const chunk = String(rawChunk || "");
    if (!chunk) continue;
    const chunkBytes = Buffer.byteLength(chunk, "utf8");

    if (size > 0 && size + chunkBytes > maxBytes) {
      rotateLogFiles(filePath, maxFiles);
      size = 0;
    }

    fs.appendFileSync(filePath, chunk, "utf8");
    size += chunkBytes;

    if (size >= maxBytes) {
      rotateLogFiles(filePath, maxFiles);
      size = 0;
    }
  }
  return size;
}

function rotateLogFileStream(streamToRotate) {
  if (!LOG_TO_FILE || logFileWriterClosed || logFileRotationPending) return logFileRotationPromise;
  logFileRotationPending = true;
  logFileDrainPending = false;
  if (logFileStream === streamToRotate) logFileStream = null;

  logFileRotationPromise = new Promise((resolve) => {
    let finished = false;
    const finishRotation = () => {
      if (finished) return;
      finished = true;
      try {
        rotateLogFiles();
        logFileBytes = 0;
        logFileRotations += 1;
      } catch (err) {
        logFileRetryAt = Date.now() + LOG_FILE_RETRY_DELAY_MS;
        logFileLastError = { at: new Date().toISOString(), message: summarizeError(err) };
        console.error(`[LOG] rotation failed file=${LOG_FILE} err=${safeLogValue(err && err.message ? err.message : err, 180)}`);
      } finally {
        logFileRotationPending = false;
        logFileRotationPromise = null;
        flushLogFileQueue();
        resolve();
      }
    };

    // The writable "finish" callback can run before fs.WriteStream closes its
    // descriptor. Rename only after "close" so rotation also works on Windows.
    streamToRotate.once("close", finishRotation);
    try {
      streamToRotate.end();
    } catch (_) {
      try { streamToRotate.destroy(); } catch {}
      if (streamToRotate.closed) finishRotation();
    }
  });
  return logFileRotationPromise;
}

function ensureLogFileStream() {
  if (!LOG_TO_FILE || logFileWriterClosed || logFileRotationPending) return null;
  if (logFileStream) return logFileStream;

  const now = Date.now();
  if (now < logFileRetryAt) return null;

  if (!ensureParentDirectoryForFile(LOG_FILE, "log")) {
    logFileRetryAt = now + LOG_FILE_RETRY_DELAY_MS;
    return null;
  }

  try {
    const existing = fs.existsSync(LOG_FILE) ? fs.statSync(LOG_FILE) : null;
    if (existing && existing.isFile() && existing.size >= LOG_FILE_MAX_BYTES) {
      rotateLogFiles();
      logFileRotations += 1;
      logFileBytes = 0;
    } else {
      logFileBytes = existing && existing.isFile() ? existing.size : 0;
    }
  } catch (err) {
    logFileRetryAt = now + LOG_FILE_RETRY_DELAY_MS;
    logFileLastError = { at: new Date(now).toISOString(), message: summarizeError(err) };
    return null;
  }

  const stream = fs.createWriteStream(LOG_FILE, { flags: "a" });
  logFileStream = stream;
  logFileLastOpenedAt = new Date().toISOString();
  logFileLastError = null;
  stream.on("error", (err) => {
    const errorAt = Date.now();
    logFileDrainPending = false;
    logFileRetryAt = errorAt + LOG_FILE_RETRY_DELAY_MS;
    logFileLastError = { at: new Date(errorAt).toISOString(), message: summarizeError(err) };

    try { stream.destroy(); } catch {}
    if (logFileStream === stream) logFileStream = null;

    if (errorAt - logFileWriteErrorAt > 30000) {
      logFileWriteErrorAt = errorAt;
      console.error(`[LOG] stream error file=${LOG_FILE} err=${safeLogValue(err && err.message ? err.message : err, 180)} retryInMs=${LOG_FILE_RETRY_DELAY_MS}`);
    }

    if (!logFileWriterClosed && logFileQueue.length > 0) {
      const retryTimer = setTimeout(() => flushLogFileQueue(), LOG_FILE_RETRY_DELAY_MS);
      if (typeof retryTimer.unref === "function") retryTimer.unref();
    }
  });
  stream.on("drain", () => {
    if (logFileStream !== stream) return;
    logFileDrainPending = false;
    flushLogFileQueue();
  });

  return stream;
}

function maybeWarnDroppedLogLines(now = Date.now()) {
  if (logFileDroppedLines <= 0) return;
  if (now - logFileDropWarnAt < 30000) return;
  logFileDropWarnAt = now;
  console.error(`[LOG] dropped lines due to queue pressure dropped=${logFileDroppedLines} queueLines=${logFileQueue.length} queueBytes=${logFileQueueBytes}`);
}

function flushLogFileQueue() {
  if (!LOG_TO_FILE || logFileWriterClosed || logFileDrainPending || logFileRotationPending) return;
  const stream = ensureLogFileStream();
  if (!stream) return;

  while (logFileQueue.length > 0) {
    const chunk = logFileQueue.shift();
    logFileQueueBytes -= Buffer.byteLength(chunk, "utf8");
    const ok = stream.write(chunk);
    logFileBytes += Buffer.byteLength(chunk, "utf8");
    if (logFileBytes >= LOG_FILE_MAX_BYTES) {
      rotateLogFileStream(stream);
      break;
    }
    if (!ok) {
      logFileDrainPending = true;
      break;
    }
  }
}

function appendLogFileLine(line) {
  if (!LOG_TO_FILE || logFileWriterClosed) return;
  const chunk = String(line || "");
  const chunkBytes = Buffer.byteLength(chunk, "utf8");

  while (
    logFileQueue.length >= LOG_FILE_QUEUE_MAX_LINES ||
    (logFileQueueBytes + chunkBytes) > LOG_FILE_QUEUE_MAX_BYTES
  ) {
    const dropped = logFileQueue.shift();
    if (!dropped) break;
    logFileQueueBytes -= Buffer.byteLength(dropped, "utf8");
    logFileDroppedLines += 1;
  }

  logFileQueue.push(chunk);
  logFileQueueBytes += chunkBytes;
  maybeWarnDroppedLogLines();
  flushLogFileQueue();
}

function ensureRuntimeIncidentFileParent() {
  return ensureParentDirectoryForFile(RUNTIME_INCIDENT_FILE, "diag");
}

function listRecentNpmDebugLogs(limit = RUNTIME_INCIDENT_NPM_LOG_LIMIT) {
  if (!limit || limit < 1) return [];

  try {
    if (!fs.existsSync(NPM_DEBUG_LOG_DIR)) return [];
    return fs.readdirSync(NPM_DEBUG_LOG_DIR, { withFileTypes: true })
      .filter((entry) => entry.isFile() && /-debug-\d+\.log$/i.test(entry.name))
      .map((entry) => {
        const file = path.join(NPM_DEBUG_LOG_DIR, entry.name);
        try {
          const st = fs.statSync(file);
          return { file, sizeBytes: st.size, mtime: st.mtime.toISOString(), mtimeMs: st.mtimeMs };
        } catch {
          return null;
        }
      })
      .filter(Boolean)
      .sort((a, b) => b.mtimeMs - a.mtimeMs)
      .slice(0, limit)
      .map(({ mtimeMs, ...entry }) => entry);
  } catch (err) {
    return [{ error: summarizeError(err), dir: NPM_DEBUG_LOG_DIR }];
  }
}

function getProcessRuntimeMetadata() {
  return {
    pid: process.pid,
    ppid: process.ppid,
    argv: process.argv.map((value) => safeLogValue(value, 240)),
    execPath: safeLogValue(process.execPath, 240),
    npmLifecycleEvent: process.env.npm_lifecycle_event || null,
    npmLifecycleScript: process.env.npm_lifecycle_script || null,
    npmCommand: process.env.npm_command || null,
    npmExecPath: process.env.npm_execpath || null,
    container: fs.existsSync("/.dockerenv") ? "docker" : null
  };
}

function buildRuntimeIncidentPayload(kind, details = {}) {
  const mem = process.memoryUsage();
  return {
    at: new Date().toISOString(),
    kind: safeLogValue(kind || "runtime", 80),
    bootId: runtimeStats.bootId,
    startedAt: runtimeStats.startedAt,
    uptimeSec: Math.round(process.uptime()),
    pid: process.pid,
    nodeVersion: process.version,
    platform: process.platform,
    process: getProcessRuntimeMetadata(),
    railway: getRailwayRuntimeMetadata(),
    correlation: getRuntimeCorrelationMetadata(),
    details,
    stats: {
      shutdownSignals: runtimeStats.shutdownSignals,
      uncaughtExceptions: runtimeStats.uncaughtExceptions,
      unhandledRejections: runtimeStats.unhandledRejections,
      processWarnings: runtimeStats.processWarnings,
      serverErrors: runtimeStats.serverErrors,
      serverClientErrors: runtimeStats.serverClientErrors,
      totalRequests: runtimeStats.totalRequests,
      inFlightRequests: runtimeStats.inFlightRequests,
      completedRequests: runtimeStats.completedRequests,
      abortedRequests: runtimeStats.abortedRequests,
      lastRequestStartedAt: runtimeStats.lastRequestStartedAt,
      lastRequestCompletedAt: runtimeStats.lastRequestCompletedAt,
      lastRequestPath: runtimeStats.lastRequestPath,
      lastResponseStatus: runtimeStats.lastResponseStatus,
      maxObservedEventLoopLagMs: runtimeStats.maxObservedEventLoopLagMs,
      resources: getRuntimeResourceGauges()
    },
    memory: {
      rssMb: Math.round((mem.rss / (1024 * 1024)) * 100) / 100,
      heapUsedMb: Math.round((mem.heapUsed / (1024 * 1024)) * 100) / 100,
      heapTotalMb: Math.round((mem.heapTotal / (1024 * 1024)) * 100) / 100,
      externalMb: Math.round((mem.external / (1024 * 1024)) * 100) / 100
    },
    recentNpmDebugLogs: listRecentNpmDebugLogs()
  };
}

function recordRuntimeIncident(kind, details = {}) {
  const payload = buildRuntimeIncidentPayload(kind, details);
  if (!ensureRuntimeIncidentFileParent()) return payload;

  try {
    fs.appendFileSync(RUNTIME_INCIDENT_FILE, JSON.stringify(payload) + "\n", "utf8");
  } catch (err) {
    console.error(`[DIAG] unable to write incident file=${RUNTIME_INCIDENT_FILE} err=${safeLogValue(err && err.message ? err.message : err, 180)}`);
  }

  return payload;
}

function parseRuntimeIncidentLines(text, limit) {
  return String(text || "")
    .trim()
    .split(/\n+/)
    .filter(Boolean)
    .slice(-limit)
    .map((line) => {
      try { return JSON.parse(line); } catch { return { parseError: true, raw: line.slice(0, 500) }; }
    });
}

function readRuntimeIncidents(limit = RUNTIME_INCIDENT_HISTORY_LIMIT) {
  try {
    const st = fs.existsSync(RUNTIME_INCIDENT_FILE) ? fs.statSync(RUNTIME_INCIDENT_FILE) : null;
    if (!st || !st.isFile() || st.size <= 0) return [];

    const maxBytes = Math.max(64 * 1024, RUNTIME_INCIDENT_READ_MAX_BYTES);
    const start = Math.max(0, st.size - maxBytes);
    const length = st.size - start;
    const fd = fs.openSync(RUNTIME_INCIDENT_FILE, "r");

    try {
      const buffer = Buffer.alloc(length);
      fs.readSync(fd, buffer, 0, length, start);
      let text = buffer.toString("utf8");

      // If reading from the middle of a large NDJSON file, discard the first
      // partial line so only complete incident records are parsed.
      if (start > 0) {
        const firstNewline = text.indexOf("\n");
        text = firstNewline >= 0 ? text.slice(firstNewline + 1) : "";
      }

      return parseRuntimeIncidentLines(text, limit);
    } finally {
      fs.closeSync(fd);
    }
  } catch (err) {
    return [{ error: summarizeError(err), file: RUNTIME_INCIDENT_FILE }];
  }
}

function getLogFileStatus() {
  try {
    const st = fs.existsSync(LOG_FILE) ? fs.statSync(LOG_FILE) : null;
    return {
      enabled: LOG_TO_FILE,
      file: LOG_FILE,
      exists: Boolean(st),
      isFile: st ? st.isFile() : false,
      sizeBytes: st ? st.size : 0,
      mtime: st ? st.mtime.toISOString() : null,
      queueLines: logFileQueue.length,
      queueBytes: logFileQueueBytes,
      droppedLines: logFileDroppedLines,
      streamReady: Boolean(logFileStream),
      rotationEnabled: LOG_TO_FILE,
      rotationPending: logFileRotationPending,
      rotations: logFileRotations,
      maxBytes: LOG_FILE_MAX_BYTES,
      maxFiles: LOG_FILE_MAX_FILES,
      trackedSizeBytes: logFileBytes,
      lastOpenedAt: logFileLastOpenedAt,
      lastError: logFileLastError
    };
  } catch (err) {
    return {
      enabled: LOG_TO_FILE,
      file: LOG_FILE,
      exists: false,
      error: summarizeError(err),
      lastError: logFileLastError
    };
  }
}

function readLogFileTail(maxBytes = 200 * 1024) {
  const status = getLogFileStatus();
  if (!status.exists || !status.isFile || status.sizeBytes <= 0) {
    return { status, text: "" };
  }

  const safeMaxBytes = clampMs(Number(maxBytes) || (200 * 1024), 1024, 1024 * 1024);
  const start = Math.max(0, status.sizeBytes - safeMaxBytes);
  const length = status.sizeBytes - start;
  const fd = fs.openSync(LOG_FILE, "r");
  try {
    const buffer = Buffer.alloc(length);
    fs.readSync(fd, buffer, 0, length, start);
    return { status, start, bytesRead: length, truncated: start > 0, text: buffer.toString("utf8") };
  } finally {
    fs.closeSync(fd);
  }
}

function closeLogFileWriter(timeoutMs = 2000) {
  if (!LOG_TO_FILE || logFileWriterClosed) return logFileClosePromise || Promise.resolve();
  if (logFileClosePromise) return logFileClosePromise;

  logFileWriterClosed = true;
  logFileClosePromise = new Promise((resolve) => {
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      resolve();
    };
    const timeout = setTimeout(finish, Math.max(250, timeoutMs));

    const closeActiveStream = () => {
      const remainingChunks = logFileQueue;
      logFileQueue = [];
      logFileQueueBytes = 0;
      const stream = logFileStream;

      if (!stream) {
        if (remainingChunks.length > 0) {
          try {
            logFileBytes = appendLogChunksSync(remainingChunks);
          } catch {}
        }
        clearTimeout(timeout);
        finish();
        return;
      }

      let streamClosed = false;
      const finishAfterClose = () => {
        if (streamClosed) return;
        streamClosed = true;
        if (remainingChunks.length > 0) {
          try {
            logFileBytes = appendLogChunksSync(remainingChunks);
          } catch {}
        }
        clearTimeout(timeout);
        finish();
      };

      stream.once("close", finishAfterClose);
      try {
        stream.end();
      } catch {
        try { stream.destroy(); } catch {}
        if (stream.closed) finishAfterClose();
      }
    };

    if (logFileRotationPromise) {
      logFileRotationPromise.then(closeActiveStream, closeActiveStream);
    } else {
      closeActiveStream();
    }
  });

  logFileClosePromise.then(
    () => { logFileStream = null; },
    () => { logFileStream = null; }
  );
  return logFileClosePromise;
}

const AGG_WINDOW_MS = parseInt(process.env.LOG_AGG_WINDOW_MS || "60000", 10);
const AGG_FLUSH_MS = parseInt(process.env.LOG_AGG_FLUSH_MS || "15000", 10);
const logAggregation = new Map();

function aggregatePerIpEvent(eventKey, details = {}) {
  const suppressFirst = details && details.suppressFirst === true;
  const ip = safeLogValue(details.ip || "unknown", 80);
  const reasonKey = details && details.reason ? safeLogValue(details.reason, 80) : "";
  const key = `${eventKey}:${ip}`;
  const now = Date.now();
  const st = logAggregation.get(key);

  if (!st || now > st.windowStart + AGG_WINDOW_MS) {
    boundedMapSet(logAggregation, key, {
      count: 1,
      windowStart: now,
      lastDetails: details,
      reasonCounts: reasonKey ? new Map([[reasonKey, 1]]) : new Map()
    }, LOG_AGGREGATION_MAX_ENTRIES);
    return !suppressFirst;
  }

  st.count += 1;
  st.lastDetails = details;
  if (reasonKey) {
    st.reasonCounts.set(reasonKey, (st.reasonCounts.get(reasonKey) || 0) + 1);
  }
  boundedMapSet(logAggregation, key, st, LOG_AGGREGATION_MAX_ENTRIES);
  return false;
}

function flushAggregatedLogs(now = Date.now()) {
  for (const [key, st] of logAggregation.entries()) {
    if (now < st.windowStart + AGG_WINDOW_MS) continue;
    if (st.count > 1) {
      const [eventKey] = key.split(":");
      const ctry = st.lastDetails.country ? ` country=${safeLogValue(st.lastDetails.country, 8)}` : "";
      const topReason = st.reasonCounts && st.reasonCounts.size
        ? [...st.reasonCounts.entries()].sort((a, b) => b[1] - a[1])[0]
        : null;
      const reason = topReason ? ` reason=${safeLogValue(topReason[0], 80)}` : "";
      const reasonSpread = st.reasonCounts && st.reasonCounts.size > 1
        ? ` reasons=${safeLogValue([...st.reasonCounts.entries()].map(([name, count]) => `${name}:${count}`).join(","), 180)}`
        : "";
      addLog(`[AGG:${eventKey}] blocked=${st.count} ip=${safeLogValue(st.lastDetails.ip || "unknown", 80)} window=${Math.round(AGG_WINDOW_MS / 1000)}s${ctry}${reason}${reasonSpread}`);
      if ((eventKey === "SCANNER-BLOCK" || eventKey === "PATH-CANONICALIZE") && st.count >= SCANNER_AGG_ALERT_THRESHOLD) {
        addLog(`[ALERT:SCANNER-BURST] event=${safeLogValue(eventKey, 40)} blocked=${st.count} threshold=${SCANNER_AGG_ALERT_THRESHOLD} ip=${safeLogValue(st.lastDetails.ip || "unknown", 80)} window=${Math.round(AGG_WINDOW_MS / 1000)}s${reason}${reasonSpread}`);
      }
      addSpacer();
    }
    logAggregation.delete(key);
  }
}

function sseSend(res, text, id) {
  if (id != null) res.write(`id: ${id}\n`);
  String(text).split(/\r?\n/).forEach(line => {
    res.write(`data: ${line}\n`);
  });
  res.write('\n');
}

function broadcastLog(line, id) {
  for (const res of LOG_LISTENERS) {
    try { sseSend(res, line, id); } catch {}
  }
}

function appendInMemoryLog(entry, id) {
  LOGS.push(entry);
  LOG_IDS.push(id);

  const overflow = LOGS.length - MAX_LOG_LINES;
  if (overflow > 0) {
    LOGS.splice(0, overflow);
    LOG_IDS.splice(0, overflow);
  }
}

const LOG_INTEGRITY_EVENT_MARKERS = [
  "[REQ:finish]", "[REQ:close]", "[DEP:finish]", "[SCANNER]",
  "[SCANNER-BLOCK]", "[VALIDATION-FAILED]", "[AGG:", "[BOT-VERIFY]",
  "[REPUTATION-DENY]", "[CHALLENGE]", "[ALERT]"
];
const LOG_INTEGRITY_TIMESTAMP_REGEX = /\[(?:\d{2}-\d{2}-\d{4} - [^\]]+|\d{4}-\d{2}-\d{2}T[^\]]+)\]/g;

function countStringOccurrences(value, needle) {
  if (!needle) return 0;
  let count = 0;
  let pos = 0;
  const source = String(value || "");
  while ((pos = source.indexOf(needle, pos)) !== -1) {
    count += 1;
    pos += needle.length;
  }
  return count;
}

function analyzeLogIntegrity(lines = LOGS, ids = LOG_IDS) {
  const inputLines = Array.isArray(lines) ? lines : [];
  const inputIds = Array.isArray(ids) ? ids : [];
  const samples = { multiTimestamp: [], multiMarker: [], adjacentDuplicate: [], idGap: [] };
  let blankSpacerLines = 0;
  let multiTimestampLines = 0;
  let multiMarkerLines = 0;
  let adjacentExactDuplicates = 0;
  let idGaps = 0;

  for (let index = 0; index < inputLines.length; index += 1) {
    const line = String(inputLines[index] || "");
    if (!line.trim()) {
      blankSpacerLines += 1;
      continue;
    }

    const timestampMatches = line.match(LOG_INTEGRITY_TIMESTAMP_REGEX) || [];
    if (timestampMatches.length > 1) {
      multiTimestampLines += 1;
      if (samples.multiTimestamp.length < 5) samples.multiTimestamp.push({ index, id: inputIds[index] || null, preview: line.slice(0, 240) });
    }

    const markerCount = LOG_INTEGRITY_EVENT_MARKERS.reduce((sum, marker) => sum + countStringOccurrences(line, marker), 0);
    if (markerCount > 1) {
      multiMarkerLines += 1;
      if (samples.multiMarker.length < 5) samples.multiMarker.push({ index, id: inputIds[index] || null, markerCount, preview: line.slice(0, 240) });
    }

    if (index > 0 && line && line === String(inputLines[index - 1] || "")) {
      adjacentExactDuplicates += 1;
      if (samples.adjacentDuplicate.length < 5) samples.adjacentDuplicate.push({ index, id: inputIds[index] || null, preview: line.slice(0, 240) });
    }
  }

  for (let index = 1; index < inputIds.length; index += 1) {
    const prior = Number(inputIds[index - 1]);
    const current = Number(inputIds[index]);
    if (Number.isFinite(prior) && Number.isFinite(current) && current !== prior + 1) {
      idGaps += 1;
      if (samples.idGap.length < 5) samples.idGap.push({ index, previousId: prior, currentId: current });
    }
  }

  return {
    ok: multiTimestampLines === 0 && multiMarkerLines === 0 && adjacentExactDuplicates === 0 && idGaps === 0,
    lineCount: inputLines.length,
    firstId: inputIds.length ? inputIds[0] : null,
    lastId: inputIds.length ? inputIds[inputIds.length - 1] : null,
    blankSpacerLines,
    multiTimestampLines,
    multiMarkerLines,
    adjacentExactDuplicates,
    idGaps,
    samples
  };
}

function addLog(message) {
  const now = new Date();
  const tsLocal = formatLocal(now);

  const parts = String(message).replace(/\r\n/g, "\n").split("\n");

  for (const raw of parts) {
    const line = sanitizeOneLine(raw);
    const entry = `[${tsLocal}] ${line}`;
    const id = ++LOG_SEQ;

    console.log(entry);

    appendInMemoryLog(entry, id);

    broadcastLog(entry, id);
    appendLogFileLine(entry + "\n");
  }
}

function addSpacer() {
  // Keep the in-memory/file/SSE spacer, but avoid emitting empty stdout lines.
  // Some platform log viewers render empty stdout writes as standalone `[inf]`
  // rows, which makes exported logs look concatenated or duplicated.
  const id = ++LOG_SEQ;
  appendInMemoryLog("", id);
  appendLogFileLine("\n");
  broadcastLog("", id);
}


  return {
    LOG_TO_FILE,
    LOG_FILE,
    LOG_FILE_MAX_BYTES,
    LOG_FILE_MAX_FILES,
    BACKLOG_ON_CONNECT,
    RUNTIME_INCIDENT_FILE,
    NPM_DEBUG_LOG_DIR,
    formatRailwayRuntimeLine,
    getRuntimeCorrelationMetadata,
    formatRuntimeCorrelationSuffix,
    LOGS,
    LOG_IDS,
    LOG_LISTENERS,
    getRuntimeResourceGauges,
    maybeEmitRuntimeGaugeAlerts,
    getProcessRuntimeMetadata,
    buildRuntimeIncidentPayload,
    recordRuntimeIncident,
    readRuntimeIncidents,
    getLogFileStatus,
    readLogFileTail,
    closeLogFileWriter,
    AGG_FLUSH_MS,
    aggregatePerIpEvent,
    flushAggregatedLogs,
    sseSend,
    analyzeLogIntegrity,
    addLog,
    addSpacer
  };
}

module.exports = createLogging;
