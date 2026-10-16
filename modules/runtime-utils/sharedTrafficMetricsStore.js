"use strict";

const { randomUUID } = require("node:crypto");
const { performance } = require("node:perf_hooks");

const KINDS = ["operational", "head", "prefetch", "get", "other"];
const STATUS_CLASSES = ["1xx", "2xx", "3xx", "4xx", "5xx", "other"];
const CHALLENGE_EVENTS = [
  "shown", "passed", "failed", "expired", "expiredOrDuplicate",
  "providerError", "redirected", "payloadExpired"
];
const RETRY_MAX_AGE_MS = 24 * 60 * 60 * 1000;
const WATERMARK_TTL_SECONDS = 7 * 24 * 60 * 60;
const MAX_NUMBER = Number.MAX_SAFE_INTEGER;
const GROUPS = ["total", ...KINDS.map((kind) => `kind:${kind}`)];
const FIELDS = GROUPS.flatMap((group) => [
  ...["requests", "completed", "aborted", ...STATUS_CLASSES.map((value) => `status:${value}`)]
    .map((name) => ({ name: `${group}:${name}`, type: "count" })),
  { name: `${group}:durationSumMs`, type: "sum" },
  { name: `${group}:durationMaxMs`, type: "max" }
]).concat(CHALLENGE_EVENTS.map((name) => ({ name: `challenge:${name}`, type: "count" })));

// The watermark and aggregate keys use one cluster hash tag. Validate every
// argument and existing numeric field before writing: Lua errors do not roll
// back writes already made by a script.
const FLUSH_SCRIPT = `
local fields = {${FIELDS.map(({ name }) => JSON.stringify(name)).join(",")}}
local types = {${FIELDS.map(({ type }) => JSON.stringify(type)).join(",")}}
local limit = 9007199254740991
local function validNumber(value)
  return value and value == value and value >= 0 and value <= limit
end
local aggregateType = redis.call("TYPE", KEYS[1]).ok
local writerType = redis.call("TYPE", KEYS[2]).ok
if (aggregateType ~= "none" and aggregateType ~= "hash") or
   (writerType ~= "none" and writerType ~= "string") then
  return redis.error_reply("traffic_metrics_invalid_type")
end
local sequence = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])
if not validNumber(sequence) or sequence < 1 or sequence % 1 ~= 0 or
   ttl ~= ${WATERMARK_TTL_SECONDS} or #ARGV ~= #fields + 2 then
  return redis.error_reply("traffic_metrics_invalid_batch")
end
local watermark = redis.call("GET", KEYS[2])
if watermark then
  local previousSequence = tonumber(watermark)
  if not validNumber(previousSequence) or previousSequence % 1 ~= 0 then
    return redis.error_reply("traffic_metrics_invalid_watermark")
  end
  if previousSequence >= sequence then return 0 end
end
local incoming = {}
local current = {}
for index, field in ipairs(fields) do
  incoming[index] = tonumber(ARGV[index + 2])
  local existing = redis.call("HGET", KEYS[1], field)
  if existing then current[index] = tonumber(existing) else current[index] = 0 end
  if not validNumber(incoming[index]) or not validNumber(current[index]) then
    return redis.error_reply("traffic_metrics_invalid_number")
  end
  if types[index] == "count" then
    if incoming[index] % 1 ~= 0 or current[index] % 1 ~= 0 or
       (existing and not string.match(existing, "^%d+$")) then
      return redis.error_reply("traffic_metrics_invalid_counter")
    end
  end
  if types[index] ~= "max" and current[index] + incoming[index] > limit then
    return redis.error_reply("traffic_metrics_counter_overflow")
  end
end
local clock = redis.call("TIME")
local timestamp = clock[1] .. string.format("%03d", math.floor(tonumber(clock[2]) / 1000))
for index, field in ipairs(fields) do
  local value = incoming[index]
  if value > 0 then
    if types[index] == "max" then
      if value > current[index] then redis.call("HSET", KEYS[1], field, ARGV[index + 2]) end
    elseif types[index] == "count" then
      redis.call("HINCRBY", KEYS[1], field, ARGV[index + 2])
    else
      redis.call("HINCRBYFLOAT", KEYS[1], field, ARGV[index + 2])
    end
  end
end
redis.call("HSETNX", KEYS[1], "startedAtMs", timestamp)
redis.call("HSET", KEYS[1], "updatedAtMs", timestamp)
redis.call("SET", KEYS[2], ARGV[1], "EX", ARGV[2])
return 1
`;

function createSharedTrafficMetricsStore({
  client, namespace = "oldserver222", flushIntervalMs = 1000, now = Date.now
} = {}) {
  if (typeof namespace !== "string" || !/^[A-Za-z0-9:_-]{1,80}$/.test(namespace)) {
    throw new TypeError("Traffic metrics namespace must contain 1-80 letters, numbers, colons, underscores, or hyphens");
  }
  const configured = !!client;
  const prefix = `traffic-metrics:{${namespace}:v1}`;
  const aggregateKey = `${prefix}:aggregate`;
  const writerKey = `${prefix}:writer:${randomUUID()}`;
  const knownKinds = new Set(KINDS);
  const knownStatuses = new Set(STATUS_CLASSES);
  const knownEvents = new Set(CHALLENGE_EVENTS);
  let pending = createAccumulator();
  let batch = null;
  let batchWasUncertain = false;
  let sequence = 0;
  let activeFlush = null;
  let closePromise = null;
  let closing = false;
  let lastFlushAt = null;
  let lastReadAt = null;
  let lastError = null;
  let uncertainBatches = 0;
  let uncertainObservations = 0;
  let droppedBatches = 0;
  let droppedObservations = 0;

  function createAccumulator() {
    return { observations: 0, fields: Object.fromEntries(FIELDS.map(({ name }) => [name, 0])) };
  }

  function isReady() {
    return configured && (client.status === undefined || client.status === "ready");
  }

  function recordRequest({ kind, completed, statusClass, durationMs } = {}) {
    if (!configured || closing || !knownKinds.has(kind) || typeof completed !== "boolean") return false;
    const status = knownStatuses.has(statusClass) ? statusClass : "other";
    const duration = typeof durationMs === "number" && Number.isFinite(durationMs)
      ? Math.min(MAX_NUMBER, Math.max(0, durationMs)) : 0;
    for (const group of ["total", `kind:${kind}`]) {
      pending.fields[`${group}:requests`] += 1;
      pending.fields[`${group}:${completed ? "completed" : "aborted"}`] += 1;
      if (completed) {
        pending.fields[`${group}:status:${status}`] += 1;
        pending.fields[`${group}:durationSumMs`] = Math.min(MAX_NUMBER, pending.fields[`${group}:durationSumMs`] + duration);
        pending.fields[`${group}:durationMaxMs`] = Math.max(pending.fields[`${group}:durationMaxMs`], duration);
      }
    }
    pending.observations += 1;
    return true;
  }

  function recordChallengeEvent(name) {
    if (!configured || closing || !knownEvents.has(name)) return false;
    pending.fields[`challenge:${name}`] += 1;
    pending.observations += 1;
    return true;
  }

  function discardExpiredBatch() {
    if (batch && Math.max(now() - batch.createdAt, performance.now() - batch.createdMonotonicAt) >= RETRY_MAX_AGE_MS) {
      droppedBatches += 1;
      droppedObservations += batch.observations;
      batch = null;
      batchWasUncertain = false;
      lastError = "retry_expired";
    }
  }

  function isoTime(value) {
    if (value === undefined || value === null || value === "") return null;
    const number = Number(value);
    return Number.isFinite(number) && number >= 0 && number <= 8640000000000000
      ? new Date(number).toISOString() : null;
  }

  async function flushOnce() {
    discardExpiredBatch();
    if (!isReady()) {
      if (configured) lastError = "unavailable";
      return false;
    }
    if (!batch && !pending.observations) return true;
    if (!batch) {
      batch = Object.freeze({
        sequence: ++sequence,
        createdAt: now(),
        createdMonotonicAt: performance.now(),
        observations: pending.observations,
        values: Object.freeze(FIELDS.map(({ name }) => String(pending.fields[name])))
      });
      batchWasUncertain = false;
      pending = createAccumulator();
    }
    try {
      const result = await client.eval(
        FLUSH_SCRIPT, 2, aggregateKey, writerKey,
        String(batch.sequence), String(WATERMARK_TTL_SECONDS), ...batch.values
      );
      if (Number(result) !== 0 && Number(result) !== 1) throw new Error("Invalid metrics acknowledgment");
      lastFlushAt = isoTime(now());
      lastError = null;
      batch = null;
      batchWasUncertain = false;
      return true;
    } catch (_) {
      if (!batchWasUncertain) {
        uncertainBatches += 1;
        uncertainObservations += batch.observations;
        batchWasUncertain = true;
      }
      lastError = "write_failed";
      return false;
    }
  }

  function flush() {
    if (activeFlush) return activeFlush;
    activeFlush = flushOnce().finally(() => { activeFlush = null; });
    return activeFlush;
  }

  function getStatus() {
    return {
      configured,
      ready: isReady(),
      namespace,
      lastFlushAt,
      lastReadAt,
      pendingObservations: pending.observations + (batch ? batch.observations : 0),
      uncertainBatches,
      uncertainObservations,
      droppedBatches,
      droppedObservations,
      lastError
    };
  }

  async function getSnapshot() {
    if (!configured) return null;
    // A retry can acknowledge an older batch while newer observations wait in
    // pending. A second bounded flush includes observations already pending at
    // the start of this read without looping under continuous traffic.
    await flush();
    if (pending.observations && !batch && isReady()) await flush();
    if (!isReady()) return null;
    try {
      const values = await client.hgetall(aggregateKey);
      const number = (field) => {
        if (!Object.hasOwn(values, field)) return 0;
        const value = Number(values[field]);
        if (!Number.isFinite(value) || value < 0 || value > MAX_NUMBER) throw new Error("Invalid metrics data");
        return value;
      };
      const counters = (group) => {
        const completed = number(`${group}:completed`);
        return {
          requests: number(`${group}:requests`),
          completed,
          aborted: number(`${group}:aborted`),
          byStatusClass: Object.fromEntries(STATUS_CLASSES.map((status) => [status, number(`${group}:status:${status}`)])),
          latencyMs: {
            mean: completed ? number(`${group}:durationSumMs`) / completed : null,
            max: completed ? number(`${group}:durationMaxMs`) : null
          }
        };
      };
      const snapshot = {
        scope: "redis",
        namespace,
        startedAt: isoTime(values.startedAtMs),
        updatedAt: isoTime(values.updatedAtMs),
        total: counters("total"),
        byKind: Object.fromEntries(KINDS.map((kind) => [kind, counters(`kind:${kind}`)])),
        challenges: Object.fromEntries(CHALLENGE_EVENTS.map((name) => [name, number(`challenge:${name}`)]))
      };
      lastReadAt = isoTime(now());
      // Keep a write failure visible even if reading the older shared totals
      // succeeds. These totals contain acknowledged Redis state only.
      if (lastError === "read_failed" || lastError === "unavailable") lastError = null;
      return snapshot;
    } catch (_) {
      lastError = "read_failed";
      return null;
    }
  }

  const interval = configured ? setInterval(() => { void flush(); },
    Math.min(60000, Math.max(50, Number(flushIntervalMs) || 1000))) : null;
  if (interval) interval.unref();

  function close() {
    if (closePromise) return closePromise;
    closing = true;
    if (interval) clearInterval(interval);
    closePromise = (async () => {
      if (activeFlush) await activeFlush;
      const flushed = await flush();
      // A previously failed batch can be acknowledged by that flush. Include
      // the final pending accumulator too, but never loop on write failures.
      if (flushed && pending.observations && !batch) return flush();
      return flushed;
    })();
    return closePromise;
  }

  return { recordRequest, recordChallengeEvent, flush, getSnapshot, getStatus, close };
}

module.exports = createSharedTrafficMetricsStore;
