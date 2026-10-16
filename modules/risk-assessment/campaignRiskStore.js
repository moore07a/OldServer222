"use strict";

const FIELDS = ["requests", "headless", "hosting", "proxy", "vpn", "residentialProxy", "challengePassed", "challengeFailed", "conversions"];
const DAY_MS = 86400000;
const MAX_COUNT = Number.MAX_SAFE_INTEGER;
const UNATTRIBUTED = "__unattributed__";
const SOURCE_RE = /^[a-f0-9]{64}$/;
const ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const BIT_COUNT = 4096;

// Only this subsystem's expiring keys are accessed. Every key shares a cluster tag.
const OBSERVE_SCRIPT = `
local hashType = redis.call('TYPE', KEYS[1]).ok
local sourceType = redis.call('TYPE', KEYS[2]).ok
if (hashType ~= 'none' and hashType ~= 'hash') or (sourceType ~= 'none' and sourceType ~= 'string') then
  return redis.error_reply('campaign_risk_invalid_type')
end
local fields = {'requests','headless','hosting','proxy','vpn','residentialProxy','challengePassed','challengeFailed'}
local existing = redis.call('HMGET', KEYS[1], unpack(fields))
for _, value in ipairs(existing) do
  if value and (not string.match(value, '^%d+$') or not tonumber(value) or tonumber(value) >= 9007199254740991) then
    return redis.error_reply('campaign_risk_invalid_counter')
  end
end
-- PFADD can fail on a corrupt string: validate before any counter changes.
redis.call('PFCOUNT', KEYS[2])
for index, field in ipairs(fields) do
  if tonumber(ARGV[index + 2]) == 1 then redis.call('HINCRBY', KEYS[1], field, 1) end
end
if ARGV[2] ~= '' then redis.call('PFADD', KEYS[2], ARGV[2]) end
redis.call('PEXPIREAT', KEYS[1], ARGV[1])
if ARGV[2] ~= '' then redis.call('PEXPIREAT', KEYS[2], ARGV[1]) end
return 1
`;
const READ_SCRIPT = `
local fields = {'requests','headless','hosting','proxy','vpn','residentialProxy','challengePassed','challengeFailed','conversions'}
local result = {}
for index = 1, #KEYS, 2 do
  local row = redis.call('HMGET', KEYS[index], unpack(fields))
  for field = 1, #fields do table.insert(result, row[field] or '0') end
  table.insert(result, redis.call('PFCOUNT', KEYS[index + 1]))
end
return result
`;
const CONVERSION_SCRIPT = `
local now = tonumber(ARGV[1])
local last = redis.call('HGET', KEYS[2], ARGV[2]) or redis.call('HGET', KEYS[3], ARGV[2])
if last and tonumber(last) > now - 86400000 then return 0 end
if redis.call('HLEN', KEYS[2]) >= tonumber(ARGV[3]) then return -1 end
local metricType = redis.call('TYPE', KEYS[1]).ok
if metricType ~= 'none' and metricType ~= 'hash' then return redis.error_reply('campaign_risk_invalid_type') end
local existing = redis.call('HGET', KEYS[1], 'conversions')
if existing and (not string.match(existing, '^%d+$') or not tonumber(existing) or tonumber(existing) >= 9007199254740991) then
  return redis.error_reply('campaign_risk_invalid_counter')
end
-- Mark first: even an unexpected later write failure cannot double-count on
-- retry. A rejected/uncertain conversion may be undercounted, never replayed.
redis.call('HSET', KEYS[2], ARGV[2], ARGV[1])
redis.call('PEXPIRE', KEYS[2], 172800000)
redis.call('HINCRBY', KEYS[1], 'conversions', 1)
redis.call('PEXPIREAT', KEYS[1], ARGV[4])
return 1
`;

function boundedInt(value, fallback, min, max) {
  return Number.isInteger(value) && value >= min && value <= max ? value : fallback;
}
function createCampaignRiskStore({
  client = null, namespace = "oldserver222", campaignIds = [], windowSec = 300,
  now = Date.now, maxQueue = 128, operationTimeoutMs = 1500,
  maxLocalConversionIds = 4096, maxRedisConversionIdsPerDay = 2048
} = {}) {
  if (typeof namespace !== "string" || !/^[A-Za-z0-9:_-]{1,80}$/.test(namespace)) throw new TypeError("Invalid campaign risk namespace");
  if (!Array.isArray(campaignIds) || campaignIds.length > 32 || campaignIds.some(id => typeof id !== "string" || !ID_RE.test(id) || id === UNATTRIBUTED) || new Set(campaignIds).size !== campaignIds.length) throw new TypeError("Configure at most 32 unique safe campaign IDs");
  windowSec = boundedInt(windowSec, 300, 10, 3600);
  maxQueue = boundedInt(maxQueue, 128, 1, 128);
  operationTimeoutMs = boundedInt(operationTimeoutMs, 1500, 20, 5000);
  maxLocalConversionIds = boundedInt(maxLocalConversionIds, 4096, 1, 4096);
  maxRedisConversionIdsPerDay = boundedInt(maxRedisConversionIdsPerDay, 2048, 1, 2048);
  const allowed = new Set(campaignIds);
  const ids = [...campaignIds, UNATTRIBUTED];
  const prefix = `campaign-risk:{${namespace}:v1}`;
  const windowMs = windowSec * 1000;
  const configured = !!client;
  const queue = [];
  const localDedupe = new Map();
  let localStart = -1;
  let local = new Map();
  let active = null;
  let closing = false;
  let stalled = false;
  let snapshotPromise = null;
  let droppedObservations = 0;
  let uncertainObservations = 0;
  let lastError = null;
  let lastReadAt = null;

  function time() { const value = Number(now()); return Number.isFinite(value) ? Math.max(0, Math.min(8640000000000000, value)) : Date.now(); }
  function startAt(timestamp = time()) { return Math.floor(timestamp / windowMs) * windowMs; }
  function rotate() {
    const start = startAt();
    if (start !== localStart) {
      localStart = start;
      local = new Map(ids.map(id => [id, { id, ...Object.fromEntries(FIELDS.map(field => [field, 0])), bits: new Uint8Array(BIT_COUNT / 8), occupied: 0 }]));
    }
    return start;
  }
  function ready() { return configured && !closing && !stalled && (client.status === undefined || client.status === "ready"); }
  function keys(id, start) { return [`${prefix}:window:${start}:${id}:counts`, `${prefix}:window:${start}:${id}:sources`]; }
  function status() {
    return { configured, ready: ready(), namespace, pendingOperations: queue.length + Number(!!active), queueLimit: maxQueue,
      droppedObservations, uncertainObservations, lastError, lastReadAt,
      ...(configured ? { fallbackScope: "current_process" } : {}), distinctSourceMethod: configured ? "redis_hyperloglog_or_local_bitmap" : "local_bitmap", distinctSourceBits: BIT_COUNT };
  }
  function cancelQueued(reason) {
    for (const job of queue.splice(0)) {
      clearTimeout(job.timer);
      if (job.observation) droppedObservations += 1;
      job.resolve({ ok: false, reason });
    }
  }
  function pump() {
    if (active || closing || !queue.length) return;
    if (!ready()) { lastError = "unavailable"; cancelQueued("unavailable"); return; }
    const job = queue.shift();
    active = job;
    job.started = true;
    // The command client must disable offline queues and command resending. A
    // timed-out command remains the sole active command until it actually settles.
    Promise.resolve().then(job.run).then(value => {
      if (!job.timedOut) { lastError = null; job.resolve({ ok: true, value }); }
    }, () => {
      if (!job.timedOut) {
        lastError = "command_failed";
        if (job.observation) uncertainObservations += 1;
        job.resolve({ ok: false, reason: "unavailable" });
      }
    }).finally(() => {
      clearTimeout(job.timer);
      active = null;
      stalled = false;
      pump();
    });
  }
  function enqueue(run, observation = false) {
    if (!ready()) {
      if (observation) droppedObservations += 1;
      lastError = "unavailable";
      return Promise.resolve({ ok: false, reason: "unavailable" });
    }
    if (queue.length + Number(!!active) >= maxQueue) {
      if (observation) droppedObservations += 1;
      lastError = "queue_full";
      return Promise.resolve({ ok: false, reason: "capacity" });
    }
    return new Promise(resolve => {
      const job = { run, observation, resolve, started: false, timedOut: false };
      job.timer = setTimeout(() => {
        job.timedOut = true;
        lastError = "operation_timeout";
        if (job.started) {
          stalled = true;
          if (observation) uncertainObservations += 1;
          cancelQueued("unavailable");
        } else {
          const index = queue.indexOf(job);
          if (index >= 0) queue.splice(index, 1);
          if (observation) droppedObservations += 1;
        }
        resolve({ ok: false, reason: "unavailable" });
      }, operationTimeoutMs);
      queue.push(job);
      pump();
    });
  }
  function localRows() {
    rotate();
    return ids.map(id => {
      const value = local.get(id);
      const { bits, occupied, ...row } = value;
      const saturated = occupied === BIT_COUNT;
      return { ...row, distinctSourcesEstimate: Math.min(value.requests, Math.round(-BIT_COUNT * Math.log(Math.max(1, BIT_COUNT - occupied) / BIT_COUNT))), distinctSourcesSaturated: saturated };
    });
  }
  function recordRequest(input = {}) {
    if (closing) return false;
    const id = allowed.has(input.campaignId) ? input.campaignId : UNATTRIBUTED;
    const source = typeof input.sourceHash === "string" && SOURCE_RE.test(input.sourceHash) ? input.sourceHash : "";
    const flags = FIELDS.slice(1, -1).map(field => input[field] === true ? 1 : 0);
    const start = rotate();
    const value = local.get(id);
    value.requests = Math.min(MAX_COUNT, value.requests + 1);
    flags.forEach((flag, index) => { const field = FIELDS[index + 1]; value[field] = Math.min(MAX_COUNT, value[field] + flag); });
    if (source) {
      const bit = parseInt(source.slice(0, 8), 16) % BIT_COUNT;
      const mask = 1 << (bit % 8);
      if (!(value.bits[bit >> 3] & mask)) { value.bits[bit >> 3] |= mask; value.occupied += 1; }
    }
    if (configured) void enqueue(() => client.eval(OBSERVE_SCRIPT, 2, ...keys(id, start), String(start + 2 * windowMs), source, "1", ...flags.map(String)), true);
    return true;
  }
  async function recordConversion({ campaignId, eventIdHash } = {}) {
    if (!allowed.has(campaignId)) return { accepted: false, reason: "invalid_campaign" };
    if (typeof eventIdHash !== "string" || !SOURCE_RE.test(eventIdHash)) return { accepted: false, reason: "invalid_event_id" };
    if (closing) return { accepted: false, reason: "unavailable" };
    const timestamp = time();
    const start = rotate();
    if (!configured) {
      for (const [key, savedAt] of localDedupe) if (savedAt <= timestamp - DAY_MS) localDedupe.delete(key);
      const dedupeKey = `${campaignId}:${eventIdHash}`;
      if (localDedupe.has(dedupeKey)) return { accepted: true, duplicate: true, scope: "current_process" };
      if (localDedupe.size >= maxLocalConversionIds) return { accepted: false, reason: "capacity" };
      localDedupe.set(dedupeKey, timestamp);
      local.get(campaignId).conversions += 1;
      return { accepted: true, duplicate: false, scope: "current_process" };
    }
    const day = Math.floor(timestamp / DAY_MS);
    const result = await enqueue(() => client.eval(CONVERSION_SCRIPT, 3,
      keys(campaignId, start)[0], `${prefix}:dedupe:${campaignId}:${day}`, `${prefix}:dedupe:${campaignId}:${day - 1}`,
      String(timestamp), eventIdHash, String(maxRedisConversionIdsPerDay), String(start + 2 * windowMs)));
    if (!result.ok) return { accepted: false, reason: result.reason };
    if (Number(result.value) === -1) return { accepted: false, reason: "capacity" };
    if (Number(result.value) !== 0 && Number(result.value) !== 1) return { accepted: false, reason: "unavailable" };
    if (Number(result.value) === 1 && rotate() === start) local.get(campaignId).conversions += 1;
    return { accepted: true, duplicate: Number(result.value) === 0, scope: "redis" };
  }
  function getSnapshot() {
    if (snapshotPromise) return snapshotPromise;
    snapshotPromise = (async () => {
      const start = rotate();
      const base = { windowStartedAt: new Date(start).toISOString(), windowSeconds: windowSec, attribution: "client_supplied" };
      if (!configured) return { ...base, scope: "current_process", campaigns: localRows(), storage: status() };
      const result = await enqueue(() => client.eval(READ_SCRIPT, ids.length * 2, ...ids.flatMap(id => keys(id, start))));
      if (result.ok && Array.isArray(result.value) && result.value.length === ids.length * (FIELDS.length + 1)) {
        const values = result.value.map(Number);
        if (values.every(value => Number.isSafeInteger(value) && value >= 0)) {
          lastReadAt = new Date(time()).toISOString();
          const campaigns = ids.map((id, index) => ({ id,
            ...Object.fromEntries(FIELDS.map((field, offset) => [field, values[index * (FIELDS.length + 1) + offset]])),
            distinctSourcesEstimate: values[index * (FIELDS.length + 1) + FIELDS.length], distinctSourcesSaturated: false }));
          return { ...base, scope: "redis", campaigns, storage: status() };
        }
      }
      if (result.ok) lastError = "invalid_data";
      const campaigns = localRows();
      return { ...base, windowStartedAt: new Date(localStart).toISOString(), scope: "unavailable", campaigns, storage: status() };
    })().finally(() => { snapshotPromise = null; });
    return snapshotPromise;
  }
  async function close() {
    closing = true;
    cancelQueued("unavailable");
    if (active && !active.timedOut) {
      clearTimeout(active.timer);
      active.timedOut = true;
      if (active.observation) uncertainObservations += 1;
      active.resolve({ ok: false, reason: "unavailable" });
    }
    localDedupe.clear();
    return true;
  }
  return { recordRequest, recordConversion, getSnapshot, getStatus: status, close };
}

module.exports = createCampaignRiskStore;
