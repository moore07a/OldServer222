"use strict";

const { isIP } = require("node:net");

const FLAG_NAMES = ["hosting", "vpn", "proxy", "residentialProxy"];

function publicIpv4(value) {
  const octets = value.split(".").map(Number);
  const [a, b, c] = octets;
  if (
    a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && (b === 168 || (b === 0 && (c === 0 || c === 2)) || (b === 88 && c === 99))) ||
    (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
    (a === 203 && b === 0 && c === 113)
  ) return null;
  return octets.join(".");
}

function publicAddress(value) {
  if (typeof value !== "string" || value.length > 128 || /[\x00-\x1f\x7f%]/.test(value)) return null;
  let address = value.trim();
  const version = isIP(address);
  if (version === 4) return publicIpv4(address);
  if (version !== 6) return null;

  // Expand a validated IPv6 address, including its optional dotted IPv4 tail.
  if (address.includes(".")) {
    const lastColon = address.lastIndexOf(":");
    const [a, b, c, d] = address.slice(lastColon + 1).split(".").map(Number);
    address = `${address.slice(0, lastColon + 1)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const halves = address.toLowerCase().split("::");
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length > 1 && halves[1] ? halves[1].split(":") : [];
  const words = [...left, ...Array(8 - left.length - right.length).fill("0"), ...right].map(word => parseInt(word, 16));
  if (words.slice(0, 5).every(word => word === 0) && words[5] === 0xffff) {
    return publicIpv4(`${words[6] >> 8}.${words[6] & 255}.${words[7] >> 8}.${words[7] & 255}`);
  }

  // Intelligence is optional: conservatively skip non-global, special-purpose,
  // documentation and transition addresses instead of querying them externally.
  // In particular, do not unwrap NAT64, translated IPv4, 6to4 or Teredo addresses.
  if (
    (words[0] & 0xe000) !== 0x2000 ||
    (words[0] === 0x2001 && (words[1] < 0x0200 || words[1] === 0x0db8)) ||
    words[0] === 0x2002 || words[0] === 0x3ffe ||
    (words[0] === 0x3fff && words[1] < 0x1000)
  ) return null;
  return words.map(word => word.toString(16).padStart(4, "0")).join(":");
}

function integer(value, fallback, maximum = Number.MAX_SAFE_INTEGER) {
  return Number.isFinite(value) && value >= 1 ? Math.min(Math.floor(value), maximum) : fallback;
}

function createIpIntelligenceCache({
  lookup = null, enabled = false, maxEntries = 2048, ttlMs = 3600000,
  negativeTtlMs = 60000, maxQueue = 64, concurrency = 2, timeoutMs = 800,
  now = Date.now, setTimeout: setTimer = setTimeout, clearTimeout: clearTimer = clearTimeout
} = {}) {
  const configured = typeof lookup === "function";
  const usable = Boolean(enabled && configured);
  const limits = {
    maxEntries: integer(maxEntries, 2048), ttlMs: integer(ttlMs, 3600000),
    negativeTtlMs: integer(negativeTtlMs, 60000), maxQueue: integer(maxQueue, 64),
    concurrency: integer(concurrency, 2, 2), timeoutMs: integer(timeoutMs, 800, 2147483647)
  };
  const counters = {
    cacheHits: 0, negativeCacheHits: 0, lookups: 0, failed: 0, timeouts: 0, unknownResponses: 0,
    queueDropped: 0, deduplicated: 0, skipped: 0, expired: 0, evicted: 0, cancelled: 0
  };
  const cache = new Map();
  const jobs = new Map();
  const activeJobs = new Set();
  const queue = [];
  let closed = false;
  let scheduled = false;
  let lastError = null;
  let lastUnknownReason = null;

  function empty(state) {
    return { state, hosting: null, vpn: null, proxy: null, residentialProxy: null, source: null };
  }

  function cachedResult(value) {
    return { ...value.result };
  }

  function writeCache(ip, result, duration) {
    if (closed) return;
    cache.delete(ip);
    if (cache.size >= limits.maxEntries) {
      cache.delete(cache.keys().next().value);
      counters.evicted += 1;
    }
    cache.set(ip, { result, expiresAt: now() + duration });
  }

  function clearDeadline(job) {
    if (job.timer !== null) clearTimer(job.timer);
    job.timer = null;
  }

  function fail(job, code) {
    if (closed || job.timedOut) return;
    counters.failed += 1;
    lastError = code;
    lastUnknownReason = null;
    writeCache(job.ip, empty("unknown"), limits.negativeTtlMs);
  }

  function finish(job) {
    clearDeadline(job);
    activeJobs.delete(job);
    if (jobs.get(job.ip) === job) jobs.delete(job.ip);
    schedule();
  }

  async function run(job) {
    try {
      const value = await lookup(job.ip, { signal: job.controller.signal });
      if (closed || job.timedOut) return;
      const explicitUnknown = value && typeof value === "object" && !Array.isArray(value) && value.state === "unknown"
        && value.reason === "indicators_unavailable" && FLAG_NAMES.every(name => value[name] == null);
      if (!value || typeof value !== "object" || Array.isArray(value)
        || (value.state === "unknown" && !explicitUnknown)
        || (!explicitUnknown && !FLAG_NAMES.some(name => typeof value[name] === "boolean"))) {
        fail(job, "invalid_response");
        return;
      }
      const result = empty(explicitUnknown ? "unknown" : "known");
      for (const name of FLAG_NAMES) result[name] = typeof value[name] === "boolean" ? value[name] : null;
      result.source = typeof value.source === "string" && /^[A-Za-z][A-Za-z0-9_.-]{0,39}$/.test(value.source) ? value.source : null;
      writeCache(job.ip, result, explicitUnknown ? limits.negativeTtlMs : limits.ttlMs);
      lastError = null;
      lastUnknownReason = explicitUnknown ? "indicators_unavailable" : null;
      if (explicitUnknown) counters.unknownResponses += 1;
    } catch (_) {
      fail(job, "lookup_failed");
    } finally {
      // Aborting an injected lookup cannot prove it stopped. Keep this slot
      // occupied until its original promise settles, even after our timeout.
      finish(job);
    }
  }

  function dispatch() {
    scheduled = false;
    if (closed) return;
    while (queue.length && activeJobs.size < limits.concurrency) {
      const job = queue.shift();
      activeJobs.add(job);
      counters.lookups += 1;
      job.controller = new AbortController();
      job.timer = setTimer(() => {
        clearDeadline(job);
        if (closed) return;
        fail(job, "lookup_timeout");
        job.timedOut = true;
        counters.timeouts += 1;
        job.controller.abort();
      }, limits.timeoutMs);
      job.timer?.unref?.();
      void run(job);
    }
  }

  function schedule() {
    if (closed || scheduled || !queue.length || activeJobs.size >= limits.concurrency) return;
    scheduled = true;
    queueMicrotask(dispatch);
  }

  function observe(ip) {
    if (!usable || closed) return empty("disabled");
    const address = publicAddress(ip);
    if (!address) {
      counters.skipped += 1;
      return empty("unknown");
    }
    const entry = cache.get(address);
    if (entry && entry.expiresAt > now()) {
      counters.cacheHits += 1;
      if (entry.result.state === "unknown") counters.negativeCacheHits += 1;
      // Refresh recency without extending the original TTL.
      cache.delete(address);
      cache.set(address, entry);
      return cachedResult(entry);
    }
    if (entry) { cache.delete(address); counters.expired += 1; }
    const existing = jobs.get(address);
    if (existing) {
      counters.deduplicated += 1;
      return empty(existing.timedOut ? "unknown" : "pending");
    }
    if (queue.length >= limits.maxQueue) {
      counters.queueDropped += 1;
      lastError = "queue_full";
      return empty("unknown");
    }
    const job = { ip: address, controller: null, timer: null, timedOut: false };
    jobs.set(address, job);
    queue.push(job);
    schedule();
    return empty("pending");
  }

  function getStatus() {
    const at = now();
    for (const [ip, entry] of cache) {
      if (entry.expiresAt <= at) { cache.delete(ip); counters.expired += 1; }
    }
    return {
      enabled: usable, configured, closed, ...counters, active: activeJobs.size,
      queued: queue.length, cacheEntries: cache.size, lastError, lastUnknownReason, limits: { ...limits }
    };
  }

  function close() {
    if (closed) return;
    closed = true;
    counters.cancelled += jobs.size;
    queue.length = 0;
    jobs.clear();
    cache.clear();
    for (const job of activeJobs) {
      clearDeadline(job);
      job.controller.abort();
    }
  }

  return { observe, getStatus, close };
}

module.exports = createIpIntelligenceCache;
