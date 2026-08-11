const DEFAULT_MAX_TIMER_MS = 2_147_483_647;

function readMaxTimerMsEnv(name = "MAX_TIMER_MS", fallbackMs = DEFAULT_MAX_TIMER_MS) {
  const raw = process.env[name];
  if (raw == null || raw === "") return fallbackMs;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed < 1) return fallbackMs;
  return Math.min(DEFAULT_MAX_TIMER_MS, Math.trunc(parsed));
}

const MAX_TIMER_MS = readMaxTimerMsEnv();

function clampMs(value, minMs = 0, maxMs = MAX_TIMER_MS) {
  return Math.min(maxMs, Math.max(minMs, value));
}

function readMsEnv(name, defaultMs, minMs = 1000, maxMs = MAX_TIMER_MS) {
  // A caller's operational minimum must win over a lower global timer cap.
  // Otherwise a misconfigured MAX_TIMER_MS can turn guarded background loops
  // into near-zero intervals. The JavaScript timer ceiling remains absolute.
  const safeMinMs = clampMs(minMs, 0, DEFAULT_MAX_TIMER_MS);
  const safeMaxMs = clampMs(Math.max(safeMinMs, maxMs), safeMinMs, DEFAULT_MAX_TIMER_MS);
  const raw = process.env[name];
  const normalizedRaw = typeof raw === "string" ? raw.trim() : raw;
  if (normalizedRaw == null || normalizedRaw === "") {
    return clampMs(defaultMs, safeMinMs, safeMaxMs);
  }
  const parsed = Number(normalizedRaw);
  const safe = Number.isFinite(parsed) ? Math.trunc(parsed) : defaultMs;
  return clampMs(safe, safeMinMs, safeMaxMs);
}

function readPositiveIntEnv(name, fallback) {
  const raw = process.env[name];
  if (raw == null || raw === "") return fallback;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed)) return fallback;
  const value = Math.trunc(parsed);
  if (value < 1) return fallback;
  return value;
}

function evictOldestMapEntry(map) {
  if (!map || map.size <= 0) return false;
  const oldest = map.keys().next();
  if (!oldest || oldest.done) return false;
  return map.delete(oldest.value);
}

function boundedMapSet(map, key, value, maxEntries) {
  const cap = Number(maxEntries);
  if (!map || !Number.isFinite(cap) || cap < 1) {
    map.set(key, value);
    return map;
  }

  if (map.has(key)) {
    map.delete(key);
  } else {
    while (map.size >= cap) {
      if (!evictOldestMapEntry(map)) break;
    }
  }

  map.set(key, value);
  while (map.size > cap) {
    if (!evictOldestMapEntry(map)) break;
  }
  return map;
}

module.exports = {
  DEFAULT_MAX_TIMER_MS,
  MAX_TIMER_MS,
  readMaxTimerMsEnv,
  clampMs,
  readMsEnv,
  readPositiveIntEnv,
  evictOldestMapEntry,
  boundedMapSet
};
