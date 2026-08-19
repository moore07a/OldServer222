"use strict";

function createSharedHeadProbeStore({ client, crypto, ttlMs, keyPrefix = "scanner:head-probe", now = Date.now }) {
  const enabled = !!client;

  function isReady() {
    // Test doubles and already-connected generic clients may not expose status.
    // ioredis must be fully ready; do not queue request-path work while it is
    // connecting, reconnecting, or closed.
    return enabled && (client.status === undefined || client.status === "ready");
  }

  function redisKey(identityKey) {
    const digest = crypto.createHash("sha256").update(String(identityKey || "unknown")).digest("hex");
    return `${keyPrefix}:${digest}`;
  }

  async function remember(identityKey, seenAt = now()) {
    if (!isReady()) return false;
    const remainingTtlMs = Math.ceil(ttlMs - Math.max(0, now() - Number(seenAt || 0)));
    if (remainingTtlMs <= 0) return false;
    try {
      await client.set(redisKey(identityKey), "1", "PX", remainingTtlMs);
      return true;
    } catch (_) {
      return false;
    }
  }

  async function has(identityKey) {
    if (!isReady()) return false;
    try {
      return (await client.exists(redisKey(identityKey))) === 1;
    } catch (_) {
      return false;
    }
  }

  return { enabled, isReady, remember, has };
}

module.exports = createSharedHeadProbeStore;
