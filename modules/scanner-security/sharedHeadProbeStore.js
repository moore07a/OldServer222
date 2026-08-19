"use strict";

function createSharedHeadProbeStore({ client, crypto, ttlMs, keyPrefix = "scanner:head-probe" }) {
  const enabled = !!client;

  function redisKey(identityKey) {
    const digest = crypto.createHash("sha256").update(String(identityKey || "unknown")).digest("hex");
    return `${keyPrefix}:${digest}`;
  }

  async function remember(identityKey) {
    if (!enabled) return false;
    try {
      await client.set(redisKey(identityKey), "1", "PX", ttlMs);
      return true;
    } catch (_) {
      return false;
    }
  }

  async function has(identityKey) {
    if (!enabled) return false;
    try {
      return (await client.exists(redisKey(identityKey))) === 1;
    } catch (_) {
      return false;
    }
  }

  return { enabled, remember, has };
}

module.exports = createSharedHeadProbeStore;
