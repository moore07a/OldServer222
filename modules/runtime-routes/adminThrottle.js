const adminHits = new Map();
const ADMIN_HIT_TTL_MS = 10 * 60_000;
const ADMIN_HIT_WINDOW_MS = 60_000;

function pruneAdminHits(now = Date.now()) {
  for (const [ip, rec] of adminHits.entries()) {
    const resetAt = Number(rec && rec.resetAt || 0);
    if (!resetAt || now - resetAt > ADMIN_HIT_TTL_MS) {
      adminHits.delete(ip);
    }
  }
}

module.exports = { adminHits, ADMIN_HIT_TTL_MS, ADMIN_HIT_WINDOW_MS, pruneAdminHits };
