function parseMinHourToMs(v, fallbackMs, defaultUnit = "m") {
  const str = String(v || "").trim().toLowerCase();
  if (!str) return fallbackMs;
  const match = str.match(/^(\d+(?:\.\d+)?)\s*(ms|s|m|h)?$/);
  if (!match) return fallbackMs;
  const value = Number(match[1]);
  if (!Number.isFinite(value) || value <= 0) return fallbackMs;
  const unit = match[2] || defaultUnit;
  const multiplier = unit === "h" ? 3600000 : unit === "m" ? 60000 : unit === "s" ? 1000 : 1;
  return Math.floor(value * multiplier);
}

module.exports = parseMinHourToMs;
