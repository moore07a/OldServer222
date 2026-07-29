#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-http://127.0.0.1:${PORT:-8080}}"
DURATION_SECONDS="${DURATION_SECONDS:-120}"
CONCURRENCY="${CONCURRENCY:-20}"

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 1
fi

end_ts=$(( $(date +%s) + DURATION_SECONDS ))
active=0
tmp_results="$(mktemp)"
cleanup() {
  rm -f "$tmp_results"
}
trap cleanup EXIT

hit() {
  local path="$1"
  local code
  code=$(curl -sS -o /dev/null -w "%{http_code}" "${BASE_URL}${path}" || echo "000")
  printf '%s\n' "$code" >> "$tmp_results"
}

paths=("/" "/status" "/pricing" "/docs" "/contact")
while [[ $(date +%s) -lt $end_ts ]]; do
  for p in "${paths[@]}"; do
    hit "$p" &
    active=$((active+1))
    if [[ $active -ge $CONCURRENCY ]]; then
      wait -n || true
      active=$((active-1))
    fi
  done
done
wait || true

success=0
fail=0
while IFS= read -r code; do
  if [[ "$code" =~ ^[234] ]]; then
    success=$((success+1))
  else
    fail=$((fail+1))
  fi
done < "$tmp_results"

echo "soak complete base_url=${BASE_URL} duration=${DURATION_SECONDS}s concurrency=${CONCURRENCY} success=${success} fail=${fail}"
