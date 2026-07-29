#!/usr/bin/env bash
set -euo pipefail

if [[ -f package.json ]]; then
  exec npm start
fi

# Fallback: if build context wraps this app in a single subdirectory, enter it.
candidate=""
while IFS= read -r p; do
  if [[ -z "$candidate" ]]; then
    candidate="$p"
  else
    candidate=""
    break
  fi
done < <(find . -mindepth 2 -maxdepth 2 -type f -name package.json | sed 's#^\./##' | sed 's#/package.json$##')

if [[ -n "$candidate" && -f "$candidate/package.json" ]]; then
  cd "$candidate"
  exec npm start
fi

echo "[start.sh] package.json not found in current directory or single nested app directory." >&2
exit 1
