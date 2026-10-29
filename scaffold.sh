#!/usr/bin/env bash
# Creates the Cyrberus repository layout. Safe to re-run: it only
# adds missing directories and never overwrites an existing file.
set -euo pipefail

for d in docs/reports common head sentinel warden ui tests deploy/clamd.conf.d; do
    mkdir -p "$d"
done

# .gitkeep so empty directories survive the first commit
for d in docs/reports warden deploy/clamd.conf.d; do
    [ -z "$(ls -A "$d" 2>/dev/null)" ] && touch "$d/.gitkeep"
done

cat > head/requirements.txt <<'REQ'
pyudev>=0.24
cryptography>=41.0
psutil>=5.9
REQ

echo "Layout created:"
find . -type d -not -path './.git*' | sort | sed 's|^\./||;s|[^/]*/|  |g'
