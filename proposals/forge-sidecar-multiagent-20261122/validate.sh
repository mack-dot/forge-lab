#!/bin/sh
# Runs the whole demo from a clean state and exits 0 only if every audit passes.
# 1. three agents race against their own caps and the swarm cap; 2. audit; 3. restart the sidecar;
# 4. it must reload and re-verify its logs; 5. one more spend over the coder's cap must be refused; 6. audit again.
set -u
cd "$(dirname "$0")"
P=forgemulti
dc() { docker compose -p "$P" "$@"; }
dc down -v --remove-orphans >/dev/null 2>&1
dc up -d --build upstream sidecar agent-support agent-research agent-coder || exit 2
dc wait agent-support agent-research agent-coder >/dev/null
echo "=== agents ==="; dc logs --no-log-prefix agent-support agent-research agent-coder
echo "=== audit 1 ==="; dc run --rm auditor; a1=$?
echo "=== restart the sidecar ==="; dc restart sidecar >/dev/null; sleep 4
dc logs --no-log-prefix sidecar | grep -E "reloaded|refusing" | tail -4
echo "=== after restart ==="; dc run --rm agent-coder python /app/x.py one-more
echo "=== audit 2 ==="; dc run --rm auditor; a2=$?
dc down -v --remove-orphans >/dev/null 2>&1
echo "RESULT: audit1=$a1 audit2=$a2"
[ "$a1" = 0 ] && [ "$a2" = 0 ]
