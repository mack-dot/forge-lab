#!/usr/bin/env bash
# prove_airlock.sh - the one-command proof. From a fresh clone (Docker required):
#   ./prove_airlock.sh [out_dir]
# 1. validate.sh: four domains (codebase, visible, quota, concurrency), each from a clean
#    state with only a different forge.yaml, plus planted-breach controls, restart,
#    tamper, second-writer and invalid-policy cases. Every case has an expected exit code.
# 2. bench.sh: per-call overhead (median and p95 over 120 calls) against direct upstream calls.
# 3. No container or volume of this demo is left behind.
# Exit 0 only if all three hold. Label: FINITE TEST (container tier; shares the host kernel).
set -u
cd "$(dirname "$0")"
OUT="${1:-results/latest}"
mkdir -p "$OUT"
T=$SECONDS
echo "prove_airlock: commit $(git rev-parse --short HEAD 2>/dev/null || echo unknown), docker $(docker version --format '{{.Server.Version}}' 2>/dev/null)" | tee "$OUT/prove.txt"
./validate.sh "$OUT"; v=$?
./bench.sh "$OUT" | tee "$OUT/bench.md"; b=${PIPESTATUS[0]}
left=$(docker ps -a -q --filter "name=forgeair-" | wc -l | tr -d ' ')
vols=$(docker volume ls -q --filter "name=forgeair-" | wc -l | tr -d ' ')
nets=$(docker network ls -q --filter "name=forgeair-" | wc -l | tr -d ' ')
c=1; [ "$left$vols$nets" = 000 ] && c=0
echo "prove_airlock: validate=$v bench=$b cleanup=$c (containers=$left volumes=$vols networks=$nets) total=$((SECONDS-T))s" | tee -a "$OUT/prove.txt"
[ "$v" = 0 ] && [ "$b" = 0 ] && [ "$c" = 0 ]
