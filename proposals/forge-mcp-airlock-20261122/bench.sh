#!/usr/bin/env bash
# bench.sh - measure the airlock's per-call overhead (policies/bench.yaml), from a clean state.
# Writes ${1:-results/latest}/bench.json and a table. Exit 0 if both runs completed.
set -u
cd "$(dirname "$0")"
OUT="${1:-results/latest}"
mkdir -p "$OUT"
export FORGE_DOMAIN=bench FORGE_PHASE=1
dc() { docker compose -p forgeair-bench -f docker-compose.yml "$@"; }
dc --profile bench down -v --remove-orphans >/dev/null 2>&1
dc up -d --wait airlock mock-http >"$OUT/bench-up.log" 2>&1 || { echo "bench: airlock did not start"; exit 2; }
dc run --rm agent-bench >"$OUT/bench-proxy.log" 2>&1; rp=$?
dc run --rm bench-direct >"$OUT/bench-direct.log" 2>&1; rd=$?
dc logs --no-log-prefix airlock >"$OUT/bench-airlock.log" 2>&1
dc --profile bench down -v --remove-orphans >/dev/null 2>&1
[ "$rp" = 0 ] && [ "$rd" = 0 ] || { echo "bench: proxy=$rp direct=$rd"; exit 1; }
python3 - "$OUT" <<'EOF'
import json, sys
out = sys.argv[1]
def res(f):
    for line in open(f"{out}/{f}"):
        if "[bench] RESULT " in line:
            return json.loads(line.split("[bench] RESULT ", 1)[1])
p, d = res("bench-proxy.log"), res("bench-direct.log")
rows = []
for k, label in (("fs_read", "read_text_file (real fs server, stdio), allowed pass-through"),
                 ("http_pass", "get_status (mock HTTP), allowed pass-through"),
                 ("http_gate", "charge amount=1 (mock HTTP), gated by the compiled verifier")):
    rows.append({"call": label, "n": p[k]["n"], "direct_median_ms": d[k]["median_ms"], "direct_p95_ms": d[k]["p95_ms"],
                 "proxy_median_ms": p[k]["median_ms"], "proxy_p95_ms": p[k]["p95_ms"],
                 "overhead_median_ms": round(p[k]["median_ms"] - d[k]["median_ms"], 2),
                 "overhead_p95_ms": round(p[k]["p95_ms"] - d[k]["p95_ms"], 2)})
json.dump({"proxy": p, "direct": d, "rows": rows}, open(f"{out}/bench.json", "w"), indent=1)
print("| call | n | direct median / p95 (ms) | via airlock median / p95 (ms) | overhead median / p95 (ms) |")
print("| --- | --- | --- | --- | --- |")
for r in rows:
    print(f"| {r['call']} | {r['n']} | {r['direct_median_ms']} / {r['direct_p95_ms']} | {r['proxy_median_ms']} / "
          f"{r['proxy_p95_ms']} | {r['overhead_median_ms']} / {r['overhead_p95_ms']} |")
EOF
