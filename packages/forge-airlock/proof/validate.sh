#!/usr/bin/env bash
# validate.sh - run the three domains through the SAME airlock image, each from a clean
# state (docker compose down -v), with only a different forge.yaml. Exit 0 only if every
# check below has its expected exit code. Logs go to ${1:-results/latest}/.
# Label: FINITE TEST. Container tier: the agent shares the host kernel.
set -u
cd "$(dirname "$0")"
OUT="${1:-results/latest}"
mkdir -p "$OUT"
: > "$OUT/summary.txt"
FAIL=0
T_ALL=$SECONDS

rec() {  # rec <check> <actual> <expected> <seconds>
  local mark=ok
  [ "$2" = "$3" ] || { mark=FAIL; FAIL=1; }
  printf '%-4s %-62s exit=%-3s expect=%-3s %4ss\n' "$mark" "$1" "$2" "$3" "$4" | tee -a "$OUT/summary.txt"
}

dc() { docker compose -p "forgeair-$DOM" -f docker-compose.yml ${OVR:+-f "$OVR"} "$@"; }

json_check() {  # json_check <file> <python expression over d>
  python3 -c "import json,sys; d=json.loads(open(sys.argv[1]).read().strip().splitlines()[-1]); sys.exit(0 if ($2) else 1)" "$1"
}

restart_airlock() { dc restart airlock >/dev/null 2>&1; dc up -d --wait airlock >/dev/null 2>&1; }

echo "== build (one image for every domain)"
t=$SECONDS; docker compose -p forgeair-build build -q >"$OUT/build.log" 2>&1; rec "image build" $? 0 $((SECONDS-t))

for DOM in codebase visible quota concurrency; do
  export FORGE_DOMAIN=$DOM FORGE_PHASE=1
  OVR="$OUT/compose.mounts.$DOM.yml"
  docker run --rm -v "$PWD/policies:/p:ro" forge-airlock-proof:local \
    python3 -I /forge/airlock/render_mounts.py "/p/$DOM.yaml" >"$OVR"
  echo "== domain $DOM (forge.yaml = policies/$DOM.yaml)"
  dc --profile controls down -v --remove-orphans >/dev/null 2>&1
  t=$SECONDS
  dc up --exit-code-from agent agent airlock mock-http >"$OUT/$DOM-up.log" 2>&1
  rec "$DOM: docker compose up (canary + scenario phase 1)" $? 0 $((SECONDS-t))
  grep -E "\[canary\] (PASS|BREACH)|\[agent\] .*ok, " "$OUT/$DOM-up.log" | sed 's/^/     /'

  if [ "$DOM" = codebase ]; then
    for c in control-env-secret control-hidden-mount control-root-writes; do
      t=$SECONDS; restart_airlock
      dc run --rm "$c" >"$OUT/$DOM-$c.log" 2>&1
      rec "$DOM: planted breach $c -> canary BREACH" $? 10 $((SECONDS-t))
      grep -E "\[canary\] BREACH:" "$OUT/$DOM-$c.log" | head -3 | sed 's/^/     /'
    done
    t=$SECONDS
    dc run --rm --no-deps agent python3 -I /forge/agent/lockdown_probe.py >"$OUT/$DOM-lockdown.log" 2>&1
    rec "$DOM: after BREACH an allowed read is refused (lockdown)" $? 0 $((SECONDS-t))
    t=$SECONDS
    dc logs --no-log-prefix airlock >"$OUT/$DOM-airlock.log" 2>&1
    n=$(grep -c "workspace: re-verified" "$OUT/$DOM-airlock.log")
    [ "$n" -ge 3 ]; rec "$DOM: workspace re-verified on each of 3 restarts (count=$n)" $? 0 $((SECONDS-t))
  fi

  if [ "$DOM" = quota ]; then
    t=$SECONDS; dc up -d --wait mock-http airlock >/dev/null 2>&1 && dc restart airlock >/dev/null 2>&1 \
      && dc up -d --wait airlock >/dev/null 2>&1
    rec "quota: docker compose restart airlock (same log volume)" $? 0 $((SECONDS-t))
    dc logs --no-log-prefix airlock 2>&1 | grep -E "reloaded" | sed 's/^/     /'
    t=$SECONDS; FORGE_PHASE=2 dc run --rm agent >"$OUT/$DOM-phase2.log" 2>&1
    rec "quota: phase 2 after restart (caps kept)" $? 0 $((SECONDS-t))
    grep -E "\[agent\] .*ok, " "$OUT/$DOM-phase2.log" | sed 's/^/     /'
    sleep 3  # the two timed-out slow_job calls finish upstream after 4 s
    t=$SECONDS; dc exec -T airlock python3 -I /forge/airlock/audit.py http://mock-http:9100/ledger >"$OUT/$DOM-audit.json" 2>&1
    rec "quota: audit (every log re-verifies ACCEPT, gross <= cap)" $? 0 $((SECONDS-t))
    json_check "$OUT/$DOM-audit.json" "d['logs']['deploy']['gross']==3 and d['logs']['run_query']['gross']==1000 and d['logs']['slow_job']['gross']==2 and d['logs']['slow_job']['journal_final_states']=={'ABORTED':2} and d['upstream_ledger']['deploy']['calls']==3 and d['upstream_ledger']['run_query']['sum']['rows']==1000 and 'drop_database' not in d['upstream_ledger'] and 'rotate_keys' not in d['upstream_ledger']"
    rec "quota: audit numbers (3 deploys, 1000 rows, 2 aborted, 0 denied calls upstream)" $? 0 0
    t=$SECONDS; restart_airlock
    dc run --rm control-egress >"$OUT/$DOM-control-egress.log" 2>&1
    rec "quota: planted breach control-egress (agent on upstream net) -> BREACH" $? 10 $((SECONDS-t))
    grep -E "\[canary\] BREACH:" "$OUT/$DOM-control-egress.log" | head -3 | sed 's/^/     /'
    t=$SECONDS; dc run --rm --no-deps airlock >"$OUT/$DOM-second-writer.log" 2>&1; rc=$?
    grep -q "another airlock holds the data volume lock" "$OUT/$DOM-second-writer.log" || rc="$rc/no-reason"
    rec "quota: second airlock on the same log volume refuses to start" "$rc" 2 $((SECONDS-t))
    dc stop airlock >/dev/null 2>&1  # the live airlock holds the lock; stop it for the next cases
    for case in "unknown-key:unknown keys" "allow-and-deny:both denied and allowed" \
                "tool-not-offered:offered by 0 matching upstreams" "cap-changed:stored cap 3 != policy cap 4"; do
      bad=${case%%:*}; why=${case#*:}; t=$SECONDS
      dc run --rm --no-deps -e FORGE_POLICY=/forge/invalid/$bad.yaml -v "$PWD/policies/invalid:/forge/invalid:ro" \
        airlock >"$OUT/$DOM-invalid-$bad.log" 2>&1; rc=$?
      grep -q "$why" "$OUT/$DOM-invalid-$bad.log" || rc="$rc/no-reason"
      rec "quota: invalid policy $bad -> refuses to start" "$rc" 2 $((SECONDS-t))
    done
    t=$SECONDS
    # flip one bit of the gross field of step 2; the tamper itself must succeed, else the case fails
    if dc run --rm --no-deps --entrypoint python3 airlock -c "import os,sys; p='/data/deploy.bin'; sys.exit(9) if os.path.getsize(p) < 3*128 else None; f=open(p,'r+b'); f.seek(128*2+72); b=f.read(1); f.seek(128*2+72); f.write(bytes([b[0]^1])); f.close()" >/dev/null 2>&1; then
      dc run --rm --no-deps airlock >"$OUT/$DOM-tampered.log" 2>&1; rc=$?
      grep -q "stored log does not verify" "$OUT/$DOM-tampered.log" || rc="$rc/no-reason"
    else
      rc="tamper-not-applied"
    fi
    rec "quota: one flipped log byte -> airlock refuses to start" "$rc" 2 $((SECONDS-t))
    grep -E "FATAL" "$OUT/$DOM-tampered.log" | sed 's/^/     /'
  fi

  if [ "$DOM" = concurrency ]; then
    t=$SECONDS; dc up -d --wait mock-http airlock >/dev/null 2>&1
    dc exec -T airlock python3 -I /forge/airlock/audit.py http://mock-http:9100/ledger >"$OUT/$DOM-audit.json" 2>&1
    rec "concurrency: audit (every log re-verifies ACCEPT, gross <= cap)" $? 0 $((SECONDS-t))
    json_check "$OUT/$DOM-audit.json" "d['logs']['charge']['gross']==1000 and d['logs']['deploy']['gross']==5 and d['upstream_ledger']['charge']['calls']==14 and d['upstream_ledger']['charge']['sum']['amount']==1000 and d['upstream_duplicate_invoice_ids']==0 and d['upstream_ledger']['deploy']['calls']==5"
    rec "concurrency: audit numbers (sum 1000, 14 charges, 0 duplicate ids, 5 deploys)" $? 0 0
  fi

  dc logs --no-log-prefix airlock >"$OUT/$DOM-airlock.log" 2>&1
  dc --profile controls down -v --remove-orphans >/dev/null 2>&1
done

echo "== total $((SECONDS-T_ALL))s" | tee -a "$OUT/summary.txt"
left=$(docker ps -a --filter "name=forgeair-" -q | wc -l | tr -d ' ')
vols=$(docker volume ls -q --filter "name=forgeair-" | wc -l | tr -d ' ')
[ "$left" = 0 ] && [ "$vols" = 0 ]; rec "cleanup: 0 containers and 0 volumes left (c=$left v=$vols)" $? 0 0
[ "$FAIL" = 0 ] && echo "VALIDATE: PASS" | tee -a "$OUT/summary.txt" || echo "VALIDATE: FAIL" | tee -a "$OUT/summary.txt"
exit "$FAIL"
