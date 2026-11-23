# Trusted test harness (not part of the product): waits for the agents, then compares the sidecar's logs
# (each re-verified by the PROVED verifier) with what the paid API really charged. Exit 0 only if every
# invariant holds.
import json, os, sys, time, urllib.request
SID, UP, ADMIN = os.environ["SIDECAR_URL"], os.environ["UPSTREAM_URL"], os.environ["ADMIN_TOKEN"]
POLICY = json.load(open("/policy/policy.json"))
def get(url, headers=None):
    return json.loads(urllib.request.urlopen(urllib.request.Request(url, headers=headers or {}), timeout=120).read())
time.sleep(float(os.environ.get("WAIT_S", "45")))
audit = get(SID + "/audit", {"x-forge-admin": ADMIN}); charges = get(UP)["charges"]
fails = []
def check(ok, text):
    print(("PASS " if ok else "FAIL ") + text, flush=True)
    if not ok: fails.append(text)
caps = {a["name"]: a for a in POLICY["agents"].values()}
total = 0
for name, a in audit["agents"].items():
    paid = sum(c["amount"] for c in charges if c["agent"] == name)
    total += a["gross"]
    print(f"     {name:9s} gross ${a['gross']/100:6.2f} / cap ${a['cap']/100:6.2f}  steps {a['steps']:3d}  charged upstream ${paid/100:6.2f}", flush=True)
    check(a["gross"] <= a["cap"], f"{name}: gross <= its own cap")
    check(a["steps"] <= a["max_calls"], f"{name}: calls <= its call limit (NATIVE CHECK)")
    check(a["proved_verdict"] == "ACCEPT", f"{name}: its log re-verifies ACCEPT with the proved verifier")
    check(paid == a["gross"], f"{name}: charged upstream == its log's gross")
    check(all(c["tool"] in caps[name]["tools"] for c in charges if c["agent"] == name), f"{name}: only allowed tools reached upstream")
s = audit["swarm"]
print(f"     swarm     gross ${s['gross']/100:6.2f} / cap ${s['cap']/100:6.2f}  steps {s['steps']:3d}  charged upstream ${sum(c['amount'] for c in charges)/100:6.2f}", flush=True)
check(s["gross"] <= s["cap"], "swarm: total gross <= swarm cap")
check(s["proved_verdict"] == "ACCEPT", "swarm: its log re-verifies ACCEPT with the proved verifier")
check(total == s["gross"], "swarm gross == sum of the agents' gross (NATIVE CHECK: both logs got every spend)")
check(sum(c["amount"] for c in charges) == s["gross"], "total charged upstream == swarm gross")
check(len(charges) == s["steps"], "every upstream charge has exactly one swarm log step")
print(f"AUDIT {'PASSED' if not fails else 'FAILED'}: {len(fails)} failure(s)", flush=True)
sys.exit(1 if fails else 0)
