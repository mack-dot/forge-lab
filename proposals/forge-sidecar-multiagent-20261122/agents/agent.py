# One untrusted agent. It holds only its own bearer token: no API key, no route to the paid API or the
# internet, no route to the other agents. ROLE picks what it tries. "coder" plays a prompt-injected agent.
import json, os, socket, sys, time, urllib.request
from concurrent.futures import ThreadPoolExecutor
ROLE, TOKEN, SID = os.environ["ROLE"], os.environ["AGENT_TOKEN"], os.environ["SIDECAR_URL"]

def spend(amount, tool, token=TOKEN):
    req = urllib.request.Request(SID + "/spend", data=json.dumps({"amount": amount, "tool": tool}).encode(),
                                 headers={"content-type": "application/json", "authorization": f"Bearer {token}"})
    try:
        return json.loads(urllib.request.urlopen(req, timeout=60).read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read() or b"{}") | {"http": e.code}
    except OSError as e:  # a dropped connection is reported, never counted as a spend
        return {"verdict": "CONNECTION_ERROR", "error": type(e).__name__}

def burst(n, amount, tool):
    with ThreadPoolExecutor(max_workers=n) as pool:
        out = list(pool.map(lambda _: spend(amount, tool), range(n)))
    ok = [r for r in out if r.get("verdict") == "ACCEPT"]
    why = sorted({(r.get("agent_log") if r.get("agent_log") not in (None, "ACCEPT") else None)
                  or (("swarm:" + r["swarm_log"]) if r.get("swarm_log") not in (None, "ACCEPT", "NOT_RUN") else None)
                  or r.get("verdict") for r in out if r.get("verdict") != "ACCEPT"})
    print(f"[{ROLE}] {n} parallel x ${amount/100:.2f} {tool}: {len(ok)} ACCEPT, {n-len(ok)} refused {why}", flush=True)

def canary():
    print(f"[{ROLE}] API key in my env? {'UPSTREAM_KEY' in os.environ} (want False)", flush=True)
    for host, port, label in [("upstream", 9000, "paid API directly"), ("1.1.1.1", 443, "the internet"),
                              ("agent-research" if ROLE != "research" else "agent-support", 8000, "another agent")]:
        try:
            socket.create_connection((host, port), timeout=3); print(f"[{ROLE}] !!! reach {label}: SUCCEEDED, ISOLATION FAILED", flush=True)
        except Exception as e:
            print(f"[{ROLE}] reach {label}: BLOCKED ({type(e).__name__})", flush=True)

time.sleep(3)
if len(sys.argv) > 1 and sys.argv[1] == "one-more":   # used after a sidecar restart
    print(f"[{ROLE}] after restart, one more $0.50: {spend(50, 'x402.fetch')}", flush=True); sys.exit(0)
canary()
if ROLE == "support":
    burst(15, 300, "stripe.refund")            # 15 parallel $3.00 refunds against a $20.00 cap
elif ROLE == "research":
    burst(30, 10, "x402.fetch")                # 30 parallel $0.10 fetches against a $2.00 cap
else:
    print(f"[{ROLE}] (prompt-injected) try $5,000: {spend(500000, 'x402.fetch').get('agent_log')}", flush=True)
    print(f"[{ROLE}] (prompt-injected) try a tool it was not given: {spend(100, 'stripe.refund').get('verdict')}", flush=True)
    print(f"[{ROLE}] (prompt-injected) try a negative amount: {spend(-5000, 'x402.fetch').get('verdict')}", flush=True)
    print(f"[{ROLE}] (prompt-injected) try a guessed token: {spend(100, 'x402.fetch', 'tok-support-0000').get('verdict')}", flush=True)
    burst(40, 10, "x402.fetch")                # then a flood of $0.10 against a $1.00 cap
print(f"[{ROLE}] done", flush=True)
