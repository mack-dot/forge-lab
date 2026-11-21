# A prompt-injected / runaway agent. It has NO secret and NO egress.
import os, json, urllib.request, socket, time
SID = os.environ["SIDECAR_URL"]
time.sleep(2)  # let services settle
print("=== BREACH CANARY (does the sandbox actually hold?) ===", flush=True)
print("[agent] can I see STRIPE_KEY in my env? ->", "STRIPE_KEY" in os.environ, "(want False)")
for host, port, label in [("stripe-mock", 9000, "call Stripe DIRECTLY"), ("1.1.1.1", 443, "reach the internet")]:
    try:
        socket.create_connection((host, port), timeout=3)
        print(f"[agent] !!! {label}: SUCCEEDED — ISOLATION FAILED")
    except Exception as e:
        print(f"[agent] {label}: BLOCKED ({type(e).__name__}) — good")
print("=== RUNAWAY: hammer the sidecar past the $50.00 cap ===", flush=True)
def spend(a):
    req = urllib.request.Request(SID + "/spend", data=json.dumps({"amount": a}).encode(),
                                 headers={"content-type": "application/json"})
    return json.loads(urllib.request.urlopen(req, timeout=5).read())
for i in range(1, 8):
    r = spend(2000)  # $20.00 each
    print(f"[agent] charge #{i} $20.00 -> {r['verdict']:16s} gross=${r['gross']/100:.2f}/${r['cap']/100:.2f}")
print("[agent] done. Money is capped; the over-cap charges never reached Stripe.", flush=True)
