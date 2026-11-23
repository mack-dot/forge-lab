# bench.py - per-call latency of the airlock compared with calling the upstream directly.
#   bench.py proxy   (in the agent container, after the canary): calls go agent -> airlock -> upstream
#   bench.py direct  (in a bench container on the upstream network): calls go straight to the upstream
# Calls, measured N times each after 5 warm-up calls:
#   fs_read   read_text_file src/ui.ts on the REAL @modelcontextprotocol/server-filesystem (stdio)
#   http_pass get_status on the mock HTTP upstream (allowed pass-through)
#   http_gate charge amount=1 on the mock HTTP upstream (gated: compiled verifier on the whole log)
# Direct fs_read runs a private copy of the same server over stdio (no HTTP hop); direct HTTP
# uses the same JSON-RPC client code as the airlock. Prints one JSON line. FINITE TEST.
import json
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
N = int(os.environ.get("BENCH_N", "120"))
FS = "/opt/mcpfs/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js"


def stats(xs):
    xs = sorted(xs)
    p95 = xs[max(0, int(round(0.95 * len(xs))) - 1)]
    return {"n": len(xs), "median_ms": round(statistics.median(xs) * 1000, 2), "p95_ms": round(p95 * 1000, 2),
            "max_ms": round(xs[-1] * 1000, 2)}


def run(fn, n=N):
    for _ in range(5):
        fn()
    out = []
    for _ in range(n):
        t = time.perf_counter()
        fn()
        out.append(time.perf_counter() - t)
    return stats(out)


def proxy():
    import mcpc

    def ok(r):
        if not r[0]:
            raise SystemExit(f"bench call failed: {r}")

    res = {"fs_read": run(lambda: ok(mcpc.call("read_text_file", path="src/ui.ts"))),
           "http_pass": run(lambda: ok(mcpc.call("get_status", service="web"))),
           "http_gate": run(lambda: ok(mcpc.call("charge", amount=1, invoice_id=os.urandom(8).hex())))}
    return res


def direct():
    sys.path.insert(0, "/forge/airlock")
    import mcp_client
    key = os.environ["BENCH_UPSTREAM_KEY"]
    fs, _ = mcp_client.connect({"name": "fs", "transport": "stdio", "command": ["node", FS, "/ws"]})
    http, _ = mcp_client.connect({"name": "ops", "transport": "http", "url": "http://mock-http:9100/mcp",
                                  "headers": {"Authorization": f"Bearer {key}"}})

    def c(up, name, args):
        r = up.request("tools/call", {"name": name, "arguments": args})
        if r.get("isError"):
            raise SystemExit(f"direct call failed: {r}")

    return {"fs_read": run(lambda: c(fs, "read_text_file", {"path": "/ws/src/ui.ts"})),
            "http_pass": run(lambda: c(http, "get_status", {"service": "web"})),
            "http_gate": run(lambda: c(http, "charge", {"amount": 1, "invoice_id": os.urandom(8).hex()}))}


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "proxy"
    print("[bench] RESULT " + json.dumps({"mode": mode, **(proxy() if mode == "proxy" else direct())}), flush=True)
