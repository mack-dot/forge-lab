# mock_http_mcp.py - MOCK upstream MCP server over HTTP (JSON-RPC POST /mcp, JSON response).
# Stands in for a paid or privileged service (deploys, database, payments). It demands a
# FAKE bearer key that only the airlock holds, and it keeps a ledger of every call it
# executed in /mockdata/ledger.jsonl so the validator can count real side effects.
# No real service, no real key. NATIVE CHECK, demo quality.
import json
import os
import signal
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

KEY = os.environ["EXPECTED_KEY"]
LEDGER = os.environ.get("LEDGER", "/mockdata/ledger.jsonl")
LOCK = threading.Lock()


def S(props, req=()):
    return {"type": "object", "properties": {k: {"type": t} for k, t in props.items()}, "required": list(req)}


TOOLS = [
    {"name": "get_status", "description": "Read service status", "inputSchema": S({"service": "string"})},
    {"name": "deploy", "description": "Deploy a branch to an environment",
     "inputSchema": S({"env": "string", "branch": "string", "request_id": "string"}, ["env", "branch"])},
    {"name": "drop_database", "description": "Destroy a database", "inputSchema": S({"name": "string"})},
    {"name": "rotate_keys", "description": "Rotate the service keys", "inputSchema": S({})},
    {"name": "run_query", "description": "Run a SQL query", "inputSchema": S({"query": "string", "rows": "integer"})},
    {"name": "slow_job", "description": "A job that takes `seconds`", "inputSchema": S({"seconds": "integer"})},
    {"name": "charge", "description": "Charge an amount in cents",
     "inputSchema": S({"amount": "integer", "invoice_id": "string"}, ["amount", "invoice_id"])},
]


def record(entry):
    with LOCK:
        with open(LEDGER, "a") as f:
            f.write(json.dumps(dict(entry, ts=time.time())) + "\n")
            f.flush()
            os.fsync(f.fileno())


def call(name, a):
    if name == "slow_job":
        time.sleep(int(a.get("seconds", 1)))
    record({"tool": name, "args": a})
    return {"content": [{"type": "text", "text": f"(mock) {name} done: {json.dumps(a, sort_keys=True)}"}],
            "isError": False}


class H(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _authed(self):
        return self.headers.get("authorization") == f"Bearer {KEY}"

    def do_GET(self):
        if self.path == "/ledger" and self._authed():
            rows = [json.loads(x) for x in open(LEDGER)] if os.path.exists(LEDGER) else []
            return self._send(200, {"rows": rows})
        return self._send(401 if not self._authed() else 404, {"error": "no"})

    def do_POST(self):
        if not self._authed():
            return self._send(401, {"error": "missing or wrong key"})
        msg = json.loads(self.rfile.read(int(self.headers.get("content-length") or 0)) or b"{}")
        mid, method, p = msg.get("id"), msg.get("method"), msg.get("params") or {}
        if mid is None:
            self.send_response(202)
            self.send_header("content-length", "0")
            self.end_headers()
            return
        if method == "initialize":
            res = {"protocolVersion": p.get("protocolVersion", "2025-06-18"), "capabilities": {"tools": {}},
                   "serverInfo": {"name": "mock-http", "version": "0"}}
        elif method == "tools/list":
            res = {"tools": TOOLS}
        elif method == "tools/call" and p.get("name") in {t["name"] for t in TOOLS}:
            res = call(p["name"], p.get("arguments") or {})
        else:
            return self._send(200, {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "unknown"}})
        self._send(200, {"jsonrpc": "2.0", "id": mid, "result": res})

    def log_message(self, *a):
        pass


class Srv(ThreadingHTTPServer):
    request_queue_size = 256
    daemon_threads = True


signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
os.makedirs(os.path.dirname(LEDGER), exist_ok=True)
print("[mock-http] up on :9100 (FAKE key required)", flush=True)
Srv(("0.0.0.0", 9100), H).serve_forever()
