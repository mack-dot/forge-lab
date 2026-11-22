# Stands in for the paid API (Stripe, x402, ...): charges only with the right key, and keeps a ledger of
# what it really charged, so the audit can compare it with the logs.
import json, os, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
KEY = os.environ["EXPECTED_KEY"]
LEDGER, LOCK = [], threading.Lock()
class H(BaseHTTPRequestHandler):
    def reply(self, code, obj):
        b = json.dumps(obj).encode(); self.send_response(code); self.send_header("content-length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("content-length", 0)))
        if self.headers.get("authorization", "") != f"Bearer {KEY}":
            return self.reply(401, {"error": "bad key"})
        d = json.loads(body or b"{}")
        with LOCK:
            LEDGER.append({"agent": d.get("agent"), "tool": d.get("tool"), "amount": d.get("amount"), "step_id": d.get("step_id")})
        return self.reply(200, {"charged_cents": d.get("amount"), "ok": True})
    def do_GET(self):
        with LOCK:
            return self.reply(200, {"charges": LEDGER})
    def log_message(self, *a): pass
print("[upstream-mock] up on :9000", flush=True)
ThreadingHTTPServer(("0.0.0.0", 9000), H).serve_forever()
