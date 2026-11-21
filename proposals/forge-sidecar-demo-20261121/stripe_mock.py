# Stands in for Stripe: only charges if the correct secret key is presented.
from http.server import BaseHTTPRequestHandler, HTTPServer
import os, json
KEY = os.environ["EXPECTED_KEY"]
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get('content-length', 0)); body = self.rfile.read(n)
        if self.headers.get('authorization', '') != f'Bearer {KEY}':
            self.send_response(401); self.end_headers(); self.wfile.write(b'{"error":"bad key"}'); return
        d = json.loads(body or b'{}')
        self.send_response(200); self.end_headers()
        self.wfile.write(json.dumps({"charged_cents": d.get("amount"), "ok": True}).encode())
    def log_message(self, *a): pass
print("[stripe-mock] up on :9000", flush=True)
HTTPServer(('0.0.0.0', 9000), H).serve_forever()
