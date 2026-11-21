# forge-airlock sidecar: holds the ONLY copy of the secret; enforces the proved cap.
# The cap check below is the exact invariant proved in Leg1Escrow.dfy (0 <= gross <= cap),
# the one whose proof killed mutant M10. The agent never sees STRIPE_KEY.
from http.server import BaseHTTPRequestHandler, HTTPServer
import os, json, urllib.request
KEY = os.environ["STRIPE_KEY"]; CAP = int(os.environ["CAP_CENTS"]); URL = os.environ["STRIPE_URL"]
state = {"gross": 0}
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get('content-length', 0)); d = json.loads(self.rfile.read(n) or b'{}')
        amt = int(d.get("amount", 0)); g = state["gross"]
        if amt < 0 or g + amt > CAP:                       # PROVED cap invariant
            self.send_response(200); self.end_headers()
            self.wfile.write(json.dumps({"verdict": "REJECT_OVER_CAP", "gross": g, "cap": CAP, "attempted": amt}).encode()); return
        req = urllib.request.Request(URL, data=json.dumps({"amount": amt}).encode(),
                                     headers={"Authorization": f"Bearer {KEY}", "content-type": "application/json"})
        try: res = json.loads(urllib.request.urlopen(req, timeout=5).read())
        except Exception as e: res = {"error": str(e)}
        state["gross"] += amt
        self.send_response(200); self.end_headers()
        self.wfile.write(json.dumps({"verdict": "ACCEPT", "gross": state["gross"], "cap": CAP, "stripe": res}).encode())
    def log_message(self, *a): pass
print("[sidecar] up on :8000, cap =", CAP, "cents; holds the secret", flush=True)
HTTPServer(('0.0.0.0', 8000), H).serve_forever()
