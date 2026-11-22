# forge-airlock sidecar: the gate is the ACTUAL PROVED Leg-1 verifier.
# Every spend is appended to a real .bin escrow WAL and run through the compiled
# Dafny verifier (leg1_cli.py -> Verifier.VerifyCLI) BEFORE the API key is used.
# The cap/conservation decision is the proved core's verdict, not a reimplementation.
import os, json, subprocess, hashlib, urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
HERE = os.path.dirname(os.path.abspath(__file__))
KEY = os.environ["STRIPE_KEY"]; CAP = int(os.environ["CAP_CENTS"]); URL = os.environ["STRIPE_URL"]
A_PUB, B_PUB = os.path.join(HERE, "a.pub"), os.path.join(HERE, "b.pub")
WAL, MAN = "/tmp/wal.bin", "/tmp/manifest.bin"
OBSERVED_NOW, EXPIRES = 1700000500, 4100000000
# --- encoder: SPEC.md 128-byte layout (validated byte-for-byte in gen_corpus.py) ---
def u64(v): return int(v & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
def sha(b): return hashlib.sha256(b).digest()
KEY_A, KEY_B = open(A_PUB, "rb").read(), open(B_PUB, "rb").read()
_gm = open(os.path.join(HERE, "accept_genesis_only.manifest.bin"), "rb").read()
DEAL_ID, SPEC_HASH, ESCROW_ID = _gm[0:32], _gm[96:128], _gm[128:160]
def manifest_bytes(cap, exp): return DEAL_ID + KEY_A + KEY_B + SPEC_HASH + ESCROW_ID + u64(cap) + u64(exp)
def genesis(cap, exp, man):
    body = b"FV2" + bytes([2, 2, 0x47]) + b"\x00\x00" + u64(0) + b"\x00"*32 + u64(cap) + u64(exp) + sha(man)
    return body + sha(body)
def step(step_id, seller, gross, ts, prev, seq):
    body = b"FV2" + bytes([2, 2, 0x53]) + b"\x00\x00" + u64(seq) + sha(prev) + step_id + u64(seller) + u64(gross) + u64(ts) + b"\x00"*8
    return body + sha(body)
MANIFEST = manifest_bytes(CAP, EXPIRES); open(MAN, "wb").write(MANIFEST)
RECORDS = [genesis(CAP, EXPIRES, MANIFEST)]
S = {"gross": 0, "seq": 1, "step": 1}
def proved_verdict(records):
    open(WAL, "wb").write(b"".join(records))
    r = subprocess.run(["python3", "-I", os.path.join(HERE, "leg1_cli.py"), WAL,
                        "--manifest", MAN, "--pubkeys", f"{A_PUB},{B_PUB}",
                        "--observed-now", str(OBSERVED_NOW), "--json"], capture_output=True, text=True)
    for line in reversed(r.stdout.splitlines()):
        if line.strip().startswith("{"):
            return json.loads(line)
    return {"verdict": "UNVERIFIABLE_INTERNAL", "err": r.stderr[:200]}
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get('content-length', 0)); amt = int(json.loads(self.rfile.read(n) or b'{}').get("amount", 0))
        tentative = step(S["step"].to_bytes(16, "little"), amt, S["gross"] + amt, OBSERVED_NOW, RECORDS[-1], S["seq"])
        verdict = proved_verdict(RECORDS + [tentative])   # <-- the PROVED verifier decides
        v = verdict["verdict"]
        if v == "ACCEPT":
            RECORDS.append(tentative); S["gross"] += amt; S["seq"] += 1; S["step"] += 1
            try:
                req = urllib.request.Request(URL, data=json.dumps({"amount": amt}).encode(),
                                             headers={"Authorization": f"Bearer {KEY}", "content-type": "application/json"})
                stripe = json.loads(urllib.request.urlopen(req, timeout=5).read())
            except Exception as e: stripe = {"error": str(e)}
            out = {"verdict": v, "gross": S["gross"], "cap": CAP, "stripe": stripe, "gate": "PROVED Leg 1 (Dafny)"}
        else:
            out = {"verdict": v, "gross": S["gross"], "cap": CAP, "gate": "PROVED Leg 1 (Dafny)"}  # refused: key never used
        self.send_response(200); self.end_headers(); self.wfile.write(json.dumps(out).encode())
    def log_message(self, *a): pass
print(f"[sidecar] up; gate = PROVED Leg-1 Dafny verifier on a real .bin WAL; cap={CAP}", flush=True)
HTTPServer(('0.0.0.0', 8000), H).serve_forever()
