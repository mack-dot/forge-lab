# forge-airlock sidecar, multi-agent: one budget log per agent plus one shared swarm log.
#
# Every spend is appended, as a tentative 128-byte record, to TWO escrow logs: the agent's own and the
# swarm's. The compiled, PROVED Leg-1 Dafny verifier (leg1_cli.py) checks each log in full. The real API
# key is used only if BOTH verdicts are ACCEPT. One lock serializes every spend, so parallel requests
# cannot both see the same balance.
#
# Labels (do not round up):
#   PROVED (in the Dafny model): the verifier's verdict on one log: gross never exceeds that log's cap,
#     conservation, no duplicate step id, dense sequence, expiry.
#   NATIVE CHECK (this file, not proved): the record encoder; bearer-token lookup; the tool allow-list;
#     the call limit; the rule "a spend is accepted only if it is accepted in BOTH logs" and "both logs get
#     the same spend"; persistence and reload; forwarding.
import hashlib
import json
import os
import subprocess
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.environ.get("DATA_DIR", "/data")
UPSTREAM_KEY = os.environ["UPSTREAM_KEY"]
UPSTREAM_URL = os.environ["UPSTREAM_URL"]
POLICY = json.load(open(os.environ.get("POLICY_FILE", "/policy/policy.json")))
A_PUB, B_PUB = os.path.join(HERE, "a.pub"), os.path.join(HERE, "b.pub")
U64_MAX = (1 << 64) - 1
MONEY_MAX = (1 << 63) - 1


# --- encoder: SPEC.md 128-byte layout, same as the #93 sidecar (NATIVE CHECK) ---
def u64(v): return int(v & U64_MAX).to_bytes(8, "little")
def sha(b): return hashlib.sha256(b).digest()


KEY_A, KEY_B = open(A_PUB, "rb").read(), open(B_PUB, "rb").read()
_gm = open(os.path.join(HERE, "accept_genesis_only.manifest.bin"), "rb").read()
SPEC_HASH, ESCROW_ID = _gm[96:128], _gm[128:160]


def manifest_bytes(deal_id, cap, exp): return deal_id + KEY_A + KEY_B + SPEC_HASH + ESCROW_ID + u64(cap) + u64(exp)


def genesis(cap, exp, man):
    body = b"FV2" + bytes([2, 2, 0x47]) + b"\x00\x00" + u64(0) + b"\x00" * 32 + u64(cap) + u64(exp) + sha(man)
    return body + sha(body)


def step(step_id, amount, gross, ts, prev, seq):
    body = (b"FV2" + bytes([2, 2, 0x53]) + b"\x00\x00" + u64(seq) + sha(prev) + step_id + u64(amount)
            + u64(gross) + u64(ts) + b"\x00" * 8)
    return body + sha(body)


def field(record, start): return int.from_bytes(record[start:start + 8], "little")


class Log:
    """One escrow log on disk: <name>.bin (records) and <name>.manifest.bin."""

    def __init__(self, name, cap, expires_at):
        self.name, self.cap = name, cap
        self.wal = os.path.join(DATA, name + ".bin")
        self.man = os.path.join(DATA, name + ".manifest.bin")
        if os.path.exists(self.wal):
            self.manifest = open(self.man, "rb").read()
            raw = open(self.wal, "rb").read()
            self.records = [raw[i:i + 128] for i in range(0, len(raw), 128)]
            self.expires_at = field(self.manifest, 168)
            last_ts = field(self.records[-1], 80) if len(self.records) > 1 else 0
            v = self.verdict(self.records, max(last_ts, 1))
            if v.get("verdict") != "ACCEPT":  # fail closed: a log that does not verify is never extended
                raise SystemExit(f"[sidecar] {name}: stored log does not verify ({v}); refusing to start")
            print(f"[sidecar] {name}: reloaded {len(self.records) - 1} steps, gross={self.gross()}, re-verified ACCEPT",
                  flush=True)
        else:
            self.expires_at = expires_at
            self.manifest = manifest_bytes(sha(b"forge-agent-log:" + name.encode()), cap, expires_at)
            self.records = [genesis(cap, expires_at, self.manifest)]
            open(self.man, "wb").write(self.manifest)
            self.persist(self.records)

    def gross(self): return field(self.records[-1], 72) if len(self.records) > 1 else 0
    def steps(self): return len(self.records) - 1
    def last_ts(self): return field(self.records[-1], 80) if len(self.records) > 1 else 0

    def persist(self, records):
        tmp = self.wal + ".tmp"
        with open(tmp, "wb") as f:
            f.write(b"".join(records))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.wal)

    def tentative(self, step_id, amount, now):
        return step(step_id, amount, self.gross() + amount, max(now, self.last_ts()), self.records[-1], len(self.records))

    def verdict(self, records, observed_now):
        """The PROVED verifier's verdict on the whole log (via the unproved CLI glue)."""
        path = self.wal + ".check"
        open(path, "wb").write(b"".join(records))
        r = subprocess.run(["python3", "-I", os.path.join(HERE, "leg1_cli.py"), path, "--manifest", self.man,
                            "--pubkeys", f"{A_PUB},{B_PUB}", "--observed-now", str(observed_now), "--json"],
                           capture_output=True, text=True)
        for line in reversed(r.stdout.splitlines()):
            if line.strip().startswith("{"):
                return json.loads(line)
        return {"verdict": "UNVERIFIABLE_INTERNAL", "err": r.stderr[:200]}


START = int(time.time())
os.makedirs(DATA, exist_ok=True)
SWARM = Log("swarm", POLICY["swarm_cap_cents"], START + POLICY.get("swarm_expires_in_s", 86400))
AGENTS = {}  # token -> {name, log, tools, max_calls}
for token, a in POLICY["agents"].items():
    AGENTS[token] = {"name": a["name"], "log": Log("agent-" + a["name"], a["cap_cents"], START + a["expires_in_s"]),
                     "tools": set(a["tools"]), "max_calls": a["max_calls"]}
LOCK = threading.Lock()  # one writer: every spend is decided and recorded under this lock


class Handler(BaseHTTPRequestHandler):
    def reply(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path != "/audit" or self.headers.get("x-forge-admin") != POLICY["admin_token"]:
            return self.reply(404, {"error": "not found"})
        with LOCK:
            now = max(int(time.time()), 1)
            out = {"swarm": {"cap": SWARM.cap, "gross": SWARM.gross(), "steps": SWARM.steps(),
                             "proved_verdict": SWARM.verdict(SWARM.records, max(SWARM.last_ts(), 1))["verdict"]},
                   "agents": {}}
            for a in AGENTS.values():
                log = a["log"]
                out["agents"][a["name"]] = {
                    "cap": log.cap, "gross": log.gross(), "steps": log.steps(), "max_calls": a["max_calls"],
                    "expires_in_s": log.expires_at - now,
                    "proved_verdict": log.verdict(log.records, max(log.last_ts(), 1))["verdict"]}
        return self.reply(200, out)

    def do_POST(self):
        if self.path != "/spend":
            return self.reply(404, {"error": "not found"})
        auth = self.headers.get("authorization", "")
        agent = AGENTS.get(auth[7:]) if auth.startswith("Bearer ") else None
        if not agent:
            return self.reply(401, {"verdict": "UNKNOWN_AGENT"})
        try:
            req = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))) or b"{}")
            amount, tool = req["amount"], req["tool"]
        except (ValueError, KeyError, TypeError):
            return self.reply(400, {"verdict": "BAD_REQUEST"})
        name, log = agent["name"], agent["log"]
        # NATIVE CHECKS (not proved): input shape, tool allow-list, call limit.
        if type(amount) is not int or not 0 < amount <= MONEY_MAX:
            return self.reply(200, {"agent": name, "verdict": "BAD_AMOUNT", "gate": "NATIVE CHECK"})
        if tool not in agent["tools"]:
            return self.reply(200, {"agent": name, "verdict": "TOOL_NOT_ALLOWED", "tool": tool, "gate": "NATIVE CHECK"})
        with LOCK:
            if log.steps() >= agent["max_calls"]:
                return self.reply(200, {"agent": name, "verdict": "CALL_LIMIT", "gate": "NATIVE CHECK"})
            now = int(time.time())
            step_id = hashlib.sha256(f"{name}:{log.steps() + 1}:{SWARM.steps() + 1}".encode()).digest()[:16]
            t_agent = log.tentative(step_id, amount, now)
            t_swarm = SWARM.tentative(step_id, amount, now)
            # The PROVED verifier decides each budget; both must accept.
            va = log.verdict(log.records + [t_agent], now)["verdict"]
            vs = SWARM.verdict(SWARM.records + [t_swarm], now)["verdict"] if va == "ACCEPT" else "NOT_RUN"
            if va != "ACCEPT" or vs != "ACCEPT":
                return self.reply(200, {"agent": name, "verdict": "REFUSED", "agent_log": va, "swarm_log": vs,
                                        "gross": log.gross(), "cap": log.cap, "swarm_gross": SWARM.gross(),
                                        "gate": "PROVED Leg 1 (Dafny), both logs"})
            # Record first (fsync), then use the key: a crash after this point can only under-pay, never
            # spend past a cap. (The upstream call itself is not idempotent here: NATIVE CHECK.)
            log.records.append(t_agent)
            log.persist(log.records)
            SWARM.records.append(t_swarm)
            SWARM.persist(SWARM.records)
            gross, swarm_gross = log.gross(), SWARM.gross()
        try:
            r = urllib.request.Request(UPSTREAM_URL, data=json.dumps(
                {"amount": amount, "tool": tool, "agent": name, "step_id": step_id.hex()}).encode(),
                headers={"Authorization": f"Bearer {UPSTREAM_KEY}", "content-type": "application/json"})
            upstream = json.loads(urllib.request.urlopen(r, timeout=5).read())
        except Exception as e:  # noqa: BLE001
            upstream = {"error": str(e)[:120]}
        return self.reply(200, {"agent": name, "verdict": "ACCEPT", "gross": gross, "cap": log.cap,
                                "swarm_gross": swarm_gross, "swarm_cap": SWARM.cap, "upstream": upstream,
                                "gate": "PROVED Leg 1 (Dafny), both logs"})

    def log_message(self, *a): pass


print(f"[sidecar] up; {len(AGENTS)} agents; swarm cap={SWARM.cap}; gate = PROVED Leg-1 verifier on two logs per spend",
      flush=True)
class Server(ThreadingHTTPServer):
    request_queue_size = 256  # the default of 5 drops connections under a burst instead of deciding them
    daemon_threads = True


Server(("0.0.0.0", 8000), Handler).serve_forever()
