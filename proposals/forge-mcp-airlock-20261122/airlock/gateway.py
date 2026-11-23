# gateway.py - the Forge MCP airlock.
#
# The agent talks MCP (JSON-RPC 2.0 over HTTP POST /mcp, JSON responses) to this
# process only. This process holds every upstream credential, applies forge.yaml
# (default deny), runs bounded-state gates through the compiled #91 verifier, and
# refuses every forwardable call until the startup breach canary has reported PASS.
#
# Labels: PROVED = only the verifier's cap/replay/expiry verdict on one log (about the
# Dafny model). Everything in this file is NATIVE CHECK (hand-written, not proved).
import fcntl
import hashlib
import json
import os
import signal
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mcp_client  # noqa: E402
import workspace  # noqa: E402
from gatelog import GateLog, GateError  # noqa: E402
from policy import Policy, PolicyError, Refusal, canonical_json, MONEY_MAX  # noqa: E402

POLICY_FILE = os.environ.get("FORGE_POLICY", "/forge/forge.yaml")
DATA = os.environ.get("FORGE_DATA", "/data")
STATE = os.environ.get("FORGE_STATE", "/state")
SOURCE = os.environ.get("FORGE_SOURCE", "/state/source")
PORT = int(os.environ.get("FORGE_PORT", "8700"))
ERR = -32001  # JSON-RPC server error code used for every FORGE_* refusal


def die(msg):
    print(f"[airlock] FATAL (fail closed): {msg}", flush=True)
    sys.exit(2)


class Airlock:
    def __init__(self):
        try:
            self.policy = Policy.load(POLICY_FILE)
        except (PolicyError, OSError) as e:
            die(f"policy: {e}")
        os.makedirs(DATA, exist_ok=True)
        os.chmod(DATA, 0o700)
        # one airlock per data volume: a second writer refuses to start
        self._owner = os.open(os.path.join(DATA, ".airlock.lock"), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(self._owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            die("another airlock holds the data volume lock")
        if os.environ.get("FORGE_DEMO_FIXTURES"):
            import make_source_repo
            make_source_repo.build(os.environ["FORGE_DEMO_FIXTURES"], SOURCE)
        try:
            self.ws = workspace.prepare(self.policy, SOURCE, STATE, self.policy.mcp_root)
        except (workspace.WorkspaceError, OSError) as e:
            die(f"workspace: {e}")
        self.logs = {}
        try:
            for name, (cap, ein, eat) in self.policy.logs.items():
                self.logs[name] = GateLog(DATA, name, cap, ein, eat)
        except (GateError, OSError) as e:
            die(f"gate log: {e}")
        self.upstreams, self.route, self.upstream_tools = {}, {}, {}
        for name, spec in self.policy.upstreams.items():
            try:
                up, tools = mcp_client.connect(spec)
            except Exception as e:  # noqa: BLE001
                die(f"upstream {name}: {e}")
            self.upstreams[name] = up
            self.upstream_tools[name] = {t["name"]: t for t in tools}
        for tp in self.policy.tools.values():
            owners = [u for u, ts in self.upstream_tools.items() if tp.name in ts
                      and (tp.upstream is None or tp.upstream == u)]
            if len(owners) != 1:
                die(f"policy tool {tp.name!r}: offered by {len(owners)} matching upstreams (need exactly 1)")
            self.route[tp.name] = owners[0]
        self.canary = "PENDING"  # PENDING -> PASSED | BREACH ; one report per airlock lifetime
        self.canary_lock = threading.Lock()
        self.canary_report = None
        print(f"[airlock] up on :{PORT}; {len(self.route)} tools exposed; {len(self.logs)} gate logs; "
              f"{sum(len(t) for t in self.upstream_tools.values())} upstream tools seen; canary PENDING", flush=True)

    # ------------------------------------------------------------ MCP methods
    def tools_list(self):
        out = []
        for name in sorted(self.route):
            t = dict(self.upstream_tools[self.route[name]][name])
            tp = self.policy.tools[name]
            if tp.gated:
                t["description"] = (t.get("description", "") + f" [forge gate: log={tp.log} unit={tp.unit} "
                                    f"cap={tp.cap}]").strip()
            out.append(t)
        return {"tools": out}

    def tools_call(self, params):
        name, args = params.get("name"), params.get("arguments") or {}
        if self.canary == "BREACH":
            raise Refusal("FORGE_BREACH_LOCKDOWN", "startup canary found a breach; airlock refuses every call")
        tp, fwd = self.policy.check_call(name, args)  # deny / unlisted / arg rules / paths
        if tp.gated:
            amount = self._amount(tp, args)
            step_id = self._step_id(tp, args)
            self._run_checker(tp, name, args)
        if self.canary != "PASSED":
            raise Refusal("FORGE_CANARY_PENDING", "startup canary has not passed; nothing is forwarded yet")
        up = self.upstreams[self.route[name]]
        if not tp.gated:
            try:
                return up.request("tools/call", {"name": name, "arguments": fwd})
            except mcp_client.UpstreamError as e:
                raise Refusal("FORGE_UPSTREAM_FAILED", str(e)) from None
        log = self.logs[tp.log]
        meta = {"tool": name, "args_sha256": hashlib.sha256(canonical_json(args).encode()).hexdigest()}
        verdict, seq, gross = log.reserve(amount, step_id, meta)
        if verdict != "ACCEPT":
            raise Refusal("FORGE_GATE_REFUSED", f"gate {tp.log}: verifier verdict {verdict}",
                          verdict=verdict, log=tp.log, gross=gross, cap=tp.cap)
        try:
            res = up.request("tools/call", {"name": name, "arguments": fwd})
        except mcp_client.UpstreamError as e:
            log.finish(seq, False, str(e))
            raise Refusal("FORGE_UPSTREAM_FAILED", f"{e}; the gate step stays spent (seq {seq})",
                          log=tp.log, seq=seq) from None
        log.finish(seq, not (isinstance(res, dict) and res.get("isError")))
        res = dict(res or {})
        res["_meta"] = {"forge": {"log": tp.log, "seq": seq, "gross": gross, "cap": tp.cap, "verdict": verdict}}
        return res

    def _amount(self, tp, args):
        if tp.unit == "count":
            amount = 1
        else:
            amount = args.get(tp.value_field)
            if type(amount) is not int or not 0 <= amount <= MONEY_MAX:
                raise Refusal("FORGE_ARG_REFUSED", f"{tp.value_field!r} must be an integer in [0, 2^63-1]")
        if tp.per_call_max is not None and amount > tp.per_call_max:
            raise Refusal("FORGE_GATE_REFUSED", f"{tp.value_field or 'units'}={amount} > per_call_max "
                          f"{tp.per_call_max}", verdict="PER_CALL_MAX", log=tp.log)
        return amount

    def _step_id(self, tp, args):
        if tp.id_field:
            if tp.id_field not in args or args[tp.id_field] in ("", None):
                raise Refusal("FORGE_ARG_REFUSED", f"id field {tp.id_field!r} is required by the gate")
            return hashlib.sha256(b"forge-step:" + tp.log.encode() + b":" +
                                  canonical_json(args[tp.id_field]).encode()).digest()[:16]
        return hashlib.sha256(b"forge-step-rand:" + os.urandom(32)).digest()[:16]

    def _run_checker(self, tp, name, args):
        if not tp.checker:
            return
        payload = canonical_json({"tool": name, "arguments": args}).encode()
        try:
            r = subprocess.run(tp.checker["command"], input=payload, capture_output=True,
                               timeout=tp.checker.get("timeout_s", 10), env={"PATH": "/usr/bin:/bin:/usr/local/bin"})
            code = r.returncode
            why = r.stderr.decode(errors="replace")[-200:]
        except (OSError, subprocess.TimeoutExpired) as e:
            code, why = -1, str(e)[:200]
        if code != 0:
            raise Refusal("FORGE_CHECKER_REFUSED", f"checker exit {code}: {why.strip()}", exit_code=code)

    # ------------------------------------------------------------ canary
    def canary_plan(self):
        """Probe plan for the startup canary. Served only while the canary is PENDING."""
        unlisted = sorted({t for ts in self.upstream_tools.values() for t in ts} - set(self.route))
        reads = [n for n, tp in self.policy.tools.items() if "read" in tp.path_args.values()]
        writes = [n for n, tp in self.policy.tools.items() if "write" in tp.path_args.values()]
        revs = [n for n, tp in self.policy.tools.items() if "git_revpath" in tp.path_args.values()]
        return {
            "agent_root": self.policy.agent_root,
            "fingerprints": self.ws["fingerprints"],
            "secret_fps": [workspace.fp(s.encode()) for s in self.policy.secrets()],
            "hidden_names": self.ws["hidden_names"],
            "readonly_files": self.ws.get("readonly_files", [])[:8],
            "closed_dirs": self.ws.get("closed_dirs", [])[:8],
            "airlock_paths": [STATE, SOURCE, DATA, POLICY_FILE, self.policy.mcp_root,
                              os.environ.get("FORGE_DEMO_FIXTURES", "/forge-fixtures")],
            "egress_targets": self.policy.egress_targets + self._upstream_hostports(),
            "deny": self.policy.deny,
            "unlisted": unlisted + ["forge_canary_no_such_tool"],
            "mcp_read": [(n, [k for k, m in self.policy.tools[n].path_args.items() if m == "read"][0]) for n in reads],
            "mcp_write": [(n, [k for k, m in self.policy.tools[n].path_args.items() if m == "write"][0])
                          for n in writes],
            "mcp_rev": [(n, [k for k, m in self.policy.tools[n].path_args.items() if m == "git_revpath"][0])
                        for n in revs],
        }

    def _upstream_hostports(self):
        out = []
        for u in self.policy.upstreams.values():
            if u["transport"] == "http":
                hp = u["url"].split("//", 1)[1].split("/", 1)[0]
                out.append(hp if ":" in hp else hp + ":80")
        return out


class Handler(BaseHTTPRequestHandler):
    A = None

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("content-length") or 0)
        if n > (1 << 20):
            raise ValueError("body too large")
        return json.loads(self.rfile.read(n) or b"null")

    def do_GET(self):
        A = self.A
        if self.path == "/healthz":
            return self._send(200, {"ok": True, "canary": A.canary})
        if self.path == "/forge/canary/plan":
            with A.canary_lock:
                if A.canary != "PENDING":
                    return self._send(404, {"error": "canary window closed"})
                return self._send(200, A.canary_plan())
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        A = self.A
        if self.path == "/forge/canary/report":
            try:
                rep = self._body()
            except ValueError:
                return self._send(400, {"error": "bad body"})
            with A.canary_lock:
                if A.canary != "PENDING":
                    return self._send(409, {"error": "canary already reported", "state": A.canary})
                ok = isinstance(rep, dict) and rep.get("result") == "PASS" and not rep.get("breaches")
                A.canary = "PASSED" if ok else "BREACH"
                A.canary_report = rep
            print(f"[airlock] canary report: {A.canary}; breaches={json.dumps((rep or {}).get('breaches'))[:600]}",
                  flush=True)
            return self._send(200, {"state": A.canary})
        if self.path != "/mcp":
            return self._send(404, {"error": "not found"})
        try:
            msg = self._body()
        except ValueError:
            return self._send(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}})
        if isinstance(msg, list) or not isinstance(msg, dict):
            return self._send(400, {"jsonrpc": "2.0", "id": None,
                                    "error": {"code": -32600, "message": "batches are not supported"}})
        mid, method, params = msg.get("id"), msg.get("method"), msg.get("params") or {}
        if mid is None:  # notification
            self.send_response(202)
            self.send_header("content-length", "0")
            self.end_headers()
            return
        try:
            if method == "initialize":
                res = {"protocolVersion": mcp_client.PROTOCOL, "capabilities": {"tools": {"listChanged": False}},
                       "serverInfo": {"name": "forge-airlock", "version": "0.1"}}
            elif method == "ping":
                res = {}
            elif method == "tools/list":
                res = A.tools_list()
            elif method == "tools/call":
                res = A.tools_call(params)
            else:
                return self._send(200, {"jsonrpc": "2.0", "id": mid,
                                        "error": {"code": -32601, "message": f"method {method!r} not supported"}})
        except Refusal as r:
            print(f"[airlock] refuse {params.get('name')!r}: {r.code} {r.message}", flush=True)
            return self._send(200, {"jsonrpc": "2.0", "id": mid, "error": {
                "code": ERR, "message": f"{r.code}: {r.message}", "data": dict(r.data, forge_code=r.code)}})
        except Exception as e:  # noqa: BLE001 - fail closed on any internal error
            print(f"[airlock] internal error: {type(e).__name__}: {e}", flush=True)
            return self._send(200, {"jsonrpc": "2.0", "id": mid, "error": {
                "code": ERR, "message": "FORGE_INTERNAL: refused", "data": {"forge_code": "FORGE_INTERNAL"}}})
        return self._send(200, {"jsonrpc": "2.0", "id": mid, "result": res})

    def log_message(self, *a):
        pass


class Server(ThreadingHTTPServer):
    request_queue_size = 256
    daemon_threads = True


def main():
    signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))  # logs are fsynced per step; exit at once
    Handler.A = Airlock()
    Server(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
