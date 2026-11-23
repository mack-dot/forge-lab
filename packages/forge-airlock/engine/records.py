# records.py - 128-byte FV2 escrow record codec and the call into the compiled verifier.
#
# Label: NATIVE CHECK. This encoder is hand-written and NOT proved. It follows
# proposals/escrow-dual-leg-20261121/spec/SPEC.md sections 2 to 4 and is the same
# layout as the #93 / #96 sidecars. The verdict comes from the compiled Dafny
# verifier (verifier/leg1_cli.py -> Verifier.VerifyCLI). Only that verifier's
# verdict on one log is the PROVED part (about the Dafny model, not about this file).
# Gated calls go to ONE persistent verifier process (verifier_server.py); start-up,
# reload and audit use a fresh subprocess, as in #97.
import hashlib
import json
import os
import select
import subprocess
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
VDIR = os.path.join(HERE, "verifier")
A_PUB, B_PUB = os.path.join(VDIR, "a.pub"), os.path.join(VDIR, "b.pub")
LEG1 = os.path.join(VDIR, "leg1_cli.py")
SERVER = os.path.join(HERE, "verifier_server.py")
U64 = (1 << 64) - 1
MONEY_MAX = (1 << 63) - 1
REC = 128


def u64(v):
    if not (0 <= v <= U64):
        raise ValueError("u64 out of range")
    return int(v).to_bytes(8, "little")


def sha(b):
    return hashlib.sha256(b).digest()


KEY_A = open(A_PUB, "rb").read()
KEY_B = open(B_PUB, "rb").read()
_GM = open(os.path.join(VDIR, "accept_genesis_only.manifest.bin"), "rb").read()
SPEC_HASH, ESCROW_ID = _GM[96:128], _GM[128:160]


def manifest_bytes(deal_id, cap, expires_at):
    assert len(deal_id) == 32
    return deal_id + KEY_A + KEY_B + SPEC_HASH + ESCROW_ID + u64(cap) + u64(expires_at)


def genesis(cap, expires_at, manifest):
    body = (b"FV2" + bytes([2, 2, 0x47]) + b"\x00\x00" + u64(0) + b"\x00" * 32
            + u64(cap) + u64(expires_at) + sha(manifest))
    return body + sha(body)


def step(step_id, amount, gross, ts, prev_record, seq):
    assert len(step_id) == 16
    body = (b"FV2" + bytes([2, 2, 0x53]) + b"\x00\x00" + u64(seq) + sha(prev_record)
            + step_id + u64(amount) + u64(gross) + u64(ts) + b"\x00" * 8)
    return body + sha(body)


def field(record, start):
    return int.from_bytes(record[start:start + 8], "little")


def _parse(stdout, stderr=""):
    for line in reversed(stdout.splitlines()):
        if line.strip().startswith("{"):
            try:
                return json.loads(line)
            except ValueError:
                break
    return {"verdict": "UNVERIFIABLE_INTERNAL", "err": stderr[-300:]}


def _argv(log_path, manifest_path, observed_now):
    return [log_path, "--manifest", manifest_path, "--pubkeys", f"{A_PUB},{B_PUB}",
            "--observed-now", str(observed_now), "--json"]


def verify_file_fresh(log_path, manifest_path, observed_now):
    """The #97 path: a NEW subprocess of the compiled verifier, no memo. Used at start,
    on reload and by audit.py, and for every call when FORGE_VERIFIER=subprocess."""
    try:
        r = subprocess.run([sys.executable, "-I", LEG1] + _argv(log_path, manifest_path, observed_now),
                           capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"verdict": "UNVERIFIABLE_INTERNAL", "err": str(e)[:200]}
    return _parse(r.stdout, r.stderr)


class PersistentVerifier:
    """One long-lived verifier_server.py process; one request at a time (a lock).

    Fail closed: a dead process, a timeout or a reply that does not parse gives
    UNVERIFIABLE_INTERNAL for that call; the process is restarted for the next call."""

    def __init__(self, timeout_s=120):
        self.timeout = timeout_s
        self.lock = threading.Lock()
        self.proc = None
        self.calls = 0
        self.last_memo = {}

    def _start(self):
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
               "FORGE_VERIFIER_MEMO": os.environ.get("FORGE_VERIFIER_MEMO", "1")}
        self.proc = subprocess.Popen([sys.executable, "-I", SERVER], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, text=True, bufsize=1, env=env)

    def _kill(self):
        if self.proc is not None:
            try:
                self.proc.kill()
                self.proc.wait(5)
            except Exception:  # noqa: BLE001
                pass
        self.proc = None

    def verify(self, log_path, manifest_path, observed_now):
        with self.lock:
            try:
                if self.proc is None or self.proc.poll() is not None:
                    self._start()
                self.proc.stdin.write(json.dumps({"argv": _argv(log_path, manifest_path, observed_now)}) + "\n")
                self.proc.stdin.flush()
                ready, _, _ = select.select([self.proc.stdout], [], [], self.timeout)
                if not ready:
                    raise TimeoutError("verifier did not answer")
                line = self.proc.stdout.readline()
                resp = json.loads(line)
                if "error" in resp:
                    raise RuntimeError(resp["error"])
                self.calls += 1
                self.last_memo = resp.get("memo", {})
                return _parse(resp["stdout"])
            except Exception as e:  # noqa: BLE001 - fail closed
                self._kill()
                return {"verdict": "UNVERIFIABLE_INTERNAL", "err": f"{type(e).__name__}: {str(e)[:200]}"}

    def close(self):
        with self.lock:
            self._kill()


_PV = None


def verify_file(log_path, manifest_path, observed_now):
    """Verdict of the compiled verifier on the WHOLE log. Default: the persistent process
    (FORGE_VERIFIER=persistent); FORGE_VERIFIER=subprocess restores the #97 behaviour."""
    global _PV
    if os.environ.get("FORGE_VERIFIER", "persistent") == "subprocess":
        return verify_file_fresh(log_path, manifest_path, observed_now)
    if _PV is None:
        _PV = PersistentVerifier()
    return _PV.verify(log_path, manifest_path, observed_now)
