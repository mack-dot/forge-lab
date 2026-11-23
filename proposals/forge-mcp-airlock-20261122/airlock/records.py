# records.py - 128-byte FV2 escrow record codec and the call into the compiled verifier.
#
# Label: NATIVE CHECK. This encoder is hand-written and NOT proved. It follows
# proposals/escrow-dual-leg-20261121/spec/SPEC.md sections 2 to 4 and is the same
# layout as the #93 / #96 sidecars. The verdict comes from the compiled Dafny
# verifier (verifier/leg1_cli.py -> Verifier.VerifyCLI). Only that verifier's
# verdict on one log is the PROVED part (about the Dafny model, not about this file).
import hashlib
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
VDIR = os.path.join(HERE, "verifier")
A_PUB, B_PUB = os.path.join(VDIR, "a.pub"), os.path.join(VDIR, "b.pub")
LEG1 = os.path.join(VDIR, "leg1_cli.py")
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


def verify_file(log_path, manifest_path, observed_now):
    """Run the compiled verifier through the unproved CLI glue. Returns the --json object.

    Any failure to get a verdict returns UNVERIFIABLE_INTERNAL (fail closed)."""
    try:
        r = subprocess.run([sys.executable, "-I", LEG1, log_path, "--manifest", manifest_path,
                            "--pubkeys", f"{A_PUB},{B_PUB}", "--observed-now", str(observed_now),
                            "--json"], capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"verdict": "UNVERIFIABLE_INTERNAL", "err": str(e)[:200]}
    for line in reversed(r.stdout.splitlines()):
        if line.strip().startswith("{"):
            try:
                return json.loads(line)
            except ValueError:
                break
    return {"verdict": "UNVERIFIABLE_INTERNAL", "err": r.stderr[-300:]}
