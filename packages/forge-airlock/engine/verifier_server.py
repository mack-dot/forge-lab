#!/usr/bin/env python3
# verifier_server.py - the compiled Leg-1 verifier (Dafny-proved model, #91) as ONE
# persistent process for the airlock's life, instead of a new subprocess per gated call.
#
# Protocol (stdin/stdout, one JSON object per line):
#   request  {"argv": ["<log>", "--manifest", "<m>", "--pubkeys", "<a>,<b>", "--observed-now", "<n>", "--json"]}
#   response {"stdout": "<what leg1_cli.py printed>", "exit": <its exit code>, "memo": {...}}
# Each request runs the SAME glue (verifier/leg1_cli.run, unchanged) on the WHOLE log, so
# every verdict is still the compiled verifier's verdict on every byte of the log.
#
# Sound reduction of repeated work (FORGE_VERIFIER_MEMO=1, the default): the compiled
# Sha.Sha256 and Ed.ValidateKey are pure (deterministic, no shared state: they read only
# their argument and constants), so their results are memoized, keyed by the EXACT input
# bytes. A repeated call returns the value the compiled code returned for the same bytes
# before. Nothing in the verifier's control flow changes; no incremental shortcut is taken.
# Label: the memo table and this file are NATIVE CHECK (hand-written, not proved). The
# equivalence "memo on == memo off" is a FINITE TEST (tests/run_airlock_tests.py).
import collections
import contextlib
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
VDIR = os.path.join(HERE, "verifier")
sys.path.insert(0, VDIR)
sys.path.insert(0, os.path.join(VDIR, "build", "escrow-py"))
import leg1_cli  # noqa: E402  (imports _dafny and Verifier)
import Sha  # noqa: E402
import Ed  # noqa: E402

MEMO_MAX = int(os.environ.get("FORGE_VERIFIER_MEMO_MAX", "262144"))
STATS = {"hits": 0, "misses": 0, "uncacheable": 0}


def _memo(fn):
    table = collections.OrderedDict()

    def wrapped(arg):
        try:
            key = bytes(arg)  # a Dafny seq of bytes; anything else is not cached
        except (TypeError, ValueError):
            STATS["uncacheable"] += 1
            return fn(arg)
        hit = table.get(key)
        if hit is not None:
            table.move_to_end(key)
            STATS["hits"] += 1
            return hit
        STATS["misses"] += 1
        val = fn(arg)
        table[key] = val
        if len(table) > MEMO_MAX:
            table.popitem(last=False)
        return val
    return wrapped


if os.environ.get("FORGE_VERIFIER_MEMO", "1") == "1":
    Sha.default__.Sha256 = staticmethod(_memo(Sha.default__.Sha256))
    Ed.default__.ValidateKey = staticmethod(_memo(Ed.default__.ValidateKey))


def main():
    out = sys.stdout
    for line in sys.stdin:
        try:
            req = json.loads(line)
            argv = ["leg1_cli.py"] + [str(a) for a in req["argv"]]
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = leg1_cli.run(argv)
            resp = {"stdout": buf.getvalue(), "exit": code, "memo": dict(STATS)}
        except Exception as e:  # noqa: BLE001 - the client maps this to UNVERIFIABLE_INTERNAL
            resp = {"error": f"{type(e).__name__}: {str(e)[:200]}"}
        out.write(json.dumps(resp) + "\n")
        out.flush()


if __name__ == "__main__":
    main()
