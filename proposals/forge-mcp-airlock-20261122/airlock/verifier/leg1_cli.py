#!/usr/bin/env python3
# leg1_cli.py — thin, UNPROVED I/O glue around the compiled Dafny Leg-1 core.
# File reading, argv parsing and JSON printing live here (not proved); all
# verification logic is the compiled Dafny Verifier.VerifyCLI. This is the
# "NATIVE CHECK" executable wrapping the PROVED model.
import sys, os, json

_HERE = os.path.dirname(os.path.abspath(__file__))
_PYDIR = os.path.join(_HERE, "build", "escrow-py")
sys.path.insert(0, _PYDIR)
import _dafny          # noqa: E402
import Verifier        # noqa: E402

DEFAULT_MAX_RECORDS = 1048576


def _seq(b):
    return _dafny.Seq(list(b))


def _bytes_of(seq):
    return bytes(int(x) for x in seq)


def _read(path):
    with open(path, "rb") as f:
        return f.read()


def run(argv):
    # ---- argv parse (glue only) ----
    args = argv[1:]
    log_path = None
    manifest_path = None
    pubkeys_arg = None
    tape_path = None
    observed_now = None
    expect_tip = None
    max_records = None
    want_json = False

    i = 0
    usage_err = False
    while i < len(args):
        a = args[i]
        if a == "--manifest":
            i += 1
            manifest_path = args[i] if i < len(args) else None
        elif a == "--pubkeys":
            i += 1
            pubkeys_arg = args[i] if i < len(args) else None
        elif a == "--tape":
            i += 1
            tape_path = args[i] if i < len(args) else None
        elif a == "--observed-now":
            i += 1
            try:
                observed_now = int(args[i])
            except (IndexError, ValueError):
                usage_err = True
        elif a == "--expect-tip":
            i += 1
            expect_tip = args[i] if i < len(args) else None
        elif a == "--max-records":
            i += 1
            try:
                max_records = int(args[i])
            except (IndexError, ValueError):
                usage_err = True
        elif a == "--json":
            want_json = True
        elif a.startswith("--"):
            usage_err = True
        else:
            if log_path is None:
                log_path = a
            else:
                usage_err = True
        i += 1

    def emit(res_fields):
        verdict, exit_code, records, torn, fail_null, fail_index, gross, payout, \
            refund, tip, epoch, expiry = res_fields
        obj = {
            "verdict": verdict,
            "exit_code": exit_code,
            "records": records,
            "torn_bytes": torn,
            "fail_index": None if fail_null else fail_index,
            "final_balances": {
                "gross_spent": gross,
                "seller_payout": payout,
                "buyer_refund": refund,
            },
            "tip": tip,
            "epoch": epoch,
            "expiry_gate_evaluated": expiry,
            "notes": "",
        }
        print(verdict)
        for k in ("exit_code", "records", "torn_bytes", "fail_index", "tip",
                  "epoch", "expiry_gate_evaluated"):
            print(f"{k}={obj[k]}")
        if want_json:
            print(json.dumps(obj))
        return exit_code

    # missing positional log OR unparseable flag -> USAGE (glue-level)
    if log_path is None or usage_err:
        return emit(("UNVERIFIABLE_USAGE", 3, 0, 0, True, 0, 0, 0, 0, "", 0, False))

    # ---- read log (unreadable -> UNREADABLE) ----
    try:
        log = _read(log_path)
    except OSError:
        return emit(("UNVERIFIABLE_UNREADABLE", 3, 0, 0, True, 0, 0, 0, 0, "", 0, False))

    # ---- manifest ----
    manifest_present = manifest_path is not None
    manifest = b""
    if manifest_present:
        try:
            manifest = _read(manifest_path)
        except OSError:
            return emit(("UNVERIFIABLE_UNREADABLE", 3, len(log) // 128, len(log) % 128,
                         True, 0, 0, 0, 0, "", 0, False))

    # ---- pubkeys (comma-separated a.pub,b.pub) ----
    pub_present = pubkeys_arg is not None
    pubA = b""
    pubB = b""
    if pub_present:
        parts = pubkeys_arg.split(",")
        if len(parts) != 2:
            pub_present = False   # malformed -> treated as usage by the core
        else:
            try:
                pubA = _read(parts[0])
                pubB = _read(parts[1])
            except OSError:
                return emit(("UNVERIFIABLE_UNREADABLE", 3, len(log) // 128, len(log) % 128,
                             True, 0, 0, 0, 0, "", 0, False))

    # ---- tape ----
    tape_present = tape_path is not None
    tape = b""
    if tape_present:
        try:
            tape = _read(tape_path)
        except OSError:
            return emit(("UNVERIFIABLE_UNREADABLE", 3, len(log) // 128, len(log) % 128,
                         True, 0, 0, 0, 0, "", 0, False))

    obs_present = observed_now is not None
    tip_present = expect_tip is not None
    expect_tip_bytes = expect_tip.encode("ascii", "replace") if tip_present else b""
    mr = max_records if max_records is not None else DEFAULT_MAX_RECORDS

    r = Verifier.default__.VerifyCLI(
        _seq(log),
        manifest_present, _seq(manifest),
        pub_present, _seq(pubA), _seq(pubB),
        tape_present, _seq(tape),
        obs_present, observed_now if obs_present else 0,
        tip_present, _seq(expect_tip_bytes),
        mr)

    fields = (
        _bytes_of(r.verdict).decode("ascii"),
        int(r.exitCode),
        int(r.records),
        int(r.tornBytes),
        bool(r.failNull),
        int(r.failIndex),
        int(r.gross),
        int(r.sellerPayout),
        int(r.buyerRefund),
        _bytes_of(r.tip).decode("ascii"),
        int(r.epoch),
        bool(r.expiryGate),
    )
    return emit(fields)


if __name__ == "__main__":
    sys.exit(run(sys.argv))
