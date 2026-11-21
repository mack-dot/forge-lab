#!/usr/bin/env python3
# harness.py — run all golden vectors through leg1_cli.py and compare the
# --json object AND exit code field-for-field against each case's expected_json.
import sys, os, json, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
PKT = "/Users/mackianni/forge/.directives/leg2-implementer-packet"
GV = os.path.join(PKT, "golden_vectors")
CLI = os.path.join(HERE, "leg1_cli.py")


def main():
    vectors = json.load(open(os.path.join(GV, "vectors.json")))
    cases = vectors["cases"]
    npass = 0
    fails = []
    for c in cases:
        name = c["name"]
        log = os.path.join(GV, c["log_file"])
        argv = [sys.executable, "-I", CLI, log, "--json"]
        if c["manifest_file"] is not None:
            argv += ["--manifest", os.path.join(GV, c["manifest_file"])]
        if c["pubkeys_file"] is not None:
            a, b = c["pubkeys_file"].split(",")
            argv += ["--pubkeys", f"{os.path.join(GV, a)},{os.path.join(GV, b)}"]
        if c["tape_file"] is not None:
            argv += ["--tape", os.path.join(GV, c["tape_file"])]
        if c["observed_now"] is not None:
            argv += ["--observed-now", str(c["observed_now"])]
        if c["expect_tip"] is not None:
            argv += ["--expect-tip", c["expect_tip"]]
        if c["max_records"] is not None:
            argv += ["--max-records", str(c["max_records"])]

        p = subprocess.run(argv, capture_output=True, text=True)
        exit_code = p.returncode
        # last stdout line is the json object
        out_lines = [l for l in p.stdout.splitlines() if l.strip()]
        got = None
        for l in reversed(out_lines):
            if l.startswith("{"):
                got = json.loads(l)
                break
        exp = c["expected_json"]
        diffs = []
        if got is None:
            diffs.append(f"no json output; stderr={p.stderr[:300]}")
        else:
            for k in exp:
                if got.get(k) != exp[k]:
                    diffs.append(f"{k}: got={got.get(k)!r} exp={exp[k]!r}")
            if exit_code != exp["exit_code"]:
                diffs.append(f"EXIT: got={exit_code} exp={exp['exit_code']}")
        if diffs:
            fails.append((name, diffs))
        else:
            npass += 1

    print(f"PASS {npass}/{len(cases)}")
    for name, diffs in fails:
        print(f"FAIL {name}")
        for d in diffs:
            print(f"     {d}")
    return 0 if npass == len(cases) else 1


if __name__ == "__main__":
    sys.exit(main())
