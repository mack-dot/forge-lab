#!/usr/bin/env python3
# run_corpus.py -- run every corpus case (and the 56 golden vectors) through
# BOTH legs, compare the canonical --json object + exit code, surface every
# divergence. Python stdlib only.
import os, sys, json, subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

HERE = os.path.dirname(os.path.abspath(__file__))
GOLD = "/Users/mackianni/forge/.directives/leg2-implementer-packet/golden_vectors"
LEG1 = "/private/tmp/claude-501/-Users-mackianni-forge/fb0fde47-8987-485d-a625-0e9fdb4facee/scratchpad/leg1-escrow/leg1_cli.py"
LEG2 = "/private/tmp/claude-501/-Users-mackianni-forge/fb0fde47-8987-485d-a625-0e9fdb4facee/scratchpad/leg2-run2/src-extract/leg2-source/target/release/leg2-verify"


def extract_json(stdout):
    """Last stdout line that parses as a JSON object (iterate in reverse).
    Leg 1's human preamble (verdict + key=value lines) is skipped this way."""
    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        if isinstance(obj, dict):
            return obj
    return None


def run_leg(cmd):
    p = subprocess.run(cmd, capture_output=True, timeout=120)
    out = p.stdout.decode("utf-8", "replace")
    return extract_json(out), p.returncode, out, p.stderr.decode("utf-8", "replace")


def diff_fields(a, b):
    """Return list of differing field paths between two json objects."""
    diffs = []
    if a is None or b is None:
        if a != b:
            diffs.append("<json-parse>")
        return diffs
    keys = set(a) | set(b)
    for k in sorted(keys):
        va, vb = a.get(k, "<MISSING>"), b.get(k, "<MISSING>")
        if isinstance(va, dict) and isinstance(vb, dict):
            for sk in sorted(set(va) | set(vb)):
                if va.get(sk, "<MISSING>") != vb.get(sk, "<MISSING>"):
                    diffs.append(f"{k}.{sk}")
        elif va != vb:
            diffs.append(k)
    return diffs


def run_case(case):
    argv = case["argv"]
    l1_json, l1_exit, l1_out, l1_err = run_leg(["python3", "-I", LEG1] + argv)
    l2_json, l2_exit, l2_out, l2_err = run_leg([LEG2] + argv)
    fields = diff_fields(l1_json, l2_json)
    agree = (l1_json == l2_json) and (l1_exit == l2_exit) and not fields
    exit_mismatch = l1_exit != l2_exit
    rec = {
        "case_id": case["case_id"], "category": case["category"],
        "inputs": case["inputs"], "argv": argv,
        "leg1_json": l1_json, "leg1_exit": l1_exit,
        "leg2_json": l2_json, "leg2_exit": l2_exit,
        "differing_fields": fields + (["<exit_code>"] if exit_mismatch else []),
        "agree": agree,
    }
    if l1_json is None:
        rec["leg1_stdout"] = l1_out[-500:]
        rec["leg1_stderr"] = l1_err[-500:]
    if l2_json is None:
        rec["leg2_stdout"] = l2_out[-500:]
        rec["leg2_stderr"] = l2_err[-500:]
    return rec


def golden_argv(c):
    argv = [os.path.join(GOLD, c["log_file"])]
    if c["manifest_file"]:
        argv += ["--manifest", os.path.join(GOLD, c["manifest_file"])]
    if c["pubkeys_file"]:
        parts = c["pubkeys_file"].split(",")
        argv += ["--pubkeys", ",".join(os.path.join(GOLD, p) for p in parts)]
    if c["tape_file"]:
        argv += ["--tape", os.path.join(GOLD, c["tape_file"])]
    if c["observed_now"] is not None:
        argv += ["--observed-now", str(c["observed_now"])]
    if c["expect_tip"] is not None:
        argv += ["--expect-tip", c["expect_tip"]]
    if c["max_records"] is not None:
        argv += ["--max-records", str(c["max_records"])]
    argv += ["--json"]
    return argv


def main():
    # ---- golden vectors: both legs vs expected_json ----
    vec = json.load(open(os.path.join(GOLD, "vectors.json")))
    golden_results = []
    golden_all_ok = True
    for c in vec["cases"]:
        argv = golden_argv(c)
        l1_json, l1_exit, _, _ = run_leg(["python3", "-I", LEG1] + argv)
        l2_json, l2_exit, _, _ = run_leg([LEG2] + argv)
        exp = c["expected_json"]
        l1_vs_exp = diff_fields(l1_json, exp)
        l2_vs_exp = diff_fields(l2_json, exp)
        legs_agree = (l1_json == l2_json) and (l1_exit == l2_exit)
        ok = (not l1_vs_exp) and (not l2_vs_exp) and legs_agree
        golden_all_ok = golden_all_ok and ok
        golden_results.append({
            "name": c["name"], "expected_verdict": exp["verdict"],
            "leg1_vs_expected_diff": l1_vs_exp, "leg2_vs_expected_diff": l2_vs_exp,
            "legs_agree": legs_agree, "ok": ok,
            "leg1_exit": l1_exit, "leg2_exit": l2_exit})
    print(f"golden: {sum(1 for g in golden_results if g['ok'])}/{len(golden_results)} ok; all_ok={golden_all_ok}")

    # ---- fuzz corpus ----
    cases = [json.loads(l) for l in open(os.path.join(HERE, "cases.jsonl"))]
    results = [None] * len(cases)
    with ThreadPoolExecutor(max_workers=8) as ex:
        futs = {ex.submit(run_case, c): i for i, c in enumerate(cases)}
        done = 0
        for fut in as_completed(futs):
            i = futs[fut]
            results[i] = fut.result()
            done += 1
            if done % 200 == 0:
                print(f"  ran {done}/{len(cases)}")

    divergences = [r for r in results if not r["agree"]]
    agreement = len(results) - len(divergences)

    evidence = {
        "label": "FINITE TEST (large but finite corpus), NOT a proof of "
                 "equivalence over all inputs. end_to_end=false.",
        "legs": {"leg1": LEG1, "leg2": LEG2},
        "corpus_size": len(results) + len(golden_results),
        "golden_cases": len(golden_results),
        "fuzz_cases": len(results),
        "agreement_count": agreement,
        "divergence_count": len(divergences),
        "golden_all_ok": golden_all_ok,
        "golden_vs_expected": golden_results,
        "divergences": [{
            "case_id": d["case_id"], "category": d["category"],
            "inputs": d["inputs"], "argv": d["argv"],
            "leg1_json": d["leg1_json"], "leg1_exit": d["leg1_exit"],
            "leg2_json": d["leg2_json"], "leg2_exit": d["leg2_exit"],
            "differing_fields": d["differing_fields"],
            **({"leg1_stdout": d.get("leg1_stdout"), "leg1_stderr": d.get("leg1_stderr")} if d["leg1_json"] is None else {}),
            **({"leg2_stdout": d.get("leg2_stdout"), "leg2_stderr": d.get("leg2_stderr")} if d["leg2_json"] is None else {}),
        } for d in divergences],
    }
    with open(os.path.join(HERE, "evidence.json"), "w") as f:
        json.dump(evidence, f, indent=1)

    # per-category agreement table
    from collections import Counter
    tot = Counter(r["category"] for r in results)
    div = Counter(d["category"] for d in divergences)
    print("\n=== PER-CATEGORY (fuzz) ===")
    for k in sorted(tot):
        print(f"  {k}: {tot[k]-div[k]}/{tot[k]} agree" + (f"  [{div[k]} DIVERGE]" if div[k] else ""))
    print(f"\nFUZZ: {agreement}/{len(results)} agree, {len(divergences)} divergences")
    print(f"TOTAL corpus (incl golden): {evidence['corpus_size']}")
    if divergences:
        print("\n=== DIVERGENCES ===")
        for d in divergences:
            print(f"- {d['case_id']} [{d['category']}] fields={d['differing_fields']}")
            print(f"    L1 exit={d['leg1_exit']} json={d['leg1_json']}")
            print(f"    L2 exit={d['leg2_exit']} json={d['leg2_json']}")


if __name__ == "__main__":
    main()
