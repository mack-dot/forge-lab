# audit.py - read-only audit of every gate log on the data volume (run inside the airlock).
# For each log: take its flock, re-run the compiled verifier on the stored bytes, count the
# journal states, and (optionally) compare with the mock upstream's ledger.
# Prints one JSON object. Exit 0 only if every log verifies ACCEPT and gross <= cap.
# Label: NATIVE CHECK around the PROVED verdict. It never writes to the data volume.
import fcntl
import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import records as R  # noqa: E402
from policy import Policy  # noqa: E402

DATA = os.environ.get("FORGE_DATA", "/data")


def main():
    pol = Policy.load(os.environ.get("FORGE_POLICY", "/forge/forge.yaml"))
    out, ok = {"logs": {}}, True
    for name in sorted(pol.logs):
        wal, man = os.path.join(DATA, f"{name}.bin"), os.path.join(DATA, f"{name}.manifest.bin")
        fd = os.open(os.path.join(DATA, f"{name}.lock"), os.O_RDWR)
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            raw = open(wal, "rb").read()
            recs = [raw[i:i + 128] for i in range(0, len(raw) - len(raw) % 128, 128)]
            last_ts = R.field(recs[-1], 80) if len(recs) > 1 else 0
            v = R.verify_file_fresh(wal, man, max(last_ts, 1))
            states = {}
            jp = os.path.join(DATA, f"{name}.journal.jsonl")
            last = {}
            if os.path.exists(jp):
                for line in open(jp):
                    if line.strip():
                        e = json.loads(line)
                        last[e["seq"]] = e["state"]
            for s in last.values():
                states[s] = states.get(s, 0) + 1
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
        gross = v.get("final_balances", {}).get("gross_spent")
        cap = R.field(open(man, "rb").read(), 160)
        good = v.get("verdict") == "ACCEPT" and gross is not None and gross <= cap
        ok &= good
        out["logs"][name] = {"proved_verdict": v.get("verdict"), "records": v.get("records"), "gross": gross,
                             "cap": cap, "journal_final_states": states, "ok": good}
    if len(sys.argv) > 1:  # mock upstream ledger URL; the airlock holds the key for it
        up = [u for u in pol.upstreams.values() if u["transport"] == "http"][0]
        req = urllib.request.Request(sys.argv[1], headers=up.get("headers") or {})
        rows = json.loads(urllib.request.urlopen(req, timeout=10).read())["rows"]
        led = {}
        for r in rows:
            d = led.setdefault(r["tool"], {"calls": 0, "sum": {}})
            d["calls"] += 1
            for k, val in r["args"].items():
                if type(val) is int:
                    d["sum"][k] = d["sum"].get(k, 0) + val
        ids = [r["args"].get("invoice_id") for r in rows if r["tool"] == "charge"]
        out["upstream_ledger"] = led
        out["upstream_duplicate_invoice_ids"] = len(ids) - len(set(ids))
    out["ok"] = ok
    print(json.dumps(out, sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
