# gatelog.py - one bounded-state gate: a persistent 128-byte FV2 log plus a status journal.
#
# Labels:
#   PROVED (about the Dafny model only): the compiled #91 verifier's verdict on ONE log:
#     gross never exceeds cap, money chain, dense seq_no, no duplicate step_id, expiry.
#   NATIVE CHECK (this file, not proved): record encoding, the lock, fsync and atomic
#     rename, per_call_max, mapping of id_field to step_id, the PENDING/COMMITTED/ABORTED
#     journal, restart recovery, the policy-to-log match check.
#
# Two-phase rule. A step is appended to the .bin log (fsync) BEFORE the upstream is
# called. The journal then records PENDING, and later COMMITTED or ABORTED. The escrow
# log has no refund record, so an ABORTED step stays counted as spent. Assumption about
# the upstream: a timeout or a transport error does NOT tell us whether the upstream
# acted, so we never retry and never give the unit back. This can under-use a cap; it
# cannot exceed it.
import fcntl
import hashlib
import json
import os
import threading
import time

import records as R


def _fsync_dir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class GateError(Exception):
    pass


class GateLog:
    def __init__(self, data_dir, name, cap, expires_in_s, expires_at):
        self.name, self.cap = name, cap
        self.dir = data_dir
        self.wal = os.path.join(data_dir, f"{name}.bin")
        self.man = os.path.join(data_dir, f"{name}.manifest.bin")
        self.journal = os.path.join(data_dir, f"{name}.journal.jsonl")
        self.lockfile = os.path.join(data_dir, f"{name}.lock")
        self._tlock = threading.Lock()
        self._lockfd = os.open(self.lockfile, os.O_RDWR | os.O_CREAT, 0o600)
        with self.locked():
            if os.path.exists(self.wal):
                self._reload(cap, expires_in_s, expires_at)
            else:
                self._create(cap, expires_in_s, expires_at)

    # ---------------------------------------------------------- locking
    class _Locked:
        def __init__(self, log):
            self.log = log

        def __enter__(self):
            self.log._tlock.acquire()
            fcntl.flock(self.log._lockfd, fcntl.LOCK_EX)
            return self.log

        def __exit__(self, *a):
            fcntl.flock(self.log._lockfd, fcntl.LOCK_UN)
            self.log._tlock.release()

    def locked(self):
        """Single writer: a thread lock plus flock on <log>.lock (covers other processes)."""
        return GateLog._Locked(self)

    # ---------------------------------------------------------- create / reload
    def _create(self, cap, expires_in_s, expires_at):
        exp = expires_at if expires_at is not None else int(time.time()) + expires_in_s
        deal = R.sha(b"forge-airlock-log:" + self.name.encode())
        self.manifest = R.manifest_bytes(deal, cap, exp)
        self.expires_at = exp
        self.records = [R.genesis(cap, exp, self.manifest)]
        self._atomic_write(self.man, self.manifest)
        self._atomic_write(self.wal, b"".join(self.records))
        v = R.verify_file(self.wal, self.man, 1)
        if v.get("verdict") != "ACCEPT":
            raise GateError(f"{self.name}: fresh genesis does not verify: {v}")
        self.state = {}
        print(f"[airlock] log {self.name}: created cap={cap} expires_at={exp}", flush=True)

    def _reload(self, cap, expires_in_s, expires_at):
        if not os.path.exists(self.man):
            raise GateError(f"{self.name}: log present but manifest missing")
        self.manifest = open(self.man, "rb").read()
        raw = open(self.wal, "rb").read()
        if len(raw) % R.REC:
            raise GateError(f"{self.name}: torn tail of {len(raw) % R.REC} bytes; refusing to start")
        self.records = [raw[i:i + R.REC] for i in range(0, len(raw), R.REC)]
        self.expires_at = R.field(self.manifest, 168)
        if R.field(self.manifest, 160) != cap:
            raise GateError(f"{self.name}: stored cap {R.field(self.manifest, 160)} != policy cap {cap}")
        if expires_at is not None and self.expires_at != expires_at:
            raise GateError(f"{self.name}: stored expires_at != policy expires_at")
        v = R.verify_file(self.wal, self.man, max(self.last_ts(), 1))
        if v.get("verdict") != "ACCEPT":
            raise GateError(f"{self.name}: stored log does not verify ({v.get('verdict')}); refusing to start")
        self.state = self._read_journal()
        # Every step in the log must have a terminal state. A PENDING left by a crash or
        # restart stays spent (see the two-phase rule above).
        for i, rec in enumerate(self.records[1:], start=1):
            sid = rec[48:64].hex()
            st = self.state.get(i)
            if st is None:
                self._journal({"seq": i, "step_id": sid, "state": "ORPHAN_SPENT",
                               "note": "step in log without journal entry (crash between append and journal)"})
            elif st["state"] == "PENDING":
                self._journal({"seq": i, "step_id": sid, "state": "ABORTED",
                               "note": "PENDING at restart; counted as spent; upstream outcome unknown"})
        self.state = self._read_journal()
        print(f"[airlock] log {self.name}: reloaded {self.steps()} steps gross={self.gross()} cap={self.cap} "
              f"re-verified {v['verdict']}", flush=True)

    def _read_journal(self):
        st = {}
        if os.path.exists(self.journal):
            for line in open(self.journal, encoding="utf-8"):
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except ValueError:
                    raise GateError(f"{self.name}: journal line does not parse; refusing to start") from None
                st[e["seq"]] = e
        return st

    def _atomic_write(self, path, data):
        tmp = path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        _fsync_dir(self.dir)

    def _journal(self, entry):
        entry = dict(entry, ts=time.time())
        with open(self.journal, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())
        self.state = getattr(self, "state", {})
        self.state[entry["seq"]] = entry

    # ---------------------------------------------------------- state
    def gross(self):
        return R.field(self.records[-1], 72) if len(self.records) > 1 else 0

    def steps(self):
        return len(self.records) - 1

    def last_ts(self):
        return R.field(self.records[-1], 80) if len(self.records) > 1 else 0

    # ---------------------------------------------------------- the gate
    def reserve(self, amount, step_id, meta):
        """Phase 1. Under the lock: ask the PROVED verifier about log + tentative step.
        On ACCEPT, append and fsync the step and journal PENDING. Returns (verdict, seq)."""
        with self.locked():
            now = int(time.time())
            ts = max(now, self.last_ts())
            seq = len(self.records)
            tentative = R.step(step_id, amount, self.gross() + amount, ts, self.records[-1], seq)
            check = self.wal + ".check"
            with open(check, "wb") as f:
                f.write(b"".join(self.records) + tentative)
            v = R.verify_file(check, self.man, now)
            verdict = v.get("verdict", "UNVERIFIABLE_INTERNAL")
            if verdict != "ACCEPT":
                return verdict, None, self.gross()
            self.records.append(tentative)
            try:
                self._atomic_write(self.wal, b"".join(self.records))
            except OSError:
                self.records.pop()
                return "UNVERIFIABLE_INTERNAL", None, self.gross()
            self._journal(dict(meta, seq=seq, step_id=step_id.hex(), amount=amount, state="PENDING"))
            return verdict, seq, self.gross()

    def finish(self, seq, ok, note=""):
        """Phase 2. COMMITTED when the upstream answered without error, else ABORTED (still spent)."""
        with self.locked():
            prev = self.state.get(seq, {})
            self._journal({"seq": seq, "step_id": prev.get("step_id"), "amount": prev.get("amount"),
                           "state": "COMMITTED" if ok else "ABORTED", "note": note[:200]})

    def audit(self):
        with self.locked():
            v = R.verify_file(self.wal, self.man, max(self.last_ts(), 1))
            states = {}
            for e in self.state.values():
                states[e["state"]] = states.get(e["state"], 0) + 1
            return {"log": self.name, "cap": self.cap, "gross": self.gross(), "steps": self.steps(),
                    "expires_at": self.expires_at, "proved_verdict": v.get("verdict"), "journal": states,
                    "wal_sha256": hashlib.sha256(b"".join(self.records)).hexdigest()}
