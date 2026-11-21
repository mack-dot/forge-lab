#!/usr/bin/env python3
"""Task V1, FORGE worker: exhaustive loops over a REAL multi-record log. FINITE TEST. end_to_end=false.

  python3 tests/refund_log_verifier/test_exhaustive.py <verifier> [--sink <native_sink>] [--standin]

1. The real sink writes a log of a genesis and 3 commits (256 bytes). EVERY single bit is flipped once (2048 cases).
   Each flip: the oracle (ref_fold.py) class, the verifier verdict, the real sink's answer. Every flip that the
   verifier does NOT reject is listed with its byte, bit and field (Trap A: a flip in the LAST record).
2. The log is truncated at EVERY byte offset 0..256. The offsets that are multiples of 64 (clean prefixes, Trap B) are
   asserted explicitly: ACCEPT of the shorter history without an anchor; REJECT with --expect-count, --expect-tip or a
   ratchet that holds the higher epoch.
A verifier/oracle class disagreement fails the suite (exit 1); a different verdict NAME with the same class is
counted and listed (it is a difference in the order of checks, not a class difference). NOT RUN fails the suite.
"""

import argparse
import os
import shutil
import sys
import tempfile
from collections import Counter
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import wal_forge as W  # noqa: E402
import ref_fold as R  # noqa: E402

# THE ONE TABLE: oracle cause -> verdict name in verifier/refund_log/VERDICTS.md (copied, none invented).
# '@0' = at record 0. Policy rows: ref_fold.py DECIDED POLICY (orchestrator, 2026-11-20).
VERDICT_TABLE = {
    'ACCEPT': 'ACCEPT', 'ACCEPT_TORN_TAIL': 'ACCEPT_TORN_TAIL',
    'MAGIC': 'REJECT_MALFORMED_RECORD',
    'CRC': 'REJECT_BAD_CRC',
    'EPOCH': 'REJECT_EPOCH_MISMATCH', 'EPOCH@0': 'REJECT_BAD_GENESIS',
    'CHAIN': 'REJECT_CHAIN_MISMATCH', 'CHAIN@0': 'REJECT_BAD_GENESIS',
    'KIND': 'REJECT_REASON_NOT_ALLOWED', 'KIND@0': 'REJECT_BAD_GENESIS',
    'ID_ENCODING': 'REJECT_MALFORMED_RECORD',
    'GENESIS': 'REJECT_BAD_GENESIS',
    'EMPTY_ID': 'REJECT_EMPTY_ID',
    'DUPLICATE_ID': 'REJECT_DUPLICATE_ID',
    'REASON': 'REJECT_REASON_NOT_ALLOWED',
    'OVER_REFUND': 'REJECT_AMOUNT_OVER_REMAINING',
    'OVER_REFUND_NOT_MONEY': 'REJECT_AMOUNT_NOT_MONEY',
    'RATCHET_BAD_ENTRY': 'REJECT_RATCHET_BAD_ENTRY',      # decided policy 3
    'RATCHET_NO_ENTRY': 'REJECT_RATCHET_NO_ENTRY',        # decided policy 4
    'EXPECT_COUNT': 'REJECT_COUNT_MISMATCH',
    'EXPECT_TIP': 'REJECT_TIP_MISMATCH',
    'RATCHET_AHEAD': 'REJECT_RATCHET_AHEAD',
    'EMPTY_FILE': 'UNVERIFIABLE_EMPTY_FILE', 'NO_WHOLE_RECORD': 'UNVERIFIABLE_NO_WHOLE_RECORD',   # decided policy 2
    'TOO_LARGE': 'UNVERIFIABLE_TOO_LARGE', 'RATCHET_TOO_LARGE': 'UNVERIFIABLE_RATCHET_TOO_LARGE',  # decided policy 6
    'UNREADABLE': 'UNVERIFIABLE_UNREADABLE',
    'BAD_ARGUMENT': 'UNVERIFIABLE_USAGE',
}
ORACLE_EXIT = R.EXIT
FIELDS = [(0, 3, 'magic'), (3, 4, 'kind'), (4, 12, 'epoch'), (12, 28, 'pre_state_hash'), (28, 52, 'id+padding'), (52, 60, 'amount'), (60, 64, 'crc')]


def field_of(offset):
    for lo, hi, name in FIELDS:
        if lo <= offset % W.REC < hi:
            return 'record %d %s' % (offset // W.REC, name)


def expected_name(cls, cause, det, standin):
    if standin:
        return cls if cause is None else cls + '_' + cause
    if cause is None:
        return cls
    return VERDICT_TABLE[cause + ('@0' if det.get('record') == 0 and cause in ('EPOCH', 'CHAIN', 'KIND') else '')]


def main():
    p = argparse.ArgumentParser()
    p.add_argument('verifier')
    p.add_argument('--sink')
    p.add_argument('--standin', action='store_true')
    a = p.parse_args()
    if not (Path(a.verifier).is_file() and os.access(a.verifier, os.X_OK)):
        print('NOT RUN: the verifier %s does not exist or is not executable; FAILED; end_to_end=false' % a.verifier)
        return 1
    work = Path(tempfile.mkdtemp(prefix='forge-exhaustive-'))
    sink = str(Path(a.sink).resolve()) if a.sink else str(W.build_sink(work))
    verifier = str(Path(a.verifier).resolve())
    refund = W.private_refund_binary(work / 'bin')
    commits = [('returned_item', 'rq-1', 100), ('duplicate_charge', 'rq-2', 0), ('service_not_delivered', 'rq-3', 250)]
    base, ratchet, _, tails = W.real_store(sink, refund, work / 'base', 'charge-1', 1000, commits)
    assert len(base) == 4 * W.REC and base == W.honest_log('charge-1', 1000, commits)
    tip, count = tails[-1], len(commits)
    print('FORGE exhaustive loops; verifier %s; real log %d bytes (%d records, tip %s); FINITE TEST; end_to_end=false' % (a.verifier, len(base), len(base) // W.REC, tip))
    failures, not_run, name_diffs, class_diffs = 0, 0, Counter(), []

    def judge(label, data, **anchors):
        nonlocal not_run
        cls, cause, det = R.verdict(data, anchors.get('ratchet'), anchors.get('expect_count'), anchors.get('expect_tip'))
        try:
            code, word, _, _ = W.run_verifier(verifier, data, anchors.get('ratchet'), anchors.get('expect_count'), anchors.get('expect_tip'))
        except Exception as error:  # noqa: BLE001
            print('NOT RUN %s: %s' % (label, error))
            not_run += 1
            return cls, cause, None, None
        want = expected_name(cls, cause, det, a.standin)
        if code != ORACLE_EXIT[cls]:
            class_diffs.append('%s: oracle %s/%s exit %d; verifier %s exit %d' % (label, cls, cause, ORACLE_EXIT[cls], word, code))
        elif want is not None and word != want:
            name_diffs[(cause, want, word)] += 1
        return cls, cause, code, word

    # ---- 1. every single bit
    flips = {'total': 0, 'verifier_rejected': 0, 'verifier_not_rejected': 0, 'oracle_rejected': 0}
    sink_by_region, not_rejected = Counter(), []
    sink_ratchet = W.honest_ratchet(count)
    for byte in range(len(base)):
        for bit in range(8):
            data = bytearray(base)
            data[byte] ^= 1 << bit
            data = bytes(data)
            cls, cause, code, word = judge('flip byte %d bit %d' % (byte, bit), data)
            flips['total'] += 1
            flips['oracle_rejected'] += cls == R.REJECT
            if code is None:
                continue
            if code == 1:
                flips['verifier_rejected'] += 1
            else:
                flips['verifier_not_rejected'] += 1
                not_rejected.append('byte %d bit %d (%s): verifier %s exit %d; oracle %s/%s' % (byte, bit, field_of(byte), word, code, cls, cause))
            _, sink_code = W.sink_summary(sink, data, sink_ratchet)
            region = 'last record' if byte >= len(base) - W.REC else 'records 0..2'
            sink_by_region[(region, sink_code)] += 1
    failures += flips['verifier_not_rejected'] + (flips['oracle_rejected'] != flips['total'])
    print('BITS flipped=%d verifier_rejected=%d verifier_not_rejected=%d oracle_rejected=%d'
          % (flips['total'], flips['verifier_rejected'], flips['verifier_not_rejected'], flips['oracle_rejected']))
    for line in not_rejected:
        print('NOT REJECTED ' + line)
    for (region, code), n in sorted(sink_by_region.items(), key=str):
        print('SINK on flipped bits: %-13s sink exit %s: %d flips (ratchet at epoch %d)' % (region, code, n, count))

    # ---- 2. every truncation offset
    by_class, trap_b = Counter(), []
    for off in range(len(base) + 1):
        data = base[:off]
        cls, cause, code, word = judge('truncate at %d' % off, data)
        sink_text, sink_code = W.sink_summary(sink, data, sink_ratchet) if off else ('sink not run on the empty file name check', None)
        by_class[('multiple of 64' if off % W.REC == 0 else 'inside a record', 'oracle ' + cls, 'verifier exit %s' % code)] += 1
        if off % W.REC == 0 and off > 0:
            k = off // W.REC - 1          # commits in the prefix
            full = k == count
            want = R.ACCEPT
            ok = cls == want and code == 0
            lines = ['TRAP B offset %d (%d commits): no anchor: oracle %s, verifier %s exit %s [want ACCEPT] %s | %s'
                     % (off, k, cls, word, code, 'ok' if ok else 'FAIL', sink_text)]
            failures += not ok
            for label, anchors in (('--expect-count %d' % count, {'expect_count': count}), ('--expect-tip <full tip>', {'expect_tip': tip}),
                                   ('--ratchet <full, epoch %d>' % count, {'ratchet': ratchet})):
                acls, acause, acode, aword = judge('truncate at %d %s' % (off, label), data, **anchors)
                awant = R.ACCEPT if full else R.REJECT
                aok = acls == awant and acode == ORACLE_EXIT[awant]
                failures += not aok
                lines.append('TRAP B offset %d %-26s oracle %s/%s, verifier %s exit %s [want %s] %s' % (off, label, acls, acause, aword, acode, awant, 'ok' if aok else 'FAIL'))
            trap_b.extend(lines)
    for line in trap_b:
        print(line)
    for key, n in sorted(by_class.items()):
        print('OFFSETS %-16s %-20s %-18s %d' % (key + (n,)))
    print('OFFSETS total=%d' % (len(base) + 1))

    # ---- summary
    for (cause, want, word), n in sorted(name_diffs.items(), key=str):
        print('NAME DIFFERS (same class; decided policy 7: compared by class) %d cases: oracle cause %s -> table %s; verifier %s' % (n, cause, want, word))
    for line in class_diffs[:60]:
        print('CLASS DISAGREEMENT ' + line)
    if len(class_diffs) > 60:
        print('CLASS DISAGREEMENT ... %d more' % (len(class_diffs) - 60))
    print('COUNTS class_disagreements=%d name_differences=%d not_run=%d assertion_failures=%d'
          % (len(class_diffs), sum(name_diffs.values()), not_run, failures))
    ok = not class_diffs and not not_run and not failures
    shutil.rmtree(work, ignore_errors=True)
    print('EXHAUSTIVE %s; FINITE TEST; end_to_end=false' % ('PASSED' if ok else 'FAILED'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
