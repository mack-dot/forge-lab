#!/usr/bin/env python3
"""Task V1, FORGE worker: negative controls of the compiled refund-log verifier. FINITE TEST. end_to_end=false.

  python3 tests/refund_log_verifier/test_negative_controls.py <verifier> [--sink <native_sink>] [--standin]

Each control builds a ledger (from a log that the REAL sink wrote, then changed with wal_forge.py with every
integrity field recomputed where the case says so), takes the expected verdict CLASS from ref_fold.py (the
independent oracle), runs the verifier and compares. It ALSO runs the real sink (`state`) on the same two files
(in a copy) and prints what the sink does: a log that the sink accepts and the verifier rejects, or the reverse,
is printed with the tag SINK-DIFFERS (a finding, not a failure of this suite). A verifier/oracle disagreement is
DISAGREE and fails the suite (exit 1). A case that cannot run is NOT RUN and fails the suite.
--standin: the verifier prints the oracle's own names (CLASS_CAUSE): the table below is not used.
"""

import argparse
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import wal_forge as W  # noqa: E402
import ref_fold as R  # noqa: E402

# THE ONE TABLE: oracle cause (ref_fold.py) -> verdict name in verifier/refund_log/VERDICTS.md.
# '@0' = the cause is at record 0 (CORE names every genesis-content fault REJECT_BAD_GENESIS).
# No name here is invented: every string is copied from VERDICTS.md. Policy rows: ref_fold.py DECIDED POLICY.
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
EXIT_OF = R.EXIT
SINK_ACCEPTS = 0


def table_key(cls, cause, details):
    if cause is None:
        return cls
    return cause + ('@0' if details.get('record') == 0 and cause in ('EPOCH', 'CHAIN', 'KIND') else '')


def expected_name(cls, cause, details, standin):
    if standin:
        return cls if cause is None else cls + '_' + cause
    return VERDICT_TABLE[table_key(cls, cause, details)]


class Suite:
    def __init__(self, verifier, sink, standin):
        self.verifier, self.sink, self.standin = verifier, sink, standin
        self.counts = {'agree': 0, 'disagree': 0, 'not_run': 0, 'sink_differs': 0}
        self.disagreements, self.sink_findings = [], []

    def case(self, name, wal, ratchet=None, sink_ratchet='auto', expect=None, measure=False, **anchors):
        """expect: the class the TEST asserts from first principles (checked against the oracle, too)."""
        cls, cause, det = R.verdict(wal, ratchet, anchors.get('expect_count'), anchors.get('expect_tip'))
        want_name = expected_name(cls, cause, det, self.standin)
        oracle = cls + ('' if cause is None else '/' + cause)
        if expect is not None and expect != cls:
            print('NOT RUN  %-44s the test asserts %s but the oracle says %s: the oracle or the test is wrong' % (name, expect, oracle))
            self.counts['not_run'] += 1
            return
        try:
            code, word, line, rss = W.run_verifier(self.verifier, wal, ratchet, anchors.get('expect_count'), anchors.get('expect_tip'), measure=measure)
        except Exception as error:  # noqa: BLE001  (a case that cannot run is NOT RUN)
            print('NOT RUN  %-44s verifier did not run: %s' % (name, error))
            self.counts['not_run'] += 1
            return
        agree = code == EXIT_OF[cls] and (want_name is None or word == want_name)
        if sink_ratchet == 'auto':
            sink_ratchet = ratchet if ratchet is not None else W.honest_ratchet(max(0, len(wal) // W.REC - 1))
        try:
            sink_text, sink_code = W.sink_summary(self.sink, wal, sink_ratchet)
        except Exception as error:  # noqa: BLE001
            sink_text, sink_code = 'sink did not run: %s' % error, None
            self.counts['not_run'] += 1
        sink_tag = ''
        if sink_code is not None and not anchors and (sink_code == SINK_ACCEPTS) != (code in (0, 4)):   # the sink has no count/tip anchor
            sink_tag = ' SINK-DIFFERS'
            self.counts['sink_differs'] += 1
            self.sink_findings.append('%s: verifier %s exit %d; %s' % (name, word, code, sink_text))
        self.counts['agree' if agree else 'disagree'] += 1
        if not agree:
            self.disagreements.append('%s: oracle %s (expected name %s, exit %d); verifier %s exit %d' % (name, oracle, want_name, EXIT_OF[cls], word or '<none>', code))
        extra = '' if rss is None else ' peak_rss=%d' % rss
        print('%-8s %-44s oracle %-30s verifier %-30s exit %d | %s%s%s' % ('AGREE' if agree else 'DISAGREE', name, oracle, word or '<none>', code, sink_text, sink_tag, extra))


def main():
    p = argparse.ArgumentParser()
    p.add_argument('verifier')
    p.add_argument('--sink')
    p.add_argument('--standin', action='store_true')
    a = p.parse_args()
    if not (Path(a.verifier).is_file() and os.access(a.verifier, os.X_OK)):
        print('NOT RUN: the verifier %s does not exist or is not executable; FAILED; end_to_end=false' % a.verifier)
        return 1
    work = Path(tempfile.mkdtemp(prefix='forge-controls-'))
    sink = a.sink or str(W.build_sink(work))
    refund = W.private_refund_binary(work / 'bin')
    S = Suite(str(Path(a.verifier).resolve()), str(Path(sink).resolve()), a.standin)
    print('FORGE negative controls; verifier %s; sink %s; oracle ref_fold.py; FINITE TEST; end_to_end=false' % (a.verifier, sink))

    # the base: a log that the REAL sink wrote (5 records, 4 commits, remaining 0)
    commits = [('returned_item', 'rq-1', 100), ('duplicate_charge', 'rq-2', 0), ('service_not_delivered', 'rq-3', 300), ('returned_item', 'rq-4', 600)]
    base, base_ratchet, _, tails = W.real_store(sink, refund, work / 'base', 'charge-1', 1000, commits)
    recs = W.records_of(base)
    tip = tails[-1]
    assert base == W.honest_log('charge-1', 1000, commits) and W.tip_hex(base) == tip
    j = b''.join

    S.case('positive: real sink log', base, expect=R.ACCEPT)
    S.case('positive: real sink log, real ratchet', base, ratchet=base_ratchet, expect=R.ACCEPT)
    S.case('positive: all anchors right', base, ratchet=base_ratchet, expect=R.ACCEPT, expect_count=4, expect_tip=tip)
    S.case('positive: genesis only', recs[0], expect=R.ACCEPT)

    # duplicate request id, CRC and chain consistent
    dup_last = W.forge_log('charge-1', 1000, commits[:3] + [('returned_item', 'rq-1', 1)])
    dup_mid = W.forge_log('charge-1', 1000, [commits[0], ('returned_item', 'rq-1', 1)] + commits[2:])
    S.case('duplicate id (last record), forged', dup_last, expect=R.REJECT)
    S.case('duplicate id (middle record), forged', dup_mid, expect=R.REJECT)
    S.case('duplicate id = charge id (allowed)', W.forge_log('charge-1', 1000, [('returned_item', 'charge-1', 1)]), expect=R.ACCEPT)

    # over-refund with consistent later fields
    S.case('over-refund then valid records, forged', W.forge_log('charge-1', 1000, [('returned_item', 'rq-1', 1001), ('returned_item', 'rq-2', 0)]), expect=R.REJECT)
    S.case('over-refund by 1 at the last record', W.forge_log('charge-1', 1000, commits[:3] + [('returned_item', 'rq-4', 601)]), expect=R.REJECT)

    # Trap C: the amount field is UNSIGNED u64 (sink.rs l.70, l.86): no negative amount is expressible
    M = W.MAX_MONEY
    for amount, exp in ((0, R.ACCEPT), (1, R.ACCEPT), (M, R.ACCEPT), (M + 1, R.REJECT), (W.U64, R.REJECT)):
        S.case('Trap C commit amount %d (original 2^63-1)' % amount, W.forge_log('c', M, [('returned_item', 'r', amount)]), expect=exp)
    for original, exp in ((0, R.ACCEPT), (1, R.ACCEPT), (M, R.ACCEPT), (M + 1, R.REJECT), (W.U64, R.REJECT)):
        S.case('Trap C genesis original %d' % original, W.forge_log('c', original, []), expect=exp)
    S.case('Trap C sum wraps u64: 2^63 + 2^63 (=0 mod 2^64)', W.forge_log('c', M, [('returned_item', 'a', 1 << 63), ('returned_item', 'b', 1 << 63)]), expect=R.REJECT)
    S.case('Trap C sum 2^63-1 then 1 (above original)', W.forge_log('c', M, [('returned_item', 'a', M), ('returned_item', 'b', 1)]), expect=R.REJECT)
    S.case('Trap C 2^64-1 then 1 (u64 sum wraps to 0)', W.forge_log('c', 10, [('returned_item', 'a', W.U64), ('returned_item', 'b', 1)]), expect=R.REJECT)
    S.case('Trap C remaining-amount would wrap (10-11)', W.forge_log('c', 10, [('returned_item', 'a', 11)]), expect=R.REJECT)
    S.case('Trap C many zeros then MaxMoney exactly', W.forge_log('c', M, [('returned_item', 'z%d' % i, 0) for i in range(5)] + [('returned_item', 'm', M)]), expect=R.ACCEPT)

    # reason outside the allowed set: the reason is only the kind byte (sink.rs l.8, l.92)
    for kind in (b'0', b'4', b'G', b'\x00', b'\xff', b'g'):
        S.case('reason kind byte %r at record 2' % kind, W.forge_log('charge-1', 1000, [commits[0], (kind[0], 'rq-2', 0)]), expect=R.REJECT)
    S.case('genesis kind byte 1 (not G)', W.forge_log('charge-1', 1000, [], charge_kind=ord('1')), expect=R.REJECT)

    # empty ids
    S.case('empty request id', W.forge_log('charge-1', 1000, [('returned_item', b'', 1)]), expect=R.REJECT)
    S.case('empty charge id', W.forge_log(b'', 1000, []), expect=R.REJECT)
    S.case('id with a space', W.forge_log('charge-1', 1000, [('returned_item', b'a b', 1)]), expect=R.REJECT)
    S.case('id with byte 0x80', W.forge_log('charge-1', 1000, [('returned_item', b'a\x80', 1)]), expect=R.REJECT)
    S.case('id of 24 bytes (no NUL at all)', W.forge_log('charge-1', 1000, [('returned_item', 'x' * 24, 1)]), expect=R.ACCEPT)
    print('NOTE     %-44s the WAL has NO remaining field: a record holds only its amount (sink.rs l.7-11, l.64-74); '
          'remaining is a fold value only (STATE line). Nothing to forge in the bytes.' % 'stated remaining not matching')

    # epoch gap and repeat (CRC recomputed; chain recomputed over the changed record)
    def with_epoch(index, epoch):
        rs = [bytearray(r) for r in recs]
        rs[index][4:12] = epoch.to_bytes(8, 'little')
        return j(W.rechain(rs, epochs=False))
    S.case('epoch gap (record 2 says 3)', with_epoch(2, 3), expect=R.REJECT)
    S.case('epoch repeat (record 2 says 1)', with_epoch(2, 1), expect=R.REJECT)
    S.case('epoch of genesis 1', with_epoch(0, 1), expect=R.REJECT)
    S.case('epoch 2^64-1 at record 1', with_epoch(1, W.U64), expect=R.REJECT)

    # chain break (CRC recomputed)
    def with_pre(index, pre):
        rs = [bytearray(r) for r in recs]
        rs[index][12:28] = pre.to_bytes(16, 'little')
        return j([bytes(r) for r in rs[:index]] + [W.reseal(rs[index])] + W.rechain(rs[index + 1:], epochs=False, start_tail=W.fnv128(W.reseal(rs[index]))))
    S.case('chain break at record 2 (later chain fixed)', with_pre(2, 12345), expect=R.REJECT)
    S.case('genesis pre_state_hash not 0', with_pre(0, 1), expect=R.REJECT)
    S.case('chain value stored big-endian at record 1', with_pre(1, int.from_bytes(W.fnv128(recs[0]).to_bytes(16, 'little'), 'big')), expect=R.REJECT)

    # record removed from the middle
    removed = recs[:2] + recs[3:]
    S.case('record 2 removed, nothing recomputed', j(removed), expect=R.REJECT)
    S.case('record 2 removed, epoch+chain+CRC recomputed', j(W.rechain(removed)), expect=R.ACCEPT)
    S.case('  same, --expect-count 4', j(W.rechain(removed)), expect=R.REJECT, expect_count=4)
    S.case('  same, --expect-tip of the real log', j(W.rechain(removed)), expect=R.REJECT, expect_tip=tip)
    S.case('  same, real ratchet (epoch 4)', j(W.rechain(removed)), ratchet=base_ratchet, expect=R.REJECT)

    # two records swapped
    swapped = recs[:2] + [recs[3], recs[2]] + recs[4:]
    S.case('records 2,3 swapped, nothing recomputed', j(swapped), expect=R.REJECT)
    S.case('records 2,3 swapped, all recomputed', j(W.rechain(swapped)), expect=R.ACCEPT)
    S.case('  same, --expect-tip of the real log', j(W.rechain(swapped)), expect=R.REJECT, expect_tip=tip)
    S.case('  same, --expect-count 4 (cannot see a swap)', j(W.rechain(swapped)), expect=R.ACCEPT, expect_count=4)
    S.case('records 3,4 swapped, all recomputed (still valid)', j(W.rechain(recs[:3] + [recs[4], recs[3]])), expect=R.ACCEPT)

    # different genesis
    S.case('different charge id, all recomputed', j(W.rechain([W.genesis('charge-2', 1000)] + recs[1:])), expect=R.ACCEPT)
    S.case('  same, --expect-tip of the real log', j(W.rechain([W.genesis('charge-2', 1000)] + recs[1:])), expect=R.REJECT, expect_tip=tip)
    S.case('smaller original, all recomputed', j(W.rechain([W.genesis('charge-1', 999)] + recs[1:])), expect=R.REJECT)
    S.case('genesis replaced, chain not recomputed', j([W.genesis('charge-2', 1000)] + recs[1:]), expect=R.REJECT)

    # canonical decoding: a non-zero byte in EVERY padding position (id NUL padding), CRC and chain recomputed
    for index in (0, 1):
        ident_len = len(W.decode(recs[index])['id'])
        for pos in range(28 + ident_len, 52):
            for value in (0x01, 0x41):
                rs = [bytearray(r) for r in recs]
                rs[index][pos] = value
                # 0x41 ('A') right after the id is NOT padding: it makes a canonical id one byte longer (another valid history)
                first = pos == 28 + ident_len and value == 0x41
                S.case('%s byte %d of record %d = 0x%02x' % ('id+1 (longer id)' if first else 'padding', pos, index, value), j(W.rechain(rs)),
                       expect=R.ACCEPT if first else R.REJECT)
    S.case('id field all NUL then 0x41 at byte 51 (record 1)', j(W.rechain([recs[0], W.raw_record(ord('3'), 1, 0, b'', 1, id_field=b'\0' * 23 + b'A')])), expect=R.REJECT)
    S.case('magic "FSX" at record 1, all recomputed', j(W.rechain([recs[0], W.raw_record(ord('3'), 1, 0, 'rq-1', 1, magic=b'FSX')])), expect=R.REJECT)

    # trailing garbage, empty, one byte
    for label, extra in (('1 NUL', b'\0'), ('63 x 0xff', b'\xff' * 63), ('64 NUL', b'\0' * 64), ('record 1 again', recs[1]), ('65 x 0xff', b'\xff' * 65)):
        S.case('trailing %s after the real log' % label, base + extra, sink_ratchet=base_ratchet, expect=R.ACCEPT_TORN_TAIL if len(extra) < 64 else R.REJECT)
    # a forged LAST record that the engine did not ratchet: the sink reads it as a torn tail and cuts it (sink.rs l.95-98, l.119-121)
    S.case('duplicate id last record, ratchet at 3 (sink)', dup_last, sink_ratchet=W.honest_ratchet(3), expect=R.REJECT)
    S.case('over-refund last record, ratchet at 3 (sink)', W.forge_log('charge-1', 1000, commits[:3] + [('returned_item', 'rq-4', 601)]),
           sink_ratchet=W.honest_ratchet(3), expect=R.REJECT)
    S.case('empty file', b'', expect=R.UNVERIFIABLE)
    S.case('one byte', b'F', expect=R.UNVERIFIABLE)
    S.case('genesis minus 1 byte', recs[0][:63], expect=R.UNVERIFIABLE)
    S.case('genesis plus 1 byte', recs[0] + b'\0', expect=R.ACCEPT_TORN_TAIL)

    # ratchet ahead, behind and malformed
    S.case('ratchet ahead of the log (5 > 4)', base, ratchet=W.ratchet_bytes(range(6)), expect=R.REJECT)
    S.case('ratchet ahead, single entry 2^64-1', base, ratchet=W.ratchet_bytes([W.U64]), expect=R.REJECT)
    S.case('ratchet behind the log (2 < 4)', base, ratchet=W.ratchet_bytes(range(3)), expect=R.ACCEPT)
    S.case('ratchet equal, last entry lower (max counts)', base, ratchet=W.ratchet_bytes([4, 1]), expect=R.ACCEPT)
    S.case('ratchet with a torn 5-byte tail', base, ratchet=base_ratchet + b'\x05\0\0\0\0', expect=R.ACCEPT_TORN_TAIL)
    S.case('ratchet with one bad-CRC entry (epoch 9)', base, ratchet=base_ratchet + W.ratchet_entry(9, crc=0), expect=R.REJECT)
    S.case('ratchet empty file', base, ratchet=b'', expect=R.REJECT)
    S.case('ratchet of 11 bytes (no whole entry)', base, ratchet=base_ratchet[:11], expect=R.REJECT)
    S.case('ratchet with only bad entries', base, ratchet=W.ratchet_entry(4, crc=1), expect=R.REJECT)

    # huge logs: bounded memory (peak RSS of the verifier, measured with /usr/bin/time -l)
    for n in (65535, 65536):   # 65,536 records is CORE's stated bound (VERDICTS.md); the second is one record above it
        huge = W.honest_log('charge-1', W.MAX_MONEY, [('returned_item', 'r%d' % i, 0) for i in range(n)])
        S.case('huge log: %d commits (%d bytes)' % (n, len(huge)), huge, expect=R.ACCEPT if n < 65536 else R.UNVERIFIABLE, measure=True)

    # hash-collision logs: 4,000 distinct ids with ONE value of the base-31 polynomial hash (so also mod 65536).
    # 31*ord(a)+ord(b) is 2134 for each of the blocks "Aw", "BX", "C9"; 12 blocks = 24 bytes, 3^12 ids in [A-Za-z0-9_-].
    blocks = ('Aw', 'BX', 'C9')
    ids = [''.join(blocks[(k // 3 ** p) % 3] for p in range(12)) for k in range(4000)]
    poly = lambda t: sum(ord(ch) * 31 ** (len(t) - 1 - i) for i, ch in enumerate(t))  # noqa: E731
    assert len(set(ids)) == 4000 and len({poly(t) % 65536 for t in ids}) == 1 and len({poly(t) for t in ids}) == 1
    colliding = W.honest_log('charge-1', 1000, [('returned_item', t, 0) for t in ids])
    for label, data, exp in (('hash collisions: 4000 distinct ids', colliding, R.ACCEPT),
                             ('hash collisions: + ids[1234] again (index 4001)',
                              W.honest_log('charge-1', 1000, [('returned_item', t, 0) for t in ids + [ids[1234]]]), R.REJECT)):
        started = time.monotonic()
        S.case(label, data, expect=exp)
        print('TIME     %-44s %.2f s (oracle + verifier + sink)' % (label, time.monotonic() - started))
    word = W.run_verifier(S.verifier, W.honest_log('charge-1', 1000, [('returned_item', t, 0) for t in ids + [ids[1234]]]))[2]
    at = 'index=4001' in word.split()
    S.counts['agree' if at else 'disagree'] += 1
    if not at:
        S.disagreements.append('hash collisions duplicate: expected index=4001; verifier line %s' % word[:120])
    print('%-8s %-44s verifier line names index=4001: %s' % ('AGREE' if at else 'DISAGREE', 'hash collisions: index of the duplicate', at))

    # repeatability: the same input 5 times gives the same verdict line (the settled-id table is keyed per run)
    for label, data in (('repeat: accepted log x5', base), ('repeat: rejected log x5', dup_mid), ('repeat: collision duplicate x5', W.honest_log('charge-1', 1000, [('returned_item', t, 0) for t in ids + [ids[0]]]))):
        lines = [W.run_verifier(S.verifier, data)[2] for _ in range(5)]
        same = len(set(lines)) == 1 and lines[0] != ''
        S.counts['agree' if same else 'disagree'] += 1
        if not same:
            S.disagreements.append('%s: %d different verdict lines' % (label, len(set(lines))))
        print('%-8s %-44s 5 runs, %d distinct verdict line(s): %s' % ('AGREE' if same else 'DISAGREE', label, len(set(lines)), lines[0][:60]))

    c = S.counts
    print('COUNTS agree=%d disagree=%d not_run=%d sink_differs=%d' % (c['agree'], c['disagree'], c['not_run'], c['sink_differs']))
    for d in S.disagreements:
        print('DISAGREEMENT ' + d)
    for f in S.sink_findings:
        print('SINK FINDING ' + f)
    ok = c['disagree'] == 0 and c['not_run'] == 0
    shutil.rmtree(work, ignore_errors=True)
    print('NEGATIVE_CONTROLS %s; FINITE TEST; end_to_end=false' % ('PASSED' if ok else 'FAILED'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
