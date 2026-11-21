#!/usr/bin/env python3
"""Task V1, FORGE worker: an INDEPENDENT reference fold and byte checker for the silicon sink's ledger.wal.

Part 1 restates the ratified Step/Replay of spec/refund/RefundLogSpec.dfy over spec/refund/RefundSpec.dfy, from the
specification TEXT, with Python integers (no fixed width, no wrap). Owner decision D1 (unsure.md U928): the genesis
record initializes refundEnabled = true. D2: amount 0 is allowed.
Part 2 is the byte decoding of src/silicon_sink/sink.rs as wal_forge.py reads it, made strict: every integrity field
of every whole record must be right, every padding byte must be what the encoder writes. Inputs that neither the
format nor the specification settles follow the DECIDED POLICY table in Part 2 (orchestrator, 2026-11-20). It does NOT read CORE's code or FORMAT.md. It is the oracle of the differential tests. FINITE TEST tooling.

verdict(...) returns (CLASS, CAUSE, details). CLASS is ACCEPT, ACCEPT_TORN_TAIL, REJECT or UNVERIFIABLE. CAUSES lists the causes.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import wal_forge as W  # noqa: E402

# ---------------------------------------------------------------- Part 1: the specification, restated

MAX_MONEY = 9223372036854775807                     # RefundSpec.MaxMoney
ALLOWED_REASONS = frozenset({'duplicate_charge', 'service_not_delivered', 'returned_item'})


def money(v):                                       # RefundSpec.Money
    return 0 <= v <= MAX_MONEY


def genesis_state(charge_id, original, refund_enabled=True):   # RefundLogSpec.Genesis (D1: true for the verifier)
    return {'chargeId': charge_id, 'original': original, 'remaining': original, 'refundEnabled': refund_enabled,
            'settled': frozenset(), 'epoch': 0}


def well_formed(s):                                 # RefundLogSpec.WellFormed
    return s['chargeId'] != '' and money(s['original']) and 0 <= s['remaining'] <= s['original']


def valid_genesis(g):                               # RefundLogSpec.ValidGenesis
    return well_formed(g) and g == genesis_state(g['chargeId'], g['original'], g['refundEnabled'])


def valid_context(c):                               # RefundSpec.ValidContext
    return (c['chargeId'] != '' and c['requestId'] != '' and c['refundEnabled'] and c['requestOpen']
            and money(c['original']) and 0 <= c['remaining'] <= c['original'])


def eligible(c, amount, reason):                    # RefundSpec.Eligible with a Candidate response
    return valid_context(c) and 0 <= amount <= c['remaining'] and reason in ALLOWED_REASONS


def context_at(s, q):                               # RefundLogSpec.ContextAt
    return {'chargeId': s['chargeId'], 'requestId': q[0], 'original': s['original'], 'remaining': s['remaining'],
            'refundEnabled': s['refundEnabled'], 'requestOpen': q[0] not in s['settled']}


def allowed(s, q):                                  # RefundLogSpec.Allowed; q = (requestId, amount, reason)
    return eligible(context_at(s, q), q[1], q[2])


def step(s, q):                                     # RefundLogSpec.Step: None or the post-state
    if not allowed(s, q):
        return None
    return dict(s, remaining=s['remaining'] - q[1], settled=s['settled'] | {q[0]}, epoch=s['epoch'] + 1)


def replay(g, log):                                 # RefundLogSpec.Replay (iterative; same fold, left to right)
    s = g
    for q in log:
        s = step(s, q)
        if s is None:
            return None
    return s


def valid_history(g, log):                          # RefundLogSpec.ValidHistory
    return valid_genesis(g) and replay(g, log) is not None


def why_not_allowed(s, q):
    """The first conjunct of Allowed that fails (for the cause only; the decision is `allowed`)."""
    c = context_at(s, q)
    if c['requestId'] == '':
        return 'EMPTY_ID'
    if not c['requestOpen']:
        return 'DUPLICATE_ID'
    if q[2] not in ALLOWED_REASONS:
        return 'REASON'
    if not 0 <= q[1] <= c['remaining']:
        return 'OVER_REFUND'
    return 'CONTEXT'


# ---------------------------------------------------------------- Part 2: the bytes

# DECIDED POLICY (decided by the orchestrator, 2026-11-20). These are decisions about what the verifier answers for
# inputs that the format and the specification do not settle. They are NOT format facts and NOT spec causes: those
# stay independent of CORE (a difference there is a finding).
# | # | Input                                                   | Answer                                   |
# | 1 | WAL: >= 1 whole genesis, then 1..63 trailing bytes      | ACCEPT_TORN_TAIL (exit 4): the whole-record prefix is verified; the trailing bytes are not counted |
# | 2 | WAL: empty, or fewer than 64 bytes                      | UNVERIFIABLE (exit 3): no genesis to verify (EMPTY_FILE / NO_WHOLE_RECORD) |
# | 3 | ratchet: a whole entry with a bad CRC (not a torn end)  | REJECT RATCHET_BAD_ENTRY (stricter than the sink, which skips it) |
# | 4 | ratchet supplied with no whole entry                    | REJECT RATCHET_NO_ENTRY |
# | 5 | ratchet: a torn final part of 1..11 bytes               | ACCEPT_TORN_TAIL (if all else accepts) |
# | 6 | WAL above the record cap (65,536 records, 4,194,304 B); ratchet above 3,145,728 B | UNVERIFIABLE TOO_LARGE / RATCHET_TOO_LARGE (exit 3; a stated limit) |
# | 7 | order of checks inside a record: CRC before magic       | CORE's order; where only the cause NAME differs because of order, tests compare by class and list the case |
# Reading of 3 vs 4 for a ratchet whose whole entries ALL have bad CRCs: rule 3 (the more specific) applies, RATCHET_BAD_ENTRY.
MAX_RECORDS = 65536
MAX_WAL_BYTES = MAX_RECORDS * 64
MAX_RATCHET_BYTES = 3145728

ACCEPT, ACCEPT_TORN_TAIL, REJECT, UNVERIFIABLE = 'ACCEPT', 'ACCEPT_TORN_TAIL', 'REJECT', 'UNVERIFIABLE'
EXIT = {ACCEPT: 0, ACCEPT_TORN_TAIL: 4, REJECT: 1, UNVERIFIABLE: 3}
CAUSES = {
    REJECT: ['MAGIC',           # bytes 0..3 are not "FSW"
             'CRC',             # bytes 60..64 are not CRC-32 of bytes 0..60
             'EPOCH',           # bytes 4..12 are not the record index
             'CHAIN',           # bytes 12..28 are not fnv128 of the previous record (0 for record 0)
             'KIND',            # byte 3 of record 0 is not 'G', or byte 3 of a later record is 'G'
             'ID_ENCODING',     # an id that is not 1..24 bytes of [A-Za-z0-9_-] followed only by NUL bytes
             'GENESIS',         # ValidGenesis is false (empty charge id; original above MaxMoney)
             'EMPTY_ID', 'DUPLICATE_ID', 'REASON', 'OVER_REFUND', 'OVER_REFUND_NOT_MONEY',   # Step is None at this record
             'RATCHET_BAD_ENTRY', 'RATCHET_NO_ENTRY',                                       # policy 3, 4
             'EXPECT_COUNT', 'EXPECT_TIP', 'RATCHET_AHEAD'],                                # an anchor shows another history
    UNVERIFIABLE: ['EMPTY_FILE', 'NO_WHOLE_RECORD', 'TOO_LARGE', 'RATCHET_TOO_LARGE', 'UNREADABLE', 'BAD_ARGUMENT'],
}
KIND_REASON = {ord('1') + i: r for i, r in enumerate(W.REASONS)}


def decode_reason(kind):
    """byte 3 of a commit record -> the reason string of the request; a byte outside '1'..'3' has no approved reason.
    It is decoded to a string that is not in the approved set, so the SPEC refuses it (Step: AllowedReason)."""
    return KIND_REASON.get(kind, 'kind-0x%02x' % kind)


def fold_bytes(data):
    """Decoding of the WHOLE records plus the fold. Returns (cause or None, failing record index, state, tip)."""
    tail, state = 0, None
    for i in range(len(data) // W.REC):
        r = data[i * W.REC:(i + 1) * W.REC]
        f = W.decode(r)
        if not f['crc_ok']:
            return 'CRC', i, state, None
        if f['magic'] != W.MAGIC:
            return 'MAGIC', i, state, None
        if f['epoch'] != i:
            return 'EPOCH', i, state, None
        if f['pre'] != tail:
            return 'CHAIN', i, state, None
        if (i == 0) != (f['kind'] == W.GENESIS):
            return 'KIND', i, state, None
        ident = f['id']
        if any(f['padding']) or (ident and not W.canonical_id(ident)):
            return 'ID_ENCODING', i, state, None
        ident = ident.decode('ascii')
        if i == 0:
            if ident == '':
                return 'GENESIS', i, state, None   # chargeId != "" (WellFormed)
            state = genesis_state(ident, f['amount'], True)
            if not valid_genesis(state):
                return 'GENESIS', i, state, None
        else:
            q = (ident, f['amount'], decode_reason(f['kind']))
            nxt = step(state, q)
            if nxt is None:
                why = why_not_allowed(state, q)
                if why == 'OVER_REFUND' and not money(q[1]):
                    why = 'OVER_REFUND_NOT_MONEY'   # the same conjunct (amount <= remaining <= MaxMoney); named apart
                return why, i, state, None
            state = nxt
        tail = W.fnv128(r)
    return None, None, state, tail


def verdict(data, ratchet=None, expect_count=None, expect_tip=None):
    """The expected class for a byte string (and optional anchors). expect_count = the number of COMMIT records
    (= the final epoch); expect_tip = 32 lowercase hex digits of fnv128(last whole record), as the sink prints it."""
    data = bytes(data)
    if expect_tip is not None and (len(expect_tip) != 32 or any(ch not in '0123456789abcdef' for ch in expect_tip)):
        return UNVERIFIABLE, 'BAD_ARGUMENT', {}
    if expect_count is not None and not (isinstance(expect_count, int) and expect_count >= 0):
        return UNVERIFIABLE, 'BAD_ARGUMENT', {}
    if len(data) == 0:
        return UNVERIFIABLE, 'EMPTY_FILE', {}                       # policy 2
    if len(data) < W.REC:
        return UNVERIFIABLE, 'NO_WHOLE_RECORD', {}                  # policy 2
    if len(data) > MAX_WAL_BYTES:
        return UNVERIFIABLE, 'TOO_LARGE', {}                        # policy 6
    if ratchet is not None and len(ratchet) > MAX_RATCHET_BYTES:
        return UNVERIFIABLE, 'RATCHET_TOO_LARGE', {}                # policy 6
    torn = len(data) % W.REC
    cause, index, state, tip = fold_bytes(data[:len(data) - torn])
    if cause:
        return REJECT, cause, {'record': index}
    details = {'epoch': state['epoch'], 'remaining': state['remaining'], 'original': state['original'],
               'charge': state['chargeId'], 'tip': '%032x' % tip, 'torn_bytes': torn}
    if ratchet is not None:
        ratchet = bytes(ratchet)
        rtorn = len(ratchet) % W.ENTRY
        whole = [ratchet[k:k + W.ENTRY] for k in range(0, len(ratchet) - rtorn, W.ENTRY)]
        if any(int.from_bytes(e[8:], 'little') != W.crc32_fast(e[:8]) for e in whole):
            return REJECT, 'RATCHET_BAD_ENTRY', details             # policy 3
        if not whole:
            return REJECT, 'RATCHET_NO_ENTRY', details              # policy 4
        floor = max(int.from_bytes(e[:8], 'little') for e in whole)
        details.update(ratchet=floor, ratchet_torn_bytes=rtorn)
        torn = torn or rtorn                                        # policy 5
    else:
        floor = None
    if floor is not None and floor > state['epoch']:
        return REJECT, 'RATCHET_AHEAD', details
    if expect_count is not None and expect_count != state['epoch']:
        return REJECT, 'EXPECT_COUNT', details
    if expect_tip is not None and int(expect_tip, 16) != tip:
        return REJECT, 'EXPECT_TIP', details
    return (ACCEPT_TORN_TAIL if torn else ACCEPT), None, details    # policy 1, 5


def verdict_of_files(wal_path, ratchet_path=None, expect_count=None, expect_tip=None):
    try:
        data = Path(wal_path).read_bytes()
        ratchet = Path(ratchet_path).read_bytes() if ratchet_path else None
    except OSError:
        return UNVERIFIABLE, 'UNREADABLE', {}
    return verdict(data, ratchet, expect_count, expect_tip)


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser(description='reference verdict CLASS of a ledger.wal (FORGE oracle; not the verifier)')
    p.add_argument('wal')
    p.add_argument('--ratchet')
    p.add_argument('--expect-count', type=int)
    p.add_argument('--expect-tip')
    a = p.parse_args()
    cls, cause, det = verdict_of_files(a.wal, a.ratchet, a.expect_count, a.expect_tip)
    print(cls + ('' if cause is None else ' ' + cause), ' '.join('%s=%s' % kv for kv in sorted(det.items())))
    sys.exit(EXIT[cls])
