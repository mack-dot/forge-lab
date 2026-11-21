#!/usr/bin/env python3
"""Task V1, FORGE worker: an INDEPENDENT encoder, reader and forger of the silicon sink's two ledger files.

Written from src/silicon_sink/sink.rs ALONE (not from verifier/refund_log/FORMAT.md, not from any Dafny file).
Python standard library only. FINITE TEST tooling; it proves nothing. end_to_end=false.

The format as read from sink.rs (line numbers of sink.rs):
  ledger.wal: a sequence of 64-byte records, no file header, no footer (REC, l.22; doc l.7-11).
    [0..3)   b"FSW"                                     (l.66)
    [3]      kind: b'G' genesis; b'1'..b'3' = 1 + index into REASONS (l.25, l.172, l.224)
    [4..12)  epoch, u64 little-endian; MUST equal the record index i (l.67, l.87)
    [12..28) pre_state_hash, u128 little-endian = FNV-1a-128 of the previous 64-byte record; 0 in record 0
             (l.68, l.87: compared with l.tail, which is 0 before the first record and fnv128(r) after it, l.96)
    [28..52) id, 1..24 bytes of [A-Za-z0-9_-], then NUL bytes to byte 52 (l.69, l.85, l.88); genesis: the charge id;
             commit: the request id
    [52..60) amount, u64 little-endian (l.70); genesis: the original amount (<= MAX_MONEY, l.90); commit: the
             refunded amount (<= remaining, l.92)
    [60..64) CRC-32/IEEE (reflected 0xEDB88320, init and final xor 0xFFFFFFFF) of bytes 0..60, little-endian (l.43-50, l.71)
  ledger.epoch (the ratchet): a sequence of 12-byte entries: u64 epoch little-endian, then CRC-32 of those 8 bytes,
    little-endian (push, l.101-104). The value of the ratchet is the MAXIMUM epoch of the entries whose CRC is right;
    a torn last entry (length % 12) and bad entries are ignored (l.114-115).
  The "tail" (state hash) that COMMITTED and STATE print is fnv128(last record) as 32 lowercase hex digits of the
  INTEGER (big-endian text, `{:032x}`, l.187, l.231, l.239); inside the next record the same value is stored
  little-endian (l.68).
"""

import os
import shutil
import signal
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

REC = 64
ENTRY = 12
MAX_MONEY = 9223372036854775807
REASONS = ('duplicate_charge', 'service_not_delivered', 'returned_item')
MAGIC = b'FSW'
GENESIS = ord('G')
U64 = (1 << 64) - 1
FNV_OFFSET = 0x6c62272e07bb014262b821756295c58d
FNV_PRIME = 0x0000000001000000000000000000013b
ID_BYTES = frozenset(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-')
ROOT = Path(__file__).resolve().parents[2]
REFUND_ARTIFACT = ROOT / 'proposals/forge2-m1-conformance/artifacts/refund-arm64-macho'


# ---------------------------------------------------------------- primitives

def crc32(data):
    """CRC-32/IEEE written out bit by bit as sink.rs l.43-50 does (zlib.crc32 is checked equal in the self-test)."""
    c = 0xFFFFFFFF
    for b in data:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ 0xEDB88320 if c & 1 else c >> 1
    return c ^ 0xFFFFFFFF


def crc32_fast(data):
    return zlib.crc32(bytes(data)) & 0xFFFFFFFF


def fnv128(data):
    h = FNV_OFFSET
    for b in data:
        h = ((h ^ b) * FNV_PRIME) & ((1 << 128) - 1)
    return h


def kind_of_reason(reason):
    return ord('1') + REASONS.index(reason)


def canonical_id(raw):
    return 1 <= len(raw) <= 24 and all(b in ID_BYTES for b in raw)


# ---------------------------------------------------------------- raw encoding (no validation: a forging primitive)

def raw_record(kind, epoch, pre, ident, amount, crc=None, id_field=None, magic=MAGIC):
    """Any 64 bytes the format can express. `ident` is put at [28..) and NUL-padded to 24 bytes, unless `id_field`
    (exactly 24 bytes) is given. kind is an int 0..255 or a one-byte bytes. epoch, amount: 0..2^64-1; pre: 0..2^128-1.
    crc=None computes the right CRC; an int is written as given."""
    if isinstance(kind, (bytes, bytearray)):
        kind = kind[0]
    if isinstance(ident, str):
        ident = ident.encode()
    field = bytes(id_field) if id_field is not None else bytes(ident).ljust(24, b'\0')
    assert len(field) == 24 and len(magic) == 3
    body = bytes(magic) + bytes([kind]) + epoch.to_bytes(8, 'little') + pre.to_bytes(16, 'little') + field + amount.to_bytes(8, 'little')
    assert len(body) == 60
    return body + (crc32_fast(body) if crc is None else crc).to_bytes(4, 'little')


def reseal(record):
    """The same 64 bytes with the CRC recomputed over bytes 0..60."""
    record = bytes(record)
    return record[:60] + crc32_fast(record[:60]).to_bytes(4, 'little')


def genesis(charge, original):
    return raw_record(GENESIS, 0, 0, charge, original)


def honest_log(charge, original, commits):
    """The bytes that an honest sink writes: init(charge, original), then one record per commit.
    commits: [(reason, request_id, amount)]. No eligibility check is made here: see `ref_fold.py`."""
    out = [genesis(charge, original)]
    for i, (reason, rid, amount) in enumerate(commits, start=1):
        out.append(raw_record(kind_of_reason(reason) if isinstance(reason, str) else reason, i, fnv128(out[-1]), rid, amount))
    return b''.join(out)


def rechain(records, epochs=True, chain=True, crc=True, start_epoch=0, start_tail=0):
    """FORGING: takes a list of 64-byte records (any content) and recomputes, in order, every integrity field that the
    format has: the epoch (= index), the pre_state_hash (= fnv128 of the previous record as rewritten) and the CRC.
    The result is exactly what a buggy or compromised engine that keeps the format's bookkeeping right could write."""
    out, tail = [], start_tail
    for i, r in enumerate(records):
        r = bytearray(r)
        assert len(r) == REC
        if epochs:
            r[4:12] = (start_epoch + i).to_bytes(8, 'little')
        if chain:
            r[12:28] = tail.to_bytes(16, 'little')
        if crc:
            r[60:64] = crc32_fast(r[:60]).to_bytes(4, 'little')
        out.append(bytes(r))
        tail = fnv128(r)
    return out


def forge_log(charge, original, commits, charge_kind=GENESIS):
    """FORGING: a log whose records carry any kind, id and amount (ints and bytes as given, no rule applied), with
    every integrity field consistent. commits: [(kind or reason, id bytes/str, amount)]."""
    recs = [raw_record(charge_kind, 0, 0, charge, original)]
    for kind, rid, amount in commits:
        recs.append(raw_record(kind_of_reason(kind) if isinstance(kind, str) else kind, 0, 0, rid, amount))
    return b''.join(rechain(recs))


def records_of(data):
    return [bytes(data[i:i + REC]) for i in range(0, len(data) - len(data) % REC, REC)]


def tip_hex(data):
    """The state hash as the sink prints it: fnv128 of the last whole record, `{:032x}`."""
    recs = records_of(data)
    return '%032x' % fnv128(recs[-1]) if recs else None


# ---------------------------------------------------------------- reading

def decode(record):
    """Field view of 64 bytes, no validation."""
    r = bytes(record)
    field = r[28:52]
    ident = field.split(b'\0', 1)[0]
    return {'magic': r[:3], 'kind': r[3], 'epoch': int.from_bytes(r[4:12], 'little'), 'pre': int.from_bytes(r[12:28], 'little'),
            'id_field': field, 'id': ident, 'padding': field[len(ident):], 'amount': int.from_bytes(r[52:60], 'little'),
            'crc': int.from_bytes(r[60:64], 'little'), 'crc_ok': int.from_bytes(r[60:64], 'little') == crc32_fast(r[:60])}


def read_wal(data):
    """(records as field dicts, trailing bytes that are not a whole record)."""
    return [decode(r) for r in records_of(data)], bytes(data[len(data) - len(data) % REC:])


def ratchet_entry(epoch, crc=None):
    e = epoch.to_bytes(8, 'little')
    return e + (crc32_fast(e) if crc is None else crc).to_bytes(4, 'little')


def ratchet_bytes(epochs):
    return b''.join(ratchet_entry(e) for e in epochs)


def honest_ratchet(last_epoch):
    """What the sink writes: one entry per init/commit/repair. The value is the maximum valid entry."""
    return ratchet_bytes(range(last_epoch + 1))


def read_ratchet(data):
    """(max epoch of valid entries or None, number of valid entries, number of bad entries, torn tail length)."""
    whole = [data[i:i + ENTRY] for i in range(0, len(data) - len(data) % ENTRY, ENTRY)]
    valid = [int.from_bytes(e[:8], 'little') for e in whole if int.from_bytes(e[8:], 'little') == crc32_fast(e[:8])]
    return (max(valid) if valid else None), len(valid), len(whole) - len(valid), len(data) % ENTRY


# ---------------------------------------------------------------- running the real sink

def run_group(argv, timeout=120, input=None, env=None):
    """Runs argv in its own process group; SIGKILL to the group on every exit path; bytes in and out."""
    p = subprocess.Popen([str(a) for a in argv], stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, env=env)
    try:
        out, err = p.communicate(input=input, timeout=timeout)
    finally:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except OSError:
            pass
        p.wait()
    return subprocess.CompletedProcess(argv, p.returncode, out, err)


def private_refund_binary(folder):
    """A 0700 copy of the tracked CakeML refund binary (the sink starts it per request)."""
    folder = Path(folder)
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    target = folder / 'refund'
    shutil.copyfile(REFUND_ARTIFACT, target)
    target.chmod(0o700)
    return target


def sink_open(sink, wal, ratchet, command='state'):
    """Puts the two files in a fresh folder and runs `<sink> <dir> state|replay` there (the sink may cut or append to
    them: that happens only in the copy). Returns (exit code, first stdout line, wal after, ratchet after)."""
    with tempfile.TemporaryDirectory(prefix='forge-sink-') as d:
        if wal is not None:
            Path(d, 'ledger.wal').write_bytes(wal)
        if ratchet is not None:
            Path(d, 'ledger.epoch').write_bytes(ratchet)
        done = run_group([sink, d, command], timeout=60)
        after_wal = Path(d, 'ledger.wal').read_bytes() if Path(d, 'ledger.wal').exists() else None
        after_r = Path(d, 'ledger.epoch').read_bytes() if Path(d, 'ledger.epoch').exists() else None
    first = done.stdout.decode('utf-8', 'replace').split('\n', 1)[0]
    return done.returncode, first, after_wal, after_r


def sink_summary(sink, wal, ratchet):
    code, line, after, _ = sink_open(sink, wal, ratchet)
    words = line.split(' ')
    if code == 0:
        cut = '' if after == wal else ' cut %d->%d bytes' % (len(wal), len(after))
        return 'sink exit 0 STATE epoch=%s remaining=%s%s' % (words[1], words[5], cut), code
    return 'sink exit %d %s' % (code, ' '.join(words[2:3])), code


def sink_request(state_line, charge, request, original, remaining, amount, reason):
    return ('%s (%s %s %d %d True True True %d %s)\n' % (state_line, charge, request, original, remaining, amount, reason)).encode()


def real_store(sink, refund, folder, charge, original, commits):
    """Makes a store with the REAL sink: init, then one serve per commit (each line names the present state).
    commits: [(reason, request_id, amount)] that the binary and the sink accept. Returns (wal bytes, ratchet bytes,
    the list of exit codes, the list of COMMITTED tails)."""
    folder = Path(folder)
    folder.mkdir(parents=True)
    init = run_group([sink, folder, 'init', charge, str(original)])
    if init.returncode != 0:
        raise RuntimeError('init exit %d %r' % (init.returncode, init.stdout))
    tail, remaining, codes, tails = init.stdout.split()[2].decode(), original, [init.returncode], [init.stdout.split()[2].decode()]
    for reason, rid, amount in commits:
        done = run_group([sink, folder, 'serve', refund], input=sink_request(tail, charge, rid, original, remaining, amount, reason))
        codes.append(done.returncode)
        if done.returncode != 0:
            raise RuntimeError('serve exit %d %r' % (done.returncode, done.stdout))
        tail = done.stdout.split()[2].decode()
        tails.append(tail)
        remaining -= amount
    return (folder / 'ledger.wal').read_bytes(), (folder / 'ledger.epoch').read_bytes(), codes, tails


def build_sink(out_dir):
    """Compiles src/silicon_sink/sink.rs with the directive's command (rustc from FORGE_RUSTC, else PATH)."""
    out = Path(out_dir) / 'native_sink'
    rustc = os.environ.get('FORGE_RUSTC') or shutil.which('rustc') or 'rustc'
    done = run_group([rustc, '-D', 'unsafe_code', '-C', 'opt-level=3', ROOT / 'src/silicon_sink/sink.rs', '-o', out], timeout=600)
    if done.returncode != 0:
        raise RuntimeError('sink build exit %d: %s' % (done.returncode, done.stderr[-800:]))
    return out


def run_verifier(verifier, wal, ratchet=None, expect_count=None, expect_tip=None, extra=(), measure=False):
    """Writes the bytes to a temp folder and runs `<verifier> ledger.wal [options]`.
    Returns (exit code, first word of stdout line 1, the whole line, peak RSS in bytes or None)."""
    with tempfile.TemporaryDirectory(prefix='forge-verify-') as d:
        argv = [verifier, Path(d, 'ledger.wal')]
        if wal is not None:
            Path(d, 'ledger.wal').write_bytes(wal)
        if ratchet is not None:
            Path(d, 'ledger.epoch').write_bytes(ratchet)
            argv += ['--ratchet', Path(d, 'ledger.epoch')]
        if expect_count is not None:
            argv += ['--expect-count', str(expect_count)]
        if expect_tip is not None:
            argv += ['--expect-tip', expect_tip]
        argv += list(extra)
        if measure:
            argv = ['/usr/bin/time', '-l'] + argv
        done = run_group(argv, timeout=600)
    line = done.stdout.decode('utf-8', 'replace').split('\n', 1)[0]
    rss = None
    if measure:
        for text in done.stderr.decode('utf-8', 'replace').splitlines():
            if 'maximum resident set size' in text:
                rss = int(text.split()[0])
    return done.returncode, (line.split(' ', 1)[0] if line else ''), line, rss


# ---------------------------------------------------------------- self-test against real bytes

SELF_TEST_STORES = [
    ('three', 'charge-1', 1000, [('returned_item', 'rq-1', 100), ('duplicate_charge', 'rq-2', 0), ('service_not_delivered', 'rq-3', 900)]),
    ('max_money', 'c_' + 'x' * 22, MAX_MONEY, [('returned_item', 'A' * 24, MAX_MONEY - 1), ('returned_item', 'b', 1)]),
    ('zero', 'z', 0, [('duplicate_charge', 'r0', 0), ('service_not_delivered', 'r-1', 0)]),
    ('same_id_as_charge', 'charge-9', 50, [('returned_item', 'charge-9', 50)]),
]


def self_test(sink):
    sink = str(Path(sink).resolve())
    lines, failures = [], 0
    if crc32(b'123456789') != 0xCBF43926 or any(crc32(bytes([i]) * i) != crc32_fast(bytes([i]) * i) for i in range(70)):
        print('FAIL crc32 does not match the CRC-32/IEEE check value or zlib')
        return 1
    print('ok   crc32 check value 0xCBF43926 and zlib agree on 70 vectors')
    work = Path(tempfile.mkdtemp(prefix='forge-selftest-'))
    try:
        refund = private_refund_binary(work / 'bin')
        for name, charge, original, commits in SELF_TEST_STORES:
            wal, ratchet, codes, tails = real_store(sink, refund, work / name, charge, original, commits)
            mine = honest_log(charge, original, commits)
            recs, rest = read_wal(wal)
            read_back = (rest == b'' and recs[0]['kind'] == GENESIS and recs[0]['id'].decode() == charge and recs[0]['amount'] == original
                         and [(REASONS[r['kind'] - ord('1')], r['id'].decode(), r['amount']) for r in recs[1:]] == list(commits)
                         and all(r['crc_ok'] and r['epoch'] == i and not any(r['padding']) for i, r in enumerate(recs)))
            my_tails = ['%032x' % fnv128(r) for r in records_of(mine)]
            r_max, r_valid, r_bad, r_torn = read_ratchet(ratchet)
            ok = (wal == mine and read_back and tails == my_tails and ratchet == honest_ratchet(len(commits))
                  and (r_max, r_bad, r_torn) == (len(commits), 0, 0))
            failures += not ok
            print('%s store %-17s %d records: wal byte-equal %s; read back %s; COMMITTED tails equal %s; ratchet byte-equal %s (max %s)'
                  % ('ok  ' if ok else 'FAIL', name, len(recs), wal == mine, read_back, tails == my_tails, ratchet == honest_ratchet(len(commits)), r_max))
            # a forged log with all integrity fields recomputed: rechain(honest records) must give the honest bytes
            same = b''.join(rechain(records_of(wal))) == wal
            failures += not same
            print('%s store %-17s rechain(real records) is the identity: %s' % ('ok  ' if same else 'FAIL', name, same))
        # refused attempts leave the bytes as they were (sink.rs l.32); my encoder writes nothing for them
        wal, ratchet, _, tails = real_store(sink, refund, work / 'refusals', 'charge-1', 100, [('returned_item', 'rq-1', 60)])
        before = (wal, ratchet)
        attempts = [sink_request(tails[-1], 'charge-1', 'rq-1', 100, 40, 1, 'returned_item'),     # duplicate id
                    sink_request(tails[-1], 'charge-1', 'rq-2', 100, 40, 41, 'returned_item'),    # above remaining (binary rejects)
                    sink_request(tails[0], 'charge-1', 'rq-3', 100, 100, 1, 'returned_item'),     # stale state hash
                    sink_request(tails[-1], 'charge-1', 'rq-4', 100, 40, 1, 'not_a_reason')]      # reason outside the set
        codes = [run_group([sink, work / 'refusals', 'serve', refund], input=a).returncode for a in attempts]
        after = ((work / 'refusals/ledger.wal').read_bytes(), (work / 'refusals/ledger.epoch').read_bytes())
        ok = after == before and all(c != 0 for c in codes) and after[0] == honest_log('charge-1', 100, [('returned_item', 'rq-1', 60)])
        failures += not ok
        print('%s refused attempts (exit codes %s) left both files byte-equal to the encoder: %s' % ('ok  ' if ok else 'FAIL', codes, ok))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    print('SELF_TEST %s (%d failures)' % ('PASSED' if failures == 0 else 'FAILED', failures))
    return 0 if failures == 0 else 1


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--self-test':
        sys.exit(self_test(sys.argv[2]))
    print('usage: wal_forge.py --self-test <sink binary>', file=sys.stderr)
    sys.exit(2)
