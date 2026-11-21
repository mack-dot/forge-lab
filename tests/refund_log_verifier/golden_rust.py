#!/usr/bin/env python3
"""Task V1, RUST worker: real Rust bytes for the refund-log verifier.

This library and CLI build the REAL native silicon sink (src/silicon_sink/sink.rs, read-only) and changed copies of it
(planted engine bugs), drive them exactly as tests/silicon_sink/test_silicon_crash.py does (init, serve with one request
line on stdin, state, replay; SIGKILL at the seam points of a `--cfg kill_points` build), and keep, per scenario:
the request lines sent, the answer lines received, the WAL and ratchet bytes, the sink's own view (state, replay) and
the GROUND TRUTH: the committed requests in commit order, taken from the sink's COMMITTED answer lines (for a killed
victim: from the kill-point table of the sink's own suite, confirmed by the sink's replay after its recovery).

Every build and every ledger lives in a work folder under build/ (ignored by git) or a given folder. Nothing in the
source tree is written. Python stdlib only. rustc comes from FORGE_RUSTC or PATH and must print the version that
scripts/exit_silicon_sink.py pins (RUSTC_VERSION); the compile flags are that script's (`-D unsafe_code -C
opt-level=3`, and `--cfg kill_points` for the kill build). Every child runs in its own process group, which gets
SIGKILL on every exit path. At most two processes run at a time (the sink and its refund binary).

FINITE TEST on one machine. It proves nothing about sink.rs. end_to_end=false.

CLI: golden_rust.py [--work DIR]  -> builds, produces every scenario and every planted-bug store, one line each.
Exit 0: every self-check passed. 1: a self-check failed. 2: the toolchain or the refund binary is not the pinned one.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time
import zlib

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'src/silicon_sink/sink.rs'
EXIT_SCRIPT = ROOT / 'scripts/exit_silicon_sink.py'
ARTIFACT = ROOT / 'proposals/forge2-m1-conformance/artifacts/refund-arm64-macho'
_PINS = EXIT_SCRIPT.read_text()
RUSTC_VERSION = re.search(r"^RUSTC_VERSION = '([^']+)'", _PINS, re.M).group(1)
ARTIFACT_SHA256 = re.search(r"^ARTIFACT_SHA256 = '([0-9a-f]{64})'", _PINS, re.M).group(1)
RUSTC_FLAGS = ['-D', 'unsafe_code', '-C', 'opt-level=3']  # BUILD_COMMAND[1:5] of scripts/exit_silicon_sink.py
ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}  # the environment of the sink in its own suite
REC, MAX_MONEY = 64, 9223372036854775807
REASONS = ['duplicate_charge', 'service_not_delivered', 'returned_item']
CODES = {0: 'COMMITTED', 2: 'USAGE', 10: 'CAKEML_REJECTED', 11: 'BAD_FRAME', 12: 'MALFORMED_ID', 13: 'STALE_STATE_HASH',
         14: 'DUPLICATE_REQUEST_ID', 15: 'EPOCH_REGRESSION', 16: 'MALFORMED_REQUEST', 17: 'CORRUPT_WAL', 18: 'IO_ERROR',
         19: 'OUTCOME_UNKNOWN', 20: 'DISPATCH_FAILED'}
# Seam points of sink.rs (`cut`), and whether the record is in the WAL after a kill there: the table COMMITTED_AT of
# tests/silicon_sink/test_silicon_crash.py. a: before the WAL write; b: inside the record (split); c: after the write,
# before the sync; r: after the WAL sync, before the ratchet; d: after both syncs, before the answer; e: inside the answer.
COMMITTED_AT = {'a': False, 'b': False, 'c': True, 'r': True, 'd': True, 'e': True}
FNV_OFFSET, FNV_PRIME, MASK128 = 0x6c62272e07bb014262b821756295c58d, 0x0000000001000000000000000000013b, (1 << 128) - 1
T, F = True, False


class Failed(Exception):
    pass


class ToolchainError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Failed(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------------------------------------------------
# A transcription of the record layout (sink.rs lines 7-11 and `encode`, lines 64-74). Used only to check that the WAL
# bytes are exactly the ground-truth history and to compute the expected tip. It can be wrong in the same way as sink.rs.

def fnv128(data):
    value = FNV_OFFSET
    for byte in data:
        value = ((value ^ byte) * FNV_PRIME) & MASK128
    return value


def record(kind, epoch, pre, ident, amount):
    body = b'FSW' + kind + struct.pack('<Q', epoch) + pre.to_bytes(16, 'little') + ident.ljust(24, b'\0') + struct.pack('<Q', amount)
    return body + struct.pack('<I', zlib.crc32(body) & 0xffffffff)


def encode_history(charge, original, commits):
    """The WAL bytes of a history: genesis, then each committed request in order. Returns (bytes, list of tails)."""
    out = [record(b'G', 0, 0, charge.encode(), original)]
    tails = [fnv128(out[0])]
    for index, c in enumerate(commits, 1):
        out.append(record(bytes([ord('1') + REASONS.index(c['reason'])]), index, tails[-1], c['id'].encode(), c['amount']))
        tails.append(fnv128(out[-1]))
    return b''.join(out), tails


FIELDS = [(0, 3, 'magic'), (3, 4, 'kind'), (4, 12, 'epoch'), (12, 28, 'pre_state_hash'), (28, 52, 'id'), (52, 60, 'amount'), (60, 64, 'crc32')]


def field_at(offset):
    """Record index and field name of a byte offset of a WAL (sink.rs lines 7-11)."""
    within = offset % REC
    return offset // REC, next(name for start, end, name in FIELDS if start <= within < end)


def crc_ok(rec):
    return rec[60:] == struct.pack('<I', zlib.crc32(rec[:60]) & 0xffffffff)


# ---------------------------------------------------------------------------------------------------------------------
# Processes: each child in its own process group; SIGKILL to the group on every exit path.

def run_group(argv, data=b'', env=None, timeout=120):
    p = subprocess.Popen([str(a) for a in argv], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         env=ENV if env is None else env, start_new_session=True)
    try:
        out, err = p.communicate(data, timeout=timeout)
    finally:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except OSError:
            pass
        p.wait()
    return p.returncode, out, err


def kill_at(kill_sink, binary, ledger, line, point, split):
    """Starts the kill build with one request, waits for `AT <point>` on stderr, sends SIGKILL to its group."""
    env = dict(ENV, SINK_KILL_AT=point, SINK_KILL_SPLIT=str(split))
    p = subprocess.Popen([str(kill_sink), str(ledger), 'serve', str(binary)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, env=env, start_new_session=True)
    marker, seen = ('AT %s\n' % point).encode(), b''
    try:
        p.stdin.write(line.encode())
        p.stdin.close()
        deadline = time.monotonic() + 60
        while marker not in seen and time.monotonic() < deadline:
            ready, _, _ = select.select([p.stderr], [], [], max(0.0, deadline - time.monotonic()))
            chunk = os.read(p.stderr.fileno(), 4096) if ready else b''
            if ready and not chunk:
                break
            seen += chunk
    finally:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except OSError:
            pass
        code = p.wait()
        out = p.stdout.read()
        p.stdout.close()
        p.stderr.close()
    require(marker in seen, 'kill point %s was not reached: stderr %r' % (point, seen))
    require(code == -signal.SIGKILL, 'kill point %s: the victim ended with %r, not SIGKILL' % (point, code))
    return out


# ---------------------------------------------------------------------------------------------------------------------
# Builds.

class Tools:
    def __init__(self, work):
        self.work = Path(work)
        self.rustc = os.environ.get('FORGE_RUSTC') or shutil.which('rustc')
        if not self.rustc:
            raise ToolchainError('TOOLCHAIN_ERROR: no rustc (FORGE_RUSTC or PATH)')
        code, out, _ = run_group([self.rustc, '-V'], env=dict(os.environ))
        self.rustc_version = out.decode().strip()
        if code != 0 or self.rustc_version != RUSTC_VERSION:
            raise ToolchainError('TOOLCHAIN_ERROR: rustc -V gave %r, scripts/exit_silicon_sink.py pins %r' % (self.rustc_version, RUSTC_VERSION))
        self.source_text = SOURCE.read_text()
        self.source_sha256 = sha(SOURCE.read_bytes())
        if sha(ARTIFACT.read_bytes()) != ARTIFACT_SHA256:
            raise ToolchainError('BINARY: the tracked refund binary is not %s' % ARTIFACT_SHA256)
        private = self.work / 'bin'
        private.mkdir(mode=0o700, parents=True)
        self.binary = private / 'refund'
        shutil.copyfile(ARTIFACT, self.binary)
        self.binary.chmod(0o700)
        code, out, err = run_group([self.binary], b'(charge-1 request-1 100 60 True True True 40 returned_item)',
                                   env={'CML_HEAP_SIZE': '256', 'CML_STACK_SIZE': '256'}, timeout=60)
        if code != 0 or out != b'(refund-result-v1 True 40 returned_item charge-1 request-1 1)' or err:
            raise ToolchainError('BINARY: the refund binary did not run as recorded: exit %d %r' % (code, out))
        self.sink = self.compile('unchanged', self.source_text, False)
        self.kill_sink = self.compile('unchanged', self.source_text, True)

    def compile(self, name, text, kill_points):
        folder = self.work / 'copies' / name
        folder.mkdir(parents=True, exist_ok=True)
        (folder / 'sink.rs').write_text(text)
        output = folder / ('native_sink_kill' if kill_points else 'native_sink')
        command = [self.rustc] + RUSTC_FLAGS + (['--cfg', 'kill_points'] if kill_points else []) + ['sink.rs', '-o', output.name]
        p = subprocess.Popen(command, cwd=folder, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
                             env=dict(os.environ))
        try:
            out, err = p.communicate(timeout=600)
        finally:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except OSError:
                pass
            p.wait()
        require(p.returncode == 0 and output.exists(), 'compile %s: exit %d\n%s' % (name, p.returncode, err.decode()[-2000:]))
        return output

    def planted(self, name, edits):
        text = self.source_text
        for old, new in edits:
            require(text.count(old) == 1, 'plant %s: anchor found %d times, expected 1: %r' % (name, text.count(old), old[:80]))
            text = text.replace(old, new)
        return self.compile(name, text, False)


# ---------------------------------------------------------------------------------------------------------------------
# One ledger and the record of what was done to it.

def request_line(state, rid, amount, reason='returned_item', flags=(T, T, T), **changed):
    v = dict(state, **changed)
    return '%s (%s %s %s %s %s %s %s)\n' % (v['tail'], v['charge'], rid, v['original'], v['remaining'],
                                            ' '.join('True' if f else 'False' for f in flags), amount, reason)


def parse_committed(answer):
    """`COMMITTED <epoch> <tail> (refund-result-v1 True <amount> <reason> <charge> <request> 1)` (sink.rs line 187)."""
    f = answer.rstrip('\n').split(' ')
    require(len(f) == 10 and f[0] == 'COMMITTED' and f[3] == '(refund-result-v1' and f[4] == 'True' and f[9] == '1)', 'COMMITTED line %r' % answer)
    return {'id': f[8], 'amount': int(f[5]), 'reason': f[6], 'epoch': int(f[1]), 'tail': f[2], 'charge': f[7]}


class Ledger:
    def __init__(self, tools, folder, sink=None):
        self.tools, self.dir, self.sink = tools, Path(folder), sink or tools.sink
        self.dir.mkdir(parents=True)
        self.steps, self.commits = [], []

    def files(self):
        return (self.dir / 'ledger.wal').read_bytes(), (self.dir / 'ledger.epoch').read_bytes()

    def init(self, charge, original):
        code, out, err = run_group([self.sink, self.dir, 'init', charge, str(original)])
        self.steps.append({'command': ['init', charge, str(original)], 'exit': code, 'answer': out.decode('utf-8', 'replace')})
        require(code == 0 and out.startswith(b'STATE 0 '), 'init %s: exit %d %r %r' % (self.dir.name, code, out, err))
        self.charge, self.original = charge, original
        return self

    def state(self, sink=None):
        code, out, _ = run_group([sink or self.sink, self.dir, 'state'])
        if code != 0:
            return code, out.decode('utf-8', 'replace'), None
        f = out.decode().split()
        require(len(f) == 6 and f[0] == 'STATE', 'state: %r' % out)
        return 0, out.decode(), {'epoch': int(f[1]), 'tail': f[2], 'charge': f[3], 'original': int(f[4]), 'remaining': int(f[5])}

    def view(self, sink=None):
        code, text, st = self.state(sink)
        require(code == 0, 'state of %s: exit %d %s' % (self.dir.name, code, text))
        return st

    def line(self, rid, amount, reason='returned_item', flags=(T, T, T), **changed):
        return request_line(self.view(), rid, amount, reason, flags, **changed)

    def send(self, line, expect=None, sink=None, what=''):
        before = self.files()
        code, out, err = run_group([sink or self.sink, self.dir, 'serve', self.tools.binary], line.encode())
        after = self.files()
        answer = out.decode('utf-8', 'replace')
        step = {'what': what, 'request': line, 'exit': code, 'name': CODES.get(code, '?'), 'answer': answer,
                'stderr': err.decode('utf-8', 'replace'), 'wal_before': [len(before[0]), sha(before[0])], 'wal_after': [len(after[0]), sha(after[0])],
                'ratchet_before': [len(before[1]), sha(before[1])], 'ratchet_after': [len(after[1]), sha(after[1])]}
        self.steps.append(step)
        if code == 0:
            c = parse_committed(answer)
            require(after[0][:len(before[0])] == before[0] and len(after[0]) == len(before[0]) + REC, '%s: a commit did not append one record' % what)
            c['source'] = 'COMMITTED answer line'
            self.commits.append(c)
        else:
            require(not answer.startswith('COMMITTED') and after == before, '%s: refusal %d changed the files or said COMMITTED' % (what, code))
            step['files_unchanged'] = True
        if expect is not None:
            require(code == expect, '%s: exit %d (%s), expected %d; %r' % (what, code, CODES.get(code), expect, answer))
        return code, answer

    def commit(self, rid, amount, reason='returned_item', what=''):
        return self.send(self.line(rid, amount, reason), 0, what=what or 'commit %s %d' % (rid, amount))


def snapshot(ledger, folder):
    folder = Path(folder)
    folder.mkdir(parents=True)
    for part in ('ledger.wal', 'ledger.epoch'):
        shutil.copyfile(ledger.dir / part, folder / part)
    return folder


def expected(charge, original, commits, torn):
    data, tails = encode_history(charge, original, commits)
    return {'verdict': 'ACCEPT_TORN_TAIL' if torn else 'ACCEPT', 'records': len(commits), 'charge': charge, 'original': original,
            'remaining': original - sum(c['amount'] for c in commits), 'epoch': len(commits), 'tail': '%032x' % tails[-1],
            'torn_bytes': torn, 'whole_bytes_sha256': sha(data)}


def write_scenario(folder, ledger, truth, variants):
    """variants: {label: (folder, torn)}. Writes requests.txt, answers.txt, steps.json, truth.json."""
    folder = Path(folder)
    (folder / 'requests.txt').write_text(''.join(s['request'] for s in ledger.steps if 'request' in s))
    (folder / 'answers.txt').write_text(''.join(s['answer'] if s['answer'].endswith('\n') else s['answer'] + '\n' for s in ledger.steps))
    (folder / 'steps.json').write_text(json.dumps(ledger.steps, indent=1) + '\n')
    (folder / 'truth.json').write_text(json.dumps(truth, indent=1, sort_keys=True) + '\n')
    return truth


def finish(tools, name, folder, ledger, extra=None, variants=None):
    """Snapshot of the final files, then the sink's view (state, replay), then the self-checks."""
    final = snapshot(ledger, folder / 'variants/final')
    commits = [{k: c[k] for k in ('id', 'amount', 'reason', 'source')} for c in ledger.commits]
    code, state_text, st = ledger.state(tools.sink)
    rcode, rout, _ = run_group([tools.sink, ledger.dir, 'replay'])
    exp = expected(ledger.charge, ledger.original, commits, 0)
    wal = (final / 'ledger.wal').read_bytes()
    require(wal == encode_history(ledger.charge, ledger.original, commits)[0], '%s: the WAL bytes are not the ground-truth history' % name)
    require(code == 0 and st['remaining'] == exp['remaining'] and st['epoch'] == exp['epoch'] and st['tail'] == exp['tail'], '%s: sink state %r, truth %r' % (name, st, exp))
    replay = ['REPLAY %d' % len(commits)] + ['EFFECT (refund-result-v1 True %d %s %s %s 1)' % (c['amount'], c['reason'], ledger.charge, c['id']) for c in commits]
    require(rcode == 0 and rout.decode() == '\n'.join(replay) + '\n', '%s: replay %r' % (name, rout))
    require(ledger.files() == ((final / 'ledger.wal').read_bytes(), (final / 'ledger.epoch').read_bytes()), '%s: state/replay changed a clean ledger' % name)
    for c, answered in zip(commits, ledger.commits):
        require(answered['tail'] == '%032x' % encode_history(ledger.charge, ledger.original, commits[:answered['epoch']])[1][-1],
                '%s: COMMITTED tail of %s' % (name, c['id']))
    all_variants = {'final': {'dir': str(final.relative_to(folder)), 'expect': exp}}
    for label, (path, vcommits, torn) in (variants or {}).items():
        all_variants[label] = {'dir': str(Path(path).relative_to(folder)), 'expect': expected(ledger.charge, ledger.original, vcommits, torn)}
    truth = {'scenario': name, 'charge': ledger.charge, 'original': ledger.original, 'commits': commits, 'remaining': exp['remaining'],
             'epoch': exp['epoch'], 'tail': exp['tail'], 'sink_state': state_text, 'sink_replay': rout.decode(), 'variants': all_variants,
             'wal_bytes': len(wal), 'ratchet_bytes': len((final / 'ledger.epoch').read_bytes()), 'sink_sha256': tools.source_sha256}
    truth.update(extra or {})
    return write_scenario(folder, ledger, truth, all_variants)


# ---------------------------------------------------------------------------------------------------------------------
# Scenarios with the real, unchanged sink.

def sc_fresh(tools, folder):
    return finish(tools, 'fresh', folder, Ledger(tools, folder / 'ledger').init('charge-1', 1000))


def sc_one_commit(tools, folder):
    L = Ledger(tools, folder / 'ledger').init('charge-1', 1000)
    L.commit('rq-1', 250)
    return finish(tools, 'one_commit', folder, L)


def sc_exhaust(tools, folder):
    L = Ledger(tools, folder / 'ledger').init('charge-1', 100)
    for i in range(20):
        L.commit('rq-%02d' % i, 5, REASONS[i % 3])
    L.send(L.line('rq-20', 1), 10, what='one more unit after exhaustion')
    return finish(tools, 'exhaust', folder, L)


def sc_zero(tools, folder):
    """D2: the ratified spec allows amount 0. Recorded as the sink answers; no expectation is imposed here."""
    L = Ledger(tools, folder / 'ledger').init('charge-1', 50)
    answers = {}
    for rid, amount in (('rq-z0', 0), ('rq-1', 50), ('rq-z1', 0)):
        code, answer = L.send(L.line(rid, amount), None, what='amount %d' % amount)
        answers[rid] = [code, answer.rstrip('\n')]
    return finish(tools, 'zero_amount', folder, L, {'zero_answers': answers})


def sc_boundary_max(tools, folder):
    L = Ledger(tools, folder / 'ledger').init('charge-1', MAX_MONEY)
    L.commit('rq-all', MAX_MONEY)
    L.send(L.line('rq-more', 1), 10, what='one unit after MaxMoney')
    L.commit('rq-nil', 0)
    return finish(tools, 'boundary_max', folder, L)


def sc_boundary_equal(tools, folder):
    L = Ledger(tools, folder / 'ledger').init('charge-1', 1000)
    L.commit('rq-1', 400)
    L.send(L.line('rq-over', 601), 10, what='remaining + 1')
    L.commit('rq-2', 600)
    return finish(tools, 'boundary_equal', folder, L)


def sc_refusals(tools, folder):
    L = Ledger(tools, folder / 'ledger').init('charge-1', 100)
    L.commit('rq-1', 10)
    st = L.view()
    for line, code, what in (
            (request_line(st, 'rq-1', 5), 14, 'duplicate id'),
            (request_line(st, 'rq-x', 91), 10, 'over-amount'),
            (request_line(st, 'rq-x', 5, 'other'), 10, 'bad reason'),
            (request_line(st, 'rq-x', 5, 'Returned_item'), 10, 'reason in another case'),
            (request_line(st, 'rq-x', 5, tail='0' * 32), 13, 'stale state hash'),
            (request_line(st, 'rq-x', 5, remaining=100), 13, 'stale remaining claim'),
            (request_line(st, 'rq-x', 5, flags=(F, T, T)), 10, 'flags off: enabled'),
            (request_line(st, 'rq-x', 5, flags=(T, F, T)), 10, 'flags off: open'),
            (request_line(st, 'rq-x', 5, flags=(T, T, F)), 10, 'flags off: candidate'),
            (request_line(st, 'x' * 25, 5), 12, 'id of 25 bytes'),
            (request_line(st, 'rq-x', '05'), 16, 'amount not canonical')):
        L.send(line, code, what=what)
    L.commit('rq-2', 20)
    L.send(L.line('rq-2', 1), 14, what='duplicate id again')
    L.commit('rq-3', 70)
    return finish(tools, 'refusals_interleaved', folder, L)


def sc_ids(tools, folder, charge):
    L = Ledger(tools, folder / 'ledger').init(charge, 1000)
    for rid in ('a', 'x' * 24, 'Z', 'y' * 23, '0', '-', '_'):
        L.commit(rid, 1)
    L.send(L.line('x' * 25, 1), 12, what='id of 25 bytes')
    L.send(L.line('x' * 24, 1), 14, what='id of 24 bytes again')
    return finish(tools, 'ids_charge_%d' % len(charge), folder, L)


def sc_reasons(tools, folder):
    L = Ledger(tools, folder / 'ledger').init('charge-1', 1000)
    for i, reason in enumerate(REASONS):
        L.commit('rq-%d' % i, 10 * (i + 1), reason)
    return finish(tools, 'all_reasons', folder, L)


def sc_crash(tools, folder, point, split):
    name = 'crash_%s%s' % (point, '_split%d' % split if point in 'be' else '')
    L = Ledger(tools, folder / 'ledger').init('charge-1', 1000)
    L.commit('rq-1', 10)
    L.commit('rq-2', 20)
    line = L.line('victim', 30)
    before = L.files()
    out = kill_at(tools.kill_sink, tools.binary, L.dir, line, point, split)
    L.steps.append({'what': 'victim killed at %s (split %d)' % (point, split), 'request': line, 'exit': -9, 'name': 'SIGKILL',
                    'answer': out.decode('utf-8', 'replace')})
    victim = {'id': 'victim', 'amount': 30, 'reason': 'returned_item', 'source': 'kill-point table COMMITTED_AT[%s] of the sink suite' % point}
    base = [{k: c[k] for k in ('id', 'amount', 'reason', 'source')} for c in L.commits]
    at_kill = base + ([victim] if COMMITTED_AT[point] else [])
    torn = split if point == 'b' else 0
    cut = snapshot(L, folder / 'variants/before_cut')
    wal_cut = (cut / 'ledger.wal').read_bytes()
    require(wal_cut[:len(before[0])] == before[0] and len(wal_cut) == len(before[0]) + (REC if COMMITTED_AT[point] else torn),
            '%s: the WAL after the kill has %d bytes' % (name, len(wal_cut)))
    require(wal_cut[:len(wal_cut) - torn] == encode_history('charge-1', 1000, at_kill)[0], '%s: whole records after the kill are not the history' % name)
    # The unchanged sink opens the store (its recovery): it cuts the torn tail and repairs the ratchet.
    code, text, st = L.state()
    require(code == 0, '%s: state after the kill: exit %d %s' % (name, code, text))
    reopened = snapshot(L, folder / 'variants/after_reopen')
    wal_re = (reopened / 'ledger.wal').read_bytes()
    require(wal_re == wal_cut[:len(wal_cut) - torn], '%s: the recovery did not cut exactly the torn tail' % name)
    rcode, rout, _ = run_group([tools.sink, L.dir, 'replay'])
    require(rcode == 0 and rout.decode().splitlines()[0] == 'REPLAY %d' % len(at_kill) and (('victim 1)' in rout.decode()) == COMMITTED_AT[point]),
            '%s: replay after recovery %r' % (name, rout))
    if COMMITTED_AT[point]:
        L.commits.append(dict(victim, epoch=3, tail='%032x' % fnv128(wal_re[-REC:]), charge='charge-1'))
    L.send(L.line('victim', 30), 14 if COMMITTED_AT[point] else 0, what='the victim request again')
    variants = {'before_cut': (cut, at_kill, torn), 'after_reopen': (reopened, at_kill, 0)}
    extra = {'kill_point': point, 'split': split, 'before_cut_wal_bytes': len(wal_cut), 'before_cut_ratchet_bytes': len((cut / 'ledger.epoch').read_bytes()),
             'after_reopen_wal_bytes': len(wal_re), 'after_reopen_ratchet_bytes': len((reopened / 'ledger.epoch').read_bytes()),
             'victim_answer_bytes': out.decode('utf-8', 'replace')}
    return finish(tools, name, folder, L, extra, variants)


CRASHES = [('a', 32), ('b', 1), ('b', 32), ('b', 63), ('c', 32), ('r', 32), ('d', 32), ('e', 5)]


def scenarios(tools, work, only=None):
    """Produces every scenario (or the named ones). Returns the list of truth dicts (each with a 'folder' key)."""
    makers = [('fresh', sc_fresh), ('one_commit', sc_one_commit), ('exhaust', sc_exhaust), ('zero_amount', sc_zero),
              ('boundary_max', sc_boundary_max), ('boundary_equal', sc_boundary_equal), ('refusals_interleaved', sc_refusals),
              ('ids_charge_1', lambda t, f: sc_ids(t, f, 'c')), ('ids_charge_24', lambda t, f: sc_ids(t, f, 'K' * 24)),
              ('all_reasons', sc_reasons)]
    makers += [('crash_%s%s' % (p, '_split%d' % s if p in 'be' else ''), (lambda p, s: lambda t, f: sc_crash(t, f, p, s))(p, s)) for p, s in CRASHES]
    out = []
    for name, maker in makers:
        if only is not None and name not in only:
            continue
        folder = Path(work) / 'scenarios' / name
        folder.mkdir(parents=True)
        truth = maker(tools, folder)
        truth['folder'] = str(folder)
        out.append(truth)
    return out


# ---------------------------------------------------------------------------------------------------------------------
# Planted engine bugs: textual changes of a COPY of sink.rs (each anchor occurs exactly once), compiled and driven.

PLANTS = [
    {'name': 'dup_id_check_removed', 'what': 'the duplicate-id check in commit (sink.rs line 167) is removed',
     'edits': [('    if l.ids.contains(r.request) { return no(DUPLICATE_REQUEST_ID, "DUPLICATE_REQUEST_ID: this request id is committed already") }\n', '')],
     'original': 100, 'setup': [('rq-1', 10, {})], 'critical': ('rq-1', 5, {}), 'control': 14, 'after': [],
     'verdict': 'REJECT_DUPLICATE_ID', 'index': 2, 'violation': [2, 'duplicate_id']},
    {'name': 'amount_check_removed', 'what': 'the amount-against-remaining checks are removed: the stale check no longer compares the claimed '
     'remaining (line 168), the bound of line 171 is gone, and the fold of line 92 no longer bounds the amount (line 93 then wraps: Trap C)',
     'edits': [(' || r.remaining != l.remaining {', ' {'),
               ('    if r.amount > l.remaining { return no(BAD_FRAME, "BAD_FRAME: the accepted amount is above the remaining amount") }\n', ''),
               ("&& amount <= l.remaining && l.ids.insert", "&& l.ids.insert")],
     'original': 100, 'setup': [('rq-1', 60, {})], 'critical': ('rq-2', 100, {'remaining': 100}), 'control': 13,
     'honest_control': ('rq-2', 100, 10), 'after': [], 'verdict': 'REJECT_AMOUNT_OVER_REMAINING', 'index': 2, 'violation': [2, 'over_remaining']},
    {'name': 'amount_check_removed_wrap', 'copy_of': 'amount_check_removed', 'what': 'the same copy; amounts that sum to 2^64: the buggy fold '
     'wraps back to remaining == original (Trap C)', 'edits': None,
     'original': MAX_MONEY, 'setup': [('rq-a', MAX_MONEY, {})], 'critical': ('rq-b', MAX_MONEY, {'remaining': MAX_MONEY}), 'control': 13,
     'honest_control': ('rq-b', MAX_MONEY, 10), 'after': [('rq-c', 2, {'remaining': MAX_MONEY})], 'verdict': 'REJECT_AMOUNT_OVER_REMAINING', 'index': 2, 'violation': [2, 'over_remaining']},
    {'name': 'reason_check_removed', 'what': 'the binary\'s rejection frame is taken as an accept (line 157) and the reason check of commit '
     '(lines 163-165) falls back to index 3: kind byte \'4\'',
     'edits': [('        (true, REJECT_FRAME) => no(CAKEML_REJECTED, "CAKEML_REJECTED: the binary rejected the request"),', '        (true, REJECT_FRAME) => Ok(()),'),
               ('    let Some(kind) = REASONS.iter().position(|x| *x == r.reason) else {\n        return no(BAD_FRAME, "BAD_FRAME: the accepted reason is not an approved reason");\n    };\n',
                '    let kind = REASONS.iter().position(|x| *x == r.reason).unwrap_or(REASONS.len());\n')],
     'original': 100, 'setup': [('rq-1', 10, {})], 'critical': ('rq-2', 5, {'reason': 'other'}), 'control': 10, 'after': [],
     'verdict': 'REJECT_REASON_NOT_ALLOWED', 'index': 2, 'violation': [2, 'reason']},
    {'name': 'remaining_update_wrong', 'what': 'the fold decrements remaining by amount / 2 (line 93)',
     'edits': [('            l.remaining -= amount;\n', '            l.remaining -= amount / 2;\n')],
     'original': 100, 'setup': [('rq-1', 60, {})], 'critical': ('rq-2', 60, {}), 'control': 13, 'honest_control': ('rq-2', 60, 10),
     'after': [('rq-3', 10, {})], 'verdict': 'REJECT_AMOUNT_OVER_REMAINING', 'index': 2, 'violation': [2, 'over_remaining']},
    {'name': 'epoch_not_advanced', 'what': 'commit writes the record with the old epoch (line 172)',
     'edits': [("encode(b'1' + kind as u8, l.epoch + 1, l.tail,", "encode(b'1' + kind as u8, l.epoch, l.tail,")],
     'original': 100, 'setup': [], 'critical': ('rq-1', 5, {}), 'control': 0, 'after': [],
     'verdict': 'REJECT_EPOCH_MISMATCH', 'index': 1, 'violation': [1, 'epoch'], 'note': 'every commit of this copy is wrong, so the first one is the critical one'},
    {'name': 'chain_not_updated', 'what': 'the fold keeps the genesis hash as tail (line 96): later records chain to the wrong record',
     'edits': [('(l.epoch, l.tail, l.len) = (i as u64, fnv128(r), (i + 1) * REC);', '(l.epoch, l.tail, l.len) = (i as u64, if i == 0 { fnv128(r) } else { l.tail }, (i + 1) * REC);')],
     'original': 100, 'setup': [('rq-1', 10, {})], 'critical': ('rq-2', 5, {}), 'control': 13, 'honest_control': ('rq-2', 5, 0),
     'after': [('rq-3', 5, {})], 'verdict': 'REJECT_CHAIN_MISMATCH', 'index': 2, 'violation': [2, 'chain']},
    {'name': 'binary_refusal_ignored', 'what': 'the binary\'s rejection frame is taken as an accept (line 157); request with a flag False',
     'edits': [('        (true, REJECT_FRAME) => no(CAKEML_REJECTED, "CAKEML_REJECTED: the binary rejected the request"),', '        (true, REJECT_FRAME) => Ok(()),')],
     'original': 100, 'setup': [('rq-1', 10, {})], 'critical': ('rq-2', 5, {'flags': (F, T, T)}), 'control': 10,
     'after': [('rq-3', 5, {'flags': (T, F, T)}), ('rq-4', 5, {'flags': (T, T, F)})], 'verdict': 'ACCEPT', 'index': None, 'violation': None,
     'note': 'the WAL has no flag field; the ratified spec derives the flags from the state (D1; RequestOpen), so these records are spec-valid'},
    {'name': 'binary_refusal_ignored_over', 'copy_of': 'binary_refusal_ignored', 'edits': None,
     'what': 'the same copy; an over-amount request: the binary refuses, the plant ignores it, the sink\'s own bound (line 171) refuses',
     'original': 100, 'setup': [('rq-1', 10, {})], 'critical': ('rq-2', 91, {}), 'control': 10, 'buggy_expect': 11, 'after': [],
     'verdict': 'ACCEPT', 'index': None, 'violation': None, 'note': 'no forbidden record can be written through this plant alone'},
]


def first_violation(wal):
    """This worker's own reader of a WAL (not the sink's code, not the verifier): the first record that breaks the
    framing or the ratified rule, as [index, kind], kind in bad_frame, epoch, chain, reason, duplicate_id,
    over_remaining, not_money; or None. Exact integers: no wrap."""
    recs = [wal[i:i + REC] for i in range(0, len(wal) - len(wal) % REC, REC)]
    if not recs or recs[0][3:4] != b'G' or not crc_ok(recs[0]):
        return [0, 'bad_frame']
    remaining, seen = struct.unpack('<Q', recs[0][52:60])[0], set()
    for i in range(1, len(recs)):
        r = recs[i]
        ident, amount = r[28:52].split(b'\0')[0], struct.unpack('<Q', r[52:60])[0]
        if r[:3] != b'FSW' or not crc_ok(r):
            return [i, 'bad_frame']
        if struct.unpack('<Q', r[4:12])[0] != i:
            return [i, 'epoch']
        if int.from_bytes(r[12:28], 'little') != fnv128(recs[i - 1]):
            return [i, 'chain']
        if r[3:4] not in (b'1', b'2', b'3'):
            return [i, 'reason']
        if ident in seen:
            return [i, 'duplicate_id']
        if amount > MAX_MONEY:
            return [i, 'not_money']
        if amount > remaining:
            return [i, 'over_remaining']
        seen.add(ident)
        remaining -= amount
    return None


def plant_line(L, sink, rid, amount, opts):
    st = L.view(sink)
    changed = {k: v for k, v in opts.items() if k not in ('reason', 'flags')}
    return request_line(st, rid, amount, opts.get('reason', 'returned_item'), opts.get('flags', (T, T, T)), **changed)


def produce_plant(tools, plant, work, copies):
    name = plant['name']
    folder = Path(work) / 'plants' / name
    folder.mkdir(parents=True)
    if plant.get('copy_of') and plant['copy_of'] not in copies:
        source = next(p for p in PLANTS if p['name'] == plant['copy_of'])
        copies[source['name']] = tools.planted(source['name'], source['edits'])
    sink = copies[plant['copy_of']] if plant.get('copy_of') else tools.planted(name, plant['edits'])
    copies[name] = sink
    L = Ledger(tools, folder / 'ledger', sink=sink).init('charge-1', plant['original'])
    for rid, amount, opts in plant['setup']:
        L.send(plant_line(L, sink, rid, amount, opts), 0, what='setup ' + rid)
    rid, amount, opts = plant['critical']
    line = plant_line(L, sink, rid, amount, opts)
    # Control: the UNCHANGED sink on a copy of the same store, the same request line.
    control = Ledger.__new__(Ledger)
    control.tools, control.dir, control.sink, control.steps, control.commits = tools, folder / 'control', tools.sink, [], []
    shutil.copytree(L.dir, control.dir)
    control.charge, control.original = L.charge, L.original
    ccode, canswer = control.send(line, None, what='control: unchanged sink, same line')  # asserted by the test
    honest = None
    if plant.get('honest_control'):
        hdir = folder / 'control_honest'
        shutil.copytree(folder / 'ledger', hdir)
        hrid, hamount, hcode = plant['honest_control']
        hline = request_line(control.view(tools.sink), hrid, hamount)
        hc, hout, _ = run_group([tools.sink, hdir, 'serve', tools.binary], hline.encode())
        honest = {'request': hline, 'exit': hc, 'expect_exit': hcode, 'answer': hout.decode('utf-8', 'replace')}
    wal_before = L.files()[0]
    bcode, banswer = L.send(line, None, what='critical request, planted sink')  # asserted by the test
    critical_record = L.files()[0][len(wal_before):]
    after_codes = []
    if bcode == 0:
        for arid, aamount, aopts in plant['after']:
            after_codes.append(L.send(plant_line(L, sink, arid, aamount, aopts), None, what='after ' + arid)[0])
    wal, ratchet = L.files()
    recs = [wal[i:i + REC] for i in range(0, len(wal), REC)]
    crc_all = len(wal) % REC == 0 and all(r[:3] == b'FSW' and crc_ok(r) for r in recs)
    chain_ok = all(int.from_bytes(recs[i][12:28], 'little') == fnv128(recs[i - 1]) for i in range(1, len(recs)))
    epochs = [struct.unpack('<Q', r[4:12])[0] for r in recs]
    store = snapshot(L, folder / 'store')
    bstate = L.state(sink)
    reopen = folder / 'reopen_unchanged'
    shutil.copytree(store, reopen)
    rcode, rout, _ = run_group([tools.sink, reopen, 'state'])
    rwal = (reopen / 'ledger.wal').read_bytes()
    # The same store with its last ratchet entry removed (the state after a kill between the WAL sync and the ratchet
    # entry, point r): what the unchanged sink does with a forbidden LAST record that its ratchet does not know yet.
    behind = folder / 'reopen_unchanged_ratchet_behind'
    shutil.copytree(store, behind)
    (behind / 'ledger.epoch').write_bytes(ratchet[:-12])
    bcode2, bout2, _ = run_group([tools.sink, behind, 'state'])
    bwal = (behind / 'ledger.wal').read_bytes()
    manifest = {'plant': name, 'what': plant['what'], 'edits': plant['edits'], 'copy_of': plant.get('copy_of'),
                'request': line, 'control_exit': ccode, 'control_name': CODES[ccode], 'control_answer': canswer.rstrip('\n'),
                'honest_control': honest, 'buggy_exit': bcode, 'buggy_answer': banswer.rstrip('\n'),
                'records': len(recs) - 1, 'kinds': [chr(r[3]) for r in recs], 'epochs': epochs, 'amounts': [struct.unpack('<Q', r[52:60])[0] for r in recs],
                'crc_all_valid': crc_all, 'chain_consistent': chain_ok, 'violation': first_violation(wal),
                'expect_violation': plant['violation'], 'control_expect': plant['control'], 'buggy_expect': plant.get('buggy_expect', 0),
                'after_codes': after_codes, 'after_expect': [0] * len(plant['after']) if bcode == 0 else [],
                'critical_record_id': critical_record[28:52].rstrip(b'\0').decode('ascii', 'replace') if len(critical_record) == REC else None,
                'critical_id': rid, 'buggy_state': [bstate[0], bstate[1].strip()],
                'unchanged_reopen': {'exit': rcode, 'name': 'OPENED' if rcode == 0 else CODES.get(rcode), 'answer': rout.decode('utf-8', 'replace').strip(),
                                     'wal_changed': rwal != wal, 'wal_bytes_after': len(rwal)},
                'unchanged_reopen_ratchet_behind': {'exit': bcode2, 'name': 'OPENED' if bcode2 == 0 else CODES.get(bcode2),
                                                    'answer': bout2.decode('utf-8', 'replace').strip(), 'wal_bytes_before': len(wal),
                                                    'wal_bytes_after': len(bwal), 'records_cut': (len(wal) - len(bwal)) // REC},
                'expect_verdict': plant['verdict'], 'expect_index': plant['index'], 'note': plant.get('note', ''),
                'store': str(store), 'wal_sha256': sha(wal), 'ratchet_bytes': len(ratchet), 'steps': L.steps}
    (folder / 'manifest.json').write_text(json.dumps(manifest, indent=1) + '\n')
    return manifest


def plants(tools, work, only=None):
    copies = {}
    return [produce_plant(tools, p, work, copies) for p in PLANTS if only is None or p['name'] in only]


# ---------------------------------------------------------------------------------------------------------------------
# The compiled verifier (CORE's program; binding CLI in the team contract). Used by the two test files.

VERDICTS_MD = ROOT / 'verifier/refund_log/VERDICTS.md'
ENCODE_MD = ROOT / 'verifier/refund_log/ENCODE.md'
# Exit code per verdict, as the coordinator reported CORE's interface: ACCEPT 0, ACCEPT_TORN_TAIL 4, REJECT_* 1, UNVERIFIABLE* 3.


def exit_of(verdict):
    return {'ACCEPT': 0, 'ACCEPT_TORN_TAIL': 4}.get(verdict, 1 if verdict.startswith('REJECT_') else 3)


def verdict_names():
    """The verdict names listed in VERDICTS.md, or None while that file does not exist."""
    if not VERDICTS_MD.exists():
        return None
    return set(re.findall(r'\b(?:ACCEPT(?:_[A-Z]+)*|REJECT_[A-Z_]*[A-Z]|UNVERIFIABLE(?:_[A-Z]+)*)\b', VERDICTS_MD.read_text()))


def run_verifier(verifier, wal, ratchet=None, extra=()):
    """Returns (exit code, the JSON object of the first stdout line or None, stdout text)."""
    argv = [verifier, wal] + (['--ratchet', ratchet] if ratchet else []) + [str(a) for a in extra] + ['--json']
    code, out, err = run_group(argv, env=dict(os.environ), timeout=900)
    text = out.decode('utf-8', 'replace')
    try:
        obj = json.loads(text.splitlines()[0]) if text.strip() else None
    except ValueError as error:
        obj, text = None, 'JSON ERROR %s in: %s' % (error, text)
    return code, obj, text + err.decode('utf-8', 'replace')


def freeze_verifier(verifier, work):
    """Copies the folder of the compiled verifier (shim and model-py) into the work folder, so that a rebuild by CORE
    during a run cannot change the program under test. Returns (path of the copy, SHA-256 of build.json or None)."""
    source = Path(verifier).resolve().parent
    target = Path(work) / 'verifier'
    shutil.copytree(source, target, symlinks=True)
    build = target / 'build.json'
    return str(target / Path(verifier).name), (sha(build.read_bytes()) if build.exists() else None)


def encoder_status():
    """(True, how) when CORE documented the proved encoder entry point; else (False, reason)."""
    for doc in (ENCODE_MD, VERDICTS_MD):
        if doc.exists() and '--encode' in doc.read_text():
            return True, doc.name
    return False, 'no `--encode` entry point is documented in verifier/refund_log/ENCODE.md or VERDICTS.md'


# Tracked fixed vectors (tests/refund_log_verifier/golden/). (file stem, source kind, source name, variant, expected
# verdict, expected index, expected torn bytes). Each is a WAL and its ratchet, copied from a run of this file.
GOLDEN_DIR = ROOT / 'tests/refund_log_verifier/golden'
GOLDEN = [
    ('one_commit', 'scenario', 'one_commit', 'final', 'ACCEPT', None, 0),
    ('zero_amount', 'scenario', 'zero_amount', 'final', 'ACCEPT', None, 0),
    ('crash_b_split32_before_cut', 'scenario', 'crash_b_split32', 'before_cut', 'ACCEPT_TORN_TAIL', None, 32),
    ('plant_amount_check_removed_wrap', 'plant', 'amount_check_removed_wrap', 'store', 'REJECT_AMOUNT_OVER_REMAINING', 2, None),
    ('plant_reason_check_removed', 'plant', 'reason_check_removed', 'store', 'REJECT_REASON_NOT_ALLOWED', 2, None),
]
GOLDEN_SCENARIOS = {'one_commit', 'zero_amount', 'crash_b_split32'}
GOLDEN_PLANTS = {'amount_check_removed_wrap', 'reason_check_removed'}


def golden_source(work, kind, name, variant):
    """The folder of a fresh run that holds the files of one tracked vector."""
    return Path(work) / ('scenarios/%s/variants/%s' % (name, variant) if kind == 'scenario' else 'plants/%s/%s' % (name, variant))


def new_work(given=None):
    if given:
        path = Path(given).resolve()
        require(not path.exists() or not any(path.iterdir()), 'the work folder %s is not empty' % path)
        path.mkdir(parents=True, exist_ok=True)
        return path
    base = ROOT / 'build' / 'refund_log_golden_rust'
    base.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix='run-', dir=base))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--work')
    parser.add_argument('--write-golden', metavar='DIR', help='after the run, copy the tracked vectors (GOLDEN) into DIR (must not exist)')
    args = parser.parse_args()
    try:
        work = new_work(args.work)
        tools = Tools(work)
        if args.write_golden:
            target = Path(args.write_golden)
            require(not target.exists(), '%s exists already' % target)
            scenarios(tools, work, GOLDEN_SCENARIOS)
            plants(tools, work, GOLDEN_PLANTS)
            target.mkdir(parents=True)
            for stem, kind, name, variant, *_ in GOLDEN:
                for part, ext in (('ledger.wal', '.wal'), ('ledger.epoch', '.epoch')):
                    data = (golden_source(work, kind, name, variant) / part).read_bytes()
                    (target / (stem + ext)).write_bytes(data)
                    print('%-40s %4d bytes sha256 %s' % (stem + ext, len(data), sha(data)))
            return 0
        print('GOLDEN_RUST work %s; %s; sink.rs %s' % (work, tools.rustc_version, tools.source_sha256))
        for t in scenarios(tools, work):
            print('SCENARIO %-22s PASS commits=%d remaining=%d wal=%dB ratchet=%dB' % (t['scenario'], len(t['commits']), t['remaining'], t['wal_bytes'], t['ratchet_bytes']))
        for m in plants(tools, work):
            print('PLANT %-28s PASS control=%s buggy=%s reopen_unchanged=%s' % (m['plant'], m['control_name'], CODES[m['buggy_exit']], m['unchanged_reopen']['name']))
    except ToolchainError as error:
        print(str(error))
        return 2
    except Failed as error:
        print('FAIL ' + str(error))
        return 1
    print('GOLDEN_RUST: PASSED; FINITE TEST; end_to_end=false')
    return 0


if __name__ == '__main__':
    sys.exit(main())
