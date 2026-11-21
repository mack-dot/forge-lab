#!/usr/bin/env python3
"""Changed copies of the refund-log VERIFIER that its judges must kill (Task V1). FINITE TEST. end_to_end=false.

usage: python3 tests/refund_log_verifier/mutants_verifier.py [--verifier DIR] [--judges test|test,proof]
           [--proof-for NAME,...] [--only NAME]... [--work DIR] [--out FILE] [--allow-stale-build]

Each entry removes or weakens ONE check. It names up to two edits of the SAME change, each an exact text that must
occur exactly once in its file (else the entry is an ERROR of the list):
  dafny   an edit of verifier/refund_log/RefundLogVerifier.dfy, applied in a temporary copy of the Dafny tree
          (verifier/refund_log/*.dfy, spec/refund/*.dfy, impl/Refund.dfy at the same relative places); the judge is
          `dafny verify` with the gate options (the PROOF judge). None for a change of the unproved shim.
  py      the same change in a copy of the COMPILED verifier (the folder that verifier/refund_log/build.py writes: the
          shim `verify-refund-log` and Dafny's Python output `model-py/`); the judges are the suites (the TEST judge).
The source tree is never written: every copy lives under the work folder.

Judges, in this order:
  test   the four suites of tests/refund_log_verifier against the changed compiled copy, cheapest first:
         test_planted_bugs, test_golden_rust, test_negative_controls, test_exhaustive. The first suite that FAILS for a
         reason (exit 1 and a failure line: FAIL, DISAGREE, CLASS DISAGREEMENT, NOT REJECTED) kills the copy:
         killed_by=test, with the suite and its first failure line. A suite that only prints NOT RUN does not kill.
  proof  `dafny verify` of the changed Dafny tree. Only a genuine verification ERROR on a named declaration kills;
         an out-of-resource or time-out result is recorded as `inconclusive: out of resource`, never as a kill. Run ONLY for (a) copies that no test killed and that change proved
         code, and (b) the copies named by --proof-for (to show the proof kill). Exit != 0 or errors > 0 kills the copy:
         killed_by=proof, with the names of the declarations that fail. With --proof-for, the proof judge of the named
         copies runs with `--filter-symbol` on the declarations given in the entry (a failure there is enough to show
         that the whole file does not verify); a copy that no test killed always gets the FULL file.
The unchanged control copy must pass every judge that runs (all four suites in full; `dafny verify` of the unchanged
tree with the same filters, when the proof judge runs). A copy that nothing kills is NOT KILLED: it is reported; this
script never accepts it.

Dafny: one Dafny job at a time on the machine. Before each Dafny run this script waits until no process matches
'dafny/dafny|Holmake|z3-4.12.1|run_regression_copy' for 3 checks one minute apart (at most 60 min; then NOT RUN).
Tools: FORGE_TOOLCHAIN_ROOT (the checkout that holds .toolchain/; cwd of every Dafny run; else this repository),
FORGE_DAFNY (else <toolchain root>/.toolchain/dafny-4.11.0/dafny/dafny), FORGE_RUSTC (passed to the suites).
Every child runs in its own process group, which gets SIGKILL on every exit path, and is reaped. Children get
TMPDIR=<work>/tmp, so every temporary folder of a suite is under the work folder.
Exit: 0 the control passed and every copy was killed; 1 a copy is NOT KILLED or the control failed; 2 an ERROR of
the list or a judge that could not run (NOT RUN).
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
TESTS = ROOT / 'tests/refund_log_verifier'
DAFNY_ROOT = Path(os.environ.get('FORGE_TOOLCHAIN_ROOT') or ROOT)
DAFNY = os.environ.get('FORGE_DAFNY') or str(DAFNY_ROOT / '.toolchain/dafny-4.11.0/dafny/dafny')
DAFNY_OPTIONS = ['--solver-path', '.toolchain/dafny-4.11.0/dafny/z3/bin/z3-4.12.1', '--resource-limit', '1000000',
                 '--verification-time-limit', '0', '--cores', '1', '--verify-included-files', '--track-print-effects']
DAFNY_TREE = ['verifier/refund_log/RefundLogVerifier.dfy', 'verifier/refund_log/RatifiedSpecLemmas.dfy',
              'spec/refund/RefundLogSpec.dfy', 'spec/refund/RefundSpec.dfy', 'impl/Refund.dfy']
ENTRY = 'verifier/refund_log/RefundLogVerifier.dfy'
SLOT = re.compile(r'dafny/dafny|Holmake|z3-4\.12\.1|run_regression_copy')
QUIET = ('sh', 'bash', 'zsh', 'pgrep', 'grep', 'ps', 'tail', 'sleep')
SUITES = ['test_planted_bugs', 'test_golden_rust', 'review_checks', 'test_negative_controls', 'test_exhaustive']   # cheapest first
# review_checks: the reproductions of the review findings F1, F4, F5 in scripts/exit_refund_log_verifier.py (without the
# F2 timing guard), run on the copy; a copy that fails one of them is killed by that check.
FAILURE = re.compile(r'^(?:CASE \S+\s+FAIL\b|DISAGREE\b|CLASS DISAGREEMENT\b|NOT REJECTED\b|TRAP B .* FAIL$|DISAGREEMENT\b)', re.M)
V = 'model-py/RefundLogVerifier.py'
F = 'model-py/SinkFormat.py'
SHIM = 'verify-refund-log'

# (name, what the copy removes, dafny edit (old, new) or None, py edit (file in the build folder, old, new),
#  declarations for the --filter-symbol proof judge)
MUTANTS = [
    ('crc_not_checked', 'the CRC-32 check of each commit record',
     ('    if !CrcOk(r) then FrameBad(BadCrc)', '    if false then FrameBad(BadCrc)'),
     (V, '        if not(SinkFormat.default__.CrcOk(r)):\n            return Frame_FrameBad(Cause_BadCrc())',
      '        if False:\n            return Frame_FrameBad(Cause_BadCrc())'), ['RefundLogVerifier.RecordBack']),
    ('magic_not_checked', 'the "FSW" magic check of each commit record',
     ('else if r[..3] != MAGIC || !IdFieldOk(r[28..52]) then FrameBad(MalformedRecord)', 'else if !IdFieldOk(r[28..52]) then FrameBad(MalformedRecord)'),
     (V, 'elif ((_dafny.SeqWithoutIsStrInference((r)[:3:])) != (SinkFormat.default__.MAGIC)) or (not(SinkFormat.default__.IdFieldOk(_dafny.SeqWithoutIsStrInference((r)[28:52:])))):\n            return Frame_FrameBad(',
      'elif (not(SinkFormat.default__.IdFieldOk(_dafny.SeqWithoutIsStrInference((r)[28:52:])))):\n            return Frame_FrameBad('), ['RefundLogVerifier.RecordBack']),
    ('epoch_not_checked', 'epoch == record index',
     ('else if FieldsOf(r).epoch != i then FrameBad(EpochMismatch)', 'else if false then FrameBad(EpochMismatch)'),
     (V, 'elif ((SinkFormat.default__.FieldsOf(r)).epoch) != (i):', 'elif False:'), ['RefundLogVerifier.RecordBack']),
    ('chain_not_checked', 'pre-state hash == FNV-1a-128 of the previous record',
     ('else if FieldsOf(r).pre != tail then FrameBad(ChainMismatch)', 'else if false then FrameBad(ChainMismatch)'),
     (V, 'elif ((SinkFormat.default__.FieldsOf(r)).pre) != (tail):', 'elif False:'), ['RefundLogVerifier.RecordBack']),
    ('id_padding_not_checked', 'canonical NUL padding after the id (a non-NUL byte after the first NUL)',
     ('(forall j | 0 <= j < k :: IdByte(f[j])) && (forall j | k <= j < |f| :: f[j] == 0)', '(forall j | 0 <= j < k :: IdByte(f[j]))'),
     (F, 'return (_dafny.quantifier(_dafny.IntegerRange(0, d_0_k_), True, lambda0_)) and (_dafny.quantifier(_dafny.IntegerRange(d_0_k_, len(f)), True, lambda1_))',
      'return (_dafny.quantifier(_dafny.IntegerRange(0, d_0_k_), True, lambda0_))'), ['SinkFormat.IdFieldBack']),
    ('id_alphabet_not_checked', 'the id byte set [A-Za-z0-9_-]',
     ('(forall j | 0 <= j < k :: IdByte(f[j])) && (forall j | k <= j < |f| :: f[j] == 0)', '(forall j | k <= j < |f| :: f[j] == 0)'),
     (F, 'return (_dafny.quantifier(_dafny.IntegerRange(0, d_0_k_), True, lambda0_)) and (_dafny.quantifier(_dafny.IntegerRange(d_0_k_, len(f)), True, lambda1_))',
      'return (_dafny.quantifier(_dafny.IntegerRange(d_0_k_, len(f)), True, lambda1_))'), ['SinkFormat.IdFieldBack']),
    ('id_length_off_by_one', 'the id field bound of commit records (bytes 28..51 checked instead of 28..52)',
     ('!IdFieldOk(r[28..52]) then FrameBad(MalformedRecord)', '!IdFieldOk(r[28..51]) then FrameBad(MalformedRecord)'),
     (V, '(not(SinkFormat.default__.IdFieldOk(_dafny.SeqWithoutIsStrInference((r)[28:52:])))):\n            return Frame_FrameBad(Cause_MalformedRecord())',
      '(not(SinkFormat.default__.IdFieldOk(_dafny.SeqWithoutIsStrInference((r)[28:51:])))):\n            return Frame_FrameBad(Cause_MalformedRecord())'),
     ['RefundLogVerifier.RecordBack']),
    ('kind_range_not_checked', 'the kind byte range 1..3 of a commit record (the approved reason)',
     ('if !(IsReason(reason) && id != [] && !settled && f.amount <= remaining) {', 'if !(id != [] && !settled && f.amount <= remaining) {'),
     (V, '(default__.IsReason(d_15_reason_)) and ((d_14_id_)', '(True) and ((d_14_id_)'), ['RefundLogVerifier.Verify']),
    ('money_range_not_checked', 'original <= MaxMoney (2^63-1) at the genesis (the commit amounts are bounded by remaining <= original)',
     ('|| |f.id| == 0 || f.amount > S.R.MaxMoney', '|| |f.id| == 0'),
     (V, ' or ((len((d_0_f_).id_)) == (0))) or (((d_0_f_).amount) > (Refund.default__.MaxMoney)):', ' or ((len((d_0_f_).id_)) == (0))) or (False):'),
     ['RefundLogVerifier.Verify']),
    ('money_cause_not_named', 'the AMOUNT_NOT_MONEY name of a commit amount above 2^63-1 (the refusal stays; only its name changes)',
     ('else if amount > S.R.MaxMoney then AmountNotMoney', 'else if false then AmountNotMoney'),
     (V, 'elif (amount) > (Refund.default__.MaxMoney):\n            return Cause_AmountNotMoney()', 'elif False:\n            return Cause_AmountNotMoney()'),
     ['RefundLogVerifier.Verify']),
    ('duplicate_not_checked', 'the settled set (a request id settles at most once)',
     ('if !(IsReason(reason) && id != [] && !settled && f.amount <= remaining) {', 'if !(IsReason(reason) && id != [] && f.amount <= remaining) {'),
     (V, '(not(d_17_settled_))', '(True)'), ['RefundLogVerifier.Verify']),
    ('empty_id_not_checked', 'the non-empty request id',
     ('if !(IsReason(reason) && id != [] && !settled && f.amount <= remaining) {', 'if !(IsReason(reason) && !settled && f.amount <= remaining) {'),
     (V, '((d_14_id_) != (_dafny.SeqWithoutIsStrInference([])))', '(True)'), ['RefundLogVerifier.Verify']),
    ('amount_le_to_lt', 'amount <= remaining weakened to amount < remaining (a refund of exactly the remaining amount refused)',
     ('&& f.amount <= remaining) {', '&& f.amount < remaining) {'),
     (V, '(((d_13_f_).amount) <= (d_6_remaining_))', '(((d_13_f_).amount) < (d_6_remaining_))'), ['RefundLogVerifier.Verify']),
    ('amount_le_plus_one', 'amount <= remaining weakened to amount <= remaining + 1 (the mirror: an over-refund by 1 accepted)',
     ('&& f.amount <= remaining) {', '&& f.amount <= remaining + 1) {'),
     (V, '(((d_13_f_).amount) <= (d_6_remaining_))', '(((d_13_f_).amount) <= ((d_6_remaining_) + (1)))'), ['RefundLogVerifier.Verify']),
    ('remaining_not_decremented', 'remaining := remaining - amount',
     ('      remaining := remaining - f.amount;', '      remaining := remaining;'),
     (V, 'd_6_remaining_ = (d_6_remaining_) - ((d_13_f_).amount)', 'd_6_remaining_ = d_6_remaining_'), ['RefundLogVerifier.Verify']),
    ('wrong_genesis_remaining', 'the fold starts from the genesis state (here: remaining = original + 1)',
     ('    var remaining: int := original;', '    var remaining: int := original + 1;'),
     (V, '        d_6_remaining_ = d_5_original_\n', '        d_6_remaining_ = (d_5_original_) + (1)\n'), ['RefundLogVerifier.Verify']),
    ('genesis_kind_not_checked', 'kind "G" of record 0',
     ('if f.kind != KIND_GENESIS || f.epoch != 0', 'if f.epoch != 0'),
     (V, '(((d_0_f_).kind) != (SinkFormat.default__.KIND__GENESIS)) or ', '(False) or '), ['RefundLogVerifier.GenesisBack']),
    ('expect_count_ignored', '--expect-count',
     ('    if countGiven && DecValue(countText) != o.records {', '    if false && countGiven && DecValue(countText) != o.records {'),
     (V, 'if (countGiven) and ((default__.DecValue(countText)) != ((o).records)):', 'if False:'), ['RefundLogVerifier.Finish']),
    ('expect_tip_ignored', '--expect-tip',
     ('    if tipGiven && tipText != Hex(o.tail, 32) {', '    if false && tipGiven && tipText != Hex(o.tail, 32) {'),
     (V, 'if (tipGiven) and ((tipText) != (default__.Hex((o).tail, 32))):', 'if False:'), ['RefundLogVerifier.Finish']),
    ('ratchet_floor_flipped', 'ratchet floor > WAL epoch flipped to floor < WAL epoch',
     ('    if v.floor > epoch { v := RatchetBad(m, Ahead, v.floor); }', '    if v.floor < epoch { v := RatchetBad(m, Ahead, v.floor); }'),
     (V, '        if ((v).floor) > (epoch):', '        if ((v).floor) < (epoch):'), ['RefundLogVerifier.CheckRatchetLoop']),
    ('ratchet_entry_crc_not_checked', 'the CRC-32 of each whole ratchet entry',
     ('      if !EntryOk(rb, k) { v := RatchetBad(k, BadEntry, best); return; }', '      if false { v := RatchetBad(k, BadEntry, best); return; }'),
     (V, '            if not(default__.EntryOk(rb, d_1_k_)):', '            if False:'), ['RefundLogVerifier.CheckRatchetLoop']),
    ('torn_tail_accept', 'the torn-tail branch: ACCEPT (exit 0) in place of ACCEPT_TORN_TAIL (exit 4)',
     ('    code := if o.tornBytes == 0 && ratchetTorn == 0 then 0 else 4;', '    code := 0;'),
     (V, '        elif True:\n            code = 4\n', '        elif True:\n            code = 0\n'), ['RefundLogVerifier.Finish']),
    ('shim_accept_on_internal_error', 'the shim prints UNVERIFIABLE_INTERNAL_ERROR (exit 3) on an exception; the copy prints ACCEPT (exit 0)',
     None,
     (SHIM, "        emit('UNVERIFIABLE_INTERNAL_ERROR reason=INTERNAL_ERROR')\n    except BaseException:\n        pass\n    exit_code = 3",
      "        emit('ACCEPT records=0')\n    except BaseException:\n        pass\n    exit_code = 0"), []),
    ('shim_ignores_trailing_bytes', 'the shim passes every byte it read; the copy drops a trailing part of fewer than 64 bytes',
     None,
     (SHIM, '            wal = _dafny.Seq(f.read(V.MaxBytes + 1))\n',
      '            wal = _dafny.Seq(f.read(V.MaxBytes + 1))\n            wal = _dafny.Seq(list(wal)[:len(wal) - len(wal) % 64])\n'), []),
    ('shim_reads_only_bound', 'the shim reads bound + 1 bytes (so an oversized file is seen as oversized); the copy reads only bound bytes',
     None,
     (SHIM, '_dafny.Seq(f.read(V.MaxBytes + 1))', '_dafny.Seq(f.read(V.MaxBytes))'), []),
    ('launcher_not_isolated', 'review F1 repair: the launcher runs Python with -I (isolated); the copy drops -I',
     None,
     (SHIM, ' -I\n"""usage: verify-refund-log', '\n"""usage: verify-refund-log'), []),
    ('shim_print_not_checked', 'review F4 repair: the line is written with os.write and checked; the copy uses print() (a lost line goes unnoticed)',
     None,
     (SHIM, "def emit(text):\n    data = (text + '\\n').encode('utf-8')", "def emit(text):\n    print(text)\n    return\n    data = (text + '\\n').encode('utf-8')"), []),
]


class ListError(Exception):
    pass


class NotRun(Exception):
    pass


def sha(data):
    return hashlib.sha256(data).hexdigest()


def run_group(argv, cwd, timeout, env):
    """subprocess.run with the child in its own process group; SIGKILL to the group and reap on every exit path
    (the pattern of tests/primitives_v2/mutants.py, unsure.md U927)."""
    p = subprocess.Popen([str(a) for a in argv], cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                         errors='replace', start_new_session=True, env=env)
    try:
        out, _ = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        out = '(timeout after %d s)' % timeout
    finally:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except OSError:
            pass
        p.wait()
    return p.returncode, out


def reap_under(work, timeout_s=30):
    """Kill every process whose command names `work` (a suite's sink, refund or verifier child, in its own session,
    beyond a parent group-kill), then poll until none remains or the bounded timeout. Returns the list still alive."""
    waited = 0.0
    while True:
        out = subprocess.run(['ps', '-ax', '-o', 'pid=,command='], capture_output=True, text=True).stdout
        found = []
        for line in out.splitlines():
            pid, _, cmd = line.strip().partition(' ')
            if pid.isdigit() and int(pid) != os.getpid() and str(work) in cmd and not cmd.startswith(('ps ', 'grep ')):
                found.append((int(pid), cmd[:160]))
        if not found or waited >= timeout_s:
            return found
        for pid, _ in found:
            try:
                os.killpg(os.getpgid(pid), signal.SIGKILL)
            except OSError:
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
        time.sleep(0.5)
        waited += 0.5


def slot_busy():
    out = subprocess.run(['ps', '-ax', '-o', 'pid=,command='], capture_output=True, text=True).stdout
    for line in out.splitlines():
        pid, _, cmd = line.strip().partition(' ')
        first = os.path.basename(cmd.split(' ', 1)[0]).lstrip('-')
        if pid.isdigit() and int(pid) != os.getpid() and first not in QUIET and SLOT.search(cmd):
            return True
    return False


def wait_slot(limit_s=3600):
    """Free = no matching process for 3 checks one minute apart. Returns the seconds waited."""
    free, waited = 0, 0
    while True:
        free = 0 if slot_busy() else free + 1
        if free >= 3:
            return waited
        if waited >= limit_s:
            raise NotRun('NOT RUN: the Dafny slot was not free for 3 checks in %d min' % (limit_s // 60))
        time.sleep(60)
        waited += 60


def replace_once(path, old, new, label):
    text = Path(path).read_text()
    n = text.count(old)
    if n != 1:
        raise ListError('ERROR of the list: %s: the anchor occurs %d times in %s (must be 1): %r' % (label, n, Path(path).name, old[:90]))
    Path(path).write_text(text.replace(old, new))


def copy_build(src, dst):
    shutil.copytree(src, dst, symlinks=True, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    return dst / SHIM


def copy_dafny_tree(dst):
    for rel in DAFNY_TREE:
        (dst / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / rel, dst / rel)
    return dst / ENTRY


def child_env(work):
    tmp = work / 'tmp'
    tmp.mkdir(parents=True, exist_ok=True)
    return dict(os.environ, TMPDIR=str(tmp), PYTHONDONTWRITEBYTECODE='1')


def run_review(verifier, work, env):
    sys.path.insert(0, str(ROOT / 'scripts'))
    import exit_refund_log_verifier as E
    import wal_forge as W
    d = work / 'w-review_checks'
    d.mkdir(parents=True, exist_ok=True)
    res, problems = E.review_checks(Path(verifier), d, env, W, timing=False)
    out = ''.join('CASE review/%s  %s\n' % (k, json.dumps(v, sort_keys=True)) for k, v in res.items())
    out += ''.join('CASE review/%s FAIL  %s\n' % (x.split(':')[0], x) for x in problems)
    return (1 if problems else 0), out


def run_suite(suite, verifier, work, env, sink):
    if suite == 'review_checks':
        return run_review(verifier, work, env)
    argv = [sys.executable, TESTS / (suite + '.py'), verifier]
    if suite in ('test_golden_rust', 'test_planted_bugs'):
        argv += ['--work', work / ('w-' + suite)]
    elif sink:
        argv += ['--sink', sink]
    code, out = run_group(argv, ROOT, 5400, env)
    return code, out


def suite_verdict(code, out):
    """('pass' | 'kill' | 'notrun', first failure line)."""
    m = FAILURE.search(out)
    if code == 0 and not m and 'NOT RUN' not in out:
        return 'pass', ''
    if code == 1 and m:
        return 'kill', out[m.start():].splitlines()[0][:300]
    if code == 1 and re.search(r'assertion_failures=[1-9]', out):
        return 'kill', re.search(r'COUNTS .*', out).group(0)[:300]
    return 'notrun', 'exit %s; %s' % (code, (out.strip().splitlines() or [''])[-1][:300])


def decl_at(text, line):
    """The name of the declaration that holds source line `line` (1-based) of a Dafny text."""
    best = '?'
    module = '?'
    for k, row in enumerate(text.splitlines()[:line], 1):
        m = re.match(r'\s*(?:abstract\s+)?module\s+(\w+)', row)
        if m:
            module = m.group(1)
        m = re.match(r'\s*(?:ghost\s+|opaque\s+|static\s+|twostate\s+|least\s+|greatest\s+)*(?:lemma|function|method|predicate)\s+(?:\{:[^}]*\}\s*)*(\w+)', row)
        if m:
            best = '%s.%s' % (module, m.group(1))
    return best


def dafny_judge(entry, filters, log):
    if not Path(DAFNY).is_file():
        raise NotRun('NOT RUN: the pinned Dafny is missing at %s: set FORGE_TOOLCHAIN_ROOT or FORGE_DAFNY' % DAFNY)
    waited = wait_slot()
    argv = [DAFNY, 'verify', entry] + DAFNY_OPTIONS
    for f in filters:
        argv += ['--filter-symbol', f]
    t = time.monotonic()
    code, out = run_group(argv, DAFNY_ROOT, 14400, dict(os.environ))
    secs = round(time.monotonic() - t, 1)
    log.write_text('$ %s\nexit %s\n%s' % (' '.join(str(a) for a in argv), code, out))
    m = re.search(r'finished with (\d+) verified, (\d+) errors?', out)
    text = Path(entry).read_text()
    errors = [(int(x.group(1)), x.group(2)) for x in re.finditer(r'RefundLogVerifier\.dfy\((\d+),\d+\): Error:?([^\n]*)', out)]
    resource = lambda t: re.search(r'out of resource|timed? ?out', t, re.I) is not None   # noqa: E731
    failing = sorted({decl_at(text, ln) for ln, msg in errors if not resource(msg)})
    oor = sorted({decl_at(text, ln) for ln, msg in errors if resource(msg)}) or (['?'] if resource(out) else [])
    clean = code == 0 and m is not None and m.group(2) == '0' and not resource(out)
    # CORE's caution: only a genuine verification ERROR on a named declaration kills; out of resource is inconclusive
    outcome = 'verifies' if clean else ('error' if failing else ('inconclusive: out of resource' if oor else 'inconclusive: exit %s' % code))
    return {'exit': code, 'summary': m.group(0) if m else None, 'verifies': clean, 'outcome': outcome, 'failing': failing,
            'out_of_resource': oor, 'filters': filters, 'seconds': secs, 'slot_wait_s': waited}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--verifier', default=str(ROOT / 'build/refund_log_verifier'), help='a folder built by verifier/refund_log/build.py')
    ap.add_argument('--judges', default='test')
    ap.add_argument('--proof-for', default='')
    ap.add_argument('--only', action='append', default=[])
    ap.add_argument('--work')
    ap.add_argument('--out')
    ap.add_argument('--allow-stale-build', action='store_true',
                    help='run the TEST judge although build.json does not match the current Dafny sources (recorded)')
    args = ap.parse_args()
    judges = set(args.judges.split(','))
    proof_for = [n for n in args.proof_for.split(',') if n]
    names = [m[0] for m in MUTANTS]
    for n in args.only + proof_for:
        if n not in names:
            print('ERROR of the list: no copy named %s' % n)
            return 2
    base = Path(args.verifier).resolve()
    work = Path(args.work).resolve() if args.work else Path(tempfile.mkdtemp(prefix='mutants-verifier-', dir=ROOT / 'build'))
    work.mkdir(parents=True, exist_ok=True)
    env = child_env(work)
    result = {'judges': sorted(judges), 'proof_for': proof_for, 'copies': [], 'control': {}, 'errors': [], 'not_run': []}
    try:
        if not (base / SHIM).is_file() or not (base / V).is_file():
            raise NotRun('NOT RUN: no compiled verifier in %s (run verifier/refund_log/build.py)' % base)
        build = json.loads((base / 'build.json').read_text())
        stale = sorted(k for k, v in build.get('inputs', {}).items() if (ROOT / k).is_file() and sha((ROOT / k).read_bytes()) != v)
        result['build_json_sha256'] = sha((base / 'build.json').read_bytes())
        result['stale_inputs'] = stale
        if stale and not args.allow_stale_build:
            raise NotRun('NOT RUN: the compiled verifier in %s is older than %s (rebuild, or --allow-stale-build for test kills only)' % (base, stale))
        if stale and 'proof' in judges:
            raise NotRun('NOT RUN: the proof judge needs a build of the current sources; stale: %s' % stale)
        sys.path.insert(0, str(TESTS))
        import wal_forge as W   # FORGE's helper: one sink build for the FORGE suites of every copy
        (work / 'sink').mkdir(parents=True, exist_ok=True)
        try:
            sink = str(W.build_sink(work / 'sink'))
        except Exception as error:  # noqa: BLE001
            raise NotRun('NOT RUN: the sink for the FORGE suites does not build: %s' % error)
        selected = [m for m in MUTANTS if not args.only or m[0] in args.only]
        # check every anchor before any judge runs
        for name, _, dedit, pedit, _ in selected:
            text = (base / pedit[0]).read_text()
            if text.count(pedit[1]) != 1:
                raise ListError('ERROR of the list: %s: the py anchor occurs %d times in %s' % (name, text.count(pedit[1]), pedit[0]))
            if dedit and (ROOT / ENTRY).read_text().count(dedit[0]) != 1:
                raise ListError('ERROR of the list: %s: the dafny anchor occurs %d times in %s' % (name, (ROOT / ENTRY).read_text().count(dedit[0]), ENTRY))
        # the control: the unchanged copy passes every suite
        cdir = work / 'control'
        cver = copy_build(base, cdir / 'build')
        result['control']['suites'] = {}
        for suite in SUITES:
            t = time.monotonic()
            code, out = run_suite(suite, cver, cdir, env, sink)
            (cdir / (suite + '.log')).write_text(out)
            v, line = suite_verdict(code, out)
            result['control']['suites'][suite] = {'exit': code, 'verdict': v, 'line': line, 'seconds': round(time.monotonic() - t, 1)}
            print('CONTROL %-24s exit %s %s %s' % (suite, code, v.upper(), line), flush=True)
            if v != 'pass':
                raise ListError('CONTROL FAILED: the unchanged copy does not pass %s (exit %s): %s' % (suite, code, line))
        proof_filters = sorted({f for m in selected if m[0] in proof_for for f in m[4]})
        for name, removes, dedit, pedit, filters in selected:
            row = {'name': name, 'removes': removes, 'applied': True, 'killed': False, 'killed_by': None, 'test': None, 'proof': None,
                   'proved_code': dedit is not None}
            mdir = work / name
            mver = copy_build(base, mdir / 'build')
            replace_once(mdir / 'build' / pedit[0], pedit[1], pedit[2], name)
            for suite in SUITES:
                t = time.monotonic()
                code, out = run_suite(suite, mver, mdir, env, sink)
                (mdir / (suite + '.log')).write_text(out)
                v, line = suite_verdict(code, out)
                if v == 'kill':
                    row['test'] = {'suite': suite, 'exit': code, 'line': line, 'seconds': round(time.monotonic() - t, 1)}
                    row['killed'], row['killed_by'] = True, 'test'
                    break
                if v == 'notrun':
                    row.setdefault('suite_not_run', []).append({'suite': suite, 'exit': code, 'line': line})
            want_proof = 'proof' in judges and dedit is not None and (not row['killed'] or name in proof_for)
            if want_proof:
                tdir = mdir / 'dafny'
                entry = copy_dafny_tree(tdir)
                replace_once(entry, dedit[0], dedit[1], name)
                full = not row['killed']
                row['proof'] = dafny_judge(entry, [] if full else filters, mdir / 'dafny.log')
                row['proof']['scope'] = 'full file' if full else 'filter ' + ','.join(filters)
                if row['proof']['outcome'] == 'error' and not row['killed']:
                    row['killed'], row['killed_by'] = True, 'proof'
            elif dedit is None and not row['killed']:
                row['proof'] = {'not_applicable': 'the shim is not proved Dafny code'}
            print('COPY %-30s %s%s%s' % (name, ('KILLED by ' + row['killed_by']) if row['killed'] else 'NOT KILLED',
                                         (' [%s: %s]' % (row['test']['suite'], row['test']['line'][:110])) if row['test'] else '',
                                         (' [proof: %s; %s; failing %s]' % (row['proof'].get('summary'), row['proof']['outcome'], ','.join(row['proof'].get('failing', [])) or '-'))
                                         if row['proof'] and 'verifies' in row['proof'] else ''), flush=True)
            result['copies'].append(row)
        if 'proof' in judges and proof_filters:
            entry = copy_dafny_tree(cdir / 'dafny')
            result['control']['proof'] = dafny_judge(entry, proof_filters, cdir / 'dafny.log')
            print('CONTROL dafny verify (filters %s): %s' % (','.join(proof_filters), result['control']['proof']['summary']), flush=True)
            if result['control']['proof']['outcome'] != 'verifies':
                raise ListError('CONTROL FAILED: the unchanged Dafny tree does not verify with the filters %s' % proof_filters)
        survivors_full = [r['name'] for r in result['copies'] if r['proof'] and r['proof'].get('scope') == 'full file' and r['proof'].get('verifies')]
        if survivors_full:
            result['control']['proof_full_note'] = 'copies that verify in full: %s (the full control is the proofs case)' % survivors_full
    except ListError as e:
        result['errors'].append(str(e))
    except NotRun as e:
        result['not_run'].append(str(e))
    finally:
        leftover = reap_under(work)   # no suite child (its sink/refund/verifier) outlives this run, on any exit path
        result['leftover_processes'] = len(leftover)
        if args.out:
            Path(args.out).write_text(json.dumps(result, indent=1, sort_keys=True) + '\n')
    for e in result['errors'] + result['not_run']:
        print(e)
    if result['errors'] or result['not_run']:
        return 2
    killed = [r for r in result['copies'] if r['killed']]
    not_killed = [r['name'] for r in result['copies'] if not r['killed']]
    print('MUTANTS copies=%d killed=%d (test %d, proof %d) not_killed=%d%s; FINITE TEST; end_to_end=false' % (
        len(result['copies']), len(killed), sum(r['killed_by'] == 'test' for r in killed), sum(r['killed_by'] == 'proof' for r in killed),
        len(not_killed), (' NOT KILLED: ' + ','.join(not_killed)) if not_killed else ''))
    return 1 if not_killed else 0


if __name__ == '__main__':
    sys.exit(main())
