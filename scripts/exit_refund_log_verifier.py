#!/usr/bin/env python3
"""Task V1, the refund-log verifier (verifier/refund_log/): EXIT checks of its Dafny proofs, its compiled program, its
tests and its changed copies.

What a pass means: on this machine the checks below gave the recorded results. PROVED applies to the named Dafny
statements of verifier/refund_log/RefundLogVerifier.dfy (pinned Dafny 4.11.0 and Z3 4.12.1, one machine). The compiled
program is a NATIVE CHECK: the Dafny compiler, its Python runtime and the file-reading shim are unverified. The suites
and the changed copies are FINITE TESTS. end_to_end=false. The bundle is a RECORD, NOT gate evidence.

Cases (python3 scripts/exit_refund_log_verifier.py --case NAME [--verifier DIR]):
  proofs     `dafny verify` of verifier/refund_log/RefundLogVerifier.dfy (it includes RatifiedSpecLemmas.dfy, the
             ratified specification and impl/Refund.dfy) with the gate options: exit 0, 0 errors, and NO out-of-resource
             or time-out line. `dafny audit` compared with the empty baseline gate/expected-audit.md. CHEAT SCAN of every
             .dfy under verifier/refund_log/ on the token level (comments and strings removed): no assume, expect,
             {:axiom}, {:verify false}, {:extern}, `decreases *`, and no declaration (lemma, function, predicate,
             method) without a body. SPEC PIN: SHA-256 of spec/refund/RefundLogSpec.dfy and `git diff origin/main --
             spec/` empty. THEOREM HEADERS: the signatures of Soundness, Completeness, the two record round trips
             (DecodeEncode, EncodeDecode) and the program contract Run are printed in full; a requires clause that uses a
             byte-string parameter other than through its length |p| fails the case unless it is the declared
             antecedent of that statement (listed in HEADERS below and printed as CALLED OUT).
             PLANT CONTROLS: the same scan and header check on scratch copies with one planted cheat each (PLANTS) must
             fail and name the plant; `dafny audit` of a copy with a planted axiom must differ from the empty baseline.
  build      verifier/refund_log/build.py --no-verify twice from clean (two output folders): are the two compiled
             outputs byte-identical? The answer is recorded (reproducible: true/false); a difference alone does not
             fail the case. The shim's line count and its entry in the trusted base of verifier/refund_log/README.md.
             No machine path of a user in a file of this package. The package's own file list: no file under a
             protected path; no package file that exists on origin/main differs from it; outside the package only
             ROADMAP.md, unsure.md and proposals/refund-log-spec-20261120/README.md may differ from origin/main (computed against the merge-base, so it stays true
             after the merge).
  suite      the review reproductions (F1 planted modules, F2 repeated runs and a 16,000-record timing guard, F4 lost
             output line, F5 duplicate JSON key) and the two tail inputs, then FORGE's and RUST's suites against the compiled verifier (a fresh build, or --verifier DIR, copied into the
             attempt folder): wal_forge.py --self-test, test_negative_controls, test_exhaustive, test_golden_rust,
             test_planted_bugs; real exit codes and their printed counts. Any NOT RUN line fails the case. TEARDOWN: no
             process that names the attempt folder is left at the end (every child gets TMPDIR under it).
  cross_target  BOTH compiled programs (verify-refund-log, Python; verify-refund-log-node, JavaScript) on every input
             that FORGE's and RUST's suites make: the suites run against a cross wrapper that runs both programs with the
             same arguments, compares stdout, exit code, the --json form and the --encode bytes, logs each call, and
             answers with the Node program (so the suites also judge the Node program); plus the owner's integer-boundary
             group (both programs, plain and --json, and FORGE's ref_fold.py for the class), the two tail inputs of the
             owner's decision, and the review reproductions, on both. Any difference fails the case.
  mutations  tests/refund_log_verifier/mutants_verifier.py on the compiled verifier, judges test and proof, with the
             proof kill shown on PROOF_DEMO. A copy that nothing kills is NOT KILLED and the case FAILS; there is no
             accepted list. --no-proof-judge runs the test judge only; the case is then NOT RUN (exit 2), never PASSED.
  evidence   build, proofs, suite, cross_target and mutations twice into build/refund_log_verifier_exit/evidence/attempt-NNNN/run-1
             and run-2. evidence.json holds only deterministic content (hashes, counts, verdicts, per changed copy only
             applied/killed/judge class); times and machine facts go to measurements.json. The two bundles must be
             byte-identical; the SHA-256 is printed. A failed case is recorded in the bundle and makes the exit 1.
Raw outputs: build/refund_log_verifier_exit/<case>/attempt-NNNN/ (ignored by git).
Dafny: one Dafny job at a time on this machine. Before each Dafny step this script waits until no process matches
'dafny/dafny|Holmake|z3-4.12.1|run_regression_copy' for 3 checks one minute apart (at most 60 min, then NOT RUN).
Tools (no path of any machine is written here; nothing falls back silently):
  FORGE_TOOLCHAIN_ROOT  the checkout that holds .toolchain/ (cwd of every Dafny run); else this repository.
  FORGE_DAFNY           the dafny binary; else <toolchain root>/.toolchain/dafny-4.11.0/dafny/dafny.
  FORGE_RUSTC           the rustc binary for the suites (they check the pinned version); else rustc on PATH.
  FORGE_NODE            the pinned Node 24.3.0 for build.py's JavaScript target (read by build.py).
Exit: 0 every check of the case is true; 1 a check failed; 2 the case could not run (NOT RUN).
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / 'build/refund_log_verifier_exit'
DAFNY_ROOT = Path(os.environ.get('FORGE_TOOLCHAIN_ROOT') or ROOT)
DAFNY = os.environ.get('FORGE_DAFNY') or str(DAFNY_ROOT / '.toolchain/dafny-4.11.0/dafny/dafny')
DAFNY_OPTIONS = ['--solver-path', '.toolchain/dafny-4.11.0/dafny/z3/bin/z3-4.12.1', '--resource-limit', '1000000',
                 '--verification-time-limit', '0', '--cores', '1', '--verify-included-files', '--track-print-effects']
BASELINE = ROOT / 'gate/expected-audit.md'
SLOT = re.compile(r'dafny/dafny|Holmake|z3-4\.12\.1|run_regression_copy')
QUIET = ('sh', 'bash', 'zsh', 'pgrep', 'grep', 'ps', 'tail', 'sleep')
PY = sys.executable

VDIR = 'verifier/refund_log'
ENTRY = VDIR + '/RefundLogVerifier.dfy'
SHIM_SRC = VDIR + '/verify_refund_log.py'
SPEC = 'spec/refund/RefundLogSpec.dfy'
SPEC_SHA256 = '1a8c7c2a306cd651ea691a9d93f96063c5dffb1686ee1f43845e2de727b4bc5a'
SINK = 'src/silicon_sink/sink.rs'
TESTS = 'tests/refund_log_verifier'
PACKAGE = (VDIR + '/', TESTS + '/', 'scripts/exit_refund_log_verifier.py')
PROTECTED = ('spec/', 'gate/', 'clearing/', 'policy/', 'src/', 'spec.lock', 'package.json', 'package-lock.json', 'tsconfig.json')
# Files of main that this package may change, by name: the records, and the dated status note that the owner asked for at
# the top of the ratified proposal's README (ratified by pull request 88). Any other changed file outside the package fails.
ALLOWED_OUTSIDE = ('ROADMAP.md', 'unsure.md', 'proposals/refund-log-spec-20261120/README.md')
USER_PATH = re.compile(r'/(?:Users|home)/[^/\s\'"]+/|/private/(?:tmp|var)/|[A-Za-z]:\\\\Users\\\\')
PROOF_DEMO = ['chain_not_checked', 'amount_le_to_lt', 'torn_tail_accept']

# The statements whose headers are checked: name -> (role, declared antecedents allowed on byte parameters).
HEADERS = {
    'Soundness': ('SOUNDNESS: ACCEPT on arbitrary bytes implies a valid history', ['VerifySpec(wal).Accept?']),
    'Completeness': ('COMPLETENESS: the model log of every valid history (plus any torn part) is accepted', []),
    'DecodeEncode': ('ROUND TRIP 1: decode(encode(fields)) == fields (record level)', []),
    'EncodeDecode': ('ROUND TRIP 2: a record that passes the framing checks equals encode(decode(record))', ['|r| == 64 && Framed(r)']),
    'Run': ('PROGRAM CONTRACT: the verdict and exit code of the compiled method on any bytes and arguments', []),
}
BYTE_NEWTYPE = 'newtype byte = x: int | 0 <= x < 256'

ACCEPT_MEANING = ('ACCEPT (exit 0) means: the bytes of this file decode, with no byte ignored, to a genesis and N refund records '
                  'that form a valid history of the ratified refund-log specification spec/refund/RefundLogSpec.dfy '
                  '(SHA-256 %s): no request id settles twice and original = remaining + the sum of the amounts.' % SPEC_SHA256)
LABELS = {
    'kind': 'record, NOT gate evidence',
    'gate_accepted': False,
    'end_to_end': False,
    'proved': 'PROVED applies to the named Dafny statements of %s (Soundness, SoundnessExists, Completeness, ExactOnModelLogs, '
              'DecodeEncode, EncodeDecode, EncodedLogInjective, and the postconditions of Verify, Run, Finish, EncodeEntry), '
              'checked by the pinned Dafny 4.11.0 and Z3 4.12.1 on one machine' % ENTRY,
    'native_check': 'NATIVE CHECK: the compiled program build/refund_log_verifier/ (the unverified Dafny compiler and its Python '
                    'runtime; the unverified shim %s; the Python interpreter)' % SHIM_SRC,
    'finite_test': 'FINITE TEST: the suites of %s and the changed copies, on one machine. A test count is not a proof.' % TESTS,
    'accept_means': ACCEPT_MEANING,
    'does_not_establish': ['that the engine wrote these bytes (CRC-32 and FNV-1a-128 are unkeyed)',
                           'that the file is complete (clean truncation; a joint restore of log and ratchet needs an outside anchor: H_LOG)',
                           'that the drive kept it', 'that any payment happened', 'who sent a request',
                           'anything about the engine code or hardware', 'prevention: a bad transition is found only after it is on disk'],
}


class Failed(Exception):
    pass


class NotRun(Exception):
    pass


def require(cond, msg):
    if not cond:
        raise Failed(msg)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fsha(rel):
    return sha((ROOT / rel).read_bytes())


def canonical(obj):
    return (json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode()


class Meter:
    """Times and machine facts: measurements.json only, never the bundle."""
    def __init__(self):
        self.data = {}

    def put(self, key, value):
        self.data[key] = value


M = Meter()


def run_group(argv, cwd=ROOT, timeout=7200, env=None):
    """The child in its own process group; SIGKILL to the group and reap on every exit path (tests/primitives_v2/mutants.py)."""
    p = subprocess.Popen([str(a) for a in argv], cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                         errors='replace', start_new_session=True, env=env or dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
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


def git(*args):
    p = subprocess.run(['git'] + list(args), cwd=str(ROOT), capture_output=True, text=True)
    return p.returncode, p.stdout


# --------------------------------------------------------------------------------------------------------- Dafny slot
def slot_busy():
    out = subprocess.run(['ps', '-ax', '-o', 'pid=,command='], capture_output=True, text=True).stdout
    for line in out.splitlines():
        pid, _, cmd = line.strip().partition(' ')
        first = os.path.basename(cmd.split(' ', 1)[0]).lstrip('-')
        if pid.isdigit() and int(pid) != os.getpid() and first not in QUIET and SLOT.search(cmd):
            return True
    return False


def wait_slot(label, limit=3600):
    free, waited = 0, 0
    while True:
        free = 0 if slot_busy() else free + 1
        if free >= 3:
            M.put('slot_wait_s/' + label, waited)
            return
        if waited >= limit:
            raise NotRun('NOT RUN: %s: the Dafny slot was not free for 3 checks in %d min' % (label, limit // 60))
        time.sleep(60)
        waited += 60


def need_dafny():
    if not Path(DAFNY).is_file():
        raise NotRun('NOT RUN: the pinned Dafny is missing at %s: set FORGE_TOOLCHAIN_ROOT to the checkout that holds .toolchain/, '
                     'or FORGE_DAFNY' % DAFNY)


def dafny(args, label, log):
    need_dafny()
    wait_slot(label)
    t = time.monotonic()
    code, out = run_group([DAFNY] + args, cwd=DAFNY_ROOT, timeout=14400)
    M.put('dafny_s/' + label, round(time.monotonic() - t, 1))
    with open(log, 'a') as f:
        f.write('$ dafny %s\nexit %s\n%s\n' % (' '.join(str(a) for a in args), code, out))
    return code, out


# --------------------------------------------------------------------------------------------------------- Dafny tokens
def tokenize(text):
    """Dafny tokens outside comments and string or char literals: [(token, line, start, end, first on its line)].
    String literals become the token STR, char literals CHR, numbers NUM."""
    toks, i, n, line = [], 0, len(text), 1

    def add(tok, start, end):
        toks.append((tok, line, start, end, not toks or toks[-1][1] != line))
    ident0 = re.compile(r"[A-Za-z_]")
    ident = re.compile(r"[A-Za-z0-9_'?]")
    while i < n:
        c = text[i]
        if c == '\n':
            line += 1
            i += 1
        elif c.isspace():
            i += 1
        elif text.startswith('//', i):
            while i < n and text[i] != '\n':
                i += 1
        elif text.startswith('/*', i):
            depth, i = 1, i + 2
            while i < n and depth:
                if text.startswith('/*', i):
                    depth, i = depth + 1, i + 2
                elif text.startswith('*/', i):
                    depth, i = depth - 1, i + 2
                else:
                    line += text[i] == '\n'
                    i += 1
        elif c == '@' and text.startswith('@"', i):
            s0, i = i, i + 2
            while i < n and not (text[i] == '"' and not text.startswith('""', i)):
                i += 2 if text.startswith('""', i) else 1
                line += text[i - 1] == '\n'
            i += 1
            add('STR', s0, i)
        elif c == '"':
            s0, i = i, i + 1
            while i < n and text[i] != '"':
                i += 2 if text[i] == '\\' else 1
            i += 1
            add('STR', s0, i)
        elif c == "'":
            j = text.index("'", i + 2 if text[i + 1] == '\\' else i + 1) if i + 1 < n else n
            if text[i + 1] == '\\' and text[i + 2] == "'":
                j = text.index("'", i + 3)
            add('CHR', i, j + 1)
            i = j + 1
        elif ident0.match(c):
            j = i + 1
            while j < n and ident.match(text[j]):
                j += 1
            add(text[i:j], i, j)
            i = j
        elif c.isdigit():
            j = i + 1
            while j < n and (text[j].isalnum() or text[j] in '_.') and not text.startswith('..', j):
                j += 1
            add('NUM', i, j)
            i = j
        else:
            for op in ('<==>', '==>', '<==', '::', ':=', '==', '!=', '<=', '>=', '&&', '||', '..', '=>'):
                if text.startswith(op, i):
                    add(op, i, i + len(op))
                    i += len(op)
                    break
            else:
                add(c, i, i + 1)
                i += 1
    return toks


DECL = {'lemma', 'function', 'method', 'predicate', 'constructor', 'iterator'}
STOP = DECL | {'datatype', 'codatatype', 'const', 'module', 'import', 'newtype', 'type', 'class', 'trait', 'include', 'ghost',
               'opaque', 'static', 'abstract', 'twostate', 'least', 'greatest', 'export'}
EXPR_KW = {'then', 'else', 'in', 'if', 'match', 'case', 'forall', 'exists', 'var', 'returns', 'requires', 'ensures', 'decreases',
           'reads', 'modifies', 'by', 'calc', 'old', 'fresh', 'not'}
CHEAT_WORDS = {'assume', 'expect'}
CHEAT_ATTRS = {'axiom', 'extern', 'verify'}


def ends_expression(tok):
    return tok in (')', ']', '}', '>', '|', 'STR', 'CHR', 'NUM') or (re.match(r"[A-Za-z_]", tok) is not None and tok not in EXPR_KW)


def skip_block(toks, k):
    """toks[k] is '{'; returns the index after its matching '}'."""
    depth = 0
    while k < len(toks):
        if toks[k][0] == '{':
            depth += 1
        elif toks[k][0] == '}':
            depth -= 1
            if depth == 0:
                return k + 1
        k += 1
    return k


def declarations(toks):
    """[(kind, name, line, header token range (a, b), has_body)] for every lemma/function/predicate/method."""
    out, k = [], 0
    while k < len(toks):
        t = toks[k][0]
        if t in DECL and not (t == 'method' and k > 0 and toks[k - 1][0] == 'by'):
            start, k = k, k + 1
            while k + 1 < len(toks) and toks[k][0] == '{' and toks[k + 1][0] == ':':   # attributes before the name
                k = skip_block(toks, k)
            name = toks[k][0] if k < len(toks) else '?'
            depth, body = 0, False
            while k < len(toks):
                tok = toks[k][0]
                if tok == '{' and k + 1 < len(toks) and toks[k + 1][0] == ':':
                    k = skip_block(toks, k)
                    continue
                if depth == 0 and tok == '{' and (toks[k][4] or ends_expression(toks[k - 1][0]) or
                                                  (toks[k - 1][0] == '*' and toks[k - 2][0] == 'decreases')):
                    body = True
                    break
                if depth == 0 and (tok in STOP or tok == '}') and k > start + 1 and not (tok == 'method' and toks[k - 1][0] == 'by'):
                    break
                if tok in '([{':
                    depth += 1
                elif tok in ')]}':
                    depth -= 1
                k += 1
            out.append((t, name, toks[start][1], (start, k), body))
            if body:
                k = skip_block(toks, k)
                if k + 1 < len(toks) and toks[k][0] == 'by' and toks[k + 1][0] == 'method':
                    k = skip_block(toks, k + 2)
            continue
        k += 1
    return out


# A planted text that the scanner must flag line by line (its control; run in the proofs case).
SCANNER_CONTROL = """module X {
  lemma A() ensures true
  lemma B() { assume false; }
  function C(x: int): int { if x > 0 then 1 else 0 }
  lemma {:axiom} D() ensures false {}
  method E() decreases * { expect 1 == 1; }
  // assume {:axiom} in a comment, and in a string:
  const s := "assume {:axiom} lemma W()"
  method {:verify false} G() {}
  function {:extern} H(): int
  predicate P(s: set<int>) requires s == {}
  {
    true
  }
  lemma Q() ensures 1 in {1, 2}
  {}
  function R(c: char): bool { c == '\\'' }
  lemma Z()
}
"""
SCANNER_EXPECTED = ['x.dfy:2: lemma A has no body', 'x.dfy:3: `assume`', 'x.dfy:5: `{:axiom}`', 'x.dfy:6: `decreases *`',
                    'x.dfy:6: `expect`', 'x.dfy:9: `{:verify false}`', 'x.dfy:10: `{:extern}`', 'x.dfy:10: function H has no body',
                    'x.dfy:18: lemma Z has no body']


def scanner_control(work):
    d = work / 'scanner-control'
    d.mkdir(parents=True, exist_ok=True)
    (d / 'x.dfy').write_text(SCANNER_CONTROL)
    found, _ = cheat_scan([d / 'x.dfy'], base=d)
    return sorted(found) == sorted(SCANNER_EXPECTED), found


def cheat_scan(paths, base=None):
    findings, counts = [], {}
    for path in paths:
        rel = str(path.relative_to(base or ROOT))
        toks = tokenize(path.read_text())
        decls = declarations(toks)
        counts[rel] = {'tokens': len(toks), 'declarations': len(decls)}
        for k, (t, line, _, _, _) in enumerate(toks):
            if t in CHEAT_WORDS:
                findings.append('%s:%d: `%s`' % (rel, line, t))
            if t == 'decreases' and k + 1 < len(toks) and toks[k + 1][0] == '*':
                findings.append('%s:%d: `decreases *`' % (rel, line))
            if t == '{' and k + 2 < len(toks) and toks[k + 1][0] == ':' and toks[k + 2][0] in CHEAT_ATTRS:
                attr = toks[k + 2][0]
                if attr != 'verify' or (k + 3 < len(toks) and toks[k + 3][0] == 'false'):
                    findings.append('%s:%d: `{:%s%s}`' % (rel, line, attr, ' false' if attr == 'verify' else ''))
        for kind, name, line, _, body in decls:
            if not body:
                findings.append('%s:%d: %s %s has no body' % (rel, line, kind, name))
    return findings, counts


def clauses(toks, a, b):
    """Split the header toks[a:b] at depth 0 on the clause keywords. Returns (params text, [(keyword, tokens)])."""
    out, cur, depth, params = [], None, 0, None
    k = a
    while k < b:
        t = toks[k][0]
        if t == '{' and k + 1 < b and toks[k + 1][0] == ':':
            k = skip_block(toks, k)
            continue
        if params is None and t == '(':
            j, d = k, 0
            while j < b:
                d += toks[j][0] in '([{'
                d -= toks[j][0] in ')]}'
                j += 1
                if d == 0:
                    break
            params = [x[0] for x in toks[k + 1:j - 1]]
            k = j
            continue
        if depth == 0 and t in ('requires', 'ensures', 'decreases', 'reads', 'modifies', 'returns'):
            cur = (t, [])
            out.append(cur)
        elif cur is not None:
            cur[1].append(k)
        depth += t in '([{'
        depth -= t in ')]}'
        k += 1
    return params or [], out


def norm(text):
    return re.sub(r'\s+', '', text)


def header_check(path):
    """Print the full signature of each statement of HEADERS and check its requires clauses (see the case text)."""
    text = path.read_text()
    toks = tokenize(text)
    decls = {name: (kind, line, rng) for kind, name, line, rng, _ in declarations(toks)}
    lines, findings, record = [], [], {}
    m = re.search(r'newtype\s+byte\s*=\s*[^\n]*', text)
    byte_ok = m is not None and ' '.join(m.group(0).split()) == BYTE_NEWTYPE
    lines.append('  byte type: %s  [%s]' % (m.group(0).strip() if m else 'NOT FOUND', 'every value 0..255: ok' if byte_ok else 'FINDING'))
    if not byte_ok:
        findings.append('the byte type is not `%s`' % BYTE_NEWTYPE)
    src = text.splitlines()
    for name, (role, allowed) in HEADERS.items():
        if name not in decls:
            findings.append('statement %s not found in %s' % (name, path.name))
            continue
        kind, line, (a, b) = decls[name]
        end = toks[b][1] if b < len(toks) else len(src)
        signature = '\n'.join(src[line - 1:end - 1]).rstrip()
        params, cls = clauses(toks, a, b)
        ptext = ' '.join(params)
        byte_params = [p.group(1) for p in re.finditer(r'(\w+)\s*:\s*seq\s*<\s*byte\s*>', ptext.replace(' ', ' '))]
        reqs = [([toks[k][0] for k in c[1]], ' '.join(text[toks[c[1][0]][2]:toks[c[1][-1]][3]].split())) for c in cls if c[0] == 'requires' and c[1]]
        lines.append('  %s %s  (%s)' % (kind, name, role))
        lines.extend('    | ' + s for s in signature.splitlines())
        notes = []
        for r, rtext in reqs:
            uses = [k for k, t in enumerate(r) if t in byte_params and not (0 < k < len(r) - 1 and r[k - 1] == '|' and r[k + 1] == '|')]
            if not uses:
                notes.append('requires %s: no use of a byte parameter except its length' % rtext if any(t in byte_params for t in r)
                             else 'requires %s: not about a byte parameter' % rtext)
            elif norm(rtext) in [norm(x) for x in allowed]:
                notes.append('CALLED OUT: requires %s: a predicate on the byte parameter, the declared antecedent of this statement' % rtext)
            else:
                notes.append('FINDING: requires %s: a precondition on the byte parameter %s' % (rtext, [r[k] for k in uses]))
                findings.append('%s: requires %s restricts the bytes' % (name, rtext))
        if not reqs:
            notes.append('no requires clause: the statement holds for every value of its parameters')
        lines.extend('    > ' + x for x in notes)
        record[name] = {'kind': kind, 'byte_parameters': byte_params, 'requires': [x[1] for x in reqs],
                        'signature_sha256': sha(signature.encode()), 'findings': [x for x in notes if x.startswith('FINDING')]}
    return lines, findings, record


# --------------------------------------------------------------------------------------------------------- package
def package_files():
    c1, tracked = git('ls-files', '--', *PACKAGE)
    c2, other = git('ls-files', '--others', '--exclude-standard', '--', *PACKAGE)
    if c1 or c2:
        raise NotRun('NOT RUN: git ls-files exit %s/%s' % (c1, c2))
    files = sorted({f for f in (tracked + other).splitlines() if f and '__pycache__' not in f and (ROOT / f).is_file()})
    return files


def package_rules(files):
    c, _ = git('rev-parse', '--verify', '--quiet', 'origin/main')
    if c:
        raise NotRun('NOT RUN: no origin/main in this repository (git fetch origin main)')
    protected = [f for f in files if f.startswith(PROTECTED)]
    modified_main = []
    for f in files:
        c, blob = git('rev-parse', '--verify', '--quiet', 'origin/main:' + f)
        if c == 0:
            _, here = git('hash-object', f)
            if here.strip() != blob.strip():
                modified_main.append(f)
    c, base = git('merge-base', 'origin/main', 'HEAD')
    if c:
        raise NotRun('NOT RUN: git merge-base origin/main HEAD exit %d' % c)
    c1, committed = git('diff', '--name-only', base.strip())
    if c1:
        raise NotRun('NOT RUN: git diff --name-only exit %d' % c1)
    outside = sorted(f for f in committed.splitlines() if f and not f.startswith(PACKAGE) and f not in ALLOWED_OUTSIDE)
    paths = []
    for f in files:
        for k, row in enumerate((ROOT / f).read_text(errors='replace').splitlines(), 1):
            if USER_PATH.search(row):
                paths.append('%s:%d' % (f, k))
    return {'package_files': len(files), 'under_protected_path': protected, 'differs_from_origin_main': modified_main,
            'changed_outside_package': outside, 'machine_paths': paths}


# --------------------------------------------------------------------------------------------------------- cases
def build_once(out, log):
    need_dafny()
    wait_slot('build-' + out.name)
    env = dict(os.environ, FORGE_TOOLCHAIN_ROOT=str(DAFNY_ROOT), FORGE_DAFNY=DAFNY, PYTHONDONTWRITEBYTECODE='1')
    t = time.monotonic()
    code, text = run_group([PY, ROOT / VDIR / 'build.py', '--out', out, '--no-verify'], env=env)
    M.put('build_s/' + out.name, round(time.monotonic() - t, 1))
    with open(log, 'a') as f:
        f.write('$ build.py --out %s --no-verify\nexit %s\n%s\n' % (out.name, code, text))
    require(code == 0 and (out / 'verify-refund-log').is_file(), 'BUILD: build.py exit %s: %s' % (code, text[-800:]))
    files = {}
    for p in sorted(out.rglob('*')):
        if not p.is_file() or '__pycache__' in p.parts or p.name in ('dafny-build.log', 'build.json'):
            continue
        data = p.read_bytes()
        if p.name.startswith('verify-refund-log') and data.startswith(b'#!/'):
            # a launcher: its first line names the absolute interpreter of the build, a machine fact (measurements only)
            first, _, rest = data.partition(b'\n')
            M.put('launcher_first_line/%s/%s' % (out.name, p.name), first.decode('utf-8', 'replace'))
            data = b'#!<interpreter of the build>\n' + rest
        files[str(p.relative_to(out))] = sha(data)
    return files


def case_build(work):
    work.mkdir(parents=True, exist_ok=True)
    log = work / 'build.log'
    one = build_once(work / 'build-1', log)
    two = build_once(work / 'build-2', log)
    differ = sorted(k for k in set(one) | set(two) if one.get(k) != two.get(k))
    reproducible = not differ
    shim_text = (ROOT / SHIM_SRC).read_text()
    shim_lines = len(shim_text.splitlines())
    fallback = shim_text.splitlines()[0] == '#!/usr/bin/env -S python3 -I'
    print('  tracked shim first line is the `#!/usr/bin/env -S python3 -I` fallback: %s' % fallback, flush=True)
    require(fallback, 'BUILD: the tracked shim does not start with #!/usr/bin/env -S python3 -I')
    readme = (ROOT / VDIR / 'README.md').read_text() if (ROOT / VDIR / 'README.md').is_file() else ''
    node_shim = ROOT / VDIR / 'verify_refund_log_node.cjs'
    node_lines = len(node_shim.read_text().splitlines()) if node_shim.is_file() else None
    listed = 'verify_refund_log.py' in readme and ('%d lines' % shim_lines) in readme and \
        (node_lines is None or ('verify_refund_log_node.cjs' in readme and ('%d lines' % node_lines) in readme))
    M.put('node_shim_lines', node_lines)
    files = package_files()
    rules = package_rules(files)
    M.put('build_output_sha256', {'build-1': one, 'build-2': two})
    print('  two builds: byte-identical %s%s' % (reproducible, '' if reproducible else ' (differ: %s)' % differ), flush=True)
    print('  shim %s: %d lines; listed with that count in README trusted base: %s' % (SHIM_SRC, shim_lines, listed), flush=True)
    print('  package: %d files; under protected path %s; differ from origin/main %s; changed outside the package %s; machine paths %s' % (
        rules['package_files'], rules['under_protected_path'] or 'none', rules['differs_from_origin_main'] or 'none',
        rules['changed_outside_package'] or 'none', rules['machine_paths'] or 'none'), flush=True)
    require(listed, 'BUILD: README.md does not list the shims (verify_refund_log.py %d lines; verify_refund_log_node.cjs %s lines) in its trusted base' % (shim_lines, node_lines))
    require(not rules['under_protected_path'] and not rules['differs_from_origin_main'] and not rules['changed_outside_package']
            and not rules['machine_paths'], 'BUILD: package rules: %r' % rules)
    return {'builds': 2, 'build_exit': [0, 0], 'reproducible': reproducible, 'differing_files': differ,
            'reproducible_reason': 'the two compiled outputs are byte-identical' if reproducible else
            'the Dafny Python back end wrote different bytes for the same input in two clean runs: %s' % differ,
            'compared': 'every output file; the launcher with its first line (the absolute interpreter) replaced by a placeholder',
            'compiled_files': len(one), 'shim_lines': shim_lines, 'node_shim_lines': node_lines, 'tracked_shim_fallback_line': fallback, 'shim_listed_in_trusted_base': listed, 'package': rules,
            'package_files': {f: fsha(f) for f in files}}, work / 'build-1'


# Planted cheats (the owner's negative control of the scan): each is applied to a scratch copy of the real sources; the
# scan (or the header check) must FAIL and name it. (name, file, exact text or None = before the last '}', new text,
# text that a finding must contain)
END = None
PLANTS = [
    ('axiom_false', ENTRY, END, '  lemma {:axiom} False0() ensures false\n', '`{:axiom}`'),
    ('assume_in_lemma_body', ENTRY, '    var v := VerifySpec(wal);\n    var n := |wal| / 64;', '    var v := VerifySpec(wal);\n    assume false;\n    var n := |wal| / 64;', '`assume`'),
    ('bodyless_lemma', ENTRY, END, '  lemma Bodyless0()\n    ensures 1 == 2\n', 'lemma Bodyless0 has no body'),
    ('bodyless_function_in_ensures', ENTRY, END, '  function Ghost0(x: int): bool\n  lemma UsesGhost0()\n    ensures Ghost0(1)\n  {\n  }\n',
     'function Ghost0 has no body'),
    ('verify_false_on_soundness', ENTRY, '  lemma {:isolate_assertions} Soundness(wal: seq<byte>)', '  lemma {:isolate_assertions} {:verify false} Soundness(wal: seq<byte>)',
     '`{:verify false}`'),
    ('wellformed_precondition_on_soundness', ENTRY, '  lemma {:isolate_assertions} Soundness(wal: seq<byte>)\n    requires VerifySpec(wal).Accept?\n',
     '  lemma {:isolate_assertions} Soundness(wal: seq<byte>)\n    requires VerifySpec(wal).Accept?\n    requires WellFormed(wal)\n',
     'Soundness: requires WellFormed(wal) restricts the bytes'),
    ('expect_in_compiled_code', ENTRY, '    if |wal| > MaxBytes { return Unverifiable(TooLarge); }\n    var n := |wal| / 64;',
     '    if |wal| > MaxBytes { return Unverifiable(TooLarge); }\n    var n := |wal| / 64;\n    expect n >= 1;', '`expect`'),
    ('dodge_spaced_attribute', ENTRY, END, '  lemma {: axiom } False1() ensures false\n', '`{:axiom}`'),
    ('dodge_comment_in_attribute', ENTRY, END, '  lemma {:/* hidden */axiom} False2() ensures false\n', '`{:axiom}`'),
    ('dodge_nested_module', VDIR + '/RatifiedSpecLemmas.dfy', END, '  module Inner {\n    lemma Hidden0()\n      ensures false\n  }\n',
     'lemma Hidden0 has no body'),
    ('dodge_assume_after_comment', ENTRY, '    var v := VerifySpec(wal);\n    var n := |wal| / 64;',
     '    var v := VerifySpec(wal);\n    /* a comment */ assume/* split */ false;\n    var n := |wal| / 64;', '`assume`'),
]


def apply_plant(root, rel, old, new):
    p = root / rel
    text = p.read_text()
    if old is None:
        k = text.rstrip().rfind('}')
        text = text[:k] + new + text[k:]
    else:
        require(text.count(old) == 1, 'PROOFS: plant anchor occurs %d times in %s: %r' % (text.count(old), rel, old[:60]))
        text = text.replace(old, new)
    p.write_text(text)


def plant_controls(work):
    """Every plant must make the scan or the header check fail and name it. Returns {plant: caught finding}."""
    out, missed = {}, []
    for name, rel, old, new, want in PLANTS:
        d = work / 'plants' / name
        for f in sorted((ROOT / VDIR).glob('*.dfy')):
            (d / VDIR).mkdir(parents=True, exist_ok=True)
            shutil.copyfile(f, d / VDIR / f.name)
        apply_plant(d, rel, old, new)
        found, _ = cheat_scan(sorted((d / VDIR).glob('*.dfy')), base=d)
        _, hfind, _ = header_check(d / ENTRY)
        hit = [x for x in found + hfind if want in x]
        out[name] = hit[0] if hit else None
        if not hit:
            missed.append('%s (scan said %s)' % (name, found + hfind))
    return out, missed


def audit_plant_control(work, log):
    """Dafny-level control: with `lemma {:axiom} False0() ensures false` planted, `dafny audit` must NOT equal the empty baseline."""
    d = work / 'audit-plant'
    for rel in (VDIR + '/RefundLogVerifier.dfy', VDIR + '/RatifiedSpecLemmas.dfy', SPEC, 'spec/refund/RefundSpec.dfy', 'impl/Refund.dfy'):
        (d / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / rel, d / rel)
    apply_plant(d, ENTRY, None, PLANTS[0][3])
    report = work / 'audit-plant.md'
    shutil.copyfile(BASELINE, report)
    code, text = dafny(['audit', d / ENTRY, '--report-format', 'md', '--report-file', report, '--compare-report'], 'audit-plant', log)
    # `--compare-report` leaves the given file as it is and writes the generated report to <file>.expect on a mismatch
    gen = Path(str(report) + '.expect')
    generated = gen.read_text() if gen.is_file() else report.read_text()
    m = re.search(r'completed with (\d+) findings?', text)
    differs = code != 0 and generated.encode() != BASELINE.read_bytes()
    return {'audit_exit': code, 'report_differs_from_empty_baseline': differs, 'names_False0': 'False0' in generated,
            'findings': int(m.group(1)) if m else None}


def case_proofs(work):
    work.mkdir(parents=True, exist_ok=True)
    log = work / 'dafny.log'
    out = {}
    # spec pin first (cheap)
    spec_sha = fsha(SPEC)
    c1, d = git('diff', '--name-only', 'origin/main', '--', 'spec/')
    c2, u = git('status', '--porcelain', '--', 'spec/')
    if c1 or c2:
        raise NotRun('NOT RUN: git diff origin/main -- spec/ exit %s (status %s): is origin/main fetched?' % (c1, c2))
    out['spec_pin'] = {'file': SPEC, 'sha256': spec_sha, 'expected': SPEC_SHA256, 'equal': spec_sha == SPEC_SHA256,
                       'git_diff_origin_main_spec_empty': d.strip() == '' and u.strip() == ''}
    print('  spec pin: %s sha256 %s (expected %s); git diff origin/main -- spec/ empty: %s' % (
        SPEC, spec_sha[:16] + '...', 'equal' if spec_sha == SPEC_SHA256 else 'NOT EQUAL', out['spec_pin']['git_diff_origin_main_spec_empty']), flush=True)
    # cheat scan and headers (no Dafny)
    dfy = sorted((ROOT / VDIR).glob('**/*.dfy'))
    findings, counts = cheat_scan(dfy)
    control_ok, control_found = scanner_control(work)
    print('  cheat scan control (a planted text with %d cheats): found exactly them: %s' % (len(SCANNER_EXPECTED), control_ok), flush=True)
    require(control_ok, 'PROOFS: the cheat scanner missed or added a finding on its control: %s' % control_found)
    out['cheat_scan'] = {'scanner_control_ok': control_ok, 'files': {str(p.relative_to(ROOT)): fsha(str(p.relative_to(ROOT))) for p in dfy}, 'counts': counts,
                         'findings': findings, 'extern_outside_dafny': SHIM_SRC + ' (the unverified shim, listed in the trusted base)'}
    print('  cheat scan: %d .dfy files, %d declarations, findings: %s' % (len(dfy), sum(c['declarations'] for c in counts.values()),
                                                                        findings or 'none'), flush=True)
    caught, missed = plant_controls(work)
    out['plant_controls'] = {'plants': len(PLANTS), 'caught': caught, 'missed': missed}
    print('  planted cheats: %d of %d caught by the scan or the header check%s' % (len(PLANTS) - len(missed), len(PLANTS),
                                                                               '; MISSED: %s' % missed if missed else ''), flush=True)
    for k, v in caught.items():
        print('    plant %-38s -> %s' % (k, v), flush=True)
    hlines, hfind, hrec = header_check(ROOT / ENTRY)
    out['headers'] = {'statements': hrec, 'findings': hfind}
    print('  theorem headers (%s):' % ENTRY)
    print('\n'.join(hlines), flush=True)
    # Dafny verify and audit
    code, text = dafny(['verify', ROOT / ENTRY] + DAFNY_OPTIONS, 'verify', log)
    m = re.search(r'finished with (\d+) verified, (\d+) errors?([^\n]*)', text)
    oor = re.findall(r'[^\n]*(?:out of resource|timed? ?out)[^\n]*', text, re.I)
    out['verify'] = {'command': 'dafny verify %s <gate options> (a plain verify; `dafny build` of build.py prints another count)' % ENTRY,
                     'file': ENTRY, 'exit': code, 'summary': m.group(0) if m else None, 'verified': int(m.group(1)) if m else None,
                     'errors': int(m.group(2)) if m else None, 'out_of_resource_or_timeout_lines': len(oor)}
    print('  dafny verify: exit %s; %s; out-of-resource/time-out lines: %d' % (code, m.group(0) if m else 'NO SUMMARY', len(oor)), flush=True)
    report = work / 'audit.md'
    shutil.copyfile(BASELINE, report)
    acode, atext = dafny(['audit', ROOT / ENTRY, '--report-format', 'md', '--report-file', report, '--compare-report'], 'audit', log)
    equal = report.read_bytes() == BASELINE.read_bytes()
    equal = equal and acode == 0 and not Path(str(report) + '.expect').exists()
    out['audit'] = {'exit': acode, 'equals_empty_baseline': equal}
    print('  dafny audit: exit %s; report equal to the empty baseline gate/expected-audit.md: %s' % (acode, equal), flush=True)
    out['audit_plant_control'] = audit_plant_control(work, log)
    print('  audit control (False0 axiom planted): audit exit %s; report differs from the empty baseline: %s; names False0: %s' % (
        out['audit_plant_control']['audit_exit'], out['audit_plant_control']['report_differs_from_empty_baseline'],
        out['audit_plant_control']['names_False0']), flush=True)
    problems = []
    if missed:
        problems.append('PLANTS missed by the scan: %s' % missed)
    if not (out['audit_plant_control']['report_differs_from_empty_baseline'] and out['audit_plant_control']['names_False0']):
        problems.append('AUDIT CONTROL: the planted axiom did not change the audit report')
    if not out['spec_pin']['equal'] or not out['spec_pin']['git_diff_origin_main_spec_empty']:
        problems.append('SPEC PIN')
    if findings:
        problems.append('CHEAT SCAN %s' % findings)
    if hfind:
        problems.append('HEADERS %s' % hfind)
    if code != 0 or not m or m.group(2) != '0' or oor:
        problems.append('VERIFY exit %s %s %s' % (code, m.group(0) if m else 'no summary', oor[:3]))
    if acode != 0 or not equal:
        problems.append('AUDIT exit %s equal %s' % (acode, equal))
    require(not problems, 'PROOFS: ' + '; '.join(problems))
    return out


def counts_of(suite, out):
    c = {}
    if suite == 'negative_controls':
        m = re.search(r'COUNTS agree=(\d+) disagree=(\d+) not_run=(\d+) sink_differs=(\d+)', out)
        if m:
            c = dict(zip(('agree', 'disagree', 'not_run', 'sink_differs'), map(int, m.groups())))
        c['sink_findings'] = len(re.findall(r'^SINK FINDING', out, re.M))
    elif suite == 'exhaustive':
        m = re.search(r'BITS flipped=(\d+) verifier_rejected=(\d+) verifier_not_rejected=(\d+) oracle_rejected=(\d+)', out)
        if m:
            c['bits'] = dict(zip(('flipped', 'verifier_rejected', 'verifier_not_rejected', 'oracle_rejected'), map(int, m.groups())))
        c['offsets'] = {' '.join(r.split()[:-1]): int(r.split()[-1]) for r in re.findall(r'^OFFSETS (?!total)(.*)$', out, re.M)}
        m = re.search(r'OFFSETS total=(\d+)', out)
        c['offsets_total'] = int(m.group(1)) if m else None
        c['trap_b_lines'] = len(re.findall(r'^TRAP B ', out, re.M))
        c['trap_b_ok'] = len(re.findall(r'^TRAP B .* ok(?: \||$)', out, re.M))
        c['name_differences'] = re.findall(r'^NAME DIFFERS (.*)$', out, re.M)
        m = re.search(r'COUNTS class_disagreements=(\d+) name_differences=(\d+) not_run=(\d+) assertion_failures=(\d+)', out)
        if m:
            c.update(dict(zip(('class_disagreements', 'name_differences_n', 'not_run', 'assertion_failures'), map(int, m.groups()))))
        c['sink_on_flips'] = re.findall(r'^SINK on flipped bits: (.*)$', out, re.M)
    elif suite in ('golden_rust', 'planted_bugs'):
        m = re.search(r'SUMMARY PASS (\d+) FAIL (\d+) NOT_RUN (\d+)(?: INFO (\d+))?', out)
        if m:
            c = dict(zip(('pass', 'fail', 'not_run'), map(int, m.groups()[:3])))
            if m.group(4) is not None:
                c['info'] = int(m.group(4))
        groups = {}
        for name, status in re.findall(r'^CASE (\S+)\s+(PASS|FAIL|NOT RUN)', out, re.M):
            g = name.split('/')[0] + ('/' + name.split('/')[-1] if suite == 'planted_bugs' else '')
            groups.setdefault(g, {}).setdefault(status, 0)
            groups[g][status] += 1
        c['groups'] = groups
        if suite == 'planted_bugs':
            c['plant_verdicts'] = {n: v for n, v in re.findall(r'^CASE plant/(\S+)/verifier\s+PASS\s+(\S+ index \S+ exit \d+)', out, re.M)}
            c['gaps'] = len(re.findall(r'GAP', out))
    elif suite == 'wal_forge_self_test':
        m = re.search(r'SELF_TEST (\w+) \((\d+) failures\)', out)
        c = {'verdict': m.group(1), 'failures': int(m.group(2))} if m else {}
        c['checks'] = len(re.findall(r'^(?:ok  |FAIL)', out, re.M))
    return c


def leftovers(work):
    out = subprocess.run(['ps', '-ax', '-o', 'pid=,command='], capture_output=True, text=True).stdout
    found = []
    for line in out.splitlines():
        pid, _, cmd = line.strip().partition(' ')
        if pid.isdigit() and int(pid) != os.getpid() and str(work) in cmd and not cmd.startswith(('ps ', 'grep ')):
            found.append((int(pid), cmd[:160]))
    return found


def teardown(work, label, timeout_s=30):
    """Deterministic reap: kill every process whose command names this run's work dir (the suites' sink, refund and
    verifier children, in their own sessions, which a parent group-kill cannot reach), then poll until none remains or
    the bounded timeout. A child caught mid-exit is killed and confirmed gone on the next poll, so the "0 leftovers"
    requirement does not fail on the exit race (the flaky REAP RACE of run-1). The requirement itself is unchanged:
    this returns the number STILL alive after the bounded reap, and the case fails on any."""
    waited, killed = 0.0, []
    while True:
        found = leftovers(work)
        if not found:
            break
        for pid, cmd in found:
            if pid not in [k[0] for k in killed]:
                killed.append((pid, cmd))
            for sig in (signal.SIGKILL,):
                try:
                    os.killpg(os.getpgid(pid), sig)
                except OSError:
                    try:
                        os.kill(pid, sig)
                    except OSError:
                        pass
            try:                 # reap if it happens to be our direct child
                os.waitpid(pid, os.WNOHANG)
            except OSError:
                pass
        if waited >= timeout_s:
            break
        time.sleep(0.5)
        waited += 0.5
    remaining = leftovers(work)
    M.put('teardown/' + label, {'killed': killed, 'reap_wait_s': waited, 'remaining': remaining})
    print('  TEARDOWN %s: killed %d, %d still alive after %.1fs%s' % (
        label, len(killed), len(remaining), waited, (': %s' % remaining[:3]) if remaining else ''), flush=True)
    return len(remaining)


def frozen_verifier(given, work):
    """A copy of a built verifier folder in the attempt folder (a rebuild elsewhere cannot change the program under test)."""
    target = work / 'verifier'
    shutil.copytree(given, target, symlinks=True, ignore=shutil.ignore_patterns('__pycache__'))
    require((target / 'verify-refund-log').is_file(), 'SUITE: no verify-refund-log in %s' % given)
    built = json.loads((target / 'build.json').read_text())
    stale = sorted(k for k, v in built.get('inputs', {}).items() if (ROOT / k).is_file() and fsha(k) != v)
    return target, built, stale


COLLIDE_BLOCKS = ('0k', '1L', '2-')   # 31*a + b is equal for the three blocks: ids made of them share one bucket of Hash
COLLIDE_RECORDS = 16000
COLLIDE_BOUND_S = 600                 # generous bound for the F2 timing guard; the measured time goes to measurements.json


def review_checks(ver, work, env, W, timing=True, node=False):
    """The reproductions of the review findings F1, F4, F5 and the F2 timing guard, on the compiled verifier.
    Returns ({check: result}, [problem])."""
    res, problems = {}, []
    d = work / 'review'
    d.mkdir(parents=True)
    good = W.honest_log('charge-1', 1000, [('returned_item', 'rq-1', 100)])
    (d / 'ok.wal').write_bytes(good)
    # F1: planted json.py and os.py (`os._exit(0)`) on PYTHONPATH, and a planted json.py beside the launcher; the WAL
    # does not exist. Each must print UNVERIFIABLE_UNREADABLE and exit 3.
    plant = d / 'plant'
    plant.mkdir()
    for name in ('json.py', 'os.py'):
        (plant / name).write_text('import os\nos._exit(0)\n')
    beside = d / 'beside'
    shutil.copytree(Path(ver).parent, beside, symlinks=True, ignore=shutil.ignore_patterns('__pycache__'))
    (beside / 'json.py').write_text('import os\nos._exit(0)\n')
    (plant / 'plant.js').write_text('process.exit(0);\n')
    f1 = [('F1_planted_modules_on_pythonpath', ver, {'PYTHONPATH': str(plant)}),
          ('F1_planted_json_beside_launcher', beside / Path(ver).name, {})]
    if node:
        f1 += [('F1_node_options_require', ver, {'NODE_OPTIONS': '--require %s' % (plant / 'plant.js'), 'NODE_PATH': str(plant)})]
    for label, argv0, extra in f1:
        code, out = run_group([argv0, d / 'missing.wal'], env=dict(env, **extra), timeout=600)
        word = (out.split() or [''])[0]
        res[label] = {'exit': code, 'first_line_word': word}
        if code != 3 or word != 'UNVERIFIABLE_UNREADABLE':
            problems.append('F1: %s: exit %s, first word %r (must be UNVERIFIABLE_UNREADABLE, exit 3)' % (label, code, word))
    shutil.rmtree(beside, ignore_errors=True)
    # F2 (keyed hash): the same file gives the same full verdict line in 5 runs (accepted and rejected); the per-run key
    # must not show in any output.
    bad = W.forge_log('charge-1', 1000, [('returned_item', 'rq-1', 100), ('returned_item', 'rq-1', 1)])
    (d / 'rejected.wal').write_bytes(bad)
    for label, f in (('F2_repeat_accepted', 'ok.wal'), ('F2_repeat_rejected', 'rejected.wal')):
        outs = set()
        codes = set()
        for _ in range(5):
            code, out = run_group([ver, d / f, '--json'], env=env, timeout=600)
            outs.add(out)
            codes.add(code)
        res[label] = {'runs': 5, 'distinct_outputs': len(outs), 'exits': sorted(codes), 'verdict': (sorted(outs)[0][:40] if outs else '')}
        if len(outs) != 1 or len(codes) != 1:
            problems.append('F2: %s: %d distinct outputs in 5 runs' % (label, len(outs)))
    # F4: stdout closed, and stdout a pipe whose reader is gone: the line cannot be written, so exit 3.
    # Documented per target (VERDICTS.md, "One known difference"): Python cannot write and exits 3; Node reopens a
    # closed stdout on /dev/null, writes the line there and exits with the verdict's code. Either way never 0 for a
    # rejected file.
    bad = W.forge_log('charge-1', 1000, [('returned_item', 'rq-1', 100), ('returned_item', 'rq-1', 1)])
    (d / 'closed-rejected.wal').write_bytes(bad)
    for label, f, verdict_code in (('F4_stdout_closed', 'ok.wal', 0), ('F4_stdout_closed_rejected_file', 'closed-rejected.wal', 1)):
        code, _ = run_group(['/bin/sh', '-c', '"$0" "$1" >&-; exit $?', ver, d / f], env=env, timeout=600)
        want = verdict_code if node else 3
        res[label] = {'exit': code, 'expected': want, 'documented': 'Node: verdict code (stdout reopened on /dev/null)' if node else 'Python: 3'}
        if code != want:
            problems.append('F4: %s exited %s (documented: %s)' % (label, code, want))
    r, w = os.pipe()
    os.close(r)
    p = subprocess.Popen([str(ver), str(d / 'ok.wal')], stdout=w, stderr=subprocess.DEVNULL, env=env, start_new_session=True)
    os.close(w)
    try:
        p.wait(timeout=600)
    finally:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except OSError:
            pass
        p.wait()
    res['F4_stdout_reader_gone'] = {'exit': p.returncode}
    if p.returncode != 3:
        problems.append('F4: with a stdout pipe whose reader is gone the verifier exited %s (must be 3)' % p.returncode)
    # F5: duplicate JSON key in an --encode history: refused (exit 3), no file written.
    (d / 'dup.json').write_text('{"charge": "ch_1", "charge": "ch_2", "original": 100, "records": []}')
    target = d / 'dupkey-out.wal'
    code, out = run_group([ver, '--encode', d / 'dup.json', '--out', target], env=env, timeout=600)
    word = (out.split() or [''])[0]
    res['F5_duplicate_key'] = {'exit': code, 'file_written': target.exists(), 'first_line_word': word}
    if code != 3 or target.exists() or word != 'UNVERIFIABLE_ENCODE_INPUT':
        problems.append('F5: a history with a duplicate key gave exit %s, %s, file written %s' % (code, word, target.exists()))
    if not timing:
        shutil.rmtree(d, ignore_errors=True)
        return res, problems
    # F2: 16,000 commit records whose ids all fall into one bucket of the current Hash; time bound.
    ids = []
    for k in range(COLLIDE_RECORDS):
        t, x = '', k
        for _ in range(9):
            t, x = t + COLLIDE_BLOCKS[x % 3], x // 3
        ids.append(t)
    (d / 'collide.wal').write_bytes(W.honest_log('c', W.MAX_MONEY, [('returned_item', i, 0) for i in ids]))
    t = time.monotonic()
    code, out = run_group([ver, d / 'collide.wal', '--expect-count', COLLIDE_RECORDS], env=env, timeout=COLLIDE_BOUND_S + 60)
    secs = round(time.monotonic() - t, 1)
    M.put('review/F2_collide_%d_records_s' % COLLIDE_RECORDS, secs)
    res['F2_colliding_ids'] = {'records': COLLIDE_RECORDS, 'exit': code, 'verdict': (out.split() or [''])[0], 'bound_s': COLLIDE_BOUND_S,
                               'within_bound': secs <= COLLIDE_BOUND_S}
    if code != 0 or secs > COLLIDE_BOUND_S:
        problems.append('F2: %d colliding ids: exit %s, %.1f s (bound %d s)' % (COLLIDE_RECORDS, code, secs, COLLIDE_BOUND_S))
    shutil.rmtree(d, ignore_errors=True)
    return res, problems


TAIL_INPUTS = 'the owner-ratified tail semantics: trailing 1..63 bytes = ACCEPT_TORN_TAIL (exit 4); a whole last record with a bad CRC = REJECT_BAD_CRC (exit 1)'


def tail_checks(vers, work, W):
    """The two tail inputs of the owner's decision, on every program in `vers`: {program: {input: (exit, word)}}."""
    d = work / 'tail'
    d.mkdir(parents=True, exist_ok=True)
    base = W.honest_log('charge-1', 1000, [('returned_item', 'rq-1', 100), ('duplicate_charge', 'rq-2', 0)])
    bad_last = bytearray(W.honest_log('charge-1', 1000, [('returned_item', 'rq-1', 100), ('duplicate_charge', 'rq-2', 0),
                                                         ('returned_item', 'rq-3', 1)]))
    bad_last[-1] ^= 0x01
    inputs = {'torn_%d' % k: base + b'\xff' * k for k in range(1, 64)}
    inputs['whole_last_record_bad_crc'] = bytes(bad_last)
    want = {k: (4, 'ACCEPT_TORN_TAIL') for k in inputs}
    want['whole_last_record_bad_crc'] = (1, 'REJECT_BAD_CRC')
    res, problems = {}, []
    for label, ver in vers.items():
        bad = []
        for k, data in inputs.items():
            (d / 'in.wal').write_bytes(data)
            code, out = run_group([ver, d / 'in.wal'], timeout=600)
            got = (code, (out.split() or [''])[0])
            if got != want[k]:
                bad.append('%s: %s (want %s)' % (k, got, want[k]))
        res[label] = {'inputs': len(inputs), 'as_ratified': len(inputs) - len(bad), 'differences': bad}
        if bad:
            problems.append('TAIL %s: %s' % (label, bad[:5]))
    shutil.rmtree(d, ignore_errors=True)
    return res, problems


CROSS_WRAPPER = r'''#!%(python)s -I
# Cross-target judge (written by scripts/exit_refund_log_verifier.py into a build folder; never tracked). It runs BOTH
# compiled programs with the same arguments, compares stdout, exit code (and, without --json, also the --json form),
# and for --encode the bytes written; appends one JSON line per call to the log; answers with the program `answer`.
import json, os, shutil, subprocess, sys
here = os.path.dirname(os.path.realpath(__file__))
cfg = json.load(open(os.path.join(here, 'cross.json')))
args = sys.argv[1:]
def run(prog, a):
    p = subprocess.run([prog] + a, capture_output=True)
    return p.returncode, p.stdout, p.stderr
rec = {'args': [os.path.basename(x) if os.sep in x else x for x in args]}
if '--out' in args:
    i = args.index('--out') + 1
    out = args[i]
    other = out + '.cross-other'
    if os.path.lexists(out):
        shutil.copyfile(out, other)
    a2 = list(args)
    a2[i] = other
    first, second = (args, a2) if cfg['answer'] == 'python' else (a2, args)
    rp, rn = run(cfg['python'], first), run(cfg['node'], second)
    fo = open(out, 'rb').read() if os.path.exists(out) else None
    fx = open(other, 'rb').read() if os.path.exists(other) else None
    if os.path.lexists(other):
        os.unlink(other)
    rec['encode_bytes_equal'] = fo == fx
    rec['equal'] = rp[:2] == rn[:2] and fo == fx
else:
    rp, rn = run(cfg['python'], args), run(cfg['node'], args)
    rec['equal'] = rp[:2] == rn[:2]
    files = [a for a in args if not a.startswith('-') and os.path.isfile(a)]
    big = any(os.path.getsize(a) > 200000 for a in files)
    rec['large_input'] = big
    if '--json' not in args and big:
        rec['json_skipped_large'] = True   # the Node program needs about 15 ms per record: the plain form only
    elif '--json' not in args:
        jp, jn = run(cfg['python'], args + ['--json']), run(cfg['node'], args + ['--json'])
        rec['json_equal'] = jp[:2] == jn[:2]
        rec['equal'] = rec['equal'] and rec['json_equal']
rec['exit'] = [rp[0], rn[0]]
if not rec['equal']:
    rec['python'] = rp[1].decode('utf-8', 'replace')[:300]
    rec['node'] = rn[1].decode('utf-8', 'replace')[:300]
with open(cfg['log'], 'a') as f:
    f.write(json.dumps(rec, sort_keys=True) + '\n')
code, out, err = rp if cfg['answer'] == 'python' else rn
os.write(1, out)
os.write(2, err)
os._exit(code)
'''


def cross_wrapper(folder, python_ver, node_ver, log, answer='node'):
    folder.mkdir(parents=True, exist_ok=True)
    (folder / 'cross.json').write_text(json.dumps({'python': str(python_ver), 'node': str(node_ver), 'log': str(log), 'answer': answer}))
    w = folder / 'verify-refund-log-cross'
    w.write_text(CROSS_WRAPPER % {'python': os.path.realpath(sys.executable)})
    w.chmod(0o755)
    return w


def integer_vectors(W):
    """The owner's integer-boundary group: [(name, wal, ratchet or None, extra args)], built with FORGE's wal_forge.py."""
    P = [0, 1, 2**31 - 1, 2**31, 2**32 - 1, 2**32, 2**53 - 1, 2**53, 2**53 + 1, 2**63 - 2, 2**63 - 1, 2**63, 2**64 - 1]
    vec = []
    for v in P:
        vec.append(('genesis original %d' % v, W.forge_log('c', v, []), None, []))
    top = 2**63 - 1
    for v in P:
        vec.append(('commit amount %d (original 2^63-1)' % v, W.forge_log('c', top, [('returned_item', 'a', v)]), None, []))
    for orig in (2**53 + 1, 2**63 - 1):
        vec.append(('amount == remaining (%d)' % orig, W.forge_log('c', orig, [('returned_item', 'a', orig)]), None, []))
        vec.append(('amount == remaining + 1 (%d)' % orig, W.forge_log('c', orig, [('returned_item', 'a', orig + 1)]), None, []))
        vec.append(('1 then remaining - 1 (%d)' % orig, W.forge_log('c', orig, [('returned_item', 'a', 1), ('returned_item', 'b', orig - 1)]), None, []))
    vec.append(('running sum crosses 2^53', W.forge_log('c', top, [('returned_item', 'a', 2**53 - 1), ('returned_item', 'b', 2), ('returned_item', 'c', 2**53)]), None, []))
    vec.append(('running sum crosses 2^63 (refused)', W.forge_log('c', top, [('returned_item', 'a', 2**62), ('returned_item', 'b', 2**62)]), None, []))
    vec.append(('running sum reaches 2^63-1 exactly', W.forge_log('c', top, [('returned_item', 'a', 2**62), ('returned_item', 'b', 2**62 - 1)]), None, []))
    base = W.forge_log('c', 1000, [('returned_item', 'a', 1)])
    for e in (2**32, 2**53 + 1, 2**64 - 1):
        rs = [bytearray(r) for r in W.records_of(base)]
        rs[1][4:12] = e.to_bytes(8, 'little')
        vec.append(('epoch field %d at index 1' % e, b''.join(W.rechain(rs, epochs=False)), None, []))
    vec.append(('--expect-count 2^53+1', base, None, ['--expect-count', str(2**53 + 1)]))
    vec.append(('--expect-count 1', base, None, ['--expect-count', '1']))
    vec.append(('--expect-count with 30 digits', base, None, ['--expect-count', '1' * 30]))
    for e in (2**53 + 1, 2**64 - 1):
        vec.append(('ratchet entry epoch %d' % e, base, W.ratchet_bytes([0, 1, e]), []))
    vec.append(('ratchet entry epoch 1 (consistent)', base, W.ratchet_bytes([0, 1]), []))
    return vec


def integer_group(pyv, nodev, work, W, R):
    d = work / 'integers'
    d.mkdir(parents=True, exist_ok=True)
    vec = integer_vectors(W)
    diffs, oracle_diffs, json_text = [], [], []
    for k, (name, wal, ratchet, extra) in enumerate(vec):
        (d / 'in.wal').write_bytes(wal)
        argv = [d / 'in.wal'] + extra
        if ratchet is not None:
            (d / 'in.epoch').write_bytes(ratchet)
            argv += ['--ratchet', d / 'in.epoch']
        outs = {}
        for label, ver in (('python', pyv), ('node', nodev)):
            outs[label] = (run_group([ver] + argv, timeout=600), run_group([ver] + argv + ['--json'], timeout=600))
        if outs['python'] != outs['node']:
            diffs.append('%s: python %r / node %r' % (name, outs['python'][0][1][:160], outs['node'][0][1][:160]))
        code = outs['python'][0][0]
        count = int(extra[1]) if extra[:1] == ['--expect-count'] else None
        if count is not None and len(extra[1]) > 20:
            oracle = None   # the CLI's own bound (DecimalOk: at most 20 digits): USAGE, not a property of the log
            if code != 3:
                oracle_diffs.append('%s: exit %s (want 3, UNVERIFIABLE_USAGE)' % (name, code))
        else:
            cls, cause, _ = R.verdict(wal, ratchet, count, None)
            oracle = (cls, cause)
            if R.EXIT[cls] != code:
                oracle_diffs.append('%s: verifier exit %s, oracle %s/%s exit %s' % (name, code, cls, cause, R.EXIT[cls]))
        if name == 'genesis original %d' % (2**63 - 1) or name.startswith('amount == remaining (%d)' % (2**63 - 1)):
            for label in ('python', 'node'):
                raw = outs[label][1][1]
                ok = '"original":%d' % (2**63 - 1) in raw and 'e+' not in raw.lower().split('"spec_sha256"')[0]
                obj = json.loads(raw.splitlines()[0])
                json_text.append({'vector': name, 'program': label, 'exact_digits_in_text': ok,
                                  'json_number_as_python_int': obj.get('original') == 2**63 - 1})
    bad_text = [x for x in json_text if not (x['exact_digits_in_text'] and x['json_number_as_python_int'])]
    shutil.rmtree(d, ignore_errors=True)
    return {'vectors': len(vec), 'calls_per_program': 2 * len(vec), 'differences': diffs, 'oracle_differences': oracle_diffs,
            'json_exact_digits': json_text}, diffs + oracle_diffs + ['JSON digits: %s' % x for x in bad_text]


def case_cross_target(work, verifier_dir):
    """Both compiled programs on every input that FORGE's and RUST's suites make (through the cross wrapper, which
    answers with the Node program, so the suites also judge the Node program), plus the tail inputs and the review
    reproductions on both."""
    work.mkdir(parents=True, exist_ok=True)
    target, _, stale = frozen_verifier(verifier_dir, work)
    pyv, nodev = target / 'verify-refund-log', target / 'verify-refund-log-node'
    if not nodev.is_file():
        raise NotRun('NOT RUN: no Node program verify-refund-log-node in %s (CORE\'s second target)' % verifier_dir)
    tmp = work / 'tmp'
    tmp.mkdir()
    env = dict(os.environ, TMPDIR=str(tmp), PYTHONDONTWRITEBYTECODE='1')
    sys.path.insert(0, str(ROOT / TESTS))
    import wal_forge as W
    (work / 'sink').mkdir()
    try:
        sink = W.build_sink(work / 'sink')
    except Exception as error:  # noqa: BLE001
        raise NotRun('NOT RUN: the sink does not build: %s' % error)
    res, problems = {'suites_on_node': {}, 'compared': {}}, []
    for name, script, extra in (('negative_controls', 'test_negative_controls.py', ['--sink', sink]),
                                ('exhaustive', 'test_exhaustive.py', ['--sink', sink]),
                                ('golden_rust', 'test_golden_rust.py', ['--work', work / 'golden']),
                                ('planted_bugs', 'test_planted_bugs.py', ['--work', work / 'planted'])):
        log = work / ('cross-%s.jsonl' % name)
        wrapper = cross_wrapper(work / ('cross-' + name), pyv, nodev, log)
        t = time.monotonic()
        code, out = run_group([PY, ROOT / TESTS / script, wrapper] + extra, env=env, timeout=4 * 3600)
        M.put('cross_s/' + name, round(time.monotonic() - t, 1))
        (work / (name + '-on-node.log')).write_text(out)
        rows = [json.loads(x) for x in log.read_text().splitlines()] if log.is_file() else []
        diffs = [r for r in rows if not r['equal']]
        nr_lines = re.findall(r'^.*NOT RUN.*$', out, re.M)
        # FORGE's run_verifier has a 600 s timeout; the Node program needs about 15 ms per record, so the 65,535-record
        # case of the negative controls cannot finish inside it. That one line is replaced by the direct full-cap
        # comparison below (both programs, once, no timeout of 600 s); any other NOT RUN line still fails.
        huge = [x for x in nr_lines if name == 'negative_controls' and 'huge log: 65535 commits' in x]
        nr = len(nr_lines) - len(huge)
        if huge:
            res.setdefault('replaced_by_direct_full_cap', []).append(name + ': huge log: 65535 commits')
            code = 0 if code == 1 and nr == 0 and re.search(r'COUNTS agree=\d+ disagree=0 not_run=1 ', out) else code
        res['suites_on_node'][name] = {'exit': code, 'not_run_lines': nr, 'counts': counts_of(name, out)}
        res['compared'][name] = {'calls': len(rows), 'large_inputs': sum(bool(r.get('large_input')) for r in rows), 'json_forms_compared': sum('json_equal' in r for r in rows),
                                 'encode_outputs_compared': sum('encode_bytes_equal' in r for r in rows), 'differences': len(diffs)}
        print('  %-18s on Node: exit %s, NOT RUN lines %d; compared %d calls (%d also in --json form, %d --encode outputs); differences %d' % (
            name, code, nr, len(rows), res['compared'][name]['json_forms_compared'], res['compared'][name]['encode_outputs_compared'], len(diffs)), flush=True)
        for r in diffs[:40]:
            print('    DIFFERENCE %s' % json.dumps(r, sort_keys=True)[:400], flush=True)
        if code != 0 or nr or diffs or not rows:
            problems.append('%s: exit %s on Node, NOT RUN %d, %d calls, %d differences' % (name, code, nr, len(rows), len(diffs)))
    import ref_fold as R
    # the full-cap log (65,535 commits, the size class bound) on both programs once, plain form, compared byte for byte
    d = work / 'fullcap'
    d.mkdir()
    (d / 'ledger.wal').write_bytes(W.honest_log('charge-1', W.MAX_MONEY, [('returned_item', 'r%d' % i, 0) for i in range(65535)]))
    full = {}
    for label, ver in (('python', pyv), ('node', nodev)):
        t = time.monotonic()
        full[label] = run_group([ver, d / 'ledger.wal', '--expect-count', '65535'], timeout=3600)
        M.put('cross_fullcap_s/' + label, round(time.monotonic() - t, 1))
        if full[label][1].startswith('(timeout after'):
            raise NotRun('NOT RUN: the full-cap log on %s did not finish within the 3600 s ceiling' % label)
    same = full['python'] == full['node']
    res['full_cap'] = {'records': 65535, 'verdict_lines_equal': same, 'equal': same, 'exit': [full['python'][0], full['node'][0]],
                       'verdict': (full['python'][1].split() or [''])[0]}
    print('  full-cap log (65,535 commits) once on each program: equal %s; exits %s; verdict %s' % (
        same, res['full_cap']['exit'], res['full_cap']['verdict']), flush=True)
    if not same or full['python'][0] != 0:
        problems.append('FULL CAP: equal %s, exits %s' % (same, res['full_cap']['exit']))
    shutil.rmtree(d, ignore_errors=True)
    ires, iprob = integer_group(pyv, nodev, work, W, R)
    res['integer_boundaries'] = ires
    print('  integer boundaries: %d vectors, each on both programs in plain and --json form; differences %d; oracle differences %d; '
          'exact digits of 2^63-1 in --json: %s' % (ires['vectors'], len(ires['differences']), len(ires['oracle_differences']),
                                                  all(x['exact_digits_in_text'] and x['json_number_as_python_int'] for x in ires['json_exact_digits'])), flush=True)
    for x in iprob:
        print('    DIFFERENCE ' + x, flush=True)
    problems += ['INTEGERS: ' + x for x in iprob]
    tres, tprob = tail_checks({'python': pyv, 'node': nodev}, work, W)
    res['tail'] = tres
    print('  tail inputs (%s): %s' % (TAIL_INPUTS, json.dumps(tres, sort_keys=True)[:600]), flush=True)
    problems += tprob
    for label, ver in (('python', pyv), ('node', nodev)):
        rres, rprob = review_checks(ver, work / ('review-' + label), env, W, timing=False, node=label == 'node')
        res['review_' + label] = rres
        print('  review checks on %s: %s' % (label, 'PASS' if not rprob else rprob), flush=True)
        problems += ['%s: %s' % (label, x) for x in rprob]
    left = teardown(work, 'cross_target')
    shutil.rmtree(tmp, ignore_errors=True)
    if left:
        problems.append('TEARDOWN: %d leftover processes' % left)
    if stale:
        problems.append('stale build %s' % stale)
    require(not problems, 'CROSS_TARGET: ' + '; '.join(problems))
    return res


def case_suite(work, verifier_dir):
    work.mkdir(parents=True, exist_ok=True)
    target, built, stale = frozen_verifier(verifier_dir, work)
    ver = target / 'verify-refund-log'
    print('  verifier: frozen copy of %s (build.json sha256 %s; stale inputs: %s)' % (
        verifier_dir.name, sha((target / 'build.json').read_bytes())[:16], stale or 'none'), flush=True)
    tmp = work / 'tmp'
    tmp.mkdir()
    env = dict(os.environ, TMPDIR=str(tmp), PYTHONDONTWRITEBYTECODE='1')
    sys.path.insert(0, str(ROOT / TESTS))
    import wal_forge as W
    (work / 'sink').mkdir()
    try:
        sink = W.build_sink(work / 'sink')
    except Exception as error:  # noqa: BLE001
        raise NotRun('NOT RUN: the sink does not build for the suites: %s' % error)
    plan = [('wal_forge_self_test', [ROOT / TESTS / 'wal_forge.py', '--self-test', sink]),
            ('negative_controls', [ROOT / TESTS / 'test_negative_controls.py', ver]),
            ('exhaustive', [ROOT / TESTS / 'test_exhaustive.py', ver]),
            ('golden_rust', [ROOT / TESTS / 'test_golden_rust.py', ver, '--work', work / 'golden']),
            ('planted_bugs', [ROOT / TESTS / 'test_planted_bugs.py', ver, '--work', work / 'planted'])]
    res, problems = {}, []
    for name, argv in plan:
        t = time.monotonic()
        code, out = run_group([PY] + argv, env=env, timeout=7200)
        M.put('suite_s/' + name, round(time.monotonic() - t, 1))
        (work / (name + '.log')).write_text(out)
        c = counts_of(name, out)
        nr = len(re.findall(r'NOT RUN', out))
        res[name] = {'exit': code, 'not_run_lines': nr, 'counts': c}
        print('  %-20s exit %s; NOT RUN lines %d; %s' % (name, code, nr, json.dumps(c, sort_keys=True)[:600]), flush=True)
        if code != 0 or nr:
            problems.append('%s exit %s, NOT RUN lines %d' % (name, code, nr))
        if name in ('golden_rust', 'planted_bugs') and (c.get('pass') is None or c.get('pass', 0) + c.get('fail', 0) == 0):
            problems.append('%s: no SUMMARY line with a real case (counts come from the summary line only; review F7)' % name)
    tres, tprob = tail_checks({'python': ver}, work, W)
    res['tail_checks'] = {'exit': 0 if not tprob else 1, 'not_run_lines': 0, 'counts': tres}
    print('  %-20s %s; %s' % ('tail_checks', 'PASS' if not tprob else 'FAIL', json.dumps(tres, sort_keys=True)), flush=True)
    problems += tprob
    rres, rprob = review_checks(ver, work, env, W)
    res['review_checks'] = {'exit': 0 if not rprob else 1, 'not_run_lines': 0, 'counts': rres}
    print('  %-20s %s; %s' % ('review_checks', 'PASS' if not rprob else 'FAIL', json.dumps(rres, sort_keys=True)), flush=True)
    problems += rprob
    left = teardown(work, 'suite')
    shutil.rmtree(tmp, ignore_errors=True)
    if left:
        problems.append('TEARDOWN: %d leftover processes' % left)
    if stale:
        problems.append('the compiled verifier is older than its sources %s' % stale)
    require(not problems, 'SUITE: ' + '; '.join(problems))
    M.put('suite_verifier_build_json_sha256', sha((target / 'build.json').read_bytes()))
    return {'suites': res, 'teardown_leftover_processes': 0}


def case_mutations(work, verifier_dir, proof=True):
    work.mkdir(parents=True, exist_ok=True)
    out_json = work / 'mutants.json'
    argv = [PY, ROOT / TESTS / 'mutants_verifier.py', '--verifier', verifier_dir, '--work', work / 'copies', '--out', out_json,
            '--judges', 'test,proof' if proof else 'test']
    if proof:
        argv += ['--proof-for', ','.join(PROOF_DEMO)]
    else:
        argv += ['--allow-stale-build']
    t = time.monotonic()
    code, out = run_group(argv, timeout=6 * 3600)
    M.put('mutations_s', round(time.monotonic() - t, 1))
    (work / 'mutants.log').write_text(out)
    print('\n'.join('  ' + x for x in out.strip().splitlines()), flush=True)
    left = teardown(work, 'mutations')
    require(out_json.is_file(), 'MUTATIONS: mutants_verifier.py exit %s wrote no result' % code)
    r = json.loads(out_json.read_text())
    if r.get('stale_inputs'):
        M.put('mutations_stale_inputs', r['stale_inputs'])
    rows = [{'name': x['name'], 'applied': x['applied'], 'killed': x['killed'], 'killed_by': x['killed_by'],
             'proof_judge': None if not x.get('proof') or 'verifies' not in x['proof'] else
             ('error in: ' + ','.join(x['proof']['failing'])) if x['proof']['outcome'] == 'error' else x['proof']['outcome']} for x in r['copies']]
    det = {'copies': rows, 'changed_copies': len(rows), 'killed': sum(x['killed'] for x in rows),
           'killed_by_test': sum(x['killed_by'] == 'test' for x in rows), 'killed_by_proof': sum(x['killed_by'] == 'proof' for x in rows),
           'not_killed': [x['name'] for x in rows if not x['killed']], 'proof_demo': PROOF_DEMO if proof else [],
           'control_passed': not r['errors'] and bool(r['control'].get('suites')), 'errors': r['errors'], 'not_run': r['not_run']}
    (work / 'result-detail.json').write_text(json.dumps(r, indent=1, sort_keys=True) + '\n')
    if not proof:
        raise NotRun('NOT RUN: the proof judge was not run (--no-proof-judge); test kills: %d of %d; not killed by a test: %s'
                     % (det['killed_by_test'], len(rows), det['not_killed']))
    require(code == 0 and not det['not_killed'] and det['control_passed'] and not left,
            'MUTATIONS: exit %s; NOT KILLED %s; control passed %s; errors %s; not run %s; leftovers %d'
            % (code, det['not_killed'], det['control_passed'], r['errors'], r['not_run'], left))
    return det


def subject():
    files = package_files() + [SPEC, 'spec/refund/RefundSpec.dfy', 'impl/Refund.dfy', SINK, 'gate/expected-audit.md']
    return {f: fsha(f) for f in sorted(set(files)) if (ROOT / f).is_file()}


def bundle_of(work):
    before = subject()
    cases, status = {}, {}
    built = None
    for name in ('build', 'proofs', 'suite', 'cross_target', 'mutations'):
        try:
            if name == 'build':
                cases[name], built = case_build(work / 'build')
            elif name == 'proofs':
                p = case_proofs(work / 'proofs')
                p['headers'] = {'findings': p['headers']['findings'],
                                'statements': {k: {kk: vv for kk, vv in v.items()} for k, v in p['headers']['statements'].items()}}
                cases[name] = p
            elif name == 'suite':
                require(built is not None, 'SUITE: no build')
                cases[name] = case_suite(work / 'suite', built)
            elif name == 'cross_target':
                require(built is not None, 'CROSS_TARGET: no build')
                cases[name] = case_cross_target(work / 'cross_target', built)
            else:
                require(built is not None, 'MUTATIONS: no build')
                cases[name] = case_mutations(work / 'mutations', built)
            status[name] = 'PASSED'
        except (Failed, NotRun) as e:
            status[name] = ('NOT RUN: ' if isinstance(e, NotRun) else 'FAILED: ') + str(e)[:600]
        print('  %s: %s' % (name, status[name][:200]), flush=True)
    require(subject() == before, 'INPUT_CHANGED: a subject file changed during the checks')
    M.put('machine', {'system': platform.system(), 'release': platform.release(), 'machine': platform.machine(),
                      'python': platform.python_version()})
    return {
        'record': 'forge-task-v1-refund-log-verifier', 'format_version': 1,
        'producer': 'scripts/exit_refund_log_verifier.py (an EXIT script; not the gate)',
        'kind': 'record, NOT gate evidence', 'gate_accepted': False, 'end_to_end': False, 'labels': LABELS,
        'note': 'A record of real tool runs on one machine. Only deterministic content: hashes, counts, verdicts. Times, waits, '
                'machine facts and build output hashes are in measurements.json.',
        'spec_pin': {'file': SPEC, 'sha256': SPEC_SHA256},
        'subject': before, 'status': status, 'cases': cases,
        'passed': all(v == 'PASSED' for v in status.values()),
        'reproduce_cmd': 'python3 scripts/exit_refund_log_verifier.py --case evidence',
    }


def attempt_folder(case):
    base = BUILD / case
    base.mkdir(parents=True, exist_ok=True)
    n = 1 + max([int(p.name.split('-')[1]) for p in base.glob('attempt-*')] or [0])
    return base / ('attempt-%04d' % n)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--case', required=True, choices=('build', 'proofs', 'suite', 'cross_target', 'mutations', 'evidence'))
    ap.add_argument('--verifier', help='suite, mutations: use this built verifier folder (verifier/refund_log/build.py output) '
                                       'instead of a fresh build')
    ap.add_argument('--no-proof-judge', action='store_true', help='mutations: test judge only (the case is then NOT RUN)')
    args = ap.parse_args()
    work = attempt_folder(args.case)
    work.mkdir(parents=True)
    print('REFUND_LOG_VERIFIER %s: %s' % (args.case, work.relative_to(ROOT)), flush=True)
    start = time.monotonic()
    result = None
    code = 0
    try:
        if args.case == 'build':
            result, _ = case_build(work)
        elif args.case == 'proofs':
            result = case_proofs(work)
        elif args.case in ('suite', 'cross_target', 'mutations'):
            if args.verifier:
                vdir = Path(args.verifier).resolve()
            else:
                vdir = work / 'build'
                vdir.mkdir()
                build_once(vdir, work / 'build.log')
            if args.case == 'suite':
                result = case_suite(work, vdir)
            elif args.case == 'cross_target':
                result = case_cross_target(work, vdir)
            else:
                result = case_mutations(work, vdir, proof=not args.no_proof_judge)
        else:
            bundles = []
            for k in (1, 2):
                print(' run %d' % k, flush=True)
                M.data = {}
                t = time.monotonic()
                b = bundle_of(work / ('run-%d' % k))
                M.put('wall_s', round(time.monotonic() - t, 1))
                data = canonical(b)
                bundles.append((data, b['passed']))
                (work / ('run-%d' % k) / 'evidence.json').write_bytes(data)
                (work / ('run-%d' % k) / 'measurements.json').write_text(json.dumps(M.data, indent=1, sort_keys=True, default=str) + '\n')
                print('  run %d bundle sha256 %s (all cases passed: %s)' % (k, sha(data), b['passed']), flush=True)
            same = bundles[0][0] == bundles[1][0]
            print('  two bundles byte-identical: %s' % same, flush=True)
            (work / 'evidence.json').write_bytes(bundles[0][0])
            print('  bundle: %s/evidence.json sha256 %s' % (work.relative_to(ROOT), sha(bundles[0][0])))
            require(same, 'EVIDENCE: the two bundles differ')
            require(bundles[0][1] and bundles[1][1], 'EVIDENCE: a case failed or did not run (see status in the bundle)')
    except NotRun as e:
        print('REFUND_LOG_VERIFIER %s: %s; end_to_end=false' % (args.case, e))
        code = 2
    except Failed as e:
        print('REFUND_LOG_VERIFIER %s: FAILED; end_to_end=false; wall %.0f s\n%s' % (args.case, time.monotonic() - start, e))
        code = 1
    finally:
        if args.case != 'evidence':
            (work / 'measurements.json').write_text(json.dumps(M.data, indent=1, sort_keys=True, default=str) + '\n')
    if result is not None:
        (work / 'result.json').write_bytes(canonical(result))
    if code == 0:
        print('REFUND_LOG_VERIFIER %s: PASSED; end_to_end=false; wall %.0f s' % (args.case, time.monotonic() - start))
    return code


if __name__ == '__main__':
    sys.exit(main())
