#!/usr/bin/env python3
"""Task V1: the compiled refund-log verifier on REAL bytes of the real silicon sink (rule 2 of the team contract).

usage: test_golden_rust.py <verifier> [--work DIR]

For every scenario of golden_rust.py (written by the real, unchanged sink, built fresh in a work folder under build/),
and for every file variant of it (the final files; for a crash also the files as the SIGKILL left them, before the
sink's cut, and the files after the sink reopened the store), the compiled verifier runs on the WAL and the ratchet and
its verdict and reported state are compared with the GROUND TRUTH (the committed requests that the sink answered,
in order): verdict, exit code, records, charge, original, remaining, epoch, tail, torn bytes.
The history itself (ids, amounts, reasons, order) is reconciled in two ways: (1) the WAL bytes equal the transcribed
encoding of the ground-truth history (a self-check of golden_rust.py, before any verifier call), and (2) the verifier
accepts with `--expect-count <n> --expect-tip <tip of the ground-truth history>` and refuses with `--expect-count n+1`.
Group rust_bytes_equal_dafny_bytes: the PROVED Dafny encoder (CORE's `--encode` entry point) on the ground-truth
history must give the WAL file byte for byte.
Group tracked_golden: the five fixed vectors in tests/refund_log_verifier/golden/ (see its README.md): (a) fresh_bytes:
each tracked WAL and ratchet equals byte for byte the files of a fresh real-sink run of the same scenario or plant;
(b) verifier: the compiled verifier gives the expected verdict, index and torn bytes on the tracked files.
Every case kind here can fail: golden/build_and_scenarios FAILs when a self-check of golden_rust.py raises (WAL bytes
not the ground truth, a refusal that changed a file, state or replay that differs, a kill point not reached).

One line per case. A case that cannot run is NOT RUN and fails the suite.
Exit 0: every case passed. 1: a case failed. 2: the toolchain or the binary is not the pinned one. 3: no case failed,
but at least one is NOT RUN. FINITE TEST; end_to_end=false.
"""

import argparse
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import golden_rust as G  # noqa: E402

RESULTS = {'PASS': 0, 'FAIL': 0, 'NOT RUN': 0}


def case(name, status, detail=''):
    RESULTS[status] += 1
    print('CASE %-58s %s%s' % (name, status, ('  ' + detail) if detail else ''), flush=True)


FIELDS = ('records', 'charge', 'original', 'remaining', 'epoch', 'tail', 'torn_bytes')


def check_variant(verifier, name, folder, exp, names):
    wal, ratchet = str(folder / 'ledger.wal'), str(folder / 'ledger.epoch')
    code, obj, text = G.run_verifier(verifier, wal, ratchet)
    if obj is None:
        return case(name, 'FAIL', 'exit %d, no JSON verdict: %r' % (code, text[:120] + ' ... ' + text[-260:]))
    wrong = ['%s=%r (truth %r)' % (k, obj.get(k), exp[k]) for k in FIELDS if obj.get(k) != exp[k]]
    if obj.get('verdict') != exp['verdict'] or code != G.exit_of(exp['verdict']):
        wrong.insert(0, 'verdict %s exit %d (truth %s exit %d)' % (obj.get('verdict'), code, exp['verdict'], G.exit_of(exp['verdict'])))
    if names is not None and exp['verdict'] not in names:
        wrong.append('verdict %s is not listed in VERDICTS.md' % exp['verdict'])
    if wrong:
        return case(name, 'FAIL', '; '.join(wrong) + ' | ' + text.splitlines()[0][:200])
    case(name, 'PASS', '%s records=%d remaining=%d epoch=%d torn=%d' % (exp['verdict'], exp['records'], exp['remaining'], exp['epoch'], exp['torn_bytes']))


def check_anchors(verifier, name, folder, exp):
    wal, ratchet = str(folder / 'ledger.wal'), str(folder / 'ledger.epoch')
    n, tip = exp['records'], exp['tail']
    good = G.run_verifier(verifier, wal, ratchet, ['--expect-count', n, '--expect-tip', tip])
    high = G.run_verifier(verifier, wal, ratchet, ['--expect-count', n + 1])
    other = G.run_verifier(verifier, wal, ratchet, ['--expect-tip', '%032x' % (int(tip, 16) ^ 1)])
    if any((r[1] or {}).get('verdict') == 'UNVERIFIABLE_USAGE' for r in (good, high, other)):
        return case(name, 'NOT RUN', 'the CLI refused --expect-count/--expect-tip as usage: %r' % good[2][:150])
    ok = good[0] == G.exit_of(exp['verdict']) and (good[1] or {}).get('verdict') == exp['verdict']
    refused = high[0] == 1 and (high[1] or {}).get('verdict') == 'REJECT_COUNT_MISMATCH'
    refused_tip = other[0] == 1 and (other[1] or {}).get('verdict') == 'REJECT_TIP_MISMATCH'
    if ok and refused and refused_tip:
        return case(name, 'PASS', 'count %d and tip of the ground-truth history accepted; n+1 -> REJECT_COUNT_MISMATCH; tip^1 -> REJECT_TIP_MISMATCH' % n)
    case(name, 'FAIL', 'expect n/tip: exit %d %r; n+1: exit %d %r; tip^1: exit %d %r' % (good[0], good[2][:100], high[0], high[2][:100], other[0], other[2][:100]))


def check_encoder(verifier, name, truth, folder):
    """CORE's proved encoder on the ground-truth history; must equal the WAL bytes the Rust sink wrote."""
    history = folder.parent.parent / ('history-%s.json' % folder.name)
    history.write_text(json.dumps({'charge': truth['charge'], 'original': truth['original'],
                                   'records': [{'id': c['id'], 'reason': c['reason'], 'amount': c['amount']} for c in truth['commits_of_variant']]}))
    target = folder.parent.parent / ('encoded-%s.wal' % folder.name)
    code, said, err = G.run_group([verifier, '--encode', history, '--out', target], env=dict(os.environ), timeout=900)
    wal = (folder / 'ledger.wal').read_bytes()
    if code != 0 or not target.exists():
        return case(name, 'FAIL', 'encoder exit %d: %r' % (code, (said + err)[:200]))
    out = target.read_bytes()
    if out == wal:
        return case(name, 'PASS', '%d bytes equal' % len(wal))
    first = next((i for i in range(min(len(out), len(wal))) if out[i] != wal[i]), min(len(out), len(wal)))
    if first >= min(len(out), len(wal)):
        return case(name, 'FAIL', 'lengths differ: Dafny %d, Rust %d' % (len(out), len(wal)))
    record, field = G.field_at(first)
    case(name, 'FAIL', 'first difference at offset %d (record %d, field %s): Dafny 0x%02x, Rust 0x%02x' % (first, record, field, out[first], wal[first]))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('verifier')
    parser.add_argument('--work')
    args = parser.parse_args()
    verifier = str(Path(args.verifier).resolve())
    present = Path(verifier).is_file() and os.access(verifier, os.X_OK)
    try:
        work = G.new_work(args.work)
        tools = G.Tools(work)
        truths = G.scenarios(tools, work)
    except G.ToolchainError as error:
        print(str(error))
        return 2
    except G.Failed as error:
        case('golden/build_and_scenarios', 'FAIL', str(error))
        return 1
    built = None
    if present:
        verifier, built = G.freeze_verifier(verifier, work)
    print('GOLDEN work %s; %s; sink.rs %s; verifier %s' % (work, tools.rustc_version, tools.source_sha256, (verifier + ' (frozen copy; build.json %s)' % built) if present else 'ABSENT'))
    case('golden/build_and_scenarios', 'PASS', '%d scenarios, real sink; WAL bytes == ground-truth history in each' % len(truths))
    names = G.verdict_names()
    encoder_ok, encoder_why = G.encoder_status()
    for truth in truths:
        base = Path(truth['folder'])
        for label, variant in truth['variants'].items():
            name = 'golden/%s/%s' % (truth['scenario'], label)
            if not present:
                case(name, 'NOT RUN', 'the compiled verifier %s does not exist yet' % args.verifier)
            else:
                check_variant(verifier, name, base / variant['dir'], variant['expect'], names)
        final = base / truth['variants']['final']['dir']
        if not present:
            case('golden/%s/anchors' % truth['scenario'], 'NOT RUN', 'the compiled verifier does not exist yet')
        else:
            check_anchors(verifier, 'golden/%s/anchors' % truth['scenario'], final, truth['variants']['final']['expect'])
    for truth in truths:
        base = Path(truth['folder'])
        for label, variant in truth['variants'].items():
            if variant['expect']['torn_bytes']:
                continue
            name = 'rust_bytes_equal_dafny_bytes/%s/%s' % (truth['scenario'], label)
            if not present or not encoder_ok:
                case(name, 'NOT RUN', 'the compiled verifier does not exist yet' if not present else encoder_why)
                continue
            n = variant['expect']['records']
            check_encoder(verifier, name, dict(truth, commits_of_variant=truth['commits'][:n] if label != 'final' else truth['commits']), base / variant['dir'])
    # Group tracked_golden: (a) tracked bytes == a fresh real-sink run; (b) the verifier on the tracked files.
    try:
        G.plants(tools, work, G.GOLDEN_PLANTS)
        fresh_ok = True
    except G.Failed as error:
        fresh_ok, fresh_error = False, str(error)
    for stem, kind, source, variant, verdict, index, torn in G.GOLDEN:
        name = 'tracked_golden/%s' % stem
        wal, ratchet = G.GOLDEN_DIR / (stem + '.wal'), G.GOLDEN_DIR / (stem + '.epoch')
        if not (wal.exists() and ratchet.exists()):
            case(name + '/fresh_bytes', 'FAIL', 'tracked file missing')
            continue
        if not fresh_ok:
            case(name + '/fresh_bytes', 'FAIL', 'the planted copies could not be driven: ' + fresh_error)
        else:
            folder = G.golden_source(work, kind, source, variant)
            diffs = [part for part, tracked in (('ledger.wal', wal), ('ledger.epoch', ratchet)) if (folder / part).read_bytes() != tracked.read_bytes()]
            case(name + '/fresh_bytes', 'FAIL' if diffs else 'PASS', ('differs from the fresh run: %s' % diffs) if diffs else
                 'WAL %d B and ratchet %d B equal to a fresh real-sink run' % (wal.stat().st_size, ratchet.stat().st_size))
        if not present:
            case(name + '/verifier', 'NOT RUN', 'the compiled verifier does not exist yet')
            continue
        code, obj, text = G.run_verifier(verifier, str(wal), str(ratchet))
        obj = obj or {}
        ok = (obj.get('verdict') == verdict and code == G.exit_of(verdict) and (index is None or obj.get('index') == index)
              and (torn is None or obj.get('torn_bytes') == torn) and (names is None or verdict in names))
        case(name + '/verifier', 'PASS' if ok else 'FAIL', '%s exit %d index %s torn %s (expected %s index %s torn %s)' % (
            obj.get('verdict'), code, obj.get('index'), obj.get('torn_bytes'), verdict, index, torn))
    print('SUMMARY PASS %d FAIL %d NOT_RUN %d; FINITE TEST; end_to_end=false' % (RESULTS['PASS'], RESULTS['FAIL'], RESULTS['NOT RUN']))
    return 1 if RESULTS['FAIL'] else (3 if RESULTS['NOT RUN'] else 0)


if __name__ == '__main__':
    sys.exit(main())
