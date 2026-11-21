#!/usr/bin/env python3
"""Task V1: planted engine bugs (rule 9 of the team contract).

usage: test_planted_bugs.py <verifier> [--work DIR]

Each plant of golden_rust.PLANTS is a textual change of a COPY of src/silicon_sink/sink.rs (every anchor occurs exactly
once), compiled for real with the pinned rustc in a work folder and driven for real with the real refund binary. Per
plant, one line per case:
  control           the UNCHANGED sink on a copy of the same store, with the same request line, gives the exit code of
                    the table PLANTS (a refusal; or 0 for a plant that only damages the record); FAIL otherwise
  buggy_wrote       the planted sink answered COMMITTED, appended the record of the critical request, every record has
                    the magic and a valid CRC-32, and this worker's own reader (golden_rust.first_violation) finds the
                    expected first forbidden transition at the expected index (None for a spec-valid plant); FAIL otherwise
  planted_sink_refused_itself  (instead of buggy_wrote, for a sub-scenario where the plant cannot write): the planted
                    sink gives the expected refusal code and appends no record
  INFO lines        reopen_unchanged and reopen_unchanged_ratchet_behind: what the unchanged sink does when it opens
                    the planted store (accept, cut or refuse). Observations, not tests: not counted as PASS. Exit 0 on a
                    store that the verifier must reject is printed as GAP
  verifier          the compiled verifier on the planted store gives the exact named verdict and record index
  control_verifier  the compiled verifier ACCEPTs the store that the unchanged sink left in the control
Until verifier/refund_log/VERDICTS.md exists, expected names come from the table PLANTS (verdict names CORE reported
to the coordinator) and the name comparison is NOT RUN.
Exit 0: every case passed. 1: a case failed. 2: the toolchain or the binary is not the pinned one. 3: no case failed,
but at least one is NOT RUN. FINITE TEST; end_to_end=false.
"""

import argparse
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import golden_rust as G  # noqa: E402

RESULTS = {'PASS': 0, 'FAIL': 0, 'NOT RUN': 0, 'INFO': 0}


def info(name, detail):
    """An observation, not a test: it cannot fail and is not counted as PASS."""
    RESULTS['INFO'] += 1
    print('INFO %-50s %s' % (name, detail), flush=True)


def case(name, status, detail=''):
    RESULTS[status] += 1
    print('CASE %-50s %s%s' % (name, status, ('  ' + detail) if detail else ''), flush=True)


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
        manifests = G.plants(tools, work)
    except G.ToolchainError as error:
        print(str(error))
        return 2
    except G.Failed as error:
        case('plants/build_and_drive', 'FAIL', str(error))
        return 1
    built = None
    if present:
        verifier, built = G.freeze_verifier(verifier, work)
    print('PLANTS work %s; %s; sink.rs %s; verifier %s' % (work, tools.rustc_version, tools.source_sha256, (verifier + ' (frozen copy; build.json %s)' % built) if present else 'ABSENT'))
    names = G.verdict_names()
    for m in manifests:
        p = 'plant/' + m['plant']
        honest = m['honest_control']
        control_ok = m['control_exit'] == m['control_expect'] and (honest is None or honest['exit'] == honest['expect_exit'])
        case(p + '/control', 'PASS' if control_ok else 'FAIL', 'unchanged sink, same line: exit %d %s (expected %d)%s' % (
            m['control_exit'], m['control_name'], m['control_expect'],
            '; honest claim: exit %d (expected %d)' % (honest['exit'], honest['expect_exit']) if honest else ''))
        if m['buggy_expect'] == 0:
            # The forbidden record must be in the WAL bytes, found by this worker's own reader (golden_rust.first_violation).
            wrote = (m['buggy_exit'] == 0 and m['critical_record_id'] == m['critical_id'] and m['crc_all_valid']
                     and m['violation'] == m['expect_violation'] and m['after_codes'] == m['after_expect'])
            case(p + '/buggy_wrote', 'PASS' if wrote else 'FAIL', 'exit %d; record %r appended; own reader: first violation %s (expected %s); '
                 'CRC all valid %s; after-steps %s; buggy state: %s' % (m['buggy_exit'], m['critical_record_id'], m['violation'], m['expect_violation'],
                                                                     m['crc_all_valid'], m['after_codes'], m['buggy_state'][1][:60]))
        else:
            refused = m['buggy_exit'] == m['buggy_expect'] and m['critical_record_id'] is None and m['violation'] is None
            case(p + '/planted_sink_refused_itself', 'PASS' if refused else 'FAIL', 'exit %d (expected %d %s); no record appended: %s' % (
                m['buggy_exit'], m['buggy_expect'], G.CODES[m['buggy_expect']], m['critical_record_id'] is None))
        r = m['unchanged_reopen']
        gap = r['exit'] == 0 and m['expect_verdict'] != 'ACCEPT'
        info(p + '/reopen_unchanged', '%s%s exit %d (%s); WAL %s' % ('GAP: ' if gap else '', r['name'], r['exit'], r['answer'][:60],
                                                                 'changed' if r['wal_changed'] else 'unchanged'))
        b = m['unchanged_reopen_ratchet_behind']
        cut_forbidden = b['exit'] == 0 and b['records_cut'] > 0 and m['expect_verdict'] != 'ACCEPT'
        info(p + '/reopen_unchanged_ratchet_behind', '%s%s exit %d (%s); WAL %d -> %d bytes' % (
            'GAP (silent cut of a COMMITTED record): ' if cut_forbidden else ('GAP: ' if b['exit'] == 0 and m['expect_verdict'] != 'ACCEPT' else ''),
            b['name'], b['exit'], b['answer'][:50], b['wal_bytes_before'], b['wal_bytes_after']))
        store, control = Path(m['store']), Path(m['store']).parent / 'control'
        if not present:
            case(p + '/verifier', 'NOT RUN', 'the compiled verifier %s does not exist yet (expect %s index %s)' % (args.verifier, m['expect_verdict'], m['expect_index']))
            case(p + '/control_verifier', 'NOT RUN', 'the compiled verifier does not exist yet')
            continue
        code, obj, text = G.run_verifier(verifier, str(store / 'ledger.wal'), str(store / 'ledger.epoch'))
        got, index = (obj or {}).get('verdict'), (obj or {}).get('index')
        exit_ok = code == G.exit_of(m['expect_verdict']) and code in (0, 1)
        index_ok = m['expect_index'] is None or index == m['expect_index']
        if obj is None or not exit_ok or not index_ok:
            case(p + '/verifier', 'FAIL', 'exit %d %r (expect %s index %s)' % (code, text.splitlines()[0][:160] if text else '', m['expect_verdict'], m['expect_index']))
        elif names is None:
            case(p + '/verifier', 'NOT RUN', 'verdict name comparison: VERDICTS.md absent; verifier said %s index %s exit %d (table: %s)'
                 % (got, index, code, m['expect_verdict']))
        elif got != m['expect_verdict'] or got not in names:
            case(p + '/verifier', 'FAIL', 'verdict %s (expect %s; listed in VERDICTS.md: %s)' % (got, m['expect_verdict'], got in names))
        else:
            case(p + '/verifier', 'PASS', '%s index %s exit %d' % (got, index, code))
        code, obj, text = G.run_verifier(verifier, str(control / 'ledger.wal'), str(control / 'ledger.epoch'))
        if code == 0 and (obj or {}).get('verdict') == 'ACCEPT':
            case(p + '/control_verifier', 'PASS', 'ACCEPT records=%s remaining=%s' % (obj.get('records'), obj.get('remaining')))
        else:
            case(p + '/control_verifier', 'FAIL', 'exit %d %r' % (code, text[:160]))
    print('SUMMARY PASS %d FAIL %d NOT_RUN %d INFO %d; FINITE TEST; end_to_end=false' % (RESULTS['PASS'], RESULTS['FAIL'], RESULTS['NOT RUN'], RESULTS['INFO']))
    return 1 if RESULTS['FAIL'] else (3 if RESULTS['NOT RUN'] else 0)


if __name__ == '__main__':
    sys.exit(main())
