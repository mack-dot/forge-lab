#!/usr/bin/env python3
"""Build the refund-log verifier: `dafny build --target py` of RefundLogVerifier.dfy (with the gate's verification
options, so the build also verifies) and the shim, into build/refund_log_verifier/ (ignored by git).

usage: python3 verifier/refund_log/build.py [--out DIR] [--no-verify] [--wait-slot]

  --out DIR     the output folder (default: build/refund_log_verifier under this repository); it is replaced
  --no-verify   compile only (the `proofs` case of scripts/exit_refund_log_verifier.py verifies separately)
  --wait-slot   before the Dafny run, wait until no process of dafny/dafny, Holmake, z3-4.12.1 or
                run_regression_copy runs for 3 checks one minute apart (one proof job at a time on a machine)

Result: DIR/verify-refund-log-node (the JavaScript target: shim launched by `#!/usr/bin/env -S -i <absolute node>`,
DIR/node-model/model.cjs, DIR/node-model/node_modules/bignumber.js copied from the toolchain checkout, 9.3.1),
DIR/verify-refund-log (the shim, executable; its first line names the absolute interpreter that runs this
build, with -I), DIR/model-py/ (Dafny's Python output and its runtime),
DIR/build.json (the command, its exit code, the SHA-256 of every input and output file; no time). DIR is replaced only
after a complete build; a failed build leaves a folder `.<name>.new-<pid>` beside it and DIR unchanged.
Tools (no machine path is written here): FORGE_TOOLCHAIN_ROOT = the checkout that holds .toolchain/ (else this
repository; it is the working folder of the Dafny run, because the gate options name the solver by a relative
path; its node_modules/bignumber.js is copied); FORGE_NODE = the pinned node v24.3.0 (else `node` on PATH, which must
report v24.3.0); FORGE_DAFNY = the dafny binary (else <toolchain root>/.toolchain/dafny-4.11.0/dafny/dafny).
Exit: 0 built; 1 Dafny failed (verification or compilation); 2 a tool is missing or the usage is wrong.
The child process runs in its own process group and is killed (SIGKILL to the group) and reaped on every exit path.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SOURCE = HERE / 'RefundLogVerifier.dfy'
SHIM = HERE / 'verify_refund_log.py'
NODE_SHIM = HERE / 'verify_refund_log_node.cjs'
NODE_VERSION = 'v24.3.0'
BIGNUMBER_VERSION = '9.3.1'
JS_FOOTER = b'\nmodule.exports = { V: RefundLogVerifier.__default, rt: _dafny, BigNumber };\n'
INPUTS = ['verifier/refund_log/RefundLogVerifier.dfy', 'verifier/refund_log/RatifiedSpecLemmas.dfy', 'verifier/refund_log/verify_refund_log.py', 'verifier/refund_log/verify_refund_log_node.cjs',
          'spec/refund/RefundLogSpec.dfy', 'spec/refund/RefundSpec.dfy', 'impl/Refund.dfy']
OPTIONS = ['--solver-path', '.toolchain/dafny-4.11.0/dafny/z3/bin/z3-4.12.1', '--resource-limit', '1000000',
           '--verification-time-limit', '0', '--cores', '1', '--verify-included-files', '--track-print-effects']
SLOT = re.compile(r'dafny/dafny|Holmake|z3-4\.12\.1|run_regression_copy')
QUIET = ('sh', 'bash', 'zsh', 'pgrep', 'grep', 'ps', 'tail', 'sleep')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def slot_busy():
    out = subprocess.run(['ps', '-ax', '-o', 'pid=,command='], capture_output=True, text=True).stdout
    for line in out.splitlines():
        pid, _, cmd = line.strip().partition(' ')
        first = os.path.basename(cmd.split(' ', 1)[0]).lstrip('-')
        if pid.isdigit() and int(pid) != os.getpid() and first not in QUIET and SLOT.search(cmd):
            return True
    return False


def wait_slot():
    free = 0
    while free < 3:
        free = 0 if slot_busy() else free + 1
        if free < 3:
            time.sleep(60)


def run_group(argv, cwd):
    p = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, start_new_session=True)
    try:
        out, _ = p.communicate()
    finally:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except OSError:
            pass
        p.wait()
    return p.returncode, out


def main(argv):
    args = list(argv)
    no_verify, wait = '--no-verify' in args, '--wait-slot' in args
    args = [a for a in args if a not in ('--no-verify', '--wait-slot')]
    out = ROOT / 'build/refund_log_verifier'
    if len(args) == 2 and args[0] == '--out':
        out = Path(args[1]).resolve()
    elif args:
        print(__doc__, file=sys.stderr)
        return 2
    toolroot = Path(os.environ.get('FORGE_TOOLCHAIN_ROOT') or ROOT)
    dafny = os.environ.get('FORGE_DAFNY') or str(toolroot / '.toolchain/dafny-4.11.0/dafny/dafny')
    if not Path(dafny).is_file():
        print('NOT RUN: the pinned Dafny is missing at %s: set FORGE_TOOLCHAIN_ROOT or FORGE_DAFNY' % dafny, file=sys.stderr)
        return 2
    before = {name: sha(ROOT / name) for name in INPUTS}
    final = out   # built in a fresh sibling folder and moved into place only on success: a failed or killed build
    out = final.parent / ('.%s.new-%d' % (final.name, os.getpid()))   # never leaves `final` half-built
    out.mkdir(parents=True)
    command = [dafny, 'build', '--target', 'py', str(SOURCE), '--output', str(out / 'model')] + (['--no-verify'] if no_verify else OPTIONS)
    if wait:
        wait_slot()
    code, text = run_group(command, toolroot)
    (out / 'dafny-build.log').write_text(text)
    if code != 0 or not (out / 'model-py' / 'RefundLogVerifier.py').is_file():
        print('BUILD FAILED: dafny exit %d\n%s' % (code, text[-3000:]))
        return 1
    # The launcher: the shim with its first line replaced by the ABSOLUTE interpreter that runs this build, in
    # isolated mode. (The tracked first line, `#!/usr/bin/env -S python3 -I`, is the documented PATH fallback.)
    interpreter = os.path.realpath(sys.executable)
    lines = SHIM.read_text().split('\n')
    if not lines[0].startswith('#!') or ' ' in interpreter or not os.path.isabs(interpreter):
        print('BUILD FAILED: cannot write the launcher line for interpreter %r' % interpreter)
        return 1
    (out / 'verify-refund-log').write_text('\n'.join(['#!%s -I' % interpreter] + lines[1:]))
    (out / 'verify-refund-log').chmod(0o755)
    # The JavaScript target: the same source, compiled by Dafny's JS back end (not verified again: the run above
    # verified these bytes, unless --no-verify). Precedent of scripts/exit_slice1.py and minter-build.sh: an export
    # line is appended, and bignumber.js is a copy of the pinned package of the toolchain checkout's node_modules.
    node = os.environ.get('FORGE_NODE') or shutil.which('node')
    seen = subprocess.run([node, '--version'], capture_output=True, text=True).stdout.strip() if node else ''
    if seen != NODE_VERSION:
        print('NOT RUN: node %r reports %r, pinned %s: set FORGE_NODE to the pinned node' % (node, seen, NODE_VERSION), file=sys.stderr)
        return 2
    node = os.path.realpath(node)
    bn = toolroot / 'node_modules/bignumber.js'
    if json.loads((bn / 'package.json').read_text()).get('version') != BIGNUMBER_VERSION:
        print('NOT RUN: %s is not bignumber.js %s' % (bn, BIGNUMBER_VERSION), file=sys.stderr)
        return 2
    js = out / 'node-model'
    code, text = run_group([dafny, 'build', '--target', 'js', str(SOURCE), '--output', str(js / 'model'), '--no-verify'], toolroot)
    (out / 'dafny-build-js.log').write_text(text)
    if code != 0 or not (js / 'model.js').is_file():
        print('BUILD FAILED: dafny --target js exit %d\n%s' % (code, text[-3000:]))
        return 1
    (js / 'model.cjs').write_bytes((js / 'model.js').read_bytes() + JS_FOOTER)
    (js / 'model.js').unlink()
    (js / 'node_modules/bignumber.js').mkdir(parents=True)
    for name in ('package.json', 'bignumber.js'):
        shutil.copyfile(bn / name, js / 'node_modules/bignumber.js' / name)
    lines = NODE_SHIM.read_text().split('\n')
    if not lines[0].startswith('#!') or ' ' in node:
        print('BUILD FAILED: cannot write the launcher line for node %r' % node)
        return 1
    (out / 'verify-refund-log-node').write_text('\n'.join(['#!/usr/bin/env -S -i %s' % node] + lines[1:]))
    (out / 'verify-refund-log-node').chmod(0o755)
    after = {name: sha(ROOT / name) for name in INPUTS}
    if after != before:
        print('BUILD FAILED: an input changed during the build')
        return 1
    produced = sorted(p for p in (out / 'model-py').rglob('*.py')) + [js / 'model.cjs', js / 'node_modules/bignumber.js/bignumber.js',
                                                                      js / 'node_modules/bignumber.js/package.json', out / 'verify-refund-log-node']
    record = {'command': ['dafny', 'build', '--target', 'py', 'verifier/refund_log/RefundLogVerifier.dfy', '--output', '<out>/model']
              + (['--no-verify'] if no_verify else OPTIONS), 'dafny_exit': code, 'verified': not no_verify,
              'summary': re.findall(r'Dafny program verifier .*', text), 'inputs': before,
              'launcher_interpreter': interpreter, 'launcher_first_line': '#!%s -I' % interpreter,
              'node_launcher_first_line': '#!/usr/bin/env -S -i %s' % node, 'node_version': NODE_VERSION,
              'bignumber_js': {'version': BIGNUMBER_VERSION, 'from': 'node_modules/bignumber.js of the toolchain checkout'},
              'outputs': {str(p.relative_to(out)): sha(p) for p in produced + [out / 'verify-refund-log']}}
    (out / 'build.json').write_text(json.dumps(record, indent=1, sort_keys=True) + '\n')
    old = final.parent / ('.%s.old-%d' % (final.name, os.getpid()))
    if final.exists():
        final.rename(old)
    out.rename(final)
    shutil.rmtree(old, ignore_errors=True)
    print('BUILT %s and %s (dafny exit 0; %s)' % (final / 'verify-refund-log', final / 'verify-refund-log-node',
                                                  'verified' if not no_verify else 'not verified here'))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
