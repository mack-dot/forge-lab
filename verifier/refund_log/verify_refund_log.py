#!/usr/bin/env -S python3 -I
"""usage: verify-refund-log <ledger.wal> [--witness F] [--ratchet F] [--expect-count N] [--expect-tip HEX] [--json]
       verify-refund-log --encode <history.json> --out <new file> [--json]

UNVERIFIED shim, in the trusted base. It splits the arguments, reads at most bound + 1 bytes of each named file (or
parses the history JSON of ENCODE.md into plain values), draws the random hash key, calls the Dafny-compiled
RefundLogVerifier.Run (or EncodeEntry), writes the one output line and exits with the code that Run returns. The
exit code starts at 3 and becomes 0 or 4 only by Run's (EncodeEntry's 0) return value AND only after the whole line
was written to stdout; every other path ends with os._exit(3). Python runs isolated (-I: no PYTHON* variables, no
user site, no script folder on the path); build.py replaces the first line by the absolute interpreter of the build.
The compiled code is the folder `model-py` beside this file, put FIRST on the path from the resolved file location.
"""
import os
import sys


def emit(text):
    data = (text + '\n').encode('utf-8')
    while data:
        n = os.write(1, data)
        if n <= 0:
            raise OSError('short write')
        data = data[n:]


def main(argv):
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), 'model-py'))
    import json
    import _dafny
    from RefundLogVerifier import default__ as V
    text = lambda s: _dafny.Seq(map(_dafny.CodePoint, s))   # noqa: E731
    unverifiable = lambda why: (3, V.UnverifiableText(text(why), as_json).VerbatimString(False))   # noqa: E731
    key = int.from_bytes(os.urandom(8), 'little') % 2305843009213693951
    as_json = '--json' in argv
    args = [a for a in argv if a != '--json']
    names = ('--witness', '--ratchet', '--expect-count', '--expect-tip', '--encode', '--out')
    opts, rest = {}, []
    while args:
        a = args.pop(0)
        if a in names and args and a not in opts:
            opts[a] = args.pop(0)
        else:
            rest.append(a)
    encode = '--encode' in opts or '--out' in opts
    if (encode and (rest or set(opts) != {'--encode', '--out'})) or (not encode and (len(rest) != 1 or rest[0].startswith('-'))):
        try:
            os.write(2, (__doc__.split('\n\n')[0] + '\n').encode())
        except OSError:
            pass
        return unverifiable('USAGE')
    if encode:
        out = os.path.abspath(opts['--out'])
        if os.path.lexists(out):
            return unverifiable('OUT_EXISTS')

        def unique(pairs):
            if len({k for k, _ in pairs}) != len(pairs):
                raise ValueError('duplicate key')
            return dict(pairs)
        try:
            with open(opts['--encode'], 'rb') as f:
                h = json.loads(f.read(V.MaxBytes + 1).decode('utf-8'), object_pairs_hook=unique)
            recs = h['records']
            ok = isinstance(h, dict) and set(h) == {'charge', 'original', 'records'} and isinstance(h['charge'], str) and \
                type(h['original']) is int and isinstance(recs, list) and \
                all(isinstance(r, dict) and set(r) == {'id', 'reason', 'amount'} and isinstance(r['id'], str) and
                    isinstance(r['reason'], str) and type(r['amount']) is int for r in recs)
            if not ok:
                raise ValueError('history form')
        except (OSError, ValueError, KeyError, TypeError):
            return unverifiable('ENCODE_INPUT')
        code, wal, line = V.EncodeEntry(text(h['charge']), h['original'], _dafny.Seq([text(r['id']) for r in recs]),
                                        _dafny.Seq([r['amount'] for r in recs]), _dafny.Seq([text(r['reason']) for r in recs]), as_json, key)
        if code != 0:
            return 3, line.VerbatimString(False)
        tmp = os.path.join(os.path.dirname(out), '.%s.tmp-%d' % (os.path.basename(out), os.getpid()))
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            try:
                data = bytes(wal)
                while data:
                    data = data[os.write(fd, data):]
                os.fsync(fd)
            finally:
                os.close(fd)
            os.link(tmp, out)      # fails if `out` appeared meanwhile: never replaced
        except FileExistsError:
            return unverifiable('OUT_EXISTS')
        except OSError:
            return unverifiable('OUT_WRITE_FAILED')
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        return 0, line.VerbatimString(False)
    try:
        with open(rest[0], 'rb') as f:
            wal = _dafny.Seq(f.read(V.MaxBytes + 1))
        rb = _dafny.Seq([])
        if '--ratchet' in opts:
            with open(opts['--ratchet'], 'rb') as f:
                rb = _dafny.Seq(f.read(V.MaxRatchetBytes + 1))
    except OSError:
        return unverifiable('UNREADABLE')
    code, line = V.Run(wal, '--ratchet' in opts, rb, '--expect-count' in opts, text(opts.get('--expect-count', '')),
                       '--expect-tip' in opts, text(opts.get('--expect-tip', '')), '--witness' in opts, as_json, key)
    return int(code), line.VerbatimString(False)


exit_code = 3
try:
    result, line = main(sys.argv[1:])
    emit(line)
    exit_code = result if result in (0, 1, 3, 4) else 3
except BaseException:
    try:
        emit('UNVERIFIABLE_INTERNAL_ERROR reason=INTERNAL_ERROR')
    except BaseException:
        pass
    exit_code = 3
os._exit(exit_code)
