# Verdicts of `verify-refund-log`

```
verify-refund-log <ledger.wal> [--witness <file>] [--ratchet <file>] [--expect-count <n>] [--expect-tip <hex>] [--json]
```

Built by `python3 verifier/refund_log/build.py` into `build/refund_log_verifier/` (untracked), from ONE verified
Dafny file, for TWO targets with the same CLI, verdict lines, `--json` fields, exit codes and `--encode`:
- Python: `verify-refund-log` (shim `verify_refund_log.py`) and `model-py/` (Dafny's Python output and runtime);
- JavaScript on Node 24.3.0: `verify-refund-log-node` (shim `verify_refund_log_node.cjs`) and `node-model/`
  (`model.cjs` = Dafny's JS output with its runtime and one appended export line; `node_modules/bignumber.js` =
  a copy of bignumber.js 9.3.1 from the toolchain checkout's `node_modules`, as `minter-build.sh` does).

Output: ONE line on stdout. Plain: `<VERDICT> key=value key=value …`, always ending with
`spec_sha256=1a8c7c2a… sink_sha256=1962af4a…` (full 64 hex digits). With `--json`: one JSON object
`{"verdict":…,"exit_code":…, <the same keys in the same order>}`; numbers are JSON numbers, ids and hex are strings.
Nothing on stderr except the usage text.

Exit codes (orchestrator decision of 2026-11-20): **0** `ACCEPT` only (clean: no torn part); **4**
`ACCEPT_TORN_TAIL` (the whole-record prefix is a valid history; trailing partial bytes were not counted);
**1** every `REJECT_*`; **3** every `UNVERIFIABLE_*`, a usage error (`UNVERIFIABLE_USAGE`) and any internal error.
No error path prints an `ACCEPT` verdict. Every verdict and exit code is computed by the proved Dafny method
`RefundLogVerifier.Run`; the shim only splits the arguments, reads the files (bounded) and passes the strings.
The second entry point `--encode` (the proved model encoder) is described in `ENCODE.md`.

How the exit code is made (the shim, `verify_refund_log.py`): it starts at 3. It becomes 0 or 4 only when the proved
`Run` returns 0 or 4 (or `EncodeEntry` returns 0) AND the whole output line was written to stdout with `os.write`
(the byte count is checked). If the line cannot be written (closed stdout, broken pipe), the exit code is 3 and no
other line follows. Every path ends with `os._exit(code)`: no exit handler and no module code runs after it.

The launcher and what stays trusted:
- `build/refund_log_verifier/verify-refund-log` starts with `#!<absolute interpreter> -I`, written by `build.py`
  from the interpreter that ran the build (`os.path.realpath(sys.executable)`; recorded in `build.json`). The
  tracked file `verifier/refund_log/verify_refund_log.py` starts with `#!/usr/bin/env -S python3 -I`: that line,
  which looks `python3` up in `PATH`, is only the documented fallback for a copy that `build.py` did not make.
- `-I` (isolated mode) makes Python ignore every `PYTHON*` variable (`PYTHONPATH`, `PYTHONHOME`, `PYTHONSTARTUP`,
  ...), the user site folder and the script's folder. The shim then puts `model-py` (from the shim's resolved
  location) first on `sys.path` and imports `json` and the Dafny modules only after that. `os` and `sys` come from
  the interpreter's own standard library.
- Still in the trusted base: that interpreter file and its standard library; the build folder (`model-py`, the
  launcher); the operating system's dynamic loader, which still honours `DYLD_*` variables of the caller's
  environment for an interpreter that is not a protected system binary; and `os.urandom` for the hash key (only
  the running time depends on it, never the verdict: `Verify` is proved equal to `VerifySpec` for every key).
- Manual check (the reviewer's reproduction of finding F1; it must print `UNVERIFIABLE_UNREADABLE …` and exit 3):

  ```
  d=$(mktemp -d) && printf 'import os\nos._exit(0)\n' > "$d/json.py" && cp "$d/json.py" "$d/os.py" && \
  PYTHONPATH="$d" build/refund_log_verifier/verify-refund-log /nonexistent; echo "exit $?"
  ```

 `index` is the position of the 64-byte record in the WAL (0 = genesis). `verified_records` is the
number of commit records (index >= 1) that passed every check before the refused one. "records" and "epoch" count
commit records (genesis excluded); for an accepted log they are equal.

## Ratified tail semantics (owner, 2026-11-20)

Only a trailing part of 1 to 63 bytes is a torn tail: `ACCEPT_TORN_TAIL`, exit 4, and that part is never read as a
record. A whole 64-byte final record that fails its CRC or any other check is a `REJECT_*` (exit 1). This departs
from Report F, which expected TORN for a full final record with a bad CRC; the owner ratified the built behaviour on
2026-11-20. Reason: a whole record that fails its seal cannot be told apart from corruption or modification, so
calling it torn would be a guess; and the verifier never repairs or truncates the file it reads, so it reports
what the bytes are.

## The Node launcher

`verify-refund-log-node` starts with `#!/usr/bin/env -S -i <absolute node>` (written by `build.py`; the tracked
`verify_refund_log_node.cjs` has `#!/usr/bin/env node` as the documented PATH fallback, without the isolation). `env -i`
empties the caller's environment before Node starts, so `NODE_OPTIONS`, `NODE_PATH` and `DYLD_*` never reach it; a
`NODE_*` variable that still arrives (fallback use) is refused with `UNVERIFIABLE_INTERNAL_ERROR`, exit 3 (in that
case a `--require` in `NODE_OPTIONS` could already have run: the fallback is NOT isolated). The exit code starts at
3, becomes 0 or 4 only by `Run`'s return value after a checked `fs.writeSync` of the whole line, and the program ends
with `process.exit`. `--encode` uses a strict JSON reader (exact integers; a repeated key or a lone surrogate is
refused) and the same temporary-file-then-link write as the Python shim. One known difference: when the caller
CLOSES stdout, Node itself reopens it on `/dev/null` at start, so the Node program writes the line there and exits
with the verdict's code, while the Python program cannot write and exits 3. Still trusted for this target: the Node
binary recorded in the launcher, `/usr/bin/env`, the copied bignumber.js 9.3.1, `crypto.randomBytes` (running time
only).

## Order of checks (the first failing check names the verdict)

1. File: empty, shorter than 64 bytes, larger than the bound (the shim reads at most bound + 1 bytes).
2. Record 0 (genesis): CRC, then magic and id field, then genesis content.
3. Each record i >= 1, in order: CRC; magic and id field; epoch == i; pre-state hash == FNV-1a-128(record i-1);
   then the ratified rule (`RefundLogSpec.Step` on the state folded so far). If Step refuses, the cause is named in
   this order: reason, empty id, duplicate id, amount above MaxMoney, amount above remaining.
4. Only for an accepted fold, in this order: `--ratchet`, `--expect-count`, `--expect-tip`.

## Accepted (exit 0 and exit 4)

| Verdict | Meaning | Fields |
| --- | --- | --- |
| `ACCEPT` (exit 0) | Every whole record passed; the length is a multiple of 64; the ratchet (if given) has no torn part; each anchor given matches. Then theorem `RefundLogVerifier.Soundness` applies (ratified `ValidHistory` from the D1 genesis; conservation; at most once). | `records charge original remaining epoch tail torn_bytes`, then `ratchet=none` or `ratchet_floor ratchet_entries ratchet_torn_bytes`, then `expect_count=<n or none> expect_tip=<hex or none>` |
| `ACCEPT_TORN_TAIL` (exit 4) | As `ACCEPT` for the whole records, but the WAL ends in a part of 1 to 63 bytes (`torn_bytes`), or the ratchet ends in a part of 1 to 11 bytes. That part is not read as a record. The sink cuts it at its next start. The name is never shortened to ACCEPT: a consumer that tests the verdict name sees the tail. | same as `ACCEPT` |

`tail` is the FNV-1a-128 of the last whole record, 32 lowercase hex digits: the value that the sink prints in
`COMMITTED <epoch> <tail> …` and `STATE <epoch> <tail> …`.

## Refused (exit 1)

| Verdict | Meaning | Fields |
| --- | --- | --- |
| `REJECT_BAD_CRC` | bytes 60..64 of record `index` are not the CRC-32 of its bytes 0..60 | `index verified_records` |
| `REJECT_MALFORMED_RECORD` | record `index` does not start with `FSW`, or its id field has a byte outside `[A-Za-z0-9_-]` before the first NUL or a non-NUL byte after it | `index verified_records` |
| `REJECT_BAD_GENESIS` | record 0 is framed but is not a genesis: kind not `G`, epoch not 0, pre-state hash not 0, empty charge id, or original amount above 2^63-1 | `index` (= 0) `verified_records` (= 0) |
| `REJECT_EPOCH_MISMATCH` | the epoch field of record `index` is not `index` (gap, repeat, removed or swapped record) | `index verified_records` |
| `REJECT_CHAIN_MISMATCH` | the pre-state hash of record `index` is not the FNV-1a-128 of record `index`-1 | `index verified_records` |
| `REJECT_REASON_NOT_ALLOWED` | the kind byte of commit record `index` is not `1`, `2` or `3` (so its reason is not an approved reason) | `index verified_records` |
| `REJECT_EMPTY_ID` | commit record `index` has an empty request id | `index verified_records` |
| `REJECT_DUPLICATE_ID` | the request id of record `index` is already settled by an earlier record | `index verified_records` |
| `REJECT_AMOUNT_NOT_MONEY` | the amount of record `index` is above 2^63-1 (the format is unsigned; a signed reader would see a negative amount) | `index verified_records` |
| `REJECT_AMOUNT_OVER_REMAINING` | the amount of record `index` is above the remaining amount at that point | `index verified_records` |
| `REJECT_RULE` | the ratified Step refused for a cause not listed above (not reachable with a D1 genesis; listed for totality) | `index verified_records` |
| `REJECT_RATCHET_NO_ENTRY` | `--ratchet` was given and has no whole 12-byte entry | accepted-fold fields + `ratchet_entry ratchet_floor` |
| `REJECT_RATCHET_BAD_ENTRY` | a whole ratchet entry (`ratchet_entry`) has a bad CRC (the sink would skip it; the verifier refuses) | same |
| `REJECT_RATCHET_AHEAD` | the highest ratchet entry (`ratchet_floor`) is above the WAL's final epoch: the WAL is older than its ratchet (cut back or restored) | same |
| `REJECT_COUNT_MISMATCH` | `--expect-count n` was given and the accepted log has another number of commit records | accepted-fold fields + `expect_count` |
| `REJECT_TIP_MISMATCH` | `--expect-tip h` was given and the FNV-1a-128 of the last whole record is not `h` | accepted-fold fields + `expect_tip` |

## Not verifiable (exit 3)

| Verdict | Meaning | Fields |
| --- | --- | --- |
| `UNVERIFIABLE_EMPTY_FILE` | the WAL has 0 bytes | `reason` |
| `UNVERIFIABLE_NO_WHOLE_RECORD` | the WAL has 1 to 63 bytes | `reason` |
| `UNVERIFIABLE_TOO_LARGE` | the WAL is larger than 65,536 records (4,194,304 bytes) | `reason` |
| `UNVERIFIABLE_RATCHET_TOO_LARGE` | the ratchet is larger than 3,145,728 bytes | `reason` |
| `UNVERIFIABLE_UNREADABLE` | a named file cannot be opened or read | `reason` |
| `UNVERIFIABLE_WITNESS_UNSUPPORTED` | `--witness` was given. The format holds every field in clear (FORMAT.md), so no witness is defined; the verifier refuses rather than ignore an input | `reason` |
| `UNVERIFIABLE_ENCODE_INPUT`, `UNVERIFIABLE_INVALID_HISTORY`, `UNVERIFIABLE_OUT_EXISTS`, `UNVERIFIABLE_OUT_WRITE_FAILED` | only with `--encode`: see ENCODE.md | `reason` |
| `UNVERIFIABLE_USAGE` | the arguments do not match the usage line, `--expect-count` is not a decimal number without a sign or leading zero, or `--expect-tip` is not exactly 32 lowercase hex digits | `reason` |
| `UNVERIFIABLE_INTERNAL_ERROR` | an exception in the shim or the runtime (printed by the shim; plain form only) | `reason` |

`reason` repeats the part after `UNVERIFIABLE_`.

## What ACCEPT establishes, and what it does not

ACCEPT (or ACCEPT_TORN_TAIL) means: the whole records of these bytes are exactly the model encoding of a history
that the ratified specification `spec/refund/RefundLogSpec.dfy` (SHA-256 `1a8c7c2a…`) accepts from the genesis
`Genesis(charge, original, refundEnabled := true)`, and the reported `remaining`, `epoch` are its final state. It
does NOT establish that these bytes are what the engine wrote: CRC-32 and FNV-1a-128 are not keyed and not
cryptographic, so anyone who can write the file can rewrite ANY record and recompute every later chain value and CRC
(see FORMAT.md, "Authenticity"). It does NOT establish either: that these bytes are the whole durable log (truncation, rollback of both files: H_LOG), that the
last record was not rewritten (unless `--expect-tip`), that the sink prevented anything, that the external payment
happened, who sent a request, or anything about the drive or the hardware.
