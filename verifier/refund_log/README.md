# Refund-log verifier (`verify-refund-log`)

## What this is

A program that reads the write-ahead log `ledger.wal` of the native silicon sink (`src/silicon_sink/sink.rs`) and
its ratchet file `ledger.epoch`, and decides whether the log is a valid history of the ratified refund-log
specification `spec/refund/RefundLogSpec.dfy` (SHA-256
`1a8c7c2a306cd651ea691a9d93f96063c5dffb1686ee1f43845e2de727b4bc5a`). It does not trust the engine that wrote the
log. It reads the bytes and re-checks every rule.

- The checker is written and proved in Dafny: `RefundLogVerifier.dfy` (the decoder, the fold, the program, the
  theorems) and `RatifiedSpecLemmas.dfy` (lemmas about the ratified specification).
- The Dafny compiler translates it to two targets with the same command line: Python
  (`build/refund_log_verifier/verify-refund-log`, shim `verify_refund_log.py`) and JavaScript on Node 24.3.0
  (`build/refund_log_verifier/verify-refund-log-node`, shim `verify_refund_log_node.cjs`). Each small unverified
  shim reads the files and writes the result. The `cross_target` case of the exit script requires byte-identical
  output lines and exit codes of the two programs on every test input.
- `FORMAT.md` gives the log format byte by byte, with `sink.rs` line references. `VERDICTS.md` gives every
  verdict. `ENCODE.md` describes the second entry point, `--encode`, which writes the model encoding of a history.

Labels: the Dafny statements are PROVED (on one machine, pinned Dafny 4.11.0 and Z3 4.12.1). The compiled program is
a NATIVE CHECK. The test suites under `tests/refund_log_verifier/` are a FINITE TEST. `end_to_end=false`.

## Build and run (three commands)

```sh
python3 verifier/refund_log/build.py              # Dafny build (verifies, then compiles) into build/refund_log_verifier/
build/refund_log_verifier/verify-refund-log <ledger.wal> --ratchet <ledger.epoch> --expect-count <n> --expect-tip <hex>
python3 scripts/exit_refund_log_verifier.py --case proofs   # re-check the proofs, the audit, the cheat scan, the spec pin
```

The pinned Dafny is looked up under `<FORGE_TOOLCHAIN_ROOT>/.toolchain/dafny-4.11.0/dafny/dafny`, or at
`FORGE_DAFNY`. Set `FORGE_TOOLCHAIN_ROOT` to the checkout that holds `.toolchain/` when you build in another
worktree. The anchors (`--ratchet`, `--expect-count`, `--expect-tip`) are optional. Add `--json` for one JSON object
in place of the text line.

## What ACCEPT establishes

ACCEPT (exit 0) establishes exactly this: the bytes of this file decode, with no byte ignored, to a genesis and N
refund records that form a valid history of the ratified refund-log specification `1a8c7c2a…bc5a`: no request id
settles twice and original = remaining + the sum of the amounts.

The Dafny lemma `RefundLogVerifier.Soundness` states this for any byte string. Its only precondition is the verdict
itself (`VerifySpec(wal).Accept?`). The method `Run`, which the compiled program calls, has no precondition. Its
postcondition ties exit 0 and exit 4 to that verdict. `Completeness` states the converse for model logs: every
valid history, encoded by the model encoder, is accepted. The genesis is read as `Genesis(charge, original,
refundEnabled := true)` by the owner's decision D1 (`unsure.md` U928).

## What ACCEPT does NOT establish

- **That the engine wrote these bytes.** CRC-32 and FNV-1a-128 are unkeyed and not cryptographic. Anyone who can
  write the file can rewrite any record and recompute every later chain value and CRC. The result is accepted if it
  is a valid history.
- **That the file is complete.** Removing whole records from the end leaves a valid shorter log (clean
  truncation). A joint restore of the log and the ratchet to an older state is not visible from the two files.
  Both need an outside anchor (hypothesis H_LOG of Report D).
- **That the drive kept the data.**
- **That any payment happened.** The log records decisions, not external effects.
- **Who sent a request.** The format has no requester field.
- **Anything about the engine's code or hardware.** The verifier does not read them and does not need them.
- **Prevention.** The verifier runs after the fact. A bad transition is found only after it is on disk.
- **That the proved CakeML refund binary agreed.** The log does not store the binary's answer. A sabotaged sink
  that commits a refund although the binary refused it writes a valid history, and the verifier ACCEPTs it (test
  `binary_refusal_ignored` of `tests/refund_log_verifier/test_planted_bugs.py`).
- **The request's flag bits.** They are not in the log, so the verifier cannot check them.
- **That refunds were enabled.** `refundEnabled = true` is an interpretation fixed by the owner's decision D1
  (`unsure.md` U928). It is not a stored fact.
- **The external dispatch of a refund, and that it happened at most once.** "No request id settles twice" is a
  statement about the records in this file, not about the payment provider.
- **Other stores of the same charge.** The verifier reads one store. A second store or a fork is not covered.
- **Anything, unless the exit code is 0 from the proved `Run`.** The meaning above holds only when the process
  exits 0 with the verdict `ACCEPT`, and only if the launcher and the Python interpreter ran the compiled `Run`
  as built. They are in the trusted base (item 4 below). See `VERDICTS.md` for how the launcher isolates the
  interpreter from the environment of the caller.

## Tail semantics (ratified by the owner, 2026-11-20)

Quoted from `VERDICTS.md`, section "Ratified tail semantics":

> Only a trailing part of 1 to 63 bytes is a torn tail: `ACCEPT_TORN_TAIL`, exit 4, and that part is never read as a
> record. A whole 64-byte final record that fails its CRC or any other check is a `REJECT_*` (exit 1). This departs
> from Report F, which expected TORN for a full final record with a bad CRC; the owner ratified the built behaviour on
> 2026-11-20.

## Anchors

| Option | What it adds | What it still does not show |
| --- | --- | --- |
| `--expect-count <n>` | The log must hold exactly `n` commit records. Detects clean truncation and appended records when `n` comes from a trusted source. | A swap or a rewrite that keeps the count. |
| `--expect-tip <hex>` | The FNV-1a-128 of the last whole record must equal `<hex>` (the value that the sink prints in `COMMITTED <epoch> <hex>` and `STATE <epoch> <hex>`). Detects a rewritten last record (Trap A) and a truncation. | FNV-1a-128 is not a cryptographic digest. It does not resist a forger who searches for a second log with the same value. |
| `--ratchet <ledger.epoch>` | Every whole 12-byte entry must have a valid CRC, at least one entry must exist, and the highest entry must not be above the log's final epoch. Detects a log that is older than its ratchet. | A joint restore of both files. |

## Verdicts and exit codes

From `VERDICTS.md` (the authoritative list; field lists are there).

| Exit | Verdicts |
| --- | --- |
| 0 | `ACCEPT`: every whole record passed, the length is a multiple of 64, the ratchet (if given) has no torn part, each anchor given matches |
| 4 | `ACCEPT_TORN_TAIL`: as ACCEPT for the whole records, but the log ends in a part of 1 to 63 bytes, or the ratchet in a part of 1 to 11 bytes; that part is not read as a record |
| 1 | `REJECT_BAD_CRC`, `REJECT_MALFORMED_RECORD`, `REJECT_BAD_GENESIS`, `REJECT_EPOCH_MISMATCH`, `REJECT_CHAIN_MISMATCH`, `REJECT_REASON_NOT_ALLOWED`, `REJECT_EMPTY_ID`, `REJECT_DUPLICATE_ID`, `REJECT_AMOUNT_NOT_MONEY`, `REJECT_AMOUNT_OVER_REMAINING`, `REJECT_RULE`, `REJECT_RATCHET_NO_ENTRY`, `REJECT_RATCHET_BAD_ENTRY`, `REJECT_RATCHET_AHEAD`, `REJECT_COUNT_MISMATCH`, `REJECT_TIP_MISMATCH` |
| 3 | `UNVERIFIABLE_EMPTY_FILE`, `UNVERIFIABLE_NO_WHOLE_RECORD`, `UNVERIFIABLE_TOO_LARGE`, `UNVERIFIABLE_RATCHET_TOO_LARGE`, `UNVERIFIABLE_UNREADABLE`, `UNVERIFIABLE_WITNESS_UNSUPPORTED`, `UNVERIFIABLE_USAGE`, `UNVERIFIABLE_INTERNAL_ERROR`; with `--encode` also `UNVERIFIABLE_ENCODE_INPUT`, `UNVERIFIABLE_INVALID_HISTORY`, `UNVERIFIABLE_OUT_EXISTS`, `UNVERIFIABLE_OUT_WRITE_FAILED` |

A consumer that needs the strict meaning of the section "What ACCEPT establishes" must require exit 0 and the
verdict name `ACCEPT`. Exit 4 means that trailing bytes were present and were not counted.

## Trusted base

The result depends on these items. None of them is proved here.

1. **Dafny 4.11.0 and Z3 4.12.1** (the verifier and its solver) are sound for these files.
2. **The Dafny compiler and its Python runtime** (`model-py/_dafny`) preserve the meaning of the proved code.
   The compiler is not verified.
3. **The shim `verify_refund_log.py`, 122 lines**, unverified. It splits the arguments, reads at most
   bound + 1 bytes of each file, draws the random key of the settled-id table, calls the compiled
   `RefundLogVerifier.Run` (or `EncodeEntry`), writes the one output line with checked writes, and exits with the
   code that `Run` returns only after the whole line was written. Every other path exits 3; on an exception it
   tries to write `UNVERIFIABLE_INTERNAL_ERROR`. The tracked file starts with `#!/usr/bin/env -S python3 -I`;
   `build.py` replaces that line in the built launcher by the absolute interpreter of the build, with `-I`.
4. **The launchers and their runtimes** that run the shims and the compiled code: the Python interpreter named in
   the first line of `verify-refund-log` (run with `-I`), and for the second target the Node binary named in
   `verify-refund-log-node` (started through `/usr/bin/env -S -i`), the copied `bignumber.js` 9.3.1 and the
   unverified shim `verify_refund_log_node.cjs`, 122 lines. `VERDICTS.md` lists one known difference: when the caller
   closes stdout, Node reopens it on `/dev/null`, writes the line there and exits with the verdict's code, while the
   Python program exits 3. A module planted on the
   import path of an unisolated interpreter could exit 0 before `Run` is called (review finding F1); the launcher's
   isolation is described in `VERDICTS.md` and tested by the `suite` case of `scripts/exit_refund_log_verifier.py`.
5. **The reader's own copy of the ratified specification**: compare its SHA-256 with
   `1a8c7c2a306cd651ea691a9d93f96063c5dffb1686ee1f43845e2de727b4bc5a`. The verifier prints `spec_sha256=` on every
   line, but that value is a constant in the program. It is not a hash that the program computes at run time.

## Two findings about the sink at the tail

1. **The sink silently cuts up to 64 trailing bytes.** On each open, `sink.rs` cuts a trailing part that does not
   form a valid record (`sink.rs:98`, `119-123`). This includes a torn append and also a whole last record that
   fails a check.
2. **A forged last record without its ratchet entry is cut silently.** When the ratchet floor is below the epoch of
   the last record, the sink treats that record as a torn append and cuts it, with exit 0. The negative controls
   show this for a duplicate id and an over-refund in the last record.

So the verifier reports what it reads, not what the sink would recover. A partial tail gives
`ACCEPT_TORN_TAIL` (exit 4). A whole bad last record gives a `REJECT_*`. "What the sink recovered" and "what the
verifier read" can therefore differ exactly at the tail. To ask about the recovered state, run the verifier after
the sink has opened the store.

## Finding: a defect in the unverified Dafny compiler (JavaScript runtime)

The JavaScript runtime of Dafny 4.11.0 computes `^` and `|` on bit vectors with JavaScript's signed 32-bit
operators on its 53-bit BigNumber chunks (`_dafny.BitwiseXor`, `_dafny.BitwiseOr`). A proved Dafny program can
therefore give another result on the JavaScript target than on the Python target. This is a known upstream issue,
dafny-lang/dafny#6584. Reproduction (as reported by CORE; not re-run by the exit check):

```
method Main() { var x: bv32 := 0xFFFF_FFFF; print x ^ 0x31, "\n"; }
dafny run --target py x.dfy    # prints 4294967246
dafny run --target js x.dfy    # prints -50
```

Before the repair, the Node program refused every log with `REJECT_BAD_CRC` at record 0. The repair is in the
Dafny source only: the helpers `Xor32` and `XorByte128` (`RefundLogVerifier.dfy`) have method bodies that Dafny
proves equal to the plain `^`. This shows why the compiler is in the trusted base: the proofs speak about the Dafny
text, and the `cross_target` check is the only check that the two compiled programs agree.

## Records note: which proved Dafny files are reused

The verifier reuses the lemmas about the ratified specification: `RatifiedSpecLemmas.dfy` is byte-equal to
`proposals/refund-log-spec-20261120/RefundLogSpecLemmas.dfy` except its first line (the include path). It does not
reuse `impl/finality-core/SinkCoreV3.dfy` or `impl/finality-core/ShellCoreV5.dfy`. Both are drafts that say so in
their first lines ("A DRAFT … NOT approved", SinkCoreV3.dfy:1; "A DRAFT. NOT gate evidence. NOT about sink.ts",
ShellCoreV5.dfy:1). They are stated over another state and record type: `RefundFinality.Charge` with signed
`SinkToken` values (SinkCoreV3.dfy:19-24, 100-102) and rows of decoded tokens with Ed25519 and SHA-256 checks
(ShellCoreV5.dfy:5-8, 27), not over `RefundLogSpec.LedgerState` and not over the 64-byte records of
`src/silicon_sink/sink.rs`. ShellCoreV5 also takes the initial charge from outside the stored data
(ShellCoreV5.dfy:12-13), while this verifier reads it from record 0.

## Checks of this package

`scripts/exit_refund_log_verifier.py --case proofs|build|suite|mutations|evidence` runs the proofs, the audit, a
token-level scan for `assume`, axioms and declarations without a body, the theorem headers, the build (twice), the
suites, and changed copies of the verifier that the suites or the proofs must refuse
(`tests/refund_log_verifier/mutants_verifier.py`). Its bundle is a record, NOT gate evidence. `end_to_end=false`.
