# BUILD.md — building and running Leg 2

## Requirements

Rust 1.70 or newer (developed and tested on **rustc 1.97.0 / cargo 1.97.0**),
edition 2021. **Nothing else.** No network, no crate registry, no system
libraries, no C toolchain. `cargo tree` lists exactly one package: this crate.

## Build

```sh
cd leg2-verify
cargo build --offline --release
# binary at ./target/release/leg2-verify
```

`--offline` is not strictly required (there is nothing to fetch) but makes the
zero-dependency property explicit, and it is how the build was validated.

The release profile deliberately keeps `overflow-checks = true` and
`panic = "unwind"`. Do not change either:

* `overflow-checks` turns any unintended integer overflow into a panic, which is
  then caught and reported as `UNVERIFIABLE_INTERNAL` (exit 3). Without it, an
  arithmetic bug could silently wrap — the one thing SPEC.md §1 forbids outside
  SHA-256 compression.
* `panic = "abort"` would bypass the `catch_unwind` in `main` and let a panic
  reach the shell as exit 101 instead of a fail-closed exit 3.

## Run

```
leg2-verify <log.bin> --manifest <m.bin> --pubkeys <a.pub,b.pub> \
            [--tape <t.bin>] [--observed-now N] [--expect-tip HEX] \
            [--max-records N] [--json]
```

Example, against the packet's vectors:

```sh
GV=path/to/golden_vectors
./target/release/leg2-verify "$GV/accept_two_step.log.bin" \
    --manifest "$GV/accept_two_step.manifest.bin" \
    --pubkeys  "$GV/a.pub,$GV/b.pub" \
    --observed-now 1700000500
```

```
ACCEPT
records=3 torn_bytes=0 fail_index=-
gross_spent=200 seller_payout=200 buyer_refund=300
tip=89c32e8d0ab59b90f10eef66b79a946477e988d38be0e4a28a9782a6e724bce8
expiry_gate=evaluated
```

Line 1 is always the verdict, in full, with nothing else on it. Exit codes:
**0** `ACCEPT`, **4** `ACCEPT_TORN_TAIL`, **1** any `REJECT_*`, **3** any
`UNVERIFIABLE_*`.

### Machine-readable output

`--json` prints one object, which is what the differential harness should compare
(see SPEC_QUESTIONS.md Q9 — the text line format is not yet ratified):

```sh
leg2-verify log.bin --manifest m.bin --pubkeys a.pub,b.pub --observed-now 1700000500 --json
```

```json
{"verdict":"ACCEPT","exit_code":0,"records":3,"torn_bytes":0,"fail_index":null,
 "final_balances":{"gross_spent":200,"seller_payout":200,"buyer_refund":300},
 "tip":"89c32e8d...","expiry_gate_evaluated":true,"notes":[]}
```

### Spec flags and the one extension

`--tape`, `--observed-now`, `--expect-tip`, `--max-records` and `--json` are all
part of the ratified CLI (SPEC.md §9.1). The switches that existed in the
pre-ratification build to make open items bisectable
(`--genesis-id-check`, `--strict-pubkeys`, `--require-valid-pubkeys`) are **gone**:
those checks are now mandatory spec, and a flag that can disable a required check
is a divergence waiting to happen.

| Flag | Purpose | Question |
| --- | --- | --- |
| `--json` | the canonical SPEC.md §9.6 comparison object | §9.6 |
| `--tape <t.bin>` | co-signed sidecar; WITH it signatures are enforced, WITHOUT it skipped | §9.2 |
| `--expect-spec-hash HEX` | **extension**: activates `SPEC_MISMATCH`, which SPEC.md leaves deferred and unwired | §3.2 |
| `--strict-pubkeys` | require `--pubkeys` to equal the manifest's `key_A`/`key_B` | Q5 |
| `--genesis-id-check on\|off` | enforce the all-zero-id rule on the manifest ids (default `on`) | Q4 |
| `--require-valid-pubkeys` | require the manifest's pinned keys to be valid, non-small-order points. **Refuses the current corpus**: `a.pub` is not a curve point | Q14 |
| `--max-records N` | whole-record ceiling (default 16777216) | Q8 |
| `--selftest` | run the built-in crypto self-checks and exit | — |
| `--tape <path>` | **refused**: the sidecar layout is unratified (D-TAPE) | Q11 |

## Verify the build

```sh
# 1. built-in crypto self-checks (derived curve constants, [L]B == identity)
./target/release/leg2-verify --selftest        # -> SELFTEST_OK

# 2. the full Rust test suite: 55 tests
cargo test --offline --release

# 3. the golden corpus: 54/54 cases
python3 tools/run_vectors.py ./target/release/leg2-verify path/to/golden_vectors

# 4. process-level CLI contract: 39 checks
bash tools/cli_tests.sh ./target/release/leg2-verify path/to/golden_vectors
```

See TEST_RESULTS.md for the recorded output of all four, plus the hash
differential test, the SHA-2 constant re-derivation and the speed measurement.

## Layout

```
src/
  main.rs      CLI, output formatting, exit codes, fail-closed panic handling
  lib.rs       crate root, hex helpers, crypto_self_check()
  spec.rs      every frozen width/offset/bound from SPEC.md §8, with citations
  record.rs    byte-exact envelope + manifest accessors (cannot panic)
  verdict.rs   Verdict enum, exact printed names, exit-code derivation, Report
  verify.rs    genesis checks (§3.2, 7 steps), the Step fold (§5.2, 13 steps) and
               the co-signed tape check (§9.2), all in the ratified order
  sha2.rs      SHA-256 and SHA-512, hand-rolled (FIPS 180-4)
  fe.rs        GF(2^255-19) field arithmetic; derives d, sqrt(-1), base point
  scalar.rs    scalars mod L
  ed25519.rs   RFC 8032 verification (strict profile), plus signing for KATs
tests/
  crypto_kat.rs   FIPS 180-4 + RFC 8032 known-answer tests, step-9 predicate
  ed25519_edge.rs torsion/non-canonical/malleability battery (derived, not tabled)
  robustness.rs   bit flips, truncation, reordering, money bounds, determinism
tools/
  run_vectors.py          golden-vector acceptance runner
  cli_tests.sh            process-level exit-code and I/O contract tests
  py_hashes.py            independent hash oracle (Python hashlib)
  check_sha_constants.py  re-derives all 160 SHA-2 constants from first principles
  make_big_log.py         large-corpus generator (a third, independent encoder)
  check_pubkeys.py        independent pure-Python check of the packet's a.pub/b.pub
examples/
  hashdump.rs             dumps hashes for the differential test
  make_tape_corpus.rs     builds a co-signed corpus so --tape can be measured
```

Read `spec.rs` and `verify.rs` first: between them they contain the whole of the
escrow semantics, each check annotated with the SPEC.md step number it implements.
