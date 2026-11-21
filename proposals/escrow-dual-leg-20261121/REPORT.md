# Forge V2 escrow verifier — clean-room dual-leg (N-version), 2026-11-21

A 128-byte-record escrow-log verifier, built TWICE, independently, and cross-checked. The point is
component replaceability across an explicit contract (`spec/SPEC.md`): swap the entire implementation —
language, model vendor, crypto stack — and correctness survives, with zero human review of either leg's code.

## The two legs (neither author saw the other's code)
- **Leg 1 — Dafny, PROVED.** `leg1/` — hand-written SHA-256/512 + Ed25519 + verifier in Dafny, compiled to
  Python and JavaScript. `dafny verify` = **86 obligations, 0 errors** (SHA 30, Ed 16, verifier 40). Built
  clean-room by one agent from `spec/SPEC.md` + the golden vectors only.
- **Leg 2 — Rust, zero-dependency.** `leg2/` — hand-rolled SHA-256/512 + Ed25519, Rust `std` only. Built
  clean-room by a DIFFERENT model (GPT) from the spec alone, and **pre-registered** in `leg2_frozen.json`
  (commit-reveal, git commit `862ee20a`) BEFORE Leg 1 ever touched git. That ordering is what makes the
  agreement a genuine N-version check, not a copy.

## The contract
`spec/` is the frozen spec packet (`spec_packet_hash = 127b515567e2172846473d66c797d803289c89c4fdf3547f53cc343d4ffb20e7`,
re-release 5), 64 golden vectors. Ratified through `RATIFICATION_2026-11-21.md` (Q1–Q14) and, after fuzzing
surfaced a §2-vs-§3 genesis reject-code precedence gap, `FINDINGS_FUZZ_20261121.md` (Option B: §2 envelope
checks run first at every record, kind-gate before seq_no at genesis).

## RQ1 — component replaceability (differential): 0 divergences on 1,999 cases
`receipts/differential/` — both legs run on 64 golden + 1,935 generated fuzz cases (bit-flips, boundary money
values incl. 2^63±1, truncations, malformed manifests, key/signature corruption, record reorder, CLI edges,
~340 random). Canonical `--json` + exit code compared Leg1-vs-oracle, Leg2-vs-oracle, and Leg1-vs-Leg2:
**64/64 golden, 1935/1935 fuzz, 0 divergences.** The fuzz FOUND the genesis precedence gap the 56-vector
golden suite missed (303 divergences → ratified → 3 → 0 across passes); that progression is the evidence,
not an embarrassment.

## RQ2 — mutation (why finite suites hide flaws): 14/14 killed per leg, 0 survivors
`receipts/mutation/` — 14 realistic single-point bugs planted per leg, each on a copy. **14/14 killed on each.**
Highlight: **M10 (drop the cap check) is killed BY THE PROOF on Leg 1** — `dafny verify` fails on
`invariant 0 <= gross <= cap` (39 verified, 1 error), so the mutant can never ship; on Leg 2 the same bug
underflows and fails closed to `UNVERIFIABLE_INTERNAL` (killed by test). One bug, two independent catches.
Three mutants initially SURVIVED (records==max ceiling, bad genesis domain, decreasing record_ts) — real
coverage gaps in the 56 vectors, closed by 3 oracle-generated vectors (none tuned); re-run → 14/14.

## Honest labels (do not round up)
- **PROVED** applies only to Leg 1's named Dafny statements about the MODEL on one machine (round-trip
  encode/decode, money-fold soundness with no precondition + completeness, the #6584 `by method` guard).
- The compiled Leg 1 (Python/JS) and Leg 2 (Rust) are **NATIVE CHECK** (unverified compilers; the Python/JS
  pair cross-checks the #6584 JS-backend miscompile, dafny-lang/dafny#6584).
- The 1,999-case differential and the 14 mutants are a **FINITE TEST** — a large but finite corpus, NOT a
  proof of equivalence over all inputs. `end_to_end = false`.
- Not established: anything outside the byte-level verdict — no claim about the daemon/glue, OS isolation,
  effect doors, or that an ACCEPT means the work is good (only that the history is a conserved, authorized,
  at-most-once ledger per the ratified spec).

## Reproduce
- Leg 1: `cd leg1 && export PATH=/opt/homebrew/bin:$PATH NODE_PATH=<repo>/node_modules && bash build.sh && python3 -I harness.py` → 64/64.
- Differential: `receipts/differential/gen_corpus.py` then `run_corpus.py` (regenerates the 1,935 corpus; raw binaries not committed — deterministic from the generator).
- Mutation: `receipts/mutation/patches/` holds the 28 mutation diffs; evidence in `evidence_leg{1,2}.json`.
- Freeze/packet hash: `cd spec && sh freeze_leg2.sh` reproduces `127b5155`.

NOT merged by the agent.
