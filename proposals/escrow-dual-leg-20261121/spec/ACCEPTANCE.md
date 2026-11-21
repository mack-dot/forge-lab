# ACCEPTANCE.md — how we know Leg 2 is done and correct

**STATUS: DRAFT.** `end_to_end=false`. No build is run here; this states the bar.

Leg 2 is accepted when all four conditions hold.

## 1. Passes 100% of the golden vectors

- Leg 2 runs every case in `golden_vectors/vectors.json` with the case's inputs
  (`log_file`, `manifest_file`, `pubkeys_file`, optional `tape_file`, `observed_now`,
  `expect_tip`, `max_records`) and emits a `--json` object EQUAL to the case's
  `expected_json` (SPEC.md §9.6): `verdict`, `exit_code`, `records`, `torn_bytes`,
  `fail_index`, `final_balances`, `tip`, `epoch`, `expiry_gate_evaluated`, `notes`.
- No case may be skipped, quietly passed, or "close enough". Any field differing from
  `expected_json` is a failure, even if the verdict name matches.
- The signature/key cases are REAL (no placeholders): `accept_cosigned_tape`
  (valid co-signatures), `reject_bad_signature_tape` (one corrupted sig),
  `reject_key_mismatch`, `reject_bad_key`. Leg 2 must implement the strict Ed25519
  profile (SPEC.md §9.3).

## 2. Differential harness: Leg 1 and Leg 2 must agree

A differential harness (built later, outside this packet) runs Leg 1 and Leg 2 over
the SAME corpora:

- the golden vectors here;
- large random / generated logs;
- structured fuzzing (bit flips, truncation, reordered records, boundary money
  values, malformed ids, torn tails of every length 1..127).

Rule: for every input, the two legs must emit an **identical `--json` object** (and an
identical first stdout token). Any mismatch is a `DIVERGENCE_HALT`:

- fail closed before any value moves;
- save the exact byte slice that diverged as a reproducer;
- page a human.

Agreement is an **N-version NATIVE CHECK**, not a proof. It catches a Dafny
front-end bug with the independent Rust leg, and a human Rust logic bug with the
proved Dafny leg. That two-sided catch exists ONLY under genuine independence.

## 3. The independence attestation

Gharib confirms, in writing, that Leg 2 was built from THIS packet alone:

- did not read the Dafny verifier, any Leg-1 source, or any Leg-1 `FORMAT.md` /
  `VERDICTS.md` / internal note;
- shares no parser, front-end, IR, compiler, or runtime with Leg 1;
- is a different human from Leg 1's author.

Without this attestation the two-leg agreement proves far less: a shared blind spot
would survive. The attestation is part of acceptance, not a formality.

## 4. Honest labels on the result

- Leg 2's label: **UNPROVED-but-independent-toolchain.**
- Two-leg agreement: **NATIVE CHECK**, not a proof, not authenticity.
- Measure Leg 2's real speed on real corpora before quoting any number. Do not quote
  the UNVERIFIED "~5 ms" figure.
- `end_to_end=false` stays until a real end-to-end path (real rail, real payment, real
  custody) is shown.

## 5. Frozen — nothing provisional remains

The spec is owner-ratified (`RATIFICATION_2026-11-21.md`, Q1-Q14) and the packet is
frozen under a `spec_packet_hash` (`FREEZE.md`). Every width, encoding, verdict name,
check order, and interface in `SPEC.md` is FINAL. If a future change touches any of
them, regenerate the vectors with `gen_vectors.py`, re-freeze with a new hash, and
re-run acceptance.
