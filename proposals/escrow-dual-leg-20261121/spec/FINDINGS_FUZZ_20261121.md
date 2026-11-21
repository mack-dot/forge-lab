# Fuzz differential finding + ratified resolution (2026-11-21)

## Finding F1 — genesis reject-code classification split (surfaced by the 1991-case fuzz differential)
At the genesis record (index 0), a bad `magic`/`version`/header-`reserved` or a non-zero `seq_no` produced
DIFFERENT verdict CODES between the two legs — every other `--json` field identical, both exit 1:
- `magic`/`version`/`reserved` wrong: Leg 1 `REJECT_BAD_GENESIS` vs Leg 2 `REJECT_MALFORMED_RECORD`
- `seq_no != 0`: Leg 1 `REJECT_BAD_GENESIS` vs Leg 2 `REJECT_SEQ_MISMATCH`
303 of 1935 fuzz cases; all one finding. Reproduced by hand (orchestrator), independent of the harness.
The 56 golden vectors never mutate these genesis bytes, so the golden suite could not see it. Everything
else (money/time boundaries incl 2^63±1, truncations, manifests, keys, signatures, CLI edges, ~340 random)
agreed 100%. Impact bounded: exit code 1 either way (safety/money decisions unaffected); only the verdict
STRING differs; under the §9.6 `--json` substrate it is a divergence.

Cause: `SPEC §3` ("a record at index 0 that is not a valid genesis -> `BAD_GENESIS`") and the Q1/Q2a
ratification pin genesis structural faults to `BAD_GENESIS`, but `§3.2 step 1` does not say whether
magic/version/reserved/seq_no at index 0 emit the `§2` per-field codes or fold under `BAD_GENESIS`. Leg 1
folds; Leg 2 applies the per-field codes. Both defensible.

## Ratified resolution (owner, 2026-11-21): COLLAPSE TO REJECT_BAD_GENESIS
At the genesis record, ALL envelope structural faults (magic, version, domain-is-checked-separately as
`BAD_DOMAIN`, header reserved, seq_no != 0, prev_hash != 0, kind != 'G') -> `REJECT_BAD_GENESIS`. This
matches §3 and the Q1/Q2a precedent. (Domain stays `BAD_DOMAIN`, already agreed by both legs.)

To reach TRUE 0-diff:
1. SPEC §3.2 gets one explicit sentence stating the above (rr4 clarification of the frozen packet).
2. Add golden vectors pinning the genesis magic/version/reserved/seq_no cases to `BAD_GENESIS`.
3. Leg 1 ALREADY conforms (no change).
4. Leg 2 needs a one-site genesis-classifier change (the 4 codes -> `BAD_GENESIS`). For the paper's RQ1
   ("zero human review of the implementations"), this patch should come from Leg 2's author (the GPT),
   against the clarified spec — NOT from the orchestrator editing Rust.
5. Re-run the differential -> expect 0-diff; re-freeze (leg2 v2) and note the published commit-reveal
   (`862ee20a`, spec packet `51d1d035`, leg2 source `cdec66ea…`) stands as the historical pre-registration
   of leg2 v1 (built blind); v2 = v1 + this one spec-driven conformance patch.

Honest status until then: 0 safety divergences; one ratified genesis-classification corner; Leg 2
conformance pending. The fuzz result is a FINITE TEST (1991 cases), not a proof of equivalence.
