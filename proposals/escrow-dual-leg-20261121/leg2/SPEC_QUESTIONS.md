# SPEC_QUESTIONS.md — **ALL 14 CLOSED** by the owner's ratification

**From:** Leg 2 implementer
**Was raised against:** `leg2-packet-FROZEN-cd51e45` (DRAFT content)
**Now answered by:** `leg2-packet-FROZEN-76f4ab54` — `SPEC.md` STATUS: FROZEN,
`RATIFICATION_2026-11-21.md` (Q1–Q14), 54 golden vectors
**Status of Leg 2:** rebuilt to the ratified spec. **54/54 golden vectors pass.**

Nothing in this file is an open question any more. It is kept as the audit trail:
what was asked, what the owner ruled, and — the part that matters for the
two-leg gate — **which of my interim readings the ruling overturned**.

---

## 0. The honest tally: the ratification corrected 5 of my 14 readings

This is the whole argument for ratifying rather than guessing, so it belongs at
the top rather than buried. Of the 14 items, Leg 2's interim behaviour matched
the eventual ruling on 9 and was **wrong on 5**. None of the 5 could have been
caught by the old 43-vector corpus — every one of them lived in a corner no
vector exercised, which is exactly why they were questions and not decisions.

| | Q | Leg 2's interim reading | Ratified | |
| --- | --- | --- | --- | --- |
| ✗ | Q1 | genesis `prev_hash != 0` → `REJECT_CHAIN_BREAK` | `REJECT_BAD_GENESIS` | code |
| ✗ | Q3 | `Money(expires_at)` checked at genesis step 2 | `expires_at` is **not** money-gated | scope |
| ✗ | Q6 | `--observed-now` absent → skip the expiry gate, ACCEPT | `UNVERIFIABLE_USAGE` when ≥1 step | behaviour |
| ✗ | Q8 | ceiling `16777216` records | `1048576` records | value |
| ✗ | Q10a | anchor mismatch reports `fail_index` = last record | `fail_index` **null** | reporting |
| ✓ | Q2a | index 0 with `kind='S'` → `BAD_GENESIS` | same | |
| ✓ | Q2b | index ≥1 with `kind='G'` → `MALFORMED_RECORD` | same | |
| ✓ | Q2c | payload reserved checked before `seq_no`/`prev_hash`/seal | same (step 2 of 13) | |
| ✓ | Q4 | manifest `deal_id`/`escrow_id` empty → `EMPTY_ID`, after the hash check | same, now mandatory (step 5) | |
| ✓ | Q7 | `TOO_LARGE`, `UNREADABLE`, `USAGE`, `INTERNAL` | **all four names identical** | |
| ✓ | Q9 | line 1 = bare verdict name; `--json` for the harness | same, plus a fixed schema | |
| ✓ | Q11 | signed message = the 32-byte `record_seal`, no domain separation; strict profile (cofactorless, reject non-canonical `A`/`R`, reject `S ≥ L`) | **identical on every point** | |
| ✓ | Q12 | magic `FV2` isolated in one constant | ratified `FV2` | |
| ✓ | Q13 | all seven sub-items (1,2,3,5,6,7 and the `record_ts` baseline) | same | |

Two items were ruled *in the direction* I recommended but with **new verdict
codes** I had no way to invent: **Q5** (the pinned-key cross-check, which I had
argued for and implemented behind `--strict-pubkeys` reporting `BAD_GENESIS`) is
now mandatory with its own `REJECT_KEY_MISMATCH`; **Q14** (pinned-key validity,
which I had implemented behind `--require-valid-pubkeys` reporting
`BAD_GENESIS`) is now mandatory with its own `REJECT_BAD_KEY`.

**What this means for the differential harness.** The 5 corrections are 5 inputs
on which Leg 2 would have diverged from a correctly-built Leg 1 and the
disagreement would have looked like a bug in one of the legs. They were instead
resolved by the owner, in the spec, before the harness ran. There is now no
`SPEC_UNRATIFIED` class left: a Leg-1/Leg-2 mismatch on the frozen packet is a
genuine `DIVERGENCE_HALT`.

---

## 1. What Leg 2 now implements, question by question

Each row cites where in the source the ratified rule lives, so a reviewer can
check conformance without reading the whole crate.

### Q1 — genesis `prev_hash` must be 32 zero bytes
`REJECT_BAD_GENESIS`, not `CHAIN_BREAK`. `verify.rs::verify_genesis`, step 1.
Vector: `reject_genesis_bad_prevhash`. Test: `genesis_faults`.

### Q2 — kind in the wrong position, and the payload-reserved position
`kind != 'G'` at index 0 → `BAD_GENESIS`; `kind == 'G'` at index ≥1 →
`MALFORMED_RECORD`; step payload reserved `[88..96)` is **check 2 of 13**, ahead
of `seq_no`, `prev_hash` and the seal, so a non-zero reserved byte is
`MALFORMED_RECORD` *even when the seal was recomputed over it*.
`verify.rs::verify_genesis` step 1, `verify.rs::step` steps 1–2.
Vectors: `reject_genesis_kind_s`, `reject_step_kind_g`,
`reject_malformed_payload_reserved`. Tests: `genesis_faults`,
`reserved_bytes_must_be_zero` (both the recomputed-seal and stale-seal cases),
`envelope_codes_are_distinct_and_ordered`.

### Q3 — the `Money` predicate's scope
`Money` gates **only** `cap`, `seller_amount`, `gross_spent` and running
balances. `seq_no`, `record_ts`, `expires_at` and `observed_now` are plain `u64`.
A `record_ts` or `expires_at` at `2^63` or `2^64-1` is **not** a `NOT_MONEY`
error. `spec.rs::is_money`, applied at `verify_genesis` step 2 (cap only) and
`step` step 7 (the two step amounts only).
Test: `money_gate_applies_only_to_money_fields`, which pins `expires_at = 2^63`,
`record_ts = 2^64-1` and `observed_now = 2^63` as all legitimate.

### Q4 — manifest id emptiness
Mandatory, as genesis check 5, after the length+hash agreement.
Vector: `reject_manifest_empty_deal_id`. Test: `manifest_ids_must_be_non_empty`,
which also pins the ordering against the step-3 hash check.

### Q5 — the pinned-key cross-check → `REJECT_KEY_MISMATCH`
Mandatory, as genesis check 7: `--pubkeys` must equal `manifest.key_A,key_B`
byte-for-byte. Vector: `reject_key_mismatch`. Test: `key_mismatch_and_bad_key`.

### Q6 — `--observed-now` is required when the log holds a step
`UNVERIFIABLE_USAGE` (exit 3), decided **before** the fold; a genesis-only log
may omit it and ACCEPTs. `verify.rs::verify_log`, pre-fold gates.
Vector: `unverifiable_usage_missing_observed_now`.
Test: `observed_now_is_required_when_a_step_is_present`, which also pins that it
wins over a broken genesis (because it is decided pre-fold).

### Q7 — the six `UNVERIFIABLE_*` names
`EMPTY`, `NO_RECORD`, `TOO_LARGE`, `UNREADABLE`, `USAGE`, `INTERNAL`, all exit 3,
and a usage error does print a verdict line. `verdict.rs`.
Vectors: `unverifiable_empty_file`, `unverifiable_no_record`,
`unverifiable_too_large`, `unverifiable_usage_missing_observed_now`. The CLI
suite drives `UNREADABLE` and `USAGE` across 20 argument and I/O failures.

### Q8 — the record ceiling
`DEFAULT_MAX_RECORDS = 1048576`, `--max-records` overrides, decided before any
fold. `spec.rs::DEFAULT_MAX_RECORDS`. Vector: `unverifiable_too_large`.
Test: `oversized_logs_are_unverifiable_too_large`, which asserts the constant.

### Q9 — the canonical `--json` object
Line 1 of stdout is the bare verdict name; `--json` emits exactly the ten keys of
SPEC.md §9.6 with the ratified semantics: `torn_bytes` = `len mod 128` always,
`epoch` = records folded on ACCEPT* else 0, `tip` = "" unless ACCEPT*,
`final_balances` all-zero unless ACCEPT*, `notes` always "".
`main.rs::print_json`. The runner compares all ten fields on all 54 cases and
fails on any single field.

### Q10 — `--expect-tip`
Mismatch → `REJECT_CHAIN_BREAK` with `fail_index` **null**; evaluated only after
a fully successful fold; compared against the last **whole** record even when the
file would otherwise be `ACCEPT_TORN_TAIL`; case-insensitive, exactly 64 hex.
`verify.rs::verify_log`. Vectors: `accept_expect_tip_match`,
`reject_expect_tip_mismatch`, `reject_expect_tip_torn_mismatch`.
Test: `expect_tip_anchor`.

### Q11 — D-TAPE, now specified
`--tape` is a sidecar of 64-byte signatures, 2 per record in record order
(`sig_A` then `sig_B`), over the 32-byte `record_seal`, no domain separation.
Genesis and every step require **both** valid. Missing or invalid →
`REJECT_BAD_SIGNATURE`, as step 13 (so a structurally bad record reports its own
code first). Without `--tape`, signatures are skipped; the key checks run either
way. `verify.rs::check_tape_signatures`.
Vectors: `accept_cosigned_tape`, `reject_bad_signature_tape`.
Tests: `cosigned_tape_is_enforced_only_when_supplied` (24 bit flips across all
six signatures, a truncated tape, an empty tape, a rotated tape),
`tape_check_runs_after_the_fold_checks_for_a_record`, `tape_signature_predicate`.

**Cross-implementation evidence.** `accept_cosigned_tape` carries real signatures
minted by the packet's own vendored pure-Python Ed25519. Leg 2's hand-rolled
Ed25519 verifies them, and rejects the one corrupted signature in
`reject_bad_signature_tape`. Two independent Ed25519 implementations agreeing on
real signatures is a much stronger check than either one's self-tests.

### Q12 — magic
`FV2` ratified final. `spec.rs::MAGIC`.

### Q13 — the seven low-risk confirmations
All confirmed as implemented: no expiry check at genesis (13.1); a wrong-length
manifest witness is `BAD_GENESIS` (13.2); `gross_refunded` is structurally 0 and
its conjunct vacuous (13.3); `observed_now` is not money-bounded (13.4);
`--expect-tip` is case-insensitive (13.5); **`torn_bytes` = `len mod 128` always**
(13.6); first refusal wins (13.7).
13.6 is the one with teeth — it removes the reject-with-tail divergence I had
flagged. Test: `torn_bytes_is_reported_even_on_a_refusal`.

### Q14 — pinned-key validity → `REJECT_BAD_KEY`, and the `a.pub` defect
Mandatory, as genesis check 6: `manifest.key_A` and `key_B` must each decode as a
canonical (`y < p`), **non-small-order** Ed25519 point.
`verify.rs::verify_genesis` step 6, `ed25519::is_small_order`.

The two findings behind this question were both acted on:

1. **`a.pub` was not a curve point** in the old packet, which would have made
   every signed log `REJECT_BAD_SIGNATURE` regardless of its signatures. The new
   packet mints **real** keypairs — re-verified independently here:
   `a.pub = ec379cc5…bd10` and `b.pub = fdaf60ac…7884` are both valid,
   non-small-order points.
2. **A small-order pinned key makes the signature check vacuous.** The new
   `badA.pub` is `0100…00` — the identity encoding, i.e. precisely the universal
   forgery key from that finding — and `reject_bad_key` now pins that Leg 2
   refuses it. The rewrite attack it enabled is closed twice over: by the
   validity check (Q14) and by the mandatory pin cross-check (Q5).

Tests: `key_mismatch_and_bad_key` (small-order key, a non-point key, `key_B` as
well as `key_A`, and the step-6-before-step-7 ordering),
`identity_public_key_admits_a_universal_forgery`,
`order_8_public_key_admits_forgery_for_a_fraction_of_messages`,
`small_order_detection_works`.

---

## 2. One residual note, not a question

SPEC.md §9.2 fixes the tape's layout and says a **missing** signature is
`REJECT_BAD_SIGNATURE`, which Leg 2 implements: for record `i` it requires
`tape[i*128 .. i*128+128]`, and refuses at index `i` when the tape is shorter.
The spec does not say what a tape **longer** than `128 × records` means. Leg 2
ignores trailing bytes beyond what the records need. If the owner would rather
that be a usage error, it is a two-line change — but no vector drives it and the
behaviour is noted here rather than guessed at silently.
