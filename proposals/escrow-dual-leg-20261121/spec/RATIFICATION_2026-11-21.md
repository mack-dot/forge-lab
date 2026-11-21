# Spec ratification — escrow Leg-2 packet, 2026-11-21 (resolves SPEC_QUESTIONS.md Q1-Q14)
Owner spec-clearing decisions. Fold ALL into SPEC.md + gen_vectors.py, regenerate vectors, re-freeze (new hash).

Q1  Genesis with prev_hash != 32 zero bytes -> REJECT_BAD_GENESIS (genesis-structural fault; §3 "index-0 not a
    valid genesis -> BAD_GENESIS" governs). [Overrides Leg2's provisional CHAIN_BREAK.] Ship a vector.
Q2a index 0 with kind='S' -> REJECT_BAD_GENESIS. 2b index>=1 with kind='G' -> REJECT_MALFORMED_RECORD.
    2c the payload reserved[88..96) is checked at the "reserved" position, BEFORE seq_no/prev_hash/seal; a non-zero
    payload reserved -> REJECT_MALFORMED_RECORD even if the seal is (re)computed over it. Ship a vector (non-zero
    payload reserved + a stale seal) that distinguishes this from BAD_SEAL.
Q3  The Money predicate (reject >= 2^63 as REJECT_AMOUNT_NOT_MONEY) applies ONLY to money fields: cap,
    seller_amount, gross_spent, and running balances. seq_no, record_ts, expires_at, observed_now are plain u64
    and are NOT Money-gated (validated by their own rules). REWORD §1 to delete the broad "every seq_no/record_ts
    ... any wire value >= 2^63 refused" language that created the tension. Reason: only money is summed
    (conservation), so only money needs the 2^63 overflow bound.
Q4  Manifest deal_id and escrow_id all-zero -> REJECT_EMPTY_ID, checked AFTER the §3.2 manifest-hash-agreement
    step. step_id all-zero -> REJECT_EMPTY_ID (existing). Add the genesis id-check to §3.2's numbered list with its
    position stated.
Q5  --pubkeys cross-check is MANDATORY (not a flag): the pinned a.pub,b.pub MUST equal the manifest key_A,key_B
    byte-for-byte; mismatch -> REJECT_KEY_MISMATCH (exit 1), checked in §3.2 before signature use. This also closes
    the Q14 manifest key-rewrite attack (attacker can't pin identity keys without also owning the out-of-band pins).
Q6  observed_now is REQUIRED when the log contains >=1 step record; if absent -> UNVERIFIABLE_USAGE (exit 3). A
    genesis-only log may omit it and ACCEPTs. (Fail-closed for a money verifier; update README's "Optional".)
Q7  The six UNVERIFIABLE_* names (align to the two the vectors already use): UNVERIFIABLE_EMPTY (0 bytes),
    UNVERIFIABLE_NO_RECORD (<128 bytes, no whole record), UNVERIFIABLE_TOO_LARGE, UNVERIFIABLE_UNREADABLE,
    UNVERIFIABLE_USAGE, UNVERIFIABLE_INTERNAL. All exit 3. A usage error DOES print a verdict line. torn_bytes is
    reported on every path (see Q13.6).
Q8  DEFAULT_MAX_RECORDS = 1048576 (128 MiB of whole records), overridable --max-records N; a file over the ceiling
    -> UNVERIFIABLE_TOO_LARGE decided before any fold. State the number in §8.
Q9  Canonical differential interface = --json (one object): {"verdict":str,"exit_code":int,"records":int,
    "torn_bytes":int,"fail_index":int|null,"final_balances":{"gross_spent":int,"seller_payout":int,
    "buyer_refund":int},"tip":hexstr,"epoch":int,"expiry_gate_evaluated":bool,"notes":str}. Integers are decimal
    JSON numbers (no float/exponent). stdout line 1 = the bare verdict NAME and nothing else; detail on following
    key=value lines. The harness compares the --json object (and may compare only the first whitespace token of
    line 1). Every case in vectors.json carries its expected --json.
Q10 --expect-tip: (a) a mismatch folds under REJECT_CHAIN_BREAK (no separate code now); (b) the anchor compares
    against the last WHOLE record's SHA-256 even when the file is otherwise ACCEPT_TORN_TAIL (mismatch REJECTs);
    (c) the anchor is evaluated ONLY after a fully successful fold; a fold refusal keeps its own code/index and the
    anchor is never consulted.
Q11 D-TAPE (define it): --tape <file> = a sidecar of 64-byte Ed25519 signatures, 2 per record in record order
    [sig_A(rec0), sig_B(rec0), sig_A(rec1), sig_B(rec1), ...]. SIGNED MESSAGE = the 32-byte record_seal (bytes
    [96..128]) of that record, NO domain separation (matches §5.2 step 9). Genesis (rec0) requires both sig_A and
    sig_B valid; each step requires sig_A (proposer) + sig_B (countersigner) valid. Any missing/invalid ->
    REJECT_BAD_SIGNATURE (exit 1). WITHOUT --tape: signatures are skipped (log-only verdict). Ed25519 PROFILE =
    STRICT, ratified: cofactorless verification ([S]B = R + [k]A), reject non-canonical A/R encodings, reject
    S >= L, reject a small-order A. Leg 1 MUST use this exact profile.
Q12 magic = FV2 (0x46 0x56 0x32), RATIFIED FINAL (O-1 closed).
Q13 Confirmations (state each as a rule): (1) no expiry check at genesis — a genesis-only log ACCEPTs regardless
    of observed_now; (2) a manifest witness of the wrong length -> REJECT_BAD_GENESIS (cannot hash to
    manifest_sha256); (3) gross_refunded is structurally always 0 in this CLI (no refund record type in Domain 2);
    the gross_refunded<=gross_spent conjunct is kept but vacuous; (4) observed_now is full u64, not Money-bounded;
    (5) --expect-tip is case-insensitive, exactly 64 hex chars; (6) RATIFIED: torn_bytes = (file length mod 128)
    ALWAYS, computed independently of the verdict and of where the fold stopped (removes the Leg1/Leg2 divergence
    risk on a reject-with-tail); (7) first refusal wins: report the refusal of the LOWEST-indexed failing record
    and stop (state as an explicit rule).
Q14 Fixed by: minting REAL Ed25519 keypairs for a.pub/b.pub + regenerating all vectors (already instructed); the
    mandatory Q5 cross-check; the strict Q11 profile. ALSO add a genesis key-validity check: key_A and key_B must
    decode as canonical, non-small-order Ed25519 points -> else REJECT_BAD_KEY (exit 1), checked in §3.2. Ship
    vectors: reject_key_mismatch, reject_bad_key (small-order key_A), a valid co-signed ACCEPT with --tape (real
    sigs), and reject_bad_signature with --tape (one sig corrupted); retire the reject_bad_signature_HARNESS placeholder.
