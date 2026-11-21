# FREEZE.md — Leg 2 Implementer Packet, frozen (re-release 5)

**FROZEN 2026-11-21.** Owner spec-clearing `RATIFICATION_2026-11-21.md` (Q1-Q14) plus
real Ed25519 keys, the strict signature profile, two divergence-corner tightenings
(small-order `R`; missing-arg `UNVERIFIABLE_USAGE`), a post-fuzz genesis reject-code
clarification (Option B) + 3 coverage vectors, and the exact genesis check-order
precedence (kind-gate before `seq_no`) + 1 vector are folded in. This is the
clean-room spec Leg 2 (Gharib's independent Rust verifier) is built from.

## spec_packet_hash (re-release 5)

```
127b515567e2172846473d66c797d803289c89c4fdf3547f53cc343d4ffb20e7
```

Retired: `cd51e45235b566016d27ef87079389d40fa5a54c23856801b8683a66758206f5`
(re-release 1, broken placeholder keys);
`76f4ab54ee9d119a23ab00a42fcdc24b5087a58800aa8b3cb85ea21ca5e41fc6` (re-release 2);
`51d1d035a3943e7bd9dcef23540e207aa968a2ff837241eede9c94a9ab7e8106` (re-release 3);
`fb1c7d83e7e178497dd9320db4e840d35703b3df950cc0b61e279509f83d928f` (re-release 4).

The previously published `leg2_frozen.json` (commit `862ee20a`, packet `51d1d035`)
stands as the historical pre-registration of Leg 2 v1 and is NOT invalidated; rr4 is a
documented post-fuzz clarification. Under Option B, Leg 1 (uncommitted) is the leg
updated to conform; the frozen/published Leg 2 is unchanged.

- Algorithm (unchanged): for each file in the freeze set, compute its SHA-256 hex.
  Build one line per file as `"<relative-path>  <sha256hex>"` (two spaces). Sort the
  lines by path with `LC_ALL=C`. Join with `\n`, add a trailing `\n`. `spec_packet_hash`
  = SHA-256 of that text.
- Freeze set = 139 files: `README.md`, `SPEC.md`, `ACCEPTANCE.md`, `gen_vectors.py`,
  and every file under `golden_vectors/` (`vectors.json`, 64 `*.log.bin`, 64
  `*.manifest.bin`, 3 `*.tape.bin`, `a.pub`, `b.pub`, `badA.pub`).
- The freeze set is a WHITELIST (the four named root files + all of `golden_vectors/`),
  so any other file in the packet dir is excluded by construction: `FREEZE.md`,
  `freeze_leg2.sh`, `GPT_SANDBOX_TASK.md` (builder brief), `RATIFICATION_2026-11-21.md`
  and `FINDINGS_FUZZ_20261121.md` (owner/fuzz input docs), and any `__pycache__`.
  `freeze_leg2.sh` recomputes this exact whitelist (`spec_packet_tree_hash`), so it can
  verify the hash independently regardless of stray docs.

## What changed in re-release 5 (genesis check-order precedence)

- **SPEC §3.2 step 1 now pins the EXACT genesis check order** (fuzz found the
  `seq_no`-vs-kind-gate precedence under-specified): (1) magic/version/header-reserved
  -> `REJECT_MALFORMED_RECORD`; (2) `kind != 'G'` -> `REJECT_BAD_GENESIS` (kind-gate,
  BEFORE `seq_no`); (3) `seq_no != 0` -> `REJECT_SEQ_MISMATCH`; (4) non-zero `prev_hash`
  -> `REJECT_BAD_GENESIS`; (5) `domain != 2` -> `REJECT_BAD_DOMAIN`; (6) bad seal ->
  `REJECT_BAD_SEAL`.
- **1 new vector (total 64):** `reject_genesis_step_at_index0` — a well-formed step
  record (`kind='S'`, `seq_no=1`, valid seal) as the sole record at index 0 ->
  `REJECT_BAD_GENESIS` (the kind-gate fires before `seq_no`, so NOT `SEQ_MISMATCH`).
- The other 63 vectors are byte-unchanged (the reorder changes no existing verdict:
  no prior vector had both `kind != 'G'` and `seq_no != 0`).

## What changed in re-release 4 (post-fuzz; a 1991-case cross-leg differential)

- **Genesis reject-code clarification (Option B, §3.2 step 1).** The §2 wire-envelope
  checks run FIRST on EVERY record INCLUDING genesis, before the §3 genesis checks. At
  index 0: magic/version/header-reserved -> `REJECT_MALFORMED_RECORD`; `seq_no != 0` ->
  `REJECT_SEQ_MISMATCH`; `kind != 'G'` / non-zero `prev_hash` -> `REJECT_BAD_GENESIS`
  (Q1/Q2a stand); `domain != 2` -> `REJECT_BAD_DOMAIN`. `MALFORMED_RECORD` and
  `SEQ_MISMATCH` DO apply at index 0.
- **7 new golden vectors (total 63):** `reject_genesis_bad_magic` / `_bad_version` /
  `_bad_reserved` -> `REJECT_MALFORMED_RECORD`; `reject_genesis_bad_seqno` ->
  `REJECT_SEQ_MISMATCH`; `reject_genesis_bad_domain` -> `REJECT_BAD_DOMAIN`;
  `accept_records_eq_max` (records == `--max-records`, inclusive ceiling) -> `ACCEPT`;
  `reject_record_ts_decreasing` -> `REJECT_SEQ_MISMATCH`. Each genesis case isolates
  one field with a recomputed valid seal.

## What changed in re-release 3 (two divergence-corner tightenings)

- **Strict profile rejects a small-order `R` (Q11, §9.3)** -> `REJECT_BAD_SIGNATURE`
  (same cofactor test as `A`, but `R` is part of the signature). Full predicate stated
  with an explicit warning: a default/cofactored Ed25519 library (OpenSSL, libsodium,
  Go `crypto/ed25519`, Python `cryptography`) WILL diverge on torsion-added points and
  must NOT be on the verification path. New vector `reject_bad_signature_small_order_R`.
- **Missing `--manifest` / `--pubkeys` (or an unreadable/non-32-byte pubkey) ->
  `UNVERIFIABLE_USAGE` (exit 3), before any record is read (§9.1).** New vector
  `unverifiable_usage_missing_pubkeys`.

## What changed in re-release 2 (security fixes + Q1-Q14)

- **Real Ed25519 keys.** `gen_vectors.py` vendors a pure-Python RFC 8032 Ed25519
  (hashlib SHA-512 only), self-tests it against RFC 8032 vectors, then mints real
  keypairs. `a.pub` / `b.pub` are real 32-byte public keys (the broken placeholder
  `a.pub` is gone). `badA.pub` is a small-order point for `reject_bad_key`.
- **Mandatory key checks (Q5, Q14).** `--pubkeys` MUST equal the manifest keys
  (`REJECT_KEY_MISMATCH`); keys must be canonical, non-small-order points
  (`REJECT_BAD_KEY`). Both run on every invocation.
- **`--tape` (Q11).** Optional sidecar, 2 × 64-byte sigs per record, signed over the
  32-byte `record_seal` `[96..128)`. Strict profile: cofactorless `[S]B = R + [k]A`,
  reject non-canonical `A`/`R`, reject `S >= L`, reject small-order `A`.
- **`--json` canonical substrate (Q9).** Each vector carries its `expected_json`.
- **Money scope (Q3):** `Money` gate only on `cap` / `seller_amount` / `gross_spent`;
  `seq_no` / `record_ts` / `expires_at` / `observed_now` are plain `u64`.
- **Six UNVERIFIABLE names (Q7):** `EMPTY`, `NO_RECORD`, `TOO_LARGE`, `UNREADABLE`,
  `USAGE`, `INTERNAL` (all exit 3). `observed_now` REQUIRED with any step (Q6).
- **`DEFAULT_MAX_RECORDS = 1048576` (Q8); `torn_bytes = len mod 128` always (Q13.6);
  first-refusal-wins (Q13.7); magic `FV2` RATIFIED FINAL (Q12).**

## Frozen widths and encodings (summary; full text in SPEC.md §8, interfaces §9)

- Ids = RAW fixed bytes, bytewise: `deal_id` 32 B, `escrow_id` 32 B, `step_id` 16 B;
  all-zero -> `REJECT_EMPTY_ID`.
- Money (`cap`, `seller_amount`, `gross_spent`): `u64` LE cents, `[0, 2^63-1]`.
- Time (`expires_at`, `record_ts`): `u64` LE Unix seconds. Expiry: `REJECT_EXPIRED`
  iff `observed_now >= expires_at`.
- Reserved bytes (header `[6..8)`, step payload `[88..96)`) MUST be zero; payload
  reserved is checked BEFORE the seal (Q2c).
- GenesisManifest = 176 B: `deal_id[0..32]` `key_A[32..64]` `key_B[64..96]`
  `spec_hash[96..128]` `escrow_id[128..160]` `cap[160..168]` `expires_at[168..176]`.
  Verifier checks length 176, `sha256(manifest) == payload.manifest_sha256`, and
  `payload.cap/expires_at == manifest.cap/expires_at`.
- 48-byte genesis payload: `cap[0..8]` `expires_at[8..16]` `manifest_sha256[16..48]`.
- 48-byte step payload: `step_id[0..16]` `seller_amount[16..24]` `gross_spent[24..32]`
  `record_ts[32..40]` `reserved[40..48]`.

## Golden vectors

64 cases in `golden_vectors/vectors.json`, each with its `expected_json`. Regenerate
with `python3 gen_vectors.py` (stdlib only; self-tests Ed25519 incl. small-order A/R
first; exit 0). Record sizes verified (384 = 3×128; torn-127 = 383; tape = 384).
`end_to_end=false`.

## Ordering rule (load-bearing)

This packet and its `spec_packet_hash` are committed and pushed **PUBLICLY BEFORE**
Escrow Leg 1 is ever pushed. Leg 2 is frozen against this hash before any differential
testing against Leg 1. See `freeze_leg2.sh`.
