# SPEC.md — Forge V2 Escrow (Domain 2), self-contained

**STATUS: FROZEN (owner-ratified 2026-11-21, `RATIFICATION_2026-11-21.md`, Q1-Q14).**
`end_to_end=false`. All byte widths, encodings, verdicts and interfaces below are
FINAL. See §8 for the one-page summary and §9 for the CLI / `--json` / `--tape`
interfaces. Magic is FINAL (`FV2`, Q12); there are no owner-pending items left.

This is the complete escrow semantics. Build Leg 2 from this file alone. It carries
no Dafny and no Leg-1 content.

Terminology is kept consistent with the upstream docs:
`cap` = `buyer_cap`, `expires_at` = `lease_expiry`. This spec uses `cap` and
`expires_at`.

---

## 1. Number & money law (zero ambiguity)

**The `Money` predicate applies ONLY to money fields: `cap`, `seller_amount`,
`gross_spent`, and running balances (Q3).** Each is an unsigned 64-bit field read as
an integer in `0 .. 2^64 - 1` (little-endian). A money value is valid exactly when:

```
Money(v)  <==>  0 <= v <= 2^63 - 1        (2^63 - 1 = 9223372036854775807)
```

- A MONEY field with `v >= 2^63` is REFUSED as `REJECT_AMOUNT_NOT_MONEY`. It is
  **never wrapped, never rounded, never clamped**. The format is unsigned; no negative
  value exists and none is invented.
- Read the full `0 .. 2^64 - 1` integer and compare with the bound (and with the
  remaining cap) BEFORE any subtraction. No wrap can occur in money arithmetic.
- **`seq_no`, `record_ts`, `expires_at`, and `observed_now` are plain `u64` and are
  NOT `Money`-gated (Q3).** They are validated by their own rules: `seq_no == index`
  (`REJECT_SEQ_MISMATCH`); `record_ts` non-decreasing; expiry by comparison
  (`observed_now` vs `expires_at`). Reason: only money is summed (conservation), so
  only money needs the `2^63` overflow bound. A large `expires_at` or `record_ts` is
  not a `NOT_MONEY` error.
- **The ONLY permitted modular wraparound** is 32-bit unsigned word addition mod
  `2^32` inside the SHA-256 compression rounds. Nowhere else. A leg that wraps
  anything outside SHA-256 compression is wrong.

Money is cents. Never float. For the demo: $5.00 = `500`, $1.00 = `100`.

**Word-boundary values that MUST be exercised** (golden vectors ship them; both legs
must agree):
`0, 1, 2^15-1, 2^15, 2^16-1, 2^16, 2^31-1, 2^31, 2^32-1, 2^32, 2^53-1, 2^53, 2^63-1,
2^63, 2^64-1`. The last accepted money value is `2^63-1`; the first refused is `2^63`.
The `2^53` pair catches any implementation that drifts into floating point (a 64-bit
float loses integer precision above `2^53`). Keep all money arithmetic in 64-bit (or
wider) integers.

---

## 2. The 128-byte envelope, byte-exact

All multi-byte integers are **little-endian**. Offsets are half-open byte ranges from
the start of the 128-byte record.

| Field | Bytes | Width | Content |
| --- | --- | --- | --- |
| magic | [0..3) | 3 B | `FV2` (0x46 0x56 0x32), RATIFIED FINAL (Q12). Any other value -> `REJECT_MALFORMED_RECORD` |
| version | [3] | 1 B | `u8 = 2`. Any other -> `REJECT_MALFORMED_RECORD` |
| domain_id | [4] | 1 B | `u8 = 2` (Escrow). Any other -> `REJECT_BAD_DOMAIN` |
| kind | [5] | 1 B | `u8`: `0x47` `'G'` = genesis, `0x53` `'S'` = step. Any other -> `REJECT_MALFORMED_RECORD` |
| reserved | [6..8) | 2 B | MUST be zero (FROZEN). Non-zero -> `REJECT_MALFORMED_RECORD` |
| seq_no | [8..16) | 8 B | `u64` LE, dense and gap-free: record at index `i` has `seq_no == i`. Genesis = 0 |
| prev_hash | [16..48) | 32 B | SHA-256 of the whole previous 128-byte record. Genesis: 32 zero bytes |
| payload | [48..96) | 48 B | Domain-2 payload (§3 genesis, §4 step) |
| record_seal | [96..128) | 32 B | SHA-256 of bytes `[0..96)` of THIS record |

**Record totals 128 bytes.** Header `[0..16)` is magic(3)+version(1)+domain(1)+kind(1)
+reserved(2)+seq_no(8).

**Two distinct bonds:**
- **record_seal** binds ONE record: `SHA-256(record[0..96))`. A single flipped bit in
  the record fails its seal -> `REJECT_BAD_SEAL`.
- **prev_hash** binds record `i` to record `i-1`: it must equal `SHA-256` of the whole
  previous 128-byte record. Mismatch -> `REJECT_CHAIN_BREAK`. Genesis carries 32 zero
  bytes.

**seq_no monotonicity.** The fold checks `seq_no(record i) == i`. A gap, repeat, swap,
or removed record -> `REJECT_SEQ_MISMATCH`.

**Tail semantics (ratified, carried from V1):**
- A trailing partial of **1 to 127 bytes** is a torn tail: `ACCEPT_TORN_TAIL` (exit 4).
  It is NEVER read as a record. Report `torn_bytes` = its length.
- A WHOLE 128-byte final record that fails its seal or any other check is **REJECT**
  (exit 1), NOT torn. A whole record that fails its seal cannot be told from
  corruption or modification, so calling it torn would be a guess. The verifier never
  repairs the file it reads.

**Ids (FROZEN).** Every id field (`deal_id` 32 B, `escrow_id` 32 B, `step_id` 16 B)
holds **RAW FIXED bytes** of its full width — NOT hex, NOT ASCII, NOT a charset-limited
spelling. Ids are compared **bytewise** over the whole field: no charset rule, no
case folding, no whitespace trimming, no NUL-padding rule. Two ids are equal exactly
when all their bytes are equal (this is the `DUPLICATE_ID` key). An id whose field is
all-zero bytes (`0x00` × width) is the empty id -> `REJECT_EMPTY_ID`. There is no
"malformed id" charset check: any non-all-zero byte pattern is a valid id.

**The seal is full SHA-256**, not CRC/FNV. SHA-256 here is **not keyed**: anyone who
can write the file can rewrite a record and recompute every later `prev_hash` and
`record_seal`, and the result is accepted if it is a valid history. ACCEPT means
"these bytes are a valid history", NOT "these bytes are what the daemon wrote".
Authenticity needs the Ed25519 tip signature or an external anchor (`--expect-tip`).

---

## 3. Genesis record (kind `G`, seq_no 0) — payload + manifest witness

The genesis payload is 48 bytes (D-GEN RESOLVED, owner 2026-11-21). Offsets below are
within the record.

| Payload field | Bytes | Width | Content |
| --- | --- | --- | --- |
| cap | [48..56) | 8 B | `u64` LE, MINOR UNITS (cents). The most the buyer can be charged across the deal. `Money` bound `[0, 2^63-1]`. IN CLEAR |
| expires_at | [56..64) | 8 B | `u64` LE, Unix epoch SECONDS. Deal expiry. IN CLEAR for the EXPIRED check. Plain `u64`, NOT `Money`-gated (Q3) |
| manifest_sha256 | [64..96) | 32 B | full SHA-256 of the canonical 176-byte GenesisManifest (§3.1) |

A record at index 0 that is not a valid genesis -> `REJECT_BAD_GENESIS`.

### 3.1 The GenesisManifest witness (REQUIRED input, `--manifest`)

The 48-byte payload commits the big fields by a 256-bit hash only. To verify a
genesis, Leg 2 MUST be given the full GenesisManifest as a separate witness, hash it,
and check the hash equals `manifest_sha256`. It MUST also check that the in-clear
`cap` and `expires_at` match the manifest's values.

**Canonical GenesisManifest layout — FROZEN, 176 bytes:**

| Field | Bytes | Width | Content |
| --- | --- | --- | --- |
| deal_id | [0..32) | 32 B | the escrow deal id, RAW fixed bytes (bytewise) |
| key_A | [32..64) | 32 B | Ed25519 public key of party A (buyer), FULL |
| key_B | [64..96) | 32 B | Ed25519 public key of party B (seller), FULL |
| spec_hash | [96..128) | 32 B | SHA-256 of the ratified acceptance checker / job spec |
| escrow_id | [128..160) | 32 B | the rail's escrow id, RAW fixed bytes (bytewise) |
| cap | [160..168) | 8 B | `u64` LE cents (same value as the in-clear payload `cap`) |
| expires_at | [168..176) | 8 B | `u64` LE Unix seconds (same value as the in-clear payload `expires_at`) |

`32+32+32+32+32+8+8 = 176`.

`cap` and `expires_at` are carried in BOTH the manifest AND in-clear in the 48-byte
genesis payload. The full Ed25519 keys live in the manifest (a fingerprint cannot
verify a signature); the chain commits to them only by the 256-bit `manifest_sha256`.

### 3.2 Genesis verification steps (STRICT ORDER; first failure wins)

For the record at index 0, in this exact order:

1. **Envelope + genesis structure (rr5, owner-ratified EXACT precedence).** The §2
   wire-envelope checks run on EVERY record INCLUDING the genesis. At index 0, apply
   these checks in THIS EXACT ORDER and report the first that fails:
   1. magic != `FV2`, or `version != 2`, or non-zero header reserved `[6..8)` ->
      `REJECT_MALFORMED_RECORD`.
   2. `kind != 'G'` -> `REJECT_BAD_GENESIS` (the genesis kind-gate, BEFORE `seq_no`).
   3. `seq_no != 0` (the `seq_no == index` rule) -> `REJECT_SEQ_MISMATCH`.
   4. non-zero `prev_hash` -> `REJECT_BAD_GENESIS` (Q1).
   5. `domain_id != 2` -> `REJECT_BAD_DOMAIN`.
   6. record_seal invalid -> `REJECT_BAD_SEAL`.
   `REJECT_MALFORMED_RECORD` and `REJECT_SEQ_MISMATCH` DO apply at index 0. The
   **kind-gate PRECEDES the `seq_no` check** (rr5): a STEP record (`kind == 'S'`,
   non-zero `seq_no`, otherwise well-formed) placed at index 0 yields
   `REJECT_BAD_GENESIS`, NOT `REJECT_SEQ_MISMATCH`. The Q1 (`prev_hash`) and Q2a
   (`kind`) ratifications stand.
2. `Money(cap)` -> else `REJECT_AMOUNT_NOT_MONEY`. (`expires_at` is NOT money-gated,
   Q3.)
3. **Manifest length + hash agreement.** The manifest witness MUST be exactly 176
   bytes and `SHA-256(manifest) == manifest_sha256` -> else `REJECT_BAD_GENESIS`. A
   wrong-length witness cannot hash to `manifest_sha256` (Q13.2).
4. `manifest.cap == payload.cap` and `manifest.expires_at == payload.expires_at`
   -> else `REJECT_BAD_GENESIS`.
5. **Manifest id emptiness (Q4), checked AFTER step 3.** `manifest.deal_id` and
   `manifest.escrow_id` are each non-all-zero -> else `REJECT_EMPTY_ID`.
6. **Key validity (Q14).** `manifest.key_A` and `manifest.key_B` each decode as a
   canonical, NON-small-order Ed25519 point -> else `REJECT_BAD_KEY`. (Canonical =
   `y < p`; non-small-order = `cofactor * A != identity`; see §9.3.)
7. **Pinned-key cross-check (Q5), mandatory.** The pinned `--pubkeys` (`a.pub,b.pub`)
   MUST equal `manifest.key_A,key_B` byte-for-byte -> else `REJECT_KEY_MISMATCH`.
   This closes the manifest key-rewrite attack (Q14): an attacker cannot pin chosen
   keys without also owning the out-of-band pins.

`SPEC_MISMATCH` (`manifest.spec_hash` vs an externally-ratified `spec_hash`) is a
genesis-level check wired only when that input is supplied; the CLI here does not pass
it, and no golden vector drives it. There is **no expiry check at genesis** (Q13.1): a
genesis-only log ACCEPTs regardless of `observed_now`.

The genesis establishes the folded state's pinned anchors: `cap`, `expires_at`,
`spec_hash`, `key_A`, `key_B`, `deal_id`, `escrow_id`.

---

## 4. Step record (kind `S`, seq_no >= 1) — payload

| Payload field | Bytes | Width | Content |
| --- | --- | --- | --- |
| step_id | [48..64) | 16 B | the part id, RAW fixed 16 bytes (bytewise). Unique within the deal. The `DUPLICATE_ID` key |
| seller_amount | [64..72) | 8 B | `u64` LE, MINOR UNITS (cents) released to the seller for THIS step. `Money` bound |
| gross_spent | [72..80) | 8 B | `u64` LE cents: running cumulative gross AFTER this step. `Money` bound |
| record_ts | [80..88) | 8 B | `u64` LE, Unix epoch SECONDS (same clock as `expires_at`). Plain `u64`, NOT `Money`-gated (Q3). Non-decreasing across steps |
| reserved | [88..96) | 8 B | MUST be zero (FROZEN). Non-zero -> `REJECT_MALFORMED_RECORD` |

`16+8+8+8+8 = 48`. The `cap`, `expires_at`, keys, and `spec_hash` are NOT in the step;
they are pinned once at genesis and checked from the folded state. That is what frees
the step to 48 bytes.

---

## 5. The decidable Step function and every refusal code

```
Step(state, record, observed_now) -> Some(state') | refuse(code)
```

folded from the genesis over the log. The verifier ACCEPTS a log only when the genesis
is valid and every record is `Some` at its pre-state. `observed_now` is an explicit
input; the verifier NEVER calls a wall clock, so the same bytes + the same
`observed_now` always give the same verdict.

**First refusal wins (Q13.7).** Fold records in index order and report the refusal of
the LOWEST-indexed failing record, then stop. Within one record, apply the §5.2 checks
in the listed order and report the first that fails.

**`observed_now` is REQUIRED when the log contains >= 1 step record (Q6).** If a step
is present and `--observed-now` is absent -> `UNVERIFIABLE_USAGE` (exit 3), decided
before the fold. A genesis-only log may omit it and ACCEPTs (fail-closed for a money
verifier).

### 5.1 The folded state

```
EscrowState {
  deal_id, cap, expires_at,        // pinned from genesis (payload + manifest)
  spec_hash, key_A, key_B, escrow_id,
  gross_spent,                     // running cumulative gross; starts 0
  gross_refunded,                  // starts 0 (refund only at settlement)
  settled_steps,                   // set of step_id seen so far; starts empty
  epoch,                           // == seq_no == count of records so far
  tip_hash,                        // SHA-256 of the last whole record
}
```

### 5.2 Per-step checks, in order, each with its named refusal code

For a step record at index `i` (i >= 1), with pre-state `state`:

1. **Structural.** magic/version/domain; `kind == 'S'` (a `kind == 'G'` at index
   `i >= 1` -> `REJECT_MALFORMED_RECORD`, Q2b); header reserved `[6..8)` zero.
2. **Payload reserved, BEFORE seq_no/prev_hash/seal (Q2c).** Step payload reserved
   `[88..96)` MUST be zero -> else `REJECT_MALFORMED_RECORD`, EVEN IF the seal is
   (re)computed over the non-zero reserved. This is checked at the reserved position,
   ahead of the seal, so a non-zero-reserved record is MALFORMED, never BAD_SEAL.
3. `seq_no == i` -> else `REJECT_SEQ_MISMATCH`.
4. `prev_hash == tip_hash` -> else `REJECT_CHAIN_BREAK`.
5. Seal: `record_seal == SHA-256(record[0..96))` -> else `REJECT_BAD_SEAL`.
6. Id check (RAW 16-byte `step_id`, bytewise): non-all-zero -> else `REJECT_EMPTY_ID`.
   There is no charset "malformed id" check (ids are raw bytes).
7. `Money(seller_amount)` and `Money(gross_spent)` -> else `REJECT_AMOUNT_NOT_MONEY`.
   (Only these two step fields are money-gated; `record_ts` is plain `u64`, Q3.)
8. `record_ts >= state.record_ts_prev` (non-decreasing; genesis baseline 0)
   -> else `REJECT_SEQ_MISMATCH`.
9. **Money chain / conservation:** `gross_spent == state.gross_spent + seller_amount`
   -> else `REJECT_CHAIN_BREAK` (the money-fold failure is folded under `CHAIN_BREAK`
   — both mean "this record does not continue the previous state").
10. **Cap (strict monotonic gross):** `gross_spent <= cap`, and
    `gross_refunded <= gross_spent` -> else `REJECT_OVER_CAP`. `gross_refunded` is
    structurally always 0 in this CLI (no refund record type in Domain 2); the
    conjunct is kept but vacuous (Q13.3). Never silent netting.
11. **At most once:** `step_id not in settled_steps` -> else `REJECT_DUPLICATE_ID`.
12. **Expiry (boundary):** valid strictly while `observed_now < expires_at`;
    `REJECT_EXPIRED` iff `observed_now >= expires_at` (equality is EXPIRED). Keys on
    `observed_now` (required, step present), not on `record_ts`. No wall clock.
13. **Signature (only WITH `--tape`, §9.2).** Each step requires a valid `sig_A`
    (proposer) AND `sig_B` (countersigner) over the 32-byte `record_seal`; missing or
    invalid -> `REJECT_BAD_SIGNATURE`. WITHOUT `--tape`, this check is skipped.

Effect of a `Some` step: `gross_spent := gross_spent + seller_amount`;
`settled_steps := settled_steps + {step_id}`; `epoch := epoch + 1`;
`record_ts_prev := record_ts`; `tip_hash := SHA-256(this record)`.

### 5.3 The complete refusal-code list

Domain-2 codes (exit 1):
`REJECT_DUPLICATE_ID`, `REJECT_CHAIN_BREAK`, `REJECT_OVER_CAP`, `REJECT_EXPIRED`,
`REJECT_BAD_SIGNATURE`, `REJECT_KEY_MISMATCH`, `REJECT_BAD_KEY`, `REJECT_SPEC_MISMATCH`.

Envelope / structural codes (exit 1):
`REJECT_AMOUNT_NOT_MONEY`, `REJECT_MALFORMED_RECORD`, `REJECT_BAD_SEAL`,
`REJECT_SEQ_MISMATCH`, `REJECT_BAD_GENESIS`, `REJECT_BAD_DOMAIN`, `REJECT_EMPTY_ID`.

UNVERIFIABLE codes — the SIX names (Q7), all exit 3; a usage error DOES print a
verdict line:
`UNVERIFIABLE_EMPTY` (0 bytes), `UNVERIFIABLE_NO_RECORD` (1..127 bytes, no whole
record), `UNVERIFIABLE_TOO_LARGE` (more whole records than the ceiling, §9.4),
`UNVERIFIABLE_UNREADABLE` (log/manifest/pubkeys unreadable), `UNVERIFIABLE_USAGE`
(bad/missing args, incl. a step present with no `--observed-now`, or a malformed
`--expect-tip`), `UNVERIFIABLE_INTERNAL` (verifier internal error).

Accept (exit 0 / 4): `ACCEPT` (0), `ACCEPT_TORN_TAIL` (4).

The short forms in the demo doc (`DUPLICATE_ID`, `CHAIN_BREAK`, `OVER_CAP`, `EXPIRED`,
`BAD_SIGNATURE`, `SPEC_MISMATCH`) are aliases of the `REJECT_*` names. Leg 2 prints the
full name. The exit code for every `REJECT_*` is 1; for every `UNVERIFIABLE_*`, 3.

---

## 6. Settlement balances (deterministic from an ACCEPTED tape)

After an ACCEPTED log with final `gross_spent = G` and genesis `cap = C`:

```
seller_payout = G
buyer_refund  = C - G          (C >= G is guaranteed by the OVER_CAP check)
```

Leg 2 reconstructs and reports these final balances for an ACCEPT. The actual money
move is the rail's job and is SIMULATED; `end_to_end=false`.

---

## 7. Owner defaults carried into this spec (from the rulebook)

- Distinct V2 magic `FV2` + `version = 2` (not V1's `FSW`). Magic RATIFIED FINAL (Q12).
- Strict monotonic GROSS caps: `gross_spent <= cap`, `gross_refunded <= gross_spent`.
  Never silent netting.
- Monotonic in-band `record_ts` + an explicit `observed_now` INPUT. No wall clock.
  Same bytes + same `observed_now` -> same verdict.
- Genesis pins the domain trust anchors (keys + spec_hash), committed by
  `manifest_sha256` and supplied as the manifest witness.
- Ed25519 tip signature is out-of-band (alongside the records), not in the 48-byte
  payload.

## 8. FROZEN 2026-11-21 (owner-ratified widths and encodings)

These are FINAL. Build Leg 2 to them exactly. Regenerate the golden vectors if any
line here ever changes.

**Ids — RAW FIXED bytes, compared bytewise (no hex, no ASCII, no charset, no case, no
whitespace, no NUL-padding rule):**
- `deal_id` = 32 raw bytes.
- `escrow_id` = 32 raw bytes.
- `step_id` = 16 raw bytes (the `DUPLICATE_ID` key).
- An all-zero id field -> `REJECT_EMPTY_ID`. No charset "malformed id" check.

**Money and time (all `u64` little-endian):**
- `cap`, `seller_amount`, `gross_spent` = minor units (cents), `Money` bound `[0, 2^63-1]`.
- `expires_at` = Unix epoch seconds. `record_ts` = Unix epoch seconds (same clock).
- All multi-byte integers are little-endian.

**Expiry boundary (exact inequality):**
- Valid strictly while `observed_now < expires_at`.
- `REJECT_EXPIRED` iff `observed_now >= expires_at` (equality is EXPIRED).

**Reserved bytes:** header `[6..8)` and step payload `[88..96)` MUST be zero; a non-zero
reserved byte -> `REJECT_MALFORMED_RECORD`.

**GenesisManifest = 176 bytes** (SHA-256 of these 176 bytes == payload `manifest_sha256`):

```
deal_id    [0..32)
key_A      [32..64)
key_B      [64..96)
spec_hash  [96..128)
escrow_id  [128..160)
cap        [160..168)   u64 LE cents
expires_at [168..176)   u64 LE Unix seconds
```

`cap` and `expires_at` appear in BOTH the manifest AND in-clear in the 48-byte genesis
payload. The verifier checks `payload.cap == manifest.cap`,
`payload.expires_at == manifest.expires_at`, and `sha256(manifest) == payload.manifest_sha256`.

**48-byte genesis payload** (unchanged): `cap[0..8]` `expires_at[8..16]`
`manifest_sha256[16..48]`.

**48-byte step payload** (unchanged): `step_id[0..16]` `seller_amount[16..24]`
`gross_spent[24..32]` `record_ts[32..40]` `reserved[40..48]`.

**Refusal-code placement that is now final:** money-fold failure folded under
`REJECT_CHAIN_BREAK`; non-monotonic `record_ts` -> `REJECT_SEQ_MISMATCH`.

**Magic** `FV2` is RATIFIED FINAL (Q12). Nothing is owner-pending.

**`torn_bytes` = (file length mod 128) ALWAYS (Q13.6)**, computed independently of the
verdict and of where the fold stopped. This removes any Leg-1/Leg-2 divergence on a
reject-with-tail.

**Ed25519 `--tape` (Q11):** signed message = the 32-byte `record_seal` `[96..128)`,
NO domain separation. Strict profile: cofactorless `[S]B = R + [k]A`, reject
non-canonical `A`/`R`, reject `S >= L`, reject small-order `A`. See §9.

`SPEC_MISMATCH` (external `spec_hash`) stays deferred and unwired in this CLI.

---

## 9. CLI, `--json`, `--tape`, limits (all FINAL)

### 9.1 CLI

```
leg2-verify <log.bin> --manifest <m.bin> --pubkeys <a.pub,b.pub> \
            [--tape <t.bin>] [--observed-now N] [--expect-tip HEX] \
            [--max-records N] [--json]
```

- `--manifest` and `--pubkeys` are REQUIRED. `--pubkeys` is two comma-separated
  32-byte Ed25519 public-key files (`key_A`, `key_B`); they MUST equal the manifest
  keys (Q5, §3.2 step 7).
- **Omitting `--manifest` or `--pubkeys` (or an unreadable, or non-32-byte, pubkey
  file) -> `UNVERIFIABLE_USAGE` (exit 3), decided BEFORE any record is read.** This is
  the input-shape symmetry of the mandatory `--observed-now` rule (Q6).
- `--observed-now N` is a trusted `u64` time input; REQUIRED when the log has >= 1 step
  (Q6), optional for a genesis-only log. The verifier NEVER reads a wall clock.
- `--expect-tip HEX` is an optional anchor; see §9.5.
- `--max-records N` overrides the default ceiling; see §9.4.
- `--json` emits the canonical comparison object; see §9.6.

### 9.2 `--tape` (co-signed sidecar)

`--tape <file>` is a sidecar of 64-byte Ed25519 signatures, **2 per record in record
order**: `[sig_A(rec0), sig_B(rec0), sig_A(rec1), sig_B(rec1), ...]`. The **signed
message is the 32-byte `record_seal` (bytes `[96..128)`)** of that record, with no
domain separation. Genesis (rec 0) requires BOTH `sig_A` and `sig_B` valid; each step
requires `sig_A` (proposer) + `sig_B` (countersigner) valid. Any missing or invalid
signature -> `REJECT_BAD_SIGNATURE`. WITHOUT `--tape`, signatures are skipped and the
verdict is log-only (structure + fold + key checks). WITH `--tape`, signatures are
enforced.

### 9.3 Ed25519 STRICT profile (ratified; Leg 1 MUST match)

The full, unambiguous verification predicate for a signature `(R, S)` over message `m`
with key `A`:

- Canonical encoding on `A` and `R`: each decoded `y < p` -> else reject non-canonical.
- Cofactorless equation: `[S]B == R + [k]A`, where `k = SHA-512(R || A || m) mod L`
  and `B` is the base point. NO multiply by the cofactor.
- Reject `S >= L` (the group order `L = 2^252 + 27742317777372353535851937790883648493`).
- Reject a small-order `A`: `[8] * A == identity` -> `REJECT_BAD_KEY` at genesis
  (§3.2 step 6). `A` is the KEY.
- Reject a small-order `R`: `[8] * R == identity` -> `REJECT_BAD_SIGNATURE`. `R` is
  part of the SIGNATURE, not the key, so its code is `BAD_SIGNATURE`, not `BAD_KEY`.
  Same cofactor test as `A`.

**WARNING — do NOT use a default Ed25519 library on the verification path.** A
default/cofactored Ed25519 (OpenSSL, libsodium, Go `crypto/ed25519`, Python
`cryptography`) is COFACTORED and will diverge from this spec on torsion-added points
(a small-order `R` added to a valid one). Leg 1 and Leg 2 MUST each implement THIS
exact cofactorless predicate, including the small-order `A`/`R` rejections, or the two
legs will disagree on crafted torsion signatures.

### 9.4 Record ceiling (Q8)

`DEFAULT_MAX_RECORDS = 1048576` (128 MiB of whole 128-byte records). Overridable with
`--max-records N`. A file whose whole-record count exceeds the ceiling ->
`UNVERIFIABLE_TOO_LARGE` (exit 3), decided BEFORE any fold.

### 9.5 `--expect-tip` (Q10)

- Case-insensitive, EXACTLY 64 hex chars (else `UNVERIFIABLE_USAGE`) (Q13.5).
- Evaluated ONLY after a fully successful fold. A fold refusal keeps its own code and
  index; the anchor is never consulted (Q10c).
- Compared against the SHA-256 of the LAST WHOLE record, even when the file would
  otherwise be `ACCEPT_TORN_TAIL` (Q10b).
- A mismatch folds under `REJECT_CHAIN_BREAK` (no separate code) with `fail_index`
  null (Q10a).

### 9.6 Canonical `--json` object (Q9) — the differential substrate

`stdout` line 1 is the bare verdict NAME and nothing else; detail follows on
`key=value` lines for humans. The DIFFERENTIAL harness compares the `--json` object
(and may compare only the first whitespace token of line 1). Both legs MUST emit an
identical `--json` object. Schema (integers are decimal JSON numbers, no float, no
exponent):

```
{
  "verdict": str,                 // the full verdict name
  "exit_code": int,               // 0 / 4 / 1 / 3
  "records": int,                 // whole 128-byte records in the file
  "torn_bytes": int,              // file length mod 128, ALWAYS (Q13.6)
  "fail_index": int | null,       // lowest failing record index; null if none/anchor
  "final_balances": {             // all 0 unless ACCEPT / ACCEPT_TORN_TAIL
    "gross_spent": int, "seller_payout": int, "buyer_refund": int },
  "tip": hexstr,                  // SHA-256 of last whole record on ACCEPT*, else ""
  "epoch": int,                   // records folded on ACCEPT*, else 0
  "expiry_gate_evaluated": bool,  // true iff the expiry gate decided (ACCEPT w/ steps,
                                  //   or REJECT_EXPIRED)
  "notes": str                    // "" in canonical mode (informational only)
}
```

Every case in `golden_vectors/vectors.json` carries its `expected_json`.
