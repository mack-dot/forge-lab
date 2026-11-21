# Leg 2 Implementer Packet — Forge V2 Escrow Verifier (clean-room)

**STATUS: DRAFT. NOT ratified.** `end_to_end=false`. Prepared 2026-11-21.
Design + test-vector deliverable. No verifier is built here. No proof is claimed.

This packet is for a SECOND, INDEPENDENT engineer — called **Gharib** — who builds
the Leg-2 escrow verifier in Rust. The whole value of this packet is that Gharib
builds Leg 2 **from this packet alone**.

---

## 0. The independence contract (read first, it is the product)

The two-leg gate is only honest if the two legs are genuinely independent. So:

- **Do NOT look at Leg 1.** Do not read the Dafny verifier, any Leg-1 source, any
  Leg-1 `FORMAT.md` / `VERDICTS.md`, or any Leg-1 internal note. Build only from the
  files in this packet.
- This packet contains **only** the spec: the byte formats, the money law, the
  Step/verdict contract, the refusal codes, and black-box golden vectors
  (input bytes -> expected verdict). It embeds **no** proof-assistant source, **no**
  Leg-1 code, and **no** Leg-1 implementation detail. There is nothing in here that
  could correlate your work with Leg 1.
- The ONLY artifacts the two legs share are the upstream rulebook
  (`DIRECTIVE_V2_RULEBOOK.md`), the demo spec (`DIRECTIVE_V2_DEMO_ESCROW.md`), and
  the golden vectors in this packet. Shared VECTORS are allowed and good — they are
  the cross-check substrate. The IMPLEMENTATIONS must share nothing: no parser, no
  front-end, no IR, no compiler, no runtime.
- Agents spawned by one model are correlated and do NOT satisfy independence. Leg 2
  must be written by a different human in a different toolchain.

**Honesty labels (carried from the rulebook, use them unchanged):**
- **NATIVE CHECK** — two independent compiled verifiers agreed on exact bytes.
  NOT a proof. Leg-2 ACCEPT agreeing with Leg-1 ACCEPT is a NATIVE CHECK, an
  N-version cross-check, not a proof of the transition and not authenticity.
- **FINITE TEST** — a check on specific inputs only. Not a proof.
- Leg 2's own label is **UNPROVED-but-independent-toolchain.** Measure its real
  speed before quoting any number. Do not quote the "~5 ms for 65,535 records"
  figure; it is UNVERIFIED.

**Note on scope.** An escrow verifier is a NEW domain (Domain 2). The V1 refund
verifier is a DIFFERENT domain (Domain 1) with a different payload and a different
record width. Do not reuse or port it. This packet is self-contained for escrow.

---

## 1. What Leg 2 must do

Leg 2 is a command-line program that reads a log of 128-byte escrow records, folds a
decidable `Step` function over them from the genesis, and prints ONE verdict line,
then exits with a code.

### 1.1 CLI contract

```
leg2-verify <log.bin> --manifest <m.bin> --pubkeys <a.pub,b.pub> \
            [--tape <t.bin>] [--observed-now N] [--expect-tip HEX] \
            [--max-records N] [--json]
```

| Argument | Meaning |
| --- | --- |
| `<log.bin>` | the escrow log: zero or more whole 128-byte records, maybe a 1..127-byte trailing partial |
| `--manifest <m.bin>` | the 176-byte GenesisManifest witness (SPEC.md §3). REQUIRED |
| `--pubkeys <a.pub,b.pub>` | two 32-byte Ed25519 public-key files (key_A, key_B). REQUIRED; they MUST equal the manifest keys (REJECT_KEY_MISMATCH otherwise) |
| `--tape <t.bin>` | optional co-signed sidecar: 64-byte sigs, 2 per record, signed over the 32-byte record_seal (SPEC.md §9.2). WITH it, signatures are enforced; WITHOUT it, skipped |
| `--observed-now N` | trusted time input (u64). The verifier NEVER calls a wall clock. REQUIRED when the log has >= 1 step (Q6); optional for a genesis-only log |
| `--expect-tip HEX` | optional anchor: 64 hex chars, case-insensitive; SHA-256 of the last whole record. Checked only after a successful fold; mismatch -> REJECT_CHAIN_BREAK (SPEC.md §9.5) |
| `--max-records N` | optional ceiling override (default 1048576); over it -> UNVERIFIABLE_TOO_LARGE (SPEC.md §9.4) |
| `--json` | emit the canonical comparison object (SPEC.md §9.6). stdout line 1 stays the bare verdict name |

### 1.2 Verdict + exit-code scheme (from rulebook §5, unchanged)

ONE verdict line on stdout. The verdict name is NEVER shortened.

| Exit | Verdict class | Meaning |
| --- | --- | --- |
| **0** | `ACCEPT` | every whole record passed; file length is a multiple of 128; any given anchor matches |
| **4** | `ACCEPT_TORN_TAIL` | as ACCEPT, plus a trailing 1..127-byte partial exists; the partial is NEVER read as a record. Report `torn_bytes` |
| **1** | `REJECT_*` | any refusal (SPEC.md §5.3 lists every code). First failure wins: report the lowest-indexed failing record |
| **3** | `UNVERIFIABLE_*` | one of the six names: `UNVERIFIABLE_EMPTY`, `_NO_RECORD`, `_TOO_LARGE`, `_UNREADABLE`, `_USAGE`, `_INTERNAL` (SPEC.md §5.3) |

No error path ever prints an ACCEPT verdict. A consumer that tests the name sees the
full `ACCEPT_TORN_TAIL`, not `ACCEPT`. The canonical differential substrate is the
`--json` object (SPEC.md §9.6), not the human line.

### 1.3 Trusted base you may use (your choice, state it)

- **Rust std** and nothing else, OR
- **ONE vetted dependency each** for SHA-256 and for Ed25519, OR
- **hand-rolled** SHA-256 and Ed25519.

Name the choice as the implementer. If you hand-roll SHA-256, check it against the
NIST FIPS 180-4 vectors before trusting it. The one permitted modular wraparound in
the whole program is the 32-bit add mod 2^32 inside the SHA-256 compression rounds
(SPEC.md §2). Nothing else wraps.

### 1.4 What Leg 2 establishes, stated honestly

Leg-2 ACCEPT means: "these bytes are a valid escrow history of the ratified
semantics in SPEC.md, within the genesis-pinned cap, and (when signatures are
supplied) signed by the pinned keys." It does NOT establish that a payment happened,
who the humans are, or that these bytes are the only durable copy. `end_to_end=false`.

---

## 2. Files in this packet

| File | Role |
| --- | --- |
| `README.md` | this file: the independence contract + the CLI/verdict contract |
| `SPEC.md` | the complete, self-contained escrow semantics (envelope, payloads, manifest, money law, Step, every refusal code) |
| `gen_vectors.py` | Python stdlib generator (SHA-256 + a vendored RFC 8032 Ed25519) that writes the golden vectors |
| `golden_vectors/vectors.json` | machine-readable manifest: each case = input bytes + expected `--json` object |
| `golden_vectors/*.log.bin` | raw log bytes per case |
| `golden_vectors/*.manifest.bin` | the 176-byte GenesisManifest witness per case |
| `golden_vectors/*.tape.bin` | co-signed signature sidecar for the `--tape` cases |
| `golden_vectors/a.pub`, `b.pub` | REAL 32-byte Ed25519 public keys (minted by the generator) |
| `golden_vectors/badA.pub` | a small-order point, for the `reject_bad_key` vector |

## 3. Signatures (Ed25519) — REAL keys and the `--tape` sidecar

- The generator **vendors a pure-Python RFC 8032 Ed25519** (hashlib SHA-512 only, no
  pip) and **self-tests it against the RFC 8032 test vectors** before minting any key.
  It mints REAL keypairs for A and B and writes real 32-byte `a.pub` / `b.pub`; the
  manifest `key_A` / `key_B` are those real keys.
- **Signatures are checked only WITH `--tape`** (SPEC.md §9.2): a sidecar of 64-byte
  signatures, 2 per record, over the 32-byte `record_seal`. WITHOUT `--tape`, the
  verdict is log-only (structure + fold + the mandatory key checks). The key checks
  (`REJECT_KEY_MISMATCH`, `REJECT_BAD_KEY`) run on EVERY invocation, tape or not.
- The signed vectors are REAL: `accept_cosigned_tape` carries valid co-signatures;
  `reject_bad_signature_tape` carries one corrupted signature. Implement the strict
  Ed25519 profile in SPEC.md §9.3 (cofactorless, reject non-canonical `A`/`R`, reject
  `S >= L`, reject small-order `A`); the vectors confirm it directly.

See `ACCEPTANCE.md` for how we decide Leg 2 is done and correct.
