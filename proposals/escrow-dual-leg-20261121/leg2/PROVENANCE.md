# PROVENANCE.md — what was accessed, and the independence attestation

**Artifact:** `leg2-verify` 0.2.0 — Leg 2 escrow verifier, Forge V2 Domain 2.
**Built against:** `leg2-packet-FROZEN-76f4ab54.zip` (SPEC.md STATUS FROZEN,
owner-ratified Q1–Q14). Supersedes the 0.1.0 build against the DRAFT packet
`cd51e45`.
**Date:** 2026-11-21.
**Label:** **UNPROVED-but-independent-toolchain.**

---

## 1. Independence attestation

I confirm, as the Leg-2 implementer:

1. **Leg 2 was built from the uploaded specification packages alone.** The only
   inputs were `SPEC.md`, `README.md`, `ACCEPTANCE.md` and the black-box
   `golden_vectors/` (`vectors.json` plus the `.log.bin`, `.manifest.bin`,
   `.tape.bin`, `a.pub`, `b.pub` and `badA.pub` files) of the two packets
   `cd51e45` and `76f4ab54`, together with my own knowledge of Rust, SHA-2 and
   Ed25519.

2. **I have never seen Leg 1, in any form.** I did not read the Dafny verifier,
   any Leg-1 source, any Leg-1 `FORMAT.md` / `VERDICTS.md` / internal note, or any
   proof-assistant source of any kind. I did not search for one, ask for one, or
   attempt to infer one. All I know about Leg 1 is that it exists, that it is
   written in Dafny, and that it is the other half of the 2-of-2 gate — which is
   what README §0 already told me.

3. **No proof-assistant source was consulted or produced.** This leg carries no
   proof and claims none.

4. **I did not optimize to match another implementation.** Every semantic choice
   was made from SPEC.md's own text, and each choice the text does not settle is
   written down in SPEC_QUESTIONS.md as a question for the owner rather than
   resolved by guessing at what another leg might do. Where I had to act in order
   to ship (13 items), the reading is argued from the cited SPEC.md lines, is
   isolated to one site in the code, and is switchable where that is meaningful.
   None of those readings was chosen because it seemed likely to agree with Leg 1.

5. **Leg 2 shares no parser, front-end, IR, compiler or runtime with Leg 1.**
   It is a standalone Rust 2021 binary with **zero third-party dependencies**
   (`cargo tree` lists only this crate; `Cargo.lock` holds one package, this
   crate). SHA-256, SHA-512 and Ed25519 are hand-rolled in `src/`, so not even a
   cryptographic library is shared with the other leg.

6. **No V1 code was reused.** README's scope note says the V1 refund verifier is a
   different domain with a different payload and record width. I did not have it
   and did not port anything.

### Limits of this attestation — read before relying on it

ACCEPTANCE.md §3 requires that Leg 2 "is a different human from Leg 1's author".
**I am not a human.** I am an AI assistant (Claude) that wrote this leg in a
single session from the uploaded packet.

That matters for exactly the reason README §0 gives: "Agents spawned by one model
are correlated and do NOT satisfy independence." So:

- If **Leg 1 was written by a human in Dafny**, then the toolchains, the
  languages and the authors are genuinely different, and the two-leg agreement
  retains the two-sided catch README §0 describes — with the caveat that an AI
  author and a human author are a less-studied independence pairing than two
  humans, and that any blind spot shared between my training distribution and the
  Dafny author's reasoning would survive.
- If **Leg 1 was written, in whole or in part, by the same or a similar model**,
  the two legs are **correlated** and the agreement is worth substantially less
  than the acceptance bar assumes. In that case ACCEPTANCE.md §3 is **not met**
  and the honest label for the pair is not a clean NATIVE CHECK.

Only the owner knows which case holds. I am flagging it rather than letting the
attestation read as though the §3 condition were satisfied in full. Everything in
items 1–6 above is accurate as written.

---

## 2. Everything accessed during this build

### 2.1 Read from the uploaded package

| File | Use |
| --- | --- |
| `SPEC.md` | read in full; the sole source of semantics |
| `README.md` | read in full; CLI contract, verdict/exit scheme, trusted base, independence rules |
| `ACCEPTANCE.md` | read in full; the acceptance bar |
| `golden_vectors/vectors.json` | read in full; the test suite and its `expected_json` |
| `golden_vectors/*.log.bin` (54) | read as bytes; decoded for test input only |
| `golden_vectors/*.manifest.bin` (54) | read as bytes; test input |
| `golden_vectors/a.pub`, `b.pub`, `badA.pub` | read as bytes (32 each); test input |
| `golden_vectors/*.tape.bin` (2) | read as bytes; co-signed sidecar test input |

### 2.2 Deliberately NOT read: `gen_vectors.py` (either version)

`gen_vectors.py` ships in both packets — and in `76f4ab54` it additionally
vendors a pure-Python RFC 8032 Ed25519, which is precisely the implementation my
own hand-rolled Ed25519 is cross-checked against by the `accept_cosigned_tape`
vector. Reading it would have been within the letter of "build only from the
uploaded files". I chose not to read either version, and I did not read them.

That restraint matters more now than it did for the DRAFT packet: the signed
vectors are the one place where two independent *implementations of the same
primitive* are compared, and that comparison is worth nothing if I had read the
other implementation first.

Reason: it is the **generator of the oracle**. Reading it would have let me
resolve the 13 open questions by copying the behaviour of the program that
produced the expected answers, which is precisely the "guess that happens to
match" the brief warns about — it would have manufactured agreement without
evidence and hidden real spec gaps. The vectors themselves are a different
matter: README §0 calls shared **vectors** "allowed and good … the cross-check
substrate", so I used them strictly as black-box `input bytes -> expected verdict`
pairs. My reading of the byte layout comes from SPEC.md §2/§3/§4/§8 and nothing
else.

Two consequences worth noting. First, I wrote my own encoders of the envelope from
the spec tables — one in `tests/robustness.rs` and one in `tools/make_big_log.py`
— so the layout is implemented three times in this deliverable (verifier reader,
test builder, corpus generator) from the same prose; all three agree with each
other and with the packet's vectors, which is good evidence the tables were read
correctly. Second, I verified `vectors.json`'s own internal consistency
independently (recomputing every seal, `prev_hash` and manifest hash with Python's
`hashlib` before writing any Rust) rather than taking the generator's word for it.

### 2.3 Network access: none

No network was used at any point in this build.

- No web search, no browsing, no documentation lookup, no package download.
- The build is `cargo build --offline` with an **empty crate registry** on the
  machine; there is no `~/.cargo/registry`, so no third-party crate could have
  been fetched even accidentally. `Cargo.lock` contains exactly one package.
- The FIPS 180-4 and RFC 8032 test vectors in `tests/crypto_kat.rs` were written
  **from my own knowledge of those standards, not fetched.** This is the one place
  where offline recall is load-bearing, so it is validated rather than trusted:
  see §3 below, and the caveat printed in the header comment of that file.

### 2.4 Tools used

Rust 1.97.0 / cargo 1.97.0 (offline); Python 3 standard library (`hashlib`,
`json`, `struct`) for the vector runner, the differential hash oracle, the
constant re-derivation and the large-corpus generator; `bash` for the CLI tests.
Python's `hashlib` is used **only as an independent oracle in the test harness** —
no Python participates in the verifier, which is pure Rust std.

---

## 3. How the offline-recalled crypto vectors were validated

Because the standards could not be fetched, each recalled vector is corroborated
by something that does not depend on my recall:

1. **All 160 SHA-2 constants re-derived from their definition.**
   `tools/check_sha_constants.py` recomputes `K256`, `H256`, `K512` and `H512`
   from "fractional parts of the cube/square roots of the first N primes" using
   exact integer arithmetic and compares them to the tables in `src/sha2.rs`.
   All 160 match. A transcription error in those tables is therefore impossible.
2. **SHA-256 and SHA-512 differential-tested against Python `hashlib`** over 410
   inputs covering every length 0–400 plus block-boundary and multi-block cases:
   **0 mismatches** against an independent implementation.
3. **SHA-256 cross-validated by the packet itself.** The 43 golden vectors'
   seals, `prev_hash` chains and manifest commitments were produced by a different
   SHA-256 (the packet's own). A wrong SHA-256 in Leg 2 would fail essentially
   every vector; all 42 gradable vectors pass.
4. **Ed25519 vectors are self-consistent quadruples.** For each RFC 8032 §7.1
   case, Leg 2 derives the public key *from the secret seed* and re-derives the
   64-byte signature *from the secret seed and message*, and both match the
   recalled values byte for byte, for all four cases. A misremembered constant
   could not do that — it would have to be a genuine `(sk, pk, msg, sig)` tuple of
   the real Ed25519 group. This also exercises SHA-512 end to end, since the key
   expansion and both hashes run through it.
5. **Curve constants derived, not recalled.** `d`, `sqrt(-1)` and the base point
   are computed from their defining equations; `[L]B == identity` validates the
   one transcribed constant (`L`).

**Residual risk, stated honestly:** a reviewer with the printed FIPS 180-4 and
RFC 8032 documents should still diff the constants in `tests/crypto_kat.rs`
against the published tables. Items 1–5 make a silent error very unlikely, not
impossible.

---

## 4. Honest labels on the result

- **Leg 2's label: UNPROVED-but-independent-toolchain.** It is tested, not proved.
- **Leg 2 alone is a NATIVE CHECK.** Its ACCEPT means only what README §1.4 says:
  these bytes are a valid escrow history of SPEC.md's semantics within the
  genesis-pinned cap. Not that a payment happened, not who the parties are, not
  that these bytes are the only durable copy. `end_to_end=false`.
- **Any later agreement with Leg 1 is an N-version FINITE TEST**, over the inputs
  actually run — not a proof of the transition, and not authenticity. Its value
  is also conditional on the independence caveat in §1 above.
- **Speed: measured, not quoted from the packet.** On this machine (Intel Xeon,
  single core, release build) Leg 2 verifies 65,536 records in **~92 ms** and
  1,000,001 records in **~1.43 s** without a tape; **with `--tape` the cost is
  dominated by Ed25519 at ~230 µs per signature, i.e. ~460 µs per record** —
  see TEST_RESULTS.md §6. The packet's UNVERIFIED "~5 ms for 65,535 records"
  figure is **not reproduced** by this leg and is **not quoted** anywhere in this
  deliverable. Anyone quoting a throughput figure for Leg 2 should re-measure on
  the target hardware.
