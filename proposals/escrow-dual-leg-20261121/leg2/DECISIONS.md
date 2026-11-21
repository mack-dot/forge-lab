# DECISIONS.md — every assumption Leg 2 makes

Built against `leg2-packet-FROZEN-76f4ab54`: SPEC.md STATUS **FROZEN**,
owner-ratified Q1–Q14. **Nothing in SPEC.md is open any more**, so this file no
longer carries interim readings of ambiguous items — SPEC_QUESTIONS.md records
how each ruling landed (and which 5 of my earlier readings it overturned). What
remains below is the engineering: choices SPEC.md leaves to the implementer.

Label: **UNPROVED-but-independent-toolchain.** This verifier is a **NATIVE CHECK**.
Any later agreement with Leg 1 is an **N-version FINITE TEST**, not a proof.

---

## 1. Trusted base

**D1.1 — Rust std only; zero third-party crates.** README §1.3 offers three
options. I took the third: **hand-rolled SHA-256 and Ed25519** (plus SHA-512,
which Ed25519 is defined over). `cargo tree` lists only this crate.

Why: the environment has no package registry, and more importantly a hand-rolled
primitive cannot share a bug with whatever Leg 1 uses. A shared dependency is
exactly the correlated failure the two-leg gate is supposed to catch. The cost is
that my primitives must be validated independently, which TEST_RESULTS.md §1 does
(FIPS 180-4, RFC 8032, a hashlib differential, and re-derivation of all 160 SHA-2
constants from their mathematical definition).

**D1.2 — Curve and field constants are derived, not transcribed.** `d`,
`sqrt(-1)`, the base point and the inversion/sqrt exponents are computed in
`fe.rs`/`ed25519.rs` from their defining equations (`d = -121665/121666`,
`sqrt(-1) = 2^((p-1)/4)`, `B.y = 4/5`), so a mistyped hex literal cannot exist.
The one transcribed constant is the group order `L`, and `ed25519::self_check()`
validates it independently by asserting `[L]B == identity`.

**D1.3a — Key validity is checked at the genesis, not inside `verify`.** RFC 8032
mandates no key-validity check, so `ed25519::verify` performs none; SPEC.md §3.2
step 6 instead requires it once, where the keys are pinned, reporting
`REJECT_BAD_KEY`. That is the right place: it is a property of the deal's
anchors, not of an individual signature. The reason it matters is pinned by
tests — a small-order pinned key would otherwise make the §5.2 step-13 check
vacuous (identity key → universal forgery; order-8 key → ~1 message in 8).

**D1.3b — Derived constants are cached, not re-derived.** `d`, `sqrt(-1)` and the
base point are still computed from their defining equations (no transcribed
hex), but each is memoised in a `OnceLock`. Deriving `d` costs a field
exponentiation and `Point::add` needs it on every call, so re-deriving per use
made scalar multiplication about two orders of magnitude slower than it should
be. The derivation is pure, so caching changes speed only, never the value.

**D1.3c — The scalar ladder is 4-bit windowed with a dedicated doubling
formula**, not bit-at-a-time with `add(P,P)`. Both are standard transformations
and both are pinned against the naive version they replace
(`dedicated_doubling_matches_addition`, `windowed_ladder_matches_bitwise_ladder`)
rather than trusted. Neither is constant time, by design: every input here is
public bytes — a public key, an `R` from a signature, a record's seal — so there
is no secret for a timing or window-pattern side channel to leak.

**D1.3 — Ed25519 verification profile: STRICT.** Cofactorless
`[S]B = R + [k]A`, plus rejection of `S >= L` and of non-canonical `A`/`R`
encodings (`y >= p`). RFC 8032 §5.1.7 permits either the cofactored or the
cofactorless form; cofactorless is strictly stronger, so it cannot accept anything
the other would reject. **Flagged as SPEC_QUESTIONS.md Q11.4** because a
permissive library on the other leg would be a genuine N-version split.

---

## 2. Arithmetic and the money law

**D2.1 — Everything is `u64`, never `i64`, never floating point.** SPEC.md §1:
the wire format is unsigned, no negative value exists, "and none is invented".
The `Money` predicate is a single `const fn` (`spec::is_money`) tested against the
full wire range before any arithmetic.

**D2.2 — The only *value* wraparound in the program is inside SHA-256/SHA-512
compression**, and every such add is written explicitly as `wrapping_add` so the
intent is visible at the call site (SPEC.md §1). Everywhere else the crate is
compiled with `overflow-checks = true` **in release as well as debug**, so an
unintended overflow panics rather than wrapping — and a panic is caught and
becomes `UNVERIFIABLE_INTERNAL` (exit 3), never an ACCEPT.

Stated precisely, because §1 is emphatic about this: the escrow verdict path —
envelope parsing, the money law, the fold, the balances — contains **no**
`wrapping_*` or `overflowing_*` arithmetic at all outside `sha2.rs`. The only
other uses in the crate are the carry/borrow chains of the multi-precision
scalar arithmetic in `scalar.rs` (`overflowing_add`/`overflowing_sub` to extract
a carry bit between 64-bit limbs). Those preserve the mathematical value across
limbs rather than reducing it mod 2^64, so they are not wraparound in §1's sense;
and they are reachable only through Ed25519, which §5.2 step 9 leaves deferred
and which the fold therefore never calls. A reviewer can confirm the whole list
with `grep -rn "wrapping_\|overflowing_" src/`.

**D2.3 — The money fold uses `checked_add`, the refund uses `checked_sub`.**
With both addends `Money` (≤ 2^63−1) the sum is at most 2^64−2 and a `u64` add
cannot wrap, so the checked form is belt-and-braces; it makes "no wrap can occur
in money arithmetic" (§1) a property the compiler enforces rather than a comment.
If `state.gross_spent + seller_amount` ever did overflow it becomes
`REJECT_CHAIN_BREAK` (the record does not continue the state), never a wrap.
Consequence worth stating: because `gross_spent` is itself `Money`-checked, a sum
above 2^63−1 can never equal it, so near-maximum running totals refuse at §5.2
step 5 rather than at the cap check.

**D2.4 — `cap - gross_spent` cannot borrow.** §5.2 step 6 guarantees
`gross_spent <= cap` for every folded step, and a genesis-only log has
`gross_spent = 0`. `checked_sub` with an `UNVERIFIABLE_INTERNAL` fallback keeps
that from degrading into a wrap if the invariant were ever broken.

---

## 3. Check order (the part that decides *which* refusal code)

**D3.1 — The numbered order of §3.2 and §5.2 is implemented literally**, in one
place each (`verify::verify_genesis`, `verify::step`), with the step number in a
comment beside each check. The order is load-bearing: it is what makes a record
with several faults deterministic. Four golden vectors actually discriminate it
(`reject_not_money_2p63` puts step 3 before step 6; `demo_sabotage_over_cap` puts
step 5 before step 6; `reject_bad_domain` and `reject_malformed_record` put the
step-1 envelope checks before the payload), and `tests/robustness.rs`
(`envelope_codes_are_distinct_and_ordered`) pins seven more orderings that no
vector covers.

**D3.2 — Within the envelope, the sub-order is §2's table order** as restated by
§3.2/§5.2 step 1: magic → version → domain → kind → reserved → `seq_no` →
`prev_hash` → seal. So the seal is checked **last** among envelope checks, which
is why `reject_bad_domain` (whose record also has a valid recomputed seal) is
`BAD_DOMAIN` and why a record that is both malformed and unsealed reports the
malformation.

**D3.3 — The first refusal in record order wins**, and verification stops there
(SPEC_QUESTIONS.md Q13.7). Scanning continues to end-of-file without verifying,
only so the reported `torn_bytes` is the file's true tail length (Q13.6).

**D3.4 — The ratified order is implemented with no switches.** Every item that
was behind a command-line switch in the pre-ratification build
(`--genesis-id-check`, `--strict-pubkeys`, `--require-valid-pubkeys`) is now
**mandatory spec**, so the switches are gone: a flag that can turn off a required
check is a divergence waiting to happen, and there is nothing left to bisect.
The genesis is 7 ordered checks (§3.2) and a step is 13 (§5.2); both sequences
live in one function each, annotated with the spec step number.

The only remaining configuration is what SPEC.md itself parameterises:
`--max-records` (§9.4) and `--tape` (§9.2). `--expect-spec-hash` stays as the one
extension flag, because §3.2 leaves `SPEC_MISMATCH` deferred and unwired — it is
inactive unless a hash is supplied.

---

## 4. Verdicts, exit codes, output

**D4.1 — Exit codes are derived from the verdict variant's class**, not attached
case by case (`verdict::Verdict::exit_code`), so a future refusal code cannot get
the wrong exit code by omission: 0 ACCEPT, 4 ACCEPT_TORN_TAIL, 1 every `REJECT_*`,
3 every `UNVERIFIABLE_*`.

**D4.2 — Only the full names are ever printed.** The demo short forms
(`DUPLICATE_ID`, `OVER_CAP`, …) exist nowhere in the output path (SPEC.md §5.3,
README §1.2). `ACCEPT_TORN_TAIL` is a distinct string from `ACCEPT`, so a consumer
testing the name sees the long form.

**D4.3 — Line 1 is the bare verdict name and nothing else**; details follow on
`key=value` lines; `--json` gives one object for the harness. See
SPEC_QUESTIONS.md Q9 — the format is not specified and needs ratification.

**D4.4 — Exactly two sites in the program can produce a name starting with
`ACCEPT`**, both at the very end of `verify_log` after a fully successful fold and
a satisfied anchor. Every other return path is a `REJECT_*` or `UNVERIFIABLE_*`
(README §1.2: "No error path ever prints an ACCEPT verdict"). A CLI test asserts
that any exit code other than 0/4 is never accompanied by an `ACCEPT*` line.

**D4.5 — Four `UNVERIFIABLE_*` spellings are mine, not the packet's** —
`TOO_LARGE`, `UNREADABLE`, `USAGE`, `INTERNAL`. SPEC_QUESTIONS.md Q7.
Assignment: I/O failure on any input file → `UNREADABLE`; a malformed argument or
a wrong-sized pubkey → `USAGE`; over the record ceiling → `TOO_LARGE`; a caught
panic or a broken internal invariant → `INTERNAL`.

---

## 5. Fail-closed engineering

**D5.1 — No panic can reach the shell.** `main` installs a panic hook and wraps
the whole verification in `catch_unwind`; a panic prints `UNVERIFIABLE_INTERNAL`
and exits 3. `panic = "unwind"` is pinned in the release profile because
`panic = "abort"` would defeat this.

**D5.2 — No unchecked indexing on attacker-controlled bytes.** A record is a
`[u8; 128]` value and every accessor in `record.rs` uses compile-time-constant
ranges within those bounds, so no accessor can panic or read out of range on any
input. The manifest is the one variable-length input; it is length-checked before
any field is read, and its hash is computed over whatever was supplied.

**D5.3 — Streaming, O(1) in file size except for the duplicate-id set.** The log
is read 128 bytes at a time with a short-read loop (so pipes and FIFOs work, not
just regular files). Memory grows only with the number of distinct `step_id`s,
which `--max-records` bounds.

**D5.4 — Truncated reads are never folded.** `fill()` returns the number of bytes
actually obtained; a result in 1..127 is the torn tail and the bytes are never
interpreted as a record (§2). A whole 128-byte final record that fails any check
is a REJECT, never "torn" — the verifier never repairs or re-interprets the file
it reads.

**D5.5 — `BTreeSet`, not `HashSet`, for `settled_steps`.** `HashSet`'s default
hasher is randomly seeded per process. Membership results would be identical
either way, but a verifier should contain no seeded randomness at all, so there
is none.

---

## 6. Determinism

**D6.1 — Time enters only through `--observed-now` and each record's
`record_ts`.** The program calls no clock API; there is no `SystemTime`,
`Instant` or equivalent anywhere in `src/`. Verified by inspection and by
`grep` (TEST_RESULTS.md §5).

**D6.2 — No environment, locale or filesystem-order dependence.** Nothing reads
environment variables or directory listings; output is ASCII `key=value` lines
with no locale-sensitive formatting.

**D6.3 — The expiry gate keys on `observed_now`, never on `record_ts`.** §5.2
step 8 is explicit, and a test pins the discriminating case: a log whose
`record_ts` is far past `expires_at` still ACCEPTs when `observed_now` is before
`expires_at`.

---

## 7. Deliberate non-decisions

Things I could have guessed at and did not:

- **The co-signed tape format.** `--tape` is refused with a usage error that names
  D-TAPE. Inventing a wire format would have produced a confident, wrong verifier.
- **A `REJECT_TIP_MISMATCH` code.** The vector folds the anchor under
  `CHAIN_BREAK` and the note says a split "may" come later; I followed the vector.
- **Any check not in SPEC.md.** No deal_id-vs-record binding, no `escrow_id`
  checks beyond the id rule, no cross-record `record_ts` window, no limit on
  `expires_at` relative to `record_ts` — none of these is specified, so none is
  implemented, however reasonable they might look.
- **Reading `gen_vectors.py`.** It ships in the packet, but it is the oracle's
  generator. I implemented from SPEC.md's prose and tables and used the vectors
  only as black-box input→verdict pairs, which is what README §0 calls the
  cross-check substrate. See PROVENANCE.md.
