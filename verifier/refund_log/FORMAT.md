# The silicon sink's ledger files, byte by byte (decoder correspondence)

Source read: `src/silicon_sink/sink.rs`, 248 lines, SHA-256
`1962af4a54c48704749ae919dbeae4d5f1cdc2c7990cf7db3f17614459c2db71` (unchanged on `origin/main` `236198b2`).
"sink.rs:N" is a line of that file. "Dafny" names a declaration in `RefundLogVerifier.dfy` (module `SinkFormat`
for the format, module `RefundLogVerifier` for the fold). This table compares TEXT with TEXT: that the Rust
program writes what the Dafny model encoder writes is NOT proved (it is checked only by finite tests on real
logs). The verifier does not rely on it: it trusts the bytes it reads, not the engine.

## 1. `ledger.wal`: a sequence of 64-byte records, little-endian (sink.rs:5-11, 64-74)

| Bytes | Content | Written by (sink.rs) | Read by the sink (sink.rs) | Dafny (decoder / encoder model) | Verifier check |
| --- | --- | --- | --- | --- | --- |
| 0..3 | ASCII `FSW` | `encode` 66 | `scan` 87: `&r[..3] == b"FSW"` | `MAGIC`; `Framed`; `Body` | else `REJECT_MALFORMED_RECORD` |
| 3 | kind: `G` (0x47) genesis; `1`,`2`,`3` (0x31-0x33) = index + 1 into `REASONS` (sink.rs:25) | `encode` 66; `init` 224 (`b'G'`); `commit` 172 (`b'1' + kind`) | `scan` 90 (`G` at index 0), 92 (`'1'..='3'` after) | `FieldsOf(r).kind`; `ReasonOf`, `KindOf` | genesis: not `G` = `REJECT_BAD_GENESIS`; commit: not `1`..`3` = `REJECT_REASON_NOT_ALLOWED` |
| 4..12 | epoch, u64 LE | `encode` 67; init 0; commit `l.epoch + 1` (172) | `scan` 87: equal to the record index | `FromLE(r[4..12])` | equal to the record index, else `REJECT_EPOCH_MISMATCH` (index 0: `REJECT_BAD_GENESIS`) |
| 12..28 | pre-state hash, u128 LE: FNV-1a-128 of the whole previous 64-byte record; 0 in the genesis | `encode` 68; commit `l.tail` (172); `scan` 96 sets `tail = fnv128(r)` | `scan` 88: `== l.tail` | `FromLE(r[12..28])`; `Fnv128` | equal to the FNV-1a-128 of record i-1, else `REJECT_CHAIN_MISMATCH` (index 0: must be 0, else `REJECT_BAD_GENESIS`) |
| 28..52 | id, in CLEAR: 1 to 24 bytes of `[A-Za-z0-9_-]`, then NUL bytes to 52. Genesis: the charge id. Commit: the request id | `encode` 69 (`id.len()` bytes, the rest stays 0 from line 65) | `scan` 85 (up to the first NUL), 88 (`canonical_id`, padding all 0) | `NulAt`, `IdFieldOk`, `FieldsOf(r).id` | a byte outside the set before the first NUL, or a non-NUL byte after it: `REJECT_MALFORMED_RECORD`; empty id: commit `REJECT_EMPTY_ID`, genesis `REJECT_BAD_GENESIS` |
| 52..60 | amount, u64 LE. Genesis: the original amount. Commit: the refund amount. UNSIGNED: no negative value exists in the format | `encode` 70 | `scan` 86 | `FromLE(r[52..60])` (a mathematical integer 0..2^64-1; no arithmetic before the bound checks) | genesis: above 2^63-1 = `REJECT_BAD_GENESIS`; commit: above 2^63-1 (what a signed reader would call negative) = `REJECT_AMOUNT_NOT_MONEY`; above the remaining amount = `REJECT_AMOUNT_OVER_REMAINING` |
| 60..64 | CRC-32/IEEE (poly 0xEDB88320, init and final xor 0xFFFFFFFF) of bytes 0..60, u32 LE | `encode` 71-72; `crc32` 43-50 | `scan` 87 | `Crc32` (`CrcUpTo`, `CrcBits`, `CrcShift`); `CrcOk` | else `REJECT_BAD_CRC` |

Facts that follow:

- **No field is only hashed.** The request id and the reason (as the kind byte) are in clear in each record, the
  charge id and the original amount are in clear in the genesis record. The specification's `RefundRequest(requestId,
  amount, reason)` is read directly from each record, and `Genesis(chargeId, original, true)` (owner decision D1)
  from record 0. **No witness file is needed.** `--witness` is refused (see VERDICTS.md).
- **No field states the remaining amount, the settled set or the reason text.** The remaining amount after a
  record is recomputed by the fold; it cannot be compared with a stated value. A control "stated remaining does not
  match" cannot be built from this format.
- **The refund flag is not stored** (D1: the verifier takes `refundEnabled = true` at genesis).
- **What seals a record.** Each record carries its own CRC-32 over bytes 0..60. It catches accidental damage: every
  single-bit error and every burst of up to 32 bits (a property of CRC-32; in this work it is TESTED, bit by bit,
  not proved). It authenticates nothing: anyone who can write the file can recompute it. Records 0..n-2 are also
  bound by the pre-state hash of the next record (FNV-1a-128; not cryptographic either).
- **Trap A, the last record.** Its only seal in the file is its own CRC-32. So a flipped bit in the last record is
  rejected (`REJECT_BAD_CRC`), but a deliberate rewrite of the last record with a recomputed CRC is ACCEPTED from the
  log alone. The anchor for the last record is `--expect-tip`: the FNV-1a-128 of the last record, which the sink
  prints in each `COMMITTED <epoch> <hex>` line (sink.rs:187) and in `STATE <epoch> <hex> …` (sink.rs:231, 239).
- **Trap B, clean truncation.** Removing whole records from the end leaves a valid shorter log: ACCEPT from the log
  alone. Anchors: `--expect-count` (number of commits = final epoch), `--expect-tip`, and the ratchet file (an entry
  above the WAL's epoch gives `REJECT_RATCHET_AHEAD`). A joint restore of BOTH files is not detectable without an
  outside anchor (hypothesis H_LOG.1 / H_ROLLBACK of Report D).
- **Torn tail.** A file whose length is not a multiple of 64 ends in a part of fewer than 64 bytes. The sink treats
  it as a torn append and cuts it on its next start (sink.rs:98, 119-123). The verifier never reads it as a
  record and reports its length (`ACCEPT_TORN_TAIL`, `torn_bytes`). A WHOLE last record that fails any check is not
  treated as torn: it is a REJECT (the sink, by contrast, cuts it or refuses with EPOCH_REGRESSION, sink.rs:95-98,
  118-123).
- **Canonical decoding** (proved, `EncodeDecode` and `DecodeEncode`): a record that passes the framing checks is
  exactly `Encode(FieldsOf(r))`; there is no second spelling and no ignored byte. Every byte is either checked
  (magic, id, padding, CRC, epoch, pre-state hash, genesis kind) or decoded into a value that the rule judges (kind,
  amount).

- **Ids.** A request id may equal the charge id: the sink (sink.rs:56, 92, 167) and the specification
  (`RequestOpen` looks only at the settled set) both accept it; so does the verifier.
- **Two spellings of one hash value.** The sink prints the FNV-1a-128 of a record as 32 lowercase hex digits,
  most significant first (`{:032x}`, sink.rs:187, 231, 239); the next record stores the same value little-endian in
  bytes 12..28. `--expect-tip` and the output field `tail` use the PRINTED form (32 lowercase hex digits, big-endian
  text), so the value of a `COMMITTED` or `STATE` line can be passed unchanged.
- **The sink and the verifier can differ at the tail.** On every open the sink silently cuts up to 64 trailing bytes
  that do not form a valid record (sink.rs:98, 119-123): a torn append, but also a whole forged or damaged last
  record whose ratchet entry is missing (floor < its epoch). The verifier reports what it SAW: a partial tail as
  `ACCEPT_TORN_TAIL` (exit 4), a whole bad last record as a `REJECT_*`. So "what the sink recovered" and "what the
  verifier reads" may differ exactly at the tail; compare after the sink's recovery only if that is the question.
- **Authenticity: none.** CRC-32 and FNV-1a-128 are not keyed and not cryptographic. Anyone who can write the
  file can rewrite ANY record and recompute every later chain value and CRC; the result is accepted if it is a valid
  history. So ACCEPT establishes "these bytes are a valid history of the ratified specification", NOT "these bytes
  are what the engine wrote". Authenticity needs an outside anchor: `--expect-tip` or `--expect-count` from a trusted
  source, a witness under another uid, an external log (Report D, V2-V4).
- **`--expect-tip` is FNV-1a-128 too.** It anchors against accidental or naive change, not against an adversary who
  can search for a second record (or a whole second log) with the same FNV-1a-128 value. The cost of such a search
  was NOT established in this work. FNV-1a is not designed to resist it (it is a multiply-xor hash without a key;
  its structure is open to algebraic attacks), so the safe reading is: no security against a deliberate forger.
  An anchor against an adversary would need a cryptographic digest of the file, taken by a party the forger cannot
  influence; this verifier does not compute one.

- **Two compiled targets, and what their agreement shows.** The proved Dafny file is compiled twice: by Dafny's
  Python back end (trusted: that back end, Dafny's Python runtime, CPython 3.10, `verify_refund_log.py`) and by its
  JavaScript back end (trusted: that back end, Dafny's JS runtime, bignumber.js 9.3.1, Node 24.3.0,
  `verify_refund_log_node.cjs`). Neither compiler nor runtime is verified. Equal verdict lines of the two programs
  on the tested inputs are a FINITE TEST: a cross-check of two unverified compilers and runtimes, not a proof. It
  catches a fault that only one target has, on those inputs; it cannot catch a fault both have, nor one on inputs
  not tested. It has already caught one: Dafny 4.11.0's JS runtime computes bit-vector `^` (and `|`) with
  JavaScript's 32-bit signed operators on 53-bit chunks, so `0xFFFFFFFF ^ 0x31` came out as -50, every CRC was wrong
  and the first Node build refused every log with `REJECT_BAD_CRC index=0`. Repair in the Dafny source: the two XORs
  of the program (`Xor32`, `XorByte128`) have compiled bodies whose `^` and `&` see only operands below 2^16, each
  PROVED equal to the plain `^`; the model's meaning did not change. What bounds a fault of the same kind in the
  Python target: its CRC-32 and FNV-1a-128 values are byte-equal to the real Rust sink's on real logs (each record's
  stored CRC is recomputed and every chain value is compared; the printed tail equals the sink's `COMMITTED` and
  `STATE` values), the tests' independent forger computes CRC-32 bit by bit and checks it against zlib's, and Python integers are unbounded (its runtime
  maps `^` to Python's `^`). This bounds the fault class on the tested inputs only.

## 2. `ledger.epoch`: the ratchet, 12-byte entries (sink.rs:101-104, 112-123)

| Bytes of an entry | Content | sink.rs | Verifier |
| --- | --- | --- | --- |
| 0..8 | an epoch, u64 LE | `push` 102-103 | `EntryEpoch` |
| 8..12 | CRC-32 of bytes 0..8, u32 LE | `push` 103 | `EntryOk`; a whole entry with a bad CRC: `REJECT_RATCHET_BAD_ENTRY` (the sink SKIPS such an entry, sink.rs:114) |

The sink's floor is the highest valid entry (sink.rs:115; none: CORRUPT_WAL, 116); a WAL epoch below it is
`EPOCH_REGRESSION` (sink.rs:118). The verifier: no whole entry = `REJECT_RATCHET_NO_ENTRY`; floor above the WAL's final epoch =
`REJECT_RATCHET_AHEAD`; floor equal to or below it = consistent (floor = epoch - 1 is the sink's crash window between
the WAL sync and the ratchet entry, sink.rs:183-184, repaired at the next start, sink.rs:119-123). A trailing part of
fewer than 12 bytes is reported as `ratchet_torn_bytes`.

## 3. Bounds

Integers are mathematical in Dafny: a u64 field is read as 0..2^64-1 and compared with `MaxMoney = 2^63-1` and with
the remaining amount BEFORE the subtraction, so no wrap can occur. The cap exists for bounded memory and time of one run (the shim holds the bytes as a
Python list). Measured on this machine (one run each, FINITE TEST, not a bound): 65,535 commits with ordinary ids
33.6 s and 142 MB peak; 65,535 commits whose ids all collide under the former base-31 bucket hash 44.3 s and 293 MB
(16,000 such commits: 10.5 s; with the former hash 95.4 s, quadratic). The settled-id table is now indexed by a
polynomial hash at a point drawn at random for each run (`os.urandom`) modulo 2^61-1: a log written in advance
cannot aim its ids at one bucket, so the EXPECTED time is linear; the worst case (all ids in one bucket) is still
quadratic and is reachable only by someone who knows the run's key. The verdict never depends on the key (proved). A second measurement
under heavy machine load (load average 20-30; same inputs): Python 43.0 s / 135 MB (ordinary) and 48.6 s / 290 MB
(colliding); the JavaScript target 1,217 s / 292 MB (ordinary) and 1,189 s / 345 MB (colliding). The JavaScript
target is about 25 times slower because Dafny's JS runtime computes every `bv32`/`bv128` operation of CRC-32 and
FNV-1a-128 with BigNumber (about 15 ms of CRC per record); its time is still linear in the number of records. The proofs need only
some bound below 2^64 records (the epoch is a u64); 65,536 is a resource choice, far above the logs of the tests,
and NOT a property of the sink, which has no cap. Size classes: at most 65,536 whole records
(4 MiB, `MaxBytes`) in the WAL and 3 MiB (`MaxRatchetBytes`) in the ratchet; a larger file is
`UNVERIFIABLE_TOO_LARGE`, and the shim never reads more than the bound + 1 byte.
