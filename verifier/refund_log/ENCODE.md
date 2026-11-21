# The proved encoder as a program: `verify-refund-log --encode`

```
build/refund_log_verifier/verify-refund-log --encode <history.json> --out <new file> [--json]
```

It writes the WAL bytes that the Dafny model encoder `RefundLogVerifier.EncodeLog` yields for a history, so that a
test can compare them byte for byte with the `ledger.wal` that the real Rust sink wrote for the same history. The
encoder is the same compiled code that the theorems speak of (`EncodeLog`, with a loop in place of the recursion,
proved equal). The JSON parsing is in the UNVERIFIED shim (`verify_refund_log.py`, in the trusted base): it only
checks the JSON types and hands plain values to the proved method `EncodeEntry`.

## Input

One JSON object, UTF-8, exactly these keys:

```json
{"charge": "ch_1", "original": 100,
 "records": [{"id": "rq_1", "reason": "returned_item", "amount": 40},
             {"id": "rq_2", "reason": "duplicate_charge", "amount": 0}]}
```

- `charge`: the charge id (genesis record, bytes 28..52).
- `original`: the original amount (genesis, bytes 52..60), a JSON integer.
- `records`: the committed refunds in commit order. `id` = request id; `reason` = one of `duplicate_charge`,
  `service_not_delivered`, `returned_item` (written as kind byte `1`, `2`, `3`); `amount` = a JSON integer.
- The epoch of record i is i, its pre-state hash is the FNV-1a-128 of record i-1: the encoder computes both. They
  are never input.

## Output and exit codes

- Exit 0: `ENCODED records=<n> bytes=<64(n+1)> tail=<32 hex> spec_sha256=… sink_sha256=…`, and `<new file>` holds the
  bytes. The shim writes them to a temporary file in the same folder (`O_EXCL`), calls `fsync`, and only then
  hard-links it to `<new file>` (which fails if that name exists: nothing is ever replaced) and removes the
  temporary name. On any failure no file of that name is left and the temporary name is removed. Proved (`EncodeEntry` postcondition): the
  bytes are `EncodeLog(Genesis(charge, original, true), history)`, the history is `ValidHistory` of the ratified
  specification, and the verifier ACCEPTS the bytes.
- Exit 3, no file written:
  - `UNVERIFIABLE_OUT_EXISTS`: `<new file>` exists already (checked before the encoding and again by the link).
  - `UNVERIFIABLE_OUT_WRITE_FAILED`: the bytes could not be written, synced or linked.
  - `UNVERIFIABLE_ENCODE_INPUT`: not this JSON form (also: an object with a repeated key, at any depth: the
    parser refuses it instead of keeping the last value); or an id that is not 0..24 bytes of `[A-Za-z0-9_-]`; or an
    amount or original outside 0..2^64-1; or more than 65,535 records; or the file cannot be read.
  - `UNVERIFIABLE_INVALID_HISTORY`: the ratified specification refuses the history (for example an empty id or
    charge id, an original above 2^63-1, a repeated request id, an amount above the remaining amount, a reason
    outside the three). The encoder never writes such a history: to make an invalid log for a test, use the
    independent forger (tests), not this program.
- `UNVERIFIABLE_USAGE` (exit 3): the arguments are not one of the two usage lines.
