# Fixed golden vectors of the refund-log verifier (Task V1)

These are five WAL files of the real native silicon sink (`src/silicon_sink/sink.rs`, SHA-256 `1962af4a…db71`), each
with its ratchet. 1,248 bytes in total. They were produced on 2026-11-20 with
`python3 tests/refund_log_verifier/golden_rust.py --write-golden <new folder>`, using the pinned
`rustc 1.92.0 (ded5c06cf 2025-12-08)`, `-D unsafe_code -C opt-level=3`, and the refund binary `b8ed5ec2…7bb8`.
The scenarios and plants are defined in `golden_rust.py` (`GOLDEN`, `PLANTS`). FINITE TEST. `end_to_end=false`.

| File | Bytes | SHA-256 | How it was produced | Expected verdict |
| --- | --- | --- | --- | --- |
| `one_commit.wal` | 128 | `5d62987381da70ad3346231bede97336c461b8d0f7ee238b6ae3ea409bec3028` | scenario `one_commit`: init `charge-1` 1000; commit `rq-1` 250 `returned_item` | `ACCEPT` |
| `one_commit.epoch` | 24 | `a3ce1784886bd57d75531acdbc79a20ed4e31d04942e6b2792ed07dbf4f81f33` | its ratchet | |
| `zero_amount.wal` | 256 | `e16e80f7a9411f892290bb8d222e9e78ea18a77abafd4c44b9c59b0ac65bad54` | scenario `zero_amount`: init 50; `rq-z0` 0, `rq-1` 50, `rq-z1` 0 (owner decision D2) | `ACCEPT` |
| `zero_amount.epoch` | 48 | `4b794eb51fe437ffb99b8803e451a0c02511bb5d2b4ec436fd83ea6276d76482` | its ratchet | |
| `crash_b_split32_before_cut.wal` | 224 | `40331c79c083aded862e382a315f813e382811f95ec2b151295e811b973219a7` | scenario `crash_b_split32`: init 1000; `rq-1` 10, `rq-2` 20; then `victim` 30 in the `--cfg kill_points` build, SIGKILL at point `b` with `SINK_KILL_SPLIT=32`. These are the files as the kill left them, before the sink's cut: 3 whole records + 32 bytes | `ACCEPT_TORN_TAIL`, `torn_bytes=32`, 2 records |
| `crash_b_split32_before_cut.epoch` | 36 | `d47f0cb68ba63e1a44d4e606b7788d8ade6c9e513164d2085c5a6e84eb61bec3` | its ratchet | |
| `plant_amount_check_removed_wrap.wal` | 256 | `66e0250cfef5545d21349b55c1892a1d495239d5670167b9509f642260d4237e` | the planted copy `amount_check_removed` (3 checks of the amount removed): init MaxMoney; `rq-a` MaxMoney, `rq-b` MaxMoney, `rq-c` 2. The planted fold wraps back to remaining == original (Trap C) | `REJECT_AMOUNT_OVER_REMAINING`, `index=2` |
| `plant_amount_check_removed_wrap.epoch` | 48 | `4b794eb51fe437ffb99b8803e451a0c02511bb5d2b4ec436fd83ea6276d76482` | its ratchet | |
| `plant_reason_check_removed.wal` | 192 | `e40dc6178c460717cdbe9e60080fa90b661ded6e605cd8e7774936dd4008b08f` | the planted copy `reason_check_removed` (the rejection frame taken as an accept; an unknown reason gets index 3): init 100; `rq-1` 10; `rq-2` 5 `other`, kind byte `4` | `REJECT_REASON_NOT_ALLOWED`, `index=2` |
| `plant_reason_check_removed.epoch` | 36 | `d47f0cb68ba63e1a44d4e606b7788d8ade6c9e513164d2085c5a6e84eb61bec3` | its ratchet | |

Equal ratchet digests are expected: a ratchet holds only the epochs 0..n, so ratchets with the same n are equal.

Reproducibility: a store holds no time, no random value and no path. The record bytes are a function of the
requests. The kill-point build writes exactly `SINK_KILL_SPLIT` bytes before the kill. So each of the five vectors is
expected to be reproducible. The group `tracked_golden` of `test_golden_rust.py` checks this: it compares every
tracked file byte for byte with a fresh real-sink run of the same scenario or plant, and runs the compiled verifier
on the tracked files. A reproducibility claim holds only for the runs that passed that comparison.
