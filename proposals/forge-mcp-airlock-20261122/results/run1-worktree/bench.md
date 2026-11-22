| call | n | direct median / p95 (ms) | via airlock median / p95 (ms) | overhead median / p95 (ms) |
| --- | --- | --- | --- | --- |
| read_text_file (real fs server, stdio), allowed pass-through | 120 | 1.06 / 4.18 | 3.12 / 10.1 | 2.06 / 5.92 |
| get_status (mock HTTP), allowed pass-through | 120 | 1.72 / 3.32 | 3.03 / 6.81 | 1.31 / 3.49 |
| charge amount=1 (mock HTTP), gated by the compiled verifier | 120 | 1.48 / 3.04 | 317.8 / 537.78 | 316.32 / 534.74 |
