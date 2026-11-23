| call | n | direct median / p95 (ms) | via airlock median / p95 (ms) | overhead median / p95 (ms) |
| --- | --- | --- | --- | --- |
| read_text_file (real fs server, stdio), allowed pass-through | 120 | 2.29 / 27.24 | 2.04 / 3.42 | -0.25 / -23.82 |
| get_status (mock HTTP), allowed pass-through | 120 | 1.92 / 3.63 | 3.66 / 8.38 | 1.74 / 4.75 |
| charge amount=1 (mock HTTP), gated by the compiled verifier | 120 | 1.6 / 2.89 | 338.16 / 776.48 | 336.56 / 773.59 |
