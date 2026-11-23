| call | n | direct median / p95 (ms) | via airlock median / p95 (ms) | overhead median / p95 (ms) |
| --- | --- | --- | --- | --- |
| read_text_file (real fs server, stdio), allowed pass-through | 120 | 0.8 / 1.27 | 1.78 / 2.63 | 0.98 / 1.36 |
| get_status (mock HTTP), allowed pass-through | 120 | 1.74 / 3.09 | 2.56 / 3.74 | 0.82 / 0.65 |
| charge amount=1 (mock HTTP), gated by the compiled verifier | 120 | 1.39 / 2.31 | 22.67 / 30.33 | 21.28 / 28.02 |
