| call | n | direct median / p95 (ms) | via airlock median / p95 (ms) | overhead median / p95 (ms) |
| --- | --- | --- | --- | --- |
| read_text_file (real fs server, stdio), allowed pass-through | 120 | 0.64 / 1.13 | 1.81 / 19.4 | 1.17 / 18.27 |
| get_status (mock HTTP), allowed pass-through | 120 | 1.27 / 2.0 | 2.53 / 7.96 | 1.26 / 5.96 |
| charge amount=1 (mock HTTP), gated by the compiled verifier | 120 | 1.43 / 3.11 | 298.35 / 495.75 | 296.92 / 492.64 |
