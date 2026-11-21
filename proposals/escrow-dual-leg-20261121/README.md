# Escrow dual-leg verifier — Leg 2 freeze (commit-reveal), 2026-11-21

This commit **pre-registers** the Rust escrow verifier (Leg 2), published PUBLICLY **before** the
Dafny verifier (Leg 1) is ever committed to this repository. That ordering is what makes the later
two-leg agreement a genuine clean-room N-version check, not a copy: Leg 2 was frozen against the spec
before any differential against Leg 1 existed.

`leg2_frozen.json` pins:
- `spec_packet_hash` `51d1d035…` — the frozen spec packet (SPEC.md + README + ACCEPTANCE + generator +
  56 golden vectors) that BOTH legs implement.
- `leg2_source_tree_sha256` `cdec66ea…` — the exact Leg 2 source (load-bearing commitment).
- `leg2_binary_sha256`, `rustc_version_string`, `built_offline`, `timestamp`.

Leg 2 was built by a different model (GPT), from the spec alone, with hand-rolled SHA-256/512 + Ed25519
and zero dependencies. Leg 1 (Dafny, proved) is built independently and will be committed in a later PR
with the cross-leg differential and mutation receipts.

Honest labels (carried from the freeze record): verifier = NATIVE CHECK, agreement = FINITE TEST,
`end_to_end = false`. This file is a hash commitment; it contains no secrets.
