# Vendored dependencies: NONE

No external crates to vendor. `Cargo.toml` has an empty `[dependencies]` section
and `Cargo.lock` contains exactly one package — this crate itself:

    $ cargo tree --offline
    leg2-verify v0.2.1 (.)

SHA-256, SHA-512 and Ed25519 are hand-rolled in `src/sha2.rs`, `src/fe.rs`,
`src/scalar.rs` and `src/ed25519.rs` (README §1.3 permits this; DECISIONS.md D1.1
says why it was chosen over a vetted crate each).

Build: `cargo build --offline --release`  (rustc 1.70+; developed on 1.97.0)
Keep the release profile as shipped — `overflow-checks = true` and
`panic = "unwind"` are load-bearing, see BUILD.md.
