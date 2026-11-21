//! leg2-verify -- Leg 2 of a 2-of-2 independent verifier for the Forge V2 escrow
//! log (Domain 2), built from the SPEC.md in the Leg-2 implementer packet alone.
//!
//! Label (README §0): UNPROVED-but-independent-toolchain. This is a NATIVE CHECK.
//! Agreement with Leg 1 would be an N-version FINITE TEST, not a proof.
//!
//! Trusted base (README §1.3): Rust std only. SHA-256, SHA-512 and Ed25519 are
//! hand-rolled in this crate; there are no third-party dependencies.

pub mod ed25519;
pub mod fe;
pub mod record;
pub mod scalar;
pub mod sha2;
pub mod spec;
pub mod verdict;
pub mod verify;

/// Lowercase hex of a byte slice.
pub fn to_hex(b: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push(HEX[(byte >> 4) as usize] as char);
        s.push(HEX[(byte & 0x0f) as usize] as char);
    }
    s
}

/// Parse exactly 64 hex characters into 32 bytes. Case-insensitive. None on any
/// wrong length or non-hex character.
pub fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let nib = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = nib(bytes[i * 2])?;
        let lo = nib(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

/// Run every built-in cryptographic self-check. Returns the first failure.
pub fn crypto_self_check() -> Option<&'static str> {
    // SHA-256 FIPS 180-4 anchor: the empty string and "abc".
    if sha2::sha256(b"abc")
        != [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ]
    {
        return Some("sha256(\"abc\") mismatch");
    }
    if sha2::sha256(b"")
        != [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ]
    {
        return Some("sha256(\"\") mismatch");
    }
    ed25519::self_check()
}
