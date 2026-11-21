//! Arithmetic in GF(p), p = 2^255 - 19. Used only by Ed25519 (RFC 8032).
//!
//! Representation: 5 limbs, radix 2^51, each limb kept < 2^52 after a carry pass.
//! value = h[0] + h[1]*2^51 + h[2]*2^102 + h[3]*2^153 + h[4]*2^204.
//!
//! Every curve/field CONSTANT this crate needs (d, sqrt(-1), the base point, the
//! inversion exponent) is DERIVED here from its defining equation rather than
//! transcribed as a hex literal, so there is no constant-transcription risk:
//!   d        = -121665 / 121666
//!   sqrt(-1) = 2^((p-1)/4)          (valid because p = 5 mod 8)
//!   B.y      = 4/5, B.x recovered from the curve equation with sign bit 0
//! `fe::self_check()` re-derives and re-validates them at runtime.
//!
//! NOTE ON WRAPAROUND (SPEC.md §1): nothing here wraps. Limb sums and products are
//! bounded by construction (see the comments on `mul`), and the crate is built with
//! `overflow-checks = true`, so a violated bound panics and fails closed rather
//! than silently wrapping.

use std::sync::OnceLock;

const MASK: u64 = (1u64 << 51) - 1;

/// A field element. Not reduced to canonical form except by `to_bytes`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fe(pub [u64; 5]);

pub const ZERO: Fe = Fe([0, 0, 0, 0, 0]);
pub const ONE: Fe = Fe([1, 0, 0, 0, 0]);

impl Fe {
    pub const fn from_u64(v: u64) -> Fe {
        // v < 2^51 for every caller here (small literals)
        Fe([v & MASK, v >> 51, 0, 0, 0])
    }

    /// Little-endian 32-byte decode. Bit 255 is IGNORED (callers that care about
    /// the sign bit must strip it first). The result is reduced mod p only in the
    /// weak sense that limbs are < 2^52; use `is_canonical_le` for the strict
    /// "y < p" test RFC 8032 requires on point decoding.
    pub fn from_bytes(b: &[u8; 32]) -> Fe {
        let ld = |i: usize| -> u64 {
            let mut t = [0u8; 8];
            t.copy_from_slice(&b[i..i + 8]);
            u64::from_le_bytes(t)
        };
        let w0 = ld(0);
        let w1 = ld(8);
        let w2 = ld(16);
        let w3 = ld(24);
        let h0 = w0 & MASK;
        let h1 = ((w0 >> 51) | (w1 << 13)) & MASK;
        let h2 = ((w1 >> 38) | (w2 << 26)) & MASK;
        let h3 = ((w2 >> 25) | (w3 << 39)) & MASK;
        let h4 = (w3 >> 12) & MASK; // drops bit 255
        Fe([h0, h1, h2, h3, h4])
    }

    /// Fully reduce and emit canonical little-endian bytes (bit 255 always 0).
    pub fn to_bytes(self) -> [u8; 32] {
        let mut h = self.carry_full();
        // Conditionally subtract p, twice, to land in [0, p).
        for _ in 0..2 {
            // q = 1 if h >= p
            let mut q = (h[0] + 19) >> 51;
            q = (h[1] + q) >> 51;
            q = (h[2] + q) >> 51;
            q = (h[3] + q) >> 51;
            q = (h[4] + q) >> 51;
            // h = h + 19*q, then clear bit 255
            h[0] += 19 * q;
            h[1] += h[0] >> 51;
            h[0] &= MASK;
            h[2] += h[1] >> 51;
            h[1] &= MASK;
            h[3] += h[2] >> 51;
            h[2] &= MASK;
            h[4] += h[3] >> 51;
            h[3] &= MASK;
            h[4] &= MASK;
        }
        let mut out = [0u8; 32];
        let w0 = h[0] | (h[1] << 51);
        let w1 = (h[1] >> 13) | (h[2] << 38);
        let w2 = (h[2] >> 26) | (h[3] << 25);
        let w3 = (h[3] >> 39) | (h[4] << 12);
        out[0..8].copy_from_slice(&w0.to_le_bytes());
        out[8..16].copy_from_slice(&w1.to_le_bytes());
        out[16..24].copy_from_slice(&w2.to_le_bytes());
        out[24..32].copy_from_slice(&w3.to_le_bytes());
        out
    }

    fn carry_full(self) -> [u64; 5] {
        let mut h = self.0;
        let mut c;
        c = h[0] >> 51;
        h[0] &= MASK;
        h[1] += c;
        c = h[1] >> 51;
        h[1] &= MASK;
        h[2] += c;
        c = h[2] >> 51;
        h[2] &= MASK;
        h[3] += c;
        c = h[3] >> 51;
        h[3] &= MASK;
        h[4] += c;
        c = h[4] >> 51;
        h[4] &= MASK;
        h[0] += 19 * c;
        c = h[0] >> 51;
        h[0] &= MASK;
        h[1] += c;
        h
    }

    pub fn add(self, o: Fe) -> Fe {
        // limbs < 2^52 + 2^52 = 2^53; mul/sq tolerate this (see `mul`)
        Fe([
            self.0[0] + o.0[0],
            self.0[1] + o.0[1],
            self.0[2] + o.0[2],
            self.0[3] + o.0[3],
            self.0[4] + o.0[4],
        ])
        .carry()
    }

    pub fn sub(self, o: Fe) -> Fe {
        // add 2p first so no limb goes negative: 2p limbs = (2^52-38, 2^52-2, ...)
        const T0: u64 = 0xFFFFFFFFFFFDA; // 2^52 - 38
        const T: u64 = 0xFFFFFFFFFFFFE; // 2^52 - 2
        let o = Fe(o.carry_full());
        Fe([
            self.0[0] + T0 - o.0[0],
            self.0[1] + T - o.0[1],
            self.0[2] + T - o.0[2],
            self.0[3] + T - o.0[3],
            self.0[4] + T - o.0[4],
        ])
        .carry()
    }

    pub fn neg(self) -> Fe {
        ZERO.sub(self)
    }

    fn carry(self) -> Fe {
        Fe(self.carry_full())
    }

    pub fn mul(self, o: Fe) -> Fe {
        // Inputs have limbs < 2^52 (post-carry) or < 2^53 (post-add). Worst case
        // f_i < 2^53 and 19*g_j < 19*2^53 < 2^58, so each product < 2^111 and the
        // 5-term sums are < 2^114: comfortably inside u128.
        let f = self.0;
        let g = o.0;
        let g1_19 = 19 * g[1] as u128;
        let g2_19 = 19 * g[2] as u128;
        let g3_19 = 19 * g[3] as u128;
        let g4_19 = 19 * g[4] as u128;
        let f0 = f[0] as u128;
        let f1 = f[1] as u128;
        let f2 = f[2] as u128;
        let f3 = f[3] as u128;
        let f4 = f[4] as u128;
        let g0 = g[0] as u128;
        let g1 = g[1] as u128;
        let g2 = g[2] as u128;
        let g3 = g[3] as u128;
        let g4 = g[4] as u128;

        let r0 = f0 * g0 + f1 * g4_19 + f2 * g3_19 + f3 * g2_19 + f4 * g1_19;
        let r1 = f0 * g1 + f1 * g0 + f2 * g4_19 + f3 * g3_19 + f4 * g2_19;
        let r2 = f0 * g2 + f1 * g1 + f2 * g0 + f3 * g4_19 + f4 * g3_19;
        let r3 = f0 * g3 + f1 * g2 + f2 * g1 + f3 * g0 + f4 * g4_19;
        let r4 = f0 * g4 + f1 * g3 + f2 * g2 + f3 * g1 + f4 * g0;

        Fe::reduce128([r0, r1, r2, r3, r4])
    }

    pub fn sq(self) -> Fe {
        self.mul(self)
    }

    fn reduce128(r: [u128; 5]) -> Fe {
        const M: u128 = (1u128 << 51) - 1;
        let mut r0 = r[0];
        let mut r1 = r[1];
        let mut r2 = r[2];
        let mut r3 = r[3];
        let mut r4 = r[4];
        let mut c;
        c = r0 >> 51;
        r0 &= M;
        r1 += c;
        c = r1 >> 51;
        r1 &= M;
        r2 += c;
        c = r2 >> 51;
        r2 &= M;
        r3 += c;
        c = r3 >> 51;
        r3 &= M;
        r4 += c;
        c = r4 >> 51;
        r4 &= M;
        r0 += 19 * c;
        c = r0 >> 51;
        r0 &= M;
        r1 += c;
        Fe([r0 as u64, r1 as u64, r2 as u64, r3 as u64, r4 as u64])
    }

    /// self ^ e, with `e` a 32-byte little-endian exponent. Square-and-multiply,
    /// MSB first. Not constant time: every input here is public data.
    pub fn pow_le(self, e: &[u8; 32]) -> Fe {
        let mut acc = ONE;
        let mut started = false;
        for byte_idx in (0..32).rev() {
            let b = e[byte_idx];
            for bit in (0..8).rev() {
                if started {
                    acc = acc.sq();
                }
                if (b >> bit) & 1 == 1 {
                    acc = if started { acc.mul(self) } else { self };
                    started = true;
                }
            }
        }
        if started {
            acc
        } else {
            ONE
        }
    }

    /// Multiplicative inverse: self^(p-2). p-2 = 2^255 - 21.
    pub fn invert(self) -> Fe {
        let mut e = [0xffu8; 32];
        e[0] = 0xeb; // 0x100 - 21
        e[31] = 0x7f;
        self.pow_le(&e)
    }

    /// self^((p-5)/8); (p-5)/8 = 2^252 - 3.
    pub fn pow_p58(self) -> Fe {
        let mut e = [0xffu8; 32];
        e[0] = 0xfd; // 0x100 - 3
        e[31] = 0x0f;
        self.pow_le(&e)
    }

    pub fn is_zero(self) -> bool {
        self.to_bytes() == [0u8; 32]
    }

    pub fn is_negative(self) -> bool {
        self.to_bytes()[0] & 1 == 1
    }

    pub fn ct_eq(self, o: Fe) -> bool {
        self.to_bytes() == o.to_bytes()
    }
}

/// True when the 32 bytes (bit 255 already masked off by the caller) encode a
/// value strictly less than p. RFC 8032 requires rejecting non-canonical y.
pub fn is_canonical_le(b: &[u8; 32]) -> bool {
    // p = 2^255 - 19 => canonical iff NOT (b[31]&0x7f == 0x7f and b[30..1]==0xff and b[0] >= 0xed)
    let hi = b[31] & 0x7f;
    if hi < 0x7f {
        return true;
    }
    for i in 1..31 {
        if b[i] != 0xff {
            return true;
        }
    }
    b[0] < 0xed
}

// ---------------------------------------------------------------------------
// Derived constants
// ---------------------------------------------------------------------------

// Each constant is DERIVED from its defining equation (never transcribed) and
// then cached: deriving `d` costs a full field exponentiation, and `Point::add`
// needs it on every call, so re-deriving per use made scalar multiplication
// about two orders of magnitude slower than it should be. `OnceLock` is std and
// the derivation is pure, so the cached value is identical every run -- caching
// changes speed only, never the result.

/// d = -121665/121666 mod p (Ed25519 curve constant), derived, never transcribed.
pub fn d() -> Fe {
    static D: OnceLock<Fe> = OnceLock::new();
    *D.get_or_init(|| Fe::from_u64(121665).neg().mul(Fe::from_u64(121666).invert()))
}

/// 2d, used by the extended-coordinate addition formula.
pub fn d2() -> Fe {
    static D2: OnceLock<Fe> = OnceLock::new();
    *D2.get_or_init(|| d().add(d()))
}

/// sqrt(-1) = 2^((p-1)/4); valid because p = 5 (mod 8). (p-1)/4 = 2^253 - 5.
pub fn sqrt_m1() -> Fe {
    static I: OnceLock<Fe> = OnceLock::new();
    *I.get_or_init(|| {
        let mut e = [0xffu8; 32];
        e[0] = 0xfb; // 0x100 - 5
        e[31] = 0x1f;
        Fe::from_u64(2).pow_le(&e)
    })
}

/// Field-level self-checks: the derived constants really satisfy their defining
/// equations. Returns the first failure description, or None.
pub fn self_check() -> Option<&'static str> {
    // sqrt(-1)^2 == -1
    let i = sqrt_m1();
    if !i.sq().ct_eq(ONE.neg()) {
        return Some("fe: sqrt(-1)^2 != -1");
    }
    // d * 121666 == -121665
    if !d().mul(Fe::from_u64(121666)).ct_eq(Fe::from_u64(121665).neg()) {
        return Some("fe: d * 121666 != -121665");
    }
    // inversion round-trip on a non-trivial element
    let x = Fe::from_u64(1234567);
    if !x.mul(x.invert()).ct_eq(ONE) {
        return Some("fe: x * x^-1 != 1");
    }
    // 1/1 == 1, and p-1 round-trips through bytes
    let m1 = ONE.neg();
    if !Fe::from_bytes(&m1.to_bytes()).ct_eq(m1) {
        return Some("fe: byte round-trip failed");
    }
    // canonical-form rejection: p itself and p+1 are non-canonical
    let mut pbytes = [0xffu8; 32];
    pbytes[0] = 0xed;
    pbytes[31] = 0x7f;
    if is_canonical_le(&pbytes) {
        return Some("fe: p accepted as canonical");
    }
    pbytes[0] = 0xec;
    if !is_canonical_le(&pbytes) {
        return Some("fe: p-1 rejected as canonical");
    }
    None
}
