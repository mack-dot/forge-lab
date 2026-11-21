//! Scalars mod L, the order of the Ed25519 prime-order subgroup.
//! L = 2^252 + 27742317777372353535851937790883648493.
//!
//! Reduction is done by plain binary long division (shift / compare / subtract).
//! That is slower than a Barrett or Montgomery reduction and much easier to audit
//! by eye, which is the right trade for a verifier. Nothing here wraps: every
//! add/sub is checked or explicitly carried.
//!
//! The L constant below is independently validated at runtime by
//! `ed25519::self_check()`, which asserts [L]B is the identity point. A wrong L
//! could not pass that test.

/// L as four little-endian 64-bit limbs.
pub const L: [u64; 4] = [
    0x5812631a5cf5d3ed,
    0x14def9dea2f79cd6,
    0x0000000000000000,
    0x1000000000000000,
];

/// A scalar in [0, L).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Scalar(pub [u64; 4]);

#[inline]
fn ge(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

/// a -= b, assuming a >= b.
#[inline]
fn sub_assign(a: &mut [u64; 4], b: &[u64; 4]) {
    let mut borrow = 0u64;
    for i in 0..4 {
        let (d, b1) = a[i].overflowing_sub(b[i]);
        let (d, b2) = d.overflowing_sub(borrow);
        a[i] = d;
        borrow = (b1 as u64) | (b2 as u64);
    }
}

/// a = a*2 + bit, returning the bit shifted out of the top.
#[inline]
fn shl1_add(a: &mut [u64; 4], bit: u64) -> u64 {
    let mut carry = bit;
    for i in 0..4 {
        let new_carry = a[i] >> 63;
        a[i] = (a[i] << 1) | carry;
        carry = new_carry;
    }
    carry
}

impl Scalar {
    pub const ZERO: Scalar = Scalar([0, 0, 0, 0]);

    /// Reduce an arbitrary little-endian byte string mod L. Accepts any length
    /// (32 and 64 are the sizes RFC 8032 needs).
    pub fn reduce_le(bytes: &[u8]) -> Scalar {
        let mut r = [0u64; 4];
        // MSB-first over the whole input
        for byte_idx in (0..bytes.len()).rev() {
            let b = bytes[byte_idx];
            for bit in (0..8).rev() {
                let out = shl1_add(&mut r, ((b >> bit) & 1) as u64);
                // r < L < 2^253 before the shift, so the shift cannot overflow
                // 256 bits; `out` is therefore always 0. Checked, not assumed.
                debug_assert_eq!(out, 0);
                if out != 0 || ge(&r, &L) {
                    sub_assign(&mut r, &L);
                }
            }
        }
        Scalar(r)
    }

    /// Strict decode of a 32-byte little-endian scalar; None when value >= L.
    /// RFC 8032 §5.1.7 requires rejecting a signature whose S is not reduced.
    pub fn from_canonical_le32(b: &[u8; 32]) -> Option<Scalar> {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let mut t = [0u8; 8];
            t.copy_from_slice(&b[i * 8..i * 8 + 8]);
            limbs[i] = u64::from_le_bytes(t);
        }
        if ge(&limbs, &L) {
            None
        } else {
            Some(Scalar(limbs))
        }
    }

    pub fn to_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..4 {
            out[i * 8..i * 8 + 8].copy_from_slice(&self.0[i].to_le_bytes());
        }
        out
    }

    /// (self + other) mod L
    pub fn add(self, o: Scalar) -> Scalar {
        let mut r = [0u64; 4];
        let mut carry = 0u64;
        for i in 0..4 {
            let (s, c1) = self.0[i].overflowing_add(o.0[i]);
            let (s, c2) = s.overflowing_add(carry);
            r[i] = s;
            carry = (c1 as u64) + (c2 as u64);
        }
        // both inputs < L < 2^253, so the sum is < 2^254: no 256-bit carry out
        debug_assert_eq!(carry, 0);
        if carry != 0 || ge(&r, &L) {
            sub_assign(&mut r, &L);
        }
        Scalar(r)
    }

    /// (self * other) mod L, via a 512-bit schoolbook product then reduction.
    pub fn mul(self, o: Scalar) -> Scalar {
        let mut prod = [0u64; 8];
        for i in 0..4 {
            let mut carry: u128 = 0;
            for j in 0..4 {
                let t = (self.0[i] as u128) * (o.0[j] as u128)
                    + (prod[i + j] as u128)
                    + carry;
                prod[i + j] = t as u64;
                carry = t >> 64;
            }
            prod[i + 4] = carry as u64;
        }
        let mut le = [0u8; 64];
        for i in 0..8 {
            le[i * 8..i * 8 + 8].copy_from_slice(&prod[i].to_le_bytes());
        }
        Scalar::reduce_le(&le)
    }

    pub fn is_zero(self) -> bool {
        self.0 == [0, 0, 0, 0]
    }
}
