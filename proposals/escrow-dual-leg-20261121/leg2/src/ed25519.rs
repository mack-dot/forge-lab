//! Ed25519 (RFC 8032) verification, hand-rolled. Rust std only.
//!
//! SPEC.md §5.2 step 9 / README §3: the escrow signature check is an Ed25519
//! signature over `record_seal`, verified against a genesis-pinned key. The
//! co-signed tape layout that would carry those signatures is an OPEN decision
//! (D-TAPE), so this module supplies the primitive and the predicate; the wiring
//! is gated (see verify.rs / SPEC_QUESTIONS.md Q11).
//!
//! Verification profile (STRICT, documented in DECISIONS.md):
//!   * S must be canonically reduced (S < L), else reject;
//!   * A and R must be canonical point encodings (y < p), else reject;
//!   * the cofactorless equation [S]B = R + [k]A is checked. RFC 8032 §5.1.7
//!     permits either this or the [8]-multiplied form; cofactorless is strictly
//!     stronger, so it cannot accept anything the cofactored check rejects.
//!
//! Signing is implemented ONLY so the implementation can be validated against the
//! RFC 8032 §7.1 known-answer vectors end to end (secret -> public, secret ->
//! signature). The verifier binary never signs anything.

use crate::fe::{self, Fe};
use crate::scalar::Scalar;
use crate::sha2::sha512;

/// Point in extended homogeneous coordinates: x = X/Z, y = Y/Z, T = XY/Z.
#[derive(Clone, Copy, Debug)]
pub struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

pub fn identity() -> Point {
    Point { x: fe::ZERO, y: fe::ONE, z: fe::ONE, t: fe::ZERO }
}

impl Point {
    /// add-2008-hwcd-3, unified (complete) for a = -1 with non-square d, so it is
    /// also used for doubling. No exceptional cases to special-case.
    pub fn add(&self, o: &Point) -> Point {
        let d2 = fe::d2();
        let a = self.y.sub(self.x).mul(o.y.sub(o.x));
        let b = self.y.add(self.x).mul(o.y.add(o.x));
        let c = self.t.mul(d2).mul(o.t);
        let d = self.z.mul(o.z);
        let d = d.add(d);
        let e = b.sub(a);
        let f = d.sub(c);
        let g = d.add(c);
        let h = b.add(a);
        Point { x: e.mul(f), y: g.mul(h), t: e.mul(h), z: f.mul(g) }
    }

    /// Dedicated doubling (dbl-2008-hwcd for a = -1): ~5 field multiplications
    /// against ~10 for the unified addition, and doublings dominate the ladder.
    /// `tests/ed25519_edge.rs::dedicated_doubling_matches_addition` pins it
    /// against `add(P, P)` so the shortcut cannot drift from the group law.
    pub fn double(&self) -> Point {
        let a = self.x.sq();
        let b = self.y.sq();
        let zz = self.z.sq();
        let c = zz.add(zz);
        let d = a.neg(); // a = -1
        let e = self.x.add(self.y).sq().sub(a).sub(b);
        let g = d.add(b);
        let f = g.sub(c);
        let h = d.sub(b);
        Point { x: e.mul(f), y: g.mul(h), t: e.mul(h), z: f.mul(g) }
    }

    pub fn neg(&self) -> Point {
        Point { x: self.x.neg(), y: self.y, z: self.z, t: self.t.neg() }
    }

    /// Affine coordinates.
    pub fn affine(&self) -> (Fe, Fe) {
        let zi = self.z.invert();
        (self.x.mul(zi), self.y.mul(zi))
    }

    /// RFC 8032 §5.1.2 point encoding: little-endian y with x's low bit in bit 255.
    pub fn encode(&self) -> [u8; 32] {
        let (x, y) = self.affine();
        let mut out = y.to_bytes();
        out[31] |= (x.is_negative() as u8) << 7;
        out
    }

    pub fn is_identity(&self) -> bool {
        let (x, y) = self.affine();
        x.is_zero() && y.ct_eq(fe::ONE)
    }

    /// -x^2 + y^2 == 1 + d*x^2*y^2
    pub fn is_on_curve(&self) -> bool {
        let (x, y) = self.affine();
        let xx = x.sq();
        let yy = y.sq();
        let lhs = yy.sub(xx);
        let rhs = fe::ONE.add(fe::d().mul(xx).mul(yy));
        lhs.ct_eq(rhs)
    }

    /// [k]self over the 32-byte little-endian scalar, 4-bit windowed and MSB
    /// first: 256 doublings plus at most 64 additions, against ~128 additions
    /// for the bit-at-a-time ladder.
    ///
    /// Not constant time, by design: every input in this program is public
    /// bytes (a public key, an R from a signature, a log record's seal), so
    /// there is no secret to leak through the window pattern. The addition
    /// formula is complete for this curve, so the identity needs no special
    /// case and the loop has no start-up branch.
    pub fn mul_scalar_le(&self, k: &[u8; 32]) -> Point {
        // table[i] = (i+1) * self
        let mut table = [*self; 15];
        for i in 1..15 {
            table[i] = table[i - 1].add(self);
        }
        let mut acc = identity();
        for byte_idx in (0..32).rev() {
            for shift in [4u32, 0u32] {
                acc = acc.double().double().double().double();
                let nib = ((k[byte_idx] >> shift) & 0x0f) as usize;
                if nib != 0 {
                    acc = acc.add(&table[nib - 1]);
                }
            }
        }
        acc
    }
}

/// RFC 8032 §5.1.3 point decompression. None on any non-canonical or off-curve
/// encoding.
pub fn decompress(b: &[u8; 32]) -> Option<Point> {
    let sign = b[31] >> 7;
    let mut yb = *b;
    yb[31] &= 0x7f;
    if !fe::is_canonical_le(&yb) {
        return None; // y >= p: non-canonical encoding
    }
    let y = Fe::from_bytes(&yb);
    let yy = y.sq();
    let u = yy.sub(fe::ONE); // y^2 - 1
    let v = fe::d().mul(yy).add(fe::ONE); // d*y^2 + 1

    let v3 = v.sq().mul(v);
    let mut x = v3.sq().mul(v).mul(u); // u * v^7
    x = x.pow_p58(); // (u*v^7)^((p-5)/8)
    x = x.mul(v3).mul(u); // u*v^3 * (u*v^7)^((p-5)/8)

    let vxx = v.mul(x.sq());
    if !vxx.ct_eq(u) {
        if vxx.ct_eq(u.neg()) {
            x = x.mul(fe::sqrt_m1());
        } else {
            return None; // not a square: no such point
        }
    }
    // re-verify after the sqrt(-1) correction
    if !v.mul(x.sq()).ct_eq(u) {
        return None;
    }
    if x.is_zero() && sign == 1 {
        return None; // RFC 8032: x = 0 with sign bit set is invalid
    }
    if x.is_negative() != (sign == 1) {
        x = x.neg();
    }
    let t = x.mul(y);
    Some(Point { x, y, z: fe::ONE, t })
}

/// True when `enc` decodes to a point of small order, i.e. `[8]A == identity`.
/// Those are the 8 torsion points; a signature check against such a pinned key
/// is vacuous or near-vacuous (see SPEC_QUESTIONS.md Q14). Returns false for
/// bytes that are not a valid point encoding at all -- those are not keys.
///
/// RFC 8032 mandates no key-validity check, so this is NOT called from the
/// verification path; it is offered for the genesis-level check Q14 proposes.
pub fn is_small_order(enc: &[u8; 32]) -> bool {
    match decompress(enc) {
        Some(p) => p.double().double().double().is_identity(),
        None => false,
    }
}

/// The Ed25519 base point: y = 4/5, x the even root. Derived, not transcribed,
/// then cached (see the note in fe.rs: derivation is pure, so caching affects
/// speed only).
pub fn basepoint() -> Point {
    static B: std::sync::OnceLock<Point> = std::sync::OnceLock::new();
    *B.get_or_init(|| {
        let y = Fe::from_u64(4).mul(Fe::from_u64(5).invert());
        let mut enc = y.to_bytes();
        enc[31] &= 0x7f; // sign bit 0 -> the even x, per RFC 8032 §5.1
        // decompress cannot fail for the curve's own base point
        match decompress(&enc) {
            Some(p) => p,
            None => identity(), // unreachable; self_check() catches it if it is
        }
    })
}

/// RFC 8032 §5.1.7 verification. `msg` is the signed message (for the escrow use
/// this is the 32-byte `record_seal`).
pub fn verify(public_key: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
    if sig.len() != 64 {
        return false;
    }
    let mut rb = [0u8; 32];
    rb.copy_from_slice(&sig[0..32]);
    let mut sb = [0u8; 32];
    sb.copy_from_slice(&sig[32..64]);

    // S must be reduced (rejects the trivial malleability).
    let s = match Scalar::from_canonical_le32(&sb) {
        Some(s) => s,
        None => return false,
    };
    let a_point = match decompress(public_key) {
        Some(p) => p,
        None => return false,
    };
    let r_point = match decompress(&rb) {
        Some(p) => p,
        None => return false,
    };

    let mut hasher = crate::sha2::Sha512::new();
    hasher.update(&rb);
    hasher.update(public_key);
    hasher.update(msg);
    let k = Scalar::reduce_le(&hasher.finalize());

    let lhs = basepoint().mul_scalar_le(&s.to_bytes());
    let rhs = r_point.add(&a_point.mul_scalar_le(&k.to_bytes()));
    lhs.encode() == rhs.encode()
}

// ---------------------------------------------------------------------------
// Signing: test-only, used to validate against RFC 8032 §7.1 end to end.
// ---------------------------------------------------------------------------

/// Expand a 32-byte secret seed into (scalar a, prefix) per RFC 8032 §5.1.5.
fn expand(seed: &[u8; 32]) -> (Scalar, [u8; 32]) {
    let h = sha512(seed);
    let mut a = [0u8; 32];
    a.copy_from_slice(&h[0..32]);
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;
    let mut prefix = [0u8; 32];
    prefix.copy_from_slice(&h[32..64]);
    (Scalar::reduce_le(&a), prefix)
}

pub fn public_key(seed: &[u8; 32]) -> [u8; 32] {
    let (a, _) = expand(seed);
    basepoint().mul_scalar_le(&a.to_bytes()).encode()
}

pub fn sign(seed: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    let (a, prefix) = expand(seed);
    let pk = basepoint().mul_scalar_le(&a.to_bytes()).encode();

    let mut h1 = crate::sha2::Sha512::new();
    h1.update(&prefix);
    h1.update(msg);
    let r = Scalar::reduce_le(&h1.finalize());
    let rp = basepoint().mul_scalar_le(&r.to_bytes()).encode();

    let mut h2 = crate::sha2::Sha512::new();
    h2.update(&rp);
    h2.update(&pk);
    h2.update(msg);
    let k = Scalar::reduce_le(&h2.finalize());

    let s = r.add(k.mul(a));
    let mut out = [0u8; 64];
    out[0..32].copy_from_slice(&rp);
    out[32..64].copy_from_slice(&s.to_bytes());
    out
}

// ---------------------------------------------------------------------------
// Runtime self-checks on the derived constants and the group law.
// ---------------------------------------------------------------------------

/// Validates the curve constants and group arithmetic without any external
/// vector. In particular `[L]B == identity` independently confirms the L
/// constant in scalar.rs and the correctness of scalar multiplication.
pub fn self_check() -> Option<&'static str> {
    if let Some(e) = fe::self_check() {
        return Some(e);
    }
    let b = basepoint();
    if !b.is_on_curve() {
        return Some("ed25519: base point not on curve");
    }
    if b.is_identity() {
        return Some("ed25519: base point derivation failed");
    }
    // the canonical encoding of B (RFC 8032 §5.1): y = 4/5, x even
    let (bx, _) = b.affine();
    if bx.is_negative() {
        return Some("ed25519: base point x has the wrong parity");
    }
    // encode/decode round-trip
    match decompress(&b.encode()) {
        Some(p) => {
            if p.encode() != b.encode() {
                return Some("ed25519: point round-trip mismatch");
            }
        }
        None => return Some("ed25519: base point failed to decompress"),
    }
    // [L]B == identity  -> validates L and the scalar ladder
    let mut lb = [0u8; 32];
    for i in 0..4 {
        lb[i * 8..i * 8 + 8].copy_from_slice(&crate::scalar::L[i].to_le_bytes());
    }
    if !b.mul_scalar_le(&lb).is_identity() {
        return Some("ed25519: [L]B != identity");
    }
    // [L+1]B == B
    let mut l1 = lb;
    // L+1: the low byte of L is 0xed, so incrementing it cannot carry
    l1[0] += 1;
    if b.mul_scalar_le(&l1).encode() != b.encode() {
        return Some("ed25519: [L+1]B != B");
    }
    // 8*B is not the identity (B generates the prime-order subgroup)
    if b.double().double().double().is_identity() {
        return Some("ed25519: [8]B == identity");
    }
    // RFC 8032 §5.1.3: y = 1 forces x = 0, so the sign bit MUST be 0. The same
    // bytes with bit 255 set must be rejected.
    let mut ident = [0u8; 32];
    ident[0] = 1;
    if decompress(&ident).is_none() {
        return Some("ed25519: rejected the valid identity encoding");
    }
    let mut bad = ident;
    bad[31] |= 0x80;
    if decompress(&bad).is_some() {
        return Some("ed25519: accepted x=0 with sign bit 1");
    }
    // a non-canonical y (y = p) must be rejected
    let mut noncanon = [0xffu8; 32];
    noncanon[0] = 0xed;
    noncanon[31] = 0x7f;
    if decompress(&noncanon).is_some() {
        return Some("ed25519: accepted a non-canonical y encoding");
    }
    None
}
