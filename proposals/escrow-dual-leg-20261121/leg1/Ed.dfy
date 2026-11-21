// Ed.dfy — Ed25519 STRICT verification profile for Leg 1 (SPEC.md §9.3).
// Clean-room from RFC 8032 + SPEC §9.3. Cofactorless [S]B == R + [k]A, reject
// non-canonical A/R (y >= p), reject S >= L, reject small-order A (BAD_KEY) and
// small-order R (BAD_SIGNATURE). Affine twisted-Edwards (a = -1); the addition
// law is complete (d non-square), so identity (0,1) needs no special case.
// Not proved correct; self-tested against RFC 8032 vector 1 and the spec's
// own golden signature vectors.
include "./Sha.dfy"
module Ed {
  import opened Sha

  const P: int := 57896044618658097711785492504343953926634992332820282019728792003956564819949
  const L: int := 7237005577332262213973186563042994240857116359379907606001950938285454250989
  const D: int := 37095705934669439343138083508754565189542113879843219016388785533085940283555
  const BX: int := 15112221349535400772501151409588531511454012693041857206046113283949847762202
  const BY: int := 46316835694926478169428394003475163141307993866256225615783033603165251855960
  const SQRTM1: int := 19681161376707505956807079304988542015446066515923890162744021073123829784752

  datatype Point = Pt(x: int, y: int)

  function Fp(a: int): int { a % P }

  function Mul(a: int, b: int): int { (a * b) % P }
  function Add(a: int, b: int): int { (a + b) % P }
  function Sub(a: int, b: int): int { ((a - b) % P + P) % P }

  method ModPow(base: int, exp: int, m: int) returns (r: int)
    requires m > 0
    requires exp >= 0
    ensures 0 <= r < m
  {
    r := 1 % m;
    var b := ((base % m) + m) % m;
    var e := exp;
    while e > 0
      invariant e >= 0
      invariant 0 <= r < m
      invariant 0 <= b < m
      decreases e
    {
      if e % 2 == 1 { r := (r * b) % m; }
      b := (b * b) % m;
      e := e / 2;
    }
  }

  method Inv(a: int) returns (r: int)
    ensures 0 <= r < P
  { r := ModPow(((a % P) + P) % P, P - 2, P); }

  // Complete affine addition on twisted Edwards (a = -1).
  method PAdd(p1: Point, p2: Point) returns (r: Point) {
    var x1 := ((p1.x % P) + P) % P; var y1 := ((p1.y % P) + P) % P;
    var x2 := ((p2.x % P) + P) % P; var y2 := ((p2.y % P) + P) % P;
    var x1y2 := Mul(x1, y2);
    var y1x2 := Mul(y1, x2);
    var y1y2 := Mul(y1, y2);
    var x1x2 := Mul(x1, x2);
    var dxy := Mul(Mul(D, x1x2), y1y2);     // d*x1*x2*y1*y2
    var xnum := Add(x1y2, y1x2);
    var xden := Add(1 % P, dxy);
    var ynum := Add(y1y2, x1x2);            // y1y2 - a*x1x2 with a=-1
    var yden := Sub(1 % P, dxy);
    var xdi := Inv(xden);
    var ydi := Inv(yden);
    r := Pt(Mul(xnum, xdi), Mul(ynum, ydi));
  }

  method PDouble(p1: Point) returns (r: Point) { r := PAdd(p1, p1); }

  const IDENT: Point := Pt(0, 1)

  function PEq(a: Point, b: Point): bool {
    (((a.x % P) + P) % P == ((b.x % P) + P) % P) &&
    (((a.y % P) + P) % P == ((b.y % P) + P) % P)
  }

  // scalar in [0, 2^256); double-and-add, high bit first.
  method ScalarMul(k: int, p0: Point) returns (r: Point)
    requires k >= 0
  {
    r := IDENT;
    // find top bit
    var bits := 0; var t := k;
    while t > 0 invariant t >= 0 decreases t { bits := bits + 1; t := t / 2; }
    var i := bits - 1;
    while i >= 0
      invariant i >= -1
      decreases i + 1
    {
      r := PDouble(r);
      // extract bit i of k
      var bit := (k / Pow2(i)) % 2;
      if bit == 1 { r := PAdd(r, p0); }
      i := i - 1;
    }
  }

  function Pow2(n: int): int
    requires n >= 0
    ensures Pow2(n) >= 1
    decreases n
  { if n == 0 then 1 else 2 * Pow2(n - 1) }

  // little-endian 32 bytes -> integer
  function LEInt(s: seq<byte>, off: nat, n: nat): int
    requires off + n <= |s|
    ensures LEInt(s, off, n) >= 0
    decreases n
  { if n == 0 then 0 else (s[off] as int) + 256 * LEInt(s, off + 1, n - 1) }

  // Decode a 32-byte compressed point. Returns ok + point.
  // Reject non-canonical (y >= P). Reject not-on-curve.
  method DecodePoint(enc: seq<byte>) returns (ok: bool, pt: Point)
    requires |enc| == 32
  {
    var yfull := LEInt(enc, 0, 32);
    var sign := (yfull / Pow2(255)) % 2;      // top bit = x_0
    var y := yfull % Pow2(255);                // clear sign bit
    if y >= P { ok := false; pt := IDENT; return; }   // non-canonical
    // x^2 = (y^2 - 1) / (d y^2 + 1)
    var y2 := Mul(y, y);
    var u := Sub(y2, 1 % P);                    // y^2 - 1
    var v := Add(Mul(D, y2), 1 % P);            // d y^2 + 1
    // candidate x = u v^3 (u v^7)^((p-5)/8)
    var v2 := Mul(v, v);
    var v3 := Mul(v2, v);
    var v7 := Mul(Mul(v3, v3), v);
    var uv7 := Mul(u, v7);
    var pm5d8 := (P - 5) / 8;
    var pw := ModPow(uv7, pm5d8, P);
    var x := Mul(Mul(u, v3), pw);
    // check v*x^2 == u ; else multiply by sqrt(-1)
    var vx2 := Mul(v, Mul(x, x));
    if vx2 != ((u % P) + P) % P {
      var x2 := Mul(x, SQRTM1);
      var vx2b := Mul(v, Mul(x2, x2));
      if vx2b != ((u % P) + P) % P {
        ok := false; pt := IDENT; return;      // not on curve
      }
      x := x2;
    }
    // x sign handling
    if x == 0 {
      if sign == 1 { ok := false; pt := IDENT; return; }  // x==0 but sign set
    } else {
      if (x % 2) != sign { x := ((P - x) % P + P) % P; }
    }
    ok := true; pt := Pt(x, y);
  }

  // [8]P == identity ?
  method IsSmallOrder(p0: Point) returns (b: bool) {
    var p1 := PDouble(p0);
    var p2 := PDouble(p1);
    var p3 := PDouble(p2);     // [8]P
    b := PEq(p3, IDENT);
  }

  // Validate a public key per §3.2 step 6: canonical + non-small-order.
  // Returns 0 = ok, 1 = bad (non-canonical / not-on-curve / small-order).
  method ValidateKey(enc: seq<byte>) returns (code: int)
    requires |enc| == 32
  {
    var ok, pt := DecodePoint(enc);
    if !ok { code := 1; return; }
    var small := IsSmallOrder(pt);
    if small { code := 1; return; }
    code := 0;
  }

  // Strict signature verify. Message m, 32-byte key enc A, 64-byte sig (R||S).
  // Returns:  0 = valid ; 1 = BAD_SIGNATURE (any sig-side failure).
  // (Key-side small-order/non-canonical A is handled by ValidateKey earlier.)
  method VerifyStrict(Aenc: seq<byte>, sig: seq<byte>, m: seq<byte>) returns (code: int)
    requires |Aenc| == 32
  {
    if |sig| != 64 { code := 1; return; }
    var Renc := sig[0..32];
    var S := LEInt(sig, 32, 32);
    if S >= L { code := 1; return; }               // reject S >= L
    var okR, R := DecodePoint(Renc);
    if !okR { code := 1; return; }                 // non-canonical / off-curve R
    var okA, A := DecodePoint(Aenc);
    if !okA { code := 1; return; }
    // small-order R -> BAD_SIGNATURE
    var smallR := IsSmallOrder(R);
    if smallR { code := 1; return; }
    // k = SHA512(Renc || Aenc || m) mod L
    var hin := Renc + Aenc + m;
    var hk := Sha512(hin);
    var kfull := LEInt(hk, 0, 64);
    var k := kfull % L;
    // cofactorless: [S]B == R + [k]A
    var B := Pt(BX, BY);
    var left := ScalarMul(S, B);
    var kA := ScalarMul(k, A);
    var right := PAdd(R, kA);
    if PEq(left, right) { code := 0; } else { code := 1; }
  }
}
