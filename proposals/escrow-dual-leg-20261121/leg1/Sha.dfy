// Sha.dfy — SHA-256 and SHA-512 for Leg 1 (escrow verifier).
// Clean-room: built from FIPS 180-4 only. Not proved correct; self-tested
// against FIPS/known-answer vectors. Wide bitwise ops are guarded with the
// `by method` 16-bit-lane split that works around dafny-lang/dafny#6584
// (JS backend miscompiles &|^ on chunks with a bit >= 2^31). Python backend
// is unaffected; the guard also makes a JS build correct for a cross-check.
module Sha {
  newtype byte = x: int | 0 <= x < 256

  // ---- bv32 guarded bitwise ----
  function Xor32(a: bv32, b: bv32): bv32 { a ^ b } by method {
    return ((((a >> 16) ^ (b >> 16)) << 16)) + ((a & 0xFFFF) ^ (b & 0xFFFF));
  }
  function And32(a: bv32, b: bv32): bv32 { a & b } by method {
    return ((((a >> 16) & (b >> 16)) << 16)) + ((a & 0xFFFF) & (b & 0xFFFF));
  }
  function Or32(a: bv32, b: bv32): bv32 { a | b } by method {
    return ((((a >> 16) | (b >> 16)) << 16)) + ((a & 0xFFFF) | (b & 0xFFFF));
  }
  function Not32(a: bv32): bv32 { !a }
  function RotR32(x: bv32, n: int): bv32
    requires 0 <= n < 32
  { Or32(x >> n, x << (32 - n)) }
  function Shr32(x: bv32, n: int): bv32
    requires 0 <= n < 32
  { x >> n }

  // ---- bv64 guarded bitwise (16-bit lanes) ----
  function Xor64(a: bv64, b: bv64): bv64 { a ^ b } by method {
    return ((((a >> 48) ^ (b >> 48)) << 48))
         + (((((a >> 32) & 0xFFFF) ^ ((b >> 32) & 0xFFFF)) << 32))
         + (((((a >> 16) & 0xFFFF) ^ ((b >> 16) & 0xFFFF)) << 16))
         + ((a & 0xFFFF) ^ (b & 0xFFFF));
  }
  function And64(a: bv64, b: bv64): bv64 { a & b } by method {
    return ((((a >> 48) & (b >> 48)) << 48))
         + (((((a >> 32) & 0xFFFF) & ((b >> 32) & 0xFFFF)) << 32))
         + (((((a >> 16) & 0xFFFF) & ((b >> 16) & 0xFFFF)) << 16))
         + ((a & 0xFFFF) & (b & 0xFFFF));
  }
  function Or64(a: bv64, b: bv64): bv64 { a | b } by method {
    return ((((a >> 48) | (b >> 48)) << 48))
         + (((((a >> 32) & 0xFFFF) | ((b >> 32) & 0xFFFF)) << 32))
         + (((((a >> 16) & 0xFFFF) | ((b >> 16) & 0xFFFF)) << 16))
         + ((a & 0xFFFF) | (b & 0xFFFF));
  }
  function Not64(a: bv64): bv64 { !a }
  function RotR64(x: bv64, n: int): bv64
    requires 0 <= n < 64
  { Or64(x >> n, x << (64 - n)) }

  // ---- byte/word conversions ----
  function ByteToBv32(b: byte): bv32 { (b as bv32) }
  function Bv32ToByte(w: bv32): byte { ((w & 0xFF) as int) as byte }

  // big-endian 4 bytes -> bv32
  function BE32(s: seq<byte>, i: nat): bv32
    requires i + 4 <= |s|
  {
    ((s[i] as bv32) << 24) + ((s[i+1] as bv32) << 16) + ((s[i+2] as bv32) << 8) + (s[i+3] as bv32)
  }
  // bv32 -> 4 big-endian bytes
  function Bv32ToBE(w: bv32): seq<byte> {
    [ (((w >> 24) & 0xFF) as int) as byte,
      (((w >> 16) & 0xFF) as int) as byte,
      (((w >> 8) & 0xFF) as int) as byte,
      ((w & 0xFF) as int) as byte ]
  }
  function BE64(s: seq<byte>, i: nat): bv64
    requires i + 8 <= |s|
  {
    ((s[i] as bv64) << 56) + ((s[i+1] as bv64) << 48) + ((s[i+2] as bv64) << 40) + ((s[i+3] as bv64) << 32)
    + ((s[i+4] as bv64) << 24) + ((s[i+5] as bv64) << 16) + ((s[i+6] as bv64) << 8) + (s[i+7] as bv64)
  }
  function Bv64ToBE(w: bv64): seq<byte> {
    [ (((w >> 56) & 0xFF) as int) as byte, (((w >> 48) & 0xFF) as int) as byte,
      (((w >> 40) & 0xFF) as int) as byte, (((w >> 32) & 0xFF) as int) as byte,
      (((w >> 24) & 0xFF) as int) as byte, (((w >> 16) & 0xFF) as int) as byte,
      (((w >> 8) & 0xFF) as int) as byte, ((w & 0xFF) as int) as byte ]
  }

  // ================= SHA-256 =================
  const K256: seq<bv32> := [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 ]

  function Pad(msg: seq<byte>): seq<byte> {
    var ml := |msg| * 8;
    var withOne := msg + [0x80 as byte];
    var k := (56 - (|withOne| % 64) + 64) % 64;
    var zeros := seq(k, i => 0 as byte);
    var lenBytes := [ ((ml / 0x100000000000000) % 256) as byte,
                      ((ml / 0x1000000000000) % 256) as byte,
                      ((ml / 0x10000000000) % 256) as byte,
                      ((ml / 0x100000000) % 256) as byte,
                      ((ml / 0x1000000) % 256) as byte,
                      ((ml / 0x10000) % 256) as byte,
                      ((ml / 0x100) % 256) as byte,
                      (ml % 256) as byte ];
    withOne + zeros + lenBytes
  }

  function Ch32(e: bv32, f: bv32, g: bv32): bv32 { Xor32(And32(e, f), And32(Not32(e), g)) }
  function Maj32(a: bv32, b: bv32, c: bv32): bv32 { Xor32(Xor32(And32(a, b), And32(a, c)), And32(b, c)) }
  function BigS0(a: bv32): bv32 { Xor32(Xor32(RotR32(a, 2), RotR32(a, 13)), RotR32(a, 22)) }
  function BigS1(e: bv32): bv32 { Xor32(Xor32(RotR32(e, 6), RotR32(e, 11)), RotR32(e, 25)) }
  function Sig0(x: bv32): bv32 { Xor32(Xor32(RotR32(x, 7), RotR32(x, 18)), Shr32(x, 3)) }
  function Sig1(x: bv32): bv32 { Xor32(Xor32(RotR32(x, 17), RotR32(x, 19)), Shr32(x, 10)) }

  method BuildW256(block: seq<byte>) returns (w: seq<bv32>)
    requires |block| == 64
    ensures |w| == 64
  {
    var ws := new bv32[64];
    var t := 0;
    while t < 16 invariant 0 <= t <= 16 {
      ws[t] := BE32(block, t * 4);
      t := t + 1;
    }
    t := 16;
    while t < 64 invariant 16 <= t <= 64 {
      ws[t] := Sig1(ws[t-2]) + ws[t-7] + Sig0(ws[t-15]) + ws[t-16];
      t := t + 1;
    }
    w := ws[..];
  }

  method Sha256(msg: seq<byte>) returns (digest: seq<byte>)
    ensures |digest| == 32
  {
    var padded := Pad(msg);
    var h0: bv32 := 0x6a09e667; var h1: bv32 := 0xbb67ae85;
    var h2: bv32 := 0x3c6ef372; var h3: bv32 := 0xa54ff53a;
    var h4: bv32 := 0x510e527f; var h5: bv32 := 0x9b05688c;
    var h6: bv32 := 0x1f83d9ab; var h7: bv32 := 0x5be0cd19;
    var nblocks := |padded| / 64;
    var bi := 0;
    while bi < nblocks invariant 0 <= bi <= nblocks {
      var start := bi * 64;
      if start + 64 <= |padded| {
        var block := padded[start..start+64];
        var w := BuildW256(block);
        var a := h0; var b := h1; var c := h2; var d := h3;
        var e := h4; var f := h5; var g := h6; var h := h7;
        var t := 0;
        while t < 64 invariant 0 <= t <= 64 {
          var t1 := h + BigS1(e) + Ch32(e, f, g) + K256[t] + w[t];
          var t2 := BigS0(a) + Maj32(a, b, c);
          h := g; g := f; f := e; e := d + t1;
          d := c; c := b; b := a; a := t1 + t2;
          t := t + 1;
        }
        h0 := h0 + a; h1 := h1 + b; h2 := h2 + c; h3 := h3 + d;
        h4 := h4 + e; h5 := h5 + f; h6 := h6 + g; h7 := h7 + h;
      }
      bi := bi + 1;
    }
    digest := Bv32ToBE(h0) + Bv32ToBE(h1) + Bv32ToBE(h2) + Bv32ToBE(h3)
            + Bv32ToBE(h4) + Bv32ToBE(h5) + Bv32ToBE(h6) + Bv32ToBE(h7);
  }

  // ================= SHA-512 =================
  const K512: seq<bv64> := [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817 ]

  function Pad128(msg: seq<byte>): seq<byte> {
    // 128-byte blocks; 16-byte length field (we only fill the low 8 bytes).
    var ml := |msg| * 8;
    var withOne := msg + [0x80 as byte];
    var k := (112 - (|withOne| % 128) + 128) % 128;
    var zeros := seq(k, i => 0 as byte);
    var lenBytes := seq(8, i => 0 as byte) +
                  [ ((ml / 0x100000000000000) % 256) as byte,
                    ((ml / 0x1000000000000) % 256) as byte,
                    ((ml / 0x10000000000) % 256) as byte,
                    ((ml / 0x100000000) % 256) as byte,
                    ((ml / 0x1000000) % 256) as byte,
                    ((ml / 0x10000) % 256) as byte,
                    ((ml / 0x100) % 256) as byte,
                    (ml % 256) as byte ];
    withOne + zeros + lenBytes
  }

  function Ch64(e: bv64, f: bv64, g: bv64): bv64 { Xor64(And64(e, f), And64(Not64(e), g)) }
  function Maj64(a: bv64, b: bv64, c: bv64): bv64 { Xor64(Xor64(And64(a, b), And64(a, c)), And64(b, c)) }
  function BigT0(a: bv64): bv64 { Xor64(Xor64(RotR64(a, 28), RotR64(a, 34)), RotR64(a, 39)) }
  function BigT1(e: bv64): bv64 { Xor64(Xor64(RotR64(e, 14), RotR64(e, 18)), RotR64(e, 41)) }
  function SigT0(x: bv64): bv64 { Xor64(Xor64(RotR64(x, 1), RotR64(x, 8)), x >> 7) }
  function SigT1(x: bv64): bv64 { Xor64(Xor64(RotR64(x, 19), RotR64(x, 61)), x >> 6) }

  method BuildW512(block: seq<byte>) returns (w: seq<bv64>)
    requires |block| == 128
    ensures |w| == 80
  {
    var ws := new bv64[80];
    var t := 0;
    while t < 16 invariant 0 <= t <= 16 {
      ws[t] := BE64(block, t * 8);
      t := t + 1;
    }
    t := 16;
    while t < 80 invariant 16 <= t <= 80 {
      ws[t] := SigT1(ws[t-2]) + ws[t-7] + SigT0(ws[t-15]) + ws[t-16];
      t := t + 1;
    }
    w := ws[..];
  }

  method Sha512(msg: seq<byte>) returns (digest: seq<byte>)
    ensures |digest| == 64
  {
    var padded := Pad128(msg);
    var h0: bv64 := 0x6a09e667f3bcc908; var h1: bv64 := 0xbb67ae8584caa73b;
    var h2: bv64 := 0x3c6ef372fe94f82b; var h3: bv64 := 0xa54ff53a5f1d36f1;
    var h4: bv64 := 0x510e527fade682d1; var h5: bv64 := 0x9b05688c2b3e6c1f;
    var h6: bv64 := 0x1f83d9abfb41bd6b; var h7: bv64 := 0x5be0cd19137e2179;
    var nblocks := |padded| / 128;
    var bi := 0;
    while bi < nblocks invariant 0 <= bi <= nblocks {
      var start := bi * 128;
      if start + 128 <= |padded| {
        var block := padded[start..start+128];
        var w := BuildW512(block);
        var a := h0; var b := h1; var c := h2; var d := h3;
        var e := h4; var f := h5; var g := h6; var h := h7;
        var t := 0;
        while t < 80 invariant 0 <= t <= 80 {
          var t1 := h + BigT1(e) + Ch64(e, f, g) + K512[t] + w[t];
          var t2 := BigT0(a) + Maj64(a, b, c);
          h := g; g := f; f := e; e := d + t1;
          d := c; c := b; b := a; a := t1 + t2;
          t := t + 1;
        }
        h0 := h0 + a; h1 := h1 + b; h2 := h2 + c; h3 := h3 + d;
        h4 := h4 + e; h5 := h5 + f; h6 := h6 + g; h7 := h7 + h;
      }
      bi := bi + 1;
    }
    digest := Bv64ToBE(h0) + Bv64ToBE(h1) + Bv64ToBE(h2) + Bv64ToBE(h3)
            + Bv64ToBE(h4) + Bv64ToBE(h5) + Bv64ToBE(h6) + Bv64ToBE(h7);
  }
}
