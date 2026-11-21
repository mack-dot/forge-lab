include "./Sha.dfy"
module BackendCheck {
  import opened Sha
  method Hex(b: seq<byte>) returns (s: string) {
    var hexd := "0123456789abcdef"; s := ""; var i := 0;
    while i < |b| { var v := b[i] as int; s := s + [hexd[v/16]] + [hexd[v%16]]; i := i+1; }
  }
  method Bytes(msg: string) returns (r: seq<byte>) {
    r := []; var i := 0; while i < |msg| { r := r + [(msg[i] as int) as byte]; i := i+1; }
  }
  method Main() {
    var abc := Bytes("abc"); var e: seq<byte> := [];
    var d := Sha256(abc); var h := Hex(d); print "sha256(abc)=", h, "\n";
    var d2 := Sha256(e); var h2 := Hex(d2); print "sha256()=", h2, "\n";
    var d3 := Sha512(abc); var h3 := Hex(d3); print "sha512(abc)=", h3, "\n";
    var d4 := Sha512(e); var h4 := Hex(d4); print "sha512()=", h4, "\n";
    // word-boundary bitwise table (#6584-sensitive values from SPEC §1)
    var xs: seq<bv32> := [0, 1, 0x7FFF, 0x8000, 0xFFFF, 0x10000, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF];
    var i := 0;
    while i < |xs| {
      var a := xs[i];
      print "x32 ", a as int, " xor=", Xor32(a,0x80000001) as int,
            " and=", And32(a,0xFFFFFFFF) as int, " or=", Or32(a,0x80000000) as int, "\n";
      i := i + 1;
    }
    var ys: seq<bv64> := [0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0x100000000, 0x1FFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF];
    i := 0;
    while i < |ys| {
      var a := ys[i];
      print "x64 ", a as int, " xor=", Xor64(a,0x8000000080000001) as int,
            " and=", And64(a,0xFFFFFFFFFFFFFFFF) as int, "\n";
      i := i + 1;
    }
  }
}
