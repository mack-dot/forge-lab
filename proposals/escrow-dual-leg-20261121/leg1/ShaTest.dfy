include "./Sha.dfy"
module ShaTest {
  import opened Sha
  method Hex(b: seq<byte>) returns (s: string) {
    var hexd := "0123456789abcdef";
    s := "";
    var i := 0;
    while i < |b| {
      var v := b[i] as int;
      s := s + [hexd[v / 16]] + [hexd[v % 16]];
      i := i + 1;
    }
  }
  method Bytes(msg: string) returns (r: seq<byte>) {
    r := []; var i := 0;
    while i < |msg| { r := r + [(msg[i] as int) as byte]; i := i + 1; }
  }
  method Main() {
    var abc := Bytes("abc");
    var d := Sha256(abc); var h := Hex(d); print "sha256(abc)=", h, "\n";
    var e := []; var d2 := Sha256(e); var h2 := Hex(d2); print "sha256()=", h2, "\n";
    var d3 := Sha512(abc); var h3 := Hex(d3); print "sha512(abc)=", h3, "\n";
    var d4 := Sha512(e); var h4 := Hex(d4); print "sha512()=", h4, "\n";
  }
}
