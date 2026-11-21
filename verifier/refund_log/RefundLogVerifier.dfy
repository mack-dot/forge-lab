include "RatifiedSpecLemmas.dfy"
include "../../impl/Refund.dfy"

// Task V1: an independent verifier of the silicon sink's write-ahead log (ledger.wal), proved in Dafny against the
// RATIFIED stateful specification spec/refund/RefundLogSpec.dfy (SHA-256 1a8c7c2a...bc5a, read only, included by
// RatifiedSpecLemmas.dfy). The decoder is written against src/silicon_sink/sink.rs (SHA-256 1962af4a...db71); the
// line-by-line table is verifier/refund_log/FORMAT.md. Owner decisions used (unsure.md U928): D1, the genesis
// record initializes refundEnabled = true; D2, amount 0 is allowed (no extra conjunct: the ratified Allowed is used).
// PROVED here (one machine, pinned Dafny 4.11.0 and Z3 4.12.1): statements about THIS Dafny text. NOT proved: that the
// Rust engine writes what the model encoder writes (not needed for soundness: the verifier does not trust the engine);
// that the bytes read are the whole durable state (H_LOG); the Dafny compiler, the Python runtime and the file-reading
// shim. No assume, no axiom, no lemma without a body, no extern. end_to_end=false.

// The ratified specification, bound to the approved stateless implementation impl/Refund.dfy (unchanged). The
// specified decision returns Step. This is the same binding as proposals/refund-log-spec-20261120/RefundLogSpecInstance.dfy.
module RefundLogRatified refines RefundLogSpec {
  import R = Refund

  method Decide(s: LedgerState, q: RefundRequest) returns (r: Option<LedgerState>)
  {
    r := Step(s, q);
  }
}

// The proved lemmas about the specification (conservation, at most once, the fold), REUSED: RatifiedSpecLemmas.dfy is
// proposals/refund-log-spec-20261120/RefundLogSpecLemmas.dfy with only its include line changed to the ratified path.
module RefundLogRatifiedLemmas refines RefundLogSpecLemmas {
  import S = RefundLogRatified
}

// Format F: the 64-byte record of sink.rs, lines 7-11 (layout), 43-54 (CRC-32 and FNV-1a-128), 56 (id spelling),
// 64-74 (encode).
module SinkFormat {
  newtype byte = x: int | 0 <= x < 256

  const MAGIC: seq<byte> := [70, 83, 87]   // "FSW"
  const KIND_GENESIS: byte := 71           // 'G'

  function Pow256(n: nat): nat
  {
    if n == 0 then 1 else 256 * Pow256(n - 1)
  }

  lemma Pow256Values()
    ensures Pow256(4) == 4294967296
    ensures Pow256(8) == 18446744073709551616
    ensures Pow256(16) == 340282366920938463463374607431768211456
  {
    assert Pow256(1) == 256;
    assert Pow256(2) == 65536;
    assert Pow256(3) == 16777216;
    assert Pow256(4) == 4294967296;
    assert Pow256(5) == 1099511627776;
    assert Pow256(6) == 281474976710656;
    assert Pow256(7) == 72057594037927936;
    assert Pow256(8) == 18446744073709551616;
    assert Pow256(9) == 4722366482869645213696;
    assert Pow256(10) == 1208925819614629174706176;
    assert Pow256(11) == 309485009821345068724781056;
    assert Pow256(12) == 79228162514264337593543950336;
    assert Pow256(13) == 20282409603651670423947251286016;
    assert Pow256(14) == 5192296858534827628530496329220096;
    assert Pow256(15) == 1329227995784915872903807060280344576;
    assert Pow256(16) == 340282366920938463463374607431768211456;
  }

  // Little-endian bytes of v, n bytes long (Rust `to_le_bytes`), and back (Rust `from_le_bytes`).
  function LE(v: nat, n: nat): seq<byte>
    ensures |LE(v, n)| == n
  {
    if n == 0 then [] else [(v % 256) as byte] + LE(v / 256, n - 1)
  }

  function FromLE(b: seq<byte>): nat
  {
    if |b| == 0 then 0 else b[0] as nat + 256 * FromLE(b[1..])
  }

  lemma FromLEBound(b: seq<byte>)
    ensures FromLE(b) < Pow256(|b|)
  {
    if |b| > 0 {
      FromLEBound(b[1..]);
    }
  }

  lemma FromLEOfLE(v: nat, n: nat)
    requires v < Pow256(n)
    ensures FromLE(LE(v, n)) == v
  {
    if n > 0 {
      var t := LE(v, n);
      assert t[1..] == LE(v / 256, n - 1);
      assert v / 256 < Pow256(n - 1);
      FromLEOfLE(v / 256, n - 1);
    }
  }

  lemma LECons(b0: byte, x: nat, n: nat)
    ensures LE(b0 as nat + 256 * x, n + 1) == [b0] + LE(x, n)
  {
    DivMod256(b0 as int, x);
  }

  lemma FromLECons(b: seq<byte>)
    requires |b| > 0
    ensures FromLE(b) == b[0] as nat + 256 * FromLE(b[1..])
  {
  }

  lemma LEOfFromLE(b: seq<byte>)
    ensures LE(FromLE(b), |b|) == b
  {
    if |b| > 0 {
      FromLECons(b);
      LECons(b[0], FromLE(b[1..]), |b| - 1);
      LEOfFromLE(b[1..]);
      assert [b[0]] + b[1..] == b;
    }
  }

  lemma DivMod256(b0: int, x: int)
    requires 0 <= b0 < 256
    ensures (b0 + 256 * x) % 256 == b0 && (b0 + 256 * x) / 256 == x
  {
  }

  // CRC-32/IEEE, bit by bit, as sink.rs crc32 (lines 43-50): c = !0; per byte c ^= b, then 8 shifts; !c. The
  // recursion is not a tail call, so the compiled program recurses (depth at most 64) and raises no exception.
  // Dafny 4.11.0's JavaScript runtime computes `^` and `|` with JavaScript's 32-bit signed operators on 53-bit
  // chunks, which gives a wrong value when a chunk is 2^31 or more (found by the cross-check of the Python and the
  // JavaScript targets, 2026-11-20). The two XORs of the program therefore have a compiled body whose `^` and `&`
  // see only operands below 2^16; each body is PROVED equal to the plain `^` (the model text is unchanged in meaning).
  function Xor32(a: bv32, b: bv32): bv32
  {
    a ^ b
  } by method {
    return (((a >> 16) ^ (b >> 16)) << 16) + ((a & 0xFFFF) ^ (b & 0xFFFF));
  }

  function XorByte128(h: bv128, b: bv8): bv128
  {
    h ^ (b as bv128)
  } by method {
    return ((h >> 8) << 8) + ((h & 0xFF) ^ (b as bv128));
  }

  function CrcShift(c: bv32): bv32
  {
    if (c & 1) == 1 then Xor32(c >> 1, 0xEDB8_8320) else c >> 1
  }

  function CrcBits(c: bv32, k: nat): bv32
    decreases k
  {
    if k == 0 then c else CrcShift(CrcBits(c, k - 1))
  }

  function CrcUpTo(data: seq<byte>, n: nat): bv32
    requires n <= |data|
    decreases n
  {
    if n == 0 then 0xFFFF_FFFF else CrcBits(Xor32(CrcUpTo(data, n - 1), data[n - 1] as bv32), 8)
  }

  opaque function Crc32(data: seq<byte>): nat
  {
    (!CrcUpTo(data, |data|)) as nat
  }

  // FNV-1a, 128 bits, as sink.rs fnv128 (lines 52-54): h = offset; per byte h = (h ^ b) * prime mod 2^128.
  // NOT cryptographic.
  function FnvUpTo(data: seq<byte>, n: nat): bv128
    requires n <= |data|
    decreases n
  {
    if n == 0 then 0x6c62272e07bb014262b821756295c58d
    else XorByte128(FnvUpTo(data, n - 1), data[n - 1] as bv8) * 0x0000000001000000000000000000013b
  }

  opaque function Fnv128(data: seq<byte>): nat
    ensures Fnv128(data) < 340282366920938463463374607431768211456
  {
    FnvUpTo(data, |data|) as nat
  }

  // The byte set of an id (sink.rs canonical_id, line 56): [A-Za-z0-9_-]. It excludes 0 (NUL).
  predicate IdByte(b: byte)
  {
    (48 <= b <= 57) || (65 <= b <= 90) || (97 <= b <= 122) || b == 95 || b == 45
  }

  // The index of the first NUL at or after i, or |f| (sink.rs scan, line 85: `split(|&b| b == 0).next()`).
  function NulAt(f: seq<byte>, i: nat): nat
    requires i <= |f|
    ensures i <= NulAt(f, i) <= |f|
    ensures forall j | i <= j < NulAt(f, i) :: f[j] != 0
    ensures NulAt(f, i) < |f| ==> f[NulAt(f, i)] == 0
    decreases |f| - i
  {
    if i == |f| || f[i] == 0 then i else NulAt(f, i + 1)
  }

  // The id field [28..52): id bytes up to the first NUL, then only NUL (sink.rs scan, line 88, without the
  // non-emptiness, which the verifier reports separately as EMPTY_ID or BAD_GENESIS).
  predicate IdFieldOk(f: seq<byte>)
  {
    var k := NulAt(f, 0);
    (forall j | 0 <= j < k :: IdByte(f[j])) && (forall j | k <= j < |f| :: f[j] == 0)
  }

  predicate CrcOk(r: seq<byte>)
    requires |r| == 64
  {
    r[60..] == LE(Crc32(r[..60]), 4)
  }

  // A record is framed when its CRC holds, it starts with "FSW", and its id field is well spelled.
  predicate Framed(r: seq<byte>)
    requires |r| == 64
  {
    CrcOk(r) && r[..3] == MAGIC && IdFieldOk(r[28..52])
  }

  datatype Fields = Fields(kind: byte, epoch: nat, pre: nat, id: seq<byte>, amount: nat)

  // THE DECODER: the one reading of the fields of a 64-byte record.
  function FieldsOf(r: seq<byte>): Fields
    requires |r| == 64
  {
    Fields(r[3], FromLE(r[4..12]), FromLE(r[12..28]), r[28..28 + NulAt(r[28..52], 0)], FromLE(r[52..60]))
  }

  predicate FieldsOk(f: Fields)
  {
    f.epoch < Pow256(8) && f.pre < Pow256(16) && |f.id| <= 24 && (forall j | 0 <= j < |f.id| :: IdByte(f.id[j])) &&
    f.amount < Pow256(8)
  }

  function Zeros(n: nat): seq<byte>
  {
    seq(n, _ => 0)
  }

  // THE MODEL ENCODER, as sink.rs encode (lines 64-74): magic and kind, epoch, pre-state hash, id with NUL padding,
  // amount, then the CRC-32 of bytes 0..60.
  function Body(f: Fields): seq<byte>
    requires |f.id| <= 24
  {
    [MAGIC[0], MAGIC[1], MAGIC[2], f.kind] + LE(f.epoch, 8) + LE(f.pre, 16) + (f.id + Zeros(24 - |f.id|)) + LE(f.amount, 8)
  }

  function Encode(f: Fields): seq<byte>
    requires |f.id| <= 24
  {
    Body(f) + LE(Crc32(Body(f)), 4)
  }

  lemma EncodeSlices(f: Fields)
    requires |f.id| <= 24
    ensures |Body(f)| == 60 && |Encode(f)| == 64
    ensures Encode(f)[..60] == Body(f) && Encode(f)[60..] == LE(Crc32(Body(f)), 4)
    ensures Encode(f)[..3] == MAGIC && Encode(f)[3] == f.kind
    ensures Encode(f)[4..12] == LE(f.epoch, 8) && Encode(f)[12..28] == LE(f.pre, 16)
    ensures Encode(f)[28..52] == f.id + Zeros(24 - |f.id|) && Encode(f)[52..60] == LE(f.amount, 8)
  {
    var A: seq<byte> := [MAGIC[0], MAGIC[1], MAGIC[2], f.kind];
    var B, C, D, E := LE(f.epoch, 8), LE(f.pre, 16), f.id + Zeros(24 - |f.id|), LE(f.amount, 8);
    var b := Body(f);
    assert b == A + B + C + D + E;
    var e := Encode(f);
    assert e == b + LE(Crc32(b), 4);
    assert e[..60] == b;
    assert e[60..] == LE(Crc32(b), 4);
    assert e[..3] == MAGIC;
    assert e[3] == f.kind;
    assert e[4..12] == B by {
      forall j | 0 <= j < 8 ensures e[4 + j] == B[j] { assert e[4 + j] == b[4 + j]; }
    }
    assert e[12..28] == C by {
      forall j | 0 <= j < 16 ensures e[12 + j] == C[j] { assert e[12 + j] == b[12 + j]; }
    }
    assert e[28..52] == D by {
      forall j | 0 <= j < 24 ensures e[28 + j] == D[j] { assert e[28 + j] == b[28 + j]; }
    }
    assert e[52..60] == E by {
      forall j | 0 <= j < 8 ensures e[52 + j] == E[j] { assert e[52 + j] == b[52 + j]; }
    }
  }

  lemma IdFieldOfId(id: seq<byte>)
    requires |id| <= 24 && forall j | 0 <= j < |id| :: IdByte(id[j])
    ensures NulAt(id + Zeros(24 - |id|), 0) == |id|
    ensures IdFieldOk(id + Zeros(24 - |id|))
  {
    var f := id + Zeros(24 - |id|);
    var k := NulAt(f, 0);
    if k < |id| {
      assert f[k] == id[k] && IdByte(id[k]);
      assert false;
    }
    if k > |id| {
      assert f[|id|] != 0;
      assert f[|id|] == 0;
      assert false;
    }
  }

  // L1a (decode after encode): the model encoder's record is framed and decodes to exactly its fields.
  lemma {:isolate_assertions} DecodeEncode(f: Fields)
    requires FieldsOk(f)
    ensures |Encode(f)| == 64 && Framed(Encode(f)) && FieldsOf(Encode(f)) == f
  {
    EncodeSlices(f);
    IdFieldOfId(f.id);
    FromLEOfLE(f.epoch, 8);
    FromLEOfLE(f.pre, 16);
    FromLEOfLE(f.amount, 8);
    var e := Encode(f);
    var k := NulAt(e[28..52], 0);
    assert k == |f.id|;
    assert e[28..28 + k] == f.id by {
      forall j | 0 <= j < k ensures e[28 + j] == f.id[j] { assert e[28 + j] == e[28..52][j]; }
    }
  }

  // L1b (encode after decode): every framed record is exactly the model encoding of its decoded fields. So the
  // decoder's reading is the only reading of a framed record: two framed records with equal fields are equal.
  lemma Split60(r: seq<byte>)
    requires |r| == 64
    ensures r[..60] == r[..4] + r[4..12] + r[12..28] + r[28..52] + r[52..60]
    ensures r == r[..60] + r[60..]
    ensures r[..4] == r[..3] + [r[3]]
  {
  }

  lemma IdFieldBack(r: seq<byte>)
    requires |r| == 64 && IdFieldOk(r[28..52])
    ensures var id := FieldsOf(r).id;
      |id| <= 24 && (forall j | 0 <= j < |id| :: IdByte(id[j])) && r[28..52] == id + Zeros(24 - |id|)
  {
    var f := FieldsOf(r);
    var field := r[28..52];
    var k := NulAt(field, 0);
    assert f.id == field[..k] by {
      forall j | 0 <= j < k ensures f.id[j] == field[..k][j] { assert f.id[j] == r[28 + j] == field[j]; }
    }
    assert field == f.id + Zeros(24 - k) by {
      forall j | 0 <= j < 24 ensures field[j] == (f.id + Zeros(24 - k))[j] {
        if j < k { assert field[j] == f.id[j]; } else { assert field[j] == 0; }
      }
    }
  }

  lemma NumbersBack(r: seq<byte>)
    requires |r| == 64
    ensures var f := FieldsOf(r);
      f.epoch < Pow256(8) && f.pre < Pow256(16) && f.amount < Pow256(8) &&
      LE(f.epoch, 8) == r[4..12] && LE(f.pre, 16) == r[12..28] && LE(f.amount, 8) == r[52..60]
  {
    FromLEBound(r[4..12]);
    FromLEBound(r[12..28]);
    FromLEBound(r[52..60]);
    LEOfFromLE(r[4..12]);
    LEOfFromLE(r[12..28]);
    LEOfFromLE(r[52..60]);
  }

  lemma EncodeDecode(r: seq<byte>)
    requires |r| == 64 && Framed(r)
    ensures FieldsOk(FieldsOf(r)) && Encode(FieldsOf(r)) == r
  {
    var f := FieldsOf(r);
    IdFieldBack(r);
    NumbersBack(r);
    Split60(r);
    assert [MAGIC[0], MAGIC[1], MAGIC[2], f.kind] == r[..4];
    assert Body(f) == r[..4] + r[4..12] + r[12..28] + r[28..52] + r[52..60];
    assert Body(f) == r[..60];
    assert Encode(f) == r[..60] + r[60..];
  }
}

module RefundLogVerifier {
  import S = RefundLogRatified
  import L = RefundLogRatifiedLemmas
  import opened SinkFormat

  // The bytes this verifier was proved against and written against. The exit script recomputes both.
  const SPEC_SHA256: string := "1a8c7c2a306cd651ea691a9d93f96063c5dffb1686ee1f43845e2de727b4bc5a"
  const SINK_SHA256: string := "1962af4a54c48704749ae919dbeae4d5f1cdc2c7990cf7db3f17614459c2db71"

  // Size classes. A larger file is UNVERIFIABLE (exit 3), never read in full by the shim.
  const MaxRecords: nat := 65536
  const MaxBytes: nat := 64 * MaxRecords
  const MaxRatchetBytes: nat := 12 * 4 * MaxRecords
  const Buckets: nat := 65536

  // ---------------------------------------------------------------- the reading of records as requests

  function ToStr(b: seq<byte>): string
  {
    seq(|b|, j requires 0 <= j < |b| => (b[j] as int) as char)
  }

  predicate Latin(s: string)
  {
    forall j | 0 <= j < |s| :: (s[j] as int) < 256
  }

  function BytesOf(s: string): seq<byte>
    requires Latin(s)
  {
    seq(|s|, j requires 0 <= j < |s| => (s[j] as int) as byte)
  }

  // A string that the sink can store in an id field (no emptiness condition).
  predicate StrOk(s: string)
  {
    |s| <= 24 && Latin(s) && forall j | 0 <= j < |s| :: IdByte((s[j] as int) as byte)
  }

  lemma StrRoundTrip(b: seq<byte>)
    ensures Latin(ToStr(b)) && BytesOf(ToStr(b)) == b && |ToStr(b)| == |b|
    ensures (|b| <= 24 && forall j | 0 <= j < |b| :: IdByte(b[j])) ==> StrOk(ToStr(b))
  {
  }

  lemma BytesRoundTrip(s: string)
    requires StrOk(s)
    ensures ToStr(BytesOf(s)) == s && |BytesOf(s)| == |s| && forall j | 0 <= j < |s| :: IdByte(BytesOf(s)[j])
  {
  }

  // The kind byte of a commit record: '1'..'3' = index + 1 into REASONS (sink.rs lines 8, 25, 172, 242).
  function ReasonOf(k: byte): string
  {
    if k == 49 then "duplicate_charge" else if k == 50 then "service_not_delivered"
    else if k == 51 then "returned_item" else ""
  }

  function KindOf(reason: string): byte
  {
    if reason == "duplicate_charge" then 49 else if reason == "service_not_delivered" then 50
    else if reason == "returned_item" then 51 else 0
  }

  predicate IsReason(r: string)
  {
    r == "duplicate_charge" || r == "service_not_delivered" || r == "returned_item"
  }

  lemma ReasonFacts(k: byte, r: string)
    ensures S.R.AllowedReason(r) <==> IsReason(r)
    ensures IsReason(ReasonOf(k)) <==> 49 <= k <= 51
    ensures 49 <= k <= 51 ==> KindOf(ReasonOf(k)) == k
    ensures IsReason(r) ==> ReasonOf(KindOf(r)) == r
  {
  }

  function ReqOf(r: seq<byte>): S.RefundRequest
    requires |r| == 64
  {
    var f := FieldsOf(r);
    S.RefundRequest(ToStr(f.id), f.amount, ReasonOf(f.kind))
  }

  function RecAt(wal: seq<byte>, i: nat): seq<byte>
    requires 64 * (i + 1) <= |wal|
  {
    wal[64 * i .. 64 * i + 64]
  }

  // ---------------------------------------------------------------- verdicts

  datatype Cause = BadCrc | MalformedRecord | BadGenesis | EpochMismatch | ChainMismatch
                 | ReasonNotAllowed | EmptyId | DuplicateId | AmountNotMoney | AmountOverRemaining | RuleOther

  datatype Why = EmptyFile | NoWholeRecord | TooLarge

  // `final` is the ratified LedgerState after the fold. It is ghost: the program does not keep the settled set.
  datatype Outcome =
    | Accept(records: nat, chargeId: string, original: int, remaining: int, epoch: nat, tail: nat, tornBytes: nat,
             ghost final: S.LedgerState)
    | Reject(index: nat, cause: Cause, verified: nat)
    | Unverifiable(why: Why)

  datatype GenesisResult = GenesisOk(chargeId: string, original: nat) | GenesisBad(cause: Cause)

  // Record 0: framed, kind 'G', epoch 0, pre-state hash 0, a non-empty id (the charge id), amount <= MaxMoney.
  function CheckGenesis(r: seq<byte>): GenesisResult
    requires |r| == 64
  {
    if !CrcOk(r) then GenesisBad(BadCrc)
    else if r[..3] != MAGIC || !IdFieldOk(r[28..52]) then GenesisBad(MalformedRecord)
    else
      var f := FieldsOf(r);
      if f.kind != KIND_GENESIS || f.epoch != 0 || f.pre != 0 || |f.id| == 0 || f.amount > S.R.MaxMoney
      then GenesisBad(BadGenesis)
      else GenesisOk(ToStr(f.id), f.amount)
  }

  datatype Frame = FrameOk | FrameBad(cause: Cause)

  // Record i >= 1: framed, its epoch is i, its pre-state hash is the FNV-1a-128 of record i - 1.
  function CheckFraming(r: seq<byte>, i: nat, tail: nat): Frame
    requires |r| == 64
  {
    if !CrcOk(r) then FrameBad(BadCrc)
    else if r[..3] != MAGIC || !IdFieldOk(r[28..52]) then FrameBad(MalformedRecord)
    else if FieldsOf(r).epoch != i then FrameBad(EpochMismatch)
    else if FieldsOf(r).pre != tail then FrameBad(ChainMismatch)
    else FrameOk
  }

  // The name of a refusal by the ratified rule (used only when Step gives None).
  function RuleCause(reason: string, id: string, amount: int, remaining: int, settled: bool): Cause
  {
    if !IsReason(reason) then ReasonNotAllowed
    else if id == [] then EmptyId
    else if settled then DuplicateId
    else if amount > S.R.MaxMoney then AmountNotMoney
    else if amount > remaining then AmountOverRemaining
    else RuleOther
  }

  // THE FOLD (specification of the program): record by record, framing first, then the ratified Step.
  opaque ghost function FoldFrom(wal: seq<byte>, n: nat, i: nat, s: S.LedgerState, tail: nat, torn: nat): Outcome
    requires 1 <= i <= n && 64 * n <= |wal|
    decreases n - i
  {
    if i == n then Accept(n - 1, s.chargeId, s.original, s.remaining, s.epoch, tail, torn, s)
    else
      var r := RecAt(wal, i);
      var fr := CheckFraming(r, i, tail);
      if fr.FrameBad? then Reject(i, fr.cause, i - 1)
      else
        var q := ReqOf(r);
        var t := S.Step(s, q);
        if t.None? then Reject(i, RuleCause(q.reason, q.requestId, q.amount, s.remaining, q.requestId in s.settled), i - 1)
        else FoldFrom(wal, n, i + 1, t.value, Fnv128(r), torn)
  }

  lemma FoldEnd(wal: seq<byte>, n: nat, s: S.LedgerState, tail: nat, torn: nat)
    requires 1 <= n && 64 * n <= |wal|
    ensures FoldFrom(wal, n, n, s, tail, torn) == Accept(n - 1, s.chargeId, s.original, s.remaining, s.epoch, tail, torn, s)
  {
    reveal FoldFrom();
  }

  lemma FoldFrameBad(wal: seq<byte>, n: nat, i: nat, s: S.LedgerState, tail: nat, torn: nat)
    requires 1 <= i < n && 64 * n <= |wal| && CheckFraming(RecAt(wal, i), i, tail).FrameBad?
    ensures FoldFrom(wal, n, i, s, tail, torn) == Reject(i, CheckFraming(RecAt(wal, i), i, tail).cause, i - 1)
  {
    reveal FoldFrom();
  }

  lemma FoldRuleBad(wal: seq<byte>, n: nat, i: nat, s: S.LedgerState, tail: nat, torn: nat)
    requires 1 <= i < n && 64 * n <= |wal| && CheckFraming(RecAt(wal, i), i, tail).FrameOk?
    requires S.Step(s, ReqOf(RecAt(wal, i))).None?
    ensures var q := ReqOf(RecAt(wal, i));
      FoldFrom(wal, n, i, s, tail, torn) == Reject(i, RuleCause(q.reason, q.requestId, q.amount, s.remaining, q.requestId in s.settled), i - 1)
  {
    reveal FoldFrom();
  }

  lemma FoldNext(wal: seq<byte>, n: nat, i: nat, s: S.LedgerState, tail: nat, torn: nat)
    requires 1 <= i < n && 64 * n <= |wal| && CheckFraming(RecAt(wal, i), i, tail).FrameOk?
    requires S.Step(s, ReqOf(RecAt(wal, i))).Some?
    ensures FoldFrom(wal, n, i, s, tail, torn) == FoldFrom(wal, n, i + 1, S.Step(s, ReqOf(RecAt(wal, i))).value, Fnv128(RecAt(wal, i)), torn)
  {
    reveal FoldFrom();
  }

  lemma FoldAcceptStep(wal: seq<byte>, n: nat, i: nat, s: S.LedgerState, tail: nat, torn: nat)
    requires 1 <= i < n && 64 * n <= |wal| && FoldFrom(wal, n, i, s, tail, torn).Accept?
    ensures CheckFraming(RecAt(wal, i), i, tail).FrameOk? && S.Step(s, ReqOf(RecAt(wal, i))).Some?
    ensures FoldFrom(wal, n, i, s, tail, torn) == FoldFrom(wal, n, i + 1, S.Step(s, ReqOf(RecAt(wal, i))).value, Fnv128(RecAt(wal, i)), torn)
  {
    reveal FoldFrom();
  }

  // The verdict on any byte string. Total: every input gives exactly one Outcome. A trailing part of less than 64
  // bytes (a torn append) is never read as a record; its length is reported as tornBytes.
  ghost function VerifySpec(wal: seq<byte>): Outcome
  {
    if |wal| == 0 then Unverifiable(EmptyFile)
    else if |wal| < 64 then Unverifiable(NoWholeRecord)
    else if |wal| > MaxBytes then Unverifiable(TooLarge)
    else
      var r0 := RecAt(wal, 0);
      var gc := CheckGenesis(r0);
      if gc.GenesisBad? then Reject(0, gc.cause, 0)
      else FoldFrom(wal, |wal| / 64, 1, S.Genesis(gc.chargeId, gc.original, true), Fnv128(r0), |wal| % 64)   // D1
  }

  // ---------------------------------------------------------------- the program

  // The bucket of an id in the program's table of settled ids: a polynomial hash at the point `key`, modulo the prime
  // 2^61 - 1, then modulo Buckets. The shim draws `key` at random for each run (os.urandom), so a log cannot be
  // built in advance to put many ids into one bucket. No proof depends on `key` or on this function beyond
  // Hash(k, key) < Buckets: the verdict is the same for every key (Verify ensures o == VerifySpec(wal)).
  const HashPrime: nat := 2305843009213693951

  function HashFrom(k: string, key: nat, i: nat, acc: nat): nat
    requires i <= |k| && acc < HashPrime
    ensures HashFrom(k, key, i, acc) < HashPrime
    decreases |k| - i
  {
    if i == |k| then acc else HashFrom(k, key, i + 1, (acc * key + (k[i] as int) + 1) % HashPrime)
  }

  function Hash(k: string, key: nat): nat
    ensures Hash(k, key) < Buckets
  {
    HashFrom(k, key, 0, 0) % Buckets
  } by method {
    var acc: nat := 0;
    for i := 0 to |k|
      invariant acc < HashPrime && HashFrom(k, key, i, acc) == HashFrom(k, key, 0, 0)
    {
      acc := (acc * key + (k[i] as int) + 1) % HashPrime;
    }
    return acc % Buckets;
  }

  lemma AllowedIff(s: S.LedgerState, q: S.RefundRequest, settled: bool)
    requires s.chargeId != [] && s.refundEnabled && 0 <= s.remaining <= s.original <= S.R.MaxMoney
    requires settled == (q.requestId in s.settled) && q.amount >= 0
    ensures S.Allowed(s, q) <==> (IsReason(q.reason) && q.requestId != [] && !settled && q.amount <= s.remaining)
    ensures S.Step(s, q).None? <==> !S.Allowed(s, q)
  {
    ReasonFacts(0, q.reason);
  }

  // The program: the fold with a hash table of the settled ids in place of the set. Its result IS VerifySpec(wal).
  method {:isolate_assertions} Verify(wal: seq<byte>, key: nat) returns (o: Outcome)
    ensures o == VerifySpec(wal)
  {
    if |wal| == 0 { return Unverifiable(EmptyFile); }
    if |wal| < 64 { return Unverifiable(NoWholeRecord); }
    if |wal| > MaxBytes { return Unverifiable(TooLarge); }
    var n := |wal| / 64;
    var torn := |wal| % 64;
    var r0 := wal[0..64];
    assert r0 == RecAt(wal, 0);
    var gc := CheckGenesis(r0);
    if gc.GenesisBad? { return Reject(0, gc.cause, 0); }
    var charge, original := gc.chargeId, gc.original;
    ghost var s := S.Genesis(charge, original, true);
    var remaining: int := original;
    var tail := Fnv128(r0);
    var table := new seq<string>[Buckets](_ => []);
    var i := 1;
    while i < n
      invariant 1 <= i <= n && table.Length == Buckets
      invariant FoldFrom(wal, n, i, s, tail, torn) == VerifySpec(wal)
      invariant s.chargeId == charge && s.original == original && s.refundEnabled && s.epoch == i - 1
      invariant s.remaining == remaining && 0 <= remaining <= original <= S.R.MaxMoney && charge != []
      invariant forall k: string :: k in s.settled <==> k in table[Hash(k, key)]
      decreases n - i
    {
      var r := wal[64 * i .. 64 * i + 64];
      assert r == RecAt(wal, i);
      var fr := CheckFraming(r, i, tail);
      if fr.FrameBad? {
        FoldFrameBad(wal, n, i, s, tail, torn);
        return Reject(i, fr.cause, i - 1);
      }
      var f := FieldsOf(r);
      var id := ToStr(f.id);
      var reason := ReasonOf(f.kind);
      var h := Hash(id, key);
      var settled := id in table[h];
      ghost var q := S.RefundRequest(id, f.amount, reason);
      assert q == ReqOf(r);
      assert settled == (id in s.settled);
      AllowedIff(s, q, settled);
      if !(IsReason(reason) && id != [] && !settled && f.amount <= remaining) {
        FoldRuleBad(wal, n, i, s, tail, torn);
        return Reject(i, RuleCause(reason, id, f.amount, remaining, settled), i - 1);
      }
      FoldNext(wal, n, i, s, tail, torn);
      ghost var t := S.Step(s, q).value;
      assert t.settled == s.settled + {id} && t.remaining == remaining - f.amount && t.epoch == i;
      assert t.chargeId == charge && t.original == original && t.refundEnabled;
      ghost var before := table[..];
      table[h] := table[h] + [id];
      forall k: string
        ensures k in t.settled <==> k in table[Hash(k, key)]
      {
        if Hash(k, key) == h {
          assert table[h] == before[h] + [id];
        } else {
          assert table[Hash(k, key)] == before[Hash(k, key)];
        }
      }
      s := t;
      remaining := remaining - f.amount;
      tail := Fnv128(r);
      i := i + 1;
    }
    FoldEnd(wal, n, s, tail, torn);
    return Accept(n - 1, charge, original, remaining, n - 1, tail, torn, s);
  }

  // ---------------------------------------------------------------- the ratchet file (ledger.epoch)

  // An entry is 12 bytes: the epoch (u64, little-endian) and the CRC-32 of those 8 bytes (sink.rs push, lines 101-104).
  datatype RatchetCause = NoValidEntry | BadEntry | Ahead
  datatype RatchetVerdict = RatchetOk(floor: nat, entries: nat, tornBytes: nat) | RatchetBad(index: nat, cause: RatchetCause, floor: nat)

  predicate EntryOk(rb: seq<byte>, k: nat)
    requires 12 * (k + 1) <= |rb|
  {
    rb[12 * k + 8 .. 12 * k + 12] == LE(Crc32(rb[12 * k .. 12 * k + 8]), 4)
  }

  function EntryEpoch(rb: seq<byte>, k: nat): nat
    requires 12 * (k + 1) <= |rb|
  {
    FromLE(rb[12 * k .. 12 * k + 8])
  }

  function RatchetFrom(rb: seq<byte>, m: nat, k: nat, best: nat): RatchetVerdict
    requires k <= m && 12 * m <= |rb|
    decreases m - k
  {
    if k == m then RatchetOk(best, m, |rb| - 12 * m)
    else if !EntryOk(rb, k) then RatchetBad(k, BadEntry, best)
    else RatchetFrom(rb, m, k + 1, if EntryEpoch(rb, k) > best then EntryEpoch(rb, k) else best)
  }

  // Every whole entry must have a valid CRC (the sink skips a bad entry; the verifier refuses it), there must be at
  // least one, and the highest entry (the sink's floor) must not be above the epoch of the WAL (else the WAL is older
  // than its ratchet: the sink's EPOCH_REGRESSION). A trailing part of less than 12 bytes is reported as torn.
  function CheckRatchet(rb: seq<byte>, epoch: nat): RatchetVerdict
  {
    var m := |rb| / 12;
    if m == 0 then RatchetBad(0, NoValidEntry, 0)
    else
      var v := RatchetFrom(rb, m, 0, 0);
      if v.RatchetOk? && v.floor > epoch then RatchetBad(m, Ahead, v.floor) else v
  }

  method CheckRatchetLoop(rb: seq<byte>, epoch: nat) returns (v: RatchetVerdict)
    ensures v == CheckRatchet(rb, epoch)
  {
    var m := |rb| / 12;
    if m == 0 { return RatchetBad(0, NoValidEntry, 0); }
    var k, best := 0, 0;
    while k < m
      invariant k <= m && RatchetFrom(rb, m, k, best) == RatchetFrom(rb, m, 0, 0)
      decreases m - k
    {
      if !EntryOk(rb, k) { v := RatchetBad(k, BadEntry, best); return; }
      var e := EntryEpoch(rb, k);
      best := if e > best then e else best;
      k := k + 1;
    }
    v := RatchetOk(best, m, |rb| - 12 * m);
    if v.floor > epoch { v := RatchetBad(m, Ahead, v.floor); }
  }

  lemma RatchetFromMeaning(rb: seq<byte>, m: nat, k: nat, best: nat)
    requires k <= m && 12 * m <= |rb|
    requires RatchetFrom(rb, m, k, best).RatchetOk?
    requires forall j | 0 <= j < k :: EntryOk(rb, j) && EntryEpoch(rb, j) <= best
    requires (k == 0 && best == 0) || exists j | 0 <= j < k :: EntryEpoch(rb, j) == best
    ensures var v := RatchetFrom(rb, m, k, best);
      v.entries == m && v.tornBytes == |rb| - 12 * m &&
      (forall j | 0 <= j < m :: EntryOk(rb, j) && EntryEpoch(rb, j) <= v.floor) &&
      ((m == 0 && v.floor == 0) || exists j | 0 <= j < m :: EntryEpoch(rb, j) == v.floor)
    decreases m - k
  {
    if k < m {
      var e := EntryEpoch(rb, k);
      var nb := if e > best then e else best;
      assert EntryOk(rb, k);
      if e > best {
        assert EntryEpoch(rb, k) == nb;
      } else if k == 0 {
        assert EntryEpoch(rb, 0) == nb;
      } else {
        var j :| 0 <= j < k && EntryEpoch(rb, j) == best;
        assert EntryEpoch(rb, j) == nb;
      }
      RatchetFromMeaning(rb, m, k + 1, nb);
    }
  }

  // What an accepted ratchet shows: every whole entry is intact, the highest entry (the floor) is one of the entries
  // and is not above the WAL's epoch. It does NOT show that the two files were not restored together (H_LOG.1).
  lemma RatchetMeaning(rb: seq<byte>, epoch: nat)
    requires CheckRatchet(rb, epoch).RatchetOk?
    ensures var v := CheckRatchet(rb, epoch);
      v.entries == |rb| / 12 && v.entries >= 1 && v.tornBytes == |rb| % 12 && v.floor <= epoch &&
      (forall j | 0 <= j < |rb| / 12 :: EntryOk(rb, j) && EntryEpoch(rb, j) <= v.floor) &&
      (exists j | 0 <= j < |rb| / 12 :: EntryEpoch(rb, j) == v.floor)
  {
    RatchetFromMeaning(rb, |rb| / 12, 0, 0);
  }

  // ---------------------------------------------------------------- the model log and the theorems

  // A history the sink can store: ids fit the id field, amounts fit a u64, the epoch fits a u64.
  predicate Encodable(g: S.LedgerState, qs: seq<S.RefundRequest>)
  {
    StrOk(g.chargeId) && 0 <= g.original < Pow256(8) && |qs| < Pow256(8) &&
    forall j | 0 <= j < |qs| :: StrOk(qs[j].requestId) && 0 <= qs[j].amount < Pow256(8)
  }

  function GenesisFields(g: S.LedgerState): Fields
    requires StrOk(g.chargeId) && 0 <= g.original
  {
    Fields(KIND_GENESIS, 0, 0, BytesOf(g.chargeId), g.original)
  }

  function CommitFields(q: S.RefundRequest, epoch: nat, pre: nat): Fields
    requires StrOk(q.requestId) && 0 <= q.amount
  {
    Fields(KindOf(q.reason), epoch, pre, BytesOf(q.requestId), q.amount)
  }

  // THE MODEL LOG: sink.rs init writes encode(b'G', 0, 0, charge, original) (line 224); each commit appends
  // encode(b'1' + kind, epoch + 1, tail, request, amount) (line 172), tail = fnv128 of the last record.
  function {:isolate_assertions} EncodeLog(g: S.LedgerState, qs: seq<S.RefundRequest>): seq<byte>
    requires Encodable(g, qs)
    ensures |EncodeLog(g, qs)| == 64 * (|qs| + 1)
    decreases |qs|
  {
    if |qs| == 0 then Encode(GenesisFields(g))
    else
      var p := EncodeLog(g, qs[..|qs| - 1]);
      var q := qs[|qs| - 1];
      p + Encode(CommitFields(q, |qs|, Fnv128(p[|p| - 64..])))
  } by method {
    var out := Encode(GenesisFields(g));
    var last := out;
    assert qs[..0] == [];
    for i := 0 to |qs|
      invariant Encodable(g, qs[..i]) && out == EncodeLog(g, qs[..i]) && |out| == 64 * (i + 1) && last == out[64 * i..]
    {
      EncodeLogPrefix(g, qs, i + 1);
      assert qs[..i + 1] == qs[..i] + [qs[i]];
      EncodeLogSnoc(g, qs[..i], qs[i]);
      last := Encode(CommitFields(qs[i], i + 1, Fnv128(last)));
      out := out + last;
    }
    assert qs[..|qs|] == qs;
    return out;
  }

  lemma {:isolate_assertions} EncodeLogPrefix(g: S.LedgerState, qs: seq<S.RefundRequest>, k: nat)
    requires Encodable(g, qs) && k <= |qs|
    ensures Encodable(g, qs[..k]) && EncodeLog(g, qs)[..64 * (k + 1)] == EncodeLog(g, qs[..k])
    decreases |qs|
  {
    if k < |qs| {
      var p := qs[..|qs| - 1];
      EncodeLogPrefix(g, p, k);
      assert p[..k] == qs[..k];
      assert EncodeLog(g, qs)[..64 * |qs|] == EncodeLog(g, p);
    } else {
      assert qs[..k] == qs;
    }
  }

  // Record j of the model log, j >= 1, is the commit of qs[j - 1] at epoch j on the hash of record j - 1.
  lemma TakeParts(E: seq<byte>, j: nat, A: seq<byte>, X: seq<byte>)
    requires |A| == 64 * j && |X| == 64 && 64 * (j + 1) <= |E|
    requires E[..64 * (j + 1)] == A + X && E[..64 * j] == A
    ensures RecAt(E, j) == X
    ensures j >= 1 ==> RecAt(E, j - 1) == A[64 * (j - 1)..]
  {
    assert RecAt(E, j) == E[..64 * (j + 1)][64 * j..];
    if j >= 1 {
      assert RecAt(E, j - 1) == E[..64 * j][64 * (j - 1)..];
    }
  }

  // Record j of the model log, j >= 1, is the commit of qs[j - 1] at epoch j on the hash of record j - 1.
  lemma LogRecord(g: S.LedgerState, qs: seq<S.RefundRequest>, j: nat)
    requires Encodable(g, qs) && 1 <= j <= |qs|
    ensures var E := EncodeLog(g, qs);
      RecAt(E, j) == Encode(CommitFields(qs[j - 1], j, Fnv128(RecAt(E, j - 1))))
  {
    var E := EncodeLog(g, qs);
    var q := qs[j - 1];
    var p := qs[..j - 1];
    assert qs[..j] == p + [q];
    EncodeLogPrefix(g, qs, j);
    EncodeLogPrefix(g, qs, j - 1);
    EncodeLogSnoc(g, p, q);
    var Ep := EncodeLog(g, p);
    var X := Encode(CommitFields(q, j, Fnv128(Ep[64 * (j - 1)..])));
    assert E[..64 * (j + 1)] == Ep + X;
    TakeParts(E, j, Ep, X);
  }

  lemma LogGenesis(g: S.LedgerState, qs: seq<S.RefundRequest>)
    requires Encodable(g, qs)
    ensures RecAt(EncodeLog(g, qs), 0) == Encode(GenesisFields(g))
  {
    EncodeLogPrefix(g, qs, 0);
    assert qs[..0] == [];
    BytesRoundTrip(g.chargeId);
  }

  // In a valid history every reason is approved (so the kind byte gives it back).
  lemma ValidStep(g: S.LedgerState, qs: seq<S.RefundRequest>, j: nat)
    requires S.ValidHistory(g, qs) && 1 <= j <= |qs|
    ensures S.Replay(g, qs[..j - 1]).Some? && S.Replay(g, qs[..j]) == S.Step(S.Replay(g, qs[..j - 1]).value, qs[j - 1])
    ensures S.Replay(g, qs[..j]).Some? && S.Allowed(S.Replay(g, qs[..j - 1]).value, qs[j - 1]) && IsReason(qs[j - 1].reason)
  {
    L.PrefixIsValid(g, qs, j);
    L.PrefixIsValid(g, qs, j - 1);
    assert qs[..j][..j - 1] == qs[..j - 1];
    assert qs[..j][j - 1] == qs[j - 1];
    ReasonFacts(0, qs[j - 1].reason);
  }

  lemma ModelRecordReads(g: S.LedgerState, qs: seq<S.RefundRequest>, j: nat)
    requires Encodable(g, qs) && S.ValidHistory(g, qs) && 1 <= j <= |qs|
    ensures var E := EncodeLog(g, qs);
      Framed(RecAt(E, j)) && ReqOf(RecAt(E, j)) == qs[j - 1] &&
      FieldsOf(RecAt(E, j)).epoch == j && FieldsOf(RecAt(E, j)).pre == Fnv128(RecAt(E, j - 1))
  {
    var E := EncodeLog(g, qs);
    LogRecord(g, qs, j);
    BytesRoundTrip(qs[j - 1].requestId);
    Pow256Values();
    var f := CommitFields(qs[j - 1], j, Fnv128(RecAt(E, j - 1)));
    assert FieldsOk(f);
    DecodeEncode(f);
    ValidStep(g, qs, j);
    ReasonFacts(0, qs[j - 1].reason);
  }

  // COMPLETENESS for the model: the model encoding of every valid history from a D1 genesis, with or without a torn
  // append of fewer than 64 bytes, is accepted, with the ratified final state, and nothing else is reported.
  lemma {:isolate_assertions} Completeness(g: S.LedgerState, qs: seq<S.RefundRequest>, torn: seq<byte>)
    requires S.ValidHistory(g, qs) && g.refundEnabled && Encodable(g, qs)
    requires |torn| < 64 && 64 * (|qs| + 1) + |torn| <= MaxBytes
    ensures var v := VerifySpec(EncodeLog(g, qs) + torn);
      v.Accept? && v.records == |qs| && v.final == S.Replay(g, qs).value && v.tornBytes == |torn| &&
      v.chargeId == g.chargeId && v.original == g.original && v.remaining == S.Replay(g, qs).value.remaining &&
      v.epoch == |qs|
  {
    var E := EncodeLog(g, qs);
    var wal := E + torn;
    var n := |qs| + 1;
    assert |wal| / 64 == n && |wal| % 64 == |torn|;
    assert RecAt(wal, 0) == RecAt(E, 0);
    LogGenesis(g, qs);
    BytesRoundTrip(g.chargeId);
    Pow256Values();
    DecodeEncode(GenesisFields(g));
    L.Conservation(g, qs);
    assert CheckGenesis(RecAt(wal, 0)) == GenesisOk(g.chargeId, g.original);
    assert g == S.Genesis(g.chargeId, g.original, true);
    assert qs[..0] == [];
    FoldComplete(g, qs, torn, 1);
  }

  lemma CompleteStep(g: S.LedgerState, qs: seq<S.RefundRequest>, torn: seq<byte>, i: nat)
    requires S.ValidHistory(g, qs) && Encodable(g, qs) && |torn| < 64 && 1 <= i <= |qs|
    ensures var wal := EncodeLog(g, qs) + torn;
      S.Replay(g, qs[..i - 1]).Some? && S.Replay(g, qs[..i]).Some? &&
      CheckFraming(RecAt(wal, i), i, Fnv128(RecAt(wal, i - 1))) == FrameOk &&
      S.Step(S.Replay(g, qs[..i - 1]).value, ReqOf(RecAt(wal, i))) == S.Replay(g, qs[..i])
  {
    var E := EncodeLog(g, qs);
    var wal := E + torn;
    assert RecAt(wal, i) == RecAt(E, i);
    assert RecAt(wal, i - 1) == RecAt(E, i - 1);
    ModelRecordReads(g, qs, i);
    ValidStep(g, qs, i);
  }

  lemma {:isolate_assertions} FoldComplete(g: S.LedgerState, qs: seq<S.RefundRequest>, torn: seq<byte>, i: nat)
    requires S.ValidHistory(g, qs) && Encodable(g, qs) && |torn| < 64
    requires 1 <= i <= |qs| + 1
    ensures var wal := EncodeLog(g, qs) + torn;
      S.Replay(g, qs[..i - 1]).Some? &&
      FoldFrom(wal, |qs| + 1, i, S.Replay(g, qs[..i - 1]).value, Fnv128(RecAt(wal, i - 1)), |torn|) ==
      Accept(|qs|, g.chargeId, g.original, S.Replay(g, qs).value.remaining, S.Replay(g, qs).value.epoch,
             Fnv128(RecAt(wal, |qs|)), |torn|, S.Replay(g, qs).value)
    decreases |qs| + 1 - i
  {
    var wal := EncodeLog(g, qs) + torn;
    L.PrefixIsValid(g, qs, i - 1);
    L.Conservation(g, qs);
    if i == |qs| + 1 {
      assert qs[..i - 1] == qs;
      FoldEnd(wal, |qs| + 1, S.Replay(g, qs).value, Fnv128(RecAt(wal, i - 1)), |torn|);
    } else {
      CompleteStep(g, qs, torn, i);
      FoldNext(wal, |qs| + 1, i, S.Replay(g, qs[..i - 1]).value, Fnv128(RecAt(wal, i - 1)), |torn|);
      FoldComplete(g, qs, torn, i + 1);
    }
  }

  ghost function Reqs(wal: seq<byte>, k: nat): seq<S.RefundRequest>
    requires 1 <= k && 64 * k <= |wal|
  {
    seq(k - 1, j requires 0 <= j < k - 1 => ReqOf(RecAt(wal, j + 1)))
  }

  // The requests that the whole records 1 .. n-1 of a file state (empty for a file without a whole record).
  ghost function Requests(wal: seq<byte>): seq<S.RefundRequest>
  {
    if |wal| < 64 then [] else Reqs(wal, |wal| / 64)
  }

  lemma ReqsSnoc(wal: seq<byte>, i: nat)
    requires 1 <= i && 64 * (i + 1) <= |wal|
    ensures Reqs(wal, i + 1) == Reqs(wal, i) + [ReqOf(RecAt(wal, i))]
    ensures |Reqs(wal, i)| == i - 1
  {
  }

  lemma PrefixExtend(wal: seq<byte>, i: nat)
    requires 64 * (i + 1) <= |wal|
    ensures wal[..64 * (i + 1)] == wal[..64 * i] + RecAt(wal, i)
    ensures i >= 1 ==> wal[..64 * i][64 * (i - 1)..] == RecAt(wal, i - 1)
  {
  }

  lemma EncodeLogSnoc(g: S.LedgerState, qs: seq<S.RefundRequest>, q: S.RefundRequest)
    requires Encodable(g, qs + [q]) && StrOk(q.requestId) && 0 <= q.amount < Pow256(8)
    ensures Encodable(g, qs)
    ensures var p := EncodeLog(g, qs);
      EncodeLog(g, qs + [q]) == p + Encode(CommitFields(q, |qs| + 1, Fnv128(p[64 * |qs|..])))
  {
    var qs2 := qs + [q];
    assert qs2[..|qs2| - 1] == qs;
    assert qs2[|qs2| - 1] == q;
    assert forall j | 0 <= j < |qs| :: qs[j] == qs2[j];
  }

  // A framed commit record whose kind is an approved reason is the model encoding of the request it states.
  lemma RecordBack(r: seq<byte>, i: nat, tail: nat)
    requires |r| == 64 && CheckFraming(r, i, tail).FrameOk? && IsReason(ReqOf(r).reason)
    ensures StrOk(ReqOf(r).requestId) && 0 <= ReqOf(r).amount < Pow256(8)
    ensures Encode(CommitFields(ReqOf(r), i, tail)) == r
  {
    var f := FieldsOf(r);
    EncodeDecode(r);
    ReasonFacts(f.kind, ReqOf(r).reason);
    StrRoundTrip(f.id);
    BytesRoundTrip(ReqOf(r).requestId);
    assert CommitFields(ReqOf(r), i, tail) == f;
  }

  lemma SoundStepBytes(wal: seq<byte>, i: nat, tail: nat, g: S.LedgerState, qs: seq<S.RefundRequest>, q: S.RefundRequest)
    requires 1 <= i < MaxRecords && 64 * (i + 1) <= |wal| && |qs| == i - 1
    requires Encodable(g, qs) && wal[..64 * i] == EncodeLog(g, qs) && tail == Fnv128(RecAt(wal, i - 1))
    requires StrOk(q.requestId) && 0 <= q.amount < Pow256(8) && Encode(CommitFields(q, i, tail)) == RecAt(wal, i)
    ensures Encodable(g, qs + [q]) && wal[..64 * (i + 1)] == EncodeLog(g, qs + [q])
  {
    Pow256Values();
    assert Encodable(g, qs + [q]);
    EncodeLogSnoc(g, qs, q);
    PrefixExtend(wal, i);
    var p := EncodeLog(g, qs);
    assert p[64 * |qs|..] == RecAt(wal, i - 1);
  }

  lemma SoundStep(wal: seq<byte>, i: nat, s: S.LedgerState, tail: nat, g: S.LedgerState)
    requires 1 <= i < MaxRecords && 64 * (i + 1) <= |wal|
    requires CheckFraming(RecAt(wal, i), i, tail).FrameOk? && S.Step(s, ReqOf(RecAt(wal, i))).Some?
    requires S.Replay(g, Reqs(wal, i)) == S.Some(s)
    requires Encodable(g, Reqs(wal, i)) && wal[..64 * i] == EncodeLog(g, Reqs(wal, i))
    requires tail == Fnv128(RecAt(wal, i - 1))
    ensures S.Replay(g, Reqs(wal, i + 1)) == S.Some(S.Step(s, ReqOf(RecAt(wal, i))).value)
    ensures Encodable(g, Reqs(wal, i + 1)) && wal[..64 * (i + 1)] == EncodeLog(g, Reqs(wal, i + 1))
  {
    var r := RecAt(wal, i);
    var q := ReqOf(r);
    var qs := Reqs(wal, i);
    ReqsSnoc(wal, i);
    assert S.Allowed(s, q);
    ReasonFacts(0, q.reason);
    RecordBack(r, i, tail);
    L.ReplaySnoc(g, qs, q);
    SoundStepBytes(wal, i, tail, g, qs, q);
  }

  lemma {:isolate_assertions} FoldSound(wal: seq<byte>, n: nat, i: nat, s: S.LedgerState, tail: nat, torn: nat, g: S.LedgerState)
    requires 1 <= i <= n && 64 * n <= |wal| && n <= MaxRecords
    requires FoldFrom(wal, n, i, s, tail, torn).Accept?
    requires S.Replay(g, Reqs(wal, i)) == S.Some(s)
    requires Encodable(g, Reqs(wal, i)) && wal[..64 * i] == EncodeLog(g, Reqs(wal, i))
    requires tail == Fnv128(RecAt(wal, i - 1))
    ensures var v := FoldFrom(wal, n, i, s, tail, torn);
      S.Replay(g, Reqs(wal, n)) == S.Some(v.final) && Encodable(g, Reqs(wal, n)) &&
      wal[..64 * n] == EncodeLog(g, Reqs(wal, n)) &&
      v.records == n - 1 && v.tornBytes == torn && v.remaining == v.final.remaining && v.epoch == v.final.epoch &&
      v.chargeId == v.final.chargeId && v.original == v.final.original
    decreases n - i
  {
    if i < n {
      FoldAcceptStep(wal, n, i, s, tail, torn);
      SoundStep(wal, i, s, tail, g);
      FoldSound(wal, n, i + 1, S.Step(s, ReqOf(RecAt(wal, i))).value, Fnv128(RecAt(wal, i)), torn, g);
    } else {
      FoldEnd(wal, n, s, tail, torn);
    }
  }

  // Record 0 that passes CheckGenesis is the model genesis record of the D1 genesis state it states.
  lemma GenesisBack(r0: seq<byte>)
    requires |r0| == 64 && CheckGenesis(r0).GenesisOk?
    ensures var g := S.Genesis(CheckGenesis(r0).chargeId, CheckGenesis(r0).original, true);
      S.ValidGenesis(g) && Encodable(g, []) && EncodeLog(g, []) == r0
  {
    var gc := CheckGenesis(r0);
    var g := S.Genesis(gc.chargeId, gc.original, true);
    var f0 := FieldsOf(r0);
    EncodeDecode(r0);
    StrRoundTrip(f0.id);
    Pow256Values();
    assert Encodable(g, []);
    BytesRoundTrip(g.chargeId);
    assert GenesisFields(g) == f0;
  }

  lemma {:isolate_assertions} RecordsRead(wal: seq<byte>, g: S.LedgerState, qs: seq<S.RefundRequest>)
    requires Encodable(g, qs) && S.ValidHistory(g, qs) && 64 * (|qs| + 1) <= |wal| && wal[..64 * (|qs| + 1)] == EncodeLog(g, qs)
    ensures forall j | 1 <= j <= |qs| :: Framed(RecAt(wal, j)) && ReqOf(RecAt(wal, j)) == qs[j - 1]
  {
    forall j | 1 <= j <= |qs|
      ensures Framed(RecAt(wal, j)) && ReqOf(RecAt(wal, j)) == qs[j - 1]
    {
      ModelRecordReads(g, qs, j);
      var E := EncodeLog(g, qs);
      assert RecAt(wal, j) == RecAt(E, j);
    }
  }

  // SOUNDNESS. If the verdict on the bytes is ACCEPT (with or without a torn tail), then with the D1 genesis g of
  // record 0 and the requests qs that records 1 .. n-1 state: the ratified ValidGenesis and ValidHistory hold, the
  // ratified Replay gives the reported final state, no request id occurs twice, original == remaining + sum of the
  // amounts, 0 <= remaining <= original, and the whole records ARE the model encoding of (g, qs), byte for byte.
  lemma {:isolate_assertions} Soundness(wal: seq<byte>)
    requires VerifySpec(wal).Accept?
    ensures var v := VerifySpec(wal);
      var g := S.Genesis(v.chargeId, v.original, true);
      var qs := Requests(wal);
      |wal| >= 64 && |qs| == v.records && |qs| + 1 == |wal| / 64 && v.tornBytes == |wal| % 64 &&
      S.ValidGenesis(g) && S.ValidHistory(g, qs) && S.Replay(g, qs) == S.Some(v.final) &&
      v.remaining == v.final.remaining && v.epoch == v.final.epoch && v.epoch == |qs| &&
      S.AtMostOnce(qs) && g.original == v.final.remaining + S.SumAmounts(qs) && 0 <= v.final.remaining <= v.final.original &&
      S.Conserves(g, qs, v.final) &&
      Encodable(g, qs) && wal[..64 * (|qs| + 1)] == EncodeLog(g, qs) &&
      (forall j | 1 <= j <= |qs| :: Framed(RecAt(wal, j)) && ReqOf(RecAt(wal, j)) == qs[j - 1])
  {
    var v := VerifySpec(wal);
    var n := |wal| / 64;
    var r0 := RecAt(wal, 0);
    var gc := CheckGenesis(r0);
    var g := S.Genesis(gc.chargeId, gc.original, true);
    GenesisBack(r0);
    assert Reqs(wal, 1) == [];
    assert wal[..64] == r0;
    FoldSound(wal, n, 1, g, Fnv128(r0), |wal| % 64, g);
    var qs := Requests(wal);
    assert qs == Reqs(wal, n);
    L.Conservation(g, qs);
    L.AtMostOnceHolds(g, qs);
    assert v.chargeId == g.chargeId && v.original == g.original;
    RecordsRead(wal, g, qs);
  }

  // The same statement in the "there exist" form of the task.
  ghost predicate Witness(wal: seq<byte>, v: Outcome, g: S.LedgerState, qs: seq<S.RefundRequest>)
    requires v.Accept?
  {
    |qs| == v.records && S.ValidGenesis(g) && S.ValidHistory(g, qs) && S.Replay(g, qs) == S.Some(v.final) &&
    g.refundEnabled && S.AtMostOnce(qs) && g.original == v.final.remaining + S.SumAmounts(qs) &&
    0 <= v.final.remaining <= v.final.original && v.remaining == v.final.remaining &&
    (forall j | 1 <= j <= |qs| :: 64 * (j + 1) <= |wal| && Framed(RecAt(wal, j)) && ReqOf(RecAt(wal, j)) == qs[j - 1])
  }

  lemma SoundnessExists(wal: seq<byte>)
    requires VerifySpec(wal).Accept?
    ensures exists g: S.LedgerState, qs: seq<S.RefundRequest> :: Witness(wal, VerifySpec(wal), g, qs)
  {
    Soundness(wal);
    var v := VerifySpec(wal);
    var g := S.Genesis(v.chargeId, v.original, true);
    var qs := Requests(wal);
    assert Witness(wal, v, g, qs);
  }

  // Exactness for model logs: Soundness and Completeness together. A verifier that refused everything would not
  // satisfy Completeness; one that accepted a non-history would not satisfy Soundness.
  lemma {:isolate_assertions} ExactOnModelLogs(g: S.LedgerState, qs: seq<S.RefundRequest>, torn: seq<byte>)
    requires g == S.Genesis(g.chargeId, g.original, true) && Encodable(g, qs)
    requires |torn| < 64 && 64 * (|qs| + 1) + |torn| <= MaxBytes
    ensures VerifySpec(EncodeLog(g, qs) + torn).Accept? <==> S.ValidHistory(g, qs)
  {
    var wal := EncodeLog(g, qs) + torn;
    if S.ValidHistory(g, qs) {
      Completeness(g, qs, torn);
    }
    if VerifySpec(wal).Accept? {
      Soundness(wal);
      var v := VerifySpec(wal);
      var g2 := S.Genesis(v.chargeId, v.original, true);
      var qs2 := Requests(wal);
      assert |wal| / 64 == |qs| + 1;
      assert |qs2| == |qs|;
      assert wal[..64 * (|qs| + 1)] == EncodeLog(g, qs);
      forall j | 0 <= j < |qs2| ensures IsReason(qs2[j].reason) {
        ValidStep(g2, qs2, j + 1);
      }
      EncodedLogInjective(g, qs, g2, qs2);
    }
  }

  lemma EncodeInjective(f1: Fields, f2: Fields)
    requires FieldsOk(f1) && FieldsOk(f2) && Encode(f1) == Encode(f2)
    ensures f1 == f2
  {
    DecodeEncode(f1);
    DecodeEncode(f2);
  }

  lemma CommitFieldsInjective(q1: S.RefundRequest, q2: S.RefundRequest, e: nat, p: nat)
    requires StrOk(q1.requestId) && StrOk(q2.requestId) && 0 <= q1.amount && 0 <= q2.amount && IsReason(q2.reason)
    requires CommitFields(q1, e, p) == CommitFields(q2, e, p)
    ensures q1 == q2
  {
    BytesRoundTrip(q1.requestId);
    BytesRoundTrip(q2.requestId);
    ReasonFacts(0, q2.reason);
    assert KindOf(q1.reason) == KindOf(q2.reason);
    assert q1.reason == q2.reason;
    assert q1.requestId == ToStr(BytesOf(q1.requestId)) == ToStr(BytesOf(q2.requestId)) == q2.requestId;
  }

  lemma {:isolate_assertions} InjectiveAt(g1: S.LedgerState, qs1: seq<S.RefundRequest>, g2: S.LedgerState, qs2: seq<S.RefundRequest>, j: nat)
    requires Encodable(g1, qs1) && Encodable(g2, qs2) && |qs1| == |qs2| && j < |qs1|
    requires EncodeLog(g1, qs1) == EncodeLog(g2, qs2) && IsReason(qs2[j].reason)
    ensures qs1[j] == qs2[j]
  {
    var E := EncodeLog(g1, qs1);
    LogRecord(g1, qs1, j + 1);
    LogRecord(g2, qs2, j + 1);
    var pre := Fnv128(RecAt(E, j));
    var f1 := CommitFields(qs1[j], j + 1, pre);
    var f2 := CommitFields(qs2[j], j + 1, pre);
    assert Encode(f1) == Encode(f2);
    BytesRoundTrip(qs1[j].requestId);
    BytesRoundTrip(qs2[j].requestId);
    Pow256Values();
    assert FieldsOk(f1) && FieldsOk(f2);
    EncodeInjective(f1, f2);
    CommitFieldsInjective(qs1[j], qs2[j], j + 1, pre);
  }

  // Two encodable histories from D1 genesis states with equal model logs are equal: the reading is the only reading.
  lemma EncodedLogInjective(g1: S.LedgerState, qs1: seq<S.RefundRequest>, g2: S.LedgerState, qs2: seq<S.RefundRequest>)
    requires Encodable(g1, qs1) && Encodable(g2, qs2) && |qs1| == |qs2|
    requires g1 == S.Genesis(g1.chargeId, g1.original, true) && g2 == S.Genesis(g2.chargeId, g2.original, true)
    requires EncodeLog(g1, qs1) == EncodeLog(g2, qs2)
    requires forall j | 0 <= j < |qs2| :: IsReason(qs2[j].reason)
    ensures g1 == g2 && qs1 == qs2
  {
    Pow256Values();
    LogGenesis(g1, qs1);
    LogGenesis(g2, qs2);
    BytesRoundTrip(g1.chargeId);
    BytesRoundTrip(g2.chargeId);
    DecodeEncode(GenesisFields(g1));
    DecodeEncode(GenesisFields(g2));
    assert GenesisFields(g1) == GenesisFields(g2);
    assert g1.chargeId == ToStr(BytesOf(g1.chargeId)) == ToStr(BytesOf(g2.chargeId)) == g2.chargeId;
    forall j | 0 <= j < |qs1| ensures qs1[j] == qs2[j]
    {
      InjectiveAt(g1, qs1, g2, qs2, j);
    }
    assert qs1 == qs2;
  }

  // ---------------------------------------------------------------- the verdict text and the exit code

  function Digit(d: nat): char
    requires d < 16
  {
    "0123456789abcdef"[d]
  }

  opaque function NatStr(n: nat): string
    decreases n
  {
    if n < 10 then [Digit(n)] else NatStr(n / 10) + [Digit(n % 10)]
  }

  function IntStr(n: int): string
  {
    if n < 0 then "-" + NatStr(-n) else NatStr(n)
  }

  opaque function Hex(v: nat, k: nat): string
    decreases k
  {
    if k == 0 then "" else Hex(v / 16, k - 1) + [Digit(v % 16)]
  }

  function CauseName(c: Cause): string
  {
    match c
    case BadCrc => "BAD_CRC"
    case MalformedRecord => "MALFORMED_RECORD"
    case BadGenesis => "BAD_GENESIS"
    case EpochMismatch => "EPOCH_MISMATCH"
    case ChainMismatch => "CHAIN_MISMATCH"
    case ReasonNotAllowed => "REASON_NOT_ALLOWED"
    case EmptyId => "EMPTY_ID"
    case DuplicateId => "DUPLICATE_ID"
    case AmountNotMoney => "AMOUNT_NOT_MONEY"
    case AmountOverRemaining => "AMOUNT_OVER_REMAINING"
    case RuleOther => "RULE"
  }

  function RatchetCauseName(c: RatchetCause): string
  {
    match c
    case NoValidEntry => "RATCHET_NO_ENTRY"
    case BadEntry => "RATCHET_BAD_ENTRY"
    case Ahead => "RATCHET_AHEAD"
  }

  function WhyName(w: Why): string
  {
    match w
    case EmptyFile => "EMPTY_FILE"
    case NoWholeRecord => "NO_WHOLE_RECORD"
    case TooLarge => "TOO_LARGE"
  }

  // One output: `VERDICT key=value ...`, or one JSON object with the same keys in the same order.
  opaque function Line(verdict: string, code: nat, pairs: seq<(string, string, bool)>, json: bool): string
  {
    var sig := [("spec_sha256", SPEC_SHA256, true), ("sink_sha256", SINK_SHA256, true)];
    if json then "{\"verdict\":\"" + verdict + "\",\"exit_code\":" + NatStr(code) + Json(pairs + sig) + "}"
    else verdict + Plain(pairs + sig)
  }

  function Json(pairs: seq<(string, string, bool)>): string
  {
    if |pairs| == 0 then "" else
    var p := pairs[|pairs| - 1];
    var value := if p.2 then "\"" + p.1 + "\"" else p.1;
    Json(pairs[..|pairs| - 1]) + ",\"" + p.0 + "\":" + value
  }

  function Plain(pairs: seq<(string, string, bool)>): string
  {
    if |pairs| == 0 then "" else Plain(pairs[..|pairs| - 1]) + " " + pairs[|pairs| - 1].0 + "=" + pairs[|pairs| - 1].1
  }

  function UnverifiableText(why: string, json: bool): string
  {
    Line("UNVERIFIABLE_" + why, 3, [("reason", why, true)], json)
  }

  // --expect-count: a decimal number, no sign, no leading zero, at most 20 digits.
  predicate DecimalOk(t: string)
  {
    1 <= |t| <= 20 && (forall j | 0 <= j < |t| :: '0' <= t[j] <= '9') && (t[0] != '0' || |t| == 1)
  }

  function DecValue(t: string): nat
    requires forall j | 0 <= j < |t| :: '0' <= t[j] <= '9'
    decreases |t|
  {
    if |t| == 0 then 0 else 10 * DecValue(t[..|t| - 1]) + ((t[|t| - 1] as int) - ('0' as int))
  }

  // --expect-tip: exactly 32 lowercase hex digits, compared as text with the tail as the sink prints it ({:032x}).
  predicate TipOk(t: string)
  {
    |t| == 32 && forall j | 0 <= j < |t| :: ('0' <= t[j] <= '9') || ('a' <= t[j] <= 'f')
  }

  ghost predicate ArgsOk(witnessGiven: bool, countGiven: bool, countText: string, tipGiven: bool, tipText: string)
  {
    !witnessGiven && (countGiven ==> DecimalOk(countText)) && (tipGiven ==> TipOk(tipText))
  }

  // ACCEPT or ACCEPT_TORN_TAIL: the fold accepts, the ratchet (if given) is consistent, each anchor given matches.
  ghost predicate AcceptedO(o: Outcome, ratchetGiven: bool, rb: seq<byte>, countGiven: bool, countText: string,
                            tipGiven: bool, tipText: string)
    requires countGiven ==> DecimalOk(countText)
  {
    o.Accept? &&
    (ratchetGiven ==> |rb| <= MaxRatchetBytes && CheckRatchet(rb, o.epoch).RatchetOk?) &&
    (countGiven ==> DecValue(countText) == o.records) &&
    (tipGiven ==> tipText == Hex(o.tail, 32))
  }

  ghost predicate TornO(o: Outcome, ratchetGiven: bool, rb: seq<byte>)
    requires o.Accept?
  {
    o.tornBytes > 0 || (ratchetGiven && CheckRatchet(rb, o.epoch).RatchetOk? && CheckRatchet(rb, o.epoch).tornBytes > 0)
  }

  ghost predicate Accepted(wal: seq<byte>, ratchetGiven: bool, rb: seq<byte>, countGiven: bool, countText: string,
                           tipGiven: bool, tipText: string)
    requires countGiven ==> DecimalOk(countText)
  {
    AcceptedO(VerifySpec(wal), ratchetGiven, rb, countGiven, countText, tipGiven, tipText)
  }

  ghost predicate Torn(wal: seq<byte>, ratchetGiven: bool, rb: seq<byte>)
    requires VerifySpec(wal).Accept?
  {
    TornO(VerifySpec(wal), ratchetGiven, rb)
  }

  // The verdict and the exit code, from the bytes and the argument strings. Exit 0 (ACCEPT) or 4 (ACCEPT_TORN_TAIL)
  // EXACTLY when the arguments are well formed and Accepted holds; then Soundness applies to the bytes. Exit 0 only
  // without a torn part. 1: REJECT_<cause>. 3: UNVERIFIABLE_<why>. No other code.
  method Run(wal: seq<byte>, ratchetGiven: bool, rb: seq<byte>, countGiven: bool, countText: string, tipGiven: bool,
             tipText: string, witnessGiven: bool, json: bool, key: nat) returns (code: int, text: string)
    ensures code == 0 || code == 1 || code == 3 || code == 4
    ensures (code == 0 || code == 4) <==>
      ArgsOk(witnessGiven, countGiven, countText, tipGiven, tipText) &&
      Accepted(wal, ratchetGiven, rb, countGiven, countText, tipGiven, tipText)
    ensures code == 0 ==> VerifySpec(wal).Accept? && !Torn(wal, ratchetGiven, rb)
    ensures code == 4 ==> VerifySpec(wal).Accept? && Torn(wal, ratchetGiven, rb)
  {
    if witnessGiven {
      code, text := 3, UnverifiableText("WITNESS_UNSUPPORTED", json);
      return;
    }
    if (countGiven && !DecimalOk(countText)) || (tipGiven && !TipOk(tipText)) {
      code, text := 3, UnverifiableText("USAGE", json);
      return;
    }
    var o := Verify(wal, key);
    if o.Unverifiable? {
      code, text := 3, UnverifiableText(WhyName(o.why), json);
      return;
    }
    if o.Reject? {
      code := 1;
      text := Line("REJECT_" + CauseName(o.cause), 1, [("index", NatStr(o.index), false), ("verified_records", NatStr(o.verified), false)], json);
      return;
    }
    code, text := Finish(o, ratchetGiven, rb, countGiven, countText, tipGiven, tipText, json);
  }

  method Finish(o: Outcome, ratchetGiven: bool, rb: seq<byte>, countGiven: bool, countText: string, tipGiven: bool,
                tipText: string, json: bool) returns (code: int, text: string)
    requires o.Accept? && (countGiven ==> DecimalOk(countText))
    ensures code == 0 || code == 1 || code == 3 || code == 4
    ensures (code == 0 || code == 4) <==> AcceptedO(o, ratchetGiven, rb, countGiven, countText, tipGiven, tipText)
    ensures code == 0 ==> !TornO(o, ratchetGiven, rb)
    ensures code == 4 ==> TornO(o, ratchetGiven, rb)
  {
    var facts := [("records", NatStr(o.records), false), ("charge", o.chargeId, true), ("original", IntStr(o.original), false),
                  ("remaining", IntStr(o.remaining), false), ("epoch", NatStr(o.epoch), false), ("tail", Hex(o.tail, 32), true),
                  ("torn_bytes", NatStr(o.tornBytes), false)];
    var ratchetTorn := 0;
    if !ratchetGiven {
      facts := facts + [("ratchet", "none", true)];
    } else {
      if |rb| > MaxRatchetBytes {
        code, text := 3, UnverifiableText("RATCHET_TOO_LARGE", json);
        return;
      }
      var rv := CheckRatchetLoop(rb, o.epoch);
      if rv.RatchetBad? {
        code := 1;
        text := Line("REJECT_" + RatchetCauseName(rv.cause), 1, facts + [("ratchet_entry", NatStr(rv.index), false),
                     ("ratchet_floor", NatStr(rv.floor), false)], json);
        return;
      }
      facts := facts + [("ratchet_floor", NatStr(rv.floor), false), ("ratchet_entries", NatStr(rv.entries), false),
                        ("ratchet_torn_bytes", NatStr(rv.tornBytes), false)];
      ratchetTorn := rv.tornBytes;
    }
    facts := facts + [("expect_count", if countGiven then countText else "none", !countGiven),
                      ("expect_tip", if tipGiven then tipText else "none", true)];
    if countGiven && DecValue(countText) != o.records {
      code, text := 1, Line("REJECT_COUNT_MISMATCH", 1, facts, json);
      return;
    }
    if tipGiven && tipText != Hex(o.tail, 32) {
      code, text := 1, Line("REJECT_TIP_MISMATCH", 1, facts, json);
      return;
    }
    code := if o.tornBytes == 0 && ratchetTorn == 0 then 0 else 4;
    text := Line(if code == 0 then "ACCEPT" else "ACCEPT_TORN_TAIL", code, facts, json);
  }

  // ---------------------------------------------------------------- the second entry point: the proved encoder

  // The model log of a history given as plain values (the shim parses a JSON file into them). Exit 0 only when the
  // history is one that the ratified specification accepts and the model can store; then `wal` IS EncodeLog(g, qs).
  // Anything else: exit 3, no bytes (the model's preconditions are checked, never stretched).
  function HistoryOf(ids: seq<string>, amounts: seq<int>, reasons: seq<string>): seq<S.RefundRequest>
    requires |ids| == |amounts| == |reasons|
  {
    seq(|ids|, j requires 0 <= j < |ids| => S.RefundRequest(ids[j], amounts[j], reasons[j]))
  }

  method {:isolate_assertions} EncodeEntry(charge: string, original: int, ids: seq<string>, amounts: seq<int>, reasons: seq<string>, json: bool,
                                               key: nat)
    returns (code: int, wal: seq<byte>, text: string)
    ensures code == 0 || code == 3
    ensures code == 0 ==>
      |ids| == |amounts| == |reasons| &&
      var g := S.Genesis(charge, original, true);
      var qs := HistoryOf(ids, amounts, reasons);
      Encodable(g, qs) && S.ValidHistory(g, qs) && wal == EncodeLog(g, qs) && VerifySpec(wal).Accept?
    ensures code == 3 ==> wal == []
  {
    wal := [];
    if !(|ids| == |amounts| == |reasons|) || 64 * (|ids| + 1) > MaxBytes {
      code, text := 3, UnverifiableText("ENCODE_INPUT", json);
      return;
    }
    var g := S.Genesis(charge, original, true);
    var qs := HistoryOf(ids, amounts, reasons);
    Pow256Values();
    if !(StrOk(charge) && 0 <= original < 18446744073709551616 && forall j | 0 <= j < |qs| :: StrOk(qs[j].requestId) && 0 <= qs[j].amount < 18446744073709551616) {
      code, text := 3, UnverifiableText("ENCODE_INPUT", json);
      return;
    }
    assert Encodable(g, qs);
    var bytes := EncodeLog(g, qs);
    var o := Verify(bytes, key);
    assert bytes + [] == bytes;
    ExactOnModelLogs(g, qs, []);
    if !o.Accept? {
      code, text := 3, UnverifiableText("INVALID_HISTORY", json);
      return;
    }
    code, wal := 0, bytes;
    text := Line("ENCODED", 0, [("records", NatStr(|qs|), false), ("bytes", NatStr(|bytes|), false), ("tail", Hex(o.tail, 32), true)], json);
  }
}
