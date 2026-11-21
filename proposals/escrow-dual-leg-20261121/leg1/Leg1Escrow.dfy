// Leg1Escrow.dfy — Forge V2 Escrow verifier, LEG 1 (Dafny).
// Independent second implementation of the N-version check. Built clean-room
// from SPEC.md (spec_packet_hash 51d1d035) + the golden vectors only.
//
// Structure:
//   module Model    — the PROVED core: little-endian encode/decode round-trip
//                      (both directions), header round-trip, and the money-fold
//                      soundness + completeness lemmas (no precondition on input).
//   module Verifier — the executable fold that implements SPEC §3/§4/§5, the CLI
//                      decision order (§9), and emits the §9.6 canonical object.
//                      SHA-256/512 (Sha) and Ed25519 strict (Ed) are executable
//                      and self-tested, not proved correct.
include "./Ed.dfy"

// ===========================================================================
//  PROVED CORE
// ===========================================================================
module Model {
  import opened Sha

  function Pow256(n: nat): nat
    ensures Pow256(n) >= 1
    decreases n
  { if n == 0 then 1 else 256 * Pow256(n - 1) }

  // little-endian decode of n bytes starting at off
  function LED(s: seq<byte>, off: nat, n: nat): nat
    requires off + n <= |s|
    decreases n
  { if n == 0 then 0 else (s[off] as nat) + 256 * LED(s, off + 1, n - 1) }

  // LED depends only on the slice s[off..off+n].
  lemma LEDOffset(s: seq<byte>, off: nat, n: nat)
    requires off + n <= |s|
    ensures LED(s, off, n) == LED(s[off..], 0, n)
    decreases n
  {
    if n == 0 {
    } else {
      LEDOffset(s, off + 1, n - 1);
      assert s[off..][1..] == s[off + 1..];
    }
  }

  // little-endian encode of v into n bytes (low byte first)
  function LEE(v: nat, n: nat): seq<byte>
    decreases n
  { if n == 0 then []
    else [ (v % 256) as byte ] + LEE(v / 256, n - 1) }

  lemma LEELen(v: nat, n: nat)
    ensures |LEE(v, n)| == n
    decreases n
  { if n == 0 {} else { LEELen(v / 256, n - 1); } }

  // Round-trip, direction 1: decode(encode(v)) == v for v < 256^n.
  lemma LERoundTrip(v: nat, n: nat)
    requires v < Pow256(n)
    ensures |LEE(v, n)| == n
    ensures LED(LEE(v, n), 0, n) == v
    decreases n
  {
    LEELen(v, n);
    if n == 0 {
    } else {
      var enc := LEE(v, n);
      assert enc[0] == (v % 256) as byte;
      assert enc[1..] == LEE(v / 256, n - 1);
      LERoundTrip(v / 256, n - 1);
      LEDOffset(enc, 1, n - 1);
      assert LED(enc, 1, n - 1) == LED(enc[1..], 0, n - 1);
      assert LED(enc, 1, n - 1) == v / 256;
      assert LED(enc, 0, n) == (enc[0] as nat) + 256 * LED(enc, 1, n - 1);
    }
  }

  // Round-trip, direction 2: encode(decode(s)) == s[off..off+n]  (canonical decode).
  lemma LERoundTrip2(s: seq<byte>, off: nat, n: nat)
    requires off + n <= |s|
    ensures LEE(LED(s, off, n), n) == s[off..off + n]
    decreases n
  {
    if n == 0 {
      assert s[off..off] == [];
    } else {
      var v := LED(s, off, n);
      // low byte of v is s[off]
      calc {
        v % 256;
        ((s[off] as nat) + 256 * LED(s, off + 1, n - 1)) % 256;
        (s[off] as nat) % 256;
        s[off] as nat;
      }
      calc {
        v / 256;
        ((s[off] as nat) + 256 * LED(s, off + 1, n - 1)) / 256;
        LED(s, off + 1, n - 1);
      }
      LERoundTrip2(s, off + 1, n - 1);
      assert LEE(v, n) == [ (v % 256) as byte ] + LEE(v / 256, n - 1);
      assert [ (v % 256) as byte ] == [ s[off] ];
      assert LEE(v / 256, n - 1) == s[off + 1 .. off + n];
      assert [ s[off] ] + s[off + 1 .. off + n] == s[off .. off + n];
    }
  }

  // ---- 16-byte record header round-trip (both directions, canonical) ----
  datatype Header = Header(magic: seq<byte>, version: byte, domain: byte,
                           kind: byte, reserved: seq<byte>, seqno: nat)

  predicate WFHeader(h: Header) {
    |h.magic| == 3 && |h.reserved| == 2 && h.seqno < Pow256(8)
  }

  function EncHeader(h: Header): seq<byte>
    requires WFHeader(h)
  { h.magic + [h.version, h.domain, h.kind] + h.reserved + LEE(h.seqno, 8) }

  function DecHeader(s: seq<byte>): Header
    requires |s| >= 16
  { Header(s[0..3], s[3], s[4], s[5], s[6..8], LED(s, 8, 8)) }

  lemma HeaderRoundTrip(h: Header)
    requires WFHeader(h)
    ensures |EncHeader(h)| == 16
    ensures DecHeader(EncHeader(h)) == h
  {
    LEELen(h.seqno, 8);
    var e := EncHeader(h);
    LERoundTrip(h.seqno, 8);
    assert e[0..3] == h.magic;
    assert e[6..8] == h.reserved;
    assert e[8..] == LEE(h.seqno, 8);
    LEDOffset(e, 8, 8);
    assert LED(e, 8, 8) == LED(e[8..], 0, 8) == LED(LEE(h.seqno, 8), 0, 8) == h.seqno;
  }

  lemma HeaderRoundTrip2(s: seq<byte>)
    requires |s| >= 16
    ensures WFHeader(DecHeader(s))
    ensures EncHeader(DecHeader(s)) == s[0..16]
  {
    var h := DecHeader(s);
    LERoundTrip2(s, 8, 8);
    assert EncHeader(h) == s[0..3] + [s[3], s[4], s[5]] + s[6..8] + LEE(LED(s, 8, 8), 8);
    assert LEE(LED(s, 8, 8), 8) == s[8..16];
  }

  // ===========================================================================
  //  MONEY-FOLD soundness + completeness (SPEC §1, §5.2 checks 7,9,10)
  // ===========================================================================
  const MONEY_MAX: nat := 9223372036854775807   // 2^63 - 1

  predicate Money(v: int) { 0 <= v <= MONEY_MAX }

  function SumSeller(xs: seq<nat>): nat
    decreases |xs|
  { if |xs| == 0 then 0 else xs[0] + SumSeller(xs[1..]) }

  datatype Opt<T> = None | Some(v: T)

  // A step pair is (seller_amount, gross_field). The fold models SPEC §5.2
  // checks 7 (Money), 9 (conservation gross == run+seller) and 10 (gross <= cap).
  // NO precondition: it accepts an arbitrary sequence of arbitrary pairs.
  function MoneyFold(cap: nat, steps: seq<(nat, nat)>, run: nat): Opt<nat>
    decreases |steps|
  {
    if |steps| == 0 then Some(run)
    else
      var sa := steps[0].0;
      var gf := steps[0].1;
      if !Money(sa) || !Money(gf) then None
      else if gf != run + sa then None
      else if gf > cap then None
      else MoneyFold(cap, steps[1..], gf)
  }

  function Sellers(steps: seq<(nat, nat)>): seq<nat>
    decreases |steps|
  { if |steps| == 0 then [] else [steps[0].0] + Sellers(steps[1..]) }

  // SOUNDNESS: an accepted fold conserves money and never exceeds the cap.
  // If MoneyFold returns Some(g) then g == run + sum(seller amounts) and g <= cap.
  lemma MoneyFoldSound(cap: nat, steps: seq<(nat, nat)>, run: nat)
    requires run <= cap
    requires MoneyFold(cap, steps, run).Some?
    ensures MoneyFold(cap, steps, run).v == run + SumSeller(Sellers(steps))
    ensures MoneyFold(cap, steps, run).v <= cap
    decreases |steps|
  {
    if |steps| == 0 {
    } else {
      var gf := steps[0].1;
      // the fold took the recursive branch, so gf <= cap and gf == run + sa
      MoneyFoldSound(cap, steps[1..], gf);
      assert Sellers(steps) == [steps[0].0] + Sellers(steps[1..]);
    }
  }

  // COMPLETENESS: a canonical good history always folds to ACCEPT.
  // Build canonical steps from seller amounts with gross = running sum.
  function CanonSteps(run: nat, sellers: seq<nat>): seq<(nat, nat)>
    decreases |sellers|
  {
    if |sellers| == 0 then []
    else [(sellers[0], run + sellers[0])] + CanonSteps(run + sellers[0], sellers[1..])
  }

  lemma MoneyFoldComplete(cap: nat, sellers: seq<nat>, run: nat)
    requires Money(cap)
    requires run <= cap
    requires forall k :: 0 <= k < |sellers| ==> Money(sellers[k])
    requires run + SumSeller(sellers) <= cap
    ensures MoneyFold(cap, CanonSteps(run, sellers), run) == Some(run + SumSeller(sellers))
    decreases |sellers|
  {
    if |sellers| == 0 {
    } else {
      var sa := sellers[0];
      var gf := run + sa;
      assert Money(sa);
      // gf <= run + SumSeller(sellers) <= cap, and cap <= MONEY_MAX so Money(gf)
      assert SumSeller(sellers) == sellers[0] + SumSeller(sellers[1..]);
      assert gf <= cap;
      assert Money(gf);
      var rest := CanonSteps(gf, sellers[1..]);
      assert CanonSteps(run, sellers) == [(sa, gf)] + rest;
      MoneyFoldComplete(cap, sellers[1..], gf);
    }
  }
}

// ===========================================================================
//  EXECUTABLE VERIFIER
// ===========================================================================
module Verifier {
  import opened Sha
  import opened Ed
  import Model

  // ---- verdict names (ASCII) ----
  function Asc(s: string): seq<byte>
  { seq(|s|, i requires 0 <= i < |s| => ((s[i] as int) % 256) as byte) }

  const MONEY_MAX: nat := 9223372036854775807

  function Pow(b: nat, n: nat): nat decreases n
  { if n == 0 then 1 else b * Pow(b, n - 1) }

  // little-endian decode of n bytes
  function LE(s: seq<byte>, off: nat, n: nat): nat
    requires off + n <= |s|
    decreases n
  { if n == 0 then 0 else (s[off] as nat) + 256 * LE(s, off + 1, n - 1) }

  function Zeros(n: nat): seq<byte> { seq(n, i => 0 as byte) }

  function HexDigit(v: nat): byte
    requires 0 <= v < 16
  { if v < 10 then (48 + v) as byte else (87 + v) as byte }  // lowercase ('a'=97=87+10)

  function HexOf(b: seq<byte>): seq<byte>
    decreases |b|
  {
    if |b| == 0 then []
    else [ HexDigit((b[0] as nat) / 16), HexDigit((b[0] as nat) % 16) ] + HexOf(b[1..])
  }

  predicate IsHexChar(c: byte) {
    var v := c as int;
    (48 <= v <= 57) || (97 <= v <= 102) || (65 <= v <= 70)
  }
  function LowerHex(c: byte): byte {
    var v := c as int;
    if 65 <= v <= 70 then (v + 32) as byte else c
  }
  function LowerHexSeq(s: seq<byte>): seq<byte>
    decreases |s|
  { if |s| == 0 then [] else [LowerHex(s[0])] + LowerHexSeq(s[1..]) }

  predicate ValidHex64(h: seq<byte>) {
    |h| == 64 && forall i :: 0 <= i < |h| ==> IsHexChar(h[i])
  }

  const MAGIC: seq<byte> := [0x46 as byte, 0x56 as byte, 0x32 as byte]  // "FV2"

  // Result bundle mirrors the §9.6 canonical object.
  datatype Res = Res(
    verdict: seq<byte>, exitCode: int, records: int, tornBytes: int,
    failNull: bool, failIndex: int,
    gross: int, sellerPayout: int, buyerRefund: int,
    tip: seq<byte>, epoch: int, expiryGate: bool)

  // Verify a single whole record's seal: seal == SHA256(record[0..96]).
  method SealOk(rec: seq<byte>) returns (ok: bool)
    requires |rec| == 128
  {
    var h := Sha256(rec[0..96]);
    ok := h == rec[96..128];
  }

  method WholeHash(rec: seq<byte>) returns (h: seq<byte>)
    requires |rec| == 128
    ensures |h| == 32
  { h := Sha256(rec); }

  // ---- the full verifier ----
  method VerifyCLI(
      log: seq<byte>,
      manifestPresent: bool, manifest: seq<byte>,
      pubPresent: bool, pubA: seq<byte>, pubB: seq<byte>,
      tapePresent: bool, tape: seq<byte>,
      obsPresent: bool, observedNow: nat,
      tipPresent: bool, expectTip: seq<byte>,
      maxRecords: nat)
    returns (r: Res)
  {
    var records := |log| / 128;
    var tornBytes := |log| % 128;
    // defaults
    r := Res(Asc("UNVERIFIABLE_INTERNAL"), 3, records, tornBytes,
             true, 0, 0, 0, 0, [], 0, false);

    // (1) USAGE: required args present + pubkey shape (decided before the fold;
    //     records/torn still reported from the file length). SPEC §9.1.
    if !manifestPresent || !pubPresent {
      r := r.(verdict := Asc("UNVERIFIABLE_USAGE"), exitCode := 3); return;
    }
    if |pubA| != 32 || |pubB| != 32 {
      r := r.(verdict := Asc("UNVERIFIABLE_USAGE"), exitCode := 3); return;
    }
    // (2) EMPTY / NO_RECORD
    if |log| == 0 {
      r := r.(verdict := Asc("UNVERIFIABLE_EMPTY"), exitCode := 3); return;
    }
    if records == 0 {  // 1..127 bytes
      r := r.(verdict := Asc("UNVERIFIABLE_NO_RECORD"), exitCode := 3); return;
    }
    // (3) TOO_LARGE
    if records > maxRecords {
      r := r.(verdict := Asc("UNVERIFIABLE_TOO_LARGE"), exitCode := 3); return;
    }
    // (4) observed_now required when >=1 step (records >= 2). SPEC §5/Q6.
    if records >= 2 && !obsPresent {
      r := r.(verdict := Asc("UNVERIFIABLE_USAGE"), exitCode := 3); return;
    }
    // (5) expect-tip format. SPEC §9.5/Q13.5.
    if tipPresent && !ValidHex64(expectTip) {
      r := r.(verdict := Asc("UNVERIFIABLE_USAGE"), exitCode := 3); return;
    }

    // ---------- GENESIS (index 0) ----------
    var g := log[0..128];
    // step 1 (rr4 Option B, SPEC §3.2): the §2 wire-envelope checks run FIRST at
    // index 0 too, BEFORE the genesis-specific checks.
    //   1. magic / version / header-reserved -> REJECT_MALFORMED_RECORD
    if g[0..3] != MAGIC {
      r := r.(verdict := Asc("REJECT_MALFORMED_RECORD"), exitCode := 1, failNull := false, failIndex := 0); return;
    }
    if g[3] != 2 as byte {
      r := r.(verdict := Asc("REJECT_MALFORMED_RECORD"), exitCode := 1, failNull := false, failIndex := 0); return;
    }
    if g[6..8] != Zeros(2) {
      r := r.(verdict := Asc("REJECT_MALFORMED_RECORD"), exitCode := 1, failNull := false, failIndex := 0); return;
    }
    //   2. kind != 'G' -> REJECT_BAD_GENESIS (Q2a). The kind gate runs BEFORE the
    //      seq_no check: a STEP record promoted to index 0 is BAD_GENESIS, not
    //      SEQ_MISMATCH. (Conforms to frozen Leg 2.)
    if g[5] != 0x47 as byte {  // 'G'
      r := r.(verdict := Asc("REJECT_BAD_GENESIS"), exitCode := 1, failNull := false, failIndex := 0); return;
    }
    //   3. seq_no != 0 (seq_no == index) -> REJECT_SEQ_MISMATCH
    if LE(g, 8, 8) != 0 {
      r := r.(verdict := Asc("REJECT_SEQ_MISMATCH"), exitCode := 1, failNull := false, failIndex := 0); return;
    }
    //   4. genesis-specific: prev_hash -> BAD_GENESIS (Q1); domain_id -> BAD_DOMAIN
    if g[16..48] != Zeros(32) {  // genesis prev_hash must be zero
      r := r.(verdict := Asc("REJECT_BAD_GENESIS"), exitCode := 1, failNull := false, failIndex := 0); return;
    }
    if g[4] != 2 as byte {
      r := r.(verdict := Asc("REJECT_BAD_DOMAIN"), exitCode := 1, failNull := false, failIndex := 0); return;
    }
    //   4. seal
    var gseal := SealOk(g);
    if !gseal {
      r := r.(verdict := Asc("REJECT_BAD_SEAL"), exitCode := 1, failNull := false, failIndex := 0); return;
    }
    // step 2 Money(cap)
    var cap := LE(g, 48, 8);
    var expiresAt := LE(g, 56, 8);
    if cap > MONEY_MAX {
      r := r.(verdict := Asc("REJECT_AMOUNT_NOT_MONEY"), exitCode := 1, failNull := false, failIndex := 0); return;
    }
    // step 3 manifest length + hash agreement
    var manifestHash := g[64..96];
    if |manifest| != 176 {
      r := r.(verdict := Asc("REJECT_BAD_GENESIS"), exitCode := 1, failNull := false, failIndex := 0); return;
    }
    var mh := Sha256(manifest);
    if mh != manifestHash {
      r := r.(verdict := Asc("REJECT_BAD_GENESIS"), exitCode := 1, failNull := false, failIndex := 0); return;
    }
    // step 4 manifest cap/expires match in-clear
    var mCap := LE(manifest, 160, 8);
    var mExp := LE(manifest, 168, 8);
    if mCap != cap || mExp != expiresAt {
      r := r.(verdict := Asc("REJECT_BAD_GENESIS"), exitCode := 1, failNull := false, failIndex := 0); return;
    }
    // step 5 manifest id emptiness
    var dealId := manifest[0..32];
    var escrowId := manifest[128..160];
    if dealId == Zeros(32) || escrowId == Zeros(32) {
      r := r.(verdict := Asc("REJECT_EMPTY_ID"), exitCode := 1, failNull := false, failIndex := 0); return;
    }
    // step 6 key validity
    var keyA := manifest[32..64];
    var keyB := manifest[64..96];
    var vkA := ValidateKey(keyA);
    var vkB := ValidateKey(keyB);
    if vkA != 0 || vkB != 0 {
      r := r.(verdict := Asc("REJECT_BAD_KEY"), exitCode := 1, failNull := false, failIndex := 0); return;
    }
    // step 7 pinned-key cross-check
    if pubA != keyA || pubB != keyB {
      r := r.(verdict := Asc("REJECT_KEY_MISMATCH"), exitCode := 1, failNull := false, failIndex := 0); return;
    }
    // genesis signatures when tape present (both over genesis seal)
    if tapePresent {
      var gseal32 := g[96..128];
      if |tape| < 128 {
        r := r.(verdict := Asc("REJECT_BAD_SIGNATURE"), exitCode := 1, failNull := false, failIndex := 0); return;
      }
      var sA := tape[0..64];
      var sB := tape[64..128];
      var rA := VerifyStrict(keyA, sA, gseal32);
      var rB := VerifyStrict(keyB, sB, gseal32);
      if rA != 0 || rB != 0 {
        r := r.(verdict := Asc("REJECT_BAD_SIGNATURE"), exitCode := 1, failNull := false, failIndex := 0); return;
      }
    }

    // folded state
    var gross := 0;
    var settled: set<seq<byte>> := {};
    var tsPrev := 0;
    var tipHash := g;           // placeholder; overwrite below
    var th := WholeHash(g);
    tipHash := th;
    var expiryEvaluated := false;

    // ---------- STEPS (index 1..records-1) ----------
    var i := 1;
    while i < records
      invariant 1 <= i <= records
      invariant 0 <= gross <= cap
    {
      var rec := log[i * 128 .. i * 128 + 128];
      // step 1 structural
      if rec[0..3] != MAGIC {
        r := r.(verdict := Asc("REJECT_MALFORMED_RECORD"), exitCode := 1, failNull := false, failIndex := i); return;
      }
      if rec[3] != 2 as byte {
        r := r.(verdict := Asc("REJECT_MALFORMED_RECORD"), exitCode := 1, failNull := false, failIndex := i); return;
      }
      if rec[4] != 2 as byte {
        r := r.(verdict := Asc("REJECT_BAD_DOMAIN"), exitCode := 1, failNull := false, failIndex := i); return;
      }
      if rec[5] != 0x53 as byte {  // 'S'
        r := r.(verdict := Asc("REJECT_MALFORMED_RECORD"), exitCode := 1, failNull := false, failIndex := i); return;
      }
      if rec[6..8] != Zeros(2) {
        r := r.(verdict := Asc("REJECT_MALFORMED_RECORD"), exitCode := 1, failNull := false, failIndex := i); return;
      }
      // step 2 payload reserved [88..96) zero, BEFORE seq/prev/seal
      if rec[88..96] != Zeros(8) {
        r := r.(verdict := Asc("REJECT_MALFORMED_RECORD"), exitCode := 1, failNull := false, failIndex := i); return;
      }
      // step 3 seq_no == i
      if LE(rec, 8, 8) != i {
        r := r.(verdict := Asc("REJECT_SEQ_MISMATCH"), exitCode := 1, failNull := false, failIndex := i); return;
      }
      // step 4 prev_hash == tip_hash
      if rec[16..48] != tipHash {
        r := r.(verdict := Asc("REJECT_CHAIN_BREAK"), exitCode := 1, failNull := false, failIndex := i); return;
      }
      // step 5 seal
      var sok := SealOk(rec);
      if !sok {
        r := r.(verdict := Asc("REJECT_BAD_SEAL"), exitCode := 1, failNull := false, failIndex := i); return;
      }
      // step 6 step_id non-empty
      var stepId := rec[48..64];
      if stepId == Zeros(16) {
        r := r.(verdict := Asc("REJECT_EMPTY_ID"), exitCode := 1, failNull := false, failIndex := i); return;
      }
      // step 7 Money(seller_amount) && Money(gross_spent)
      var sellerAmount := LE(rec, 64, 8);
      var grossSpent := LE(rec, 72, 8);
      var recordTs := LE(rec, 80, 8);
      if sellerAmount > MONEY_MAX || grossSpent > MONEY_MAX {
        r := r.(verdict := Asc("REJECT_AMOUNT_NOT_MONEY"), exitCode := 1, failNull := false, failIndex := i); return;
      }
      // step 8 record_ts non-decreasing
      if recordTs < tsPrev {
        r := r.(verdict := Asc("REJECT_SEQ_MISMATCH"), exitCode := 1, failNull := false, failIndex := i); return;
      }
      // step 9 conservation
      if grossSpent != gross + sellerAmount {
        r := r.(verdict := Asc("REJECT_CHAIN_BREAK"), exitCode := 1, failNull := false, failIndex := i); return;
      }
      // step 10 cap (gross_refunded == 0 vacuous)
      if grossSpent > cap {
        r := r.(verdict := Asc("REJECT_OVER_CAP"), exitCode := 1, failNull := false, failIndex := i); return;
      }
      // step 11 duplicate id
      if stepId in settled {
        r := r.(verdict := Asc("REJECT_DUPLICATE_ID"), exitCode := 1, failNull := false, failIndex := i); return;
      }
      // step 12 expiry (observed_now required here; present because records>=2)
      expiryEvaluated := true;
      if obsPresent && observedNow >= expiresAt {
        r := r.(verdict := Asc("REJECT_EXPIRED"), exitCode := 1, failNull := false, failIndex := i, expiryGate := true); return;
      }
      // step 13 signatures (only with tape)
      if tapePresent {
        var seal32 := rec[96..128];
        if |tape| < i * 128 + 128 {
          r := r.(verdict := Asc("REJECT_BAD_SIGNATURE"), exitCode := 1, failNull := false, failIndex := i); return;
        }
        var sA := tape[i * 128 .. i * 128 + 64];
        var sB := tape[i * 128 + 64 .. i * 128 + 128];
        var rA := VerifyStrict(keyA, sA, seal32);
        var rB := VerifyStrict(keyB, sB, seal32);
        if rA != 0 || rB != 0 {
          r := r.(verdict := Asc("REJECT_BAD_SIGNATURE"), exitCode := 1, failNull := false, failIndex := i); return;
        }
      }
      // accept step: update state
      gross := grossSpent;
      settled := settled + {stepId};
      tsPrev := recordTs;
      var nh := WholeHash(rec);
      tipHash := nh;
      i := i + 1;
    }

    // ---------- fold succeeded ----------
    var lastTipHex := HexOf(tipHash);

    // expect-tip anchor: compared against SHA256 of last whole record, even when
    // the file would otherwise be ACCEPT_TORN_TAIL (Q10b). Mismatch -> CHAIN_BREAK,
    // fail_index null (Q10a), all accept-fields zeroed.
    if tipPresent {
      var want := LowerHexSeq(expectTip);
      if want != lastTipHex {
        r := r.(verdict := Asc("REJECT_CHAIN_BREAK"), exitCode := 1, failNull := true, failIndex := 0,
                gross := 0, sellerPayout := 0, buyerRefund := 0, tip := [], epoch := 0, expiryGate := false);
        return;
      }
    }

    var hasSteps := records >= 2;
    var finalGross := gross;
    var payout := finalGross;
    var refund := cap - finalGross;  // cap >= gross by the OVER_CAP check
    var eg := hasSteps;              // ACCEPT with steps => expiry gate decided

    if tornBytes > 0 {
      r := Res(Asc("ACCEPT_TORN_TAIL"), 4, records, tornBytes, true, 0,
               finalGross, payout, refund, lastTipHex, records, eg);
    } else {
      r := Res(Asc("ACCEPT"), 0, records, tornBytes, true, 0,
               finalGross, payout, refund, lastTipHex, records, eg);
    }
  }
}
