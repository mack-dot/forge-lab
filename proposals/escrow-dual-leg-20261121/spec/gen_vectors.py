#!/usr/bin/env python3
# gen_vectors.py - Forge V2 Leg-2 escrow golden-vector generator.
# Python standard library ONLY (hashlib). No external packages, no pip, no network.
# Run once:  python3 gen_vectors.py
#
# Implements the owner ratification RATIFICATION_2026-11-21.md (Q1-Q14).
# Vectors are BLACK-BOX: input bytes -> expected --json verdict object. They carry
# zero Leg-1 content. Shared vectors are the cross-check substrate; only the two
# IMPLEMENTATIONS must stay independent.
#
# Ed25519 is a VENDORED pure-Python RFC 8032 reference (hashlib SHA-512 only). It is a
# standard public-domain crypto primitive, NOT Leg-1 content. It is self-tested
# against RFC 8032 test vectors before any key is minted or any record is signed.

import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "golden_vectors")

# ================================================================================
# VENDORED Ed25519 (RFC 8032 reference, public domain). hashlib SHA-512 only.
# Strict profile used by sign/verify: cofactorless [S]B = R + [k]A, reject S>=L,
# reject non-canonical A/R (y >= p), reject small-order A (cofactor*A == identity).
# ================================================================================
_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493   # group order (L)


def _sha512(b):
    return hashlib.sha512(b).digest()


def _modp_inv(x):
    return pow(x, _P - 2, _P)


_D = -121665 * _modp_inv(121666) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * _modp_inv(_D * y * y + 1) % _P
    if x2 == 0:
        if sign:
            return None
        return 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_GY = 4 * _modp_inv(5) % _P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)
_IDENT = (0, 1, 1, 0)


def _point_add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % _P
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % _P
    C = 2 * P[3] * Q[3] * _D % _P
    Dd = 2 * P[2] * Q[2] % _P
    E, F, Gg, H = B - A, Dd - C, Dd + C, B + A
    return (E * F % _P, Gg * H % _P, F * Gg % _P, E * H % _P)


def _point_mul(s, P):
    Q = _IDENT
    while s > 0:
        if s & 1:
            Q = _point_add(Q, P)
        P = _point_add(P, P)
        s >>= 1
    return Q


def _point_equal(P, Q):
    if (P[0] * Q[2] - Q[0] * P[2]) % _P != 0:
        return False
    if (P[1] * Q[2] - Q[1] * P[2]) % _P != 0:
        return False
    return True


def _point_compress(P):
    zinv = _modp_inv(P[2])
    x = P[0] * zinv % _P
    y = P[1] * zinv % _P
    return int(y | ((x & 1) << 255)).to_bytes(32, "little")


def _point_decompress(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def _secret_expand(secret):
    h = _sha512(secret)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= (1 << 254)
    return a, h[32:]


def ed_public(secret):
    a, _ = _secret_expand(secret)
    return _point_compress(_point_mul(a, _G))


def ed_sign(secret, msg):
    a, prefix = _secret_expand(secret)
    A = _point_compress(_point_mul(a, _G))
    r = int.from_bytes(_sha512(prefix + msg), "little") % _L
    R = _point_mul(r, _G)
    Rs = _point_compress(R)
    k = int.from_bytes(_sha512(Rs + A + msg), "little") % _L
    s = (r + k * a) % _L
    return Rs + int(s).to_bytes(32, "little")


def ed_verify(public, msg, signature):
    # Strict: reject non-canonical A/R, reject S>=L, cofactorless equality.
    if len(public) != 32 or len(signature) != 64:
        return False
    A = _point_decompress(public)
    if A is None:
        return False
    Rs = signature[:32]
    R = _point_decompress(Rs)
    if R is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    k = int.from_bytes(_sha512(Rs + public + msg), "little") % _L
    return _point_equal(_point_mul(s, _G), _point_add(R, _point_mul(k, A)))


def ed_is_small_order(public):
    # True if the key is non-canonical OR small-order (cofactor*A == identity).
    A = _point_decompress(public)
    if A is None:
        return True
    return _point_equal(_point_mul(8, A), _IDENT)


def ed_sig_small_order_R(signature):
    # Strict-profile sub-check (Q11, SPEC 9.3): True if the signature's R (the first
    # 32 bytes) is a small-order point. A strict cofactorless verifier MUST reject
    # such a signature as REJECT_BAD_SIGNATURE (a cofactored library would accept a
    # torsion-added R and diverge).
    return ed_is_small_order(signature[:32])


def ed25519_selftest():
    # RFC 8032 Test 2 (exact deterministic match) + Test 1 (verify-only) + roundtrip
    # + small-order detection. Raises AssertionError on any failure.
    sk2 = bytes.fromhex(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
    pk2 = bytes.fromhex(
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
    msg2 = bytes.fromhex("72")
    sig2 = bytes.fromhex(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")
    assert ed_public(sk2) == pk2, "RFC8032 Test2 public-key derivation failed"
    assert ed_sign(sk2, msg2) == sig2, "RFC8032 Test2 deterministic sign failed"
    assert ed_verify(pk2, msg2, sig2), "RFC8032 Test2 verify failed"
    assert not ed_verify(pk2, bytes.fromhex("73"), sig2), "verify-tampered-msg leaked"

    pk1 = bytes.fromhex(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    sig1 = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    assert ed_verify(pk1, b"", sig1), "RFC8032 Test1 verify (empty msg) failed"

    sk = hashlib.sha256(b"selftest-roundtrip-seed").digest()
    pk = ed_public(sk)
    sg = ed_sign(sk, b"hello-forge")
    assert ed_verify(pk, b"hello-forge", sg), "roundtrip verify failed"
    bad = bytearray(sg)
    bad[0] ^= 0xFF
    assert not ed_verify(pk, b"hello-forge", bytes(bad)), "corrupt-sig leaked"

    ident = b"\x01" + b"\x00" * 31  # neutral element (order 1): small order
    assert ed_is_small_order(ident), "small-order detection missed identity"
    assert not ed_is_small_order(pk), "false small-order on a real key"

    # small-order R detection (Q11 FIX): a signature carrying a small-order R is
    # flagged; a real signature's R is not.
    so_r = bytes.fromhex(
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")  # order 8
    assert ed_is_small_order(so_r), "order-8 R not detected as small-order"
    assert ed_sig_small_order_R(so_r + sg[32:]), "small-order-R sig not flagged"
    assert not ed_sig_small_order_R(sg), "false small-order-R on a real signature"
    return ("PASS (RFC8032 Test1 verify, Test2 derive+sign+verify, roundtrip, "
            "small-order A, small-order R)")


# ================================================================================
# Envelope / payload builders (widths FROZEN; magic FV2 RATIFIED FINAL, Q12).
# ================================================================================
MAGIC = b"FV2"            # 0x46 0x56 0x32, RATIFIED FINAL (Q12, O-1 closed)
VERSION = 2
DOMAIN = 2
KIND_G = 0x47             # 'G'
KIND_S = 0x53            # 'S'
P63 = 2 ** 63            # first NOT_MONEY value
MAXMONEY = P63 - 1       # last accepted money value
DEFAULT_MAX_RECORDS = 1048576   # Q8: 128 MiB of whole records
ZERO32 = b"\x00" * 32
IDENTITY_KEY = b"\x01" + b"\x00" * 31   # small-order (neutral) point, for BAD_KEY
SMALL_ORDER_R = bytes.fromhex(          # an order-8 point, for small-order-R signature
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")

CAP = 500                 # $5.00
EXPIRES_AT = 2_000_000_000
TS1, TS2, TS3 = 1_700_000_000, 1_700_000_001, 1_700_000_002
OBSERVED_NOW = 1_700_000_500
SPEC_HASH = hashlib.sha256(b"ratified-acceptance-checker-v1").digest()

# Real minted keys (deterministic seeds so vectors are reproducible).
SEC_A = hashlib.sha256(b"forge-v2-escrow-leg2/key-A/v1").digest()
SEC_B = hashlib.sha256(b"forge-v2-escrow-leg2/key-B/v1").digest()
SEC_C = hashlib.sha256(b"forge-v2-escrow-leg2/key-C-wrong/v1").digest()
SEC_D = hashlib.sha256(b"forge-v2-escrow-leg2/key-D-wrong/v1").digest()
KEY_A = KEY_B = KEY_C = KEY_D = None   # filled in main() after the self-test

DEAL_ID = "deal-escrow-0001"
ESCROW_ID = "escrow-0001"


def sha256(b):
    return hashlib.sha256(b).digest()


def u64(v):
    return int(v).to_bytes(8, "little")


def id_field(s, width):
    # RAW fixed bytes (bytewise). Accepts str (ascii test labels) or raw bytes.
    b = s if isinstance(s, (bytes, bytearray)) else s.encode("ascii")
    assert len(b) <= width, "id too long"
    return bytes(b) + b"\x00" * (width - len(b))


def manifest_bytes(deal_id=DEAL_ID, cap=CAP, expires_at=EXPIRES_AT,
                   spec_hash=SPEC_HASH, key_a=None, key_b=None,
                   escrow_id=ESCROW_ID):
    # 176-byte canonical GenesisManifest (FROZEN):
    # deal_id[0..32] key_A[32..64] key_B[64..96] spec_hash[96..128]
    # escrow_id[128..160] cap[160..168] expires_at[168..176].
    m = (id_field(deal_id, 32) + (key_a if key_a is not None else KEY_A) +
         (key_b if key_b is not None else KEY_B) + spec_hash +
         id_field(escrow_id, 32) + u64(cap) + u64(expires_at))
    assert len(m) == 176, len(m)
    return m


def genesis_payload(cap, expires_at, manifest_sha):
    p = u64(cap) + u64(expires_at) + manifest_sha
    assert len(p) == 48
    return p


def step_payload(step_id, seller_amount, gross_spent, record_ts,
                 raw_step_id=None, reserved8=b"\x00" * 8):
    sid = raw_step_id if raw_step_id is not None else id_field(step_id, 16)
    assert len(sid) == 16 and len(reserved8) == 8
    p = sid + u64(seller_amount) + u64(gross_spent) + u64(record_ts) + reserved8
    assert len(p) == 48
    return p


def record(kind, seq_no, prev_hash, payload, magic=MAGIC, version=VERSION,
           domain=DOMAIN, reserved=b"\x00\x00", bad_seal=False):
    assert len(prev_hash) == 32 and len(payload) == 48 and len(reserved) == 2
    header = magic + bytes([version, domain, kind]) + reserved + u64(seq_no)
    assert len(header) == 16, len(header)
    body = header + prev_hash + payload       # [0..96)
    seal = sha256(body)
    if bad_seal:
        seal = bytes((seal[0] ^ 0xFF,)) + seal[1:]
    rec = body + seal
    assert len(rec) == 128
    return rec


def build_genesis(cap=CAP, expires_at=EXPIRES_AT, manifest=None):
    if manifest is None:
        manifest = manifest_bytes(cap=cap, expires_at=expires_at)
    g = record(KIND_G, 0, ZERO32, genesis_payload(cap, expires_at, sha256(manifest)))
    return g, manifest


def chain_step(prev_rec, seq_no, step_id, seller_amount, gross_spent, record_ts,
               **kw):
    return record(KIND_S, seq_no, sha256(prev_rec),
                  step_payload(step_id, seller_amount, gross_spent, record_ts),
                  **kw)


def sign_record(secret, rec):
    # Q11: signed message = the 32-byte record_seal, bytes [96..128].
    return ed_sign(secret, rec[96:128])


# ================================================================================
# Case accumulator + canonical --json oracle (Q9 schema).
# ================================================================================
CASES = []


def bal(gross_spent, cap=CAP):
    return {"gross_spent": gross_spent, "seller_payout": gross_spent,
            "buyer_refund": cap - gross_spent}


def add(name, desc, records, manifest, *, verdict, exit_code,
        observed_now=OBSERVED_NOW, expect_tip=None, tape=None, max_records=None,
        torn=b"", fail_index=None, final=None, pubkeys_file="a.pub,b.pub",
        expiry_evaluated=None, note=None):
    log = b"".join(records) + torn
    add_raw(name, desc, log, manifest, verdict=verdict, exit_code=exit_code,
            observed_now=observed_now, expect_tip=expect_tip, tape=tape,
            max_records=max_records, fail_index=fail_index, final=final,
            pubkeys_file=pubkeys_file, expiry_evaluated=expiry_evaluated, note=note)


def add_raw(name, desc, log, manifest, *, verdict, exit_code,
            observed_now=OBSERVED_NOW, expect_tip=None, tape=None, max_records=None,
            fail_index=None, final=None, pubkeys_file="a.pub,b.pub",
            expiry_evaluated=None, note=None):
    with open(os.path.join(OUT, name + ".log.bin"), "wb") as f:
        f.write(log)
    with open(os.path.join(OUT, name + ".manifest.bin"), "wb") as f:
        f.write(manifest)
    tape_file = None
    if tape is not None:
        tape_file = name + ".tape.bin"
        with open(os.path.join(OUT, tape_file), "wb") as f:
            f.write(tape)

    nrec = len(log) // 128
    torn_bytes = len(log) % 128          # Q13.6: ALWAYS file length mod 128
    nsteps = sum(1 for i in range(nrec) if log[i * 128 + 5] == KIND_S)
    accept = verdict in ("ACCEPT", "ACCEPT_TORN_TAIL")
    if accept:
        tip = sha256(log[(nrec - 1) * 128:nrec * 128]).hex()
        fb = {"gross_spent": final["gross_spent"],
              "seller_payout": final["seller_payout"],
              "buyer_refund": final["buyer_refund"]}
        epoch = nrec
    else:
        tip = ""
        fb = {"gross_spent": 0, "seller_payout": 0, "buyer_refund": 0}
        epoch = 0
    if expiry_evaluated is None:
        expiry_evaluated = (accept and nsteps >= 1) or (verdict == "REJECT_EXPIRED")

    ejson = {
        "verdict": verdict,
        "exit_code": exit_code,
        "records": nrec,
        "torn_bytes": torn_bytes,
        "fail_index": fail_index,
        "final_balances": fb,
        "tip": tip,
        "epoch": epoch,
        "expiry_gate_evaluated": bool(expiry_evaluated),
        "notes": "",
    }
    CASES.append({
        "name": name,
        "description": desc,
        "log_file": name + ".log.bin",
        "manifest_file": name + ".manifest.bin",
        "tape_file": tape_file,
        "pubkeys_file": pubkeys_file,
        "observed_now": observed_now,
        "expect_tip": expect_tip,
        "max_records": max_records,
        "expected_json": ejson,
        "note": note,
    })


def main():
    os.makedirs(OUT, exist_ok=True)
    global KEY_A, KEY_B, KEY_C, KEY_D

    # 1) self-test the vendored Ed25519 BEFORE minting or signing.
    try:
        st = ed25519_selftest()
    except AssertionError as e:
        print("ED25519 SELF-TEST FAILED:", e, file=sys.stderr)
        sys.exit(3)
    print("ed25519 self-test:", st)

    # 2) mint real keys, write real pubkey files.
    KEY_A, KEY_B = ed_public(SEC_A), ed_public(SEC_B)
    KEY_C, KEY_D = ed_public(SEC_C), ed_public(SEC_D)
    assert not ed_is_small_order(KEY_A) and not ed_is_small_order(KEY_B)
    for fn, kb in (("a.pub", KEY_A), ("b.pub", KEY_B), ("badA.pub", IDENTITY_KEY)):
        with open(os.path.join(OUT, fn), "wb") as f:
            f.write(kb)

    g, man = build_genesis()
    s1 = chain_step(g, 1, "part-0001", 100, 100, TS1)
    s2 = chain_step(s1, 2, "part-0002", 100, 200, TS2)

    # ---------- ACCEPT ----------
    add("accept_genesis_only",
        "Valid genesis only, no steps; observed_now omitted (Q6/Q13.1: genesis-only "
        "ACCEPTs regardless of observed_now, no expiry gate).",
        [g], man, verdict="ACCEPT", exit_code=0, observed_now=None, final=bal(0))
    add("accept_one_step",
        "Genesis + one clean step of 100 (gross 100 <= cap 500).",
        [g, s1], man, verdict="ACCEPT", exit_code=0, final=bal(100))
    add("accept_two_step",
        "Genesis + two clean steps (gross 200 <= cap 500).",
        [g, s1, s2], man, verdict="ACCEPT", exit_code=0, final=bal(200))

    gmax, manmax = build_genesis(cap=MAXMONEY)
    smax = chain_step(gmax, 1, "part-max", MAXMONEY, MAXMONEY, TS1)
    add("accept_cap_boundary_2p63_minus_1",
        "cap = 2^63-1; one step spends exactly the cap. ACCEPT.",
        [gmax, smax], manmax, verdict="ACCEPT", exit_code=0,
        final=bal(MAXMONEY, cap=MAXMONEY))

    gbig, manbig = build_genesis(cap=MAXMONEY)
    a1 = 2 ** 53 - 1
    b1 = chain_step(gbig, 1, "cross-53", a1, a1, TS1)
    a2 = (2 ** 53 + 7) - a1
    b2 = chain_step(b1, 2, "cross-53b", a2, 2 ** 53 + 7, TS2)
    a3 = MAXMONEY - (2 ** 53 + 7)
    b3 = chain_step(b2, 3, "cross-63", a3, MAXMONEY, TS3)
    add("accept_gross_cross_2p53_and_2p63",
        "Cumulative gross crosses 2^53 then lands on 2^63-1 under a 2^63-1 cap "
        "(catches float drift). ACCEPT.",
        [gbig, b1, b2, b3], manbig, verdict="ACCEPT", exit_code=0,
        final=bal(MAXMONEY, cap=MAXMONEY))

    for n in (1, 64, 127):
        add("accept_torn_tail_%03d" % n,
            "Genesis + one step + %d trailing partial bytes. ACCEPT_TORN_TAIL." % n,
            [g, s1], man, verdict="ACCEPT_TORN_TAIL", exit_code=4,
            torn=bytes((0xAB,)) * n, final=bal(100))

    add("accept_expect_tip_match",
        "Two clean steps with --expect-tip = SHA-256 of the last whole record.",
        [g, s1, s2], man, verdict="ACCEPT", exit_code=0,
        expect_tip=sha256(s2).hex(), final=bal(200))

    # valid co-signed ACCEPT with --tape (real signatures over record_seal).
    tape_ok = b"".join([sign_record(SEC_A, g), sign_record(SEC_B, g),
                        sign_record(SEC_A, s1), sign_record(SEC_B, s1),
                        sign_record(SEC_A, s2), sign_record(SEC_B, s2)])
    # sanity: every signature verifies
    for i, rec in enumerate((g, s1, s2)):
        assert ed_verify(KEY_A, rec[96:128], tape_ok[(2 * i) * 64:(2 * i + 1) * 64])
        assert ed_verify(KEY_B, rec[96:128], tape_ok[(2 * i + 1) * 64:(2 * i + 2) * 64])
    add("accept_cosigned_tape",
        "Genesis + two steps WITH --tape: real Ed25519 co-signatures (sig_A+sig_B per "
        "record, signed message = 32-byte record_seal). ACCEPT.",
        [g, s1, s2], man, verdict="ACCEPT", exit_code=0, tape=tape_ok,
        final=bal(200))

    # ---------- REJECT: fold / structural ----------
    dup = chain_step(s2, 3, "part-0001", 100, 300, TS3)
    add("reject_duplicate_id",
        "Third step replays step_id 'part-0001' -> REJECT_DUPLICATE_ID at index 3.",
        [g, s1, s2, dup], man, verdict="REJECT_DUPLICATE_ID", exit_code=1,
        fail_index=3)

    s2badchain = record(KIND_S, 2, ZERO32,
                        step_payload("part-0002", 100, 200, TS2))
    add("reject_chain_break",
        "Step 2 prev_hash is 32 zeros, not SHA-256(record 1) -> REJECT_CHAIN_BREAK "
        "at index 2.",
        [g, s1, s2badchain], man, verdict="REJECT_CHAIN_BREAK", exit_code=1,
        fail_index=2)

    over = chain_step(g, 1, "part-over", 600, 600, TS1)
    add("reject_over_cap",
        "One step gross_spent 600 > cap 500 -> REJECT_OVER_CAP at index 1.",
        [g, over], man, verdict="REJECT_OVER_CAP", exit_code=1, fail_index=1)

    expstep = chain_step(g, 1, "part-late", 100, 100, TS1)
    add("reject_expired",
        "observed_now == expires_at (>= expires_at) -> REJECT_EXPIRED at index 1. "
        "Expiry keys on observed_now (Q6), not record_ts.",
        [g, expstep], man, verdict="REJECT_EXPIRED", exit_code=1,
        observed_now=EXPIRES_AT, fail_index=1)

    sealbad = record(KIND_S, 1, sha256(g),
                     step_payload("part-0001", 100, 100, TS1), bad_seal=True)
    add("reject_bad_seal",
        "Whole step record with a corrupted record_seal -> REJECT_BAD_SEAL at index 1 "
        "(NOT torn: a whole record that fails its seal is a REJECT).",
        [g, sealbad], man, verdict="REJECT_BAD_SEAL", exit_code=1, fail_index=1)

    nm = chain_step(g, 1, "part-nm", P63, P63, TS1)
    add("reject_not_money_2p63",
        "seller_amount = 2^63 (>= 2^63) -> REJECT_AMOUNT_NOT_MONEY at index 1.",
        [g, nm], man, verdict="REJECT_AMOUNT_NOT_MONEY", exit_code=1, fail_index=1)

    gcapnm, mancapnm = build_genesis(cap=P63)
    add("reject_genesis_cap_not_money",
        "Genesis cap = 2^63 -> REJECT_AMOUNT_NOT_MONEY at index 0 (cap IS money-gated).",
        [gcapnm], mancapnm, verdict="REJECT_AMOUNT_NOT_MONEY", exit_code=1,
        observed_now=None, fail_index=0)

    wrong_manifest = manifest_bytes(deal_id="deal-WRONG-9999")
    add("reject_manifest_mismatch",
        "Supplied manifest witness does not hash to payload manifest_sha256 "
        "-> REJECT_BAD_GENESIS at index 0.",
        [g], wrong_manifest, verdict="REJECT_BAD_GENESIS", exit_code=1,
        observed_now=None, fail_index=0)

    bd = record(KIND_S, 1, sha256(g),
                step_payload("part-0001", 100, 100, TS1), domain=9)
    add("reject_bad_domain",
        "Step with domain_id = 9 -> REJECT_BAD_DOMAIN at index 1.",
        [g, bd], man, verdict="REJECT_BAD_DOMAIN", exit_code=1, fail_index=1)

    sm = chain_step(g, 5, "part-0001", 100, 100, TS1)
    add("reject_seq_mismatch",
        "Step at index 1 carries seq_no = 5 -> REJECT_SEQ_MISMATCH at index 1.",
        [g, sm], man, verdict="REJECT_SEQ_MISMATCH", exit_code=1, fail_index=1)

    ei = record(KIND_S, 1, sha256(g),
                step_payload(None, 100, 100, TS1, raw_step_id=b"\x00" * 16))
    add("reject_empty_id",
        "Step with an all-zero step_id -> REJECT_EMPTY_ID at index 1.",
        [g, ei], man, verdict="REJECT_EMPTY_ID", exit_code=1, fail_index=1)

    # Q2c: non-zero payload reserved + STALE seal -> MALFORMED (reserved checked
    # BEFORE the seal; distinguishes from BAD_SEAL).
    mf_ok = record(KIND_S, 1, sha256(g), step_payload("part-mal", 100, 100, TS1))
    mf = bytearray(mf_ok)
    mf[88] = 0x01    # payload reserved[40..48] -> record offset 88; seal now stale
    add("reject_malformed_payload_reserved",
        "Step payload reserved[40..48] has a non-zero byte and the record_seal is now "
        "STALE; reserved is checked BEFORE the seal -> REJECT_MALFORMED_RECORD at "
        "index 1 (Q2c; NOT BAD_SEAL).",
        [g, bytes(mf)], man, verdict="REJECT_MALFORMED_RECORD", exit_code=1,
        fail_index=1)

    add("reject_expect_tip_mismatch",
        "Two clean steps, fold succeeds, but --expect-tip is wrong -> "
        "REJECT_CHAIN_BREAK (Q10a; anchor folds under CHAIN_BREAK, no record index).",
        [g, s1, s2], man, verdict="REJECT_CHAIN_BREAK", exit_code=1,
        expect_tip="f" * 64, fail_index=None,
        note="Post-fold anchor mismatch; fail_index is null (not a per-record fold "
             "failure).")

    # Q10b: anchor compares against the last WHOLE record even with a torn tail.
    add("reject_expect_tip_torn_mismatch",
        "Genesis + one step + 64 torn bytes; would be ACCEPT_TORN_TAIL, but "
        "--expect-tip (wrong) is checked against the last WHOLE record -> "
        "REJECT_CHAIN_BREAK (Q10b).",
        [g, s1], man, verdict="REJECT_CHAIN_BREAK", exit_code=1,
        torn=bytes((0xAB,)) * 64, expect_tip="f" * 64, fail_index=None)

    # Q1: genesis prev_hash != 32 zeros -> BAD_GENESIS (not CHAIN_BREAK)
    gbadprev = record(KIND_G, 0, sha256(b"not-zero"),
                      genesis_payload(CAP, EXPIRES_AT, sha256(man)))
    add("reject_genesis_bad_prevhash",
        "Genesis prev_hash is non-zero -> REJECT_BAD_GENESIS at index 0 (Q1; overrides "
        "a provisional CHAIN_BREAK).",
        [gbadprev], man, verdict="REJECT_BAD_GENESIS", exit_code=1,
        observed_now=None, fail_index=0)

    # Q2a: index 0 with kind 'S' -> BAD_GENESIS
    gkinds = record(KIND_S, 0, ZERO32, genesis_payload(CAP, EXPIRES_AT, sha256(man)))
    add("reject_genesis_kind_s",
        "Index 0 carries kind 'S' -> REJECT_BAD_GENESIS at index 0 (Q2a).",
        [gkinds], man, verdict="REJECT_BAD_GENESIS", exit_code=1,
        observed_now=None, fail_index=0)

    # Q2b: index >= 1 with kind 'G' -> MALFORMED
    skindg = record(KIND_G, 1, sha256(g),
                    step_payload("part-0001", 100, 100, TS1))
    add("reject_step_kind_g",
        "Index 1 carries kind 'G' -> REJECT_MALFORMED_RECORD at index 1 (Q2b).",
        [g, skindg], man, verdict="REJECT_MALFORMED_RECORD", exit_code=1,
        fail_index=1)

    # Q4: manifest deal_id all-zero -> EMPTY_ID (after manifest-hash agreement)
    man_empty = manifest_bytes(deal_id=b"\x00" * 32)
    g_empty = record(KIND_G, 0, ZERO32,
                     genesis_payload(CAP, EXPIRES_AT, sha256(man_empty)))
    add("reject_manifest_empty_deal_id",
        "Manifest deal_id is all-zero -> REJECT_EMPTY_ID at index 0, checked AFTER "
        "manifest-hash agreement (Q4).",
        [g_empty], man_empty, verdict="REJECT_EMPTY_ID", exit_code=1,
        observed_now=None, fail_index=0)

    # Q13.2: manifest witness of the wrong length -> BAD_GENESIS
    add("reject_manifest_wrong_length",
        "Manifest witness is 170 bytes (not 176); cannot hash to manifest_sha256 "
        "-> REJECT_BAD_GENESIS at index 0 (Q13.2).",
        [g], man[:170], verdict="REJECT_BAD_GENESIS", exit_code=1,
        observed_now=None, fail_index=0)

    # Q5: pinned --pubkeys != manifest keys -> KEY_MISMATCH
    man_cd = manifest_bytes(key_a=KEY_C, key_b=KEY_D)
    g_cd = record(KIND_G, 0, ZERO32,
                  genesis_payload(CAP, EXPIRES_AT, sha256(man_cd)))
    add("reject_key_mismatch",
        "Pinned --pubkeys (a.pub,b.pub) != manifest key_A,key_B -> "
        "REJECT_KEY_MISMATCH at index 0 (Q5).",
        [g_cd], man_cd, verdict="REJECT_KEY_MISMATCH", exit_code=1,
        observed_now=None, fail_index=0)

    # Q14: small-order key_A -> BAD_KEY (pinned pubkeys match the bad manifest)
    man_bad = manifest_bytes(key_a=IDENTITY_KEY, key_b=KEY_B)
    g_bad = record(KIND_G, 0, ZERO32,
                   genesis_payload(CAP, EXPIRES_AT, sha256(man_bad)))
    add("reject_bad_key",
        "Manifest key_A is a small-order Ed25519 point -> REJECT_BAD_KEY at index 0 "
        "(Q14). Pinned --pubkeys = badA.pub,b.pub (match the manifest).",
        [g_bad], man_bad, verdict="REJECT_BAD_KEY", exit_code=1,
        observed_now=None, pubkeys_file="badA.pub,b.pub", fail_index=0)

    # reject_bad_signature WITH --tape (one sig corrupted) -- replaces HARNESS stub
    tape_bad = bytearray(tape_ok)
    tape_bad[3 * 64] ^= 0xFF       # corrupt sig_B(record 1)
    assert not ed_verify(KEY_B, s1[96:128], bytes(tape_bad[3 * 64:4 * 64]))
    add("reject_bad_signature_tape",
        "Genesis + two steps WITH --tape, but sig_B(record 1) is corrupted -> "
        "REJECT_BAD_SIGNATURE at index 1 (Q11).",
        [g, s1, s2], man, verdict="REJECT_BAD_SIGNATURE", exit_code=1,
        tape=bytes(tape_bad), fail_index=1)

    # small-order R in sig_A(record 1): strict cofactorless profile rejects it
    # (a cofactored library would accept a torsion-added R and diverge). Q11 FIX.
    tape_sor = bytearray(tape_ok)
    orig_sigA1 = bytes(tape_ok[2 * 64:3 * 64])
    sor_sig = SMALL_ORDER_R + orig_sigA1[32:]     # small-order R, keep original S
    tape_sor[2 * 64:3 * 64] = sor_sig
    assert ed_sig_small_order_R(sor_sig), "crafted R is not small-order"
    assert not ed_sig_small_order_R(orig_sigA1), "original sig R unexpectedly small-order"
    add("reject_bad_signature_small_order_R",
        "Genesis + two steps WITH --tape; sig_A(record 1) carries a small-order R "
        "(order-8 point) -> REJECT_BAD_SIGNATURE at index 1 (Q11 strict profile: "
        "reject small-order R; a cofactored Ed25519 library would ACCEPT and diverge).",
        [g, s1, s2], man, verdict="REJECT_BAD_SIGNATURE", exit_code=1,
        tape=bytes(tape_sor), fail_index=1)

    # ---------- UNVERIFIABLE ----------
    add_raw("unverifiable_empty_file",
            "Empty log file -> UNVERIFIABLE_EMPTY (exit 3).",
            b"", man, verdict="UNVERIFIABLE_EMPTY", exit_code=3, observed_now=None,
            fail_index=None)
    add_raw("unverifiable_no_record",
            "50 bytes, no whole 128-byte record -> UNVERIFIABLE_NO_RECORD (exit 3).",
            bytes((0xCD,)) * 50, man, verdict="UNVERIFIABLE_NO_RECORD", exit_code=3,
            observed_now=None, fail_index=None)
    add("unverifiable_usage_missing_observed_now",
        "Log has a step but observed_now is omitted -> UNVERIFIABLE_USAGE (exit 3, "
        "Q6: observed_now REQUIRED when >=1 step).",
        [g, s1], man, verdict="UNVERIFIABLE_USAGE", exit_code=3, observed_now=None,
        fail_index=None)
    add("unverifiable_too_large",
        "Two whole records but --max-records 1 -> UNVERIFIABLE_TOO_LARGE (exit 3, Q8; "
        "decided before any fold). Demonstrates the ceiling without a 128 MiB file.",
        [g, s1], man, verdict="UNVERIFIABLE_TOO_LARGE", exit_code=3, max_records=1,
        fail_index=None)
    # Q5/Q6 symmetry (FIX 2): --pubkeys omitted -> UNVERIFIABLE_USAGE before any
    # record is read. pubkeys_file=None marks the omitted flag.
    add("unverifiable_usage_missing_pubkeys",
        "Invoked with NO --pubkeys -> UNVERIFIABLE_USAGE (exit 3), decided before any "
        "record is read (SPEC 9.1). --manifest is still supplied.",
        [g], man, verdict="UNVERIFIABLE_USAGE", exit_code=3, observed_now=None,
        pubkeys_file=None, fail_index=None)

    # ---------- money word-boundary vectors (SPEC 1 / Q3) ----------
    boundaries = [0, 1, 2**15 - 1, 2**15, 2**16 - 1, 2**16, 2**31 - 1, 2**31,
                  2**32 - 1, 2**32, 2**53 - 1, 2**53, 2**63 - 1]
    gmb, manmb = build_genesis(cap=MAXMONEY)
    for v in boundaries:
        sb = chain_step(gmb, 1, "mb", v, v, TS1)
        add("money_bound_accept_%d" % v,
            "seller_amount = %d (<= 2^63-1) under cap 2^63-1 -> ACCEPT." % v,
            [gmb, sb], manmb, verdict="ACCEPT", exit_code=0,
            final=bal(v, cap=MAXMONEY))
    for v in (P63, 2**64 - 1):
        sb = chain_step(gmb, 1, "mb", v, v, TS1)
        add("money_bound_reject_%d" % v,
            "seller_amount = %d (>= 2^63) -> REJECT_AMOUNT_NOT_MONEY at index 1." % v,
            [gmb, sb], manmb, verdict="REJECT_AMOUNT_NOT_MONEY", exit_code=1,
            fail_index=1)

    # ---------- the three demo sabotage records (demo spec Step 4b) ----------
    add("demo_sabotage_replay",
        "Demo 4b replay: a second step_id 'part-0001' at seq 3 -> "
        "REJECT_DUPLICATE_ID at index 3.",
        [g, s1, s2, dup], man, verdict="REJECT_DUPLICATE_ID", exit_code=1,
        fail_index=3)
    alt1 = chain_step(g, 1, "part-0001", 10, 10, TS1)
    add("demo_sabotage_altered_amount",
        "Demo 4b alter #1: record 1 rewritten to seller_amount 10 (recomputed seal), "
        "but record 2 prev_hash points at the original record 1 -> REJECT_CHAIN_BREAK "
        "at index 2.",
        [g, alt1, s2], man, verdict="REJECT_CHAIN_BREAK", exit_code=1, fail_index=2)
    oc = chain_step(s2, 3, "part-0003", 600, 800, TS3)
    add("demo_sabotage_over_cap",
        "Demo 4b over-cap: step seller_amount 600, gross_spent 800 on top of gross "
        "200 -> REJECT_OVER_CAP at index 3 (800 > cap 500).",
        [g, s1, s2, oc], man, verdict="REJECT_OVER_CAP", exit_code=1, fail_index=3)

    # ---------- rr4: post-fuzz genesis-code clarity + coverage gaps ----------
    # Option B (owner, reversed): the SPEC 2 wire-envelope checks run FIRST on EVERY
    # record INCLUDING genesis, before the SPEC 3 genesis checks. So at index 0:
    # magic/version/header-reserved -> REJECT_MALFORMED_RECORD; seq_no != 0 ->
    # REJECT_SEQ_MISMATCH; kind != 'G' / non-zero prev_hash -> REJECT_BAD_GENESIS;
    # domain != 2 -> REJECT_BAD_DOMAIN. Each record is built from the
    # accept_genesis_only seed with exactly ONE field corrupted and the seal
    # RECOMPUTED (valid seal; the named field is the sole fault).
    gp = genesis_payload(CAP, EXPIRES_AT, sha256(man))   # same payload as `g`
    add("reject_genesis_bad_magic",
        "Genesis magic != 'FV2' (seal valid) -> REJECT_MALFORMED_RECORD at index 0 "
        "(rr4 Option B: wire-envelope check runs at genesis too).",
        [record(KIND_G, 0, ZERO32, gp, magic=b"FVX")], man,
        verdict="REJECT_MALFORMED_RECORD", exit_code=1, observed_now=None, fail_index=0)
    add("reject_genesis_bad_version",
        "Genesis version != 2 (seal valid) -> REJECT_MALFORMED_RECORD at index 0 "
        "(rr4 Option B).",
        [record(KIND_G, 0, ZERO32, gp, version=3)], man,
        verdict="REJECT_MALFORMED_RECORD", exit_code=1, observed_now=None, fail_index=0)
    add("reject_genesis_bad_reserved",
        "Genesis header reserved [6..8) != 0 (seal valid) -> REJECT_MALFORMED_RECORD "
        "at index 0 (rr4 Option B).",
        [record(KIND_G, 0, ZERO32, gp, reserved=b"\x01\x00")], man,
        verdict="REJECT_MALFORMED_RECORD", exit_code=1, observed_now=None, fail_index=0)
    add("reject_genesis_bad_seqno",
        "Genesis seq_no != 0 (seal valid) -> REJECT_SEQ_MISMATCH at index 0 "
        "(rr4 Option B: seq_no != index applies at genesis).",
        [record(KIND_G, 5, ZERO32, gp)], man,
        verdict="REJECT_SEQ_MISMATCH", exit_code=1, observed_now=None, fail_index=0)
    add("reject_genesis_bad_domain",
        "Genesis domain_id != 2 (seal valid) -> REJECT_BAD_DOMAIN at index 0 (rr4).",
        [record(KIND_G, 0, ZERO32, gp, domain=9)], man,
        verdict="REJECT_BAD_DOMAIN", exit_code=1, observed_now=None, fail_index=0)

    # --max-records EXACTLY equal to the whole-record count -> ACCEPT (ceiling is
    # inclusive; closes the Q8/9.4 off-by-one gap).
    add("accept_records_eq_max",
        "Two whole records with --max-records 2 (records == ceiling) -> ACCEPT (rr4; "
        "the ceiling is inclusive).",
        [g, s1], man, verdict="ACCEPT", exit_code=0, max_records=2, final=bal(100))

    # record_ts strictly decreasing at a later step -> REJECT_SEQ_MISMATCH (SPEC 5.2
    # step 8). Seal recomputed so the timestamp is the sole fault.
    rts1 = chain_step(g, 1, "part-0001", 100, 100, TS2)       # record_ts = TS2
    rts2 = chain_step(rts1, 2, "part-0002", 100, 200, TS1)    # record_ts = TS1 < TS2
    add("reject_record_ts_decreasing",
        "Step 2 record_ts (TS1) < step 1 record_ts (TS2) -> REJECT_SEQ_MISMATCH at "
        "index 2 (rr4; non-decreasing record_ts rule, SPEC 5.2 step 8).",
        [g, rts1, rts2], man, verdict="REJECT_SEQ_MISMATCH", exit_code=1, fail_index=2)

    # rr5: a VALID step record (kind='S', non-zero seq_no, valid seal) as the SOLE
    # record at index 0 -> REJECT_BAD_GENESIS. Pins the kind-gate-before-seq_no
    # precedence (SPEC 3.2 step 1): the kind-gate fires, NOT SEQ_MISMATCH.
    add("reject_genesis_step_at_index0",
        "A well-formed step record (kind='S', seq_no=1, valid seal) placed as the sole "
        "record at index 0 -> REJECT_BAD_GENESIS at index 0 (rr5: the genesis "
        "kind-gate precedes the seq_no check).",
        [s1], man, verdict="REJECT_BAD_GENESIS", exit_code=1, fail_index=0)

    # ---------- re-release 3 confirmations (both new paths fire) ----------
    _sor = [c for c in CASES if c["name"] == "reject_bad_signature_small_order_R"][0]
    _sor_tape = open(os.path.join(OUT, _sor["tape_file"]), "rb").read()
    assert ed_sig_small_order_R(_sor_tape[2 * 64:3 * 64]), "small-order-R not embedded"
    assert _sor["expected_json"]["verdict"] == "REJECT_BAD_SIGNATURE"
    _mp = [c for c in CASES if c["name"] == "unverifiable_usage_missing_pubkeys"][0]
    assert _mp["pubkeys_file"] is None, "missing-pubkeys case still has --pubkeys"
    assert _mp["expected_json"]["verdict"] == "UNVERIFIABLE_USAGE"
    print("re-release 3: small-order-R vector fires (R is small-order, "
          "verdict REJECT_BAD_SIGNATURE); missing-pubkeys vector omits --pubkeys "
          "(verdict UNVERIFIABLE_USAGE)")

    # ---------- write the manifest ----------
    doc = {
        "schema": "forge-v2-leg2-golden-vectors",
        "ratification": "RATIFICATION_2026-11-21.md (Q1-Q14)",
        "status": "FROZEN",
        "end_to_end": False,
        "magic_hex": MAGIC.hex(),
        "money_max": MAXMONEY,
        "cap_default": CAP,
        "manifest_layout_bytes": 176,
        "default_max_records": DEFAULT_MAX_RECORDS,
        "tape_signed_message": "record_seal bytes [96..128]",
        "ed25519_profile": "strict (cofactorless, reject non-canonical A/R, S>=L, "
                           "small-order A)",
        "json_schema_keys": ["verdict", "exit_code", "records", "torn_bytes",
                             "fail_index", "final_balances", "tip", "epoch",
                             "expiry_gate_evaluated", "notes"],
        "note": "Black-box vectors: input bytes + witness + pubkeys (+ optional tape) "
                "-> expected --json. torn_bytes = len mod 128 ALWAYS (Q13.6). "
                "observed_now null means the flag is omitted. Zero Leg-1 content.",
        "count": len(CASES),
        "cases": CASES,
    }
    with open(os.path.join(OUT, "vectors.json"), "w") as f:
        json.dump(doc, f, indent=2)
    print("wrote %d cases to %s" % (len(CASES), OUT))


if __name__ == "__main__":
    main()
