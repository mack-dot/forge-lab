#!/usr/bin/env python3
# gen_corpus.py -- FUZZ corpus generator for the Forge V2 escrow cross-leg
# differential. Python stdlib only. Mutates INPUT BYTES and varies CLI args.
# It does NOT read either leg's logic; record layout comes from SPEC.md only,
# and the SHA-256 constructor was validated byte-for-byte against the golden
# vectors before use. Emits cases.jsonl + binary files under corpus/.
import os, sys, json, hashlib, struct, random

HERE = os.path.dirname(os.path.abspath(__file__))
GOLD = "/Users/mackianni/forge/.directives/leg2-implementer-packet/golden_vectors"
FILES = os.path.join(HERE, "corpus")
os.makedirs(FILES, exist_ok=True)

A_PUB = os.path.join(GOLD, "a.pub")
B_PUB = os.path.join(GOLD, "b.pub")
BADA_PUB = os.path.join(GOLD, "badA.pub")

random.seed(20261121)  # deterministic corpus

def rd(p):
    with open(p, "rb") as f:
        return f.read()

KEY_A = rd(A_PUB)
KEY_B = rd(B_PUB)
# borrow deal_id / escrow_id / spec_hash from a real golden manifest so the
# pinned a.pub/b.pub keys stay consistent with the manifest witness.
_gm = rd(os.path.join(GOLD, "accept_genesis_only.manifest.bin"))
DEAL_ID = _gm[0:32]
SPEC_HASH = _gm[96:128]
ESCROW_ID = _gm[128:160]
MONEY_MAX = 2**63 - 1

def u64(v):
    return int(v & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")

def sha(b):
    return hashlib.sha256(b).digest()

def build_manifest(cap, expires, keyA=KEY_A, keyB=KEY_B,
                   deal_id=DEAL_ID, spec=SPEC_HASH, esc=ESCROW_ID):
    return deal_id + keyA + keyB + spec + esc + u64(cap) + u64(expires)

def genesis_record(cap, expires, manifest, seq_no=0, prev_hash=b"\x00"*32,
                   kind=0x47, magic=b"FV2", version=2, domain=2,
                   hdr_reserved=b"\x00\x00"):
    mhash = sha(manifest)
    hdr = magic + bytes([version, domain, kind]) + hdr_reserved + \
        u64(seq_no) + prev_hash
    payload = u64(cap) + u64(expires) + mhash
    body = hdr + payload
    return body + sha(body)

def step_record(step_id, seller_amount, gross_spent, record_ts, prev_record,
                seq_no, kind=0x53, magic=b"FV2", version=2, domain=2,
                hdr_reserved=b"\x00\x00", pay_reserved=b"\x00"*8):
    prev_hash = sha(prev_record)
    hdr = magic + bytes([version, domain, kind]) + hdr_reserved + \
        u64(seq_no) + prev_hash
    payload = step_id + u64(seller_amount) + u64(gross_spent) + \
        u64(record_ts) + pay_reserved
    body = hdr + payload
    return body + sha(body)

STEP_ID1 = bytes(range(1, 17))      # 16 nonzero bytes
STEP_ID2 = bytes(range(17, 33))

CASES = []
_seen = set()

def add(case_id, category, log_bytes, *, manifest_bytes=None,
        manifest_path=None, pubkeys="a.pub,b.pub", tape_bytes=None,
        observed_now=None, expect_tip=None, max_records=None,
        omit_manifest=False, omit_pubkeys=False, inputs_note=""):
    """Register one corpus case. Writes needed binary files and records argv
    (with ABSOLUTE paths). pubkeys 'a.pub,b.pub' etc map to golden files; a
    custom pubkeys value may contain absolute paths already."""
    assert case_id not in _seen, "dup case id " + case_id
    _seen.add(case_id)
    log_path = os.path.join(FILES, case_id + ".log.bin")
    with open(log_path, "wb") as f:
        f.write(log_bytes if log_bytes is not None else b"")
    argv = [log_path]
    inputs = {"log": os.path.basename(log_path), "log_len": len(log_bytes or b""),
              "note": inputs_note}
    # manifest
    if not omit_manifest:
        if manifest_path is not None:
            mp = manifest_path
        elif manifest_bytes is not None:
            mp = os.path.join(FILES, case_id + ".manifest.bin")
            with open(mp, "wb") as f:
                f.write(manifest_bytes)
        else:
            mp = os.path.join(GOLD, "accept_genesis_only.manifest.bin")
        argv += ["--manifest", mp]
        inputs["manifest"] = os.path.basename(mp)
        inputs["manifest_len"] = os.path.getsize(mp)
    else:
        inputs["manifest"] = None
    # pubkeys
    if not omit_pubkeys and pubkeys is not None:
        pkmap = {"a.pub": A_PUB, "b.pub": B_PUB, "badA.pub": BADA_PUB}
        parts = pubkeys.split(",")
        resolved = ",".join(pkmap.get(p, p) for p in parts)
        argv += ["--pubkeys", resolved]
        inputs["pubkeys"] = pubkeys
    else:
        inputs["pubkeys"] = None
    # tape
    if tape_bytes is not None:
        tp = os.path.join(FILES, case_id + ".tape.bin")
        with open(tp, "wb") as f:
            f.write(tape_bytes)
        argv += ["--tape", tp]
        inputs["tape"] = os.path.basename(tp)
        inputs["tape_len"] = len(tape_bytes)
    if observed_now is not None:
        argv += ["--observed-now", str(observed_now)]
        inputs["observed_now"] = observed_now
    if expect_tip is not None:
        argv += ["--expect-tip", expect_tip]
        inputs["expect_tip"] = expect_tip
    if max_records is not None:
        argv += ["--max-records", str(max_records)]
        inputs["max_records"] = max_records
    argv += ["--json"]
    CASES.append({"case_id": case_id, "category": category,
                  "argv": argv, "inputs": inputs})

# ---------- reference valid logs ----------------------------------------
# For the mutation seeds (bit-flips, truncation, reorder, struct-byte) use the
# REAL golden bytes so the baseline is a genuine ACCEPT. The SHA-256 record
# constructor above (validated byte-exact vs these golden files) is used only
# for the BUILT boundary/manifest cases that need novel field values.
GEN = rd(os.path.join(GOLD, "accept_genesis_only.log.bin"))
MANG_PATH = os.path.join(GOLD, "accept_genesis_only.manifest.bin")
TWO = rd(os.path.join(GOLD, "accept_two_step.log.bin"))
MAN2_PATH = os.path.join(GOLD, "accept_two_step.manifest.bin")
# genesis expires_at carried in the two-step log (for expiry-boundary CLI cases)
EXP = int.from_bytes(TWO[56:64], "little")
# cross-check our constructor reproduces the golden genesis-only record exactly
assert genesis_record(int.from_bytes(GEN[48:56], "little"),
                      int.from_bytes(GEN[56:64], "little"),
                      rd(MANG_PATH)) == GEN, "constructor drift"

# =====================================================================
# CLASS A: structural byte mutations at named offsets
# =====================================================================
# offsets within a 128-byte record and their field name
REC_OFFS = {0:"magic0",1:"magic1",2:"magic2",3:"version",4:"domain",5:"kind",
            6:"hdr_res0",7:"hdr_res1",8:"seq0",15:"seq7",16:"prev0",47:"prev31",
            48:"pay0",55:"pay7",56:"pay8",63:"pay15",88:"stepres0",95:"stepres7",
            96:"seal0",127:"seal31"}
MUT_VALS = [0x00, 0xFF, 0xAA]

def mutate_byte(buf, off, val):
    b = bytearray(buf)
    b[off] = val
    return bytes(b)

# genesis-only seed (1 record), two-step seed (3 records)
for seedname, seed, mp, obs in [("genA", GEN, MANG_PATH, 1700000500),
                                ("two", TWO, MAN2_PATH, 1700000500)]:
    nrec = len(seed) // 128
    for ri in range(nrec):
        for roff, fname in REC_OFFS.items():
            off = ri*128 + roff
            for val in MUT_VALS:
                if seed[off] == val:
                    continue
                cid = f"structmut_{seedname}_r{ri}_{fname}_{val:02x}"
                add(cid, "struct_byte_mut", mutate_byte(seed, off, val),
                    manifest_path=mp, observed_now=obs,
                    inputs_note=f"rec{ri} offset {off} ({fname}) -> {val:#04x}")

# =====================================================================
# CLASS B: single bit-flips across every byte (bit 0)
# =====================================================================
for seedname, seed, mp, obs in [("genA", GEN, MANG_PATH, 1700000500),
                                ("two", TWO, MAN2_PATH, 1700000500)]:
    for off in range(len(seed)):
        cid = f"bitflip1_{seedname}_{off}"
        add(cid, "single_bit_flip", mutate_byte(seed, off, seed[off] ^ 0x01),
            manifest_path=mp, observed_now=obs,
            inputs_note=f"flip bit0 of byte {off}")

# =====================================================================
# CLASS C: double bit-flips (random pairs) on two-step seed
# =====================================================================
for n in range(180):
    o1 = random.randrange(len(TWO))
    o2 = random.randrange(len(TWO))
    b1 = 1 << random.randrange(8)
    b2 = 1 << random.randrange(8)
    buf = bytearray(TWO)
    buf[o1] ^= b1
    buf[o2] ^= b2
    cid = f"bitflip2_two_{n}"
    add(cid, "double_bit_flip", bytes(buf), manifest_path=MAN2_PATH,
        observed_now=1700000500,
        inputs_note=f"flip byte{o1} bit{b1.bit_length()-1} + byte{o2} bit{b2.bit_length()-1}")

# =====================================================================
# CLASS D: truncations (torn-tail class) -- every length
# =====================================================================
# two-step (384 bytes): every length 0..384
for L in range(0, len(TWO) + 1):
    cid = f"trunc_two_{L:03d}"
    add(cid, "truncation", TWO[:L], manifest_path=MAN2_PATH,
        observed_now=1700000500, inputs_note=f"truncate to {L} bytes")
# genesis-only (128 bytes): every length 0..128
for L in range(0, len(GEN) + 1):
    cid = f"trunc_genA_{L:03d}"
    add(cid, "truncation", GEN[:L], manifest_path=MANG_PATH,
        observed_now=1700000500, inputs_note=f"truncate to {L} bytes")

# =====================================================================
# CLASS E: duplicated / swapped / reordered / dropped records
# =====================================================================
recs = [TWO[i*128:(i+1)*128] for i in range(3)]
reorders = {
    "dup_genesis":   recs[0] + recs[0] + recs[1] + recs[2],
    "dup_step1":     recs[0] + recs[1] + recs[1] + recs[2],
    "dup_last":      recs[0] + recs[1] + recs[2] + recs[2],
    "swap_steps":    recs[0] + recs[2] + recs[1],
    "reverse_all":   recs[2] + recs[1] + recs[0],
    "drop_middle":   recs[0] + recs[2],
    "drop_genesis":  recs[1] + recs[2],
    "genesis_twice": recs[0] + recs[0],
    "step1_only":    recs[1],
    "append_copy":   TWO + recs[2],
}
for name, blob in reorders.items():
    add(f"reorder_{name}", "record_reorder", blob, manifest_path=MAN2_PATH,
        observed_now=1700000500, inputs_note=name)

# =====================================================================
# CLASS F: boundary money / time / seq values (built with valid seals)
# =====================================================================
BOUND = [0, 1, 2**15-1, 2**15, 2**15+1, 2**16-1, 2**16, 2**16+1,
         2**31-1, 2**31, 2**31+1, 2**32-1, 2**32, 2**32+1,
         2**53-1, 2**53, 2**53+1, 2**63-1, 2**63, 2**63+1, 2**64-1]

# F1: cap boundary, genesis-only (obs omitted)
for v in BOUND:
    man = build_manifest(v, EXP)
    g = genesis_record(v, EXP, man)
    add(f"cap_bound_{v}", "boundary_cap", g, manifest_bytes=man,
        inputs_note=f"genesis cap={v}")

# F2: seller_amount & gross_spent boundary (single step, cap=MONEY_MAX)
for v in BOUND:
    man = build_manifest(MONEY_MAX, EXP)
    g = genesis_record(MONEY_MAX, EXP, man)
    s = step_record(STEP_ID1, v, v, 1700000000, g, 1)
    add(f"seller_bound_{v}", "boundary_seller_gross", g + s, manifest_bytes=man,
        observed_now=1700000500, inputs_note=f"step seller_amount=gross_spent={v}, cap=2^63-1")

# F3: gross_spent inconsistent with seller (conservation) at boundary
for v in [2**31, 2**32, 2**53, 2**63-1]:
    man = build_manifest(MONEY_MAX, EXP)
    g = genesis_record(MONEY_MAX, EXP, man)
    s = step_record(STEP_ID1, 100, v, 1700000000, g, 1)  # gross != 0+seller
    add(f"gross_mismatch_{v}", "boundary_gross_mismatch", g + s,
        manifest_bytes=man, observed_now=1700000500,
        inputs_note=f"seller=100 but gross={v}")

# F4: expires_at boundary with observed_now around it
for E in [0, 1, 2**31, 2**32, 2**63-1, 2**63, 2**64-1, 1700001000]:
    man = build_manifest(500, E)
    g = genesis_record(500, E, man)
    s = step_record(STEP_ID1, 100, 100, 1700000000, g, 1)
    for obs in sorted(set([0 if E == 0 else E-1, E, (E+1) & 0xFFFFFFFFFFFFFFFF])):
        add(f"expiry_E{E}_obs{obs}", "boundary_expiry", g + s,
            manifest_bytes=man, observed_now=obs,
            inputs_note=f"expires_at={E}, observed_now={obs}")

# F5: seq_no boundary on the step record (valid seal over the wrong seq)
for v in [0, 2, 2**15, 2**31, 2**32, 2**63, 2**64-1]:
    man = build_manifest(500, EXP)
    g = genesis_record(500, EXP, man)
    s = step_record(STEP_ID1, 100, 100, 1700000000, g, v)  # should be 1
    add(f"seq_bound_{v}", "boundary_seq", g + s, manifest_bytes=man,
        observed_now=1700000500, inputs_note=f"step seq_no={v} (expected 1)")

# F6: record_ts boundary (plain u64, non-decreasing from 0)
for v in [0, 2**31, 2**32, 2**53, 2**63-1, 2**63, 2**64-1]:
    man = build_manifest(500, EXP)
    g = genesis_record(500, EXP, man)
    s = step_record(STEP_ID1, 100, 100, v, g, 1)
    add(f"ts_bound_{v}", "boundary_record_ts", g + s, manifest_bytes=man,
        observed_now=1700000500, inputs_note=f"step record_ts={v}")

# =====================================================================
# CLASS G: malformed manifests
# =====================================================================
MAN_G = rd(MANG_PATH)
# wrong lengths against a valid genesis-only log
for L in [0, 175, 177, 100, 352]:
    man = (MAN_G + b"\x00"*64)[:L] if L > len(MAN_G) else MAN_G[:L]
    if L > len(MAN_G):
        man = MAN_G + b"\x00"*(L-len(MAN_G))
    add(f"manifest_len_{L}", "manifest_wrong_length", GEN,
        manifest_bytes=man, manifest_path=None,
        inputs_note=f"manifest length {L}")
# 176 length but one byte flipped (sha mismatch)
for off in [0, 32, 96, 160, 168, 175]:
    b = bytearray(MAN_G); b[off] ^= 0xFF
    add(f"manifest_flip_{off}", "manifest_bad_field", GEN,
        manifest_bytes=bytes(b), inputs_note=f"manifest byte {off} flipped (sha mismatch)")
# empty deal_id manifest (rebuilt so sha still matches -> EMPTY_ID path)
man_empty = build_manifest(500, EXP, deal_id=b"\x00"*32)
gen_empty = genesis_record(500, EXP, man_empty)
add("manifest_empty_deal_id", "manifest_empty_id", gen_empty,
    manifest_bytes=man_empty, inputs_note="deal_id all-zero, sha rebuilt")
# key-mismatch: manifest keys swapped vs pinned a.pub,b.pub
man_swap = build_manifest(500, EXP, keyA=KEY_B, keyB=KEY_A)
gen_swap = genesis_record(500, EXP, man_swap)
add("manifest_key_swap", "manifest_key_mismatch", gen_swap,
    manifest_bytes=man_swap, pubkeys="a.pub,b.pub",
    inputs_note="manifest keyA/keyB swapped vs pinned a.pub,b.pub")

# =====================================================================
# CLASS H: pubkey / key variations
# =====================================================================
# pinned keys swapped (b.pub,a.pub) against normal manifest
add("pk_swapped", "key_mismatch", GEN, manifest_path=MANG_PATH,
    pubkeys="b.pub,a.pub", inputs_note="pinned b.pub,a.pub vs manifest a,b")
# pinned a.pub,a.pub
add("pk_aa", "key_mismatch", GEN, manifest_path=MANG_PATH,
    pubkeys="a.pub,a.pub", inputs_note="pinned a.pub,a.pub")
# small-order pinned key A (badA) with matching manifest keyA=badA
BADA = rd(BADA_PUB)
man_bada = build_manifest(500, EXP, keyA=BADA)
gen_bada = genesis_record(500, EXP, man_bada)
add("pk_small_order_A", "bad_key", gen_bada, manifest_bytes=man_bada,
    pubkeys="badA.pub,b.pub", inputs_note="small-order key A (badA) pinned+manifest")
# non-32-byte pubkey file (truncated a.pub) -> USAGE
trunc_pub = os.path.join(FILES, "a_trunc.pub")
with open(trunc_pub, "wb") as f:
    f.write(KEY_A[:31])
add("pk_wrong_length", "usage_pubkey_length", GEN, manifest_path=MANG_PATH,
    pubkeys=trunc_pub + "," + B_PUB, inputs_note="pubkey A is 31 bytes")
# malformed --pubkeys arg (one path, no comma)
add("pk_no_comma", "usage_pubkey_arg", GEN, manifest_path=MANG_PATH,
    pubkeys=A_PUB, inputs_note="--pubkeys single path, no comma")

# =====================================================================
# CLASS I: tape / signature corruption (mutate existing valid tape)
# =====================================================================
COSIGN_LOG = os.path.join(GOLD, "accept_cosigned_tape.log.bin")
COSIGN_MAN = os.path.join(GOLD, "accept_cosigned_tape.manifest.bin")
COSIGN_TAPE = rd(os.path.join(GOLD, "accept_cosigned_tape.tape.bin"))
cos_log = rd(COSIGN_LOG)
nsig = len(COSIGN_TAPE) // 64

def tape_case(cid, note, tape_bytes):
    add(cid, "tape_corruption", cos_log, manifest_path=COSIGN_MAN,
        tape_bytes=tape_bytes, observed_now=1700000500, inputs_note=note)

# flip one byte in each signature
for si in range(nsig):
    b = bytearray(COSIGN_TAPE); b[si*64] ^= 0x01
    tape_case(f"tape_flip_sig{si}_byte0", f"flip first byte of sig#{si}", bytes(b))
    b = bytearray(COSIGN_TAPE); b[si*64+63] ^= 0x80  # high bit of S region
    tape_case(f"tape_flip_sig{si}_S", f"flip high bit of S in sig#{si}", bytes(b))
# zero a whole signature
for si in range(nsig):
    b = bytearray(COSIGN_TAPE); b[si*64:(si+1)*64] = b"\x00"*64
    tape_case(f"tape_zero_sig{si}", f"zero sig#{si}", bytes(b))
# set S region (bytes [32..64) of a sig) all 0xFF -> S >= L
for si in range(min(nsig, 4)):
    b = bytearray(COSIGN_TAPE); b[si*64+32:si*64+64] = b"\xff"*32
    tape_case(f"tape_bigS_sig{si}", f"S=all-0xFF (>=L) in sig#{si}", bytes(b))
# R region (bytes [0..32)) all 0xFF -> non-canonical R
for si in range(min(nsig, 4)):
    b = bytearray(COSIGN_TAPE); b[si*64:si*64+32] = b"\xff"*32
    tape_case(f"tape_noncanon_R_sig{si}", f"R=all-0xFF (non-canonical) in sig#{si}", bytes(b))
# truncate tape (missing / short sigs)
for L in [0, 32, 64, len(COSIGN_TAPE)-1, len(COSIGN_TAPE)-64, len(COSIGN_TAPE)+64]:
    if L < 0:
        continue
    tb = COSIGN_TAPE[:L] if L <= len(COSIGN_TAPE) else COSIGN_TAPE + b"\x00"*(L-len(COSIGN_TAPE))
    tape_case(f"tape_len_{L}", f"tape length {L}", tb)
# swap two signatures
if nsig >= 2:
    b = bytearray(COSIGN_TAPE)
    b[0:64], b[64:128] = COSIGN_TAPE[64:128], COSIGN_TAPE[0:64]
    tape_case("tape_swap_sig01", "swap sig#0 and sig#1", bytes(b))
# mutate small-order-R golden tape too
SOR_LOG = rd(os.path.join(GOLD, "reject_bad_signature_small_order_R.log.bin"))
SOR_MAN = os.path.join(GOLD, "reject_bad_signature_small_order_R.manifest.bin")
SOR_TAPE = rd(os.path.join(GOLD, "reject_bad_signature_small_order_R.tape.bin"))
for si in range(len(SOR_TAPE)//64):
    b = bytearray(SOR_TAPE); b[si*64] ^= 0x01
    add(f"tape_sor_flip_sig{si}", "tape_corruption", SOR_LOG,
        manifest_path=SOR_MAN, tape_bytes=bytes(b), observed_now=1700000500,
        inputs_note=f"small-order-R seed, flip sig#{si} byte0")

# =====================================================================
# CLASS J: CLI variation
# =====================================================================
# observed_now around expiry on the valid two-step (expires_at=EXP)
for obs in [0, EXP-2, EXP-1, EXP, EXP+1, EXP+1000, 2**63-1, 2**63, 2**64-1]:
    add(f"cli_obs_{obs}", "cli_observed_now", TWO, manifest_path=MAN2_PATH,
        observed_now=obs, inputs_note=f"observed_now={obs} (expires_at={EXP})")
# --max-records ceilings on the 3-record log
for mr in [0, 1, 2, 3, 4, 1000000, 2**31, 2**63-1]:
    add(f"cli_maxr_{mr}", "cli_max_records", TWO, manifest_path=MAN2_PATH,
        observed_now=1700000500, max_records=mr,
        inputs_note=f"max_records={mr} (3 whole records)")
# --expect-tip correct / incorrect / wrong-case / bad length / non-hex
tip_last = sha(recs[2]).hex()
add("cli_tip_correct", "cli_expect_tip", TWO, manifest_path=MAN2_PATH,
    observed_now=1700000500, expect_tip=tip_last, inputs_note="expect-tip correct")
add("cli_tip_upper", "cli_expect_tip", TWO, manifest_path=MAN2_PATH,
    observed_now=1700000500, expect_tip=tip_last.upper(),
    inputs_note="expect-tip correct but UPPERCASE")
add("cli_tip_mixed", "cli_expect_tip", TWO, manifest_path=MAN2_PATH,
    observed_now=1700000500, expect_tip=(tip_last[:32].upper()+tip_last[32:]),
    inputs_note="expect-tip correct, mixed case")
add("cli_tip_wrong", "cli_expect_tip", TWO, manifest_path=MAN2_PATH,
    observed_now=1700000500, expect_tip="f"*64, inputs_note="expect-tip all-f (mismatch)")
add("cli_tip_short", "cli_expect_tip_usage", TWO, manifest_path=MAN2_PATH,
    observed_now=1700000500, expect_tip="ab"*31 + "a", inputs_note="expect-tip 63 hex chars")
add("cli_tip_long", "cli_expect_tip_usage", TWO, manifest_path=MAN2_PATH,
    observed_now=1700000500, expect_tip="ab"*32 + "cd", inputs_note="expect-tip 66 hex chars")
add("cli_tip_nonhex", "cli_expect_tip_usage", TWO, manifest_path=MAN2_PATH,
    observed_now=1700000500, expect_tip="z"*64, inputs_note="expect-tip non-hex chars")
# expect-tip on a torn-tail log (anchor vs last WHOLE record)
add("cli_tip_torn_correct", "cli_expect_tip", TWO + b"\x01"*40,
    manifest_path=MAN2_PATH, observed_now=1700000500, expect_tip=tip_last,
    inputs_note="torn tail +40 bytes, expect-tip = last whole record (should match)")
# missing required args
add("cli_missing_manifest", "usage_missing_manifest", TWO,
    omit_manifest=True, observed_now=1700000500, inputs_note="no --manifest")
add("cli_missing_pubkeys", "usage_missing_pubkeys", TWO,
    manifest_path=MAN2_PATH, omit_pubkeys=True, observed_now=1700000500,
    inputs_note="no --pubkeys")
add("cli_missing_obs_with_step", "usage_missing_obs", TWO,
    manifest_path=MAN2_PATH, inputs_note="steps present, no --observed-now")
add("cli_missing_obs_genesis_only", "genesis_no_obs", GEN,
    manifest_path=MANG_PATH, inputs_note="genesis only, no --observed-now (ok)")

# =====================================================================
# CLASS K: random corpus
# =====================================================================
# random free-length files
for n in range(200):
    L = random.randrange(0, 600)
    blob = bytes(random.randrange(256) for _ in range(L))
    add(f"rand_free_{n}", "random_free", blob, manifest_path=MAN2_PATH,
        observed_now=1700000500, inputs_note=f"random {L} bytes")
# random whole-record-count files (valid lengths, random content)
for n in range(80):
    k = random.randrange(0, 5)
    blob = bytes(random.randrange(256) for _ in range(128*k))
    add(f"rand_whole_{n}", "random_whole", blob, manifest_path=MAN2_PATH,
        observed_now=1700000500, inputs_note=f"random {k} whole records")
# random single-record with valid header but random rest (exercise seal/fold)
for n in range(60):
    hdr = b"FV2" + bytes([2,2,0x47,0,0]) + (0).to_bytes(8,"little") + b"\x00"*32
    rest = bytes(random.randrange(256) for _ in range(128-48))
    blob = hdr + rest
    add(f"rand_genhdr_{n}", "random_genesis_header", blob, manifest_path=MANG_PATH,
        observed_now=1700000500, inputs_note="valid genesis header, random payload+seal")

# ---------------------------------------------------------------------
with open(os.path.join(HERE, "cases.jsonl"), "w") as f:
    for c in CASES:
        f.write(json.dumps(c) + "\n")

from collections import Counter
cc = Counter(c["category"] for c in CASES)
print("TOTAL CASES:", len(CASES))
for k in sorted(cc):
    print(f"  {k}: {cc[k]}")
