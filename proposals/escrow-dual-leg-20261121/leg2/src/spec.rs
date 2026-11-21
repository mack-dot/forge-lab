//! Every frozen width, offset and bound from SPEC.md §8, in one place.
//!
//! Each constant cites the SPEC.md line that fixes it. If the owner's O-review
//! changes a line in §8, it changes here and nowhere else.

// --- §2 envelope -----------------------------------------------------------

/// SPEC.md §2: a record is exactly 128 bytes.
pub const RECORD_LEN: usize = 128;

/// SPEC.md §2 / §7 / §8: the 3 magic bytes. `FV2`, RATIFIED FINAL (Q12).
pub const MAGIC: [u8; 3] = [0x46, 0x56, 0x32]; // b"FV2"

/// SPEC.md §2: version byte must be 2.
pub const VERSION: u8 = 2;

/// SPEC.md §2: domain_id must be 2 (Escrow).
pub const DOMAIN_ID: u8 = 2;

/// SPEC.md §2: kind 'G' = genesis, 'S' = step.
pub const KIND_GENESIS: u8 = 0x47; // 'G'
pub const KIND_STEP: u8 = 0x53; // 'S'

// Field offsets inside the 128-byte record (SPEC.md §2 table).
pub const OFF_MAGIC: usize = 0;
pub const OFF_VERSION: usize = 3;
pub const OFF_DOMAIN: usize = 4;
pub const OFF_KIND: usize = 5;
pub const OFF_HDR_RESERVED: usize = 6; // [6..8), MUST be zero
pub const OFF_SEQ_NO: usize = 8; // [8..16)  u64 LE
pub const OFF_PREV_HASH: usize = 16; // [16..48) 32 B
pub const OFF_PAYLOAD: usize = 48; // [48..96) 48 B
pub const OFF_SEAL: usize = 96; // [96..128) SHA-256 of [0..96)

/// SPEC.md §2: the sealed region is bytes [0..96) of the record.
pub const SEALED_LEN: usize = 96;

// --- §3 genesis payload (offsets within the record) ------------------------

pub const OFF_G_CAP: usize = 48; // [48..56)  u64 LE cents
pub const OFF_G_EXPIRES_AT: usize = 56; // [56..64)  u64 LE unix seconds
pub const OFF_G_MANIFEST_SHA: usize = 64; // [64..96)  32 B

// --- §4 step payload (offsets within the record) ---------------------------

pub const OFF_S_STEP_ID: usize = 48; // [48..64)  16 raw bytes
pub const OFF_S_SELLER_AMOUNT: usize = 64; // [64..72)  u64 LE cents
pub const OFF_S_GROSS_SPENT: usize = 72; // [72..80)  u64 LE cents
pub const OFF_S_RECORD_TS: usize = 80; // [80..88)  u64 LE unix seconds
pub const OFF_S_RESERVED: usize = 88; // [88..96)  MUST be zero

pub const STEP_ID_LEN: usize = 16;

// --- §3.1 / §8 GenesisManifest (176 bytes) ---------------------------------

pub const MANIFEST_LEN: usize = 176;
pub const OFF_M_DEAL_ID: usize = 0; // [0..32)
pub const OFF_M_KEY_A: usize = 32; // [32..64)
pub const OFF_M_KEY_B: usize = 64; // [64..96)
pub const OFF_M_SPEC_HASH: usize = 96; // [96..128)
pub const OFF_M_ESCROW_ID: usize = 128; // [128..160)
pub const OFF_M_CAP: usize = 160; // [160..168) u64 LE
pub const OFF_M_EXPIRES_AT: usize = 168; // [168..176) u64 LE

pub const ID_LEN_32: usize = 32;

// --- §1 money law ----------------------------------------------------------

/// SPEC.md §1: `Money(v) <==> 0 <= v <= 2^63 - 1`.
pub const MONEY_MAX: u64 = 9_223_372_036_854_775_807; // 2^63 - 1

/// SPEC.md §1: the money predicate. The wire value is read as a full unsigned
/// 64-bit integer in 0..2^64-1 and compared against the bound BEFORE any
/// arithmetic. Never wrapped, never rounded, never clamped.
#[inline]
pub const fn is_money(v: u64) -> bool {
    v <= MONEY_MAX
}

/// Ed25519 public key width.
pub const PUBKEY_LEN: usize = 32;

// --- §9 interfaces (FINAL) -------------------------------------------------

/// SPEC.md §9.4 (Q8): default whole-record ceiling, 128 MiB of records.
/// Over it -> UNVERIFIABLE_TOO_LARGE, decided before any fold.
pub const DEFAULT_MAX_RECORDS: u64 = 1_048_576;

/// SPEC.md §9.2: one Ed25519 signature on the co-signed tape.
pub const TAPE_SIG_LEN: usize = 64;

/// SPEC.md §9.2: the tape carries 2 signatures per record (sig_A then sig_B).
pub const TAPE_BYTES_PER_RECORD: usize = 2 * TAPE_SIG_LEN;
