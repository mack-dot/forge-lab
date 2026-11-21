//! Byte-exact accessors for the 128-byte envelope (SPEC.md §2) and the 176-byte
//! GenesisManifest (SPEC.md §3.1).
//!
//! Every accessor indexes a fixed-size array with compile-time-constant ranges
//! that are all within bounds, so no accessor can panic or read out of range on
//! any input. Nothing here validates; validation order lives in verify.rs so the
//! numbered order of SPEC.md §3.2 / §5.2 is visible in one place.

use crate::spec::*;

/// A whole 128-byte record, already read from the log.
#[derive(Clone, Copy)]
pub struct Record {
    pub bytes: [u8; RECORD_LEN],
}

#[inline]
fn u64_le(src: &[u8; RECORD_LEN], off: usize) -> u64 {
    // off is one of the frozen constants in spec.rs; off+8 <= 96 always
    let mut t = [0u8; 8];
    t.copy_from_slice(&src[off..off + 8]);
    u64::from_le_bytes(t)
}

impl Record {
    pub fn new(bytes: [u8; RECORD_LEN]) -> Record {
        Record { bytes }
    }

    // --- header (§2) -------------------------------------------------------

    pub fn magic(&self) -> [u8; 3] {
        [
            self.bytes[OFF_MAGIC],
            self.bytes[OFF_MAGIC + 1],
            self.bytes[OFF_MAGIC + 2],
        ]
    }
    pub fn version(&self) -> u8 {
        self.bytes[OFF_VERSION]
    }
    pub fn domain_id(&self) -> u8 {
        self.bytes[OFF_DOMAIN]
    }
    pub fn kind(&self) -> u8 {
        self.bytes[OFF_KIND]
    }
    /// header reserved [6..8) -- MUST be zero (§2, §8)
    pub fn hdr_reserved_is_zero(&self) -> bool {
        self.bytes[OFF_HDR_RESERVED] == 0 && self.bytes[OFF_HDR_RESERVED + 1] == 0
    }
    pub fn seq_no(&self) -> u64 {
        u64_le(&self.bytes, OFF_SEQ_NO)
    }
    pub fn prev_hash(&self) -> [u8; 32] {
        let mut h = [0u8; 32];
        h.copy_from_slice(&self.bytes[OFF_PREV_HASH..OFF_PREV_HASH + 32]);
        h
    }
    pub fn record_seal(&self) -> [u8; 32] {
        let mut h = [0u8; 32];
        h.copy_from_slice(&self.bytes[OFF_SEAL..OFF_SEAL + 32]);
        h
    }

    /// §2: record_seal must equal SHA-256(record[0..96)).
    pub fn seal_is_valid(&self) -> bool {
        crate::sha2::sha256(&self.bytes[0..SEALED_LEN]) == self.record_seal()
    }

    /// §2: prev_hash of record i must equal SHA-256 of the WHOLE previous record.
    pub fn whole_hash(&self) -> [u8; 32] {
        crate::sha2::sha256(&self.bytes)
    }

    // --- genesis payload (§3) ---------------------------------------------

    pub fn g_cap(&self) -> u64 {
        u64_le(&self.bytes, OFF_G_CAP)
    }
    pub fn g_expires_at(&self) -> u64 {
        u64_le(&self.bytes, OFF_G_EXPIRES_AT)
    }
    pub fn g_manifest_sha256(&self) -> [u8; 32] {
        let mut h = [0u8; 32];
        h.copy_from_slice(&self.bytes[OFF_G_MANIFEST_SHA..OFF_G_MANIFEST_SHA + 32]);
        h
    }

    // --- step payload (§4) -------------------------------------------------

    pub fn s_step_id(&self) -> [u8; STEP_ID_LEN] {
        let mut id = [0u8; STEP_ID_LEN];
        id.copy_from_slice(&self.bytes[OFF_S_STEP_ID..OFF_S_STEP_ID + STEP_ID_LEN]);
        id
    }
    pub fn s_seller_amount(&self) -> u64 {
        u64_le(&self.bytes, OFF_S_SELLER_AMOUNT)
    }
    pub fn s_gross_spent(&self) -> u64 {
        u64_le(&self.bytes, OFF_S_GROSS_SPENT)
    }
    pub fn s_record_ts(&self) -> u64 {
        u64_le(&self.bytes, OFF_S_RECORD_TS)
    }
    /// step payload reserved [88..96) -- MUST be zero (§4, §8)
    pub fn s_reserved_is_zero(&self) -> bool {
        self.bytes[OFF_S_RESERVED..OFF_S_RESERVED + 8].iter().all(|b| *b == 0)
    }
}

/// The 176-byte GenesisManifest witness (SPEC.md §3.1 / §8).
pub struct Manifest<'a> {
    bytes: &'a [u8],
}

impl<'a> Manifest<'a> {
    /// Only call after the length has been confirmed to be exactly 176.
    pub fn new(bytes: &'a [u8]) -> Option<Manifest<'a>> {
        if bytes.len() == MANIFEST_LEN {
            Some(Manifest { bytes })
        } else {
            None
        }
    }

    fn arr32(&self, off: usize) -> [u8; 32] {
        let mut a = [0u8; 32];
        a.copy_from_slice(&self.bytes[off..off + 32]);
        a
    }
    fn u64_at(&self, off: usize) -> u64 {
        let mut t = [0u8; 8];
        t.copy_from_slice(&self.bytes[off..off + 8]);
        u64::from_le_bytes(t)
    }

    pub fn deal_id(&self) -> [u8; 32] {
        self.arr32(OFF_M_DEAL_ID)
    }
    pub fn key_a(&self) -> [u8; 32] {
        self.arr32(OFF_M_KEY_A)
    }
    pub fn key_b(&self) -> [u8; 32] {
        self.arr32(OFF_M_KEY_B)
    }
    pub fn spec_hash(&self) -> [u8; 32] {
        self.arr32(OFF_M_SPEC_HASH)
    }
    pub fn escrow_id(&self) -> [u8; 32] {
        self.arr32(OFF_M_ESCROW_ID)
    }
    pub fn cap(&self) -> u64 {
        self.u64_at(OFF_M_CAP)
    }
    pub fn expires_at(&self) -> u64 {
        self.u64_at(OFF_M_EXPIRES_AT)
    }
}

/// SPEC.md §2 / §8: "An id whose field is all-zero bytes is the empty id".
/// Ids are RAW FIXED bytes compared bytewise: no charset rule, no case folding,
/// no whitespace trimming, no NUL-padding rule.
#[inline]
pub fn id_is_empty(id: &[u8]) -> bool {
    id.iter().all(|b| *b == 0)
}
