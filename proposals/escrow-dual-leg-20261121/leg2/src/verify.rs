//! The decidable Step function and the fold (SPEC.md §5), genesis verification
//! (SPEC.md §3.2), and the co-signed tape check (SPEC.md §9.2).
//!
//! Built against the FROZEN, owner-ratified SPEC.md (RATIFICATION_2026-11-21,
//! Q1-Q14). The check ORDER below is the spec's numbered order, literally, and
//! each check carries the SPEC.md step number it implements, because the order is
//! what decides which refusal code a record with several faults gets.
//!
//! Determinism (SPEC.md §5, §7): time enters only through `observed_now` and each
//! record's `record_ts`. Nothing in this file reads a clock, a random source, or
//! the environment. `settled_steps` is a BTreeSet, so there is no hasher seed
//! anywhere in the program.

use std::collections::BTreeSet;
use std::io::Read;

use crate::ed25519;
use crate::record::{id_is_empty, Manifest, Record};
use crate::sha2::sha256;
use crate::spec::*;
use crate::verdict::{Balances, Report, Verdict};

#[derive(Clone, Debug)]
pub struct Config {
    /// SPEC.md §9.4: whole-record ceiling. Default `DEFAULT_MAX_RECORDS`.
    pub max_records: u64,
    /// SPEC.md §3.2: `SPEC_MISMATCH` stays deferred and unwired in this CLI.
    /// Supplying a ratified `spec_hash` activates `REJECT_SPEC_MISMATCH`; no
    /// golden vector drives it. (Extension flag `--expect-spec-hash`.)
    pub expect_spec_hash: Option<[u8; 32]>,
}

impl Default for Config {
    fn default() -> Self {
        Config { max_records: DEFAULT_MAX_RECORDS, expect_spec_hash: None }
    }
}

pub struct Inputs<'a> {
    /// raw bytes of the --manifest witness, whatever length was supplied
    pub manifest: &'a [u8],
    pub key_a: [u8; PUBKEY_LEN],
    pub key_b: [u8; PUBKEY_LEN],
    /// SPEC.md §9.2: the co-signed sidecar, 2 x 64-byte signatures per record in
    /// record order. None means signatures are skipped entirely.
    pub tape: Option<&'a [u8]>,
    pub observed_now: Option<u64>,
    pub expect_tip: Option<[u8; 32]>,
}

/// SPEC.md §5.1 EscrowState, folded from the genesis over the log.
#[derive(Clone)]
pub struct EscrowState {
    pub deal_id: [u8; 32],
    pub cap: u64,
    pub expires_at: u64,
    pub spec_hash: [u8; 32],
    pub key_a: [u8; 32],
    pub key_b: [u8; 32],
    pub escrow_id: [u8; 32],
    pub gross_spent: u64,
    pub gross_refunded: u64,
    pub settled_steps: BTreeSet<[u8; STEP_ID_LEN]>,
    pub epoch: u64,
    pub record_ts_prev: u64,
    pub tip_hash: [u8; 32],
    /// how many step records have been folded (drives `expiry_gate_evaluated`)
    pub steps_folded: u64,
}

// ---------------------------------------------------------------------------
// SPEC.md §9.2 -- the co-signed tape
// ---------------------------------------------------------------------------

/// SPEC.md §9.2: the tape holds `[sig_A(rec0), sig_B(rec0), sig_A(rec1), ...]`,
/// 64 bytes each, 128 bytes per record, in record order. The signed message is
/// the 32-byte `record_seal` of that record, with no domain separation (§8).
/// Genesis and every step require BOTH signatures valid. Missing or invalid ->
/// `REJECT_BAD_SIGNATURE`.
pub fn check_tape_signatures(
    tape: &[u8],
    index: u64,
    record_seal: &[u8; 32],
    key_a: &[u8; PUBKEY_LEN],
    key_b: &[u8; PUBKEY_LEN],
) -> Result<(), Verdict> {
    let off = match (index as usize).checked_mul(TAPE_BYTES_PER_RECORD) {
        Some(o) => o,
        None => return Err(Verdict::RejectBadSignature),
    };
    let end = match off.checked_add(TAPE_BYTES_PER_RECORD) {
        Some(e) => e,
        None => return Err(Verdict::RejectBadSignature),
    };
    if tape.len() < end {
        // a signature the tape does not carry is a MISSING signature
        return Err(Verdict::RejectBadSignature);
    }
    let sig_a = &tape[off..off + TAPE_SIG_LEN];
    let sig_b = &tape[off + TAPE_SIG_LEN..end];
    if !ed25519::verify(key_a, record_seal, sig_a) {
        return Err(Verdict::RejectBadSignature);
    }
    if !ed25519::verify(key_b, record_seal, sig_b) {
        return Err(Verdict::RejectBadSignature);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Genesis (SPEC.md §3.2, STRICT ORDER, first failure wins)
// ---------------------------------------------------------------------------

pub fn verify_genesis(rec: &Record, inp: &Inputs, cfg: &Config) -> Result<EscrowState, Verdict> {
    // --- step 1: genesis structure ---------------------------------------
    // §2: magic -- any other value -> REJECT_MALFORMED_RECORD
    if rec.magic() != MAGIC {
        return Err(Verdict::RejectMalformedRecord);
    }
    // §2: version u8 = 2
    if rec.version() != VERSION {
        return Err(Verdict::RejectMalformedRecord);
    }
    // §2: domain_id u8 = 2 -> REJECT_BAD_DOMAIN
    if rec.domain_id() != DOMAIN_ID {
        return Err(Verdict::RejectBadDomain);
    }
    // §3.2 step 1 (Q2a): kind != 'G' at index 0 -> REJECT_BAD_GENESIS
    if rec.kind() != KIND_GENESIS {
        return Err(Verdict::RejectBadGenesis);
    }
    // §2 / §8: header reserved [6..8) MUST be zero
    if !rec.hdr_reserved_is_zero() {
        return Err(Verdict::RejectMalformedRecord);
    }
    // §3.2 step 1: seq_no == 0
    if rec.seq_no() != 0 {
        return Err(Verdict::RejectSeqMismatch);
    }
    // §3.2 step 1 (Q1): a non-zero genesis prev_hash -> REJECT_BAD_GENESIS
    if rec.prev_hash() != [0u8; 32] {
        return Err(Verdict::RejectBadGenesis);
    }
    // §3.2 step 1: seal valid -> else REJECT_BAD_SEAL
    if !rec.seal_is_valid() {
        return Err(Verdict::RejectBadSeal);
    }

    // --- step 2: Money(cap) only. expires_at is NOT money-gated (Q3) ------
    let cap = rec.g_cap();
    let expires_at = rec.g_expires_at();
    if !is_money(cap) {
        return Err(Verdict::RejectAmountNotMoney);
    }

    // --- step 3: manifest length AND hash agreement (Q13.2) ---------------
    if inp.manifest.len() != MANIFEST_LEN || sha256(inp.manifest) != rec.g_manifest_sha256() {
        return Err(Verdict::RejectBadGenesis);
    }
    let man = match Manifest::new(inp.manifest) {
        Some(m) => m,
        None => return Err(Verdict::RejectBadGenesis), // unreachable after step 3
    };

    // --- step 4: manifest cap / expires_at equal the in-clear payload ------
    if man.cap() != cap || man.expires_at() != expires_at {
        return Err(Verdict::RejectBadGenesis);
    }

    // --- step 5: manifest id emptiness (Q4), AFTER step 3 ------------------
    if id_is_empty(&man.deal_id()) || id_is_empty(&man.escrow_id()) {
        return Err(Verdict::RejectEmptyId);
    }

    // --- step 6: key validity (Q14) ----------------------------------------
    // canonical (y < p, enforced by decompress) and NOT small order (8A != id)
    let m_key_a = man.key_a();
    let m_key_b = man.key_b();
    for k in [&m_key_a, &m_key_b] {
        if ed25519::decompress(k).is_none() || ed25519::is_small_order(k) {
            return Err(Verdict::RejectBadKey);
        }
    }

    // --- step 7: pinned-key cross-check (Q5), mandatory --------------------
    if m_key_a != inp.key_a || m_key_b != inp.key_b {
        return Err(Verdict::RejectKeyMismatch);
    }

    // --- SPEC_MISMATCH: deferred, active only when a spec_hash is supplied --
    if let Some(expected) = cfg.expect_spec_hash {
        if man.spec_hash() != expected {
            return Err(Verdict::RejectSpecMismatch);
        }
    }

    // --- §9.2: with a tape, the genesis needs BOTH signatures --------------
    if let Some(tape) = inp.tape {
        check_tape_signatures(tape, 0, &rec.record_seal(), &inp.key_a, &inp.key_b)?;
    }

    Ok(EscrowState {
        deal_id: man.deal_id(),
        cap,
        expires_at,
        spec_hash: man.spec_hash(),
        key_a: m_key_a,
        key_b: m_key_b,
        escrow_id: man.escrow_id(),
        gross_spent: 0,
        gross_refunded: 0,
        settled_steps: BTreeSet::new(),
        epoch: 1, // == count of records folded so far
        record_ts_prev: 0, // §5.2 step 8: genesis baseline 0
        tip_hash: rec.whole_hash(),
        steps_folded: 0,
    })
}

// ---------------------------------------------------------------------------
// Step (SPEC.md §5.2, 13 checks in this exact order)
// ---------------------------------------------------------------------------

/// `Step(state, record, observed_now) -> Some(state') | refuse(code)`.
/// Mutates `state` only on success.
pub fn step(
    state: &mut EscrowState,
    rec: &Record,
    index: u64,
    observed_now: Option<u64>,
    tape: Option<&[u8]>,
) -> Result<(), Verdict> {
    // 1. structural: magic / version / domain / kind=='S' / header reserved
    if rec.magic() != MAGIC {
        return Err(Verdict::RejectMalformedRecord);
    }
    if rec.version() != VERSION {
        return Err(Verdict::RejectMalformedRecord);
    }
    if rec.domain_id() != DOMAIN_ID {
        return Err(Verdict::RejectBadDomain);
    }
    // (Q2b) a kind == 'G' at index >= 1 -> REJECT_MALFORMED_RECORD
    if rec.kind() != KIND_STEP {
        return Err(Verdict::RejectMalformedRecord);
    }
    if !rec.hdr_reserved_is_zero() {
        return Err(Verdict::RejectMalformedRecord);
    }

    // 2. payload reserved [88..96), BEFORE seq_no/prev_hash/seal (Q2c): a
    //    non-zero-reserved record is MALFORMED, never BAD_SEAL, even when the
    //    seal was recomputed over the non-zero byte.
    if !rec.s_reserved_is_zero() {
        return Err(Verdict::RejectMalformedRecord);
    }

    // 3. seq_no == i
    if rec.seq_no() != index {
        return Err(Verdict::RejectSeqMismatch);
    }

    // 4. prev_hash == tip_hash
    if rec.prev_hash() != state.tip_hash {
        return Err(Verdict::RejectChainBreak);
    }

    // 5. seal == SHA-256(record[0..96))
    if !rec.seal_is_valid() {
        return Err(Verdict::RejectBadSeal);
    }

    // 6. id check: RAW 16-byte step_id, bytewise; non-all-zero
    let step_id = rec.s_step_id();
    if id_is_empty(&step_id) {
        return Err(Verdict::RejectEmptyId);
    }

    // 7. Money(seller_amount) and Money(gross_spent). record_ts is plain u64 (Q3).
    let seller_amount = rec.s_seller_amount();
    let gross_spent = rec.s_gross_spent();
    if !is_money(seller_amount) || !is_money(gross_spent) {
        return Err(Verdict::RejectAmountNotMoney);
    }

    // 8. record_ts non-decreasing (genesis baseline 0) -> REJECT_SEQ_MISMATCH
    let record_ts = rec.s_record_ts();
    if record_ts < state.record_ts_prev {
        return Err(Verdict::RejectSeqMismatch);
    }

    // 9. money chain / conservation:
    //    gross_spent == state.gross_spent + seller_amount -> else CHAIN_BREAK.
    //    Both addends are Money (<= 2^63-1) here, so the sum is at most 2^64-2
    //    and the u64 add cannot wrap; checked_add makes that explicit and fails
    //    closed rather than wrapping if the invariant were ever broken.
    let expected_gross = match state.gross_spent.checked_add(seller_amount) {
        Some(v) => v,
        None => return Err(Verdict::RejectChainBreak),
    };
    if gross_spent != expected_gross {
        return Err(Verdict::RejectChainBreak);
    }

    // 10. cap: gross_spent <= cap, and gross_refunded <= gross_spent (the second
    //     conjunct is structurally vacuous in this CLI, Q13.3)
    if gross_spent > state.cap || state.gross_refunded > gross_spent {
        return Err(Verdict::RejectOverCap);
    }

    // 11. at most once
    if state.settled_steps.contains(&step_id) {
        return Err(Verdict::RejectDuplicateId);
    }

    // 12. expiry: valid strictly while observed_now < expires_at;
    //     REJECT_EXPIRED iff observed_now >= expires_at (equality is EXPIRED).
    //     Keys on observed_now, never on record_ts, never on a wall clock.
    //     observed_now is REQUIRED when a step is present (Q6), enforced before
    //     the fold; None here would mean that gate was bypassed, so fail closed.
    match observed_now {
        Some(now) => {
            if now >= state.expires_at {
                return Err(Verdict::RejectExpired);
            }
        }
        None => return Err(Verdict::RejectExpired),
    }

    // 13. signature, only WITH --tape (§9.2): sig_A (proposer) AND sig_B
    //     (countersigner) over the 32-byte record_seal.
    if let Some(t) = tape {
        check_tape_signatures(t, index, &rec.record_seal(), &state.key_a, &state.key_b)?;
    }

    // effect of a Some step
    state.gross_spent = expected_gross;
    state.settled_steps.insert(step_id);
    state.epoch += 1;
    state.steps_folded += 1;
    state.record_ts_prev = record_ts;
    state.tip_hash = rec.whole_hash();
    Ok(())
}

// ---------------------------------------------------------------------------
// The fold over the log
// ---------------------------------------------------------------------------

/// Read up to `buf.len()` bytes, looping over short reads. Returns the number of
/// bytes actually filled; a result < buf.len() means end of input.
fn fill<R: Read>(r: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut got = 0usize;
    while got < buf.len() {
        match r.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(got)
}

/// Fold the whole log and produce the canonical report.
///
/// `log_len` is the file's byte length, which SPEC.md §8 makes authoritative for
/// both reported counts: `records = log_len / 128` and
/// `torn_bytes = log_len % 128`, ALWAYS, independent of the verdict and of where
/// the fold stopped (Q13.6).
///
/// Never panics on malformed input: all reads are length-checked and all field
/// access is over fixed-size arrays.
pub fn verify_log<R: Read>(mut r: R, log_len: u64, inp: &Inputs, cfg: &Config) -> Report {
    let records = log_len / (RECORD_LEN as u64);
    let torn_bytes = (log_len % (RECORD_LEN as u64)) as u32;

    // --- pre-fold gates, in order (all decided before any record is folded) --

    // §9.4 (Q8): over the ceiling -> UNVERIFIABLE_TOO_LARGE
    if records > cfg.max_records {
        return Report::simple(Verdict::UnverifiableTooLarge, records, torn_bytes);
    }
    // §5.3: no whole record at all
    if records == 0 {
        let v = if torn_bytes == 0 {
            Verdict::UnverifiableEmpty
        } else {
            Verdict::UnverifiableNoRecord
        };
        return Report::simple(v, records, torn_bytes);
    }
    // §5 (Q6): observed_now is REQUIRED when the log has >= 1 step record.
    // Records at index >= 1 are the step positions, so `records >= 2` is the
    // pre-fold test for "a step is present"; a genesis-only log may omit it.
    if records >= 2 && inp.observed_now.is_none() {
        return Report::simple(Verdict::UnverifiableUsage, records, torn_bytes);
    }

    // --- the fold; first refusal wins (Q13.7) and stops the scan -------------

    let mut buf = [0u8; RECORD_LEN];
    let mut index: u64 = 0;
    let mut state: Option<EscrowState> = None;

    while index < records {
        match fill(&mut r, &mut buf) {
            Ok(n) if n == RECORD_LEN => {}
            Ok(_) => {
                // Fewer bytes than the length said: the file changed under us.
                return Report::simple(Verdict::UnverifiableUnreadable, records, torn_bytes);
            }
            Err(_) => {
                return Report::simple(Verdict::UnverifiableUnreadable, records, torn_bytes)
            }
        }

        let rec = Record::new(buf);
        let outcome = if index == 0 {
            match verify_genesis(&rec, inp, cfg) {
                Ok(st) => {
                    state = Some(st);
                    Ok(())
                }
                Err(v) => Err(v),
            }
        } else {
            match state.as_mut() {
                Some(st) => step(st, &rec, index, inp.observed_now, inp.tape),
                // unreachable: index > 0 implies the genesis succeeded
                None => return Report::simple(Verdict::UnverifiableInternal, records, torn_bytes),
            }
        };

        if let Err(v) = outcome {
            let mut rep = Report::simple(v, records, torn_bytes);
            rep.fail_index = Some(index);
            return rep;
        }
        index += 1;
    }

    let st = match state {
        Some(st) => st,
        None => return Report::simple(Verdict::UnverifiableInternal, records, torn_bytes),
    };

    // --- §9.5: the anchor, only after a fully successful fold ----------------
    // Compared against the SHA-256 of the LAST WHOLE record even when the file
    // would otherwise be ACCEPT_TORN_TAIL (Q10b). A mismatch folds under
    // REJECT_CHAIN_BREAK with fail_index NULL (Q10a).
    if let Some(expected_tip) = inp.expect_tip {
        if expected_tip != st.tip_hash {
            return Report::simple(Verdict::RejectChainBreak, records, torn_bytes);
        }
    }

    // --- SPEC.md §6 settlement balances --------------------------------------
    // cap >= gross_spent is guaranteed by the step-10 cap check (and trivially
    // for a genesis-only log), so the subtraction cannot borrow; checked_sub
    // keeps that explicit instead of wrapping.
    let g = st.gross_spent;
    let refund = match st.cap.checked_sub(g) {
        Some(v) => v,
        None => return Report::simple(Verdict::UnverifiableInternal, records, torn_bytes),
    };

    let verdict = if torn_bytes > 0 {
        Verdict::AcceptTornTail
    } else {
        Verdict::Accept
    };

    Report {
        verdict,
        records,
        torn_bytes,
        fail_index: None,
        balances: Balances { gross_spent: g, seller_payout: g, buyer_refund: refund },
        tip: Some(st.tip_hash),
        epoch: st.epoch,
        // §9.6: true iff the gate decided -- an ACCEPT* whose fold included at
        // least one step. (REJECT_EXPIRED is handled in Report::simple.)
        expiry_gate_evaluated: st.steps_folded > 0,
        notes: Vec::new(),
    }
}
