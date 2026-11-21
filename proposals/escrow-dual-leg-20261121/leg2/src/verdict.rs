//! Verdicts, their exact printed names, the exit-code scheme, and the canonical
//! report.
//!
//! README §1.2 / SPEC.md §5.3 (FROZEN, ratified Q1-Q14):
//!   exit 0  ACCEPT
//!   exit 4  ACCEPT_TORN_TAIL
//!   exit 1  every REJECT_*
//!   exit 3  every UNVERIFIABLE_*  (exactly six names, Q7)
//!
//! "The verdict name is NEVER shortened" (README §1.2) and "Leg 2 prints the full
//! name" (SPEC.md §5.3): the short demo aliases (DUPLICATE_ID, ...) are never
//! printed by this program.
//!
//! "No error path ever prints an ACCEPT verdict" (README §1.2): the only two
//! variants whose name starts with ACCEPT are produced in exactly one place, at
//! the end of a fully successful fold (see verify.rs).

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict {
    // exit 0 / 4
    Accept,
    AcceptTornTail,

    // Domain-2 refusals (SPEC.md §5.3), exit 1
    RejectDuplicateId,
    RejectChainBreak,
    RejectOverCap,
    RejectExpired,
    RejectBadSignature,
    RejectKeyMismatch,
    RejectBadKey,
    RejectSpecMismatch,

    // Envelope / structural refusals (SPEC.md §5.3), exit 1
    RejectAmountNotMoney,
    RejectMalformedRecord,
    RejectBadSeal,
    RejectSeqMismatch,
    RejectBadGenesis,
    RejectBadDomain,
    RejectEmptyId,

    // The six UNVERIFIABLE names (SPEC.md §5.3, Q7), exit 3
    UnverifiableEmpty,
    UnverifiableNoRecord,
    UnverifiableTooLarge,
    UnverifiableUnreadable,
    UnverifiableUsage,
    UnverifiableInternal,
}

impl Verdict {
    /// The exact string printed as the verdict line. Never abbreviated.
    pub const fn name(self) -> &'static str {
        use Verdict::*;
        match self {
            Accept => "ACCEPT",
            AcceptTornTail => "ACCEPT_TORN_TAIL",
            RejectDuplicateId => "REJECT_DUPLICATE_ID",
            RejectChainBreak => "REJECT_CHAIN_BREAK",
            RejectOverCap => "REJECT_OVER_CAP",
            RejectExpired => "REJECT_EXPIRED",
            RejectBadSignature => "REJECT_BAD_SIGNATURE",
            RejectKeyMismatch => "REJECT_KEY_MISMATCH",
            RejectBadKey => "REJECT_BAD_KEY",
            RejectSpecMismatch => "REJECT_SPEC_MISMATCH",
            RejectAmountNotMoney => "REJECT_AMOUNT_NOT_MONEY",
            RejectMalformedRecord => "REJECT_MALFORMED_RECORD",
            RejectBadSeal => "REJECT_BAD_SEAL",
            RejectSeqMismatch => "REJECT_SEQ_MISMATCH",
            RejectBadGenesis => "REJECT_BAD_GENESIS",
            RejectBadDomain => "REJECT_BAD_DOMAIN",
            RejectEmptyId => "REJECT_EMPTY_ID",
            UnverifiableEmpty => "UNVERIFIABLE_EMPTY",
            UnverifiableNoRecord => "UNVERIFIABLE_NO_RECORD",
            UnverifiableTooLarge => "UNVERIFIABLE_TOO_LARGE",
            UnverifiableUnreadable => "UNVERIFIABLE_UNREADABLE",
            UnverifiableUsage => "UNVERIFIABLE_USAGE",
            UnverifiableInternal => "UNVERIFIABLE_INTERNAL",
        }
    }

    /// README §1.2 exit-code scheme. Derived from the variant class, so a new
    /// refusal code cannot accidentally get the wrong exit code.
    pub const fn exit_code(self) -> i32 {
        use Verdict::*;
        match self {
            Accept => 0,
            AcceptTornTail => 4,
            RejectDuplicateId
            | RejectChainBreak
            | RejectOverCap
            | RejectExpired
            | RejectBadSignature
            | RejectKeyMismatch
            | RejectBadKey
            | RejectSpecMismatch
            | RejectAmountNotMoney
            | RejectMalformedRecord
            | RejectBadSeal
            | RejectSeqMismatch
            | RejectBadGenesis
            | RejectBadDomain
            | RejectEmptyId => 1,
            UnverifiableEmpty
            | UnverifiableNoRecord
            | UnverifiableTooLarge
            | UnverifiableUnreadable
            | UnverifiableUsage
            | UnverifiableInternal => 3,
        }
    }

    pub const fn is_accept(self) -> bool {
        matches!(self, Verdict::Accept | Verdict::AcceptTornTail)
    }
}

/// SPEC.md §6: settlement balances, deterministic from an ACCEPTED tape.
///   seller_payout = G
///   buyer_refund  = C - G     (C >= G guaranteed by the cap check)
/// SPEC.md §9.6: all three are 0 unless the verdict is ACCEPT / ACCEPT_TORN_TAIL.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Balances {
    pub gross_spent: u64,
    pub seller_payout: u64,
    pub buyer_refund: u64,
}

/// The canonical report. Field semantics are fixed by SPEC.md §9.6, which is the
/// differential substrate both legs must emit identically.
#[derive(Clone, Debug)]
pub struct Report {
    pub verdict: Verdict,
    /// whole 128-byte records in the FILE: `file_len / 128`, always.
    pub records: u64,
    /// `file_len % 128`, ALWAYS -- independent of the verdict and of where the
    /// fold stopped (SPEC.md §8, Q13.6).
    pub torn_bytes: u32,
    /// lowest-indexed failing record; None when nothing failed, and None for an
    /// anchor (`--expect-tip`) mismatch (SPEC.md §9.5, Q10a).
    pub fail_index: Option<u64>,
    /// zeros unless ACCEPT*
    pub balances: Balances,
    /// SHA-256 of the last whole record on ACCEPT*, else None (emitted as "").
    pub tip: Option<[u8; 32]>,
    /// records folded on ACCEPT*, else 0.
    pub epoch: u64,
    /// true iff the expiry gate actually decided: an ACCEPT* whose fold included
    /// at least one step, or REJECT_EXPIRED.
    pub expiry_gate_evaluated: bool,
    /// Human-facing only. The canonical `--json` object always emits "".
    pub notes: Vec<String>,
}

impl Report {
    /// A report that carries only a verdict plus the file-derived counts.
    pub fn simple(verdict: Verdict, records: u64, torn_bytes: u32) -> Report {
        Report {
            verdict,
            records,
            torn_bytes,
            fail_index: None,
            balances: Balances::default(),
            tip: None,
            epoch: 0,
            expiry_gate_evaluated: verdict == Verdict::RejectExpired,
            notes: Vec::new(),
        }
    }

    /// For paths that fail before the log length is even known (unreadable input,
    /// usage errors in argument parsing).
    pub fn bare(verdict: Verdict) -> Report {
        Report::simple(verdict, 0, 0)
    }
}
