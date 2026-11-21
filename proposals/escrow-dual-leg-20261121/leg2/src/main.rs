//! leg2-verify CLI (SPEC.md §9.1 / README §1.1, FINAL).
//!
//!   leg2-verify <log.bin> --manifest <m.bin> --pubkeys <a.pub,b.pub> \
//!               [--tape <t.bin>] [--observed-now N] [--expect-tip HEX] \
//!               [--max-records N] [--json]
//!
//! Output: ONE verdict line on stdout (the full verdict name, never shortened),
//! then `key=value` detail lines for humans. `--json` emits the canonical
//! comparison object of SPEC.md §9.6 -- the differential substrate.
//!
//! Fail-closed: every error path, including an unexpected panic anywhere in the
//! program, prints an UNVERIFIABLE_* verdict and exits 3. No error path can
//! print a verdict whose name starts with ACCEPT.

use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use leg2_verify::spec::{MANIFEST_LEN, PUBKEY_LEN, RECORD_LEN};
use leg2_verify::verdict::{Report, Verdict};
use leg2_verify::verify::{self, Config, Inputs};
use leg2_verify::{crypto_self_check, parse_hex32, to_hex};

const USAGE: &str = "\
leg2-verify -- Leg 2 independent verifier, Forge V2 escrow (Domain 2)
Built to the FROZEN owner-ratified SPEC.md (RATIFICATION_2026-11-21, Q1-Q14).

USAGE:
  leg2-verify <log.bin> --manifest <m.bin> --pubkeys <a.pub,b.pub>
              [--tape <t.bin>] [--observed-now N] [--expect-tip HEX]
              [--max-records N] [--json]

REQUIRED:
  <log.bin>              zero or more whole 128-byte records, maybe a 1..127-byte
                         trailing partial
  --manifest <m.bin>     the 176-byte GenesisManifest witness (SPEC.md 3.1)
  --pubkeys <a,b>        two 32-byte Ed25519 public key files; they MUST equal the
                         manifest key_A,key_B (else REJECT_KEY_MISMATCH)

OPTIONAL:
  --tape <t.bin>         co-signed sidecar: 64-byte sigs, 2 per record in record
                         order, over the 32-byte record_seal (SPEC.md 9.2). WITH
                         it signatures are enforced; WITHOUT it they are skipped.
  --observed-now N       trusted u64 time input. REQUIRED when the log has >= 1
                         step; optional for a genesis-only log. No wall clock is
                         ever read.
  --expect-tip HEX       64 hex chars, case-insensitive: SHA-256 of the last
                         whole record. Checked only after a successful fold.
  --max-records N        whole-record ceiling (default 1048576)
  --json                 emit the canonical SPEC.md 9.6 comparison object

EXTENSIONS (not part of the frozen CLI contract):
  --expect-spec-hash HEX activates the deferred SPEC_MISMATCH check
  --selftest             run the built-in crypto self-checks and exit
  --help, --version

EXIT CODES: 0 ACCEPT | 4 ACCEPT_TORN_TAIL | 1 REJECT_* | 3 UNVERIFIABLE_*
";

struct Args {
    log: PathBuf,
    manifest: PathBuf,
    pubkey_a: PathBuf,
    pubkey_b: PathBuf,
    tape: Option<PathBuf>,
    observed_now: Option<u64>,
    expect_tip: Option<[u8; 32]>,
    json: bool,
    cfg: Config,
}

enum Parsed {
    Ok(Box<Args>),
    Info(String),
    SelfTest,
    Usage(String),
}

/// Flags that consume the following argv element. Shared by the real parser and
/// by `positional_log` so the two can never disagree about what is positional.
fn flag_takes_value(a: &str) -> bool {
    matches!(
        a,
        "--manifest"
            | "--pubkeys"
            | "--tape"
            | "--observed-now"
            | "--expect-tip"
            | "--expect-spec-hash"
            | "--max-records"
    )
}

/// Best-effort extraction of the positional `<log.bin>` from argv, independent of
/// flag order and of whether parsing later fails.
///
/// SPEC.md §9.6 defines `records` as "whole 128-byte records in the file" and §8
/// defines `torn_bytes` as `file length mod 128` ALWAYS, "computed independently
/// of the verdict and of where the fold stopped". Both are therefore properties
/// of the FILE, owed on every path -- including a usage refusal decided before
/// the log is opened. This lets those paths still measure the file.
fn positional_log(argv: &[String]) -> Option<PathBuf> {
    let mut i = 0usize;
    while i < argv.len() {
        let a = argv[i].as_str();
        if flag_takes_value(a) {
            i += 2;
            continue;
        }
        if !a.starts_with('-') {
            return Some(PathBuf::from(a));
        }
        i += 1;
    }
    None
}

/// `(records, torn_bytes)` for a log path, per SPEC.md §9.6 / §8.
///
/// Returns `(0, 0)` when there is no path, the path cannot be stat'd, or it is
/// not a regular file. A FIFO or pipe has no knowable length without consuming
/// it, and consuming it on an error path would be destructive, so 0 is the only
/// honest answer there.
fn file_counts(path: Option<&Path>) -> (u64, u32) {
    let p = match path {
        Some(p) => p,
        None => return (0, 0),
    };
    match std::fs::metadata(p) {
        Ok(md) if md.is_file() => {
            let len = md.len();
            (len / (RECORD_LEN as u64), (len % (RECORD_LEN as u64)) as u32)
        }
        _ => (0, 0),
    }
}

fn parse_args(argv: &[String]) -> Parsed {
    let mut log: Option<PathBuf> = None;
    let mut manifest: Option<PathBuf> = None;
    let mut pubkeys: Option<String> = None;
    let mut tape: Option<PathBuf> = None;
    let mut observed_now: Option<u64> = None;
    let mut expect_tip: Option<[u8; 32]> = None;
    let mut json = false;
    let mut cfg = Config::default();

    let mut i = 0usize;
    while i < argv.len() {
        let a = argv[i].as_str();

        let takes_value = flag_takes_value(a);
        let value: Option<&str> = if takes_value {
            if i + 1 >= argv.len() {
                return Parsed::Usage(format!("{} requires a value", a));
            }
            i += 1;
            Some(argv[i].as_str())
        } else {
            None
        };
        let v = value.unwrap_or("");

        match a {
            "--help" | "-h" => return Parsed::Info(USAGE.to_string()),
            "--version" | "-V" => {
                return Parsed::Info(format!(
                    "leg2-verify {} (Rust std only; hand-rolled SHA-256/SHA-512/Ed25519)\n",
                    env!("CARGO_PKG_VERSION")
                ))
            }
            "--selftest" => return Parsed::SelfTest,
            "--json" => json = true,
            "--manifest" => manifest = Some(PathBuf::from(v)),
            "--pubkeys" => pubkeys = Some(v.to_string()),
            "--tape" => tape = Some(PathBuf::from(v)),
            "--observed-now" => match v.parse::<u64>() {
                Ok(n) => observed_now = Some(n),
                Err(_) => {
                    return Parsed::Usage(format!(
                        "--observed-now must be an unsigned 64-bit integer, got {:?}",
                        v
                    ))
                }
            },
            "--expect-tip" => match parse_hex32(v) {
                Some(h) => expect_tip = Some(h),
                None => {
                    return Parsed::Usage(
                        "--expect-tip must be exactly 64 hex characters".to_string(),
                    )
                }
            },
            "--expect-spec-hash" => match parse_hex32(v) {
                Some(h) => cfg.expect_spec_hash = Some(h),
                None => {
                    return Parsed::Usage(
                        "--expect-spec-hash must be exactly 64 hex characters".to_string(),
                    )
                }
            },
            "--max-records" => match v.parse::<u64>() {
                Ok(n) => cfg.max_records = n,
                Err(_) => return Parsed::Usage("--max-records must be an integer".to_string()),
            },
            other => {
                if other.starts_with('-') {
                    return Parsed::Usage(format!("unknown option {:?}", other));
                }
                if log.is_some() {
                    return Parsed::Usage("more than one <log.bin> given".to_string());
                }
                log = Some(PathBuf::from(other));
            }
        }
        i += 1;
    }

    let log = match log {
        Some(l) => l,
        None => return Parsed::Usage("missing <log.bin>".to_string()),
    };
    let manifest = match manifest {
        Some(m) => m,
        None => return Parsed::Usage("missing --manifest <m.bin>".to_string()),
    };
    let pubkeys = match pubkeys {
        Some(p) => p,
        None => return Parsed::Usage("missing --pubkeys <a.pub,b.pub>".to_string()),
    };
    let parts: Vec<&str> = pubkeys.split(',').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
        return Parsed::Usage(
            "--pubkeys must be exactly two comma-separated paths: <a.pub,b.pub>".to_string(),
        );
    }

    Parsed::Ok(Box::new(Args {
        log,
        manifest,
        pubkey_a: PathBuf::from(parts[0]),
        pubkey_b: PathBuf::from(parts[1]),
        tape,
        observed_now,
        expect_tip,
        json,
        cfg,
    }))
}

/// Read a small input file, reading at most `cap + 1` bytes so an oversized file
/// is detectable rather than silently truncated.
fn read_small(path: &Path, cap: usize) -> Result<Vec<u8>, Verdict> {
    let f = File::open(path).map_err(|_| Verdict::UnverifiableUnreadable)?;
    let mut v = Vec::new();
    f.take(cap as u64 + 1)
        .read_to_end(&mut v)
        .map_err(|_| Verdict::UnverifiableUnreadable)?;
    Ok(v)
}

const MANIFEST_READ_CAP: usize = 1 << 20;

/// Where the log's bytes come from, together with its authoritative length.
/// SPEC.md §8 makes `file_len` decide both `records` and `torn_bytes`, so the
/// length must be known before the fold. A regular file gives it from metadata
/// (and is then streamed, O(1) memory); anything else (a pipe, a FIFO) is
/// buffered, bounded by the record ceiling.
enum LogSource {
    Stream(File, u64),
    Buffered(Vec<u8>),
}

fn open_log(path: &Path, max_records: u64) -> Result<LogSource, Verdict> {
    let f = File::open(path).map_err(|_| Verdict::UnverifiableUnreadable)?;
    match f.metadata() {
        Ok(md) if md.is_file() => {
            let len = md.len();
            Ok(LogSource::Stream(f, len))
        }
        Ok(_) => {
            // not a regular file: no trustworthy length, so buffer it. Bound the
            // read at (ceiling + 1) records so TOO_LARGE is still detectable.
            let cap = max_records
                .saturating_add(1)
                .saturating_mul(RECORD_LEN as u64)
                .saturating_add(RECORD_LEN as u64);
            let mut v = Vec::new();
            f.take(cap)
                .read_to_end(&mut v)
                .map_err(|_| Verdict::UnverifiableUnreadable)?;
            Ok(LogSource::Buffered(v))
        }
        Err(_) => Err(Verdict::UnverifiableUnreadable),
    }
}

fn run(args: &Args) -> Report {
    // SPEC.md §9.6 / §8: `records` and `torn_bytes` are properties of the log
    // FILE and are owed on every path, so measure it once up front and report
    // those counts even from the early input-validation refusals below.
    let (recs, torn) = file_counts(Some(args.log.as_path()));
    let early = |v: Verdict| Report::simple(v, recs, torn);

    // The manifest witness is hashed exactly as supplied (SPEC.md §3.2 step 3),
    // and its length must be exactly 176, so a wrong-length witness is a
    // BAD_GENESIS, not a usage error. Only a wildly oversized file is refused
    // here, purely to bound memory.
    let manifest = match read_small(&args.manifest, MANIFEST_READ_CAP) {
        Ok(v) => v,
        Err(v) => return early(v),
    };
    if manifest.len() > MANIFEST_READ_CAP {
        return early(Verdict::UnverifiableUsage);
    }

    let mut keys = [[0u8; PUBKEY_LEN]; 2];
    for (slot, path) in [args.pubkey_a.as_path(), args.pubkey_b.as_path()]
        .iter()
        .enumerate()
    {
        let raw = match read_small(path, PUBKEY_LEN + 1) {
            Ok(v) => v,
            Err(v) => return early(v),
        };
        if raw.len() != PUBKEY_LEN {
            // SPEC.md §9.1: "two 32-byte Ed25519 public-key files"
            return early(Verdict::UnverifiableUsage);
        }
        keys[slot].copy_from_slice(&raw);
    }

    // SPEC.md §9.2: the tape is read whole; its length is bounded by the record
    // ceiling (2 x 64 bytes per record).
    let tape_bytes = match &args.tape {
        None => None,
        Some(p) => {
            let cap = args
                .cfg
                .max_records
                .saturating_add(1)
                .saturating_mul(leg2_verify::spec::TAPE_BYTES_PER_RECORD as u64);
            let cap = if cap > (1u64 << 31) { 1u64 << 31 } else { cap } as usize;
            match read_small(p, cap) {
                Ok(v) => Some(v),
                Err(v) => return early(v),
            }
        }
    };

    let src = match open_log(&args.log, args.cfg.max_records) {
        Ok(s) => s,
        Err(v) => return early(v),
    };

    let inputs = Inputs {
        manifest: &manifest,
        key_a: keys[0],
        key_b: keys[1],
        tape: tape_bytes.as_deref(),
        observed_now: args.observed_now,
        expect_tip: args.expect_tip,
    };

    let mut rep = match src {
        LogSource::Stream(f, len) => {
            verify::verify_log(BufReader::new(f), len, &inputs, &args.cfg)
        }
        LogSource::Buffered(v) => {
            let len = v.len() as u64;
            verify::verify_log(&v[..], len, &inputs, &args.cfg)
        }
    };

    if manifest.len() != MANIFEST_LEN {
        rep.notes.push(format!(
            "--manifest is {} bytes; SPEC.md §8 freezes the GenesisManifest at {}",
            manifest.len(),
            MANIFEST_LEN
        ));
    }
    rep
}

fn print_text(rep: &Report) {
    let out = std::io::stdout();
    let mut o = out.lock();
    // LINE 1: the verdict line. Full name, nothing else on it (SPEC.md §9.6).
    let _ = writeln!(o, "{}", rep.verdict.name());
    let _ = writeln!(
        o,
        "records={} torn_bytes={} fail_index={} epoch={}",
        rep.records,
        rep.torn_bytes,
        match rep.fail_index {
            Some(i) => i.to_string(),
            None => "-".to_string(),
        },
        rep.epoch
    );
    if rep.verdict.is_accept() {
        let b = rep.balances;
        let _ = writeln!(
            o,
            "gross_spent={} seller_payout={} buyer_refund={}",
            b.gross_spent, b.seller_payout, b.buyer_refund
        );
    }
    if let Some(t) = rep.tip {
        let _ = writeln!(o, "tip={}", to_hex(&t));
    }
    let _ = writeln!(
        o,
        "expiry_gate={}",
        if rep.expiry_gate_evaluated {
            "evaluated"
        } else {
            "not_evaluated"
        }
    );
    for n in &rep.notes {
        let _ = writeln!(o, "note: {}", n);
    }
}

/// SPEC.md §9.6: the canonical comparison object. Keys in schema order; integers
/// are decimal JSON numbers; `tip` is "" unless ACCEPT*; `notes` is always "" in
/// canonical mode; `final_balances` is all-zero unless ACCEPT*.
fn print_json(rep: &Report) {
    let out = std::io::stdout();
    let mut o = out.lock();
    let b = if rep.verdict.is_accept() {
        rep.balances
    } else {
        leg2_verify::verdict::Balances::default()
    };
    let tip = match (rep.verdict.is_accept(), rep.tip) {
        (true, Some(t)) => to_hex(&t),
        _ => String::new(),
    };
    let _ = writeln!(
        o,
        "{{\"verdict\":\"{}\",\"exit_code\":{},\"records\":{},\"torn_bytes\":{},\
\"fail_index\":{},\"final_balances\":{{\"gross_spent\":{},\"seller_payout\":{},\
\"buyer_refund\":{}}},\"tip\":\"{}\",\"epoch\":{},\"expiry_gate_evaluated\":{},\
\"notes\":\"\"}}",
        rep.verdict.name(),
        rep.verdict.exit_code(),
        rep.records,
        rep.torn_bytes,
        match rep.fail_index {
            Some(i) => i.to_string(),
            None => "null".to_string(),
        },
        b.gross_spent,
        b.seller_payout,
        b.buyer_refund,
        tip,
        if rep.verdict.is_accept() { rep.epoch } else { 0 },
        rep.expiry_gate_evaluated,
    );
}

fn emit(rep: &Report, json: bool) -> ExitCode {
    if json {
        print_json(rep);
    } else {
        print_text(rep);
    }
    let _ = std::io::stdout().flush();
    ExitCode::from(rep.verdict.exit_code() as u8)
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();

    let args = match parse_args(&argv) {
        Parsed::Info(text) => {
            print!("{}", text);
            let _ = std::io::stdout().flush();
            return ExitCode::from(0);
        }
        Parsed::SelfTest => {
            return match crypto_self_check() {
                None => {
                    println!("SELFTEST_OK");
                    println!(
                        "sha256/sha512 anchors, derived curve constants, [L]B == identity, \
                         RFC 8032 round-trip"
                    );
                    ExitCode::from(0)
                }
                Some(e) => {
                    eprintln!("SELFTEST_FAILED: {}", e);
                    // --selftest takes no log, so there is no file to measure
                    emit(&Report::bare(Verdict::UnverifiableInternal), false)
                }
            }
        }
        Parsed::Usage(msg) => {
            eprintln!("usage error: {}", msg);
            eprintln!();
            eprint!("{}", USAGE);
            // SPEC.md §5.3: "a usage error DOES print a verdict line" -- and
            // §9.6/§8 still owe the file-derived counts, so measure the log even
            // though argument validation refused before opening it.
            let (recs, torn) = file_counts(positional_log(&argv).as_deref());
            return emit(
                &Report::simple(Verdict::UnverifiableUsage, recs, torn),
                argv.contains(&"--json".to_string()),
            );
        }
        Parsed::Ok(a) => a,
    };

    // Fail-closed against any panic anywhere below: print UNVERIFIABLE_INTERNAL
    // and exit 3. A panic must never reach the shell as an ACCEPT, nor as 101.
    let json = args.json;
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|info| {
        eprintln!("internal error (failing closed): {}", info);
    }));
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| run(&args)));
    std::panic::set_hook(prev_hook);

    match result {
        Ok(rep) => emit(&rep, json),
        // a caught panic: re-measure the file so the counts are still reported
        Err(_) => {
            let (recs, torn) = file_counts(positional_log(&argv).as_deref());
            emit(&Report::simple(Verdict::UnverifiableInternal, recs, torn), json)
        }
    }
}
