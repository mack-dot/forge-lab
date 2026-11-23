# FORGE AUTONOMOUS 24/7 ENGINEERING DIRECTIVE

You are operating as Forge's autonomous staff engineering loop across `~/forge-claude-mod` and `~/forge`. Your goal is to systematically close every engineering, usability, language, isolation, and verification gap on the path from our current prototype to honest `end_to_end=true`—one verified PR at a time.

## NON-NEGOTIABLE OPERATING LAWS (NEVER VIOLATE)
1. **Disk State Over Memory:** Maintain `STATUS_24_7.md` with exact status (`DONE`, `IN_PROGRESS`, `BLOCKED`, PR link, measured numbers) for every milestone below. Read it at the start of every run and update it after every milestone.
2. **Worktree Isolation:** Build every milestone in its own clean `git worktree` and feature branch (`feat/<milestone-id>`). Never edit `main` directly, never force-push, never touch protected paths in `~/forge` unless the milestone explicitly targets them, and never merge your own PRs—open the PR (or leave branch ready if offline) and move to the next independent milestone.
3. **Radical Honesty & Negative Controls:**
   - Never claim a number you did not measure in this checkout.
   - Every security, proof, or fuzz gate MUST include at least one **planted failure / negative control** (a planted bug, `False0` axiom, or deliberate breach) proving the gate actually fails closed (`exit != 0`) when broken.
   - Never flip `end_to_end=false` to `true` until ALL named links (`S1`, hardware VM boundary, `E2/E4`, and `M1-B`) are independently verified and merged.
4. **Hard Anti-Thrash Fuse:** If any single proof lemma, compiler quirk, or environment blocker fails **5 consecutive attempts**, STOP burning tokens on it: document the exact minimal reproducer in `STATUS_24_7.md` / `unsure.md`, mark that sub-item `BLOCKED_NEEDS_HUMAN`, and immediately advance to the next unblocked milestone.
5. **Zero Secret / Path Leaks:** Run a 2× secret and hardcoded-home-path scan (`/Users/`, tokens, keys) + clean-clone test before completing any milestone.

---

## MILESTONE QUEUE (EXECUTE IN ORDER; PARALLELIZE INDEPENDENT SUBAGENTS ONLY IN SEPARATE WORKTREES)

### M0 — Baseline Lock, `TRIAL.md`, & Sealed 40-Bug Scan Benchmark
- **M0.1:** Verify the unified single-plugin build (`scan`, `INVARIANTS.md`, diff-fuzz, and `forge-airlock` 7-gate `prove_release.sh`) is clean from a scratch clone.
- **M0.2:** Write `TRIAL.md` pre-registering external human trial metrics (`completion_rate`, `minutes_to_verified`, `unplanted_bugs_found`, `false_alarms`, `drop_off_step`).
- **M0.3 (Parallel read-only subagents):** Harvest **40 real historical logic-bug commits** across 10+ diverse public repos (Go, TS, JS, Python, Rust — auth, billing, schedulers, state machines, routers) into a sealed evaluation script. **Strict rule:** NEVER feed held-out benchmark repo names or bug specifics into `commands/scan.md`. Measure and record baseline top-5/top-7 recall and hit rate.

### M1 — All 6 Languages + Coverage/Mutation Fuzzer Upgrades (`forge-claude-mod`)
- **M1.1 (4 parallel worktree subagents):** Using the central Python `stdin/stdout` JSON-line fuzzer core (big-int safe `> 2^53`), build thin persistent evaluators + `.forge/cache/` binary caching for **Go**, **Rust**, **Java**, and **C#**.
  - *Exit gate:* `< 1.0s` warm fuzz run (`1,500` inputs) per language; 3/3 planted logic bugs caught and shrunk per language in CI.
- **M1.2:** Add **Measure 2** (branch coverage via `c8` for JS/TS and `coverage.py` for Python, naming unreached branches) and **Measure 3** (`/forge mutate --app`: planting small mutations in the *user's shipped code* and scoring what `%` the diff-fuzzer catches).
- **M1.3:** Harden the standalone **`forge-ci` GitHub Action**: zero-config workflow that verifies Dafny proofs, `INVARIANTS.md` freshness, `SPEC_CHANGED`, `BINDING_BROKEN`, unsound-construct scan (`include`-files included), and a configurable `50,000`-input CI diff-fuzz sweep.

### M2 — Zero-Key Airlock, Full MCP Transport, & Automated Red-Team (`forge-airlock`)
- **M2.1 (Kill `--pass-env`):** Add an optional `/llm` reverse-proxy inside `airlock` that holds `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` on the host side, pre-reserves worst-case `max_tokens` cost in the proved `#91` `.bin` WAL before forwarding, and credits back unused tokens on stream completion—so `claude` inside the container runs with **zero** real keys in its environment.
- **M2.2:** Complete MCP Streamable-HTTP protocol support alongside stdio, plus multi-upstream composition in `forge.yaml` and optional `roles:` profiles (`junior`, `senior`, `contractor` scoping `visible_paths`, `hidden_paths`, `tools`, and `cap`).
- **M2.3 (Adversarial Red-Team Swarm):** Spawn 4 independent breaker subagents inside the Airlock `agent` box attempting escapes via: (a) concurrent symlink/hardlink races, (b) macOS case-insensitivity & Unicode NFD/NFC path collisions, (c) malformed/oversized JSON-RPC & partial TCP frames, and (d) `/proc`, fd, env, and `.git` leaks. Turn every finding into a fix + permanent regression test in `prove_airlock.sh`.

### M3 — Closing `Link S1` (Hardware-Backed Unforgeable Human Approval)
- Implement optional hardware-key signing (`ssh-keygen -Y sign` with FIDO2 `sk-ssh-ed25519` YubiKeys + macOS Secure Enclave / Touch ID helper where available) for:
  1. Sealing `.forge/approved.json` (`/forge approve yes --hardware`), and
  2. Runtime `require_human_approval` MCP tool escalations in `forge-airlock`.
- *Exit gate:* Prove via negative control that a rogue agent with full write access to the workspace **cannot** forge a valid approval signature or modify `forge.yaml` / `INVARIANTS.md` without hardware sign-off (`exit 2`).

### M4 — Closing the Shared-Kernel Gap (MicroVM / Sandboxed-Kernel Tier)
- Add a pluggable isolation backend (`--isolation docker | gvisor | microvm`) behind the identical `forge.yaml`:
  - Support `gVisor` (`runsc`) where available and scaffold/validate a disposable hardware-VM backend (Apple `Virtualization.framework` on macOS / `Firecracker` on Linux) so the untrusted agent runs on a separate kernel from `airlock`.
- *Exit gate:* Pass 100% of `prove_airlock.sh` (`24/24+` checks) and measure cold/warm startup overhead honestly.

### M5 — Whole-State Multi-Feature Composition (`Phase 4`) & `M1-B` Native Verified Core
- **M5.1 (Stateful Trace Fuzzing):** Support multi-event state machines (`step(State, Event, now) -> Result<State, Reject>`) with deterministic simulation / trace fuzzing generating `50,000+` random interleaved multi-event sequences + crash/retry injections, shrinking failing multi-step traces to minimal event sequences.
- **M5.2 (`M1-B` Verified Native Core):** Close the unverified-compiler gap on the core `128-byte` `.bin` WAL cap/replay/expiry verifier (via our HOL4/CakeML track in `~/forge` or Verus-verified native Rust), cross-checked at `0` diffs against `#91` Leg 1 (Dafny) and Leg 2 (Rust) across all `1,999+` cases, and measure latency (`target < 1 ms`).

---

## STARTUP SEQUENCE RIGHT NOW
1. Inspect `git status`, open branches, and any running processes in `~/forge-claude-mod` and `~/forge` without disturbing active work.
2. Create `STATUS_24_7.md` recording current ground truth.
3. Begin at the first incomplete item in **M0**, execute strictly under the 5 Operating Laws, and keep advancing through the queue until all unblocked milestones have verified PR branches ready for human review.
