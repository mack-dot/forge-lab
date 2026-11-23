# STATUS_24_7

Ground truth for `endtoendtrue.md`. Read at the start of every run; update after every milestone. Numbers are
only those measured in a named checkout; anything else is marked as an estimate or inference.

**`end_to_end=false`.** Open named links: S1 (hardware human approval), hardware VM boundary, E2/E4, M1-B.

Last updated: 2026-11-23 (v0.13.0 released; M1.1b, M1.3, M3, M4 started in parallel worktrees).

## Repositories

| Repository | Visibility | `main` | Open pull requests |
| --- | --- | --- | --- |
| mack-dot/forge | private | `4aef55d0` (#97 airlock merged) | #98 private airlock plugin (pushed by the owner), #89, #76, #37, #36, #34, #15, #14, #5, #3, #2, #1 |
| mack-dot/forge-claude-mod | public | `bd23da9` (tag v0.13.0) | #2 (M0.2), #3 (M1.1) — for the owner |

Process note: plugin releases v0.9.0–v0.12.2 were made before this directive by fast-forwarding `main` and tagging
from `wip/*` branches. From now on (Law 2) every milestone is a `feat/<milestone-id>` branch with a pull request;
the agent merges and tags nothing, except where the owner explicitly authorizes it (2026-11-23: PRs #4–#8 and the v0.13.0 release).

## Released

| Release | Contents | Evidence |
| --- | --- | --- |
| forge-claude-mod v0.13.0 (`bd23da9`, 2026-11-23) | bypass gate, messy-input fuzz, scope-honest status, stale notes, syntax step, approval digest, fast JS module + serviceTest, forge-airlock with red-team fixes and the model proxy | CI 6/6 on every PR; prove_release.sh 8 gates exit 0 on 3 consecutive runs (573 s, 577 s, final tree); clean clone of the tag: plugin 99/99, airlock 149/149, validate passed; 2 secret scans 0 findings |

Found and fixed on the way: PR #6 gave false APP_SYNTAX_ERROR on Node < 22.13 and crashed without git (CI caught both; regression test fails on the old code); G8 failed 12/21 after merging F7 (canary token not passed in the harness); two committed scoreboards carried a scratch path with the user name (G1 scan widened, with a self-test).

## Milestones

| Id | Status | Evidence / measured | Next action |
| --- | --- | --- | --- |
| M0.1 unified build clean from a scratch clone | DONE | v0.13.0: clean clone of the tag, plugin 99/99, airlock 149/149; prove_release 8/8 gates on the released tree | — |
| M0.2 TRIAL.md pre-registration | PR_OPEN | forge-claude-mod pull request #2 (`feat/M0.2`): the five metrics by name, definitions, `trial-results.csv` template; 2 secret scans, 0 findings | owner review and merge |
| M0.3 sealed 40-bug benchmark | DONE (baseline) | v0.12.2, 49 bugs, 14 repos, 63 scans all exit 0, sealed 2026-11-23T01:49Z (sealed-A.json, sealed-B.json in scratch `scan-bench/`, sha256 files beside them). **Top-5 recall 33/49 (67 %), top-7 37/49 (76 %).** A (auth, money; 7 repos): 21/25 top-5 (strict, no alias names: 18/25), 23/25 top-7, HEAD top-5 rows real rules 35/35, median 74.9 s. B (parsing, time, state machines; 7 repos): 12/24 top-5, 14/24 top-7, median 81.1 s; JavaScript semver 0/4. Post-cutoff (cannot be remembered): A 6/9, B 2/4. Weak spots: rule-building code (grant authoring), parsers' loose paths, small helpers, run-to-run variance. Caveats: one scan per checkout, grading by the harvesting agent (not blind), near-duplicate clusters | do not tune scan.md on these bugs; next scan change is measured on a NEW sealed set |
| M1.1 Go, Rust, Java, C# evaluators | PR_OPEN | forge-claude-mod #3: 3 planted bugs per language in all 6 languages; negative control per language (fixed code: no logic disagreement); local 50/50, CI run 45097752640 exit 0 (C# 373 ms). The first CI run failed on a wrong C# negative control (inputs above 2^63 cannot reach `long` code), corrected | owner review and merge |
| M1.1b messy fuzz for Go/Rust/Java/C# + warm-time gate | IN_PROGRESS (agent, `feat/M1.1b-compiled-messy`) | — | — |
| M1.2 coverage (c8, coverage.py) and `mutate --app` | NOT_STARTED | — | after M1.1b (same files) |
| M1.3 forge-ci Action hardening | IN_PROGRESS (agent, `feat/M1.3-forge-ci`) | Action runs check, APPROVAL_CHANGED, build --check, invariants --check | zero-config workflow, 50k sweep, job summary, negative controls in CI |
| M2.1 `/llm` proxy, no key in the box | DONE (v0.13.0) | G8: key absent from env, /proc and 10,843 files; 20 concurrent streams → exactly 7 forwarded (= floor(room/R)); error, cut stream, SIGKILL keep full reservation; restart keeps the cap; real-API smoke 19 tokens settled, HTTP 200. PROVED: verifier verdict on the log; NATIVE CHECK: estimate, settlement, proxy. Owner decision 2026-11-23: strict 1 byte/token default, override in forge.yaml | — |
| M2.2 MCP Streamable HTTP, multi-upstream, roles | NOT_STARTED | HTTP side of #97 is a subset of MCP | start after M2.1 (same proxy code) |
| M2.3 red-team swarm | IN_PROGRESS | filesystem CRITICAL fixed (16 alias cases; 14 fail on old code; G5 requires them); protocol F1–F8 fixed; in-box /proc, git-object, fd and Docker end-to-end alias probes NOT yet run; Windows names, homoglyph folding open | combined prove_release, then in-box probes |
| M3 S1 hardware approval | IN_PROGRESS (agent, `feat/M3-hardware-approval`) | — | software-key tests + rogue-agent negative controls; real YubiKey/Touch ID positive test needs the owner |
| M4 microVM / gVisor | IN_PROGRESS (agent, `feat/M4-isolation`) | — | gVisor in a Linux CI workflow; microVM scaffold (Virtualization.framework / Firecracker if CI has KVM) |
| M5.1 stateful trace fuzzing | NOT_STARTED | — | — |
| M5.2 M1-B verified native core | NOT_STARTED | M1-B OPEN in the research record | — |

## Owner feedback queue (2026-11-23, from the chronicle session), not in the directive's list

| Item | Status |
| --- | --- |
| Bypass scan (owner's top pick) | PR #4 open, CI green; on the chronicle copy names gate.ts:83 mayRetract, companion.ts:186, :224; upgrade to hard gate UNAPPROVED_BYPASS + allowedBypasses in progress |
| Scope-honest status | PR #6 |
| Messy-input wrapper fuzz | PR #5, CI green; chronicle copy: `entry.householdId = undefined: THROWS_ON_MESSY_INPUT (TypeError)` + 23 more throws; JS/Python only |
| Build syntax step (files + importers) | PR #6; chronicle copy: missing brace in sandbox/server.ts flagged |
| DECISION_NOTE_STALE | PR #6; chronicle copy: keyword.ts change flagged; note fixed without re-approval |
| Fast generated JS module + string cache; serviceTest live-call check | IN_PROGRESS (agent, `feat/fast-js-wrapper`) |
| Normative approval hashes; compact approval digest | PR #6; chronicle approval screen 26,214 → 1,404 characters |
| Next-rule suggestion | PR #6; chronicle copy suggests `visibleTo()` (gate.ts) |

## Blocked, needs the owner

| Item | Why | What is needed |
| --- | --- | --- |
| M3 positive test | a hardware signature needs a person's key or finger | the owner's YubiKey or Touch ID session |
| M4 on Linux backends | this machine is macOS | a Linux host or CI runner with KVM |
