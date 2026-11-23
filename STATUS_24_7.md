# STATUS_24_7

Ground truth for `endtoendtrue.md`. Read at the start of every run; update after every milestone. Numbers are
only those measured in a named checkout; anything else is marked as an estimate or inference.

**`end_to_end=false`.** Open named links: S1 (hardware human approval: code in PR #11, real-key test PENDING; no physical key has been used), hardware VM boundary (Linux: Kata microVM battery 35/35 in PR #13; macOS: vfkit IN_PROGRESS), E2/E4, M1-B. None is merged and verified as a whole yet.

Last updated: 2026-11-23 (mode switch to integration and first-time UX; #14 combines seven PRs; #15–#19 open; M2.2, M2.3, vfkit, scrub in progress; end_to_end=false).

## Repositories

| Repository | Visibility | `main` | Open pull requests |
| --- | --- | --- | --- |
| mack-dot/forge | public (since 2026-11-23) | #100 README merged (`3c203cb1`) | #99 (this file), #98, #89, #76, #37, #36, #34, #15, #14, #5, #3, #2, #1 |
| mack-dot/forge-claude-mod | public, no ruleset | `bd23da9` (tag v0.13.0) | #14 (combines #2, #3, #10, #12, #9, #11, #13), #15–#19, scrub PR; the seven are superseded by #14 |

Process note: plugin releases v0.9.0–v0.12.2 were made before this directive by fast-forwarding `main` and tagging
from `wip/*` branches. From now on (Law 2) every milestone is a `feat/<milestone-id>` branch with a pull request;
the agent merges and tags nothing, except where the owner explicitly authorizes it (2026-11-23: PRs #4–#8 and the v0.13.0 release; later the same day: forge #100 and #99 with `--admin` — the review cannot come from the author's account and forge/proof-gate rejects docs-only changes — and forge-claude-mod #14 only after prove_release passes).

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
| M1.1b messy fuzz for Go/Rust/Java/C# + warm-time gate | PR_OPEN (#10) | CI run 45114389005 6/6; 115 cases; 3 planted wrapper bugs caught per language, fail-closed 0/~1,525; warm 1,500 inputs: Go 0.27 s, Rust 0.31 s, Java 0.41 s, C# 0.19 s (CI), messy on ≤ 0.62 s; negative control 1 ms/call candidate 2.63 s | 3/3 planted LOGIC bugs per language waits on owner PR #3 |
| M1.2 coverage (NODE_V8_COVERAGE, coverage.py / stdlib tracer) and `mutate --app` | PR_OPEN (#12) | CI green; 109 cases. Example, strong vs weak inputs (negative control): legacy_wallet.py lines 4/4 vs 3/4, branches 2/2 vs 1/2 (reject path named); legacy_wallet.ts blocks never run 0 vs 1; mutate --app caught 19/21 vs 8/21 (2 survivors in app.py, likely equivalent). Cost: --coverage Python 156→241 ms, TS 196→281 ms; per mutant Python 0.15–0.22 s … Java ~1.4 s | no coverage for Go/Rust/Java/C#; JS has no branch totals (blocks instead) |
| M1.3 forge-ci Action hardening | PR_OPEN (#9) | zero-config `cli/forge_ci.py` + `examples/workflows/forge.yml`; base auto-detected (PR, merge group, push); 50,000-input sweep, seed = run id; job summary with repro commands. Negative controls in CI (runs 45113316698, 45114616292, 45115220522): unchanged → pass; W1 removed → APPROVAL_CHANGED (SPEC_CHANGED with base none); planted bypass → UNAPPROVED_BYPASS; edited INVARIANTS.md → INVARIANTS_STALE; rare wrapper bug → DISAGREE (1,500 inputs found it in 8/20 seeds, 50,000 in 10/10). Sweep 1.5–5.4 s per language on ubuntu-latest. First planted bug too rare (missed in run 45113930328), replaced | follow-ups: Action input for FORGE_ALLOWED_SIGNERS (with M3); pin Java/Rust/.NET; defaults changed (upgrade note) |
| M2.1 `/llm` proxy, no key in the box | DONE (v0.13.0) | G8: key absent from env, /proc and 10,843 files; 20 concurrent streams → exactly 7 forwarded (= floor(room/R)); error, cut stream, SIGKILL keep full reservation; restart keeps the cap; real-API smoke 19 tokens settled, HTTP 200. PROVED: verifier verdict on the log; NATIVE CHECK: estimate, settlement, proxy. Owner decision 2026-11-23: strict 1 byte/token default, override in forge.yaml | — |
| M2.2 MCP Streamable HTTP, multi-upstream, roles | IN_PROGRESS (`feat/M2.2-mcp-http`) | — | PR |
| M2.3 red-team swarm | IN_PROGRESS | filesystem CRITICAL fixed (16 alias cases; 14 fail on old code; G5 requires them); protocol F1–F8 fixed; in-box /proc, git-object, fd and Docker end-to-end alias probes NOT yet run; Windows names, homoglyph folding open | in-box probes IN_PROGRESS (`feat/M2.3-inbox-probes`) |
| M3 S1 hardware approval | PR_OPEN (#11); real-hardware positive test BLOCKED_NEEDS_HUMAN | CI 6/6, 126 cases; rogue-agent negative controls 27/27 exit 2 (spec, forge.yaml, INVARIANTS.md, approved.json, .sig, signing switched off, own key added and re-signed, all at once; anchor outside the project and at --base); owner-signed positive control exit 0 (software ed25519 key, FINITE TEST); airlock require_human_approval: hardware 16 unit + 6/6 Docker e2e; mutants of the verifier code fail 7–8 cases each | owner: run the YubiKey steps in PR #11 (Homebrew openssh; macOS ssh-keygen has no FIDO provider). Follow-up: Action input for FORGE_ALLOWED_SIGNERS on push runs. Still trusted: ssh-keygen, the anchor file or base-branch protection, key custody, no rollback dates |
| M4 microVM / gVisor | PR_OPEN (#13); macOS microVM agent BLOCKED_NEEDS_HUMAN | `--isolation docker|gvisor|microvm`, fail closed (exit 2 runtime missing or mismatch; in-box kernel probe exit 10). CI ubuntu-latest runs 45116333410, 45121073630: validate.sh docker 34/34, gvisor 35/35 (kernel 4.19.0-gvisor), microvm Kata 4.3.1/QEMU 35/35 (guest 6.18.56); run_up_e2e 12/12 each. Negative controls: missing runtime refused; runc posing as gVisor caught. Warm start overhead vs runc: gVisor +8–13 ms, Kata ≈ +2 s. Firecracker boot 426–712 ms (CI has /dev/kvm); Mac vfkit VM boot 293–380 ms warm (boot only). One CI Kata job hung 29 min (run 45117987521), now time-limited | owner chose vfkit (2026-11-23); macOS agent VM IN_PROGRESS on `feat/M4b-vfkit` (stacked on #13). Not tested: G5–G8 under non-docker backends, Kata with Cloud Hypervisor/Firecracker, attacks on gVisor/Kata |
| M5.1 stateful trace fuzzing | PR_OPEN (#15) | CI 6/6; 108 cases. examples/subscription-machine (Dafny model, clauses M1–M7). 4 planted bugs caught in JS and Python, shrunk to 2, 4, 2, 2 events; correct wrapper 0 disagreements over 50,000 traces (~275,000 steps) per language; 50,000 traces JS 11.6–21.4 s, Python 11.2–17.0 s (5 runs, one machine, load varied). Negative controls: max_len 1 finds none; restart 0 misses the restart bug; unknown key exit 2 | owner review. Not built: Go/Rust/Java/C# trace mode, time going backwards, several rules over one state; pause-expiry bug is seed-sensitive |
| M5.2 M1-B verified native core | NOT_STARTED | M1-B OPEN in the research record | — |

## Owner feedback queue (2026-11-23, from dogfooding on the owner's private app), not in the directive's list

| Item | Status |
| --- | --- |
| Bypass scan (owner's top pick) | PR #4 open, CI green; on a scratch copy of the owner's private app it names 3 real places outside the rule; upgrade to hard gate UNAPPROVED_BYPASS + allowedBypasses in progress |
| Scope-honest status | PR #6 |
| Messy-input wrapper fuzz | PR #5, CI green; private-app copy: 24 THROWS_ON_MESSY_INPUT (TypeError on a missing field); JS/Python only |
| Build syntax step (files + importers) | PR #6; private-app copy: a planted missing brace flagged |
| DECISION_NOTE_STALE | PR #6; private-app copy: a code change flagged; note fixed without re-approval |
| Fast generated JS module + string cache; serviceTest live-call check | IN_PROGRESS (agent, `feat/fast-js-wrapper`) |
| Normative approval hashes; compact approval digest | PR #6; private-app approval screen 26,214 → 1,404 characters |
| Next-rule suggestion | PR #6; private-app copy: suggests the recursive visibility function as the next rule |

## Mode switch (owner, 2026-11-23, late)

No new feature tracks after the running ones. Next: one unified release (#14 + #15–#19 + M2.2/M2.3/vfkit + scrub), one integrated clean-clone test, a fresh-machine test (no Dafny/.NET/goimports), a first-time-user pass (bare `/forge` runs the whole beginner loop; advanced tools hidden until relevant; README short, depth in `docs/`), then 5 real people (TRIAL.md, run by the owner).

| PR (forge-claude-mod) | Content | CI | Notes |
| --- | --- | --- | --- |
| #14 | #2, #3, #10, #12, #9, #11, #13 merged in the owner's order, conflicts resolved | green | found: #3 made the example UNAPPROVED_BYPASS (36 failures) and a missed Rust bypass line, fixed; Docker name collisions between parallel runs, fixed (two parallel validate.sh 34/34 PASS; same-id control fails 27/27); prove_release: G2–G8 pass with parallel runs on the host, G1 re-run pending |
| #15 | M5.1 trace fuzz | 6/6 | see M5.1 row |
| #16 | recursive-rule acid test, synthetic fixture | 6/6 | found and fixed: approval did not cover included spec files (soundness) |
| #17 | callers, drift status, feeder ranking | 13/13 | stacked on #14 |
| #18 | crash-fuzz, coverage steering, tiers | 13/13 | stacked on #14; steered 20/20 vs blind 0/20 on a narrow-branch bug |
| #19 | AST bypass scan (TS/JS, Python) | 6/6 | on a real app copy: 290 → 76 hits, 46/46 AST hits real |

## Owner decisions 2026-11-23 (second batch)

- macOS agent VM: vfkit.
- Merge order (owner): forge-claude-mod #2 → #3 → #10 → #12 → #9 → #11 → #13, plus forge #99; the agent merges `main` into each later branch to fix conflicts (no force-push); v0.14.0 after all are in. Rehearsal from `bd23da9`: conflicts expected in #10 (tests/run_cs_diff.py), #9, #11 (CHANGELOG.md, hooks/register.ts, tests/run_tests.py), #13 (CHANGELOG.md).
- S1 physical YubiKey test: PENDING until the owner runs it; 27/27 software-forgery checks are not a hardware result.
- recursive-rule acid test: scratch copy of the owner's app only, synthetic fixture in the suite, IN_PROGRESS.

## Blocked, needs the owner

| Item | Why | What is needed |
| --- | --- | --- |
| M3 positive test | a hardware signature needs a person's key or finger | the owner runs the steps in forge-claude-mod PR #11 with a YubiKey (or tries Touch ID via ssh-keychain.dylib) |
