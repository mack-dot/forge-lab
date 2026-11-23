# STATUS_24_7

Ground truth for `endtoendtrue.md`. Read at the start of every run; update after every milestone. Numbers are
only those measured in a named checkout; anything else is marked as an estimate or inference.

**`end_to_end=false`.** Open named links: S1 (hardware human approval), hardware VM boundary, E2/E4, M1-B.

Last updated: 2026-11-23 (M0.3 measured; M1.1 pull request #3 green; airlock sync-back CRITICAL found, fix in progress).

## Repositories

| Repository | Visibility | `main` | Open pull requests |
| --- | --- | --- | --- |
| mack-dot/forge | private | `4aef55d0` (#97 airlock merged) | #98 private airlock plugin (pushed by the owner), #89, #76, #37, #36, #34, #15, #14, #5, #3, #2, #1 |
| mack-dot/forge-claude-mod | public | `0c1c496` (tag v0.12.2) | #2 (M0.2), #3 (M1.1) |

Process note: plugin releases v0.9.0–v0.12.2 were made before this directive by fast-forwarding `main` and tagging
from `wip/*` branches. From now on (Law 2) every milestone is a `feat/<milestone-id>` branch with a pull request;
the agent merges and tags nothing.

## Work in flight (local only, nothing pushed)

| Item | Where | State |
| --- | --- | --- |
| Single-plugin airlock (`airlock/`, `/forge:airlock`, `forge_airlock.py up`, `prove_release.sh`) | scratch clone `fcm-unified`, branch `wip/unified-airlock`, `5056699` | 7 gates passed twice on `2881584` (both exit 0; G6 gated call 300–370 ms → 16–21 ms median); merged with v0.12.1 since; not re-run after the merge |
| Model proxy (`llm` section, no key in the agent box) | copy `fcm-llm-proxy` | agent running |
| Red team: filesystem | copy `fcm-redteam-fs` | DONE. 1 CRITICAL: sync-back guards are case- and Unicode-sensitive, the macOS host is not; `Forge.yaml`, `.GIT/hooks/post-checkout`, `TESTS/…` (read-only), `SRC/proprietary/…` (hidden) all written to the real repo (host code execution through a git hook). Host-side unit suite 67/67 passed and does not cover it. Fix + regression tests in progress in `fcm-unified` |
| Red team: protocol and gates | copy `fcm-redteam-proto` | agent running |
| Sealed scan benchmark A and B | scratch `scan-bench/` (outside both repositories) | DONE, see M0.3 |

## Milestones

| Id | Status | Evidence / measured | Next action |
| --- | --- | --- | --- |
| M0.1 unified build clean from a scratch clone | IN_PROGRESS | 7/7 gates on `2881584` twice; plugin CI green on v0.12.2 | re-run all 7 gates on the merged branch from a fresh clone; open `feat/M0.1` PR in forge-claude-mod |
| M0.2 TRIAL.md pre-registration | PR_OPEN | forge-claude-mod pull request #2 (`feat/M0.2`): the five metrics by name, definitions, `trial-results.csv` template; 2 secret scans, 0 findings | owner review and merge |
| M0.3 sealed 40-bug benchmark | DONE (baseline) | v0.12.2, 49 bugs, 14 repos, 63 scans all exit 0, sealed 2026-11-23T01:49Z (sealed-A.json, sealed-B.json in scratch `scan-bench/`, sha256 files beside them). **Top-5 recall 33/49 (67 %), top-7 37/49 (76 %).** A (auth, money; 7 repos): 21/25 top-5 (strict, no alias names: 18/25), 23/25 top-7, HEAD top-5 rows real rules 35/35, median 74.9 s. B (parsing, time, state machines; 7 repos): 12/24 top-5, 14/24 top-7, median 81.1 s; JavaScript semver 0/4. Post-cutoff (cannot be remembered): A 6/9, B 2/4. Weak spots: rule-building code (grant authoring), parsers' loose paths, small helpers, run-to-run variance. Caveats: one scan per checkout, grading by the harvesting agent (not blind), near-duplicate clusters | do not tune scan.md on these bugs; next scan change is measured on a NEW sealed set |
| M1.1 Go, Rust, Java, C# evaluators | PR_OPEN | forge-claude-mod #3: 3 planted bugs per language in all 6 languages; negative control per language (fixed code: no logic disagreement); local 50/50, CI run 45097752640 exit 0 (C# 373 ms). The first CI run failed on a wrong C# negative control (inputs above 2^63 cannot reach `long` code), corrected | owner review and merge |
| M1.2 coverage (c8, coverage.py) and `mutate --app` | NOT_STARTED | — | — |
| M1.3 forge-ci Action hardening | PARTIAL | Action runs check, `APPROVAL_CHANGED`, `build --check`, `invariants --check`; included files verified and scanned | add a configurable 50,000-input diff sweep and a zero-config workflow |
| M2.1 `/llm` proxy, no key in the box | IN_PROGRESS | agent running | — |
| M2.2 MCP Streamable HTTP, multi-upstream, roles | NOT_STARTED | HTTP side of #97 is a subset of MCP | start after M2.1 (same proxy code) |
| M2.3 red-team swarm | IN_PROGRESS | filesystem: 1 CRITICAL (see above), fix in progress; protocol agent running; in-box /proc, git-object and fd probes NOT yet run | fixes + regression tests in prove_release.sh G5 |
| M3 S1 hardware approval | NOT_STARTED | — | needs the owner's hardware key or Touch ID for the positive test |
| M4 microVM / gVisor | NOT_STARTED | — | gVisor and Firecracker need a Linux host; Apple Virtualization.framework is the local route |
| M5.1 stateful trace fuzzing | NOT_STARTED | — | — |
| M5.2 M1-B verified native core | NOT_STARTED | M1-B OPEN in the research record | — |

## Owner feedback queue (2026-11-23, from the chronicle session), not in the directive's list

| Item | Status |
| --- | --- |
| Bypass scan: list code outside the proved rule that decides on the same fields (owner's top pick) | IN_PROGRESS (agent, `feat/bypass-scan`) |
| Status says what VERIFIED covers (model / compiled code fuzzed / wrapper not proved / callers outside) | IN_PROGRESS |
| Fuzz the wrapper with raw values (null, undefined, missing, numbers); wrapper must fail closed | IN_PROGRESS |
| Build sanity step (tsc --noEmit, node --check, py_compile) | IN_PROGRESS |
| Stale decision records when described code changes | IN_PROGRESS |
| Clean ES module at build time (no runtime new Function); Rust→wasm later | NOT_STARTED |
| Approval hashes only normative parts of decision records | NOT_STARTED |
| Suggest the next rule that closes the largest gap | NOT_STARTED |

## Blocked, needs the owner

| Item | Why | What is needed |
| --- | --- | --- |
| M3 positive test | a hardware signature needs a person's key or finger | the owner's YubiKey or Touch ID session |
| M4 on Linux backends | this machine is macOS | a Linux host or CI runner with KVM |
| Publishing the airlock | forge-claude-mod is public | the owner's decision after review |
