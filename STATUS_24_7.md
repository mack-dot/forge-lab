# STATUS_24_7

Ground truth for `endtoendtrue.md`. Read at the start of every run; update after every milestone. Numbers are
only those measured in a named checkout; anything else is marked as an estimate or inference.

**`end_to_end=false`.** Open named links: S1 (hardware human approval), hardware VM boundary, E2/E4, M1-B.

Last updated: 2026-11-23 (M0.2 pull request opened; M1.1 third planted bug in progress).

## Repositories

| Repository | Visibility | `main` | Open pull requests |
| --- | --- | --- | --- |
| mack-dot/forge | private | `4aef55d0` (#97 airlock merged) | #98 private airlock plugin (pushed by the owner), #89, #76, #37, #36, #34, #15, #14, #5, #3, #2, #1 |
| mack-dot/forge-claude-mod | public | `0c1c496` (tag v0.12.2) | none |

Process note: plugin releases v0.9.0–v0.12.2 were made before this directive by fast-forwarding `main` and tagging
from `wip/*` branches. From now on (Law 2) every milestone is a `feat/<milestone-id>` branch with a pull request;
the agent merges and tags nothing.

## Work in flight (local only, nothing pushed)

| Item | Where | State |
| --- | --- | --- |
| Single-plugin airlock (`airlock/`, `/forge:airlock`, `forge_airlock.py up`, `prove_release.sh`) | scratch clone `fcm-unified`, branch `wip/unified-airlock`, `5056699` | 7 gates passed twice on `2881584` (both exit 0; G6 gated call 300–370 ms → 16–21 ms median); merged with v0.12.1 since; not re-run after the merge |
| Model proxy (`llm` section, no key in the agent box) | copy `fcm-llm-proxy` | agent running |
| Red team: filesystem | copy `fcm-redteam-fs` | agent running |
| Red team: protocol and gates | copy `fcm-redteam-proto` | agent running |
| Sealed scan benchmark A (auth, billing) and B (state, scheduling, booking, parsing) | scratch `scan-bench/` (outside both repositories) | two agents running |

## Milestones

| Id | Status | Evidence / measured | Next action |
| --- | --- | --- | --- |
| M0.1 unified build clean from a scratch clone | IN_PROGRESS | 7/7 gates on `2881584` twice; plugin CI green on v0.12.2 | re-run all 7 gates on the merged branch from a fresh clone; open `feat/M0.1` PR in forge-claude-mod |
| M0.2 TRIAL.md pre-registration | PR_OPEN | forge-claude-mod pull request #2 (`feat/M0.2`): the five metrics by name, definitions, `trial-results.csv` template; 2 secret scans, 0 findings | owner review and merge |
| M0.3 sealed 40-bug benchmark | IN_PROGRESS | earlier: 8-bug set (now overfit), fresh 10-bug set recall 7/10 top-5, hit 25/25 (v0.10.2) | agents A and B harvest 40–50 bugs and measure v0.12.2 |
| M1.1 Go, Rust, Java, C# evaluators | IN_PROGRESS (gate gap) | shipped v0.9.0 (Go, Rust) and v0.10.0 (Java, C#); warm per-language run 120–520 ms on the example; planted bugs caught per language: Python 3, Go 3, TypeScript 2, Rust 2, Java 2, C# 2 (CI) | gate "3/3 planted bugs per language" is NOT met for TypeScript, Rust, Java, C#: add a third planted bug each |
| M1.2 coverage (c8, coverage.py) and `mutate --app` | NOT_STARTED | — | — |
| M1.3 forge-ci Action hardening | PARTIAL | Action runs check, `APPROVAL_CHANGED`, `build --check`, `invariants --check`; included files verified and scanned | add a configurable 50,000-input diff sweep and a zero-config workflow |
| M2.1 `/llm` proxy, no key in the box | IN_PROGRESS | agent running | — |
| M2.2 MCP Streamable HTTP, multi-upstream, roles | NOT_STARTED | HTTP side of #97 is a subset of MCP | start after M2.1 (same proxy code) |
| M2.3 red-team swarm | IN_PROGRESS (2 of 4 surfaces) | filesystem and protocol agents running; earlier: symlink-swap attack 0 leaks in 3,000 reads | findings → fixes + regression tests |
| M3 S1 hardware approval | NOT_STARTED | — | needs the owner's hardware key or Touch ID for the positive test |
| M4 microVM / gVisor | NOT_STARTED | — | gVisor and Firecracker need a Linux host; Apple Virtualization.framework is the local route |
| M5.1 stateful trace fuzzing | NOT_STARTED | — | — |
| M5.2 M1-B verified native core | NOT_STARTED | M1-B OPEN in the research record | — |

## Blocked, needs the owner

| Item | Why | What is needed |
| --- | --- | --- |
| M3 positive test | a hardware signature needs a person's key or finger | the owner's YubiKey or Touch ID session |
| M4 on Linux backends | this machine is macOS | a Linux host or CI runner with KVM |
| Publishing the airlock | forge-claude-mod is public | the owner's decision after review |
