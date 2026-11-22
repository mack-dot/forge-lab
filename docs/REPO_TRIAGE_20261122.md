# Repository triage, 2026-11-22

Read-only triage of `mack-dot/forge` for the owner. **Nothing was closed, deleted, merged or moved.**
Every action below is a suggestion; each one is the owner's decision. Counts are from `origin/main`
at `b5fb3de6` and from the owner's checkout on 2026-11-22.

## 1. The problem in numbers

| Measure | Value |
| --- | --- |
| Tracked files on `main` | 16,891 |
| Of those under `results/` and `proposals/` | 16,201 (96 %) |
| Tool code (`gate`, `src`, `scripts`, `clearing`, `ts`) | about 170 files |
| `unsure.md` / `ROADMAP.md` / `README.md` | 19,691 / 3,289 / 377 lines |
| Open pull requests | 12 |
| Remote branches other than `main` | 101 |
| Untracked items in the owner's checkout | 107 |
| Size on disk: `results/`, `build/`, `.toolchain/` | 6.7 GB, 6.4 GB, 4.6 GB |

A newcomer cannot find the product in this repository. The records are the reason its claims can be
trusted, so the answer is a split, not a cleanup that deletes records.

## 2. Suggested split

- **`mack-dot/forge` stays the research record.** Append-only `unsure.md`, protected paths, every
  result folder: unchanged. Nothing is rewritten or deleted.
- **The product lives in its own small repository.** `mack-dot/forge-claude-mod` (MIT, public) already
  holds the checker (`cli/forge_check.py`), the multi-language `build`, the GitHub Action, the Claude
  Code mod, tests, CI, `CHANGELOG.md`, `SECURITY.md`, `CONTRIBUTING.md` and `PLAN.md`. Tag `v0.3.1`.
- **A piece moves to the product only when it is finished**, with a link back to its evidence here.
  Candidates later: the escrow verifier (#91) as a library; the sidecar (#93) as a package.
- **This repository's README gets a short top section**: "the installable tool is
  `mack-dot/forge-claude-mod`; this repository is the research record". Pull request 89 already
  rewrites the README; that section fits there or after it merges.

## 3. Open pull requests

| PR | State | Suggestion | Why |
| --- | --- | --- | --- |
| 94 | open, docs only | merge | entry U931 (Dafny abstract-import finding). Hosted gate exit 3 UNSUPPORTED is the expected answer for `unsure.md` |
| 89 | open | review, then merge or close | README "front door"; overlaps with section 2 above |
| 76 | open, protected | owner's exact-diff decision | Stage 9 lock rebind (Gate F2a); Stage 9 stays deferred until decided |
| 37 | draft (2026-11-03) | close unless the RISC-V termination claim is still wanted | no `main` record links it as pending work |
| 36 | open (2026-11-02), 3 lines | check whether still needed, then merge or close | upload path fix for old report names; one record mentions it |
| 34 | draft (2026-11-02) | close | one-line booking experiment; one record mentions it |
| 15 | open, protected | decide | CODEOWNERS and templates; `.github/CODEOWNERS` on `main` already names `@mack-dot` for `*` |
| 14 | open (2026-10-28), 56 files | close or rebase | contributor readiness; much is now stale against `main` |
| 5, 3, 2, 1 | drafts (2026-10-26) | keep as they are | Stage 4 evidence: `ROADMAP.md` and other records link them with their run ids. Closing would keep the pages, but they were left open on purpose |

## 4. Remote branches (101)

GitHub keeps the head commit of every pull request under `refs/pull/<n>/head`, and a deleted branch
can be restored from its pull request page. So deleting a branch whose tip equals its pull request's
head loses nothing.

### 4a. Safe to delete: merged pull request, branch tip equals the pull request head (65)

<details><summary>List</summary>

| Branch | Commits ahead of main | Last commit |
| --- | --- | --- |
| `apex1/native-cosign` | 7 | 2026-11-20 |
| `chore/license-apache-2` | 2 | 2026-11-20 |
| `chore/release-cleanup-and-demo-audit` | 4 | 2026-11-20 |
| `ci/airlock-macos` | 6 | 2026-11-20 |
| `demo/archia-mcp-showcase` | 7 | 2026-11-20 |
| `demo/discovery-one-web` | 4 | 2026-11-20 |
| `demo/hal-9000` | 2 | 2026-11-20 |
| `demo/skeptic-gauntlet` | 1 | 2026-11-18 |
| `demo/video-storyboard` | 4 | 2026-11-20 |
| `docs/assurance-chain-audit` | 2 | 2026-11-20 |
| `docs/closeout-sync` | 1 | 2026-11-18 |
| `docs/front-door-and-v2-horizon` | 1 | 2026-11-18 |
| `docs/goal19-records` | 3 | 2026-11-19 |
| `docs/isolation-mode-design` | 3 | 2026-11-20 |
| `docs/m1-owner-decisions` | 1 | 2026-11-19 |
| `docs/m1-owner-review` | 2 | 2026-11-18 |
| `docs/m1b-route-a` | 2 | 2026-11-19 |
| `docs/master-idea-pcf` | 1 | 2026-11-17 |
| `docs/master-idea-records` | 1 | 2026-11-17 |
| `docs/master-idea-v2-horizon` | 1 | 2026-11-18 |
| `docs/readme-try-it` | 1 | 2026-11-21 |
| `docs/review-readme-claims` | 4 | 2026-11-20 |
| `docs/stage9-deferred-records` | 1 | 2026-11-18 |
| `docs/v2-formal-ceiling` | 1 | 2026-11-20 |
| `docs/wave-gate-records` | 1 | 2026-11-18 |
| `feat/airlock-review-hardening` | 20 | 2026-11-20 |
| `feat/escrow-dual-leg` | 2 | 2026-11-21 |
| `feat/intent-clearing-v2` | 15 | 2026-11-20 |
| `feat/m1-contract-link-closure` | 3 | 2026-11-19 |
| `feat/native-silicon-sink` | 3 | 2026-11-19 |
| `feat/sidecar-credential-monopoly` | 3 | 2026-11-21 |
| `feat/t19-hardened-sink` | 10 | 2026-11-20 |
| `feat/universal-primitives-v2` | 10 | 2026-11-20 |
| `feat/v1-refund-log-verifier` | 2 | 2026-11-21 |
| `feat/zero-babysitting-sdk` | 11 | 2026-11-19 |
| `fix/roadmap-sections-68-69` | 2 | 2026-11-20 |
| `fix/s2-shared-lock-teardown` | 3 | 2026-11-20 |
| `gate/coverage-soundness-v1` | 1 | 2026-10-29 |
| `governance/codeowners` | 3 | 2026-10-29 |
| `governance/ratification-0001-agent` | 2 | 2026-10-29 |
| `integration/booking-reuse-ci` | 1 | 2026-11-02 |
| `integration/receipt-authentication-contributor` | 1 | 2026-11-02 |
| `nightshift/consolidated-20261119-r1` | 7 | 2026-11-19 |
| `ops/linux-profile-v1` | 1 | 2026-10-30 |
| `proposal/refund-log-stateful-spec` | 2 | 2026-11-20 |
| `proposal/v3a-gate-ratification-rule` | 2 | 2026-11-17 |
| `proposal/v3b-print-effects-on-main` | 2 | 2026-11-18 |
| `ratify/refund-log-spec` | 2 | 2026-11-20 |
| `records/goal20-bundle-refresh` | 2 | 2026-11-20 |
| `records/m1-chain-replay` | 1 | 2026-11-18 |
| `records/stage6-epoch2-main` | 1 | 2026-11-17 |
| `slice1/refund-finality` | 2 | 2026-11-18 |
| `slice2/spec-clearing` | 1 | 2026-11-18 |
| `slice3/runtime-certificates` | 1 | 2026-11-18 |
| `slice4/m1-finality-conformance` | 2 | 2026-11-18 |
| `stage11/incremental-verification-v2` | 1 | 2026-10-30 |
| `stage4/approved-fees` | 0 | 2026-10-26 |
| `stage9/b1prime-v32` | 1 | 2026-10-28 |
| `stage9/records-b3-v32-install` | 1 | 2026-10-28 |
| `stage9/records-v33` | 1 | 2026-10-29 |
| `stage9/v33-install` | 1 | 2026-10-29 |
| `stage9/v34-install` | 1 | 2026-10-29 |
| `stage9/v35-token-compat` | 1 | 2026-10-29 |
| `stage9/v36-deploy-perms` | 1 | 2026-10-29 |
| `test/v32-candidate` | 1 | 2026-10-28 |

</details>

Command for the owner, after reading the list (deletes only these remote branches):
`gh pr list --state merged --limit 200 --json headRefName -q '.[].headRefName'` gives the names; delete
with `git push origin --delete <branch>` one by one or with the repository setting "Automatically
delete head branches" for the future.

### 4b. Check first: merged, but the branch moved after the merge (1)

| Branch | Note |
| --- | --- |
| `nightshift/A-proof` | its tip is not the merged pull request head: commits after the merge may exist only here |

### 4c. Closed pull requests, tip equals the pull request head (8) — delete after a look

| Branch | Commits ahead of main | Last commit |
| --- | --- | --- |
| `docs/m1b-wave4` | 9 | 2026-11-19 |
| `fix/proof-report-artifact-paths` | 1 | 2026-11-02 |
| `governance/ratification-0001` | 1 | 2026-10-29 |
| `integration/receipt-authentication-review` | 1 | 2026-11-02 |
| `nightshift/B-trust` | 80 | 2026-11-19 |
| `nightshift/C-redteam` | 75 | 2026-11-19 |
| `proposal/stage9-lock-rebind` | 1 | 2026-11-18 |
| `stage11/incremental-verification` | 2 | 2026-10-30 |

### 4d. No pull request (15) — keep unless the owner decides otherwise

| Branch | Commits ahead of main | Last commit |
| --- | --- | --- |
| `backup/0d0cdcee` | 3 | 2026-11-03 |
| `backup/6cfec85e` | 3 | 2026-11-02 |
| `backup/73728c2e` | 9 | 2026-11-04 |
| `backup/81255521` | 1 | 2026-11-04 |
| `backup/94549959` | 4 | 2026-11-04 |
| `backup/c8e87fd0` | 2 | 2026-11-03 |
| `backup/e60b97b6` | 1 | 2026-11-03 |
| `backup/forge-local-2026-11-11` | 77 | 2026-11-18 |
| `docs/finish-line-directive` | 8 | 2026-11-19 |
| `f2/stage9-benchmark-plan` | 3 | 2026-11-20 |
| `proposal/m1-cf-inputs-20261107` | 4 | 2026-11-08 |
| `proposal/m1-input-integrity-20261109` | 4 | 2026-11-09 |
| `proposal/m1-macos-preflight-20261106` | 4 | 2026-11-09 |
| `proposal/v3b-print-effects` | 4 | 2026-11-17 |
| `records/leg2-frozen-commit-reveal` | 1 | 2026-11-21 |

Do **not** delete without care:
- `records/leg2-frozen-commit-reveal`: the escrow dual-leg report (#91) relies on the pre-registered
  commit `862ee20a` that this branch holds (commit-reveal ordering of Leg 2 before Leg 1).
- `backup/forge-local-2026-11-11`: `ROADMAP.md` names it as the full record of Stages 10 and 11, the
  M1 work and Rounds 2 to 4.
- `docs/finish-line-directive`: holds the owner's queued finish-line directive.
- `backup/*` with short hashes: snapshots from early November; keep or archive as tags.

### 4e. Open pull requests (12): see section 3.

## 5. Untracked items in the owner's checkout (107)

| Group | Items |
| --- | --- |
| `results/refund-*` | 51 |
| `results/forge2-*` | 8 |
| `results/round3-*` | 6 |
| `results/stage7-*` | 6 |
| `results/stage8-*` | 6 |
| `results/stage9-*` | 6 |
| `results/stage11-*` | 5 |
| `results/round2-*` | 4 |
| `results/round4-*` | 3 |
| `.forge` | 1 |
| `.hol` | 1 |
| `KeyedStore` | 1 |
| `Restart` | 1 |
| `goal18.md` | 1 |
| `goal19.md` | 1 |
| `results/campaign-*` | 1 |
| `results/coverage-*` | 1 |
| `results/m1b-*` | 1 |
| `results/night-*` | 1 |
| `results/qemu-*` | 1 |
| `results/stage10-*` | 1 |

These are local result folders and scratch files that were never committed. Options, per group, for the
owner: commit the ones that a record cites; move the rest to an archive outside the repository (for
example `~/forge-archive/`); add stable scratch names to `.gitignore`. Nothing should be deleted before a
check that no `unsure.md` entry or `ROADMAP.md` row cites it.

## 6. Settings worth turning on

- "Automatically delete head branches" (stops new branch clutter after merges).
- Private vulnerability reporting (already on for `forge-claude-mod`).
- Keep branch protection on `main`; the admin bypass noted in earlier records means a merge by the
  admin account counts as a bypass.

`end_to_end=false`. No stage changes. No protected path changed by this document.
