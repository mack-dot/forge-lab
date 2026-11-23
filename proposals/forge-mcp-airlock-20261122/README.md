# Forge MCP airlock (proposal slice, 2026-11-22)

`end_to_end=false`. Additive proposal: every file is in this folder. Nothing is merged
by the agent. The airlock is a NATIVE CHECK, the gate verdict on one log is the only
PROVED part, and every result below is a FINITE TEST (see "Honest labels").

## What it does

The agent runs in a container that can reach only one thing: the airlock. The airlock
speaks MCP (JSON-RPC 2.0) to the agent and to the real upstream MCP servers, which run on
the airlock side and hold every credential. One `forge.yaml` decides everything. No tool
name, domain or unit is hardcoded in the engine (`airlock/`).

- **Default deny for tools.** A tool that `forge.yaml` does not list is removed from
  `tools/list` and refused with `FORGE_TOOL_BLOCKED`. `deny` lists tools that are refused
  explicitly. `arg_rules` (allowlist, regex, integer range, equals / not equals, type)
  refuse bad arguments with `FORGE_ARG_REFUSED`.
- **Bounded-state gates.** A `gate` tool is checked by the compiled #91 escrow verifier
  on a persistent 128-byte `.bin` log, one log for each gate: a count cap (1 unit for each
  call) or a value cap (an integer argument named by `value_field`), with `per_call_max`,
  expiry, an optional `id_field` (a replay gets `REJECT_DUPLICATE_ID`) and an optional
  `checker` (any external program; it must exit 0).
- **Hidden code is absent, not just blocked.** The airlock rewrites the source history
  commit by commit into a new repository without the hidden paths (and, with
  `visible_paths`, without everything that is not visible). The agent gets a fresh clone
  of that filtered history. Hidden content is not present in the agent container, so
  `cat`, `../`, symlinks, `git show HEAD~2:path`, `git log --all -p` and a scan of all git
  objects find nothing. MCP file, search and git tools are checked again after
  `realpath()`.
- **Read-only paths** are read-only mounts in the agent (`<dir>/**` patterns) and are
  root-owned files without capabilities in the agent (all patterns). MCP write tools
  refuse them with `FORGE_PATH_READONLY`.
- **Startup breach canary, fail closed.** Before the agent loop starts, a probe in the
  agent container looks for upstream secrets (environment, `/proc/1/environ`, every text
  file), hidden content (direct, `../`, symlinks, airlock paths, every commit, every git
  object), writes to read-only paths, direct egress (public addresses and the upstream
  servers) and denied or unlisted tools. Until the canary reports PASS, the airlock
  forwards nothing (`FORGE_CANARY_PENDING`). After a BREACH it refuses every call
  (`FORGE_BREACH_LOCKDOWN`).

Use cases (from the owner):

- protect proprietary code while agents build around it (`hidden_paths`, `visible_paths`);
- stop a prompt-injected agent from leaking server or auth code (`visible_paths:
  ["src/ui/**"]` keeps `src/routes/**` out of the container and out of git history);
- hide evaluation answers (hidden tests) from an optimizing agent (`hidden_paths:
  ["tests/hidden/**"]`; the grader runs on the airlock side);
- hide sensitive data and prompts (`hidden_paths: ["data/**", "prompts/**"]`);
- least-privilege lanes for several agents on one repository (one airlock and one
  `forge.yaml` for each lane, each with its own tools, caps and visible paths).

## How to run

Docker with Compose v2 (tested: Docker 28.5.1, Compose v2.40.2, macOS host, Linux VM).

```sh
./prove_airlock.sh                 # whole battery + overhead benchmark; exit 0 only if all holds
./validate.sh  [out_dir]           # the battery only
./bench.sh     [out_dir]           # the overhead benchmark only
./skeptic_challenge.sh             # a bash shell inside the agent container: try to break it
FORGE_DOMAIN=codebase docker compose up --build --exit-code-from agent   # one domain by hand
docker compose down -v             # clean up after a manual run
```

`FORGE_DOMAIN` selects `policies/<domain>.yaml`: `codebase`, `visible`, `quota`,
`concurrency`, `bench`, `skeptic`.

## Layout

| Path | What |
| --- | --- |
| `airlock/gateway.py` | the airlock: MCP endpoint, policy, gates, canary state, startup |
| `airlock/policy.py` | strict `forge.yaml` loader; glob, path (realpath) and argument checks |
| `airlock/gatelog.py` | one gate: `.bin` log, flock, fsync, PENDING/COMMITTED/ABORTED journal, reload |
| `airlock/records.py` | 128-byte FV2 record encoder; call into the compiled verifier |
| `airlock/workspace.py` | filtered history, filtered workspace, hidden-content checks, read-only modes |
| `airlock/mcp_client.py` | upstream MCP clients (stdio, HTTP) |
| `airlock/audit.py` | read-only re-verification of every log, upstream ledger comparison |
| `airlock/render_mounts.py` | `readonly_paths` `<dir>/**` -> compose read-only subpath mounts |
| `airlock/verifier/` | the compiled #91 verifier and CLI glue, byte-identical copies from #93 (`proposals/forge-sidecar-demo-20261121/sidecar/`) |
| `mcpfs/` | pins the REAL `@modelcontextprotocol/server-filesystem` 2.2.0 (`package-lock.json`, `npm ci`) |
| `mocks/` | mock upstreams: `mock_http_mcp.py` (ops/db/payments over HTTP, FAKE key, ledger), `mock_repo_mcp.py` (content search + git over stdio) |
| `agent/` | `canary.py`, `scenario.py` (hostile agent with expectations), `bench.py`, `mcp_cli.py`, `lockdown_probe.py` |
| `checkers/sql_select_only.py` | example `checker` hook |
| `policies/` | one `forge.yaml` for each domain; `invalid/` holds four broken ones for fail-closed tests |
| `fixtures/` | the demo "private repository" (fake code, fake key), built into a 3-commit history at start |
| `results/` | logs and summaries of the recorded runs |

## forge.yaml reference

```yaml
version: 1                       # required, must be 1
upstreams:                       # required, one or more; they run on the airlock side
  - name: fs
    transport: stdio             # stdio | http
    command: [node, /opt/mcpfs/.../dist/index.js, /ws]
    user: 1000                   # optional: run the stdio server as this uid
    env: {TOKEN: "FAKE_..."}     # optional: credentials live only here
    timeout_s: 10                # optional, per request
  - name: ops
    transport: http              # JSON-RPC POST; JSON or SSE response body
    url: http://mock-http:9100/mcp
    headers: {Authorization: "Bearer FAKE_..."}
tools:
  allow:                         # pass-through
    - tool: read_text_file
      upstream: fs               # optional; required when two upstreams offer the name
      path_args: {path: read}    # read | write | git_revpath ; value may be a string or a list
      strict_args: false         # optional: refuse arguments that the policy does not name
      arg_rules:
        env:    {in: [staging]}                    # also: not_in, equals, not_equals
        branch: {not_in: [main], regex: "[a-z0-9/_-]{1,64}"}   # regex = full match
        limit:  {int_min: 1, int_max: 100}         # integers only (not bool, not string)
        note:   {type: string, optional: true}     # a ruled argument is required unless optional
  deny: [drop_database]          # explicit refusal (unlisted tools are refused anyway)
  gate:                          # bounded state, decided by the compiled #91 verifier
    - tool: run_query
      unit: value                # count (1 for each call) | value
      value_field: rows          # unit=value only: integer argument, 0 <= v <= 2^63-1
      cap: 1000                  # 0 <= gross <= cap over the life of the log
      per_call_max: 400          # optional
      expires_in_s: 86400        # or expires_at: <unix seconds>; fixed in the log genesis
      id_field: request_id       # optional: same value again -> REJECT_DUPLICATE_ID
      log: run_query             # optional log name (default: tool name); tools may share a log
      checker: {command: [python3, -I, /forge/checkers/sql_select_only.py], timeout_s: 5}
paths:
  hidden_paths:   ["src/proprietary/**", "**/algo.ts", ".env*"]
  visible_paths:  ["src/ui/**", "README.md"]   # optional allowlist; hidden wins over visible
  readonly_paths: ["tests/**", "spec/**", ".forge/**"]
  mcp_root: /ws                  # the workspace path on the airlock side (default /ws)
  agent_root: /workspace         # the same workspace in the agent (default /workspace)
  keep_commit_messages: false    # default false: messages may name hidden code
canary:
  egress_targets: ["1.1.1.1:443", "8.8.8.8:53", "example.com:443"]   # default; HTTP upstreams are added
  extra_secrets: []              # more strings that must not appear in the agent container
```

Rules: unknown keys, a tool both allowed and denied, a policy tool that no upstream offers,
two upstreams offering one name without `upstream:`, and a cap or expiry that differs from
the stored log genesis all stop the airlock at start (exit 2). Globs: `**` crosses `/`,
`*` and `?` do not; a pattern without `/` matches a basename at any depth; a path also
matches when an ancestor directory matches. `visible_paths` absent: the workspace holds
every file except `hidden_paths`. `visible_paths` present: it holds only matching files,
minus `hidden_paths`; MCP path checks apply the same rule after `realpath()` (a directory
may be listed when a visible pattern lies below it).

Refusal codes (JSON-RPC error `-32001`, `data.forge_code`): `FORGE_TOOL_BLOCKED`,
`FORGE_ARG_REFUSED`, `FORGE_PATH_HIDDEN`, `FORGE_PATH_OUTSIDE`, `FORGE_PATH_READONLY`,
`FORGE_PATH_REFUSED`, `FORGE_GATE_REFUSED` (with `data.verdict`: a verifier verdict such as
`REJECT_OVER_CAP`, `REJECT_DUPLICATE_ID`, `REJECT_EXPIRED`, or `PER_CALL_MAX`),
`FORGE_CHECKER_REFUSED`, `FORGE_UPSTREAM_FAILED`, `FORGE_CANARY_PENDING`,
`FORGE_BREACH_LOCKDOWN`, `FORGE_INTERNAL`.

Two-phase gate rule. Under the log lock the airlock asks the verifier about the log plus
the new step; on ACCEPT it appends and fsyncs the step, journals PENDING, then calls the
upstream, then journals COMMITTED or ABORTED. **Assumed upstream behaviour:** a timeout
or transport error does not tell whether the upstream acted, so the step stays spent, is
never retried and is never given back (the escrow log has no refund record). A PENDING
found at restart becomes ABORTED and stays spent. This can under-use a cap; it cannot
exceed it. The demo shows it: two `slow_job` calls time out, the mock still executes
both, and the third call is refused `REJECT_OVER_CAP`.

## Actual results (2026-11-22, one machine: macOS host, Docker 28.5.1 Linux VM)

`prove_airlock.sh` ran twice. Both exit codes are actual.

| Run | Where | Commit tested | Exit | Wall time |
| --- | --- | --- | --- | --- |
| 1 | this worktree | `1ac68835` | 0 | 182 s (validate 127 s, bench + cleanup the rest) |
| 2 | fresh `git clone --branch feat/mcp-airlock` of the pushed branch into a scratch folder | `c4d7a49` | 0 | 154 s (validate 105 s) |

Before run 2 the local image tag was removed, but the Docker layer cache was warm, so the
image build took 2 s in both runs. A machine with a cold cache also pulls
`python:3.12-slim-bookworm` and `node:24.11.0-bookworm-slim` and runs `apt-get` and
`npm ci`; that path was not timed here. Logs: `results/run1-worktree/`,
`results/run2-fresh-clone/` (`summary.txt`, `prove.txt`, `bench.md` and one log for each case).

Cases of `validate.sh`, identical in both runs (each line has an expected exit code):

| Case | Expected | Actual (run 1, run 2) |
| --- | --- | --- |
| codebase: `docker compose up` (canary PASS, then scenario: 76 checks) | 0 | 0, 0 |
| codebase: planted breach, credential in agent env | 10 | 10, 10 |
| codebase: planted breach, hidden file bind-mounted into the agent | 10 | 10, 10 |
| codebase: planted breach, agent as uid 0 without read-only mounts | 10 | 10, 10 |
| codebase: after a BREACH an allowed read is refused `FORGE_BREACH_LOCKDOWN` | 0 | 0, 0 |
| codebase: workspace re-verified on each of 3 airlock restarts | 0 | 0, 0 |
| visible: `docker compose up` (canary PASS, then 53 checks) | 0 | 0, 0 |
| quota: `docker compose up` (canary PASS, then 27 checks) | 0 | 0, 0 |
| quota: `docker compose restart airlock` on the same log volume | 0 | 0, 0 |
| quota: phase 2 after the restart (8 checks: every cap kept) | 0 | 0, 0 |
| quota: audit, every log re-verifies ACCEPT and gross <= cap | 0 | 0, 0 |
| quota: audit numbers (3 deploys, 1000 rows, 2 aborted, no denied tool reached the upstream) | 0 | 0, 0 |
| quota: planted breach, agent attached to the upstream network | 10 | 10, 10 |
| quota: a second airlock on the same log volume | 2 | 2, 2 |
| quota: invalid policies (unknown key, allow+deny, tool not offered, cap changed) | 2 each | 2, 2 (each, with the expected reason) |
| quota: one flipped byte in `deploy.bin` | 2 | 2, 2 |
| concurrency: `docker compose up` (canary PASS, then 17 checks) | 0 | 0, 0 |
| concurrency: audit and numbers (sum 1000 = cap, 14 charges, 0 duplicate invoice ids upstream, 5 deploys) | 0 | 0, 0 |
| cleanup: 0 containers, 0 volumes, 0 networks of the demo left | 0 | 0, 0 |

What the scenario checks cover (all in `agent/scenario.py`, each an `expect` line in the logs):

- **Codebase and `.git` lockdown** (codebase): `src/ui.ts` and `src/app.ts` readable;
  `src/proprietary/core.ts`, `src/lib/algo.ts`, `.env` unreadable by `cat`-style open,
  `../`, `/workspace/../workspace/...`, a symlink, and `git show <c>:<path>` for all 3
  commits; `git log --all -p` and every git object hold no hidden marker and not the fake
  `.env` key; commit messages that named the hidden code are replaced. Through MCP (real
  server-filesystem): hidden reads refused `FORGE_PATH_HIDDEN` (also `read_multiple_files`
  with one hidden element, and agent-made symlinks); symlinks to `/state/source/...` and
  to the airlock's `forge.yaml` refused `FORGE_PATH_OUTSIDE`; `git_show HEAD~2:.env` refused.
- **Read-only `tests/`**: append, create, unlink, rename, chmod by shell fail; MCP
  `write_file`, `edit_file`, `create_directory` refused `FORGE_PATH_READONLY`.
- **visible_paths** `["src/ui/**", "README.md"]` (visible): `src/ui/button.ts` and
  `README.md` readable; `src/routes/*`, `tests/*`, `src/app.ts` and the hidden
  `src/ui/secret_theme.ts` (hidden wins) are absent by shell, `../`, symlink and every
  commit; git history names only `README.md` and `src/ui/button.ts`; MCP reads, a listing
  of `src/routes`, `git_show HEAD:src/routes/auth.ts`, an agent symlink
  `src/ui/sneak.ts -> ../routes/auth.ts` and a write to `src/routes/` are refused.
- **Default deny and arg_rules** (quota, codebase): `tools/list` is exactly the listed set;
  denied and unlisted tools refused `FORGE_TOOL_BLOCKED`; `env=production`, `branch=main`,
  a bad branch regex, a missing ruled argument and a string where an integer is required
  are refused `FORGE_ARG_REFUSED`; a `DELETE` query is refused by the checker hook.
- **Caps**: count cap 3 stops the 4th deploy `REJECT_OVER_CAP`; value cap 1000 with
  `per_call_max` 400; two timed-out `slow_job` calls stay spent and the 3rd is refused;
  after `docker compose restart airlock` every cap is still reached.
- **Concurrency and replay**: 20 concurrent charges of 100 with 740 left: exactly 7 pass,
  13 `REJECT_OVER_CAP`; 20 concurrent deploys on a count cap of 5: exactly 5 pass; 10
  concurrent calls with one new id: exactly 1 passes, 9 `REJECT_DUPLICATE_ID`; replays of
  used ids refused `REJECT_DUPLICATE_ID`; the upstream ledger shows sum 1000 and 0
  duplicate ids.
- **Zero secrets and zero direct egress**: no FAKE credential in the agent environment;
  TCP to `1.1.1.1:443`, `8.8.8.8:53` and `mock-http:9100` fails; the canary also scans
  every text file (about 6,300) and `/proc/1/environ`. Planted controls prove the canary
  sees each kind of breach.

### Per-call overhead (bench.sh, 120 calls each after 5 warm-up calls)

"Direct" calls the same upstream without the airlock (a harness container on the upstream
network; for the filesystem server, a private copy of the same server over stdio).

| Call | Run | Direct median / p95 (ms) | Via airlock median / p95 (ms) | Overhead median / p95 (ms) |
| --- | --- | --- | --- | --- |
| `read_text_file` (real server-filesystem, stdio), pass-through | 1 | 1.06 / 4.18 | 3.12 / 10.1 | 2.06 / 5.92 |
| | 2 | 0.64 / 1.13 | 1.81 / 19.4 | 1.17 / 18.27 |
| `get_status` (mock HTTP), pass-through | 1 | 1.72 / 3.32 | 3.03 / 6.81 | 1.31 / 3.49 |
| | 2 | 1.27 / 2.0 | 2.53 / 7.96 | 1.26 / 5.96 |
| `charge` (mock HTTP), gated | 1 | 1.48 / 3.04 | 317.8 / 537.78 | 316.32 / 534.74 |
| | 2 | 1.43 / 3.11 | 298.35 / 495.75 | 296.92 / 492.64 |

Reading: a pass-through call costs about 1 to 2 ms more at the median (one extra HTTP hop
plus policy checks). A gated call costs about 300 ms at the median, because each call
starts the compiled Python verifier as a subprocess and re-verifies the WHOLE log (the
cost grows with the log: here up to 126 records, genesis plus 125 steps). The p95 values vary between runs
by a factor of up to 3 on this laptop VM; they are not a stable bound.

## Honest labels

| Part | Label | Why |
| --- | --- | --- |
| Verdict of the compiled #91 verifier on one log (cap, money chain, dense seq, duplicate step id, expiry) | PROVED (about the Dafny model only) | #91 proved the model; the compiled Python is the #93 build, byte-identical |
| The compiled verifier as it runs here, and its CLI glue `leg1_cli.py` | NATIVE CHECK | compiled or hand-written code that runs, not proved |
| Everything in `airlock/` (gateway, policy, globs, realpath checks, record encoder, flock, fsync, journal, restart recovery, workspace filter, read-only modes, canary state), `agent/canary.py`, `mocks/`, `checkers/` | NATIVE CHECK | hand-written, not proved |
| "gross <= cap across concurrent calls" | NATIVE CHECK around a PROVED verdict | the lock that serializes calls is not proved; the verdict for each call is |
| "Hidden content is absent from the agent container" | NATIVE CHECK + FINITE TEST | the filter is unproved code; the scans and probes are finite |
| Every run, number and timing in this README | FINITE TEST | one machine, two runs, the listed inputs |
| Isolation | container tier | the agent shares the host kernel (Docker Desktop Linux VM); a kernel or runtime escape is out of scope |
| End to end | `end_to_end=false` | mocks and fake keys; no real paid service; no hosted run |

## Known issues

- **Gate latency grows with the log.** Every gated call re-verifies the whole log in a new
  subprocess (about 300 ms median over a log of up to 126 records). Fine for deploy-like calls, slow for
  high-rate calls. A fix (incremental verification from a verified tip) is not built.
- **Concurrency is serialized by one lock for each log.** Gated calls on one log do not run
  in parallel through the verifier; upstream calls do run in parallel after the reserve.
- **TOCTOU on symlinks.** The airlock checks `realpath()` and then the upstream opens the
  path. An agent that swaps a symlink between the two can win the race. Second layers: the
  upstreams run as uid 1000, the real server-filesystem does its own realpath check
  inside `/ws`, and hidden content is not present in `/ws` at all. Not tested.
- **Read-only open gives EACCES before EROFS.** Inside a read-only mount the file-mode check
  fails first; chmod and rename show EROFS. Both layers hold, the messages differ.
- **Root in the agent.** If the agent runs as uid 0 without the generated read-only mounts,
  it can chmod and rename read-only paths (the planted control shows the canary catches
  it). The defaults (`user: 1000`, `cap_drop: ALL`, `no-new-privileges`, read-only mounts)
  are part of the security model.
- **Directory listing with `visible_paths`.** A directory may be listed when a visible
  pattern can lie below it; a basename pattern (such as `README.md`) allows listing any
  directory that exists in the workspace. Only visible files exist there.
- **Canary plan.** The canary gets line fingerprints of hidden content and credential
  hashes once; the airlock closes that endpoint after the report. A canary that does not
  report leaves the airlock refusing everything (fail closed). The canary trusts the
  container's start state; it runs before the agent but in the agent's container.
- **Commit metadata.** Author names, emails and dates are copied into the filtered history.
- **HTTP upstream only one way.** `mcp_client.py` reads a JSON or SSE response body; no
  sessions, no server-to-client requests, no resumable streams. The agent-facing endpoint
  is JSON-RPC over HTTP POST with JSON responses (a subset of MCP Streamable HTTP).
- **Line fingerprints** ignore lines shorter than 12 characters and lines that also occur
  in visible files, so a short or shared hidden line is not detected by the scans
  (it is still absent, because the file is absent).

## Not built

- Full MCP Streamable HTTP (sessions, SSE streams to the agent), stdio towards the agent,
  resources, prompts, sampling, roots, cancellation, notifications other than
  `notifications/initialized`.
- Result filtering of upstream responses (the design relies on hidden content being absent
  from the upstream's view instead).
- Refund or release of an ABORTED gate step; retries with idempotency keys.
- Incremental verification; a proved lock or a proved policy engine.
- A merge-back path for the agent's workspace into the real repository.
- Multi-agent lanes in one compose file (each lane = one airlock + one forge.yaml; shown
  only as a design).

## Not tested

- A real repository with merges (the filter follows the first-parent chain only),
  submodules (dropped), LFS, very large histories, or binary hidden files (fingerprints
  read text lines).
- A real paid service or a real credential; any upstream other than server-filesystem
  2.2.0 and the two mocks; MCP HTTP/SSE servers from other vendors.
- Symlink-swap races (TOCTOU) and other timing attacks; side channels (file sizes, timing,
  error-message differences); resource exhaustion against the airlock.
- Crash in the middle of a gated call (kill -9 between append and journal); the restart
  path for PENDING steps is built but was not exercised by a crash.
- Expiry reached during a run (the verifier's `REJECT_EXPIRED` was seen only in the
  standalone timing test, not through the airlock).
- Kernel or container-runtime escapes; gVisor, Kata or VM-tier isolation; Linux hosts other
  than the Docker Desktop VM; rootless Docker; Podman.
- A cold Docker cache (first-ever pull and build) for the clone run.
- Interactive use of `skeptic_challenge.sh` by a person. It was run once with piped
  commands: `cat src/app.ts` worked, `cat src/proprietary/core.ts` gave "No such file",
  `env | grep -c FAKE_` gave 0, the MCP hidden read was refused `FORGE_PATH_HIDDEN`,
  deploys 1 to 3 passed and deploy 4 was refused `REJECT_OVER_CAP`, `drop_database` was
  refused `FORGE_TOOL_BLOCKED`, and `echo x >> tests/ui.test.ts` gave "Permission denied".
- Hosted CI; the repository's PR gate is not expected to accept these additive files.
