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

RESULTS_PLACEHOLDER
