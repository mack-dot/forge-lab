# forge-airlock (private, for invited users)

Run `claude` (or any command) in a box. In the box, hidden code is absent (also from git
history), read-only paths cannot change, the upstream MCP servers' keys are not present, and every
MCP tool is default deny. Gated tools (money, deploys, counts) are capped by the compiled escrow
verifier of #91, whose model is proved in Dafny. When the program exits, you see the diff, and
your repository changes only after you type `y`.

`end_to_end=false`. The verdict of the verifier on one log is the only PROVED part (about the
Dafny model). Everything else is a NATIVE CHECK or a FINITE TEST (see "Honest labels").

## 60-second quickstart

You need Docker with Compose v2, Python 3.8+, git, and read access to `mack-dot/forge`
(with a git credential, because the repository is private).

```
/plugin install forge-airlock --marketplace mack-dot/forge
```

Then, in your repository, in Claude Code:

```
/forge-airlock:airlock
```

Claude reads the repository and `.mcp.json`, proposes hidden paths, read-only paths and a rule
for each MCP tool, asks you a few questions, writes `forge.yaml` (secrets only as `${NAME}`),
and writes `./forge-airlock`, a small wrapper that calls the installed `forge_airlock.py` by
absolute path. In a terminal (not inside Claude Code: the program in the box is interactive):

```
./forge-airlock up -- claude
```

The first run builds two images (a few minutes); later runs start in about 10 to 20 seconds.
Without Claude Code, from a checkout: `packages/forge-airlock/forge init`, then
`./forge-airlock up -- claude` (or `packages/forge-airlock/forge up -- <command>`).

`./forge-airlock` holds only a path, no secret: commit it or add it to `.gitignore`. If the
plugin moves (an update), it says so; `forge_airlock.py wrapper --force` writes it again.
`init` and `wrapper` never replace a different `./forge-airlock` without a yes.

## Credentials of the program in the box

`claude` in the box needs model access. Nothing from your shell is copied into the box
implicitly. Two ways:

- log in inside the box (Claude Code asks on first start; the login lives in the box's
  temporary `/tmp` and is gone afterwards), or
- `./forge-airlock up --pass-env ANTHROPIC_API_KEY -- claude`. This prints a warning: **the
  agent CAN read that value** and can send it to any host it can reach (here only the hosts in
  `agent.egress_allow`). The clean answer is a separate, spend-capped key for the box. With
  `--pass-env`, do not say that the agent "holds zero keys": it holds that one.

An upstream secret named in `forge.yaml` cannot be passed with `--pass-env` (refused), and if
its value reaches the agent anyway, the canary reports BREACH and nothing runs.

## What `up` does

1. Validates `forge.yaml` in the airlock image (exit 2 if invalid; every `${NAME}` it names must
   be set in your shell; only the airlock container gets those values).
2. Writes the Docker configuration into a temporary folder (you never edit Docker files).
3. Stages a private copy of the repository: the HEAD history (first parent) plus one commit with
   your uncommitted and untracked, not ignored, files.
4. The airlock rewrites that history without the hidden paths (and, with `visible_paths`,
   without everything not visible) and builds the box's workspace from the result.
5. Starts the airlock with the upstream MCP servers, and an egress proxy that opens tunnels only
   to `agent.egress_allow` (for `claude`: `api.anthropic.com:443`). The box has no other route out.
6. Runs the breach canary in the agent container (secrets, hidden content, read-only writes,
   egress, denied tools). Fail closed: on BREACH the command does not run (exit 10).
7. Runs your command interactively in the agent container (uid 1000, no capabilities, read-only
   root file system). For `claude`, it adds `--mcp-config <airlock> --strict-mcp-config`, so
   `claude` in the box sees the airlock as its only MCP server.
8. On exit, lists the changed files. Never applied: hidden paths, read-only paths, `forge.yaml`,
   `.git`, symlinks, ignored files, and files that you changed in the real repository meanwhile.
   Flagged for review: `.mcp.json`, `.claude/`, `.github/`, `package.json` and similar files
   that change what runs on your machine. It applies the rest only after `y`.
9. Removes the containers, networks and run volumes. The gate logs stay in the volume
   `forge-airlock-logs-<repo>` (caps count across runs); `forge reset-logs` deletes them.

Other commands: `forge init` (draft `forge.yaml`, also as `--json`), `forge tools` (start each
upstream and list its real tools, so the draft can classify them), `forge check`,
`forge reset-logs`, `forge wrapper`.

## forge.yaml

The reference is in `proposals/forge-mcp-airlock-20261122/README.md` (same engine). Additions:

```yaml
upstreams:
  - name: github
    transport: stdio
    command: [npx, -y, "@modelcontextprotocol/server-github"]
    env: {GITHUB_PERSONAL_ACCESS_TOKEN: "${GITHUB_TOKEN}"}   # NAME only; value from your shell
agent:
  egress_allow: ["api.anthropic.com:443"]   # the only hosts the box can reach (CONNECT proxy)
```

`forge.yaml` is always read-only in the box and is never synced back.

## Faster gates, same proved verifier

#97 started a new verifier subprocess for every gated call and re-verified the whole log
(about +300 ms per call). Now:

- the compiled Leg-1 verifier (Dafny-proved model) runs as ONE persistent process for the
  airlock's life (`engine/verifier_server.py`), through the unchanged glue `leg1_cli.py`;
- inside it, the compiled `Sha.Sha256` and `Ed.ValidateKey` are memoized, keyed by the exact input
  bytes. They are pure functions, so a repeated call returns what the compiled code returned for
  the same bytes. Every call still verifies EVERY record of the log; no incremental shortcut, no
  Rust leg (the unproved Rust leg of #91 is not used and not offered);
- start-up, reload and `audit.py` still use a fresh subprocess with no memo.
  `FORGE_VERIFIER=subprocess` restores the #97 path; `FORGE_VERIFIER_MEMO=0` turns the memo off.

Measured latency of one gated call, 120 calls after 5 warm-up calls (log grows to 126 records):

| Where | Before (#97: subprocess per call) median / p95 | After (persistent + memo) median / p95 |
| --- | --- | --- |
| host, `GateLog.reserve` (Python 3.10, macOS, no Docker) | 307.75 / 503.3 ms | 15.25 / 23.47 ms |
| Docker, `charge` through the airlock (bench.sh) | BENCH_BEFORE | BENCH_AFTER |

Persistent process without the memo: 276.3 / 446.28 ms (host): process start was not the main
cost; the compiled SHA-256 over every record was. The cost still grows with the log (about
0.1 ms per record after the memo), because every record is verified on every call.

## Tests

```
python3 packages/forge-airlock/tests/run_tests.py      # no Docker: 66 cases
python3 packages/forge-airlock/tests/run_up_e2e.py     # Docker: forge up end to end, 9 cases
packages/forge-airlock/proof/prove_airlock.sh          # Docker: the #97 battery + benchmark
```

`run_tests.py`: policy validation, `${NAME}` handling, path rules (hidden, visible, read-only,
symlinks, `..`), the sync-back filter, the persistent verifier (memo on, memo off and a fresh
subprocess give identical JSON on 24 logs, valid and broken, twice; restart after a kill; fail
closed on timeout), gate decisions through it, and the `forge.yaml` draft (no secret value).
`run_up_e2e.py`: a hostile script in the box; `n` leaves the repository unchanged; `y` applies
exactly the allowed files; a passed upstream secret gives canary BREACH, exit 10, nothing synced.
There is no CI job for these (this repository's `.github/` is not changed by this package).

Local results (2026-11-22, macOS, Docker 28.5.1): see `proof/results/` and the pull request.

## Honest labels

| Part | Label |
| --- | --- |
| Verdict of the compiled #91 verifier on one log (cap, chain, seq, duplicate id, expiry) | PROVED (about the Dafny model only) |
| The compiled verifier as it runs, `leg1_cli.py`, `verifier_server.py` and its memo table | NATIVE CHECK |
| "memo on gives the same verdict as memo off" | FINITE TEST (24 logs x 2) plus the purity argument above |
| Everything else in `engine/`, `forge_airlock.py`, the canary, the egress proxy, the sync filter, the draft heuristics | NATIVE CHECK |
| Every run and number in this README | FINITE TEST (one machine) |
| Isolation | container tier: the box shares the host kernel (on macOS, Docker Desktop's Linux VM) |
| Hosts in `agent.egress_allow` | reachable: the box can send data there |
| `--pass-env NAME` | the agent can read that value |

## Not tested

- `claude` doing real work in the box with a model key (no key was used). Tested: Claude Code
  2.1.330 in the box reports the airlock as "✔ Connected" (`claude mcp list`), and the proxy
  tunnels to `api.anthropic.com:443` and refuses `github.com:443` (403).
- Interactive TTY on Linux and Windows hosts (tested on macOS through a pseudo-terminal only);
  Windows is not supported (no `pty`, POSIX paths).
- Real upstream servers other than server-filesystem 2.2.0 and the mocks (for example
  `npx -y @modelcontextprotocol/server-github`), real credentials, `forge tools` against them.
- Large repositories (thousands of commits), merges (first parent only), submodules (dropped),
  LFS, binary hidden files; a cold Docker cache on a new machine.
- The `/forge-airlock:airlock` conversation itself (it is a prompt to Claude; its quality is not
  measured) and the marketplace install by an invited user on another machine.
- Everything listed under "Not tested" in the #97 README still applies.
