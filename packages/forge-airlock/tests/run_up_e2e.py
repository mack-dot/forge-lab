#!/usr/bin/env python3
"""End-to-end test of `forge up -- <command>` (needs Docker with Compose v2).

Builds a throwaway repository from proof/fixtures (3 files hidden, tests/ read-only, a FAKE
key in .env, one uncommitted change), runs a hostile shell script as the boxed command, and
drives the y/N prompt through a pseudo-terminal. Cases:
  1. answer n -> the real repository is byte-for-byte unchanged;
  2. answer y -> exactly the allowed changes are applied; hidden, read-only, ignored and
     forge.yaml changes are not; the uncommitted change was visible in the box;
  3. a breach (the FAKE upstream key passed to the agent) -> canary BREACH, exit 10, nothing synced.
Leaves no container, volume or network of its own. Exit 0 only if all hold. Label: FINITE TEST."""
import hashlib
import json
import os
import pty
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.abspath(os.path.join(HERE, ".."))
FIX = os.path.join(PKG, "proof", "fixtures", "repo")
FAKE = "FAKE_upstream_key_DEMO_ONLY_not_real_0042"
RESULTS = []

POLICY = """version: 1
upstreams:
  - name: fs
    transport: stdio
    command: [node, /opt/mcpfs/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js, /ws]
    user: 1000
    env: {FS_TOKEN: "${FORGE_E2E_TOKEN}"}
tools:
  allow:
    - {tool: read_text_file, upstream: fs, path_args: {path: read}}
    - {tool: write_file, upstream: fs, path_args: {path: write}}
  deny: [move_file]
paths:
  hidden_paths: ["src/proprietary/**", "**/algo.ts", ".env*"]
  readonly_paths: ["tests/**", "spec/**"]
"""

SCRIPT = r"""
set -u
fail() { echo "BOX-FAIL: $1"; exit 3; }
cat src/app.ts >/dev/null || fail "public read"
grep -q uncommitted-change README.md || fail "uncommitted change not staged into the box"
[ ! -e src/proprietary/core.ts ] || fail "hidden file present"
[ ! -e .env ] || fail ".env present"
git log --all -p | grep -q FAKE_ && fail "secret in git history"
env | grep -q FAKE_upstream && fail "upstream key in env"
python3 -I /forge/agent/mcp_cli.py call read_text_file '{"path":"src/proprietary/core.ts"}' && fail "MCP hidden read"
python3 -I /forge/agent/mcp_cli.py call write_file '{"path":"src/new_by_mcp.ts","content":"export const viaMcp = 1\n"}' >/dev/null || fail "MCP write"
echo "// edited in the box" >> src/app.ts
rm src/lib/format.ts
echo "PAYMENTS_API_KEY=agent-planted" > .env
mkdir -p src/proprietary && echo "overwrite attempt" > src/proprietary/core.ts
(echo x >> tests/ui.test.ts) 2>/dev/null && fail "read-only test changed"
mkdir -p node_modules && echo junk > node_modules/x.js
echo "version: 2" > forge.yaml 2>/dev/null
echo "BOX-$((1+1))-DONE"
"""


def case(name, ok, detail=""):
    RESULTS.append(ok)
    print(("ok    " if ok else "FAIL  ") + name + ("" if ok else f"   {detail}"), flush=True)


def tree_hash(root):
    h = {}
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x != ".git"]
        for f in files:
            p = os.path.join(d, f)
            h[os.path.relpath(p, root)] = hashlib.sha256(open(p, "rb").read()).hexdigest() if not os.path.islink(p) \
                else "link:" + os.readlink(p)
    return h


def make_repo(tmp):
    repo = os.path.join(tmp, "repo")
    shutil.copytree(FIX, repo)
    open(os.path.join(repo, ".env"), "w").write(f"PAYMENTS_API_KEY={FAKE}\n")
    open(os.path.join(repo, ".gitignore"), "w").write("node_modules/\n")
    open(os.path.join(repo, "forge.yaml"), "w").write(POLICY)
    g = ["git", "-C", repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false"]
    subprocess.run(["git", "init", "-q", "-b", "main", repo], check=True)
    subprocess.run(g + ["add", "-A"], check=True)
    subprocess.run(g + ["commit", "-q", "-m", "fixture with a committed FAKE .env"], check=True)
    with open(os.path.join(repo, "README.md"), "a") as f:
        f.write("uncommitted-change\n")
    return repo


def up(repo, answer, extra=(), env_extra=None):
    """Run forge up under a pseudo-terminal; type `answer` at the y/N prompt."""
    env = dict(os.environ, FORGE_E2E_TOKEN=FAKE, **(env_extra or {}))
    argv = [sys.executable, os.path.join(PKG, "forge_airlock.py"), "up", "--repo", repo] + list(extra) + \
        ["--", "sh", "-c", SCRIPT]
    pid, fd = pty.fork()
    if pid == 0:
        os.execve(sys.executable, argv, env)
    buf, sent = b"", False
    while True:
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
        if not sent and b"[y/N]" in buf:
            os.write(fd, (answer + "\n").encode())
            sent = True
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status), buf.decode("utf-8", "replace")


def leftovers(repo):
    key = hashlib.sha256(os.path.realpath(repo).encode()).hexdigest()[:12]
    c = subprocess.run(["docker", "ps", "-aq", "--filter", f"name=forgeair-{key}"], capture_output=True, text=True).stdout
    n = subprocess.run(["docker", "network", "ls", "-q", "--filter", f"name=forgeair-{key}"], capture_output=True,
                       text=True).stdout
    v = [x for x in subprocess.run(["docker", "volume", "ls", "-q"], capture_output=True, text=True).stdout.split()
         if x.startswith(f"forgeair-{key}")]
    return len(c.split()) + len(n.split()) + len(v)


def main():
    tmp = tempfile.mkdtemp(prefix="forge-e2e-")
    repo = make_repo(tmp)
    key = hashlib.sha256(os.path.realpath(repo).encode()).hexdigest()[:12]
    try:
        before = tree_hash(repo)
        code, log = up(repo, "n")
        open(os.path.join(tmp, "run-n.log"), "w").write(log)
        case("up: the canary passed and the hostile script ran to the end (exit 0)",
             code == 0 and "BOX-2-DONE" in log and "[canary] PASS" in log, f"exit {code}: {log[-1500:]}")
        case("up: the review lists hidden and ignored changes as not applied",
             all(s in log for s in ("not applied: .env", "not applied: src/proprietary/core.ts",
                                    "not applied: node_modules/x.js")), log[-2500:])
        case("up: answer n -> the real repository is unchanged", tree_hash(repo) == before)
        code, log = up(repo, "y")
        open(os.path.join(tmp, "run-y.log"), "w").write(log)
        after = tree_hash(repo)
        changed = {k for k in set(before) | set(after) if before.get(k) != after.get(k)}
        case("up: answer y -> exactly the allowed files changed",
             changed == {"src/app.ts", "src/new_by_mcp.ts", "src/lib/format.ts"}, f"{sorted(changed)} {log[-1500:]}")
        case("up: the agent's edit and the MCP write arrived",
             "edited in the box" in open(os.path.join(repo, "src/app.ts")).read()
             and "viaMcp" in open(os.path.join(repo, "src/new_by_mcp.ts")).read())
        case("up: hidden files, read-only files and forge.yaml are untouched",
             all(before[k] == after.get(k) for k in (".env", "src/proprietary/core.ts", "tests/ui.test.ts", "forge.yaml")))
        code, log = up(repo, "n", extra=["--pass-env", "LEAK"], env_extra={"LEAK": FAKE})
        open(os.path.join(tmp, "run-breach.log"), "w").write(log)
        case("up: --pass-env prints the warning that the agent can read the value", "CAN READ this value" in log)
        case("up: an upstream secret passed to the agent -> canary BREACH, exit 10, command not run, nothing synced",
             code == 10 and "BREACH" in log and "BOX-2-DONE" not in log and tree_hash(repo) == after, f"exit {code} {log[-1500:]}")
        case("up: no container, network or run volume left behind", leftovers(repo) == 0, leftovers(repo))
    finally:
        subprocess.run(["docker", "volume", "rm", "-f", f"forge-airlock-logs-{key}"], capture_output=True)
        print(f"logs: {tmp}")
    failed = RESULTS.count(False)
    print(f"{len(RESULTS)} cases, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
