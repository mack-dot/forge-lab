#!/usr/bin/env python3
"""forge_airlock.py - run any command inside the Forge MCP airlock, with one command.

  forge init  [--repo R] [--tools tools.json] [--force] [--json]   draft forge.yaml (secrets by NAME only)
  forge tools [--repo R] [--policy P]                              list the real tools of each upstream
  forge check [--repo R] [--policy P]                              validate forge.yaml (exit 2 if invalid)
  forge up    [--repo R] [--policy P] [--pass-env NAME]... -- <command> [args...]
  forge reset-logs [--repo R]                                      delete this repository's gate logs
  forge wrapper [--repo R] [--force]                               write ./forge-airlock (init does it too)

`up` reads forge.yaml, generates the Docker configuration in a temporary folder, stages the
repository (HEAD history plus your uncommitted changes, minus ignored files), lets the airlock
build the filtered workspace (hidden paths absent, also from git history), starts the airlock
with the upstream MCP servers (they hold the credentials), runs the breach canary in the agent
container (fail closed), then runs <command> interactively there. On exit it shows the diff of
the files that may change and applies it to your repository only after you type y.

Host side: Python 3.8+ standard library and Docker with Compose v2. Label: NATIVE CHECK.
"""
import argparse
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "engine"))
import draft as D  # noqa: E402
import sync  # noqa: E402
from policy import Policy, PolicyError, env_refs  # noqa: E402

IMAGE = os.environ.get("FORGE_AIRLOCK_IMAGE", "forge-airlock:local")
CLAUDE_IMAGE = os.environ.get("FORGE_AIRLOCK_CLAUDE_IMAGE", "forge-airlock-claude:local")
PORT = 8700
EXIT_POLICY, EXIT_BREACH = 2, 10


def say(msg):
    print(f"forge-airlock: {msg}", file=sys.stderr, flush=True)


def run(cmd, **kw):
    kw.setdefault("check", False)
    return subprocess.run(cmd, **kw)


def out(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def git_root(path):
    r = out(["git", "-C", path, "rev-parse", "--show-toplevel"])
    if r.returncode != 0:
        raise SystemExit(f"forge-airlock: {path} is not inside a git repository (the airlock needs one)")
    return r.stdout.strip()


def repo_key(repo):
    return hashlib.sha256(os.path.realpath(repo).encode()).hexdigest()[:12]


def need_docker():
    if shutil.which("docker") is None or out(["docker", "compose", "version"]).returncode != 0:
        raise SystemExit("forge-airlock: needs Docker with Compose v2 (docker compose version)")


def build_images(claude):
    say("building the airlock image (cached after the first time) ...")
    if run(["docker", "build", "-q", "--target", "airlock", "-t", IMAGE, HERE], stdout=subprocess.DEVNULL).returncode:
        raise SystemExit("forge-airlock: image build failed")
    if claude:
        say("building the agent image with Claude Code (cached after the first time) ...")
        if run(["docker", "build", "-q", "--target", "agent-claude", "-t", CLAUDE_IMAGE, HERE],
               stdout=subprocess.DEVNULL).returncode:
            raise SystemExit("forge-airlock: agent image build failed")


def load_policy(policy_path):
    """Validate forge.yaml in the airlock image (PyYAML lives there) and return the host-side
    Policy with ${NAMES} kept (no secret is read on the host)."""
    r = out(["docker", "run", "--rm", "--network", "none", "-v", f"{os.path.abspath(policy_path)}:/p/forge.yaml:ro",
             IMAGE, "python3", "-I", "/forge/airlock/policy.py", "check", "/p/forge.yaml"])
    try:
        res = json.loads(r.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise SystemExit(f"forge-airlock: policy check did not run: {r.stderr[-300:]}")
    if not res.get("ok"):
        say(f"forge.yaml is invalid: {res.get('error')}")
        raise SystemExit(EXIT_POLICY)
    return Policy(res["doc"], resolve=False), res["doc"]


# ---------------------------------------------------------------- staging
def stage_repo(repo, dest):
    """A private copy of the repository for the airlock: the HEAD history (first parent) plus
    one commit with your uncommitted and untracked (not ignored) files. Returns dest."""
    head = out(["git", "-C", repo, "rev-parse", "--verify", "-q", "HEAD"]).stdout.strip()
    if not head:
        raise SystemExit("forge-airlock: the repository has no commit yet; commit once first")
    if run(["git", "clone", "-q", "--no-local", "--no-checkout", repo, dest]).returncode:
        raise SystemExit("forge-airlock: staging clone failed")
    g = ["git", "-C", dest, "-c", "user.name=forge-airlock", "-c", "user.email=forge-airlock@invalid",
         "-c", "commit.gpgsign=false"]
    run(g + ["checkout", "-q", "--detach", head], check=True)
    files = set(x for x in out(["git", "-C", repo, "ls-files", "-co", "--exclude-standard", "-z"]).stdout.split("\0") if x)
    staged = set(x for x in out(["git", "-C", dest, "ls-files", "-z"]).stdout.split("\0") if x)
    for rel in staged - files:
        p = os.path.join(dest, rel)
        if os.path.lexists(p):
            os.remove(p)
    for rel in files:
        src, dst = os.path.join(repo, rel), os.path.join(dest, rel)
        if not os.path.lexists(src) or (os.path.isdir(src) and not os.path.islink(src)):
            continue  # deleted in the working tree, or a submodule
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        if os.path.lexists(dst):
            os.remove(dst)
        if os.path.islink(src):
            os.symlink(os.readlink(src), dst)
        else:
            shutil.copy2(src, dst)
    run(g + ["add", "-A"], check=True)
    if run(g + ["diff", "--cached", "--quiet"]).returncode:
        run(g + ["commit", "-q", "--no-verify", "-m", "forge-airlock: snapshot of uncommitted changes"], check=True)
    os.chmod(dest, 0o755)
    return dest


# ---------------------------------------------------------------- compose generation
def compose_doc(pol, policy_path, stage, run_dir, logs_volume, agent_image, pass_env, readonly_dirs,
                own_agent_image=False):
    agent_env = {"FORGE_AIRLOCK": f"http://airlock:{PORT}", "HOME": "/tmp"}
    if pol.egress_allow:
        agent_env.update(HTTPS_PROXY="http://egress:3128", HTTP_PROXY="http://egress:3128",
                         NO_PROXY="airlock,localhost,127.0.0.1")
    agent_env_list = [f"{k}={v}" for k, v in agent_env.items()] + list(pass_env)  # NAME only: value from your shell
    ro_mounts = [{"type": "volume", "source": "ws", "target": f"{pol.agent_root.rstrip('/')}/{d}", "read_only": True,
                  "volume": {"subpath": d}} for d in readonly_dirs]
    harden = {"read_only": True, "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"]}
    svc = {
        "airlock": {
            "image": IMAGE, "command": ["python3", "-I", "/forge/airlock/gateway.py"],
            "environment": ["FORGE_SOURCE=/source", "FORGE_POLICY=/forge/forge.yaml"] + list(pol.env_names),
            "volumes": [f"{os.path.abspath(policy_path)}:/forge/forge.yaml:ro", f"{stage}:/source:ro",
                        "logs:/data", "state:/state", "ws:/ws"],
            "networks": ["agentnet", "outnet"],
            "healthcheck": {"test": ["CMD", "python3", "-c", "import urllib.request; urllib.request.urlopen("
                                     f"'http://127.0.0.1:{PORT}/healthz', timeout=1)"],
                            "interval": "1s", "retries": 600},
        },
        "agent": dict(harden, **{
            "image": agent_image, "user": "1000:1000", "tmpfs": ["/tmp:exec,mode=1777"],
            "environment": agent_env_list, "working_dir": pol.agent_root,
            "volumes": [f"ws:{pol.agent_root}"] + ro_mounts + [f"{run_dir}/agent:/forge-run:ro"]
            + ([f"{HERE}/agent:/forge/agent:ro"] if own_agent_image else []),
            "networks": ["agentnet"], "stdin_open": True, "tty": True,
            "depends_on": {"airlock": {"condition": "service_healthy"}},
        }),
        "exporter": {
            "image": IMAGE, "profiles": ["export"], "network_mode": "none",
            "environment": [f"FORGE_OUT_UID={os.getuid()}", f"FORGE_OUT_GID={os.getgid()}"],
            "volumes": ["ws:/ws:ro", "state:/state:ro", f"{os.path.abspath(policy_path)}:/p/forge.yaml:ro",
                        f"{run_dir}/export:/out"],
            "command": ["python3", "-I", "/forge/airlock/export_changes.py", "/p/forge.yaml", "/ws",
                        "/state/filtered.git", "/out"],
        },
    }
    if pol.egress_allow:
        svc["egress"] = dict(harden, **{
            "image": IMAGE, "user": "1000:1000", "networks": ["agentnet", "outnet"],
            "command": ["python3", "-I", "/forge/airlock/egress_proxy.py", "3128"] + list(pol.egress_allow)})
        svc["agent"]["depends_on"]["egress"] = {"condition": "service_started"}
    return {"services": svc,
            "networks": {"agentnet": {"internal": True}, "outnet": {}},
            "volumes": {"ws": {}, "state": {}, "logs": {"external": True, "name": logs_volume}}}


def readonly_dirs(pol, stage=None):
    """readonly_paths of the form <dir>/** become read-only mounts in the agent (when the
    directory exists and is not hidden); other forms are enforced by file modes and MCP checks."""
    import re
    dirs = []
    for pat in pol.readonly.patterns:
        m = re.fullmatch(r"([A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*)/\*\*", pat)
        if m and ".." not in m.group(1).split("/") and not pol.is_hidden(m.group(1)):
            if stage is None or (os.path.isdir(os.path.join(stage, m.group(1)))
                                 and not os.path.islink(os.path.join(stage, m.group(1)))):
                dirs.append(m.group(1))
    return dirs


def claude_args(cmd):
    """`claude` in the box talks to the airlock only: its MCP config is the airlock and nothing
    else (--strict-mcp-config ignores a .mcp.json in the workspace)."""
    if os.path.basename(cmd[0]) != "claude" or "--mcp-config" in cmd:
        return cmd
    return cmd[:1] + ["--mcp-config", "/forge-run/mcp.json", "--strict-mcp-config"] + cmd[1:]


# ---------------------------------------------------------------- sync back
def ignored_fn(repo):
    def ignored(rel):
        r = out(["git", "-C", repo, "check-ignore", "-q", "--", rel])
        return r.returncode == 0
    return ignored


def ask_yes(prompt):
    if not sys.stdin.isatty():
        return None
    try:
        return input(prompt).strip().lower() in ("y", "yes")
    except EOFError:
        return False


def sync_back(pol, run_dir, stage, repo):
    path = os.path.join(run_dir, "export", "changes.json")
    if not os.path.exists(path):
        say("no change list was exported; your repository is unchanged")
        return 1
    changes = json.load(open(path))["changes"]
    apply, rejected = sync.plan(pol, changes, os.path.join(run_dir, "export"), stage, repo, ignored_fn(repo))
    for rel, why in rejected:
        print(f"  not applied: {rel}: {why}")
    if not apply:
        say("no change that may be applied; your repository is unchanged")
        return 0
    print(sync.render(apply))
    print(f"\n{len(apply)} file(s) can be applied to {repo}" + (f"; {len(rejected)} not applied (listed above)"
                                                              if rejected else ""))
    yes = ask_yes("Apply these changes to your repository? [y/N] ")
    if yes is None:
        say("stdin is not a terminal: nothing applied (an explicit y at a terminal is required)")
        return 0
    if not yes:
        say("nothing applied; your repository is unchanged")
        return 0
    done = sync.apply_changes(apply, repo)
    say(f"applied {len(done)} file(s); review them with git diff")
    return 0


# ---------------------------------------------------------------- commands
def cmd_up(a):
    if not a.command:
        raise SystemExit("forge-airlock: give the command to run after --, for example: forge up -- claude")
    need_docker()
    repo = git_root(a.repo)
    policy_path = a.policy or os.path.join(repo, "forge.yaml")
    if not os.path.exists(policy_path):
        raise SystemExit(f"forge-airlock: no {policy_path}; run `forge init` (or /forge-airlock:airlock) first")
    wants_claude = os.path.basename(a.command[0]) == "claude" and not a.agent_image
    build_images(wants_claude)
    pol, _doc = load_policy(policy_path)
    missing = [n for n in pol.env_names if n not in os.environ]
    if missing:
        say(f"forge.yaml names these secrets, but your shell does not set them: {', '.join(missing)}")
        raise SystemExit(EXIT_POLICY)
    for n in a.pass_env:
        if n not in os.environ:
            raise SystemExit(f"forge-airlock: --pass-env {n}: not set in your shell")
        if n in pol.env_names:
            raise SystemExit(f"forge-airlock: --pass-env {n}: this is an upstream secret of forge.yaml; it stays "
                             "with the airlock (passing it to the agent would defeat the airlock)")
        say(f"WARNING: --pass-env {n}: the program in the box (the agent) CAN READ this value and can send it to "
            f"any host it can reach. Use a separate, spend-capped key for it.")
    agent_image = a.agent_image or (CLAUDE_IMAGE if wants_claude else IMAGE)
    run_dir = tempfile.mkdtemp(prefix="forge-airlock-")
    project = f"forgeair-{repo_key(repo)}-{os.path.basename(run_dir)[-8:].lower()}"
    logs_volume = f"forge-airlock-logs-{repo_key(repo)}"
    dc = ["docker", "compose", "-p", project, "-f", os.path.join(run_dir, "compose.json")]
    code = 1
    old_int = signal.getsignal(signal.SIGINT)
    try:
        stage = stage_repo(repo, os.path.join(run_dir, "source"))
        os.makedirs(os.path.join(run_dir, "agent"))
        os.makedirs(os.path.join(run_dir, "export"))
        with open(os.path.join(run_dir, "agent", "mcp.json"), "w") as f:
            json.dump({"mcpServers": {"forge-airlock": {"type": "http", "url": f"http://airlock:{PORT}/mcp"}}}, f)
        doc = compose_doc(pol, policy_path, stage, run_dir, logs_volume, agent_image, a.pass_env,
                          readonly_dirs(pol, stage), own_agent_image=bool(a.agent_image))
        with open(os.path.join(run_dir, "compose.json"), "w") as f:
            json.dump(doc, f, indent=1)
        run(["docker", "volume", "create", logs_volume], stdout=subprocess.DEVNULL)
        say("starting the airlock (filtered workspace, upstream servers) ...")
        services = ["airlock"] + (["egress"] if pol.egress_allow else [])
        if run(dc + ["up", "-d", "--wait"] + services, stdout=subprocess.DEVNULL,
               stderr=subprocess.DEVNULL).returncode:
            run(dc + ["logs", "--no-log-prefix", "--tail", "30", "airlock"])
            say("the airlock did not start (fail closed); see the log above")
            return EXIT_POLICY
        cmd = claude_args(a.command)
        say("running the breach canary in the agent container, then: " + " ".join(cmd))
        tty = [] if sys.stdin.isatty() and sys.stdout.isatty() else ["-T"]
        signal.signal(signal.SIGINT, signal.SIG_IGN)  # Ctrl-C belongs to the program in the box
        rc = run(dc + ["run", "--rm"] + tty + ["agent", "sh", "-c",
                 'python3 -I /forge/agent/canary.py >/tmp/forge-canary.log 2>&1; c=$?; tail -n 3 /tmp/forge-canary.log; '
                 '[ "$c" = 0 ] || exit 86; exec "$@"', "forge-box"] + cmd).returncode
        signal.signal(signal.SIGINT, old_int)
        state = out(dc + ["exec", "-T", "airlock", "python3", "-c",
                          "import json,urllib.request; print(json.load(urllib.request.urlopen("
                          f"'http://127.0.0.1:{PORT}/healthz', timeout=5))['canary'])"]).stdout.strip()
        if state != "PASSED":
            say(f"breach canary state {state or 'unknown'}: fail closed; the command did not run or was refused; "
                "nothing is synced back")
            return EXIT_BREACH
        say(f"the command exited with {rc}; collecting the changes ...")
        if run(dc + ["--profile", "export", "run", "--rm", "-T", "exporter"], stdout=subprocess.DEVNULL).returncode:
            say("export failed; your repository is unchanged")
            return 1
        sync_back(pol, run_dir, stage, repo)
        code = rc
        return code
    finally:
        signal.signal(signal.SIGINT, old_int)
        run(dc + ["--profile", "export", "down", "-v", "--remove-orphans"], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        if a.keep:
            say(f"kept {run_dir}")
        else:
            shutil.rmtree(run_dir, ignore_errors=True)


WRAPPER = """#!/bin/sh
# forge-airlock - runs the Forge airlock installed at the path below (written by `forge init`).
# Commit it or add it to .gitignore: it holds only this path, no secret.
F=%s
if [ ! -f "$F" ]; then
  echo "forge-airlock: $F is gone (the plugin moved or was updated)." >&2
  echo "Run the new forge_airlock.py with: python3 <path>/forge_airlock.py wrapper --force" >&2
  exit 127
fi
exec python3 "$F" "$@"
"""


def shell_quote(s):
    return "'" + s.replace("'", "'\\''") + "'"


def write_wrapper(repo, force=False):
    """./forge-airlock in the project root, calling THIS forge_airlock.py by absolute path.
    An existing different file is never overwritten without a yes (or --force)."""
    path = os.path.join(repo, "forge-airlock")
    text = WRAPPER % shell_quote(os.path.realpath(os.path.abspath(__file__)))
    if os.path.exists(path) and open(path).read() != text and not force:
        yes = ask_yes(f"{path} exists and differs. Overwrite it? [y/N] ")
        if not yes:
            say(f"{path} exists; not overwritten (rerun with --force to replace it)")
            return False
    with open(path, "w") as f:
        f.write(text)
    os.chmod(path, 0o755)
    say(f"wrote {path}: run ./forge-airlock up -- claude")
    return True


def cmd_wrapper(a):
    return 0 if write_wrapper(git_root(a.repo), a.force) else 1


def cmd_init(a):
    repo = git_root(a.repo)
    target = os.path.join(repo, "forge.yaml")
    tools = json.load(open(a.tools))["tools"] if a.tools else None
    doc, notes, questions = D.draft(repo, tools, claude=not a.no_claude)
    text = D.HEADER + D.to_yaml(doc)
    if a.json:
        print(json.dumps({"forge_yaml": text, "notes": notes, "questions": questions, "target": target}, indent=1))
        return 0
    if os.path.exists(target) and not a.force:
        say(f"{target} exists; not overwritten (use --force)")
        print(text)
        return 1
    with open(target, "w") as f:
        f.write(text)
    for n in notes:
        say(n)
    say(f"wrote {target}; review it")
    write_wrapper(repo, False)
    return 0


def cmd_tools(a):
    need_docker()
    repo = git_root(a.repo)
    policy_path = a.policy or os.path.join(repo, "forge.yaml")
    tmp = None
    if not os.path.exists(policy_path):  # draft upstreams from .mcp.json only
        doc, notes, _ = D.draft(repo, None, claude=False)
        tmp = tempfile.mkdtemp(prefix="forge-airlock-tools-")
        policy_path = os.path.join(tmp, "forge.yaml")
        open(policy_path, "w").write(D.to_yaml({"version": 1, "upstreams": doc["upstreams"], "tools": {}}))
    build_images(False)
    names = env_refs(json.loads(out(["docker", "run", "--rm", "--network", "none", "-v",
                                     f"{os.path.abspath(policy_path)}:/p/forge.yaml:ro", IMAGE, "python3", "-I",
                                     "/forge/airlock/policy.py", "check", "/p/forge.yaml"]).stdout or "{}").get("doc") or {})
    missing = [n for n in names if n not in os.environ]
    if missing:
        say(f"set these in your shell first: {', '.join(missing)}")
        return EXIT_POLICY
    envs = sum((["-e", n] for n in names), [])
    r = run(["docker", "run", "--rm"] + envs + ["-v", f"{os.path.abspath(policy_path)}:/p/forge.yaml:ro", IMAGE,
             "python3", "-I", "/forge/airlock/list_tools.py", "/p/forge.yaml"])
    if tmp:
        shutil.rmtree(tmp, ignore_errors=True)
    return r.returncode


def cmd_check(a):
    need_docker()
    repo = git_root(a.repo)
    build_images(False)
    pol, _ = load_policy(a.policy or os.path.join(repo, "forge.yaml"))
    say(f"forge.yaml is valid: {len(pol.upstreams)} upstreams, {len(pol.tools)} tools listed, {len(pol.deny)} denied, "
        f"{len(pol.logs)} gate logs; secrets named: {', '.join(pol.env_names) or 'none'}")
    return 0


def cmd_reset_logs(a):
    repo = git_root(a.repo)
    v = f"forge-airlock-logs-{repo_key(repo)}"
    r = run(["docker", "volume", "rm", v], stdout=subprocess.DEVNULL)
    say(f"removed gate logs volume {v}" if r.returncode == 0 else f"no volume {v} removed")
    return r.returncode


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    command = []
    if "--" in argv:
        i = argv.index("--")
        argv, command = argv[:i], argv[i + 1:]
    p = argparse.ArgumentParser(prog="forge", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="sub", required=True)
    for name in ("init", "tools", "check", "up", "reset-logs", "wrapper"):
        s = sub.add_parser(name)
        s.add_argument("--repo", default=os.getcwd())
        if name in ("tools", "check", "up"):
            s.add_argument("--policy")
        if name == "wrapper":
            s.add_argument("--force", action="store_true")
        if name == "init":
            s.add_argument("--tools", help="JSON from `forge tools` (tool names to classify)")
            s.add_argument("--force", action="store_true")
            s.add_argument("--json", action="store_true")
            s.add_argument("--no-claude", action="store_true", help="no egress to the model API in the draft")
        if name == "up":
            s.add_argument("--pass-env", action="append", default=[], metavar="NAME",
                           help="pass this variable from your shell to the agent (it CAN read it)")
            s.add_argument("--agent-image", help="your own agent image (needs python3 for the canary)")
            s.add_argument("--keep", action="store_true", help="keep the generated folder (debugging)")
    a = p.parse_args(argv)
    a.command = command
    return {"init": cmd_init, "tools": cmd_tools, "check": cmd_check, "up": cmd_up,
            "reset-logs": cmd_reset_logs, "wrapper": cmd_wrapper}[a.sub](a)


if __name__ == "__main__":
    sys.exit(main())
