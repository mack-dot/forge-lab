# scenario.py - the "agent" for the validation runs. It acts as a hostile agent would
# (tries every route it can) and asserts the expected result of each attempt.
# FORGE_DOMAIN selects the scenario; FORGE_PHASE selects the step of a multi-phase run.
# Exit 0 only when every expectation holds. Label: FINITE TEST.
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mcpc  # noqa: E402

W = "/workspace"
FAILS, PASSES = [], [0]
GENV = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp"}
GIT = ["git", "-c", "safe.directory=*", "-C", W]
MARK = "FORGE-CANARY-MARKER"


def expect(label, cond, detail=""):
    if cond:
        PASSES[0] += 1
        print(f"  ok   {label}", flush=True)
    else:
        FAILS.append(label)
        print(f"  FAIL {label} {detail}", flush=True)


def readable(path):
    try:
        with open(path, "rb") as f:
            f.read(1)
        return True
    except OSError:
        return False


def sh_ok(*cmd):
    return subprocess.run(list(cmd), capture_output=True, env=GENV).returncode == 0


def refused(code, *want):
    return code in want


# ---------------------------------------------------------------- domain 1
def codebase():
    tools = mcpc.tool_names()
    want = {"read_text_file", "read_file", "read_multiple_files", "list_directory", "directory_tree",
            "search_files", "get_file_info", "write_file", "edit_file", "create_directory", "search", "git_log",
            "git_show"}
    expect("tools/list = exactly the 13 listed tools (real fs server + mock git)", tools == want, tools ^ want)
    expect("tools/list hides denied move_file/delete_path and unlisted copy_file/append_file/push_branch",
           not ({"move_file", "delete_path", "copy_file", "append_file", "push_branch",
                 "list_allowed_directories"} & tools), tools)
    # public read
    expect("shell reads public src/ui.ts", "renderCart" in open(f"{W}/src/ui.ts").read())
    ok, code, res = mcpc.call("read_text_file", path="src/ui.ts")
    expect("MCP read_text_file src/ui.ts passes (real fs server)", ok and "renderCart" in mcpc.text_of(res), code)
    ok, code, res = mcpc.call("list_directory", path="src")
    expect("MCP list_directory src shows ui.ts and no proprietary/",
           ok and "ui.ts" in mcpc.text_of(res) and "proprietary" not in mcpc.text_of(res), mcpc.text_of(res))
    ok, code, res = mcpc.call("directory_tree", path=".")
    expect("MCP directory_tree has no hidden names",
           ok and "proprietary" not in mcpc.text_of(res) and "algo.ts" not in mcpc.text_of(res), code)
    ok, code, res = mcpc.call("search_files", path=".", pattern="**/*algo*")
    expect("MCP search_files for **/*algo* finds nothing", ok and "algo" not in mcpc.text_of(res).replace(
        "*algo*", ""), mcpc.text_of(res)[:200])
    ok, code, _ = mcpc.call("read_multiple_files", paths=["src/ui.ts", "src/proprietary/core.ts"])
    expect("MCP read_multiple_files with one hidden element refused", refused(code, "FORGE_PATH_HIDDEN"), code)
    # hidden: shell
    for p in [f"{W}/src/proprietary/core.ts", f"{W}/src/../src/proprietary/core.ts",
              f"{W}/../workspace/src/proprietary/core.ts", f"{W}/src/lib/algo.ts", f"{W}/.env",
              f"{W}/docs/core-link.ts"]:
        expect(f"shell cannot read {p}", not readable(p))
    os.symlink(f"{W}/src/proprietary/core.ts", "/tmp/sneak.ts")
    expect("shell cannot read hidden file through a symlink", not readable("/tmp/sneak.ts"))
    expect("public symlink docs/readme-link.md kept", readable(f"{W}/docs/readme-link.md"))
    commits = subprocess.run(GIT + ["rev-list", "--all"], capture_output=True, text=True, env=GENV).stdout.split()
    expect("filtered history has 3 commits", len(commits) == 3, commits)
    for c in commits:
        for h in ("src/proprietary/core.ts", ".env", "src/lib/algo.ts"):
            expect(f"git show {c[:8]}:{h} fails", not sh_ok(*GIT, "show", f"{c}:{h}"))
    logp = subprocess.run(GIT + ["log", "--all", "-p"], capture_output=True, text=True, env=GENV).stdout
    expect("git log --all -p has no hidden marker and no fake .env key",
           MARK not in logp and "FAKE_sk_demo_env_file" not in logp)
    allobj = subprocess.run(GIT + ["cat-file", "--batch-all-objects", "--batch"], capture_output=True,
                            env=GENV).stdout
    expect("no git object holds a hidden marker", MARK.encode() not in allobj)
    msgs = subprocess.run(GIT + ["log", "--format=%s"], capture_output=True, text=True, env=GENV).stdout
    expect("commit messages replaced (they named the hidden code)", "pricing" not in msgs, msgs)
    # hidden: MCP
    for p in ["src/proprietary/core.ts", "src/../src/proprietary/core.ts", "/workspace/src/proprietary/core.ts",
              "./src/lib/algo.ts", ".env", "docs/../.env.local"]:
        ok, code, _ = mcpc.call("read_text_file", path=p)
        expect(f"MCP read_text_file {p!r} refused FORGE_PATH_HIDDEN", refused(code, "FORGE_PATH_HIDDEN"), code)
    os.symlink("proprietary/core.ts", f"{W}/src/sneaky.ts")
    ok, code, _ = mcpc.call("read_text_file", path="src/sneaky.ts")
    expect("MCP read through agent-made symlink to hidden refused", refused(code, "FORGE_PATH_HIDDEN"), code)
    os.symlink("/state/source/src/proprietary/core.ts", f"{W}/src/sneaky2.ts")
    ok, code, _ = mcpc.call("read_text_file", path="src/sneaky2.ts")
    expect("MCP read through symlink to airlock source refused", refused(code, "FORGE_PATH_OUTSIDE"), code)
    os.symlink("/forge/forge.yaml", f"{W}/src/sneaky3.ts")
    ok, code, _ = mcpc.call("read_text_file", path="src/sneaky3.ts")
    expect("MCP read through symlink to the airlock policy (holds keys) refused",
           refused(code, "FORGE_PATH_OUTSIDE"), code)
    for p in ("../../state/source/src/proprietary/core.ts", "/etc/passwd"):
        ok, code, _ = mcpc.call("get_file_info", path=p)
        expect(f"MCP get_file_info {p!r} refused FORGE_PATH_OUTSIDE", refused(code, "FORGE_PATH_OUTSIDE"), code)
    for spec in ("HEAD~2:src/proprietary/core.ts", "HEAD~2:.env", "HEAD:src/lib/algo.ts"):
        ok, code, _ = mcpc.call("git_show", spec=spec)
        expect(f"MCP git_show {spec} refused FORGE_PATH_HIDDEN", refused(code, "FORGE_PATH_HIDDEN"), code)
    ok, code, res = mcpc.call("git_show", spec="HEAD:src/ui.ts")
    expect("MCP git_show HEAD:src/ui.ts passes", ok and "renderCart" in mcpc.text_of(res), code)
    ok, code, res = mcpc.call("search", query=MARK, path=".")
    expect("MCP search for the hidden marker finds nothing", ok and MARK not in mcpc.text_of(res), code)
    ok, code, res = mcpc.call("search", query="SECRET_MARGIN")
    expect("MCP search for a hidden identifier finds nothing", ok and not mcpc.text_of(res).strip(), code)
    # read-only: shell
    for label, fn in [
        ("append tests/ui.test.ts", lambda: open(f"{W}/tests/ui.test.ts", "a").close()),
        ("create tests/evil.test.ts", lambda: open(f"{W}/tests/evil.test.ts", "w").close()),
        ("unlink tests/ui.test.ts", lambda: os.remove(f"{W}/tests/ui.test.ts")),
        ("rename tests/", lambda: os.rename(f"{W}/tests", f"{W}/tests_old")),
        ("chmod tests/ui.test.ts", lambda: os.chmod(f"{W}/tests/ui.test.ts", 0o666)),
        ("write spec/api.md", lambda: open(f"{W}/spec/api.md", "w").close()),
        ("create .forge/x", lambda: open(f"{W}/.forge/x", "w").close()),
    ]:
        try:
            fn()
            expect(f"shell cannot {label}", False)
        except OSError:
            expect(f"shell cannot {label}", True)
    expect("tests/ui.test.ts unchanged", "renderCart" in open(f"{W}/tests/ui.test.ts").read())
    # read-only: MCP
    for p in ("tests/ui.test.ts", "tests/new.test.ts", "spec/api.md", ".forge/notes.md", "tests/../tests/x.ts"):
        ok, code, _ = mcpc.call("write_file", path=p, content="pwned")
        expect(f"MCP write_file {p} refused FORGE_PATH_READONLY", refused(code, "FORGE_PATH_READONLY"), code)
    ok, code, _ = mcpc.call("write_file", path="src/proprietary/core.ts", content="x")
    expect("MCP write to hidden path refused", refused(code, "FORGE_PATH_HIDDEN"), code)
    ok, code, _ = mcpc.call("edit_file", path="tests/ui.test.ts", edits=[{"oldText": "tea", "newText": "x"}])
    expect("MCP edit_file tests/ui.test.ts refused FORGE_PATH_READONLY", refused(code, "FORGE_PATH_READONLY"), code)
    ok, code, _ = mcpc.call("create_directory", path="tests/sub")
    expect("MCP create_directory tests/sub refused FORGE_PATH_READONLY", refused(code, "FORGE_PATH_READONLY"), code)
    ok, code, _ = mcpc.call("write_file", path="src/cart_view.ts", content="export const v = 1;\n")
    expect("MCP write_file src/cart_view.ts passes", ok, code)
    expect("agent sees the file written through MCP", readable(f"{W}/src/cart_view.ts"))
    with open(f"{W}/src/ui_extra.ts", "w") as f:
        f.write("export const extra = 2;\n")
    expect("agent can write public src/ by shell", readable(f"{W}/src/ui_extra.ts"))
    # blocked tools
    for t in ("move_file", "delete_path", "copy_file", "append_file", "push_branch", "rm_rf_everything"):
        ok, code, _ = mcpc.call(t, path="src/ui.ts")
        expect(f"tool {t} refused FORGE_TOOL_BLOCKED", refused(code, "FORGE_TOOL_BLOCKED"), code)
    ok, code, res = mcpc.call("git_log")
    expect("MCP git_log passes", ok and len(mcpc.text_of(res).splitlines()) == 3, code)


# ---------------------------------------------------------------- domain 2
def gate_verdict(payload):
    return (payload.get("data") or {}).get("verdict") if isinstance(payload, dict) else None


def quota(phase):
    tools = mcpc.tool_names()
    if phase == "1":
        expect("tools/list = get_status, deploy, run_query, slow_job",
               tools == {"get_status", "deploy", "run_query", "slow_job"}, tools)
        ok, code, _ = mcpc.call("get_status", service="web")
        expect("read tool get_status passes", ok, code)
        for t in ("rotate_keys", "drop_database", "charge"):
            ok, code, _ = mcpc.call(t, name="prod")
            expect(f"{t} refused FORGE_TOOL_BLOCKED", refused(code, "FORGE_TOOL_BLOCKED"), code)
        for args, why in [({"env": "production", "branch": "feat/a"}, "env=production"),
                          ({"env": "staging", "branch": "main"}, "branch=main"),
                          ({"env": "staging", "branch": "feat;rm -rf"}, "branch regex"),
                          ({"branch": "feat/a"}, "env missing")]:
            ok, code, _ = mcpc.call("deploy", **args)
            expect(f"deploy refused by arg rule ({why})", refused(code, "FORGE_ARG_REFUSED"), code)
        for i in range(3):
            ok, code, res = mcpc.call("deploy", env="staging", branch=f"feat/{i}")
            expect(f"deploy {i + 1}/3 passes", ok, code)
        ok, code, p = mcpc.call("deploy", env="staging", branch="feat/4")
        expect("deploy 4 refused REJECT_OVER_CAP", code == "FORGE_GATE_REFUSED" and gate_verdict(p) ==
               "REJECT_OVER_CAP", (code, gate_verdict(p)))
        ok, code, p = mcpc.call("run_query", query="SELECT * FROM t", rows=500)
        expect("run_query rows=500 refused per_call_max", code == "FORGE_GATE_REFUSED" and
               gate_verdict(p) == "PER_CALL_MAX", (code, p))
        ok, code, _ = mcpc.call("run_query", query="DELETE FROM users", rows=10)
        expect("run_query DELETE refused by checker hook", refused(code, "FORGE_CHECKER_REFUSED"), code)
        ok, code, _ = mcpc.call("run_query", query="SELECT 1", rows="10")
        expect("run_query rows='10' (string) refused", refused(code, "FORGE_ARG_REFUSED"), code)
        for i in range(2):
            ok, code, _ = mcpc.call("run_query", query="SELECT * FROM t", rows=400)
            expect(f"run_query rows=400 #{i + 1} passes", ok, code)
        ok, code, p = mcpc.call("run_query", query="SELECT * FROM t", rows=300)
        expect("run_query rows=300 refused REJECT_OVER_CAP (800+300>1000)", gate_verdict(p) == "REJECT_OVER_CAP",
               (code, p))
        ok, code, _ = mcpc.call("run_query", query="SELECT * FROM t", rows=200)
        expect("run_query rows=200 passes (gross=1000=cap)", ok, code)
        for i in range(2):
            t = time.time()
            ok, code, _ = mcpc.call("slow_job", seconds=4)
            expect(f"slow_job #{i + 1} times out -> FORGE_UPSTREAM_FAILED (step stays spent)",
                   refused(code, "FORGE_UPSTREAM_FAILED") and time.time() - t < 3.9, code)
        ok, code, p = mcpc.call("slow_job", seconds=0)
        expect("slow_job #3 refused REJECT_OVER_CAP (timeouts counted as spent)",
               gate_verdict(p) == "REJECT_OVER_CAP", (code, p))
    else:  # after an airlock container restart
        ok, code, p = mcpc.call("deploy", env="staging", branch="feat/after-restart")
        expect("after restart: deploy still refused REJECT_OVER_CAP", gate_verdict(p) == "REJECT_OVER_CAP",
               (code, p))
        ok, code, p = mcpc.call("run_query", query="SELECT 1", rows=1)
        expect("after restart: run_query rows=1 refused REJECT_OVER_CAP", gate_verdict(p) == "REJECT_OVER_CAP",
               (code, p))
        ok, code, p = mcpc.call("slow_job", seconds=0)
        expect("after restart: slow_job refused REJECT_OVER_CAP", gate_verdict(p) == "REJECT_OVER_CAP", (code, p))
        ok, code, _ = mcpc.call("get_status", service="web")
        expect("after restart: read tool still passes", ok, code)


# ---------------------------------------------------------------- domain 3
def burst(n, fn):
    with ThreadPoolExecutor(max_workers=n) as ex:
        return list(ex.map(fn, range(n)))


def concurrency():
    for i in range(5):
        ok, code, _ = mcpc.call("charge", amount=50, invoice_id=f"inv-seq-{i}")
        expect(f"charge inv-seq-{i} (50) passes", ok, code)
    rs = burst(3, lambda i: mcpc.call("charge", amount=50, invoice_id=f"inv-seq-{i}"))
    expect("3 concurrent replays of used ids all refused REJECT_DUPLICATE_ID",
           all(gate_verdict(p) == "REJECT_DUPLICATE_ID" for _, _, p in rs), [gate_verdict(p) for _, _, p in rs])
    rs = burst(10, lambda i: mcpc.call("charge", amount=10, invoice_id="inv-dup"))
    oks = sum(1 for ok, _, _ in rs if ok)
    dups = sum(1 for _, _, p in rs if gate_verdict(p) == "REJECT_DUPLICATE_ID")
    expect("10 concurrent calls with one new id: exactly 1 passes, 9 REJECT_DUPLICATE_ID", oks == 1 and dups == 9,
           (oks, dups))
    t = time.time()
    rs = burst(20, lambda i: mcpc.call("charge", amount=100, invoice_id=f"inv-burst-{i}"))
    dt = time.time() - t
    oks = sum(1 for ok, _, _ in rs if ok)
    over = sum(1 for _, _, p in rs if gate_verdict(p) == "REJECT_OVER_CAP")
    expect(f"20 concurrent charges of 100 with 740 left: exactly 7 pass, 13 REJECT_OVER_CAP ({dt:.1f}s)",
           oks == 7 and over == 13, (oks, over))
    ok, code, _ = mcpc.call("charge", amount=40, invoice_id="inv-last")
    expect("charge 40 passes (gross=1000=cap)", ok, code)
    ok, code, p = mcpc.call("charge", amount=1, invoice_id="inv-over")
    expect("charge 1 refused REJECT_OVER_CAP", gate_verdict(p) == "REJECT_OVER_CAP", p)
    ok, code, p = mcpc.call("charge", amount=101, invoice_id="inv-big")
    expect("charge 101 refused per_call_max", gate_verdict(p) == "PER_CALL_MAX", p)
    ok, code, p = mcpc.call("charge", amount=-5, invoice_id="inv-neg")
    expect("charge -5 refused (not an integer in [0, 2^63-1])", refused(code, "FORGE_ARG_REFUSED"), code)
    rs = burst(20, lambda i: mcpc.call("deploy", env="staging"))
    oks = sum(1 for ok, _, _ in rs if ok)
    over = sum(1 for _, _, p in rs if gate_verdict(p) == "REJECT_OVER_CAP")
    expect("20 concurrent deploys on a count cap of 5: exactly 5 pass, 15 REJECT_OVER_CAP", oks == 5 and over == 15,
           (oks, over))


# ---------------------------------------------------------------- domain 4
def visible():
    """visible_paths ["src/ui/**", "README.md"]; hidden_paths also hides src/ui/**/secret*."""
    VM = "FIXTURE-VISIBLE-DOMAIN-HIDDEN"
    expect("shell reads visible src/ui/button.ts", readable(f"{W}/src/ui/button.ts"))
    expect("shell reads visible README.md", readable(f"{W}/README.md"))
    for p in ("src/routes/api.ts", "src/routes/auth.ts", "tests/ui.test.ts", "src/ui.ts", "src/app.ts",
              "src/proprietary/core.ts", "src/ui/secret_theme.ts", "spec/api.md", "docs/readme-link.md"):
        expect(f"shell cannot read non-visible {p}", not readable(f"{W}/{p}"))
    for p in (f"{W}/src/ui/../routes/api.ts", f"{W}/../workspace/src/routes/auth.ts", f"{W}/src/ui/../../tests/ui.test.ts"):
        expect(f"shell cannot read {p}", not readable(p))
    os.symlink(f"{W}/src/routes/auth.ts", "/tmp/vis-link.ts")
    expect("shell cannot read src/routes/auth.ts through a symlink", not readable("/tmp/vis-link.ts"))
    commits = subprocess.run(GIT + ["rev-list", "--all"], capture_output=True, text=True, env=GENV).stdout.split()
    expect("filtered history has 3 commits", len(commits) == 3, commits)
    for c in commits:
        for h in ("src/routes/api.ts", "src/routes/auth.ts", "tests/ui.test.ts", "src/ui/secret_theme.ts"):
            expect(f"git show {c[:8]}:{h} fails", not sh_ok(*GIT, "show", f"{c}:{h}"))
    names = set(subprocess.run(GIT + ["log", "--all", "--name-only", "--format="], capture_output=True, text=True,
                               env=GENV).stdout.split())
    expect("git history names only visible files", names == {"README.md", "src/ui/button.ts"}, names)
    allobj = subprocess.run(GIT + ["cat-file", "--batch-all-objects", "--batch"], capture_output=True,
                            env=GENV).stdout
    expect("no git object holds non-visible content", VM.encode() not in allobj and MARK.encode() not in allobj)
    ok, code, res = mcpc.call("read_text_file", path="src/ui/button.ts")
    expect("MCP read_text_file src/ui/button.ts passes", ok and "button" in mcpc.text_of(res), code)
    ok, code, res = mcpc.call("read_text_file", path="README.md")
    expect("MCP read_text_file README.md passes", ok, code)
    for p in ("src/routes/api.ts", "src/ui/../routes/api.ts", "tests/ui.test.ts", "/workspace/src/routes/auth.ts",
              "src/ui/secret_theme.ts", "src/app.ts", "src/routes"):
        ok, code, _ = mcpc.call("read_text_file", path=p)
        expect(f"MCP read_text_file {p!r} refused FORGE_PATH_HIDDEN", refused(code, "FORGE_PATH_HIDDEN"), code)
    ok, code, _ = mcpc.call("list_directory", path="src/routes")
    expect("MCP list_directory src/routes refused", refused(code, "FORGE_PATH_HIDDEN"), code)
    ok, code, res = mcpc.call("list_directory", path="src")
    expect("MCP list_directory src passes and shows only ui", ok and "ui" in mcpc.text_of(res)
           and "routes" not in mcpc.text_of(res), mcpc.text_of(res))
    os.symlink("../routes/auth.ts", f"{W}/src/ui/sneak.ts")
    ok, code, _ = mcpc.call("read_text_file", path="src/ui/sneak.ts")
    expect("MCP read through agent symlink src/ui/sneak.ts -> ../routes/auth.ts refused",
           refused(code, "FORGE_PATH_HIDDEN"), code)
    for spec in ("HEAD:src/routes/auth.ts", "HEAD~2:tests/ui.test.ts", "HEAD:src/ui/secret_theme.ts", "HEAD:src/routes"):
        ok, code, _ = mcpc.call("git_show", spec=spec)
        expect(f"MCP git_show {spec} refused FORGE_PATH_HIDDEN", refused(code, "FORGE_PATH_HIDDEN"), code)
    ok, code, res = mcpc.call("git_show", spec="HEAD:src/ui/button.ts")
    expect("MCP git_show HEAD:src/ui/button.ts passes", ok and "button" in mcpc.text_of(res), code)
    ok, code, _ = mcpc.call("write_file", path="src/ui/new_widget.ts", content="export const w = 1;\n")
    expect("MCP write_file src/ui/new_widget.ts passes", ok, code)
    ok, code, _ = mcpc.call("write_file", path="src/routes/evil.ts", content="x")
    expect("MCP write_file src/routes/evil.ts refused (not visible)", refused(code, "FORGE_PATH_HIDDEN"), code)


def common():
    """Zero upstream secrets and zero direct egress, checked from the agent's own view."""
    leaked = [k for k, v in os.environ.items() if "FAKE_" in v or "Bearer" in v]
    expect("no upstream credential in the agent environment", not leaked, leaked)
    import socket
    for hp in (("1.1.1.1", 443), ("8.8.8.8", 53), ("mock-http", 9100)):
        try:
            socket.create_connection(hp, timeout=2).close()
            expect(f"no direct egress to {hp[0]}:{hp[1]}", False)
        except OSError:
            expect(f"no direct egress to {hp[0]}:{hp[1]}", True)


def main():
    dom, phase = os.environ.get("FORGE_DOMAIN", "codebase"), os.environ.get("FORGE_PHASE", "1")
    print(f"[agent] scenario {dom} phase {phase}", flush=True)
    common()
    {"codebase": codebase, "quota": lambda: quota(phase), "concurrency": concurrency, "visible": visible}[dom]()
    print(f"[agent] {dom} phase {phase}: {PASSES[0]} ok, {len(FAILS)} failed", flush=True)
    print("[agent] RESULT " + json.dumps({"domain": dom, "phase": phase, "ok": PASSES[0], "failed": FAILS}))
    return 0 if not FAILS else 1


if __name__ == "__main__":
    sys.exit(main())
