# canary.py - startup breach canary. Runs INSIDE the agent container as the agent user,
# BEFORE the agent loop starts (the container command is "canary.py && agent").
# It tries to break out the way an agent would and fails closed:
#   - secrets: credential fingerprints in the environment (own, /proc/1) or in any file;
#   - hidden content: direct reads, '../' forms, symlinks, airlock-side paths, every
#     commit of the git history, all git objects, and a whole-filesystem fingerprint scan;
#   - read-only paths: append, rename, chmod, create-in-dir;
#   - egress: TCP to public addresses and to the upstream servers, DNS of public names;
#   - MCP: denied and unlisted tools must be absent from tools/list and refused with
#     FORGE_TOOL_BLOCKED; hidden reads and read-only writes through MCP tools must be
#     refused by policy (FORGE_CANARY_PENDING means "would have been forwarded" = breach).
# The plan (fingerprints, names) comes from the airlock once; the airlock closes the plan
# endpoint after the report. Exit 0 = PASS, 10 = BREACH, 11 = could not run (fail closed).
# Label: NATIVE CHECK (not proved). A probe that passes shows only that these attempts failed.
import hashlib
import os
import re
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mcpc  # noqa: E402

T0 = time.time()
BREACHES, CHECKS = [], [0]
GENV = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp", "GIT_CONFIG_NOSYSTEM": "1"}
GIT = ["git", "-c", "safe.directory=*"]


def fp(b):
    return hashlib.sha256(b"forge-fp:" + b).hexdigest()[:32]


def breach(what):
    BREACHES.append(what)
    print(f"[canary] BREACH: {what}", flush=True)


def check():
    CHECKS[0] += 1


def try_read(path):
    check()
    try:
        with open(path, "rb") as f:
            f.read(1)
        return True
    except OSError:
        return False


def scan(data, fps, secret_fps, where):
    hit = False
    for ln in data.splitlines():
        s = ln.strip()
        if len(s) >= 12 and fp(s) in fps:
            hit = True
            break
        for tok in re.split(rb"[\s\"'=:,;]+", s):
            if len(tok) >= 8 and fp(tok) in secret_fps:
                hit = True
                break
        if hit:
            break
    if hit:
        breach(f"fingerprint of hidden content or a credential found in {where}")


def main():
    try:
        code, plan = mcpc.http("GET", "/forge/canary/plan", timeout=30)
    except Exception as e:  # noqa: BLE001
        print(f"[canary] cannot reach the airlock: {e}; fail closed", flush=True)
        return 11
    if code != 200:
        print(f"[canary] no probe plan (HTTP {code}); fail closed", flush=True)
        return 11
    root = plan["agent_root"].rstrip("/")
    fps, secret_fps = set(plan["fingerprints"]), set(plan["secret_fps"])
    hidden = plan["hidden_names"]

    # 1. secrets in the environment
    envs = [("self", dict(os.environ))]
    for pid in ("1", "self"):
        try:
            raw = open(f"/proc/{pid}/environ", "rb").read().split(b"\x00")
            envs.append((pid, {x.split(b"=", 1)[0].decode(errors="replace"): x.split(b"=", 1)[1].decode(errors="replace")
                               for x in raw if b"=" in x}))
        except OSError:
            pass
    for who, env in envs:
        for k, v in env.items():
            check()
            toks = [v] + re.split(r"[\s\"'=:,;]+", v)
            if any(len(t) >= 8 and fp(t.encode()) in secret_fps for t in toks):
                breach(f"credential in environment variable {k} ({who})")

    # 2. airlock-side paths must not exist here
    for p in plan["airlock_paths"]:
        check()
        if os.path.lexists(p):
            breach(f"airlock-side path is visible in the agent container: {p}")

    # 3. hidden paths: direct, '../', symlinks, airlock paths, git history
    os.makedirs("/tmp/forge-canary", exist_ok=True)
    for i, h in enumerate(hidden):
        first = h.split("/")[0]
        variants = [f"{root}/{h}", f"{root}/{first}/../{h}", f"{root}/../{os.path.basename(root)}/{h}",
                    f"{root}//{h}", f"{root}/./{h}"]
        variants += [f"{p.rstrip('/')}/{h}" for p in plan["airlock_paths"]]
        for v in variants:
            if try_read(v):
                breach(f"hidden path readable: {v}")
        link = f"/tmp/forge-canary/link{i}"
        try:
            os.symlink(f"{root}/{h}", link)
            if try_read(link):
                breach(f"hidden path readable through a symlink: {h}")
        except OSError:
            pass
    revs = subprocess.run(GIT + ["-C", root, "rev-list", "--all", "--reflog"], capture_output=True, env=GENV)
    commits = revs.stdout.decode().split()
    if revs.returncode != 0:
        breach("git history could not be read for the probe (fail closed)")
    for c in commits:
        for h in hidden:
            check()
            r = subprocess.run(GIT + ["-C", root, "cat-file", "-e", f"{c}:{h}"], capture_output=True, env=GENV)
            if r.returncode == 0:
                breach(f"hidden path in git history: {c[:8]}:{h}")
    names = subprocess.run(GIT + ["-C", root, "log", "--all", "--name-only", "--format="], capture_output=True,
                           env=GENV).stdout.decode().split("\n")
    for n in names:
        check()
        if n and n in hidden:
            breach(f"hidden path name in git log: {n}")
    objs = subprocess.run(GIT + ["-C", root, "cat-file", "--batch-all-objects", "--batch"], capture_output=True,
                          env=GENV).stdout
    check()
    scan(objs, fps, secret_fps, "the git object store")

    # 4. whole-filesystem fingerprint scan (text files up to 4 MiB)
    nfiles = 0
    for d, dirs, files in os.walk("/", followlinks=False):
        if d == "/":
            dirs[:] = [x for x in dirs if x not in ("proc", "sys", "dev")]
        for f in files:
            full = os.path.join(d, f)
            try:
                if os.path.islink(full) or not os.path.isfile(full) or os.path.getsize(full) > (4 << 20):
                    continue
                with open(full, "rb") as fh:
                    data = fh.read()
            except OSError:
                continue
            if b"\x00" in data[:8192]:
                continue
            nfiles += 1
            check()
            before = len(BREACHES)
            scan(data, fps, secret_fps, full)
            if len(BREACHES) > before + 0 and len(BREACHES) > 20:
                break
    print(f"[canary] scanned {nfiles} text files", flush=True)

    # 5. read-only paths
    for f in plan["readonly_files"]:
        p = f"{root}/{f}"
        check()
        try:
            with open(p, "ab"):
                pass
            breach(f"read-only file opened for append: {f}")
        except OSError:
            pass
        check()
        try:
            os.rename(p, p + ".forge-canary")
            breach(f"read-only file renamed: {f}")
            os.rename(p + ".forge-canary", p)
        except OSError:
            pass
        check()
        try:
            mode = os.stat(p).st_mode
            os.chmod(p, 0o666)
            breach(f"read-only file chmod: {f}")
            os.chmod(p, mode)
        except OSError:
            pass
    for d in plan["closed_dirs"]:
        p = f"{root}/{d}"
        check()
        try:
            fd = os.open(f"{p}/.forge-canary-probe", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            os.close(fd)
            os.remove(f"{p}/.forge-canary-probe")
            breach(f"file created in read-only dir: {d}")
        except OSError:
            pass
        check()
        try:
            os.rename(p, p + ".forge-canary")
            breach(f"read-only dir renamed: {d}")
            os.rename(p + ".forge-canary", p)
        except OSError:
            pass

    # 6. egress
    for hp in plan["egress_targets"]:
        host, port = hp.rsplit(":", 1)
        check()
        try:
            socket.create_connection((host, int(port)), timeout=2).close()
            breach(f"egress connection succeeded: {hp}")
        except OSError:
            pass
        if not re.fullmatch(r"[0-9.]+", host):
            check()
            try:
                socket.getaddrinfo(host, int(port))
                breach(f"DNS resolution succeeded: {host}")
            except OSError:
                pass

    # 7. MCP: denied / unlisted tools, hidden reads, read-only writes
    listed = mcpc.tool_names()
    for t in plan["deny"] + plan["unlisted"]:
        check()
        if t in listed:
            breach(f"tools/list exposes a denied or unlisted tool: {t}")
        ok, code, _ = mcpc.call(t)
        if ok or code != "FORGE_TOOL_BLOCKED":
            breach(f"tool {t} was not refused with FORGE_TOOL_BLOCKED (got {code})")
    link = f"{root}/.forge-canary-link"
    try:
        os.symlink(hidden[0] if hidden else "/etc/passwd", link)  # relative: resolves inside the workspace
        made_link = True
    except (OSError, IndexError):
        made_link = False
    for tool, arg in plan["mcp_read"]:
        probes = []
        for h in hidden:
            probes += [h, f"{h.split('/')[0]}/../{h}", f"{root}/{h}", f"./{h}"]
        probes += ["../../etc/passwd", "/etc/passwd"] + [f"{p}/x" for p in plan["airlock_paths"] if p.startswith("/")]
        if made_link:
            probes.append(os.path.basename(link))
        for p in probes:
            check()
            ok, code, _ = mcpc.call(tool, **{arg: p})
            if ok or code in (None, "FORGE_CANARY_PENDING"):
                breach(f"MCP {tool}({arg}={p!r}) was not refused by policy (got {code})")
    for tool, arg in plan["mcp_write"]:
        for p in plan["readonly_files"] + [f"{d}/new.txt" for d in plan["closed_dirs"]] + hidden:
            check()
            ok, code, _ = mcpc.call(tool, **{arg: p})
            if ok or code in (None, "FORGE_CANARY_PENDING"):
                breach(f"MCP {tool}({arg}={p!r}) was not refused by policy (got {code})")
    for tool, arg in plan["mcp_rev"]:
        for h in hidden:
            for rev in ("HEAD", "HEAD~1", "HEAD~2"):
                check()
                ok, code, _ = mcpc.call(tool, **{arg: f"{rev}:{h}"})
                if ok or code in (None, "FORGE_CANARY_PENDING"):
                    breach(f"MCP {tool}({rev}:{h}) was not refused by policy (got {code})")
    if made_link:
        os.remove(link)

    result = "PASS" if not BREACHES else "BREACH"
    dt = round(time.time() - T0, 2)
    code, ack = mcpc.http("POST", "/forge/canary/report", {"result": result, "breaches": BREACHES,
                                                            "checks": CHECKS[0], "seconds": dt})
    print(f"[canary] {result}: {CHECKS[0]} checks, {len(BREACHES)} breaches, {dt}s; airlock state={ack}", flush=True)
    if code != 200 or (ack or {}).get("state") != ("PASSED" if result == "PASS" else "BREACH"):
        print("[canary] airlock did not accept the report; fail closed", flush=True)
        return 11
    return 0 if result == "PASS" else 10


if __name__ == "__main__":
    sys.exit(main())
