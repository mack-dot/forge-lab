# workspace.py - build the agent's workspace on the airlock side so hidden content is ABSENT.
#
# Label: NATIVE CHECK (hand-written, not proved).
# Method:
#   1. Rewrite the source history commit by commit (first-parent chain only) into a new
#      bare repository (state/filtered.git). Each new tree keeps only the entries that are
#      not hidden. Blobs are copied one by one, so a hidden blob never enters the new
#      object store. Symlinks whose target is absolute, leaves the repository or lands on
#      a hidden path are dropped. Submodules are dropped. Commit messages are replaced
#      unless keep_commit_messages is true.
#   2. The agent workspace is a fresh 'git init' that fetches only from filtered.git.
#   3. Fail-closed checks: no hidden path in the tree or in any reachable commit; no
#      hidden-only blob id in the object store; no fingerprint line of hidden content in
#      any file or any decompressed git object of the workspace.
#   4. Read-only paths: root-owned files 0444 and closed directories 0555; directories
#      that hold read-only entries become root-owned 01777 (sticky), so uid 1000 cannot
#      rename or delete them. Everything else is owned by uid 1000.
import hashlib
import json
import os
import posixpath
import shutil
import subprocess

AGENT_UID = 1000
FP_MIN = 12  # shortest line (after strip) that is fingerprinted

GIT_SAFE = ["git", "-c", "safe.directory=*", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
            "-c", "protocol.file.allow=always"]
GIT_ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
           "HOME": "/nonexistent", "GIT_TERMINAL_PROMPT": "0"}


class WorkspaceError(Exception):
    pass


def git(args, cwd=None, inp=None, env=None, user=None, check=True):
    e = dict(GIT_ENV)
    e.update(env or {})
    r = subprocess.run(GIT_SAFE + args, cwd=cwd, input=inp, capture_output=True, env=e, user=user)
    if check and r.returncode != 0:
        raise WorkspaceError(f"git {' '.join(args[:3])} failed: {r.stderr.decode(errors='replace')[:300]}")
    return r.stdout


def fp(line):
    return hashlib.sha256(b"forge-fp:" + line).hexdigest()[:32]


def lines_of(data):
    out = set()
    for ln in data.splitlines():
        ln = ln.strip()
        if len(ln) >= FP_MIN:
            out.add(ln)
    return out


def scan_bytes(data, fps):
    return {fp(ln) for ln in lines_of(data)} & fps


def _walk(root):
    for d, dirs, files in os.walk(root, followlinks=False):
        for n in dirs + files:
            full = os.path.join(d, n)
            yield full, os.path.relpath(full, root)


def link_escapes(rel_link, target, is_hidden):
    if target.startswith("/"):
        return True
    res = posixpath.normpath(posixpath.join(posixpath.dirname(rel_link), target))
    return res == ".." or res.startswith("../") or is_hidden(res)


class BlobReader:
    """One 'git cat-file --batch' process for the whole filter run (not one per entry)."""

    def __init__(self, source):
        e = dict(GIT_ENV)
        self.p = subprocess.Popen(GIT_SAFE + ["-C", source, "cat-file", "--batch"], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, env=e)

    def read(self, sha):
        self.p.stdin.write(sha.encode() + b"\n")
        self.p.stdin.flush()
        head = self.p.stdout.readline().split()
        if len(head) != 3 or head[1] != b"blob":
            raise WorkspaceError(f"cat-file {sha}: {head!r}")
        n = int(head[2])
        data = self.p.stdout.read(n)
        self.p.stdout.read(1)
        return data

    def close(self):
        self.p.stdin.close()
        self.p.wait(30)


def filter_history(policy, source, filtered):
    hidden = policy.is_hidden
    if os.path.exists(filtered):
        shutil.rmtree(filtered)
    git(["init", "-q", "--bare", "-b", "main", filtered])
    commits = git(["-C", source, "rev-list", "--reverse", "--first-parent", "HEAD"]).decode().split()
    if not commits:
        raise WorkspaceError("source repository has no commits")
    hidden_blobs, public_blobs = set(), set()
    hidden_lines, public_lines = set(), set()
    hidden_names, copied = set(), set()
    parent, dropped = None, []
    seen_hidden = set()
    blobs = BlobReader(source)
    idx = filtered + ".index"
    for n, c in enumerate(commits, 1):
        raw = git(["-C", source, "ls-tree", "-r", "-z", "--full-tree", c])
        keep = []
        for ent in raw.split(b"\x00"):
            if not ent:
                continue
            meta, path = ent.split(b"\t", 1)
            mode, typ, sha = meta.decode().split()
            path_s = path.decode("utf-8", "surrogateescape")
            if typ != "blob":
                dropped.append((c[:8], path_s, "submodule"))
                continue
            if hidden(path_s):
                hidden_blobs.add(sha)
                hidden_names.add(path_s)
                if sha not in seen_hidden:
                    seen_hidden.add(sha)
                    hidden_lines |= lines_of(blobs.read(sha))
                continue
            if sha in copied and mode != "120000":
                keep.append(f"{mode} {sha}\t".encode() + path)
                continue
            data = blobs.read(sha)
            if mode == "120000" and link_escapes(path_s, data.decode("utf-8", "surrogateescape"), hidden):
                dropped.append((c[:8], path_s, "symlink to hidden or outside"))
                continue
            public_blobs.add(sha)
            public_lines |= lines_of(data)
            if sha not in copied:
                got = git(["--git-dir", filtered, "hash-object", "-w", "--stdin"], inp=data).decode().strip()
                if got != sha:
                    raise WorkspaceError("blob id changed while copying")
                copied.add(sha)
            keep.append(f"{mode} {sha}\t".encode() + path)
        env = {"GIT_INDEX_FILE": idx}
        git(["--git-dir", filtered, "read-tree", "--empty"], env=env)
        if keep:
            git(["--git-dir", filtered, "update-index", "-z", "--index-info"], inp=b"\x00".join(keep) + b"\x00",
                env=env)
        tree = git(["--git-dir", filtered, "write-tree"], env=env).decode().strip()
        fmt = git(["-C", source, "show", "-s", "--format=%an%x00%ae%x00%aI%x00%cn%x00%ce%x00%cI%x00%B", c])
        an, ae, ad, cn, ce, cd, msg = fmt.decode("utf-8", "replace").split("\x00", 6)
        if not policy.keep_commit_messages:
            msg = f"forge-filtered commit {n} of {len(commits)}\n"
        cenv = {"GIT_AUTHOR_NAME": an, "GIT_AUTHOR_EMAIL": ae, "GIT_AUTHOR_DATE": ad,
                "GIT_COMMITTER_NAME": cn, "GIT_COMMITTER_EMAIL": ce, "GIT_COMMITTER_DATE": cd}
        args = ["--git-dir", filtered, "commit-tree", tree, "-m", msg]
        if parent:
            args[4:4] = ["-p", parent]
        parent = git(args, env=cenv).decode().strip()
    blobs.close()
    os.remove(idx)
    git(["--git-dir", filtered, "update-ref", "refs/heads/main", parent])
    fps = {fp(x) for x in hidden_lines - public_lines}
    return {"commits": len(commits), "hidden_names": sorted(hidden_names),
            "hidden_only_blobs": sorted(hidden_blobs - public_blobs), "fingerprints": sorted(fps),
            "dropped": dropped}


def verify_workspace(policy, ws, info, as_uid=None, build=True):
    """Fail-closed check that hidden content is absent from the workspace.

    build=True (first build): also no hidden path names and no escaping symlinks.
    build=False (restart): content checks only. The agent may have created files or
    symlinks since; their names are harmless, hidden CONTENT must still be absent."""
    hidden, fps, bad_blobs = policy.is_hidden, set(info["fingerprints"]), set(info["hidden_only_blobs"])
    problems = []
    for full, rel in _walk(ws):
        if rel == ".git" or rel.startswith(".git/"):
            continue
        is_dir = os.path.isdir(full) and not os.path.islink(full)
        if build and (policy._path_hidden(rel) if is_dir else hidden(rel)):
            problems.append(f"hidden path present: {rel}")
        if os.path.islink(full):
            if build and link_escapes(rel, os.readlink(full), hidden):
                problems.append(f"symlink to hidden/outside: {rel}")
        elif os.path.isfile(full):
            with open(full, "rb") as f:
                if scan_bytes(f.read(4 << 20), fps):
                    problems.append(f"hidden fingerprint in file: {rel}")
    gd = ["--git-dir", os.path.join(ws, ".git")]
    objs = git(gd + ["cat-file", "--batch-all-objects", "--batch-check"], user=as_uid).decode().split("\n")
    for o in objs:
        if o and o.split()[0] in bad_blobs:
            problems.append(f"hidden blob in object store: {o.split()[0]}")
    allobj = git(gd + ["cat-file", "--batch-all-objects", "--batch"], user=as_uid)
    if scan_bytes(allobj, fps):
        problems.append("hidden fingerprint in a git object")
    names = git(gd + ["log", "--all", "--name-only", "--format="], user=as_uid).decode().split("\n")
    for nme in names:
        if build and nme and hidden(nme):
            problems.append(f"hidden path in history: {nme}")
    if problems:
        raise WorkspaceError("workspace check failed: " + "; ".join(problems[:5]))


def apply_permissions(policy, ws):
    ro = policy.readonly
    for full, _ in [(ws, ".")] + list(_walk(ws)):
        os.lchown(full, AGENT_UID, AGENT_UID)
    ro_files, closed_dirs, sticky = [], [], set()
    for full, rel in _walk(ws):
        if rel == ".git" or rel.startswith(".git/"):
            continue
        is_dir = os.path.isdir(full) and not os.path.islink(full)
        if is_dir and ro.closes_dir(rel):
            closed_dirs.append(rel)
        elif ro.match(rel):
            ro_files.append(rel)
        else:
            continue
        parent = os.path.dirname(rel)
        while True:
            sticky.add(parent)
            if not parent:
                break
            parent = os.path.dirname(parent)
    for rel in sorted(sticky):
        if rel and (ro.closes_dir(rel) or ro.match(rel)):
            continue
        full = os.path.join(ws, rel) if rel else ws
        os.chown(full, 0, 0)
        os.chmod(full, 0o1777)
    for rel in ro_files:
        full = os.path.join(ws, rel)
        os.lchown(full, 0, 0)
        if not os.path.islink(full):
            os.chmod(full, 0o444)
    for rel in closed_dirs:
        top = os.path.join(ws, rel)
        for full, _ in [(top, ".")] + list(_walk(top)):
            os.lchown(full, 0, 0)
            if os.path.islink(full):
                continue
            os.chmod(full, 0o555 if os.path.isdir(full) else 0o444)
    return {"readonly_files": sorted(ro_files), "closed_dirs": sorted(set(closed_dirs)),
            "sticky_dirs": sorted(x or "." for x in sticky)}


def prepare(policy, source, state, ws):
    """Build once per state volume; re-verify on every start. Returns the info dict."""
    os.makedirs(state, exist_ok=True)
    os.chmod(state, 0o711)
    marker = os.path.join(state, "workspace.json")
    if os.path.exists(marker):
        info = json.load(open(marker))
        vis = policy.visible.patterns if policy.visible else None
        if (info.get("policy_hidden") != policy.hidden.patterns or info.get("policy_ro") != policy.readonly.patterns
                or info.get("policy_visible") != vis):
            raise WorkspaceError("policy paths changed since the workspace was built; rebuild from a clean state")
        verify_workspace(policy, ws, info, as_uid=AGENT_UID, build=False)
        print(f"[airlock] workspace: re-verified (hidden content absent) at {ws}", flush=True)
        return info
    if os.listdir(ws):
        raise WorkspaceError(f"{ws} is not empty and has no build marker; refusing to reuse it")
    filtered = os.path.join(state, "filtered.git")
    info = filter_history(policy, source, filtered)
    git(["init", "-q", "-b", "scratch", ws])
    git(["-C", ws, "fetch", "-q", "--no-tags", filtered, "refs/heads/main"])
    git(["-C", ws, "checkout", "-q", "-B", "main", "FETCH_HEAD"])
    git(["-C", ws, "config", "user.name", "agent"])
    git(["-C", ws, "config", "user.email", "agent@forge.invalid"])
    for f in ("FETCH_HEAD", "ORIG_HEAD"):
        p = os.path.join(ws, ".git", f)
        if os.path.exists(p):
            os.remove(p)
    verify_workspace(policy, ws, info)
    info.update(apply_permissions(policy, ws))
    for full, _ in _walk(filtered):
        os.chmod(full, 0o755 if os.path.isdir(full) else 0o644)
    os.chmod(filtered, 0o755)
    info["policy_hidden"], info["policy_ro"] = policy.hidden.patterns, policy.readonly.patterns
    info["policy_visible"] = policy.visible.patterns if policy.visible else None
    with open(marker, "w") as f:
        json.dump(info, f, indent=1)
    os.chmod(marker, 0o600)
    print(f"[airlock] workspace: built from {info['commits']} commits; {len(info['hidden_names'])} hidden paths "
          f"absent; {len(info['dropped'])} entries dropped; {len(info['readonly_files'])} read-only files, "
          f"{len(info['closed_dirs'])} closed dirs", flush=True)
    return info
