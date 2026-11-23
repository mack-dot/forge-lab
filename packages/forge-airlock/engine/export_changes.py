#!/usr/bin/env python3
# export_changes.py - after the agent exits: list what changed in the box's workspace.
# Runs in a short-lived container of the airlock image with the workspace and the state
# volume mounted READ-ONLY and an output folder of the host mounted at /out.
#   export_changes.py <forge.yaml> <ws> <filtered.git> <out>
# Base = the tree of filtered.git main (built by the airlock; the agent cannot write it),
# so the agent's own .git (refs, commits, hooks) is never trusted for the diff.
# Writes <out>/changes.json and <out>/files/<n> (new content). Paths that the policy hides,
# makes read-only or that are inside .git are listed as REFUSED and never exported.
# Label: NATIVE CHECK (hand-written, not proved).
import hashlib
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sync  # noqa: E402
from policy import Policy  # noqa: E402

MAX_FILE = 20 << 20


def git(gd, *args, inp=None):
    return subprocess.run(["git", "-c", "safe.directory=*", "--git-dir", gd] + list(args), input=inp,
                          capture_output=True, check=True, env={"PATH": "/usr/bin:/bin:/usr/local/bin",
                                                                 "GIT_CONFIG_NOSYSTEM": "1", "HOME": "/nonexistent"}
                          ).stdout


def base_tree(gd):
    out = {}
    for ent in git(gd, "ls-tree", "-r", "-z", "--full-tree", "refs/heads/main").split(b"\x00"):
        if not ent:
            continue
        meta, path = ent.split(b"\t", 1)
        mode, typ, sha = meta.decode().split()
        if typ == "blob":
            out[path.decode("utf-8", "surrogateescape")] = (mode, sha)
    return out


def main():
    pol_file, ws, gd, out = sys.argv[1:5]
    pol = Policy(Policy.load_doc(pol_file), resolve=False)
    base = base_tree(gd)
    cur = {}
    for d, dirs, files in os.walk(ws, followlinks=False):
        rel_d = os.path.relpath(d, ws)
        if rel_d == ".git" or rel_d.startswith(".git" + os.sep):
            dirs[:] = []
            continue
        if rel_d == ".":
            dirs[:] = [x for x in dirs if x != ".git"]
        for n in files + [x for x in dirs if os.path.islink(os.path.join(d, x))]:
            full = os.path.join(d, n)
            rel = os.path.normpath(os.path.join(rel_d, n)).replace(os.sep, "/")
            cur[rel] = full
    os.makedirs(os.path.join(out, "files"), exist_ok=True)
    changes, n = [], 0
    for rel in sorted(set(base) | set(cur)):
        full = cur.get(rel)
        if full is None:
            entry = {"path": rel, "status": "deleted"}
        else:
            is_link = os.path.islink(full)
            if is_link:
                data = os.readlink(full).encode("utf-8", "surrogateescape")
                mode = "120000"
            else:
                if os.path.getsize(full) > MAX_FILE:
                    changes.append({"path": rel, "status": "modified" if rel in base else "added",
                                    "refused": "larger than 20 MiB; not exported"})
                    continue
                data = open(full, "rb").read()
                mode = "100755" if os.stat(full).st_mode & 0o111 else "100644"
            sha = git(gd, "hash-object", "--stdin", inp=data).decode().strip()
            if rel in base and base[rel] == (mode, sha):
                continue
            if rel in base and base[rel][1] == sha:
                continue  # only the mode bit differs (read-only paths are 0444 in the box)
            entry = {"path": rel, "status": "modified" if rel in base else "added", "mode": mode,
                     "sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "symlink": is_link}
        why = sync.refusal(pol, rel, symlink=entry.get("symlink", False))
        if why:
            entry["refused"] = why
        elif entry["status"] != "deleted":
            n += 1
            entry["file"] = f"files/{n}"
            with open(os.path.join(out, entry["file"]), "wb") as f:
                f.write(data)
        changes.append(entry)
    with open(os.path.join(out, "changes.json"), "w") as f:
        json.dump({"changes": changes}, f, indent=1)
    uid = os.environ.get("FORGE_OUT_UID")
    if uid:  # the host user owns the exported files (the export runs as root to read 0600 files)
        gid = int(os.environ.get("FORGE_OUT_GID", uid))
        for d, dirs, files in os.walk(out):
            for x in [d] + [os.path.join(d, f) for f in files]:
                os.chown(x, int(uid), gid)
    print(f"[export] {len(changes)} changed paths; {sum(1 for c in changes if 'refused' in c)} refused", flush=True)


if __name__ == "__main__":
    main()
