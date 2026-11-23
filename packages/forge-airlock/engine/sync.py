# sync.py - the diff sync-back filter: which of the box's changes may reach the real repository.
# Standard library only (used on the host by forge_airlock.py and in the box by export_changes.py).
#
# A change is applied only if ALL hold (else it is listed as refused or skipped, never applied):
#   - the path is not hidden (hidden_paths, or outside visible_paths), not read-only
#     (readonly_paths, forge.yaml), not inside .git, and not a symlink;
#   - the path is not ignored by the real repository's .gitignore (build output, node_modules);
#   - the real file still has the content the box started from (no change of yours is overwritten);
#   - the real target and every parent directory lie inside the repository after realpath()
#     (a symlink in the real repository cannot redirect a write).
# Then the person must type y at the terminal. Label: NATIVE CHECK (hand-written, not proved).
import difflib
import hashlib
import os

# Paths that change what tools on YOUR machine run or trust: flagged in the review, not refused.
SENSITIVE = (".mcp.json", ".claude/", ".github/", ".vscode/", ".envrc", ".gitattributes", ".gitmodules",
             ".pre-commit-config.yaml", "package.json", "Makefile")


def refusal(pol, rel, symlink=False):
    """Why this workspace path may never be synced back (None = it may, subject to the rest)."""
    rel = rel.strip("/")
    if not rel or rel.startswith("../") or "/../" in "/" + rel + "/" or rel.startswith("/"):
        return "path outside the workspace"
    if rel == ".git" or rel.startswith(".git/"):
        return "inside .git"
    if pol.hidden.match(rel) or pol.is_hidden(rel):
        return "hidden path (hidden_paths or outside visible_paths)"
    if pol.readonly.match(rel):
        return "read-only path (readonly_paths or forge.yaml)"
    if symlink:
        return "symlink (symlinks are never applied)"
    return None


def sensitive(rel):
    return any(rel == s.rstrip("/") or (s.endswith("/") and rel.startswith(s)) or rel.endswith("/" + s)
               for s in SENSITIVE)


def _sha_file(path):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return None


def _inside(root, path):
    real_root = os.path.realpath(root)
    parent = os.path.realpath(os.path.dirname(path))
    if parent != real_root and not parent.startswith(real_root + os.sep):
        return False
    return not os.path.islink(path)


def plan(pol, changes, export_dir, stage_root, real_root, ignored=lambda rel: False):
    """Returns (apply, rejected). apply: list of change dicts with 'new' (bytes or None).
    rejected: list of (path, reason)."""
    apply, rejected = [], []
    for c in changes:
        rel = c["path"]
        why = c.get("refused") or refusal(pol, rel, c.get("symlink", False))
        if why:
            rejected.append((rel, why))
            continue
        if ignored(rel):
            rejected.append((rel, "ignored by the repository's .gitignore"))
            continue
        real = os.path.join(real_root, rel)
        if not _inside(real_root, real):
            rejected.append((rel, "the real path leaves the repository (symlink in a parent)"))
            continue
        base = os.path.join(stage_root, rel)
        base_sha = _sha_file(base) if os.path.lexists(base) else None
        real_sha = _sha_file(real) if os.path.lexists(real) else None
        if base_sha != real_sha:
            rejected.append((rel, "changed in the real repository since the box started (not overwritten)"))
            continue
        new = None
        if c["status"] != "deleted":
            new = open(os.path.join(export_dir, c["file"]), "rb").read()
            if hashlib.sha256(new).hexdigest() != c.get("sha256"):
                rejected.append((rel, "exported content does not match its hash"))
                continue
        apply.append(dict(c, new=new, base=base))
    return apply, rejected


def render(apply, max_lines=4000):
    out = []
    for c in apply:
        old = b""
        if os.path.exists(c["base"]):
            old = open(c["base"], "rb").read()
        new = c["new"] or b""
        flag = "   <-- SENSITIVE: changes what tools on your machine run; read it" if sensitive(c["path"]) else ""
        if b"\x00" in old[:8192] or b"\x00" in new[:8192]:
            out.append(f"binary {c['status']}: {c['path']} ({len(new)} bytes){flag}")
            continue
        a = old.decode("utf-8", "replace").splitlines(keepends=True)
        b = new.decode("utf-8", "replace").splitlines(keepends=True)
        out.append(f"{c['status']}: {c['path']}{flag}")
        out.extend(x.rstrip("\n") for x in difflib.unified_diff(
            a, b, "a/" + c["path"] if c["status"] != "added" else "/dev/null",
            "b/" + c["path"] if c["status"] != "deleted" else "/dev/null"))
    if len(out) > max_lines:
        out = out[:max_lines] + [f"... {len(out) - max_lines} more lines (all of them are applied on y)"]
    return "\n".join(out)


def apply_changes(apply, real_root):
    done = []
    for c in apply:
        real = os.path.join(real_root, c["path"])
        if not _inside(real_root, real):  # checked again right before the write
            continue
        if c["status"] == "deleted":
            if os.path.lexists(real):
                os.remove(real)
        else:
            os.makedirs(os.path.dirname(real) or real_root, exist_ok=True)
            if not _inside(real_root, real):
                continue
            tmp = real + ".forge-airlock.tmp"
            with open(tmp, "wb") as f:
                f.write(c["new"])
            os.chmod(tmp, 0o755 if c.get("mode") == "100755" else 0o644)
            os.replace(tmp, real)
        done.append(c["path"])
    return done
