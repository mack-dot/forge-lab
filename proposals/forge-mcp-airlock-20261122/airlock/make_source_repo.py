# make_source_repo.py - DEMO ONLY. Builds the "operator's private repository" from the
# fixtures, with a history in which hidden files exist in old commits:
#   commit 1: public files, src/proprietary/core.ts (v1), .env (fake key)
#   commit 2: core.ts v2, src/lib/algo.ts, docs/core-link.ts (symlink to the hidden file),
#             docs/readme-link.md (symlink to a public file)
#   commit 3: deletes .env (it stays in history)
# In a real deployment the operator mounts a real repository at FORGE_SOURCE instead.
import os
import shutil
import subprocess

ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
       "HOME": "/nonexistent", "GIT_AUTHOR_NAME": "operator", "GIT_AUTHOR_EMAIL": "operator@example.invalid",
       "GIT_COMMITTER_NAME": "operator", "GIT_COMMITTER_EMAIL": "operator@example.invalid"}


def g(src, *args, date):
    e = dict(ENV, GIT_AUTHOR_DATE=date, GIT_COMMITTER_DATE=date)
    subprocess.run(["git", "-C", src, *args], check=True, env=e, capture_output=True)


def build(fixtures, src):
    if os.path.exists(os.path.join(src, ".git")):
        return
    repo = os.path.join(fixtures, "repo")
    hist = os.path.join(fixtures, "history")
    os.makedirs(src, exist_ok=True)
    os.chmod(src, 0o700)
    g(src, "init", "-q", "-b", "main", date="2026-11-01T10:00:00Z")
    # commit 1
    for d, _, files in os.walk(repo):
        for f in files:
            rel = os.path.relpath(os.path.join(d, f), repo)
            if rel in ("src/lib/algo.ts",):
                continue
            os.makedirs(os.path.dirname(os.path.join(src, rel)), exist_ok=True)
            shutil.copyfile(os.path.join(d, f), os.path.join(src, rel))
    shutil.copyfile(os.path.join(hist, "core_v1.ts"), os.path.join(src, "src/proprietary/core.ts"))
    shutil.copyfile(os.path.join(hist, "dot-env.fake"), os.path.join(src, ".env"))
    g(src, "add", "-A", date="2026-11-01T10:00:00Z")
    g(src, "commit", "-q", "-m", "initial import incl. pricing core v1 (mistake: .env committed)",
      date="2026-11-01T10:00:00Z")
    # commit 2
    shutil.copyfile(os.path.join(repo, "src/proprietary/core.ts"), os.path.join(src, "src/proprietary/core.ts"))
    shutil.copyfile(os.path.join(repo, "src/lib/algo.ts"), os.path.join(src, "src/lib/algo.ts"))
    os.makedirs(os.path.join(src, "docs"), exist_ok=True)
    os.symlink("../src/proprietary/core.ts", os.path.join(src, "docs/core-link.ts"))
    os.symlink("../README.md", os.path.join(src, "docs/readme-link.md"))
    g(src, "add", "-A", date="2026-11-02T10:00:00Z")
    g(src, "commit", "-q", "-m", "pricing core v2 with secret margin table; add algo", date="2026-11-02T10:00:00Z")
    # commit 3
    os.remove(os.path.join(src, ".env"))
    g(src, "add", "-A", date="2026-11-03T10:00:00Z")
    g(src, "commit", "-q", "-m", "remove .env", date="2026-11-03T10:00:00Z")
    print(f"[airlock] demo source repository built at {src} (3 commits)", flush=True)
