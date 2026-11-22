# mock_repo_mcp.py - MOCK upstream MCP server (stdio) with file, search and git tools.
# It runs on the airlock side. It serves the filtered workspace (--root) and the filtered
# bare history (--git-dir); hidden content is not present in either. It also confines
# every path to --root after realpath as a second layer. NATIVE CHECK, demo quality.
import json
import os
import subprocess
import sys

ARGS = dict(zip(sys.argv[1::2], sys.argv[2::2]))
ROOT = os.path.realpath(ARGS.get("--root", "/ws"))
GITDIR = ARGS.get("--git-dir", "/state/filtered.git")
GENV = {"PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "HOME": "/nonexistent"}
TOKEN = os.environ.get("REPO_TOKEN", "")  # fake credential; proves the agent never holds it

TOOLS = [
    {"name": "read_file", "description": "Read a text file", "inputSchema": {"type": "object",
     "properties": {"path": {"type": "string"}}, "required": ["path"]}},
    {"name": "list_dir", "description": "List a directory", "inputSchema": {"type": "object",
     "properties": {"path": {"type": "string"}}}},
    {"name": "search", "description": "Search text under a path", "inputSchema": {"type": "object",
     "properties": {"query": {"type": "string"}, "path": {"type": "string"}}, "required": ["query"]}},
    {"name": "write_file", "description": "Write a text file", "inputSchema": {"type": "object",
     "properties": {"path": {"type": "string"}, "content": {"type": "string"}}, "required": ["path", "content"]}},
    {"name": "delete_path", "description": "Delete a file", "inputSchema": {"type": "object",
     "properties": {"path": {"type": "string"}}, "required": ["path"]}},
    {"name": "git_log", "description": "Show the commit log", "inputSchema": {"type": "object",
     "properties": {"max": {"type": "integer"}}}},
    {"name": "git_show", "description": "Show <rev>:<path>", "inputSchema": {"type": "object",
     "properties": {"spec": {"type": "string"}}, "required": ["spec"]}},
    {"name": "push_branch", "description": "Push to the remote (uses REPO_TOKEN)", "inputSchema": {
     "type": "object", "properties": {"branch": {"type": "string"}}}},
]


def inside(p):
    real = os.path.realpath(p if os.path.isabs(p) else os.path.join(ROOT, p))
    if real != ROOT and not real.startswith(ROOT + "/"):
        raise ValueError("path outside root")
    return real


def text(s, err=False):
    return {"content": [{"type": "text", "text": s}], "isError": err}


def call(name, a):
    if name == "read_file":
        with open(inside(a["path"]), "r", errors="replace") as f:
            return text(f.read(1 << 20))
    if name == "list_dir":
        return text("\n".join(sorted(os.listdir(inside(a.get("path", "."))))))
    if name == "search":
        base, hits = inside(a.get("path", ".")), []
        for d, dirs, files in os.walk(base):
            dirs[:] = [x for x in dirs if x != ".git"]
            for f in files:
                full = os.path.join(d, f)
                try:
                    for i, ln in enumerate(open(full, errors="replace"), 1):
                        if a["query"] in ln:
                            hits.append(f"{os.path.relpath(full, ROOT)}:{i}:{ln.rstrip()}")
                except OSError:
                    pass
        return text("\n".join(hits[:200]))
    if name == "write_file":
        real = inside(os.path.dirname(a["path"]) or ".")
        fd = os.open(os.path.join(real, os.path.basename(a["path"])), os.O_WRONLY | os.O_CREAT | os.O_TRUNC
                     | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, "w") as f:
            f.write(a["content"])
        return text(f"wrote {len(a['content'])} chars")
    if name == "delete_path":
        os.remove(inside(a["path"]))
        return text("deleted")
    if name == "git_log":
        out = subprocess.run(["git", "--git-dir", GITDIR, "log", "--oneline", "--no-decorate",
                              f"-{int(a.get('max', 20))}", "main"], capture_output=True, text=True, env=GENV)
        return text(out.stdout)
    if name == "git_show":
        out = subprocess.run(["git", "--git-dir", GITDIR, "show", "--no-textconv", "--no-ext-diff", a["spec"]],
                             capture_output=True, text=True, env=GENV)
        return text(out.stdout if out.returncode == 0 else out.stderr, out.returncode != 0)
    if name == "push_branch":
        return text(f"(mock) pushed {a.get('branch')} with token ending {TOKEN[-4:]}")
    raise KeyError(name)


def main():
    for line in sys.stdin:
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        mid, method, params = msg.get("id"), msg.get("method"), msg.get("params") or {}
        if mid is None:
            continue
        try:
            if method == "initialize":
                res = {"protocolVersion": params.get("protocolVersion", "2025-06-18"),
                       "capabilities": {"tools": {}}, "serverInfo": {"name": "mock-repo", "version": "0"}}
            elif method == "tools/list":
                res = {"tools": TOOLS}
            elif method == "tools/call":
                res = call(params["name"], params.get("arguments") or {})
            else:
                raise KeyError(method)
            out = {"jsonrpc": "2.0", "id": mid, "result": res}
        except KeyError as e:
            out = {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"unknown {e}"}}
        except Exception as e:  # noqa: BLE001
            out = {"jsonrpc": "2.0", "id": mid, "result": text(f"{type(e).__name__}: {e}", True)}
        sys.stdout.write(json.dumps(out) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
