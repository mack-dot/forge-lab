# draft.py - draft a forge.yaml from a repository and its .mcp.json (for `forge init` and
# /forge-airlock:airlock). Standard library only. The draft is a PROPOSAL for the person:
# Claude asks about it, the person decides. Secrets appear only as ${NAME}, never as values.
# Label: NATIVE CHECK (hand-written heuristics, not proved, not complete).
import json
import os
import re
import subprocess

FS_SERVER = "/opt/mcpfs/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js"
FS_READ = ["read_text_file", "read_file", "read_multiple_files", "list_directory", "directory_tree",
           "search_files", "get_file_info"]
FS_WRITE = ["write_file", "edit_file", "create_directory"]
FS_PATH_ARGS = {"read_multiple_files": "paths"}

HIDDEN_HINTS = [  # (glob, why) proposed when something matches in the repository
    (".env*", "environment files often hold keys"),
    ("**/*.pem", "private keys or certificates"),
    ("**/*.key", "private keys"),
    ("**/id_rsa*", "SSH keys"),
    ("secrets/**", "a secrets folder"),
    ("**/secrets.*", "a secrets file"),
    ("**/credentials*", "credentials files"),
    ("infra/**", "infrastructure code (accounts, networks, keys)"),
    ("terraform/**", "infrastructure code"),
    ("**/*.tfvars", "Terraform variables often hold secrets"),
    ("**/*.tfstate*", "Terraform state holds secrets"),
    ("proprietary/**", "proprietary code"),
    ("src/proprietary/**", "proprietary code"),
    ("internal/**", "internal code"),
    ("**/*.p12", "certificate bundles"),
]
READONLY_HINTS = [
    ("tests/**", "tests: the agent must not weaken them"),
    ("test/**", "tests: the agent must not weaken them"),
    ("spec/**", "specifications"),
    (".forge/**", "Forge approvals and config"),
    ("INVARIANTS.md", "the approved rules in plain words"),
    (".github/**", "CI workflows: a change there runs code in CI"),
]

READ_VERBS = ("get", "list", "read", "search", "find", "view", "show", "describe", "fetch", "lookup", "query",
              "status", "info", "count", "check", "inspect", "browse", "retrieve", "head", "stat", "ping")
DESTRUCTIVE = ("delete", "drop", "remove", "destroy", "purge", "truncate", "wipe", "erase", "rotate", "revoke",
               "force", "reset", "kill", "terminate", "shutdown", "rm", "uninstall", "archive", "ban", "disable")
COSTLY = ("charge", "pay", "payment", "refund", "transfer", "send", "invoice", "payout", "withdraw", "deposit",
          "buy", "purchase", "order", "spend", "deploy", "publish", "release", "merge", "push", "run", "execute",
          "create", "post", "email", "sms", "message", "notify", "invite", "provision", "scale", "launch", "start",
          "write", "update", "edit", "upload", "commit", "open", "comment", "assign", "set", "add", "put", "patch")
AMOUNT_FIELDS = ("amount", "amount_cents", "cents", "value", "quantity", "qty", "count", "rows", "limit", "units",
                 "credits", "tokens", "price")

HOST_HOMES = ("/" + "Users/", "/home/", os.path.expanduser("~") + "/")  # paths that exist only on the host
ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-[^}]*)?\}")


def words(name):
    return [w for w in re.split(r"[^a-z0-9]+", re.sub(r"([a-z])([A-Z])", r"\1_\2", name).lower()) if w]


def classify(tool):
    """allow | deny | gate | ask, with a reason. Destructive beats costly beats read."""
    w = words(tool.get("name", ""))
    if any(x in DESTRUCTIVE for x in w):
        return "deny", "destructive verb"
    if any(x in COSTLY for x in w):
        props = ((tool.get("inputSchema") or {}).get("properties") or {})
        fld = next((f for f in AMOUNT_FIELDS if (props.get(f) or {}).get("type") == "integer"), None)
        return "gate", (f"costs money or has side effects; integer field {fld!r}" if fld
                        else "has side effects; capped by count")
    if w and w[0] in READ_VERBS or any(x in READ_VERBS for x in w[:2]):
        return "allow", "read-like"
    return "ask", "unknown kind; listed for the person to decide (default deny)"


def tracked_files(repo):
    try:
        out = subprocess.run(["git", "-C", repo, "ls-files", "-co", "--exclude-standard", "-z"], capture_output=True,
                             check=True).stdout
        return [x.decode("utf-8", "surrogateescape") for x in out.split(b"\x00") if x]
    except (OSError, subprocess.CalledProcessError):
        out = []
        for d, dirs, files in os.walk(repo):
            dirs[:] = [x for x in dirs if x not in (".git", "node_modules", ".venv", "dist", "build")]
            out += [os.path.relpath(os.path.join(d, f), repo) for f in files]
        return out


def _env_ref(key, value, notes):
    """A secret value becomes ${NAME}. Existing ${NAME} references are kept as they are."""
    if isinstance(value, str) and REF.fullmatch(value.strip()):
        return "${%s}" % REF.fullmatch(value.strip()).group(1)
    if isinstance(value, str) and REF.search(value):  # "Bearer ${TOKEN}"
        return REF.sub(lambda m: "${%s}" % m.group(1), value)
    name = re.sub(r"[^A-Za-z0-9_]", "_", key).upper() or "SECRET"
    if not ENV_NAME.match(name):
        name = "S_" + name
    notes.append(f"a literal value of {key} in .mcp.json was replaced by ${{{name}}}; export {name} in your shell "
                 f"(the value is NOT copied into forge.yaml)")
    return "${%s}" % name


def upstreams_from_mcp_json(path, notes):
    if not os.path.exists(path):
        return []
    try:
        servers = (json.load(open(path)) or {}).get("mcpServers") or {}
    except ValueError:
        notes.append(".mcp.json does not parse; no upstream drafted from it")
        return []
    ups = []
    for name, s in sorted(servers.items()):
        nm = re.sub(r"[^A-Za-z0-9_-]", "_", name)[:40] or "server"
        typ = s.get("type") or ("stdio" if "command" in s else "http")
        if typ == "stdio" or "command" in s:
            cmd = [s.get("command")] + list(s.get("args") or [])
            for i, c in enumerate(cmd):
                if isinstance(c, str) and c.startswith(HOST_HOMES):
                    notes.append(f"upstream {nm}: {c!r} is a path on your machine; it does not exist in the box")
            env = {k: _env_ref(k, v, notes) for k, v in sorted((s.get("env") or {}).items())}
            u = {"name": nm, "transport": "stdio", "command": cmd, "user": 1000}
            if env:
                u["env"] = env
        else:
            u = {"name": nm, "transport": "http", "url": s.get("url")}
            hd = {k: _env_ref(k, v, notes) for k, v in sorted((s.get("headers") or {}).items())}
            if hd:
                u["headers"] = hd
            if typ == "sse":
                notes.append(f"upstream {nm}: SSE-only servers are not supported; it may fail to start")
        ups.append(u)
    return ups


def draft(repo, tools_by_upstream=None, with_fs=True, claude=True):
    """Returns (doc, notes, questions). tools_by_upstream: {upstream: [tool dicts]} when known."""
    notes, questions = [], []
    files = tracked_files(repo)
    from policy import glob_to_regex  # noqa: E402 (same matcher as the airlock)

    def hits(pat):
        r = glob_to_regex(pat)
        return [f for f in files if r.match(f)]
    hidden, readonly = [], []
    for pat, why in HIDDEN_HINTS:
        h = hits(pat)
        if h or pat == ".env*":
            hidden.append(pat)
            questions.append({"kind": "hidden", "pattern": pat, "why": why, "examples": h[:3]})
    for pat, why in READONLY_HINTS:
        h = hits(pat)
        if h:
            readonly.append(pat)
            questions.append({"kind": "readonly", "pattern": pat, "why": why, "examples": h[:3]})
    ups = []
    allow, deny, gate = [], [], []
    if with_fs:
        ups.append({"name": "fs", "transport": "stdio", "command": ["node", FS_SERVER, "/ws"], "user": 1000})
        allow += [{"tool": t, "upstream": "fs", "path_args": {FS_PATH_ARGS.get(t, "path"): "read"}} for t in FS_READ]
        allow += [{"tool": t, "upstream": "fs", "path_args": {"path": "write"}} for t in FS_WRITE]
        deny += ["move_file"]
    ups += upstreams_from_mcp_json(os.path.join(repo, ".mcp.json"), notes)
    for u in ups[1 if with_fs else 0:]:
        tools = (tools_by_upstream or {}).get(u["name"])
        if tools is None:
            notes.append(f"upstream {u['name']}: tools not listed yet (run `forge tools`); none allowed "
                         f"(default deny)")
            continue
        for t in tools:
            kind, why = classify(t)
            if kind == "allow":
                allow.append({"tool": t["name"], "upstream": u["name"]})
            elif kind == "deny":
                deny.append(t["name"])
            elif kind == "gate":
                props = ((t.get("inputSchema") or {}).get("properties") or {})
                fld = next((f for f in AMOUNT_FIELDS if (props.get(f) or {}).get("type") == "integer"), None)
                g = {"tool": t["name"], "upstream": u["name"], "cap": 1000 if fld else 10,
                     "expires_in_s": 86400}
                if fld:
                    g.update(unit="value", value_field=fld)
                else:
                    g["unit"] = "count"
                gate.append(g)
            questions.append({"kind": "tool", "upstream": u["name"], "tool": t["name"], "proposal": kind,
                              "why": why})
    doc = {"version": 1, "upstreams": ups, "tools": {"allow": allow, "deny": sorted(set(deny)), "gate": gate},
           "paths": {"hidden_paths": hidden, "readonly_paths": readonly}}
    if claude:
        doc["agent"] = {"egress_allow": ["api.anthropic.com:443"]}
    return doc, notes, questions


# ---------------------------------------------------------------- YAML out (block style)
def _scalar(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if v is None:
        return "null"
    return json.dumps(v)  # a JSON string is a valid YAML double-quoted scalar


def to_yaml(v, ind=0):
    pad = "  " * ind
    if isinstance(v, dict):
        if not v:
            return pad + "{}\n"
        out = ""
        for k, x in v.items():
            if isinstance(x, (dict, list)) and x:
                if isinstance(x, list) and all(not isinstance(y, (dict, list)) for y in x):
                    out += f"{pad}{k}: [{', '.join(_scalar(y) for y in x)}]\n"
                else:
                    out += f"{pad}{k}:\n" + to_yaml(x, ind + 1)
            else:
                out += f"{pad}{k}: {_scalar(x) if not isinstance(x, (dict, list)) else ('{}' if isinstance(x, dict) else '[]')}\n"
        return out
    if isinstance(v, list):
        out = ""
        for x in v:
            if isinstance(x, dict) and x:
                body = to_yaml(x, ind + 1)
                out += pad + "- " + body[len(pad) + 2:]
            else:
                out += f"{pad}- {_scalar(x)}\n"
        return out
    return pad + _scalar(v) + "\n"


HEADER = """# forge.yaml - the airlock policy for this repository (drafted by forge init; review it).
# Default deny: a tool that is not listed is refused. Secrets are named as ${NAME} only:
# the value comes from your shell when `forge up` starts, and only the airlock sees it.
# Reference: packages/forge-airlock/README.md
"""
