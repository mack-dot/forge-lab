# policy.py - strict loader and evaluator for forge.yaml.
#
# Label: NATIVE CHECK (hand-written, not proved).
# Design rule: this file names no tool, no domain and no unit. Every tool name, path
# pattern, cap and argument rule comes from forge.yaml. Unknown keys, missing keys and
# contradictions are load errors (fail closed). Anything that forge.yaml does not list
# is blocked (default deny).
import json
import os
import posixpath
import re
import sys

MONEY_MAX = (1 << 63) - 1
U64_MAX = (1 << 64) - 1


class PolicyError(Exception):
    pass


class Refusal(Exception):
    """A policy refusal returned to the agent. code is a FORGE_* string."""

    def __init__(self, code, message, **data):
        super().__init__(message)
        self.code, self.message, self.data = code, message, data


# ---------------------------------------------------------------- glob matching
def glob_to_regex(pat):
    """Glob with gitignore-like anchoring.

    '**' matches any number of path segments (including none), '*' and '?' never
    cross '/'. A pattern without '/' matches a basename at any depth
    ('.env*' == '**/.env*'). A pattern with '/' is anchored at the root.
    A path also matches when one of its ancestor directories matches."""
    if not pat or pat.startswith("/"):
        raise PolicyError(f"bad path pattern {pat!r} (empty or absolute)")
    p = pat.rstrip("/")
    if "/" not in p:
        p = "**/" + p
    i, out = 0, []
    while i < len(p):
        if p.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif p.startswith("**", i):
            out.append(".*")
            i += 2
        elif p[i] == "*":
            out.append("[^/]*")
            i += 1
        elif p[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(p[i]))
            i += 1
    return re.compile("".join(out) + r"(?:/.*)?\Z", re.S)


class PathSet:
    def __init__(self, patterns, what):
        if not isinstance(patterns, list) or not all(isinstance(x, str) for x in patterns):
            raise PolicyError(f"paths.{what} must be a list of strings")
        self.patterns = list(patterns)
        self._re = [glob_to_regex(x) for x in patterns]

    def match(self, rel):
        rel = rel.strip("/")
        if rel in ("", "."):
            return False
        return any(r.match(rel) for r in self._re)

    def closes_dir(self, rel_dir):
        """True when every new child of rel_dir would match (e.g. 'tests' for 'tests/**')."""
        probe = (rel_dir.strip("/") + "/" if rel_dir.strip("/") else "") + "__forge_probe__/x"
        return self.match(probe)


# ---------------------------------------------------------------- schema helpers
def _keys(obj, where, required=(), optional=()):
    if not isinstance(obj, dict):
        raise PolicyError(f"{where} must be a mapping")
    extra = set(obj) - set(required) - set(optional)
    if extra:
        raise PolicyError(f"{where}: unknown keys {sorted(extra)}")
    missing = [k for k in required if k not in obj]
    if missing:
        raise PolicyError(f"{where}: missing keys {missing}")


def _int(v, where, lo=0, hi=U64_MAX):
    if type(v) is not int or not lo <= v <= hi:
        raise PolicyError(f"{where} must be an integer in [{lo}, {hi}]")
    return v


RULE_KEYS = ("equals", "not_equals", "in", "not_in", "regex", "int_min", "int_max", "optional", "type")
PATH_MODES = ("read", "write", "git_revpath")


class ArgRule:
    def __init__(self, name, spec, where):
        _keys(spec, where, optional=RULE_KEYS)
        if not spec or set(spec) <= {"optional"}:
            raise PolicyError(f"{where}: empty rule")
        self.name, self.spec = name, dict(spec)
        self.optional = bool(spec.get("optional", False))
        for k in ("in", "not_in"):
            if k in spec and not isinstance(spec[k], list):
                raise PolicyError(f"{where}.{k} must be a list")
        self.regex = re.compile(spec["regex"]) if "regex" in spec else None
        for k in ("int_min", "int_max"):
            if k in spec and type(spec[k]) is not int:
                raise PolicyError(f"{where}.{k} must be an integer")
        if "type" in spec and spec["type"] not in ("string", "integer", "boolean"):
            raise PolicyError(f"{where}.type must be string, integer or boolean")

    def check(self, args):
        if self.name not in args:
            if self.optional:
                return
            raise Refusal("FORGE_ARG_REFUSED", f"argument {self.name!r} is required by policy", arg=self.name)
        v, s = args[self.name], self.spec

        def bad(why):
            raise Refusal("FORGE_ARG_REFUSED", f"argument {self.name!r} refused: {why}", arg=self.name)

        t = s.get("type")
        if t == "string" and not isinstance(v, str):
            bad("must be a string")
        if t == "boolean" and not isinstance(v, bool):
            bad("must be a boolean")
        if t == "integer" and type(v) is not int:
            bad("must be an integer")
        if "equals" in s and v != s["equals"]:
            bad(f"must equal {s['equals']!r}")
        if "not_equals" in s and v == s["not_equals"]:
            bad(f"must not equal {s['not_equals']!r}")
        if "in" in s and v not in s["in"]:
            bad(f"must be one of {s['in']!r}")
        if "not_in" in s and v in s["not_in"]:
            bad(f"must not be one of {s['not_in']!r}")
        if self.regex is not None and (not isinstance(v, str) or not self.regex.fullmatch(v)):
            bad(f"must fully match /{self.regex.pattern}/")
        if ("int_min" in s or "int_max" in s) and type(v) is not int:
            bad("must be an integer")
        if "int_min" in s and v < s["int_min"]:
            bad(f"must be >= {s['int_min']}")
        if "int_max" in s and v > s["int_max"]:
            bad(f"must be <= {s['int_max']}")


class ToolPolicy:
    """One allowed or gated tool."""

    def __init__(self, spec, where, gated):
        base = ("tool",)
        opt = ("upstream", "arg_rules", "path_args", "strict_args")
        gopt = ("log", "unit", "value_field", "cap", "per_call_max", "expires_in_s", "expires_at",
                "id_field", "checker")
        if gated:
            _keys(spec, where, required=base + ("cap",), optional=opt + gopt)
        else:
            _keys(spec, where, required=base, optional=opt)
        self.name = spec["tool"]
        if not isinstance(self.name, str) or not self.name:
            raise PolicyError(f"{where}.tool must be a non-empty string")
        self.upstream = spec.get("upstream")
        self.gated = gated
        self.rules = [ArgRule(k, v, f"{where}.arg_rules.{k}") for k, v in (spec.get("arg_rules") or {}).items()]
        pa = spec.get("path_args") or {}
        _keys(pa, f"{where}.path_args", optional=list(pa))
        for k, m in pa.items():
            if m not in PATH_MODES:
                raise PolicyError(f"{where}.path_args.{k} must be one of {PATH_MODES}")
        self.path_args = dict(pa)
        self.strict_args = bool(spec.get("strict_args", False))
        if gated:
            self.unit = spec.get("unit", "count")
            if self.unit not in ("count", "value"):
                raise PolicyError(f"{where}.unit must be count or value")
            self.value_field = spec.get("value_field")
            if (self.unit == "value") != (self.value_field is not None):
                raise PolicyError(f"{where}: value_field is required for unit=value and only for it")
            self.cap = _int(spec["cap"], f"{where}.cap", 0, MONEY_MAX)
            self.per_call_max = spec.get("per_call_max")
            if self.per_call_max is not None:
                _int(self.per_call_max, f"{where}.per_call_max", 0, MONEY_MAX)
            if ("expires_in_s" in spec) == ("expires_at" in spec):
                raise PolicyError(f"{where}: give exactly one of expires_in_s or expires_at")
            self.expires_in_s = spec.get("expires_in_s")
            self.expires_at = spec.get("expires_at")
            if self.expires_in_s is not None:
                _int(self.expires_in_s, f"{where}.expires_in_s", 1)
            if self.expires_at is not None:
                _int(self.expires_at, f"{where}.expires_at", 1)
            self.log = spec.get("log", self.name)
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", self.log):
                raise PolicyError(f"{where}.log must match [A-Za-z0-9_.-]{{1,64}}")
            self.id_field = spec.get("id_field")
            ck = spec.get("checker")
            if ck is not None:
                _keys(ck, f"{where}.checker", required=("command",), optional=("timeout_s",))
                if not isinstance(ck["command"], list) or not ck["command"]:
                    raise PolicyError(f"{where}.checker.command must be a non-empty list")
            self.checker = ck

    def known_args(self):
        names = {r.name for r in self.rules} | set(self.path_args)
        if self.gated:
            names |= {x for x in (self.value_field, self.id_field) if x}
        return names


ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]{0,127})\}")


def env_refs(doc):
    """Every ${NAME} named in upstream command, env, url or headers (names only)."""
    names = set()
    for u in (doc.get("upstreams") or []) if isinstance(doc, dict) else []:
        if not isinstance(u, dict):
            continue
        vals = list(u.get("command") or []) + [u.get("url") or ""]
        vals += list((u.get("env") or {}).values()) + list((u.get("headers") or {}).values())
        for v in vals:
            if isinstance(v, str):
                names.update(ENV_REF.findall(v))
    return sorted(names)


def _resolve(v, environ, where):
    if not isinstance(v, str):
        return v

    def sub(m):
        if m.group(1) not in environ:
            raise PolicyError(f"{where}: environment variable {m.group(1)} is not set (fail closed)")
        return environ[m.group(1)]
    return ENV_REF.sub(sub, v)


class Policy:
    def __init__(self, doc, environ=None, resolve=True):
        """resolve=True replaces ${NAME} in upstreams with the value from environ (the
        airlock side). resolve=False keeps the names (host side: no secret is read)."""
        _keys(doc, "forge.yaml", required=("version", "upstreams", "tools"), optional=("paths", "canary", "agent"))
        if doc["version"] != 1:
            raise PolicyError("version must be 1")
        # upstreams
        if not isinstance(doc["upstreams"], list) or not doc["upstreams"]:
            raise PolicyError("upstreams must be a non-empty list")
        self.upstreams = {}
        for i, u in enumerate(doc["upstreams"]):
            w = f"upstreams[{i}]"
            _keys(u, w, required=("name", "transport"), optional=("command", "url", "env", "headers", "timeout_s", "user"))
            if u["name"] in self.upstreams:
                raise PolicyError(f"{w}: duplicate upstream {u['name']!r}")
            if u["transport"] == "stdio":
                if "user" in u:
                    _int(u["user"], f"{w}.user", 1, 65534)
                if not isinstance(u.get("command"), list) or "url" in u or "headers" in u:
                    raise PolicyError(f"{w}: stdio needs command (list) and no url/headers")
            elif u["transport"] == "http":
                if not isinstance(u.get("url"), str) or "command" in u or "env" in u or "user" in u:
                    raise PolicyError(f"{w}: http needs url and no command/env")
            else:
                raise PolicyError(f"{w}.transport must be stdio or http")
            if resolve:
                env = os.environ if environ is None else environ
                u = dict(u)
                if isinstance(u.get("command"), list):
                    u["command"] = [_resolve(x, env, f"{w}.command") for x in u["command"]]
                if "url" in u:
                    u["url"] = _resolve(u["url"], env, f"{w}.url")
                for k in ("env", "headers"):
                    if k in u:
                        if not isinstance(u[k], dict):
                            raise PolicyError(f"{w}.{k} must be a mapping")
                        u[k] = {kk: _resolve(vv, env, f"{w}.{k}.{kk}") for kk, vv in u[k].items()}
            self.upstreams[u["name"]] = u
        # tools
        t = doc["tools"]
        _keys(t, "tools", optional=("allow", "deny", "gate"))
        self.deny = list(t.get("deny") or [])
        if not all(isinstance(x, str) for x in self.deny):
            raise PolicyError("tools.deny must be a list of strings")
        self.tools = {}
        for gated, key in ((False, "allow"), (True, "gate")):
            for i, spec in enumerate(t.get(key) or []):
                tp = ToolPolicy(spec, f"tools.{key}[{i}]", gated)
                if tp.name in self.tools:
                    raise PolicyError(f"tool {tp.name!r} listed twice")
                if tp.name in self.deny:
                    raise PolicyError(f"tool {tp.name!r} is both denied and allowed/gated")
                if tp.upstream is not None and tp.upstream not in self.upstreams:
                    raise PolicyError(f"tool {tp.name!r}: unknown upstream {tp.upstream!r}")
                self.tools[tp.name] = tp
        # logs shared by several gated tools must agree on cap and expiry
        self.logs = {}
        for tp in self.tools.values():
            if not tp.gated:
                continue
            key = (tp.cap, tp.expires_in_s, tp.expires_at)
            if self.logs.setdefault(tp.log, key) != key:
                raise PolicyError(f"log {tp.log!r}: gated tools that share it disagree on cap/expiry")
        # paths
        p = doc.get("paths") or {}
        _keys(p, "paths", optional=("hidden_paths", "visible_paths", "readonly_paths", "mcp_root", "agent_root",
                                    "keep_commit_messages"))
        self.hidden = PathSet(p.get("hidden_paths") or [], "hidden_paths")
        # visible_paths absent: everything except hidden_paths. Present: ONLY matches, minus hidden.
        self.visible = PathSet(p["visible_paths"], "visible_paths") if "visible_paths" in p else None
        if self.visible is not None and not self.visible.patterns:
            raise PolicyError("paths.visible_paths must not be empty (omit it instead)")
        ro = p.get("readonly_paths") or []
        if isinstance(ro, list) and "forge.yaml" not in ro:
            ro = list(ro) + ["forge.yaml"]  # the policy file is always read-only in the box
        self.readonly = PathSet(ro, "readonly_paths")
        self.mcp_root = p.get("mcp_root", "/ws")
        self.agent_root = p.get("agent_root", "/workspace")
        self.keep_commit_messages = bool(p.get("keep_commit_messages", False))
        c = doc.get("canary") or {}
        _keys(c, "canary", optional=("egress_targets", "extra_secrets"))
        self.egress_targets = list(c.get("egress_targets") or ["1.1.1.1:443", "8.8.8.8:53", "example.com:443"])
        self.extra_secrets = list(c.get("extra_secrets") or [])
        a = doc.get("agent") or {}
        _keys(a, "agent", optional=("egress_allow",))
        self.egress_allow = list(a.get("egress_allow") or [])
        for hp in self.egress_allow:
            if not isinstance(hp, str) or not re.fullmatch(r"[A-Za-z0-9.-]{1,253}:[0-9]{1,5}", hp):
                raise PolicyError(f"agent.egress_allow entry {hp!r} must be host:port")
        self.env_names = env_refs(doc)
        # The policy file itself is never writable by the agent and never synced back.
        self.protected = PathSet(["forge.yaml"], "protected")

    @staticmethod
    def load_doc(path):
        import yaml  # only the airlock image needs PyYAML; the host side passes parsed JSON
        with open(path, "rb") as f:
            raw = f.read()
        try:
            return yaml.safe_load(raw)
        except yaml.YAMLError as e:
            raise PolicyError(f"forge.yaml does not parse: {e}") from None

    @staticmethod
    def load(path, resolve=True):
        return Policy(Policy.load_doc(path), resolve=resolve)

    def secrets(self):
        """Every credential value held on the airlock side (for the canary)."""
        out = list(self.extra_secrets)
        for u in self.upstreams.values():
            for d in (u.get("env") or {}, u.get("headers") or {}):
                for v in d.values():
                    v = str(v)
                    out.append(v)
                    out.extend(x for x in re.split(r"[\s:=]+", v) if len(x) >= 8)
        return sorted(set(x for x in out if len(x) >= 8))

    # ------------------------------------------------------------ path checks
    def is_hidden(self, rel):
        """A file path the agent must not see: hidden wins over visible; with visible_paths
        set, anything that does not match it is hidden too (default deny for code)."""
        rel = rel.strip("/")
        if rel in ("", "."):
            return False
        if self.hidden.match(rel):
            return True
        return self.visible is not None and not self.visible.match(rel)

    def visible_dir(self, rel, basename_ok=True):
        """A directory that may be listed because a visible pattern may lie below it.
        Callers apply this only to directories (see _path_hidden)."""
        if self.visible is None:
            return True
        rel = rel.strip("/")
        if rel in ("", "."):
            return True
        for pat in self.visible.patterns:
            if "/" not in pat.rstrip("/"):
                if basename_ok:
                    return True  # basename pattern: may match at any depth
                continue
            lit = []
            for seg in pat.split("/"):
                if any(c in seg for c in "*?["):
                    break
                lit.append(seg)
            prefix = "/".join(lit)
            if prefix == rel or prefix.startswith(rel + "/"):
                return True
        return False

    def _path_hidden(self, rel, is_dir=True, basename_ok=True):
        if self.hidden.match(rel):
            return True
        return self.is_hidden(rel) and not (is_dir and self.visible_dir(rel, basename_ok))

    def check_path(self, raw, mode):
        """Canonicalize a path argument against mcp_root and apply hidden/readonly rules.

        Returns the path relative to the root. Both the lexical form and the
        realpath form (after symlinks) must pass."""
        if not isinstance(raw, str) or "\x00" in raw:
            raise Refusal("FORGE_PATH_REFUSED", "path argument must be a string without NUL")
        root = os.path.realpath(self.mcp_root)
        p = raw
        if p.startswith(self.agent_root.rstrip("/") + "/") or p == self.agent_root:
            p = p[len(self.agent_root):]
        elif p.startswith("/"):
            raise Refusal("FORGE_PATH_OUTSIDE", f"absolute path {raw!r} is outside the workspace")
        lexical = posixpath.normpath("/" + p.lstrip("/"))  # resolves '..' without escaping '/'
        if posixpath.normpath(p.lstrip("/") or ".").startswith(".."):
            raise Refusal("FORGE_PATH_OUTSIDE", f"path {raw!r} escapes the workspace")
        lex_rel = lexical.lstrip("/")
        real = os.path.realpath(os.path.join(root, p.lstrip("/")))
        if real != root and not real.startswith(root + "/"):
            raise Refusal("FORGE_PATH_OUTSIDE", f"path {raw!r} resolves outside the workspace")
        real_rel = os.path.relpath(real, root)
        real_rel = "" if real_rel == "." else real_rel
        is_dir = os.path.isdir(real)
        for rel in (lex_rel, real_rel):
            if self._path_hidden(rel, is_dir):
                raise Refusal("FORGE_PATH_HIDDEN", f"path {raw!r} is hidden by policy")
            if rel == ".git" or rel.startswith(".git/"):
                raise Refusal("FORGE_PATH_REFUSED", f"path {raw!r} is inside .git")
            if mode == "write" and (self.readonly.match(rel) or self.readonly.closes_dir(rel)
                                    or self.protected.match(rel)):
                raise Refusal("FORGE_PATH_READONLY", f"path {raw!r} is read-only by policy")
        return real_rel

    def check_revpath(self, raw):
        if not isinstance(raw, str) or ":" not in raw:
            raise Refusal("FORGE_PATH_REFUSED", "git spec must be '<rev>:<path>'")
        rev, path = raw.split(":", 1)
        if not re.fullmatch(r"[A-Za-z0-9_./~^@{}-]{1,100}", rev) or rev.startswith("-"):
            raise Refusal("FORGE_PATH_REFUSED", "bad revision in git spec")
        lexical = posixpath.normpath("/" + path).lstrip("/")
        if path.startswith("/") or posixpath.normpath(path or ".").startswith(".."):
            raise Refusal("FORGE_PATH_OUTSIDE", "git path escapes the repository")
        if lexical not in ("", ".") and self._path_hidden(lexical, True, basename_ok=False):
            raise Refusal("FORGE_PATH_HIDDEN", f"git path {path!r} is hidden by policy")
        return raw

    # ------------------------------------------------------------ call check
    def check_call(self, name, args):
        """Static checks for one tools/call. Returns (ToolPolicy, arguments to forward).

        A path argument may be a string or a list of strings; every element is checked."""
        if name in self.deny:
            raise Refusal("FORGE_TOOL_BLOCKED", f"tool {name!r} is denied by policy", tool=name)
        tp = self.tools.get(name)
        if tp is None:
            raise Refusal("FORGE_TOOL_BLOCKED", f"tool {name!r} is not listed in policy (default deny)", tool=name)
        if not isinstance(args, dict):
            raise Refusal("FORGE_ARG_REFUSED", "arguments must be an object")
        if tp.strict_args:
            extra = set(args) - tp.known_args()
            if extra:
                raise Refusal("FORGE_ARG_REFUSED", f"arguments not declared in policy: {sorted(extra)}")
        for r in tp.rules:
            r.check(args)
        fwd = dict(args)
        root = os.path.realpath(self.mcp_root)
        for k, mode in tp.path_args.items():
            if k not in args:
                continue
            vals = args[k] if isinstance(args[k], list) else [args[k]]
            out = []
            for v in vals:
                if mode == "git_revpath":
                    out.append(self.check_revpath(v))
                else:  # forward the canonical absolute path, not the agent's spelling
                    rel = self.check_path(v, mode)
                    out.append(os.path.join(root, rel) if rel else root)
            fwd[k] = out if isinstance(args[k], list) else out[0]
        return tp, fwd


def canonical_json(v):
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def main(argv):
    """policy.py check <forge.yaml>: validate without secrets and print the parsed document
    as JSON (names of ${VARS} kept). Used by forge_airlock.py on the host. Exit 2 if invalid."""
    if len(argv) != 3 or argv[1] != "check":
        print("usage: policy.py check <forge.yaml>", file=sys.stderr)
        return 2
    try:
        doc = Policy.load_doc(argv[2])
        Policy(doc, resolve=False)
    except (PolicyError, OSError) as e:
        print(json.dumps({"ok": False, "error": str(e)}))
        return 2
    print(json.dumps({"ok": True, "doc": doc}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
