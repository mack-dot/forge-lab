#!/usr/bin/env python3
"""Unit tests of forge-airlock that need no Docker: policy validation, path rules (hidden,
visible, read-only), the diff sync-back filter, the persistent verifier (memo on and off give
the SAME verdict as a fresh subprocess), gate decisions through it, and the forge.yaml draft
(no secret values). Needs python3 and git; PyYAML is optional (YAML parsing cases are skipped
without it). Prints one line per case; exit 0 only if every case passes. Label: FINITE TEST."""
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(HERE, "..")
sys.path.insert(0, os.path.join(PKG, "engine"))
sys.path.insert(0, PKG)
import draft as D  # noqa: E402
import gatelog  # noqa: E402
import records as R  # noqa: E402
import sync  # noqa: E402
from policy import Policy, PolicyError, Refusal  # noqa: E402

RESULTS = []


def case(name, ok, detail=""):
    RESULTS.append(ok)
    print(("ok    " if ok else "FAIL  ") + name + ("" if ok else f"   {detail}"), flush=True)


def raises(fn, exc=PolicyError, contains=""):
    try:
        fn()
    except exc as e:
        return contains in str(e) or contains in getattr(e, "code", "")
    return False


def base_doc(**over):
    d = {"version": 1,
         "upstreams": [{"name": "fs", "transport": "stdio", "command": ["node", "x.js", "/ws"]},
                       {"name": "pay", "transport": "http", "url": "http://pay:1/mcp",
                        "headers": {"Authorization": "Bearer ${PAY_KEY}"}}],
         "tools": {"allow": [{"tool": "read_file", "upstream": "fs", "path_args": {"path": "read"}},
                             {"tool": "write_file", "upstream": "fs", "path_args": {"path": "write"}}],
                   "deny": ["delete_path"],
                   "gate": [{"tool": "charge", "upstream": "pay", "unit": "value", "value_field": "amount",
                             "cap": 1000, "expires_in_s": 3600}]},
         "paths": {"hidden_paths": ["src/proprietary/**", ".env*"], "readonly_paths": ["tests/**"]}}
    d.update(over)
    return d


def test_policy():
    env = {"PAY_KEY": "FAKE_pay_key_not_real_1234"}
    p = Policy(base_doc(), environ=env)
    case("policy: a valid forge.yaml loads", len(p.tools) == 3 and p.deny == ["delete_path"])
    case("policy: ${PAY_KEY} resolves on the airlock side only",
         p.upstreams["pay"]["headers"]["Authorization"] == "Bearer FAKE_pay_key_not_real_1234")
    case("policy: the host side keeps the NAME (resolve=False reads no secret)",
         Policy(base_doc(), resolve=False).upstreams["pay"]["headers"]["Authorization"] == "Bearer ${PAY_KEY}"
         and Policy(base_doc(), resolve=False).env_names == ["PAY_KEY"])
    case("policy: a named secret that is not set stops the start (fail closed)",
         raises(lambda: Policy(base_doc(), environ={}), contains="PAY_KEY is not set"))
    case("policy: resolved secrets are known to the canary", "FAKE_pay_key_not_real_1234" in p.secrets())
    bad = base_doc()
    bad["tools"]["deny"] = ["read_file"]
    case("policy: allow and deny of one tool is refused", raises(lambda: Policy(bad, environ=env), contains="both"))
    case("policy: an unknown key is refused", raises(lambda: Policy(base_doc(extra=1), environ=env),
                                                     contains="unknown keys"))
    case("policy: version 2 is refused", raises(lambda: Policy(base_doc(version=2), environ=env)))
    g = base_doc()
    g["tools"]["gate"][0].pop("expires_in_s")
    case("policy: a gate without expiry is refused", raises(lambda: Policy(g, environ=env), contains="exactly one"))
    g = base_doc()
    g["tools"]["gate"][0].pop("value_field")
    case("policy: unit=value without value_field is refused", raises(lambda: Policy(g, environ=env)))
    case("policy: agent.egress_allow must be host:port",
         raises(lambda: Policy(base_doc(agent={"egress_allow": ["https://x"]}), environ=env), contains="host:port")
         and Policy(base_doc(agent={"egress_allow": ["api.anthropic.com:443"]}), environ=env).egress_allow
         == ["api.anthropic.com:443"])
    case("policy: forge.yaml itself is always read-only", p.readonly.match("forge.yaml"))
    # default deny and argument rules
    case("policy: an unlisted tool is refused FORGE_TOOL_BLOCKED",
         raises(lambda: p.check_call("rotate", {}), Refusal, "FORGE_TOOL_BLOCKED"))
    case("policy: a denied tool is refused FORGE_TOOL_BLOCKED",
         raises(lambda: p.check_call("delete_path", {"path": "a"}), Refusal, "FORGE_TOOL_BLOCKED"))
    try:
        import yaml  # noqa: F401
        tmp = tempfile.mkdtemp()
        open(os.path.join(tmp, "forge.yaml"), "w").write(D.HEADER + D.to_yaml(base_doc()))
        ok = Policy.load(os.path.join(tmp, "forge.yaml"), resolve=False).env_names == ["PAY_KEY"]
        r = subprocess.run([sys.executable, os.path.join(PKG, "engine", "policy.py"), "check",
                            os.path.join(tmp, "forge.yaml")], capture_output=True, text=True)
        case("policy: the YAML that draft.to_yaml writes parses back to the same document",
             ok and json.loads(r.stdout)["doc"] == base_doc() and r.returncode == 0)
        open(os.path.join(tmp, "forge.yaml"), "w").write("version: 1\nupstreams: []\ntools: {}\n")
        r = subprocess.run([sys.executable, os.path.join(PKG, "engine", "policy.py"), "check",
                            os.path.join(tmp, "forge.yaml")], capture_output=True, text=True)
        case("policy: policy.py check exits 2 on an invalid file", r.returncode == 2 and '"ok": false' in r.stdout)
        shutil.rmtree(tmp)
    except ImportError:
        print("skip  policy: YAML round trip (PyYAML not installed on this host; it is in the image)")


def test_paths():
    tmp = tempfile.mkdtemp()
    for rel in ["src/app.ts", "src/proprietary/core.ts", "src/ui/button.ts", "src/ui/secret.ts", "tests/a.test.ts",
                "README.md", ".env.local", "deep/x/.env"]:
        os.makedirs(os.path.dirname(os.path.join(tmp, rel)) or tmp, exist_ok=True)
        open(os.path.join(tmp, rel), "w").write("x\n")
    os.symlink("proprietary/core.ts", os.path.join(tmp, "src/link.ts"))
    doc = base_doc()
    doc["paths"]["mcp_root"] = tmp
    p = Policy(doc, environ={"PAY_KEY": "k" * 10})
    case("paths: hidden directory pattern matches files below it", p.is_hidden("src/proprietary/core.ts"))
    case("paths: a basename pattern (.env*) matches at any depth", p.is_hidden(".env.local") and p.is_hidden("deep/x/.env"))
    case("paths: a public file is visible", not p.is_hidden("src/app.ts"))
    case("paths: '..' that leaves the workspace is refused FORGE_PATH_OUTSIDE",
         raises(lambda: p.check_path("../etc/passwd", "read"), Refusal, "FORGE_PATH_OUTSIDE"))
    case("paths: an absolute path outside the workspace is refused",
         raises(lambda: p.check_path("/etc/passwd", "read"), Refusal, "FORGE_PATH_OUTSIDE"))
    case("paths: a symlink to hidden code is refused after realpath()",
         raises(lambda: p.check_path("src/link.ts", "read"), Refusal, "FORGE_PATH_HIDDEN"))
    case("paths: 'src/../src/proprietary/core.ts' is refused",
         raises(lambda: p.check_path("src/../src/proprietary/core.ts", "read"), Refusal, "FORGE_PATH_HIDDEN"))
    case("paths: a write to a read-only path is refused FORGE_PATH_READONLY",
         raises(lambda: p.check_path("tests/a.test.ts", "write"), Refusal, "FORGE_PATH_READONLY")
         and raises(lambda: p.check_path("tests/new.ts", "write"), Refusal, "FORGE_PATH_READONLY")
         and raises(lambda: p.check_path("forge.yaml", "write"), Refusal, "FORGE_PATH_READONLY"))
    case("paths: a read of a read-only path is allowed", p.check_path("tests/a.test.ts", "read") == "tests/a.test.ts")
    case("paths: .git is refused", raises(lambda: p.check_path(".git/config", "read"), Refusal, "FORGE_PATH_REFUSED"))
    case("paths: git_revpath with a hidden path is refused",
         raises(lambda: p.check_revpath("HEAD~2:.env.local"), Refusal, "FORGE_PATH_HIDDEN"))
    vdoc = base_doc()
    vdoc["paths"] = {"hidden_paths": ["src/ui/secret.ts"], "visible_paths": ["src/ui/**", "README.md"],
                     "mcp_root": tmp}
    v = Policy(vdoc, environ={"PAY_KEY": "k" * 10})
    case("paths: visible_paths keeps only matching files", not v.is_hidden("src/ui/button.ts")
         and v.is_hidden("src/app.ts") and v.is_hidden("tests/a.test.ts") and not v.is_hidden("README.md"))
    case("paths: hidden wins over visible", v.is_hidden("src/ui/secret.ts"))
    case("paths: with visible_paths, a read outside it is refused",
         raises(lambda: v.check_path("src/app.ts", "read"), Refusal, "FORGE_PATH_HIDDEN"))
    case("paths: with visible_paths, an empty list is refused",
         raises(lambda: Policy(dict(vdoc, paths={"visible_paths": []}), environ={"PAY_KEY": "k" * 10})))
    shutil.rmtree(tmp)


def test_sync():
    tmp = tempfile.mkdtemp()
    real, stage, exp = (os.path.join(tmp, x) for x in ("real", "stage", "export"))
    files = {"src/app.ts": "a\n", "src/proprietary/core.ts": "secret\n", "tests/a.test.ts": "t\n",
             "README.md": "r\n", "keep.txt": "k\n", "conflict.txt": "base\n", "gone.txt": "g\n"}
    for root in (real, stage):
        for rel, txt in files.items():
            os.makedirs(os.path.dirname(os.path.join(root, rel)), exist_ok=True)
            open(os.path.join(root, rel), "w").write(txt)
    open(os.path.join(real, "conflict.txt"), "w").write("you changed it meanwhile\n")
    os.makedirs(os.path.join(tmp, "outside"))
    os.symlink(os.path.join(tmp, "outside"), os.path.join(real, "linkdir"))
    os.makedirs(os.path.join(exp, "files"))
    news = {}

    def ch(rel, status, txt=None, symlink=False):
        c = {"path": rel, "status": status, "symlink": symlink}
        if txt is not None:
            n = len(news) + 1
            news[n] = txt.encode()
            open(os.path.join(exp, "files", str(n)), "wb").write(news[n])
            c.update(file=f"files/{n}", sha256=__import__("hashlib").sha256(news[n]).hexdigest(), mode="100644")
        return c
    changes = [ch("src/app.ts", "modified", "a\nb\n"), ch("src/new.ts", "added", "n\n"),
               ch("src/proprietary/core.ts", "modified", "agent overwrote it\n"),
               ch(".env", "added", "PAY=evil\n"), ch("tests/a.test.ts", "modified", "weakened\n"),
               ch("forge.yaml", "added", "version: 1\n"), ch("conflict.txt", "modified", "agent\n"),
               ch("gone.txt", "deleted"), ch("node_modules/x.js", "added", "x\n"),
               ch("linkdir/escape.txt", "added", "out\n"), ch("src/sym", "added", "/etc/passwd", symlink=True),
               ch(".mcp.json", "added", "{}\n")]
    doc = base_doc()
    pol = Policy(doc, resolve=False)
    apply, rejected = sync.plan(pol, changes, exp, stage, real, ignored=lambda rel: rel.startswith("node_modules/"))
    got = {c["path"] for c in apply}
    rej = dict(rejected)
    case("sync: allowed changes are proposed (modified, added, deleted)",
         got == {"src/app.ts", "src/new.ts", "gone.txt", ".mcp.json"}, got)
    case("sync: a change to a hidden path is never applied", "src/proprietary/core.ts" in rej and ".env" in rej)
    case("sync: a change to a read-only path is never applied (incl. forge.yaml)",
         "tests/a.test.ts" in rej and "forge.yaml" in rej)
    case("sync: your own change since the start is not overwritten", "conflict.txt" in rej)
    case("sync: ignored files (node_modules) are not applied", "node_modules/x.js" in rej)
    case("sync: a write through a symlinked parent in the real repository is refused", "linkdir/escape.txt" in rej)
    case("sync: symlinks are never applied", "src/sym" in rej)
    text = sync.render(apply)
    case("sync: the review flags .mcp.json as sensitive", "SENSITIVE" in text and "+b" in text)
    before = {rel: open(os.path.join(real, rel)).read() for rel in files if os.path.exists(os.path.join(real, rel))}
    sync.apply_changes(apply, real)
    case("sync: apply writes only the proposed files",
         open(os.path.join(real, "src/app.ts")).read() == "a\nb\n" and not os.path.exists(os.path.join(real, "gone.txt"))
         and open(os.path.join(real, "src/proprietary/core.ts")).read() == before["src/proprietary/core.ts"]
         and open(os.path.join(real, "tests/a.test.ts")).read() == before["tests/a.test.ts"]
         and not os.path.exists(os.path.join(real, ".env"))
         and not os.path.exists(os.path.join(tmp, "outside", "escape.txt")))
    bad = [dict(changes[0], sha256="0" * 64)]
    a2, r2 = sync.plan(pol, bad, exp, stage, real)
    case("sync: content that does not match its hash is refused", not a2 and r2)
    shutil.rmtree(tmp)


def make_log(n, cap=10 ** 6):
    exp = int(time.time()) + 86400
    man = R.manifest_bytes(R.sha(b"t"), cap, exp)
    recs = [R.genesis(cap, exp, man)]
    for i in range(1, n):
        recs.append(R.step(os.urandom(16), 1, i, int(time.time()), recs[-1], i))
    return man, recs


def test_verifier():
    tmp = tempfile.mkdtemp()
    man, recs = make_log(40, cap=30)
    open(os.path.join(tmp, "m"), "wb").write(man)
    rng = random.Random(7)
    logs = [b"".join(recs[:k]) for k in (1, 2, 10, 30, 31, 40)]  # 31+ records: over the cap of 30
    good = b"".join(recs[:20])
    for _ in range(14):  # one flipped byte anywhere
        b = bytearray(good)
        i = rng.randrange(len(b))
        b[i] ^= 1 << rng.randrange(8)
        logs.append(bytes(b))
    logs.append(good + recs[5])                       # replayed record
    logs.append(good[:-5])                            # torn tail
    logs.append(good[:128 * 3] + good[128 * 4:])      # gap in seq
    dup = R.step(recs[3][48:64], 1, 20, int(time.time()), recs[19], 20)
    logs.append(good + dup)                           # duplicate step id
    now = int(time.time())
    pv_memo, same, verdicts = R.PersistentVerifier(), True, set()
    os.environ["FORGE_VERIFIER_MEMO"] = "0"
    pv_plain = R.PersistentVerifier()
    os.environ["FORGE_VERIFIER_MEMO"] = "1"
    for round_ in range(2):  # the 2nd round hits the memo table for every record seen before
        for i, lg in enumerate(logs):
            path = os.path.join(tmp, f"l{i}")
            open(path, "wb").write(lg)
            a = R.verify_file_fresh(path, os.path.join(tmp, "m"), now)
            b = pv_memo.verify(path, os.path.join(tmp, "m"), now)
            c = pv_plain.verify(path, os.path.join(tmp, "m"), now)
            verdicts.add(a["verdict"])
            if not (a == b == c):
                same = False
                print("      differs:", i, a.get("verdict"), b.get("verdict"), c.get("verdict"))
    case(f"verifier: persistent+memo, persistent and fresh subprocess give identical JSON on {len(logs)} logs x 2 "
         f"(verdicts seen: {', '.join(sorted(verdicts))})", same and "ACCEPT" in verdicts and len(verdicts) >= 4)
    case("verifier: the memo table was used (hits > 0)", pv_memo.last_memo.get("hits", 0) > 0, pv_memo.last_memo)
    pv_memo.proc.kill()
    pv_memo.proc.wait()
    r = pv_memo.verify(os.path.join(tmp, "l0"), os.path.join(tmp, "m"), now)
    case("verifier: a killed verifier process is restarted (next call still verified)", r["verdict"] == "ACCEPT", r)
    pv_memo.timeout = 0.000001
    r = pv_memo.verify(os.path.join(tmp, "l3"), os.path.join(tmp, "m"), now)
    case("verifier: no answer in time gives UNVERIFIABLE_INTERNAL (fail closed)",
         r["verdict"] == "UNVERIFIABLE_INTERNAL", r)
    pv_memo.close()
    pv_plain.close()
    # gate decisions through the persistent verifier
    d = os.path.join(tmp, "data")
    os.makedirs(d)
    log = gatelog.GateLog(d, "deploy", 3, 3600, None)
    vs = []
    for _ in range(4):
        v, seq, _g = log.reserve(1, os.urandom(16), {"tool": "deploy"})
        vs.append(v)
        if seq:
            log.finish(seq, True)
    case("gate: count cap 3 -> 3 ACCEPT, the 4th REJECT_OVER_CAP", vs == ["ACCEPT"] * 3 + ["REJECT_OVER_CAP"], vs)
    v = gatelog.GateLog(d, "pay", 1000, 3600, None)
    sid = os.urandom(16)
    a1 = v.reserve(600, sid, {})[0]
    a2 = v.reserve(100, sid, {})[0]
    a3 = v.reserve(401, os.urandom(16), {})[0]
    a4 = v.reserve(400, os.urandom(16), {})[0]
    case("gate: value cap 1000: 600 ok, replayed id REJECT_DUPLICATE_ID, 401 over, 400 ok",
         [a1, a2, a3, a4] == ["ACCEPT", "REJECT_DUPLICATE_ID", "REJECT_OVER_CAP", "ACCEPT"], [a1, a2, a3, a4])
    again = gatelog.GateLog(d, "deploy", 3, 3600, None)
    case("gate: after a reload the cap is still reached", again.reserve(1, os.urandom(16), {})[0] == "REJECT_OVER_CAP")
    case("gate: a reload with a different cap is refused",
         raises(lambda: gatelog.GateLog(d, "deploy", 4, 3600, None), gatelog.GateError, "stored cap"))
    with open(os.path.join(d, "deploy.bin"), "r+b") as f:
        f.seek(128 * 2 + 72)
        b = f.read(1)
        f.seek(128 * 2 + 72)
        f.write(bytes([b[0] ^ 1]))
    case("gate: one flipped log byte -> the log is refused at load",
         raises(lambda: gatelog.GateLog(d, "deploy", 3, 3600, None), gatelog.GateError, "does not verify"))
    shutil.rmtree(tmp)


def test_draft():
    tmp = tempfile.mkdtemp()
    repo = os.path.join(tmp, "r")
    for rel in ["src/app.ts", "src/proprietary/core.ts", "tests/a.test.ts", "infra/main.tf", ".env",
                "spec/api.md", "INVARIANTS.md", ".forge/forge.json", "node_modules/x.js"]:
        os.makedirs(os.path.dirname(os.path.join(repo, rel)) or repo, exist_ok=True)
        open(os.path.join(repo, rel), "w").write("x\n")
    open(os.path.join(repo, ".gitignore"), "w").write("node_modules/\n")
    secret = "FAKE_ghp_literal_value_DO_NOT_COPY_123456"
    json.dump({"mcpServers": {
        "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"],
                   "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": secret}},
        "stripe": {"type": "http", "url": "https://mcp.example.invalid/mcp",
                   "headers": {"Authorization": "Bearer ${STRIPE_KEY}"}}}}, open(os.path.join(repo, ".mcp.json"), "w"))
    subprocess.run(["git", "init", "-q", repo], check=True)
    tools = {"github": [{"name": "get_issue"}, {"name": "list_commits"}, {"name": "delete_repository"},
                        {"name": "create_pull_request"}, {"name": "frobnicate"}],
             "stripe": [{"name": "create_refund", "inputSchema": {"properties": {"amount": {"type": "integer"}}}},
                        {"name": "retrieve_balance"}]}
    doc, notes, questions = D.draft(repo, tools)
    text = D.HEADER + D.to_yaml(doc)
    case("draft: no secret value from .mcp.json reaches forge.yaml", secret not in text and secret not in json.dumps(
        [notes, questions]))
    case("draft: secrets are named ${NAME} only", "${GITHUB_PERSONAL_ACCESS_TOKEN}" in text and "${STRIPE_KEY}" in text)
    case("draft: hidden paths proposed (.env*, infra/**, proprietary)",
         {".env*", "infra/**", "src/proprietary/**"} <= set(doc["paths"]["hidden_paths"]), doc["paths"])
    case("draft: read-only paths proposed (tests, spec, .forge, INVARIANTS.md)",
         {"tests/**", "spec/**", ".forge/**", "INVARIANTS.md"} <= set(doc["paths"]["readonly_paths"]), doc["paths"])
    case("draft: ignored files are not scanned (node_modules)", not any("node_modules" in json.dumps(q)
                                                                       for q in questions))
    allow = {t["tool"] for t in doc["tools"]["allow"]}
    gate = {t["tool"]: t for t in doc["tools"]["gate"]}
    case("draft: read-like tools allowed", {"get_issue", "list_commits", "retrieve_balance"} <= allow, allow)
    case("draft: destructive tools denied", "delete_repository" in doc["tools"]["deny"])
    case("draft: money tool gated by value with a cap", gate.get("create_refund", {}).get("unit") == "value"
         and gate["create_refund"]["value_field"] == "amount" and gate["create_refund"]["cap"] > 0)
    case("draft: side-effect tool gated by count", gate.get("create_pull_request", {}).get("unit") == "count")
    case("draft: unknown tool left out (default deny) and asked about",
         "frobnicate" not in allow | set(gate) | set(doc["tools"]["deny"])
         and any(q.get("tool") == "frobnicate" and q["proposal"] == "ask" for q in questions))
    pol = Policy(doc, resolve=False)
    case("draft: the draft is a valid policy", set(pol.env_names) == {"GITHUB_PERSONAL_ACCESS_TOKEN", "STRIPE_KEY"})
    r = subprocess.run([sys.executable, os.path.join(PKG, "forge_airlock.py"), "init", "--repo", repo, "--json"],
                       capture_output=True, text=True)
    case("draft: `forge init --json` runs without Docker and leaks no value",
         r.returncode == 0 and secret not in r.stdout and "forge_yaml" in json.loads(r.stdout), r.stderr[-300:])
    shutil.rmtree(tmp)


def test_static():
    cmd = open(os.path.join(PKG, "commands", "airlock.md")).read()
    case("static: commands/airlock.md has description front matter", cmd.startswith("---\ndescription:"))
    case("static: the command uses AskUserQuestion and never asks for secret values",
         "AskUserQuestion" in cmd and "never" in cmd.lower())
    man = json.load(open(os.path.join(PKG, ".claude-plugin", "plugin.json")))
    case("static: plugin.json names the plugin forge-airlock", man.get("name") == "forge-airlock")
    bad = []
    for d, dirs, fs in os.walk(PKG):
        dirs[:] = [x for x in dirs if x not in ("__pycache__", "results")]
        for f in fs:
            try:
                t = open(os.path.join(d, f), encoding="utf-8").read()
            except (UnicodeDecodeError, OSError):
                continue
            if "/" + "Users/" in t:
                bad.append(os.path.relpath(os.path.join(d, f), PKG))
    case("static: no absolute host home path in the package", not bad, bad)


def main():
    for t in (test_policy, test_paths, test_sync, test_verifier, test_draft, test_static):
        try:
            t()
        except Exception as e:  # noqa: BLE001
            case(f"{t.__name__} crashed: {type(e).__name__}: {e}", False)
    failed = RESULTS.count(False)
    print(f"{len(RESULTS)} cases, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
