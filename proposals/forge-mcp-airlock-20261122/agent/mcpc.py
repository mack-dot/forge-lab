# mcpc.py - tiny MCP client used inside the agent container (JSON-RPC over HTTP POST).
import itertools
import json
import os
import urllib.request

URL = os.environ.get("FORGE_AIRLOCK", "http://airlock:8700")
_ids = itertools.count(1)


def http(method, path, body=None, timeout=60):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(URL + path, data=data, method=method, headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"null")


def rpc(method, params=None, timeout=60):
    _, msg = http("POST", "/mcp", {"jsonrpc": "2.0", "id": next(_ids), "method": method, "params": params or {}},
                  timeout)
    return msg


def call(_tool, **args):
    """Returns (ok, forge_code_or_None, payload)."""
    msg = rpc("tools/call", {"name": _tool, "arguments": args})
    if "error" in msg:
        return False, (msg["error"].get("data") or {}).get("forge_code"), msg["error"]
    res = msg["result"]
    return not res.get("isError"), None, res


def text_of(res):
    return "".join(c.get("text", "") for c in res.get("content", []))


def tool_names():
    return {t["name"] for t in rpc("tools/list")["result"]["tools"]}
