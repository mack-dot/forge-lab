# mcp_client.py - minimal MCP clients for upstream servers on the airlock side.
#
# Label: NATIVE CHECK (hand-written, not proved, not a full MCP implementation).
# Built: JSON-RPC 2.0 over stdio (newline-delimited) and over HTTP POST (a subset of
# MCP "Streamable HTTP": a JSON response, or an SSE body whose first matching 'data:'
# line is read). Not built: sessions (Mcp-Session-Id), server-to-client requests,
# resumable SSE streams, notifications other than notifications/initialized,
# resources, prompts, sampling, cancellation.
import itertools
import json
import os
import subprocess
import threading
import urllib.error
import urllib.request

PROTOCOL = "2025-06-18"


class UpstreamError(Exception):
    pass


class StdioUpstream:
    def __init__(self, name, command, env=None, timeout_s=10, user=None):
        self.name, self.timeout = name, timeout_s
        penv = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
        penv.update({k: str(v) for k, v in (env or {}).items()})  # credentials live only here
        self.proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=None, env=penv, text=True, bufsize=1, user=user)
        self._ids = itertools.count(1)
        self._wlock = threading.Lock()
        self._pending = {}
        self._plock = threading.Lock()
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        for line in self.proc.stdout:
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            mid = msg.get("id")
            with self._plock:
                slot = self._pending.pop(mid, None)
            if slot is not None:
                slot[1] = msg
                slot[0].set()
        with self._plock:  # upstream exited: wake every waiter with an error
            for slot in self._pending.values():
                slot[1] = {"error": {"code": -32000, "message": "upstream exited"}}
                slot[0].set()
            self._pending.clear()

    def notify(self, method, params=None):
        with self._wlock:
            self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method, "params": params or {}}) + "\n")
            self.proc.stdin.flush()

    def request(self, method, params=None, timeout=None):
        mid = next(self._ids)
        slot = [threading.Event(), None]
        with self._plock:
            self._pending[mid] = slot
        try:
            with self._wlock:
                self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": mid, "method": method,
                                                  "params": params or {}}) + "\n")
                self.proc.stdin.flush()
        except (OSError, ValueError) as e:
            raise UpstreamError(f"{self.name}: write failed: {e}") from None
        if not slot[0].wait(timeout or self.timeout):
            with self._plock:
                self._pending.pop(mid, None)
            raise UpstreamError(f"{self.name}: timeout after {timeout or self.timeout}s")
        msg = slot[1]
        if "error" in msg:
            raise UpstreamError(f"{self.name}: {msg['error'].get('message')}")
        return msg.get("result")


class HttpUpstream:
    def __init__(self, name, url, headers=None, timeout_s=10):
        self.name, self.url, self.timeout = name, url, timeout_s
        self.headers = {k: str(v) for k, v in (headers or {}).items()}  # credentials live only here
        self._ids = itertools.count(1)

    def _post(self, body, timeout):
        h = {"content-type": "application/json", "accept": "application/json, text/event-stream",
             "mcp-protocol-version": PROTOCOL}
        h.update(self.headers)
        req = urllib.request.Request(self.url, data=json.dumps(body).encode(), headers=h, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                ctype = r.headers.get("content-type", "")
                raw = r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            raise UpstreamError(f"{self.name}: HTTP {e.code}") from None
        except Exception as e:  # noqa: BLE001 - timeouts, resets, DNS
            raise UpstreamError(f"{self.name}: {type(e).__name__}: {str(e)[:120]}") from None
        if not raw:
            return None
        if ctype.startswith("text/event-stream"):
            for line in raw.splitlines():
                if line.startswith("data:"):
                    msg = json.loads(line[5:])
                    if msg.get("id") == body.get("id"):
                        return msg
            raise UpstreamError(f"{self.name}: SSE body without a matching response")
        return json.loads(raw)

    def notify(self, method, params=None):
        self._post({"jsonrpc": "2.0", "method": method, "params": params or {}}, self.timeout)

    def request(self, method, params=None, timeout=None):
        body = {"jsonrpc": "2.0", "id": next(self._ids), "method": method, "params": params or {}}
        msg = self._post(body, timeout or self.timeout)
        if msg is None:
            raise UpstreamError(f"{self.name}: empty response")
        if "error" in msg:
            raise UpstreamError(f"{self.name}: {msg['error'].get('message')}")
        return msg.get("result")


def connect(spec):
    if spec["transport"] == "stdio":
        up = StdioUpstream(spec["name"], spec["command"], spec.get("env"), spec.get("timeout_s", 10), spec.get("user"))
    else:
        up = HttpUpstream(spec["name"], spec["url"], spec.get("headers"), spec.get("timeout_s", 10))
    up.request("initialize", {"protocolVersion": PROTOCOL, "capabilities": {},
                              "clientInfo": {"name": "forge-airlock", "version": "0.1"}})
    up.notify("notifications/initialized")
    tools, cursor = [], None
    while True:
        res = up.request("tools/list", {"cursor": cursor} if cursor else {})
        tools.extend(res.get("tools", []))
        cursor = res.get("nextCursor")
        if not cursor:
            break
    return up, tools
