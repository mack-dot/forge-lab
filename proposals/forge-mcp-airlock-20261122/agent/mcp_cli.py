# mcp_cli.py - command-line MCP client for a person inside the agent container.
#   mcp list                         tools the airlock exposes
#   mcp call <tool> '<json args>'    call one tool, print the result or the FORGE_* refusal
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mcpc  # noqa: E402

if len(sys.argv) < 2 or sys.argv[1] not in ("list", "call"):
    print(__doc__ or "usage: mcp list | mcp call <tool> '<json>'")
    sys.exit(2)
if sys.argv[1] == "list":
    for t in mcpc.rpc("tools/list")["result"]["tools"]:
        print(f"{t['name']:24} {t.get('description', '')[:90]}")
    sys.exit(0)
args = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
msg = mcpc.rpc("tools/call", {"name": sys.argv[2], "arguments": args})
if "error" in msg:
    print("REFUSED:", msg["error"]["message"])
    sys.exit(1)
print(mcpc.text_of(msg["result"])[:4000])
meta = (msg["result"].get("_meta") or {}).get("forge")
if meta:
    print("forge gate:", json.dumps(meta))
