#!/usr/bin/env python3
# list_tools.py <forge.yaml> - start every upstream of forge.yaml (airlock side, with the
# credentials named in it) and print {upstream: [tools]} as JSON. Used by `forge tools` so
# that `forge init` and /forge-airlock:airlock can classify real tool names. NATIVE CHECK.
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mcp_client  # noqa: E402
from policy import Policy, PolicyError  # noqa: E402


def main():
    try:
        pol = Policy.load(sys.argv[1])
    except (PolicyError, OSError) as e:
        print(json.dumps({"ok": False, "error": str(e)}))
        return 2
    out, errors = {}, {}
    for name, spec in pol.upstreams.items():
        try:
            _, tools = mcp_client.connect(spec)
            out[name] = [{"name": t.get("name"), "description": (t.get("description") or "")[:300],
                          "inputSchema": t.get("inputSchema") or {}} for t in tools]
        except Exception as e:  # noqa: BLE001
            errors[name] = f"{type(e).__name__}: {str(e)[:200]}"
    print(json.dumps({"ok": not errors, "tools": out, "errors": errors}))
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
