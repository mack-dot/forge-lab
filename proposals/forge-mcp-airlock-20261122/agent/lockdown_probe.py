# lockdown_probe.py - after a canary BREACH, every tools/call must be refused with
# FORGE_BREACH_LOCKDOWN (even an allowed read). Exit 0 if so. FINITE TEST.
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mcpc  # noqa: E402

ok, code, _ = mcpc.call(sys.argv[1] if len(sys.argv) > 1 else "read_file", path="src/ui.ts")
print(f"[lockdown] allowed tool after BREACH -> ok={ok} code={code}")
sys.exit(0 if (not ok and code == "FORGE_BREACH_LOCKDOWN") else 1)
