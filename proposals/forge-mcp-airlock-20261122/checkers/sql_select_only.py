# sql_select_only.py - example external checker hook for the gate.
# Reads {"tool": ..., "arguments": {...}} on stdin. Exit 0 only for a single SELECT.
# Any program can be a checker (for example a compiled verifier); the airlock only reads
# the exit code. NATIVE CHECK, demo quality (a keyword check, not an SQL parser).
import json
import re
import sys

try:
    q = json.load(sys.stdin)["arguments"].get("query", "")
except (ValueError, KeyError, AttributeError):
    sys.exit(3)
if not isinstance(q, str) or ";" in q or not re.fullmatch(r"\s*SELECT\b[^;]*", q, re.I):
    print("only one SELECT statement is allowed", file=sys.stderr)
    sys.exit(1)
if re.search(r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|GRANT|TRUNCATE)\b", q, re.I):
    print("write keyword in query", file=sys.stderr)
    sys.exit(1)
sys.exit(0)
