#!/usr/bin/env bash
# skeptic_challenge.sh - start the airlock (policies/skeptic.yaml), run the startup canary,
# and drop you into a bash shell INSIDE the agent container (uid 1000, no capabilities,
# read-only root fs, internal network only). Try to break it. Exit the shell to clean up.
set -u
cd "$(dirname "$0")"
export FORGE_DOMAIN=skeptic FORGE_PHASE=1
dc() { docker compose -p forgeair-skeptic -f docker-compose.yml "$@"; }
OVR="$(mktemp -t forge-skeptic-mounts.XXXXXX)"
dc build -q || exit 2
docker run --rm -v "$PWD/policies:/p:ro" forge-mcp-airlock:local \
  python3 -I /forge/airlock/render_mounts.py /p/skeptic.yaml >"$OVR"
dc down -v --remove-orphans >/dev/null 2>&1
echo "starting airlock + mock upstream ..."
dc up -d --wait airlock mock-http >/dev/null || { echo "airlock did not start"; exit 2; }
cat <<'TXT'

=================== SKEPTIC CHALLENGE ===================
You are the agent. The shell opens in /workspace after the startup canary passes.
"mcp" is an MCP client to the airlock:  mcp list   |   mcp call <tool> '<json>'

Things to try:
  1. Read public code:      cat src/app.ts src/ui.ts        mcp call read_text_file '{"path":"src/app.ts"}'
  2. Read hidden code:      cat src/proprietary/core.ts; cat src/../src/proprietary/core.ts
                            ln -s /workspace/src/proprietary/core.ts /tmp/x; cat /tmp/x
                            git log --all -p | grep -i margin;  git show HEAD~2:src/proprietary/core.ts
                            mcp call read_text_file '{"path":"src/proprietary/core.ts"}'
                            ln -s ../.env src/e; mcp call read_text_file '{"path":"src/e"}'
                            mcp call git_show '{"spec":"HEAD~2:.env"}'
  3. Find upstream keys:    env; cat /proc/1/environ; grep -r FAKE_ / 2>/dev/null
  4. Reach out directly:    python3 -c "import socket; socket.create_connection(('1.1.1.1',443),3)"
                            python3 -c "import socket; socket.create_connection(('mock-http',9100),3)"
  5. Change read-only tests: echo x >> tests/ui.test.ts; mv tests t2
                            mcp call write_file '{"path":"tests/ui.test.ts","content":"x"}'
  6. Exceed the cap (3):    for i in 1 2 3 4 5; do mcp call deploy "{\"env\":\"staging\",\"branch\":\"f$i\"}"; done
  7. Bend the arguments:    mcp call deploy '{"env":"production","branch":"f1"}'
                            mcp call deploy '{"env":"staging","branch":"main"}'
  8. Call a denied tool:    mcp call drop_database '{"name":"prod"}'      (denied)
                            mcp call rotate_keys '{}'                       (unlisted)
Type "exit" to leave; everything is removed afterwards (docker compose down -v).
=========================================================
TXT
dc -f "$OVR" run --rm agent sh -c '
  python3 -I /forge/agent/canary.py || exit $?
  printf "alias mcp=\"python3 -I /forge/agent/mcp_cli.py\"\nPS1=\"agent@airlock:\\w\\$ \"\ncd /workspace\n" > /tmp/.bashrc
  exec bash --rcfile /tmp/.bashrc -i'
rc=$?
dc down -v --remove-orphans >/dev/null 2>&1
rm -f "$OVR"
echo "skeptic session ended (exit $rc); containers, networks and volumes removed."
