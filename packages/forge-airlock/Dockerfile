# One image for the airlock, the egress proxy and the agent (target "airlock"), plus an
# agent image with Claude Code (target "agent-claude"). It holds code only: no policy,
# no repository, no key. forge_airlock.py builds it; you never edit Docker files.
#
# Stage 1: the REAL off-the-shelf MCP filesystem server, pinned by mcpfs/package-lock.json
# (@modelcontextprotocol/server-filesystem 2.2.0), installed with npm ci.
FROM node:24.11.0-bookworm-slim AS mcpfs
WORKDIR /opt/mcpfs
COPY mcpfs/package.json mcpfs/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund

FROM python:3.12-slim-bookworm AS airlock
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir PyYAML==6.0.2
# node, npm and npx (stdio upstreams such as `npx -y <server>` run on the airlock side)
COPY --from=mcpfs /usr/local/bin/node /usr/local/bin/node
COPY --from=mcpfs /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx
COPY --from=mcpfs /opt/mcpfs /opt/mcpfs
COPY engine /forge/airlock
COPY agent /forge/agent
COPY mocks /forge/mocks
COPY checkers /forge/checkers
RUN chmod -R a+rX /forge /opt/mcpfs && node --version && npx --version

FROM airlock AS agent-claude
ARG CLAUDE_CODE_VERSION=2.1.330
RUN npm install -g --no-audit --no-fund "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" && claude --version
