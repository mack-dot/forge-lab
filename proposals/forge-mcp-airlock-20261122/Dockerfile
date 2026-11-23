# One image for the airlock, the mock upstream and the agent. It holds code only:
# no policy file, no fixture, no key. Policies and fixtures are mounted into the airlock.
#
# Stage 1: the REAL off-the-shelf MCP filesystem server, pinned by mcpfs/package-lock.json
# (@modelcontextprotocol/server-filesystem 2.2.0), installed with npm ci.
FROM node:24.11.0-bookworm-slim AS mcpfs
WORKDIR /opt/mcpfs
COPY mcpfs/package.json mcpfs/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund

FROM python:3.12-slim-bookworm
RUN apt-get update \
 && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir PyYAML==6.0.2
COPY --from=mcpfs /usr/local/bin/node /usr/local/bin/node
COPY --from=mcpfs /opt/mcpfs /opt/mcpfs
COPY airlock /forge/airlock
COPY agent /forge/agent
COPY mocks /forge/mocks
COPY checkers /forge/checkers
RUN chmod -R a+rX /forge /opt/mcpfs && node --version
