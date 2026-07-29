# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Remote Wake reference relay.
#
#   docker build -t remotewake-relay .
#   docker run --rm -p 8080:8080 -v "$PWD/config.json:/app/config.json:ro" remotewake-relay
#
# config.json is mounted at run time and deliberately NOT copied in (see .dockerignore).
# It holds every device token this relay knows, and PROTOCOL.md §11 requires that store to be
# treated as secret material. Baking it into an image layer would push it to every registry
# the image ever reaches.

FROM node:20-alpine

ENV NODE_ENV=production \
    RW_CONFIG=/app/config.json

WORKDIR /app

# Dependencies first, so editing the relay does not re-resolve the tree. `npm ci` installs
# exactly the lockfile — a relay you self-host should not pull a different `ws` than the one
# the tests ran against.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY server.js ./
COPY test ./test
COPY README.md LICENSE config.json.example ./

# node:20-alpine ships an unprivileged `node` user (uid 1000). Nothing here needs root: the
# relay binds 8080, writes nothing to disk, and reads one config file.
USER node

EXPOSE 8080

# Uses the unauthenticated /healthz endpoint, which exists precisely so an orchestrator can
# check liveness without being handed an API key to do it.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q -O- "http://127.0.0.1:${PORT:-8080}/healthz" >/dev/null || exit 1

CMD ["node", "server.js"]
