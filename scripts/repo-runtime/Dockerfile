FROM node:24-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends chromium git ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/sbom
COPY scripts/runtime-collector/package*.json scripts/runtime-collector/
RUN npm ci --prefix scripts/runtime-collector --ignore-scripts
COPY scripts/runtime-collector/cdp-scanner.js scripts/runtime-collector/export-session.mjs scripts/runtime-collector/
COPY scripts/nodejs-runtime-collector/session-agent.cjs scripts/nodejs-runtime-collector/
COPY sbom-frontend/src/pages/Reconciliation/runtimeEvidence.js sbom-frontend/src/pages/Reconciliation/
COPY scripts/repo-runtime/prepare.cjs scripts/repo-runtime/capture.sh ./
ENV HOME=/tmp/home CHROME_BIN=/usr/bin/chromium
USER node
CMD ["sleep","600"]
