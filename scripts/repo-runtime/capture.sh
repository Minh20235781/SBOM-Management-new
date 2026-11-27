#!/bin/sh
set -eu
cd "$(cat /tmp/app-dir)"
export PORT=3000
export SBOM_EVIDENCE_DIR=/tmp/evidence
export SBOM_STATIC_FILE=/tmp/static.json
export SBOM_BUILD_ID="$(cat /tmp/revision)"
export SBOM_SCENARIO="GitHub $1 @ $SBOM_BUILD_ID · GET /"
workspace=$(node -e "const s=require('./package.json').scripts||{}; const match=!s.dev && !s.start && /^npm run dev --workspace[= ]([@\w./-]+)$/.exec(s['dev:web']||''); console.log(match ? match[1] : '')")
if [ -n "$workspace" ]; then set -- "--workspace=$workspace"; else set --; fi
npm ci --offline --ignore-scripts --no-audit --no-fund --cache /tmp/npm-cache "$@"
npm cache clean --force --cache /tmp/npm-cache
mkdir -p /tmp/baseline
cp package.json package-lock.json /tmp/baseline/
node <<'NODE'
const fs = require('node:fs');
const path = require('node:path');
for (const entry of Object.values(require('./package-lock.json').packages)) {
  if (!entry.link) continue;
  const directory = fs.realpathSync(entry.resolved);
  const relative = path.relative(process.cwd(), directory);
  if (relative.startsWith('..') || path.isAbsolute(relative)) throw Error('Invalid workspace path');
  const destination = path.join('/tmp/baseline', relative);
  fs.mkdirSync(destination, {recursive:true});
  fs.copyFileSync(path.join(directory,'package.json'), path.join(destination,'package.json'));
}
NODE
(
  cd /tmp/baseline
  # npm requires a version on the root even for unpublished applications.
  node <<'NODE'
const fs = require('node:fs');
const manifest = require('./package.json');
if (!manifest.version) {
  const lock = require('./package-lock.json');
  manifest.version = '0.0.0+git.' + process.env.SBOM_BUILD_ID.slice(0, 12);
  lock.version = manifest.version;
  lock.packages[''].version = manifest.version;
  fs.writeFileSync('package.json', JSON.stringify(manifest));
  fs.writeFileSync('package-lock.json', JSON.stringify(lock));
}
NODE
  if ! npm sbom --sbom-format=cyclonedx --package-lock-only > "$SBOM_STATIC_FILE" 2>/tmp/sbom-error; then
    if ! grep -q ESBOMPROBLEMS /tmp/sbom-error; then cat /tmp/sbom-error >&2; exit 1; fi
    node /opt/sbom/lock-inventory.cjs > "$SBOM_STATIC_FILE"
  fi
)
script=$(node -e "const s=require('./package.json').scripts||{}; console.log(['dev','start','dev:web'].find(name=>s[name])||'')")
if [ -z "$script" ]; then echo "Cần script dev hoặc start trong package.json." >&2; exit 1; fi
mkdir -p "$SBOM_EVIDENCE_DIR"
if [ "$script" = "dev:web" ]; then
  export SBOM_SCENARIO="$SBOM_SCENARIO · dev:web (chỉ dịch vụ web, chưa chạy API riêng)"
fi
NODE_OPTIONS=--require=/opt/sbom/scripts/nodejs-runtime-collector/session-agent.cjs npm run "$script" >/tmp/target.log 2>&1 &
app=$!
trap 'kill "$app" 2>/dev/null || true' EXIT
url=$(node --input-type=module <<'NODE'
for (let attempt = 0; attempt < 40; attempt++) {
  for (const port of [3000, 5173, 4000, 8080]) {
    const url = 'http://127.0.0.1:' + port + '/';
    try {
      await fetch(url, { signal: AbortSignal.timeout(400) });
      console.log(url);
      process.exit(0);
    } catch { /* The server may still be starting. */ }
  }
  await new Promise(resolve => setTimeout(resolve, 750));
}
throw Error('Ứng dụng chưa mở cổng HTTP. Kiểm tra script, dịch vụ hoặc biến môi trường cần thiết.');
NODE
) || { tail -c 1200 /tmp/target.log >&2; exit 1; }
node /opt/sbom/scripts/runtime-collector/cdp-scanner.js "$url" /tmp/browser.json
node /opt/sbom/scripts/runtime-collector/export-session.mjs /tmp/browser.json "$SBOM_EVIDENCE_DIR" "$SBOM_STATIC_FILE" /tmp/runtime.json
