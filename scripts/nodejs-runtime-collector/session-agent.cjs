// Preload in the application process via NODE_OPTIONS. Each responding process owns one inventory.
const fs = require('node:fs');
const path = require('node:path');
const { createHash, randomUUID } = require('node:crypto');
const { fileURLToPath } = require('node:url');
const Module = require('node:module');

const sbom = process.env.SBOM_STATIC_FILE;
if (!sbom || !path.isAbsolute(sbom)) throw new Error('Set SBOM_STATIC_FILE to the absolute path of the original SBOM.');
const staticSha256 = createHash('sha256').update(fs.readFileSync(sbom)).digest('hex');
const directory = process.env.SBOM_EVIDENCE_DIR || path.join(path.dirname(sbom), 'runtime-evidence');
const processId = randomUUID();
const startedAt = new Date().toISOString();
const output = path.resolve(directory, 'backend-' + processId + '.json');
const packages = new Map();
const manifests = new Map();
const requests = [];
let pending = false;

function record(filename, method) {
  if (typeof filename !== 'string') return;
  const segments = filename.split(path.sep);
  const start = segments.lastIndexOf('node_modules') + 1;
  if (!start || !segments[start] || segments[start].startsWith('.')) return;
  const end = start + (segments[start].startsWith('@') ? 2 : 1);
  const manifest = segments.slice(0, end).concat('package.json').join(path.sep);
  if (!manifests.has(manifest)) {
    try { manifests.set(manifest, JSON.parse(fs.readFileSync(manifest, 'utf8'))); }
    catch { manifests.set(manifest, null); }
  }
  const pkg = manifests.get(manifest);
  if (!pkg?.name || typeof pkg.version !== 'string') return;
  const key = pkg.name + '@' + pkg.version;
  if (!packages.has(key)) packages.set(key, {
    name: pkg.name, version: pkg.version, firstLoadedAt: new Date().toISOString(),
    file: path.relative(process.cwd(), filename), method
  });
}

const originalLoad = Module._load;
Module._load = function (request, parent, isMain) {
  const value = originalLoad.apply(this, arguments);
  try { record(Module._resolveFilename(request, parent, isMain), 'CommonJS require'); } catch {}
  return value;
};

if (Module.registerHooks) Module.registerHooks({
  load(url, context, nextLoad) {
    const result = nextLoad(url, context);
    if (url.startsWith('file:') && String(result.format).startsWith('module'))
      record(fileURLToPath(url), 'ES module loader');
    return result;
  }
});

function save() {
  pending = false;
  try {
    fs.mkdirSync(directory, { recursive: true });
    const inventory = { format: 'sbom-backend/1', processId, pid: process.pid, cwd: process.cwd(),
      staticSha256, buildId: process.env.SBOM_BUILD_ID || null, startedAt,
      generatedAt: new Date().toISOString(), requests, packages: [...packages.values()] };
    fs.writeFileSync(output + '.tmp', JSON.stringify(inventory));
    fs.renameSync(output + '.tmp', output);
  } catch (error) { console.error('[SBOM]', error.message); }
}

// diagnostics_channel fires before the request handler, including for Express and Next HTTP servers.
require('node:diagnostics_channel').subscribe('http.server.request.start', ({ request, response }) => {
  const requestId = randomUUID();
  response.setHeader('x-sbom-request-id', requestId);
  const time = new Date().toISOString();
  response.once('finish', () => {
    requests.push({ requestId, method: request.method, path: request.url.split('?')[0],
      startedAt: time, finishedAt: new Date().toISOString() });
    if (!pending) { pending = true; setImmediate(save); }
  });
});
process.once('exit', () => { if (pending) save(); });
