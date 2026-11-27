import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { attachBackend, readBrowserLog } from '../../sbom-frontend/src/pages/Reconciliation/runtimeEvidence.js';

const [browserFile, directory, staticFile, outputFile] = process.argv.slice(2);
if (!outputFile) throw Error('Usage: export-session.mjs browser.json evidence-dir sbom.json runtime-log.json');
const readJson = file => JSON.parse(fs.readFileSync(file, 'utf8'));
const digest = createHash('sha256').update(fs.readFileSync(staticFile)).digest('hex');
let runtime = readBrowserLog(readJson(browserFile));
const requests = new Set(runtime.auditLog.capturedNetworkRequests.map(r => r.backendRequestId).filter(Boolean));
for (const filename of fs.readdirSync(directory)) {
  if (!/^backend-.*\.json$/.test(filename)) continue;
  const inventory = readJson(path.join(directory, filename));
  if (inventory.requests.some(r => requests.has(r.requestId))) runtime = attachBackend(runtime, inventory, digest);
}
if (!runtime.backendEvidence) throw Error('No backend handled a request observed in this browser session.');
fs.writeFileSync(outputFile, JSON.stringify({
  sessionId: runtime.sessionId, targetUrl: runtime.targetUrl, scannedAt: runtime.scannedAt,
  componentCount: runtime.componentCount, f12NetworkAuditLog: runtime.auditLog,
  backendEvidence: runtime.backendEvidence, cycloneDxRuntimeSbom: JSON.parse(runtime.content)
}, null, 2));
