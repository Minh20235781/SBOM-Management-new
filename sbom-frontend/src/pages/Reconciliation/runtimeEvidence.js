const property = (name, value) => ({ name: 'runtime:' + name, value: String(value) });

function component(name, version) {
  const purl = 'pkg:npm/' + name.split('/').map(encodeURIComponent).join('/') + (version ? '@' + encodeURIComponent(version) : '');
  return { type: 'library', name, version: version || 'VERSION_UNKNOWN', purl, 'bom-ref': purl, properties: [] };
}

export function readBrowserLog(log) {
  const audit = log.f12NetworkAuditLog ?? log.auditLog;
  if (!audit?.sessionId || audit.sessionId !== log.sessionId || audit.targetUrl !== log.targetUrl ||
      !Array.isArray(audit.identifiedPackages) || !Array.isArray(audit.capturedNetworkRequests))
    throw new Error('Cần log CDP có danh sách quan sát trình duyệt và mã phiên nhất quán.');
  const original = log.cycloneDxRuntimeSbom ?? JSON.parse(log.sbomJson);
  const packages = audit.identifiedPackages.filter(p => p.name && p.identificationMethod !== 'NODEJS_SERVER_MODULE_LOAD' && p.source !== 'NODEJS_SERVER');
  const components = packages.map(p => {
    const fingerprint = p.identificationMethod === 'BUNDLE_CODE_FINGERPRINT';
    const known = !fingerprint && p.version && p.version !== 'VERSION_UNKNOWN';
    const item = component(p.name, known ? p.version : null);
    item.properties.push(property('collectionSource', 'CHROMIUM_CDP'), property('identificationMethod', p.identificationMethod),
      property('hasExecutionEvidence', p.hasExecutionEvidence === true), property('evidence', p.evidence || p.identificationMethod));
    if (p.scriptUrl) item.properties.push(property('scriptUrl', p.scriptUrl));
    if (p.scriptHash) item.properties.push(property('scriptHash', p.scriptHash));
    return item;
  });
  const { serverRuntime, ...browserAudit } = audit;
  browserAudit.observation = {
    scenario: audit.observation?.scenario || null,
    buildId: audit.observation?.buildId || null,
    scope: 'Script và tài nguyên quan sát trong phiên CDP. Backend gồm các module có trong tiến trình đến request chung cuối cùng.'
  };
  const document = { bomFormat: 'CycloneDX', specVersion: original.specVersion, serialNumber: original.serialNumber,
    version: 1, metadata: original.metadata, components };
  return { sessionId: log.sessionId, scannedAt: audit.scannedAt, targetUrl: audit.targetUrl,
    componentCount: components.length, content: JSON.stringify(document), auditLog: { ...browserAudit, identifiedPackages: packages },
    omittedServerCount: serverRuntime?.serverPackagesCount || 0 };
}

export function attachBackend(runtime, inventory, staticHash) {
  if (inventory.format !== 'sbom-backend/1' || !staticHash || inventory.staticSha256 !== staticHash)
    throw new Error('Log backend thiếu định danh hoặc SHA-256 khác SBOM tĩnh đã chọn.');
  if (!inventory.processId || !Array.isArray(inventory.requests) || !Array.isArray(inventory.packages))
    throw new Error('Log backend thiếu tiến trình, request hoặc danh sách module.');
  const ids = new Set(runtime.auditLog.capturedNetworkRequests.map(r => r.backendRequestId).filter(Boolean));
  const requests = inventory.requests.filter(r => ids.has(r.requestId));
  if (!requests.length) throw new Error('Không có request chung giữa backend và phiên trình duyệt.');
  const last = Math.max(...requests.map(r => Date.parse(r.finishedAt)));
  const packages = inventory.packages.filter(p => p.name && p.version && Date.parse(p.firstLoadedAt) <= last);
  const evidence = { ...inventory, requests, packages };
  const inventories = { ...runtime.backendEvidence, [inventory.processId]: evidence };
  const base = readBrowserLog({ ...runtime, sbomJson: runtime.content });
  const document = JSON.parse(base.content);
  const entries = new Map(document.components.map(p => [p.purl, p]));
  for (const inv of Object.values(inventories)) {
    for (const pkg of inv.packages) {
      const candidate = component(pkg.name, pkg.version);
      const item = entries.get(candidate.purl) || candidate;
      const detail = 'Backend PID ' + inv.pid + ' · ' + pkg.method + ' · ' + pkg.file + ' · ' + pkg.firstLoadedAt;
      const prior = item.properties.find(p => p.name === 'runtime:evidence');
      if (prior) prior.value += ' | ' + detail;
      else item.properties.push(property('evidence', detail));
      const source = item.properties.find(p => p.name === 'runtime:collectionSource');
      if (!source) item.properties.push(property('collectionSource', 'NODEJS_SERVER'));
      else if (source.value === 'CHROMIUM_CDP') source.value += '+NODEJS_SERVER';
      entries.set(item.purl, item);
    }
  }
  document.components = [...entries.values()];
  return { ...runtime, content: JSON.stringify(document), componentCount: entries.size, backendEvidence: inventories };
}
