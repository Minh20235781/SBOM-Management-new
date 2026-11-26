import test from 'node:test';
import assert from 'node:assert/strict';
import { readBrowserLog, attachBackend } from '../src/pages/Reconciliation/runtimeEvidence.js';
import { readDependencyGraph, compareDependencyGraphs } from '../src/pages/Reconciliation/compareDependencyGraphs.js';

const log = { sessionId: 'one', targetUrl: 'http://localhost', cycloneDxRuntimeSbom: {specVersion: '1.4', components: [{name:'injected'}]},
  f12NetworkAuditLog: { sessionId: 'one', targetUrl: 'http://localhost', capturedNetworkRequests: [{backendRequestId:'req1'}],
    identifiedPackages: [{name:'react',version:'16.3.1',identificationMethod:'BUNDLE_CODE_FINGERPRINT'}], serverRuntime:{serverPackagesCount:25} } };
const server = { format:'sbom-backend/1', processId:'instance', pid:12, staticSha256:'abc',
  requests:[{requestId:'req1',finishedAt:'2026-01-01T01:00:00Z'}],
  packages:['declared','extra'].map(name=>({name, version:'1.0.0', file:'index.js', method:'require', firstLoadedAt:'2026-01-01T00:00:00Z'})) };
test('legacy merged inventory cannot introduce a server package or an unbound bundle version', () => {
  const runtime = readBrowserLog(log);
  assert.deepEqual(JSON.parse(runtime.content).components.map(p=>[p.name,p.version]), [['react','VERSION_UNKNOWN']]);
  assert.throws(()=>attachBackend(runtime,server,'other'),/SHA-256/);
  assert.throws(()=>attachBackend(runtime,{...server,requests:[]},'abc'),/request/);
});
test('matches request and static digest, excludes later loads and preserves replay counts', () => {
  const later = {...server.packages[0],name:'later',firstLoadedAt:'2026-02-01T00:00:00Z'};
  const evidence = {...server,packages:[...server.packages,later]};
  const combined = attachBackend(readBrowserLog(log), evidence,'abc');
  assert.equal(attachBackend(combined,evidence,'abc').componentCount,3);
  const runtime = readDependencyGraph(JSON.parse(combined.content));
  const baseline = readDependencyGraph({components:[{name:'declared',version:'1.0.0',purl:'pkg:npm/declared@1.0.0'}]});
  const { results } = compareDependencyGraphs(baseline,runtime);
  assert.deepEqual(Object.fromEntries(results.map(r=>[r.component,r.status])), {declared:'MATCHED', react:'UNRESOLVED', extra:'RUNTIME_ONLY'});
});
