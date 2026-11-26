import test from 'node:test';
import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { once } from 'node:events';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readBrowserLog, attachBackend } from '../src/pages/Reconciliation/runtimeEvidence.js';
import { readDependencyGraph, compareDependencyGraphs } from '../src/pages/Reconciliation/compareDependencyGraphs.js';

test('local HTTP application correlates a response with actual module loads', { timeout: 45000 }, async t => {
  const dir = await mkdtemp(path.join(tmpdir(), 'sbom-http-'));
  t.after(() => rm(dir,{recursive:true,force:true}));
  const agent = fileURLToPath(new URL('../../scripts/nodejs-runtime-collector/session-agent.cjs',import.meta.url));
  const file = path.join(dir,'sbom.json');
  const input = JSON.stringify({bomFormat:'CycloneDX',specVersion:'1.6',version:1,components:[
    {type:'library',name:'first',version:'1.0.0',purl:'pkg:npm/first@1.0.0'}
  ]});
  await writeFile(file,input);
  for (const [name,type] of [['first','commonjs'],['second','module']]) {
    const pkg = path.join(dir,'node_modules',name);
    await mkdir(pkg,{recursive:true});
    await writeFile(path.join(pkg,'package.json'),JSON.stringify({name,version:'1.0.0',type,main:'index.js'}));
    await writeFile(path.join(pkg,'index.js'),type==='module'?'export default 1':'module.exports = 1');
  }
  const main = path.join(dir,'server.cjs');
  await writeFile(main,`const http=require('node:http');require('first');
    const server=http.createServer(async(req,res)=>{await import('second');res.end('<html>fixture</html>')});
    server.listen(0,'127.0.0.1',()=>process.send(server.address().port));`);
  const child = fork(main,[], { cwd:dir,execArgv:['--require',agent],silent:true,
    env:{...process.env,SBOM_STATIC_FILE:file,SBOM_EVIDENCE_DIR:dir,SBOM_BUILD_ID:'independent-build'}});
  try {
    const [port] = await once(child,'message');
    const url = 'http://127.0.0.1:' + port;
    let log;
    if (process.env.SBOM_TEST_CHROME === '1') {
      const {runCdpScan} = await import('../../scripts/runtime-collector/cdp-scanner.js');
      log = await runCdpScan(url,{scenario:'Mở trang kiểm thử'});
      assert.equal(log.auditLog.observation.scenario,'Mở trang kiểm thử');
    } else {
      const response = await fetch(url);
      const requestId = response.headers.get('x-sbom-request-id');
      assert.ok(requestId);
      log = { sessionId:'test',targetUrl:url,sbomJson:'{"specVersion":"1.4"}',
        auditLog:{sessionId:'test',targetUrl:url,identifiedPackages:[],capturedNetworkRequests:[{backendRequestId:requestId}]} };
    }
    let inventory;
    for (let i=0;i<50 && !inventory;i++) {
      const name=(await readdir(dir)).find(n=>/^backend-.*\.json$/.test(n));
      if (name) inventory=JSON.parse(await readFile(path.join(dir,name),'utf8'));
      else await new Promise(resolve=>setTimeout(resolve,20));
    }
    const hash=createHash('sha256').update(input).digest('hex');
    const runtime=attachBackend(readBrowserLog(log),inventory,hash);
    assert.equal(inventory.buildId,'independent-build');
    assert.throws(()=>attachBackend(readBrowserLog(log),inventory,'wrong-project'),/SHA-256/);
    const report=compareDependencyGraphs(readDependencyGraph(JSON.parse(input)),readDependencyGraph(JSON.parse(runtime.content)));
    assert.equal(report.results.find(row=>row.component==='first').status,'MATCHED');
    if (process.getBuiltinModule?.('node:module').registerHooks)
      assert.equal(report.results.find(row=>row.component==='second').status,'RUNTIME_ONLY');
    const names=JSON.parse(runtime.content).components.map(c=>c.name);
    assert.ok(names.includes('first'));
    if (process.getBuiltinModule?.('node:module').registerHooks) assert.ok(names.includes('second'));
  } finally {
    const done=once(child,'exit');
    child.kill();
    await done;
  }
});
