import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { workflowRunner } from '../workflowRunner.js';

test('workflow runs the configured project, correlates a real request and stops the job', {timeout:30000}, async () => {
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'sbom-workflow-test-'));
  const file=path.join(dir,'sbom.json');
  fs.writeFileSync(file,'{"components":[]}');
  fs.writeFileSync(path.join(dir,'package.json'),JSON.stringify({name:'workflow-test',scripts:{dev:'node server.cjs'}}));
  fs.writeFileSync(path.join(dir,'server.cjs'),"const s=require('http').createServer((q,r)=>r.end('OK'));s.listen(0,'127.0.0.1',()=>console.log('LISTEN='+s.address().port))");
  process.env.SBOM_WORKFLOW_DIR=dir;
  process.env.SBOM_STATIC_FILE=file;
  const server=http.createServer();
  workflowRunner().configureServer({httpServer:server,middlewares:{use:(_,fn)=>server.on('request',fn)}});
  server.listen(0,'127.0.0.1');await once(server,'listening');
  const origin='http://127.0.0.1:'+server.address().port;
  const digest=createHash('sha256').update(fs.readFileSync(file)).digest('hex');
  async function call(action,fields={},from=origin) {
    const res=await fetch(origin+'/__sbom_job',{method:'POST',headers:{Origin:from,'X-SBOM-Job':'1'},body:JSON.stringify({action,...fields})});
    return {status:res.status,data:await res.json()};
  }
  let id;
  try {
    assert.equal((await call('start',{command:'npm run dev',digest},'https://example.org')).status,403);
    assert.equal((await call('start',{command:'npm run dev && echo invalid',digest})).status,400);
    assert.equal((await call('start',{command:'npm run dev',digest:'wrong'})).status,400);
    const start=await call('start',{command:'npm run dev',digest});
    assert.equal(start.status,200);id=start.data.id;
    let port;
    for(let i=0;i<80&&!port;i++){await new Promise(r=>setTimeout(r,100));port=(await call('status',{id})).data.output.match(/LISTEN=(\d+)/)?.[1];}
    assert.ok(port);
    const response=await fetch('http://127.0.0.1:'+port);
    await response.text();
    const requestId=response.headers.get('x-sbom-request-id');assert.ok(requestId);
    let matched=false;
    for(let i=0;i<20&&!matched;i++){await new Promise(r=>setTimeout(r,100));matched=(await call('evidence',{id})).data.inventories.some(inv=>inv.staticSha256===digest && inv.requests.some(r=>r.requestId===requestId));}
    assert.ok(matched);
    assert.equal((await call('stop',{id})).data.state,'stopped');
  } finally {if(id)await call('stop',{id});server.close();server.closeAllConnections();delete process.env.SBOM_WORKFLOW_DIR;delete process.env.SBOM_STATIC_FILE;}
});
