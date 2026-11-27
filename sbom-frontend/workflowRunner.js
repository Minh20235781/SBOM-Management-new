import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const loopback = new Set(['localhost','127.0.0.1','[::1]']);
const agent = fileURLToPath(new URL('../scripts/nodejs-runtime-collector/session-agent.cjs', import.meta.url));
const validCommand = /^(npm|pnpm) (?:run )?(dev|start)$/;

export function workflowRunner() {
  let job;
  function stop() {
    if (!job || !job.child.pid || job.state !== 'running') return;
    if (process.platform === 'win32') {
      const result=spawnSync('taskkill.exe', ['/PID', String(job.child.pid), '/T', '/F'], {windowsHide:true,timeout:8000});
      if(result.status!==0) throw Error('Windows chưa dừng được tiến trình. Kiểm tra quyền của runner và thử lại.');
    } else {
      try { process.kill(-job.child.pid, 'SIGTERM'); } catch {}
    }
    job.state = 'stopped';
    clearTimeout(job.timer);
  }
  function start(command, digest) {
    if (job?.state === 'running') throw Error('Một job đang chạy. Dừng job hiện tại trước khi chạy lại.');
    const dir = process.env.SBOM_WORKFLOW_DIR, file = process.env.SBOM_STATIC_FILE;
    if (!dir || !file || !path.isAbsolute(dir) || !path.isAbsolute(file))
      throw Error('Đặt SBOM_WORKFLOW_DIR và SBOM_STATIC_FILE thành đường dẫn tuyệt đối trước khi khởi động Vite.');
    const match = validCommand.exec(command);
    if (!match) throw Error('Dùng npm run dev, npm start, pnpm dev hoặc pnpm start.');
    if (createHash('sha256').update(fs.readFileSync(file)).digest('hex') !== digest)
      throw Error('SBOM gốc của runner khác Nguồn 1.');
    if (!JSON.parse(fs.readFileSync(path.join(dir,'package.json'),'utf8')).scripts?.[match[2]])
      throw Error('Thư mục dự án chưa khai báo script này.');
    const evidence = fs.mkdtempSync(path.join(os.tmpdir(),'sbom-workflow-'));
    const win = process.platform === 'win32';
    const args = win ? ['/d','/c',match[1]+'.cmd','run',match[2]] : ['run',match[2]];
    const child = spawn(win ? process.env.ComSpec : match[1], args, {cwd:dir,windowsHide:true,detached:!win,
      stdio:['ignore','pipe','pipe'],env:{...process.env,SBOM_EVIDENCE_DIR:evidence,
        NODE_OPTIONS:((process.env.NODE_OPTIONS || '')+' --require '+JSON.stringify(agent.replaceAll('\\','/'))).trim()}});
    const run = {id:randomUUID(),state:'running',child,evidence,output:'',command};
    function append(chunk) { run.output = (run.output + chunk).slice(-48000); }
    for (const stream of [child.stdout, child.stderr]) { stream.setEncoding('utf8'); stream.on('data',append); }
    child.on('error', e=>{append(e.message);run.state='failed';clearTimeout(run.timer);});
    child.on('close',code=>{if(run.state==='running') run.state=code===0?'finished':'failed';clearTimeout(run.timer);});
    run.timer=setTimeout(()=>{try {stop();} catch(e){append('\n'+e.message);}},30*60*1000); run.timer.unref();
    job=run;
  }
  return {name:'local-sbom-workflow',configureServer(server) {
    server.httpServer?.once('close',()=>{try {stop();} catch(e){console.error(e.message);}});
    server.middlewares.use('/__sbom_job', async (req,res)=>{
      res.setHeader('Content-Type','application/json'); res.setHeader('Cache-Control','no-store');
      try {
        const origin=new URL(req.headers.origin || 'about:blank');
        if (!['127.0.0.1','::1','::ffff:127.0.0.1'].includes(req.socket.remoteAddress) ||
          !loopback.has(origin.hostname) || origin.host!==req.headers.host || req.method!=='POST' ||
          req.headers['x-sbom-job']!=='1') {res.statusCode=403;res.end('{}');return;}
        let body='';
        for await (const chunk of req) {body+=chunk;if(body.length>4096)throw Error('Yêu cầu quá dài.');}
        const data=JSON.parse(body);
        if (data.action==='start') start(data.command,data.digest);
        else if (!job || data.id!==job.id) throw Error('Không tìm thấy job của phiên.');
        if (data.action==='stop') stop();
        const response={id:job.id,state:job.state,output:job.output,command:job.command};
        if (data.action==='evidence') response.inventories=fs.readdirSync(job.evidence)
          .filter(n=>/^backend-[\w-]+\.json$/.test(n)).map(n=>JSON.parse(fs.readFileSync(path.join(job.evidence,n),'utf8')));
        res.end(JSON.stringify(response));
      } catch(error) {res.statusCode=400;res.end(JSON.stringify({error:error.message}));}
    });
  }};
}
