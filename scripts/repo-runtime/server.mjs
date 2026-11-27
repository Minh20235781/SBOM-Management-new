import { execFile } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import { projectFromUrl } from './url.mjs';

const execute = promisify(execFile);
let occupied = false;
const image = 'sbom-repo-runtime:v1';
const endpoint = '/api/runtime/repository';

async function docker(args, options = {}) {
  try {
    const result = await execute('docker', args, { windowsHide:true, maxBuffer:12 * 1024 * 1024, timeout:120000, ...options });
    return result.stdout;
  } catch (error) {
    if (options.signal?.aborted) throw Error('Phiên hết thời gian hoặc đã ngắt kết nối.');
    if (error.code === 'ENOENT' || /connect to the docker|cannot connect to the docker/i.test(error.stderr || ''))
      throw Error('Docker Engine trên máy chủ chưa sẵn sàng. Hãy bật Linux containers trên máy chạy runner.');
    if (/no such image|unable to find image/i.test(error.stderr || ''))
      throw Error('Máy chủ chưa build image sbom-repo-runtime:v1. Xem scripts/repo-runtime/README.md.');
    throw Error([error.code, error.stderr, error.stdout || error.message].filter(Boolean).join('\n').trim().slice(-2200));
  }
}

async function capture(project, send, signal) {
  const name = 'sbom-runtime-' + randomUUID();
  const run = args => docker(args, {signal});
  try {
    send({step:'Khởi tạo sandbox'});
    await run(['run','--detach','--rm','--pull=never','--name',name,'--network','bridge','--read-only','--init',
      '--cap-drop=ALL','--security-opt=no-new-privileges','--memory=2g','--cpus=1','--pids-limit=256',
      '--tmpfs','/tmp:rw,exec,nosuid,nodev,size=1200m,mode=1777',image]);
    send({step:'Lấy mã nguồn và gói từ npm registry'});
    await run(['exec',name,'node','/opt/sbom/prepare.cjs',project.repo,project.branch,project.directory]);
    await run(['network','disconnect','bridge',name]);
    send({step:'Tạo SBOM tĩnh, chạy ứng dụng và quan sát bằng Chromium'});
    await run(['exec',name,'sh','/opt/sbom/capture.sh',project.repo]);
    const staticContent = await run(['exec',name,'cat','/tmp/static.json']);
    const runtime = JSON.parse(await run(['exec',name,'cat','/tmp/runtime.json']));
    send({staticContent,runtime,repo:project.repo});
  } finally {
    await docker(['rm','-f',name],{timeout:12000}).catch(()=>{});
  }
}

export async function repositoryMiddleware(req,res,next) {
  if (req.url !== endpoint) return next();
  const fail = (code,message) => {res.writeHead(code,{'Content-Type':'application/json'});res.end(JSON.stringify({error:message}));};
  if (req.method !== 'POST' || req.headers['x-sbom-runtime'] !== '1') return fail(405,'Yêu cầu không hợp lệ.');
  const origin=req.headers.origin;
  if (origin && URL.canParse(origin) && new URL(origin).host !== req.headers.host) return fail(403,'Yêu cầu khác nguồn.');
  if (origin && !URL.canParse(origin)) return fail(403,'Nguồn không hợp lệ.');
  if (occupied) return fail(409,'Runner đang thu phiên khác. Vui lòng thử lại sau.');
  let project;
  try {
    let body = '';
    for await (const chunk of req) {
      body += chunk;
      if (body.length > 2048) return fail(413,'URL quá dài.');
    }
    project = projectFromUrl(JSON.parse(body).url);
  } catch { return fail(400,'Cần URL repo GitHub công khai.'); }
  if (!project) return fail(400,'URL repo hoặc thư mục GitHub không hợp lệ.');
  if (occupied) return fail(409,'Runner đang bận.');
  occupied=true;
  const controller=new AbortController();
  const abort=()=>controller.abort();
  const deadline=setTimeout(abort,240000);
  res.on('close',abort);
  res.writeHead(200,{'Content-Type':'application/x-ndjson; charset=utf-8','Cache-Control':'no-store','X-Accel-Buffering':'no'});
  const send = value => {if (!res.destroyed) res.write(JSON.stringify(value)+'\n');};
  try { await capture(project,send,controller.signal); }
  catch(error) { send({error:error.message}); }
  finally { clearTimeout(deadline);occupied=false;res.end(); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  createServer((req,res)=>repositoryMiddleware(req,res,()=>{res.writeHead(404);res.end();})).listen(8787,'127.0.0.1');
}
