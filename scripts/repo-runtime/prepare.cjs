// Only download integrity-checked npm tarballs here. Project scripts run after disconnection.
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const npmRoot = path.join(path.dirname(process.execPath), '../lib/node_modules/npm/node_modules');
const makeFetch = require(path.join(npmRoot, 'make-fetch-happen'));
const [repo, branch, directory] = process.argv.slice(2);
async function main() {
  execFileSync('git', ['clone', '--quiet', '--depth=1', ...(branch ? ['--branch', branch] : []),
    '--', 'https://github.com/' + repo + '.git', '/tmp/project'], {env:{...process.env,GIT_TERMINAL_PROMPT:'0'},stdio:'inherit'});
  const cwd = fs.realpathSync(path.join('/tmp/project', directory));
  if (cwd !== '/tmp/project' && !cwd.startsWith('/tmp/project/')) throw Error('Invalid project directory');
  fs.writeFileSync('/tmp/app-dir', cwd);
  fs.writeFileSync('/tmp/revision', execFileSync('git', ['-C','/tmp/project','rev-parse','HEAD']));
  const lockPath = path.join(cwd,'package-lock.json');
  if (!fs.existsSync(lockPath)) throw Error('Cần package-lock.json v2/v3 trong thư mục ứng dụng. Với monorepo, nhập URL GitHub của thư mục chứa ứng dụng.');
  const entries = Object.values(JSON.parse(fs.readFileSync(lockPath)).packages || {}).slice();
  if (!entries.length) throw Error('Cần package-lock.json v2/v3.');
  const tarballs = new Map();
  for (const entry of entries) {
    if (!entry.resolved) continue;
    const url = new URL(entry.resolved);
    if (url.origin !== 'https://registry.npmjs.org' || url.username || url.password || !entry.integrity)
      throw Error('Runner chỉ hỗ trợ gói npm công khai có integrity từ registry.npmjs.org.');
    tarballs.set(url.href,entry.integrity);
  }
  const pending = [...tarballs];
  async function download() {
    while (pending.length) {
      const [url,integrity] = pending.pop();
      const response = await makeFetch(url,{cachePath:'/tmp/npm-cache/_cacache',integrity,redirect:'error'});
      if (!response.ok) throw Error('npm registry HTTP ' + response.status);
      for await (const chunk of response.body) { /* drain response to the npm cache */ }
    }
  }
  await Promise.all(Array.from({length:6},download));
}
main().catch(error=>{ console.error(error.message); process.exitCode=1; });
