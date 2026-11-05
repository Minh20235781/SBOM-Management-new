/**
 * server.js - Ứng dụng mẫu kiểm chứng đối sánh SBOM Tĩnh và SBOM Runtime
 * 
 * Kịch bản kiểm chứng:
 * - Kịch bản 1 (Startup Load): Tự động nạp `axios` và `react` khi server khởi động.
 * - Kịch bản 2 (Browser CDN): Trang chủ GET / nhúng script CDN lodash@4.17.21 (để trình duyệt tải).
 * - Kịch bản 3 (Dynamic / Lazy Load): API POST /api/dynamic-load nạp thư viện `xlsx` theo yêu cầu.
 * - Kịch bản 4 (Static Only): Package `jsonwebtoken` có trong package.json và Static SBOM nhưng KHÔNG bao giờ được nạp tại runtime.
 */

const http = require('http');
const path = require('path');
const fs = require('fs');

// KỊCH BẢN 1: Startup Load - Nạp trực tiếp khi khởi động ứng dụng
console.log('[SAMPLE-APP] Khởi động ứng dụng mẫu...');
const axios = require('axios');
const React = require('react');
console.log(`[SAMPLE-APP] Đã nạp Startup Modules: axios@${require('axios/package.json').version}, react@${require('react/package.json').version}`);

let dynamicLoaded = false;
let dynamicPackageInfo = null;

const PORT = process.env.PORT || 4000;

const server = http.createServer((req, res) => {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // ROUTE 1: GET / - Trang chủ hiển thị thông tin và nạp script CDN (Kịch bản 2)
  if (req.method === 'GET' && req.url === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(`<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8">
  <title>Ứng Dụng Mẫu Kiểm Chứng Runtime SBOM</title>
  <!-- KỊCH BẢN 2: Thư viện ngoài qua CDN phục vụ kiểm chứng Browser Runtime -->
  <script src="https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js"></script>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 30px; line-height: 1.6; background: #0f172a; color: #f8fafc; }
    .card { background: #1e293b; border-radius: 8px; padding: 20px; margin-bottom: 20px; border: 1px solid #334155; }
    h1 { color: #38bdf8; margin-top: 0; }
    h2 { color: #818cf8; font-size: 1.2rem; }
    button { background: #2563eb; color: white; border: none; padding: 10px 18px; border-radius: 6px; cursor: pointer; font-weight: bold; font-size: 14px; }
    button:hover { background: #1d4ed8; }
    code { background: #0f172a; padding: 2px 6px; border-radius: 4px; color: #38bdf8; }
    .badge { display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
    .badge-success { background: #065f46; color: #34d399; }
    .badge-info { background: #1e3a8a; color: #60a5fa; }
    .badge-warning { background: #854d0e; color: #facc15; }
    ul { list-style: none; padding-left: 0; }
    li { padding: 6px 0; border-bottom: 1px solid #334155; }
  </style>
</head>
<body>
  <h1>Ứng Dụng Mẫu Kiểm Chứng Runtime SBOM</h1>
  <div class="card">
    <h2>1. Thư Viện Nạp Sẵn Khi Khởi Động (Server Startup)</h2>
    <ul>
      <li><code>axios</code> - Phiên bản: 1.13.2 <span class="badge badge-success">Observed Server Startup</span></li>
      <li><code>react</code> - Phiên bản: 19.2.3 <span class="badge badge-success">Observed Server Startup</span></li>
    </ul>
  </div>

  <div class="card">
    <h2>2. Thư Viện Trình Duyệt Nạp Từ CDN (Browser Runtime)</h2>
    <ul>
      <li><code>lodash</code> - Tải từ <code>https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js</code> <span class="badge badge-info">Observed CDN Script</span></li>
    </ul>
    <p>Kiểm tra đối tượng toàn cục trên Browser: <span id="cdn-check">Đang kiểm tra...</span></p>
    <script>
      if (typeof _ !== 'undefined' && _.VERSION) {
        document.getElementById('cdn-check').innerHTML = '<strong>Đã tải lodash v' + _.VERSION + ' từ CDN thành công!</strong>';
      }
    </script>
  </div>

  <div class="card">
    <h2>3. Kích Hoạt Nạp Thư Viện Động (Lazy Load XLSX)</h2>
    <p>Thư viện <code>xlsx</code> ban đầu chưa nạp vào bộ nhớ. Bấm nút bên dưới để gửi lệnh nạp động qua API POST /api/dynamic-load.</p>
    <button onclick="triggerDynamicLoad()">Nạp Thư Viện Động XLSX</button>
    <div id="dynamic-result" style="margin-top: 15px;"></div>
  </div>

  <div class="card">
    <h2>4. Thư Viện Tĩnh Không Sử Dụng (Static Only)</h2>
    <ul>
      <li><code>jsonwebtoken</code> - Khai báo trong package.json và Static SBOM nhưng server không require <span class="badge badge-warning">Static Only / Unused</span></li>
    </ul>
  </div>

  <script>
    async function triggerDynamicLoad() {
      const resDiv = document.getElementById('dynamic-result');
      resDiv.innerHTML = '<span style="color: #60a5fa;">Đang gửi lệnh nạp xlsx...</span>';
      try {
        const resp = await fetch('/api/dynamic-load', { method: 'POST' });
        const data = await resp.json();
        resDiv.innerHTML = '<span style="color: #34d399; font-weight: bold;">Thành công: ' + data.message + ' (Phiên bản: ' + data.version + ', Thời gian nạp: ' + data.loadedAt + ')</span>';
      } catch (err) {
        resDiv.innerHTML = '<span style="color: #f87171;">Lỗi: ' + err.message + '</span>';
      }
    }
  </script>
</body>
</html>`);
    return;
  }

  // ROUTE 2: POST /api/dynamic-load - KỊCH BẢN 3: Nạp thư viện động lazy-load
  if (req.method === 'POST' && req.url === '/api/dynamic-load') {
    const t0 = Date.now();
    console.log('[SAMPLE-APP] Nhận yêu cầu nạp thư viện động: xlsx...');
    // Gọi require() thực tế tại runtime
    const xlsx = require('xlsx');
    const version = require('xlsx/package.json').version;
    dynamicLoaded = true;
    dynamicPackageInfo = {
      name: 'xlsx',
      version: version,
      loadedAt: new Date().toISOString(),
      durationMs: Date.now() - t0
    };
    console.log(`[SAMPLE-APP] Đã nạp động thành công xlsx@${version}!`);

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      success: true,
      message: 'Đã nạp thư viện xlsx động vào bộ nhớ Node.js runtime',
      packageName: 'xlsx',
      version: version,
      loadedAt: dynamicPackageInfo.loadedAt
    }));
    return;
  }

  // ROUTE 3: GET /api/status - Trạng thái ứng dụng
  if (req.method === 'GET' && req.url === '/api/status') {
    const mem = process.memoryUsage();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      appName: 'sample-node-app',
      status: 'UP',
      port: PORT,
      pid: process.pid,
      uptimeSec: Math.round(process.uptime()),
      startupPackages: [
        { name: 'axios', version: require('axios/package.json').version },
        { name: 'react', version: require('react/package.json').version }
      ],
      dynamicLoadedPackages: dynamicLoaded ? [dynamicPackageInfo] : [],
      unusedStaticPackages: ['jsonwebtoken'],
      memory: {
        heapUsedMB: +(mem.heapUsed / 1024 / 1024).toFixed(2),
        heapTotalMB: +(mem.heapTotal / 1024 / 1024).toFixed(2),
        rssMB: +(mem.rss / 1024 / 1024).toFixed(2)
      }
    }));
    return;
  }

  // 404
  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Not Found', url: req.url }));
});

server.listen(PORT, () => {
  console.log(`[SAMPLE-APP] 🚀 Server đang chạy tại http://localhost:${PORT}`);
  console.log(`[SAMPLE-APP]   - Trang chủ kiểm thử Browser CDP: http://localhost:${PORT}/`);
  console.log(`[SAMPLE-APP]   - API nạp động: POST http://localhost:${PORT}/api/dynamic-load`);
  console.log(`[SAMPLE-APP]   - API trạng thái: GET http://localhost:${PORT}/api/status`);
});

