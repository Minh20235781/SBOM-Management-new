/**
 * nodejs-agent.js - Node.js Server Runtime Instrumentation Agent
 * 
 * Thu thập Runtime Evidence thực tế phía Server cho các ứng dụng Node.js / Express / Next.js:
 * 1. Module Loading Interception (Module._load hook + require.cache)
 * 2. Caller Tracing (Parent module -> Child module relationship)
 * 3. Package & Version Resolution từ package.json thực tế trên đĩa
 * 4. Process Memory & Resource Monitoring (process.memoryUsage, getActiveResourcesInfo)
 * 5. Server HTTP Request Interception (phân biệt request máy chủ xử lý)
 * 6. Ghi log chuẩn JSON Lines (.jsonl) và JSON Evidence Store phục vụ kiểm chứng
 */

const Module = require('module');
const fs = require('fs');
const path = require('path');
const http = require('http');

const LOG_DIR = process.env.SBOM_EVIDENCE_DIR || path.resolve(process.cwd(), 'runtime-evidence');
const EVENTS_LOG_FILE = path.join(LOG_DIR, 'server-module-events.jsonl');
const INVENTORY_FILE = path.join(LOG_DIR, 'server-runtime-inventory.json');
const HTTP_REQUESTS_LOG_FILE = path.join(LOG_DIR, 'server-http-requests.jsonl');
const BACKEND_URL = process.env.SBOM_SERVER_URL || 'http://localhost:8080/api/reconciliation/node-agent-collector';

const APP_NAME = process.env.npm_package_name || path.basename(process.cwd());
const PID = process.pid;
const NODE_VERSION = process.version;
const START_TIME = new Date().toISOString();

// Đảm bảo thư mục lưu trữ bằng chứng tồn tại
if (!fs.existsSync(LOG_DIR)) {
  fs.mkdirSync(LOG_DIR, { recursive: true });
}

// Luồng ghi file streaming
const eventsStream = fs.createWriteStream(EVENTS_LOG_FILE, { flags: 'a', encoding: 'utf8' });
const httpStream = fs.createWriteStream(HTTP_REQUESTS_LOG_FILE, { flags: 'a', encoding: 'utf8' });

// Bộ đệm lưu trữ bằng chứng module phía server
const loadedPackagesMap = new Map();
let totalModuleLoads = 0;
let eventSeq = 0;

console.log('\n================================================================================');
console.log('🛡️  [NODE.JS RUNTIME AGENT] KHỞI ĐỘNG INSTRUMENTATION MODULE & RUNTIME EVIDENCE');
console.log(`📌 Ứng dụng: ${APP_NAME} | PID: ${PID} | Node: ${NODE_VERSION}`);
console.log(`📁 Thư mục lưu bằng chứng: ${LOG_DIR}`);
console.log(`📡 Điểm gửi Backend: ${BACKEND_URL}`);
console.log('================================================================================\n');

/**
 * Trích xuất tên package từ đường dẫn vật lý trên đĩa
 */
function parsePackageInfoFromPath(filePath) {
  if (!filePath || !filePath.includes('node_modules')) return null;

  const parts = filePath.split(/[\\/]node_modules[\\/]/);
  if (parts.length < 2) return null;

  const sub = parts[parts.length - 1]; // Phần sau node_modules cuối cùng
  let pkgName = null;
  let pkgDirName = null;

  if (sub.startsWith('@')) {
    const segments = sub.split(/[\\/]/);
    if (segments.length >= 2) {
      pkgName = `${segments[0]}/${segments[1]}`;
      pkgDirName = path.join(segments[0], segments[1]);
    }
  } else {
    const segments = sub.split(/[\\/]/);
    pkgName = segments[0];
    pkgDirName = segments[0];
  }

  if (!pkgName) return null;

  // Tìm package.json tương ứng của package này
  const baseDir = parts.slice(0, parts.length - 1).join(path.sep + 'node_modules' + path.sep);
  const pkgJsonPath = path.join(baseDir, 'node_modules', pkgDirName, 'package.json');
  let pkgVersion = 'VERSION_UNKNOWN';

  try {
    if (fs.existsSync(pkgJsonPath)) {
      const data = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
      pkgVersion = data.version || 'VERSION_UNKNOWN';
    }
  } catch (err) {}

  return {
    name: pkgName,
    version: pkgVersion,
    packageJsonPath: fs.existsSync(pkgJsonPath) ? pkgJsonPath : null
  };
}

// ============================================================================
// 1. INTERCEPT MODULE._LOAD (COMMONJS & TRANSPILED ESM IN NEXT.JS / NODE.JS)
// ============================================================================
const originalModuleLoad = Module._load;

Module._load = function (request, parent, isMain) {
  const t0 = process.hrtime.bigint();
  let resolvedFilename = null;

  try {
    resolvedFilename = Module._resolveFilename(request, parent, isMain);
  } catch (e) {
    // Không thể resolve trước khi load
  }

  // Gọi hàm load gốc của V8/Node.js Module
  const loadedModule = originalModuleLoad.apply(this, arguments);

  try {
    const filename = resolvedFilename || (loadedModule && loadedModule.filename) || null;

    if (filename && filename.includes('node_modules')) {
      const pkgInfo = parsePackageInfoFromPath(filename);
      if (pkgInfo) {
        totalModuleLoads++;
        eventSeq++;
        const now = new Date().toISOString();
        const durationNs = Number(process.hrtime.bigint() - t0);
        const caller = parent ? parent.filename : '(entrypoint)';

        const eventRecord = {
          seq: eventSeq,
          type: 'MODULE_LOADED',
          packageName: pkgInfo.name,
          packageVersion: pkgInfo.version,
          modulePath: filename,
          specifier: request,
          callerFile: caller,
          timestamp: now,
          durationNs: durationNs,
          pid: PID,
          loadingMechanism: 'CommonJS_Module_Load'
        };

        // Ghi vào file JSON Lines stream
        eventsStream.write(JSON.stringify(eventRecord) + '\n');

        // Cập nhật thống kê package
        const key = pkgInfo.name.toLowerCase();
        if (!loadedPackagesMap.has(key)) {
          loadedPackagesMap.set(key, {
            name: pkgInfo.name,
            version: pkgInfo.version,
            firstLoadedAt: now,
            lastLoadedAt: now,
            loadCount: 1,
            sampleFile: filename,
            callerFile: caller,
            runtimeSource: 'NODEJS_SERVER_MODULE_LOAD',
            hasExecutionEvidence: true
          });
          console.log(`[NODE.JS AGENT] 📦 Đã nạp package: ${pkgInfo.name}@${pkgInfo.version} (từ: ${path.basename(caller)})`);
        } else {
          const item = loadedPackagesMap.get(key);
          item.loadCount += 1;
          item.lastLoadedAt = now;
          if (item.version === 'VERSION_UNKNOWN' && pkgInfo.version !== 'VERSION_UNKNOWN') {
            item.version = pkgInfo.version;
          }
        }
      }
    }
  } catch (err) {}

  return loadedModule;
};

// ============================================================================
// 2. INTERCEPT HTTP SERVER (BẮT CÁC REQUEST MÁY CHỦ XỬ LÝ)
// ============================================================================
const originalListen = http.Server.prototype.listen;
http.Server.prototype.listen = function (...args) {
  const server = this;
  const port = args[0] || 'unknown';
  console.log(`\n[NODE.JS AGENT] 🌐 Máy chủ HTTP bắt đầu lắng nghe cổng: ${port} (PID: ${PID})`);

  // Bắt sự kiện request gửi tới máy chủ Node.js
  server.on('request', (req, res) => {
    const reqRecord = {
      type: 'SERVER_HTTP_REQUEST',
      method: req.method,
      url: req.url,
      timestamp: new Date().toISOString(),
      clientIp: req.socket?.remoteAddress || '127.0.0.1',
      headers: {
        host: req.headers['host'],
        userAgent: req.headers['user-agent']
      }
    };
    httpStream.write(JSON.stringify(reqRecord) + '\n');
  });

  // Sau khi server bật xong, quét require.cache để gom các module đã nạp trước khi hook
  setTimeout(() => {
    scanRequireCache();
    saveRuntimeInventory('SERVER_LISTEN');
  }, 1000);

  return originalListen.apply(this, args);
};

/**
 * Quét require.cache để đối chiếu và bảo đảm không sót module nạp sớm
 */
function scanRequireCache() {
  const cachedFiles = Object.keys(require.cache);
  for (const filename of cachedFiles) {
    if (!filename.includes('node_modules')) continue;
    const pkgInfo = parsePackageInfoFromPath(filename);
    if (!pkgInfo) continue;

    const key = pkgInfo.name.toLowerCase();
    if (!loadedPackagesMap.has(key)) {
      const now = new Date().toISOString();
      loadedPackagesMap.set(key, {
        name: pkgInfo.name,
        version: pkgInfo.version,
        firstLoadedAt: now,
        lastLoadedAt: now,
        loadCount: 1,
        sampleFile: filename,
        callerFile: '(early_require_cache)',
        runtimeSource: 'NODEJS_REQUIRE_CACHE',
        hasExecutionEvidence: true
      });
      console.log(`[NODE.JS AGENT] 🔍 Bắt từ require.cache: ${pkgInfo.name}@${pkgInfo.version}`);
    }
  }
}

/**
 * Xuất file tổng hợp Runtime Evidence Inventory ra đĩa và gửi sang Backend
 */
function saveRuntimeInventory(triggerReason = 'MANUAL') {
  scanRequireCache();

  const mem = process.memoryUsage();
  const packageList = Array.from(loadedPackagesMap.values());

  const activeResources = typeof process.getActiveResourcesInfo === 'function'
    ? process.getActiveResourcesInfo()
    : [];

  const inventory = {
    appName: APP_NAME,
    pid: PID.toString(),
    nodeVersion: NODE_VERSION,
    platform: process.platform,
    startedAt: START_TIME,
    generatedAt: new Date().toISOString(),
    triggerReason: triggerReason,
    totalModuleLoadEvents: totalModuleLoads,
    uniquePackageCount: packageList.length,
    packages: packageList,
    runtimeMetrics: {
      heapUsedMB: +(mem.heapUsed / 1024 / 1024).toFixed(2),
      heapTotalMB: +(mem.heapTotal / 1024 / 1024).toFixed(2),
      rssMB: +(mem.rss / 1024 / 1024).toFixed(2),
      externalMB: +(mem.external / 1024 / 1024).toFixed(2),
      activeResourcesCount: activeResources.length
    }
  };

  try {
    fs.writeFileSync(INVENTORY_FILE, JSON.stringify(inventory, null, 2), 'utf8');
    console.log(`[NODE.JS AGENT] 💾 Đã lưu Server Runtime Inventory: ${INVENTORY_FILE} (${packageList.length} packages)`);
  } catch (err) {
    console.warn(`[NODE.JS AGENT] Lỗi ghi file inventory: ${err.message}`);
  }

  // Gửi sang Backend nếu máy chủ Spring Boot đang chạy
  sendToBackend(inventory);
}

function sendToBackend(inventory) {
  try {
    const url = new URL(BACKEND_URL);
    const postData = JSON.stringify({
      appName: inventory.appName,
      pid: inventory.pid,
      timestamp: inventory.generatedAt,
      packages: inventory.packages.map(p => ({
        name: p.name,
        version: p.version,
        loadedClassesCount: p.loadCount,
        loadedTime: p.lastLoadedAt,
        source: p.runtimeSource
      })),
      memorySnapshot: inventory.runtimeMetrics
    });

    const req = http.request(
      {
        hostname: url.hostname,
        port: url.port || 80,
        path: url.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(postData)
        },
        timeout: 2000
      },
      (res) => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          console.log(`[NODE.JS AGENT] 📡 Đã đồng bộ sang Spring Boot backend (${inventory.packages.length} packages, HTTP ${res.statusCode})`);
        }
      }
    );

    req.on('error', () => {
      // Bỏ qua lỗi kết nối nếu backend chưa bật
    });

    req.write(postData);
    req.end();
  } catch (e) {}
}

// ============================================================================
// 3. ĐỊNH KỲ QUÉT VÀ HOOK KHI THOÁT
// ============================================================================
setInterval(() => {
  saveRuntimeInventory('INTERVAL_HEARTBEAT');
}, 15000).unref();

process.on('beforeExit', () => {
  saveRuntimeInventory('PROCESS_EXIT');
  try {
    eventsStream.end();
    httpStream.end();
  } catch (e) {}
});

module.exports = {
  getLoadedPackages: () => Array.from(loadedPackagesMap.values()),
  saveRuntimeInventory
};

