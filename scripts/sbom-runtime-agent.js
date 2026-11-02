#!/usr/bin/env node
/**
 * sbom-runtime-agent.js - Runtime Agent Giám Sát Bộ Nhớ V8 Engine cho Node.js / Express / NestJS
 * 
 * Cách gắn vào dự án bất kỳ:
 *   node -r ./scripts/sbom-runtime-agent.js server.js
 * hoặc đối với NestJS:
 *   node -r ./scripts/sbom-runtime-agent.js dist/main.js
 * hoặc trong package.json:
 *   "scripts": { "start": "node -r ./scripts/sbom-runtime-agent.js index.js" }
 */

const fs = require("fs");
const path = require("path");
const http = require("http");

const BACKEND_URL = process.env.SBOM_SERVER_URL || "http://localhost:8080/api/reconciliation/node-agent-collector";
const OUTPUT_FILE = process.env.SBOM_OUTPUT_FILE || "runtime-sbom.json";
const APP_NAME = process.env.npm_package_name || path.basename(process.cwd());

console.log("\n================================================================================");
console.log("🛡️  [SBOM RUNTIME AGENT] KHỞI ĐỘNG GIÁM SÁT BỘ NHỚ V8 ENGINE (NODE.JS)");
console.log(`📌 Ứng dụng: ${APP_NAME} (PID: ${process.pid}) | Node: ${process.version}`);
console.log(`📡 Điểm tiếp nhận: ${BACKEND_URL}`);
console.log("================================================================================\n");

let lastSentChecksum = "";

/**
 * Quét require.cache để trích xuất toàn bộ package thực tế đang nạp trong RAM
 */
function inspectRequireCache() {
  const loadedFiles = Object.keys(require.cache);
  const packageMap = new Map();

  for (const filePath of loadedFiles) {
    if (!filePath.includes("node_modules")) continue;

    // Bóc tách tên package chính xác:
    // Scoped package: @nestjs/core, @babel/parser
    // Normal package: axios, express, lodash
    const scopedMatch = filePath.match(/node_modules[\\/](@[^\\/]+[\\/][^\\/]+)/);
    const normalMatch = filePath.match(/node_modules[\\/]([^\\/]+)/);
    const pkgName = scopedMatch
      ? scopedMatch[1].replace(/\\/g, "/")
      : normalMatch
      ? normalMatch[1]
      : null;

    if (!pkgName) continue;

    if (!packageMap.has(pkgName)) {
      let pkgVersion = "unknown";
      try {
        const parts = filePath.split(/node_modules[\\/]/);
        if (parts.length > 1) {
          const basePath = path.join(
            parts[0],
            "node_modules",
            scopedMatch ? scopedMatch[1] : normalMatch[1]
          );
          const pkgJsonPath = path.join(basePath, "package.json");
          if (fs.existsSync(pkgJsonPath)) {
            const pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, "utf8"));
            pkgVersion = pkgJson.version || "unknown";
          }
        }
      } catch (e) {
        // Thư viện không có package.json
      }

      packageMap.set(pkgName, {
        name: pkgName,
        version: pkgVersion,
        loadedClassesCount: 1,
        runtimeSource: "V8_ENGINE_RAM",
        loadedTime: new Date().toISOString(),
      });
    } else {
      const item = packageMap.get(pkgName);
      item.loadedClassesCount += 1;
    }
  }

  return Array.from(packageMap.values());
}

/**
 * Gửi dữ liệu Runtime SBOM về Backend Spring Boot
 */
async function sendRuntimeSnapshot(triggerReason = "MANUAL") {
  const packages = inspectRequireCache();
  if (packages.length === 0) return;

  const checksum = packages.map(p => `${p.name}@${p.version}:${p.loadedClassesCount}`).sort().join("|");
  if (checksum === lastSentChecksum && triggerReason === "INTERVAL") {
    return; // Không gửi trùng lặp nếu RAM không có module mới
  }
  lastSentChecksum = checksum;

  const memUsage = process.memoryUsage();
  const payload = {
    appName: APP_NAME,
    pid: process.pid.toString(),
    nodeVersion: process.version,
    platform: process.platform,
    timestamp: new Date().toISOString(),
    triggerReason: triggerReason,
    packages: packages,
    memorySnapshot: {
      heapUsedMB: +(memUsage.heapUsed / 1024 / 1024).toFixed(1),
      heapTotalMB: +(memUsage.heapTotal / 1024 / 1024).toFixed(1),
      rssMB: +(memUsage.rss / 1024 / 1024).toFixed(1),
      totalLoadedFiles: Object.keys(require.cache).length
    }
  };

  // 1. Lưu snapshot ra file runtime-sbom.json tại thư mục làm việc
  try {
    fs.writeFileSync(OUTPUT_FILE, JSON.stringify(payload, null, 2), "utf8");
  } catch (err) {
    // ignore
  }

  // 2. Gửi HTTP POST tới Spring Boot backend
  console.log(`[SBOM AGENT] 📦 Đã phát hiện ${packages.length} packages nạp trong V8 RAM (${triggerReason}). Đang gửi tới server...`);

  try {
    const url = new URL(BACKEND_URL);
    const postData = JSON.stringify(payload);

    const req = http.request(
      {
        hostname: url.hostname,
        port: url.port || 80,
        path: url.pathname,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(postData)
        },
        timeout: 3000
      },
      (res) => {
        let respData = "";
        res.on("data", (chunk) => (respData += chunk));
        res.on("end", () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            console.log(`[SBOM AGENT] ✅ ĐÃ GỬI RUNTIME SBOM THÀNH CÔNG! (${packages.length} packages, HTTP ${res.statusCode})`);
          } else {
            console.warn(`[SBOM AGENT] ⚠ Server phản hồi HTTP ${res.statusCode}: ${respData}`);
          }
        });
      }
    );

    req.on("error", (e) => {
      console.warn(`[SBOM AGENT] ⚠ Không thể kết nối tới Backend (${BACKEND_URL}): ${e.message}`);
      console.log(`[SBOM AGENT] 💾 Snapshot vẫn được lưu an toàn tại ${path.resolve(OUTPUT_FILE)}`);
    });

    req.write(postData);
    req.end();
  } catch (err) {
    console.warn(`[SBOM AGENT] Lỗi gửi dữ liệu: ${err.message}`);
  }
}

// ============================================================================
// CƠ CHẾ HOOK TỰ ĐỘNG VÀO TIẾN TRÌNH HTTP SERVER CỦA EXPRESS / NESTJS
// ============================================================================

// Hook 1: Bắt sự kiện khi app.listen() được gọi (Server khởi động xong hoàn toàn)
const originalListen = http.Server.prototype.listen;
http.Server.prototype.listen = function (...args) {
  console.log("\n[SBOM AGENT] 🔍 Phát hiện máy chủ HTTP bắt đầu lắng nghe cổng! Lên lịch quét RAM sau khởi động...");
  setTimeout(() => {
    sendRuntimeSnapshot("SERVER_LISTEN");
  }, 1200);
  return originalListen.apply(this, args);
};

// Hook 2: Định kỳ quét lại mỗi 20 giây để bắt các dynamic import() hoặc lazy-loaded routes
setInterval(() => {
  sendRuntimeSnapshot("INTERVAL");
}, 20000).unref(); // unref() để không chặn tiến trình Node thoát

// Hook 3: Quét lần đầu sau 1.5 giây kể từ khi tiến trình khởi động
setTimeout(() => {
  sendRuntimeSnapshot("STARTUP_PROBE");
}, 1500).unref();

// Hook 4: Quét khi tiến trình chuẩn bị thoát
process.on("beforeExit", () => {
  sendRuntimeSnapshot("PROCESS_EXIT");
});
