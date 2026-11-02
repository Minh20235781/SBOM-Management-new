/**
 * demo-node-app.js - Ứng dụng mẫu Node.js / Express dùng để thử nghiệm Runtime Agent
 * Chạy lệnh:
 *   node -r ./scripts/sbom-runtime-agent.js scripts/demo-node-app.js
 */

const http = require("http");
const path = require("path");

// Thử require một số module trong node_modules nếu có
try {
  const axios = require(path.resolve(__dirname, "../sbom-frontend/node_modules/axios"));
  console.log("   [Demo App] Đã nạp module: axios v" + (axios.VERSION || "1.x"));
} catch (e) {
  // ignore
}

try {
  const xlsx = require(path.resolve(__dirname, "../sbom-frontend/node_modules/xlsx"));
  console.log("   [Demo App] Đã nạp module: xlsx v" + (xlsx.version || "0.18"));
} catch (e) {
  // ignore
}

const server = http.createServer((req, res) => {
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ status: "OK", app: "Demo-Express-Node-App", pid: process.pid }));
});

const PORT = process.env.PORT || 4000;
server.listen(PORT, () => {
  console.log(`\n🚀 [Demo App] Máy chủ demo đang lắng nghe tại: http://localhost:${PORT}`);
  console.log(`💡 Nhìn vào log phía trên để thấy SBOM Runtime Agent tự động bắt require.cache và gửi về backend!`);
});

