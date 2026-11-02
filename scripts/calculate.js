#!/usr/bin/env node
/**
 * calculate.js - Thuật Toán Đối Sánh Giữa SBOM Tĩnh và SBOM Runtime Log
 * Đọc 2 nguồn đầu vào:
 *   1. File SBOM Tĩnh (Static SBOM JSON - CycloneDX / SPDX)
 *   2. File Log Runtime (Được sinh từ dump-packages.js hoặc Browser/RAM Inspector)
 * 
 * Cách dùng:
 *   node scripts/calculate.js <file_sbom_tinh.json> <file_log_runtime.json> [bao_cao_output.json]
 * Ví dụ:
 *   node scripts/calculate.js Lakhe-Management-sbom-cyclonedx.json runtime-log.json
 */

const fs = require("fs");
const path = require("path");

const staticSbomPath = process.argv[2];
const runtimeLogPath = process.argv[3];
const outputReportPath = process.argv[4] || `reconciliation-report-${Date.now()}.json`;

if (!staticSbomPath || !runtimeLogPath) {
  console.log(`❌ THIẾU THAM SỐ ĐẦU VÀO!`);
  console.log(`Cú pháp: node scripts/calculate.js <static_sbom.json> <runtime_log.json> [output.json]`);
  console.log(`Ví dụ:   node scripts/calculate.js sbom-build.json runtime-log.json\n`);
  process.exit(1);
}

console.log(`================================================================`);
console.log(`⚖️  [CALCULATE.JS] TIẾN HÀNH ĐỐI SÁNH SBOM THEO TRACK CHANGES`);
console.log(`📄 Nguồn 1 (SBOM Tĩnh/Cơ sở): ${staticSbomPath}`);
console.log(`🌐 Nguồn 2 (SBOM Runtime Log): ${runtimeLogPath}`);
console.log(`================================================================\n`);

function parseStaticSbom(filePath) {
  const content = JSON.parse(fs.readFileSync(filePath, "utf8"));
  const packages = [];

  if (content.components && Array.isArray(content.components)) {
    // CycloneDX format
    for (const comp of content.components) {
      let name = comp.name;
      if (comp.group && !name.includes(comp.group)) {
        name = `${comp.group}:${name}`;
      }
      packages.push({
        name: name,
        version: comp.version || "unknown",
        scope: comp.scope || comp.type || "compile",
        purl: comp.purl || "",
        vulnerabilities: []
      });
    }
  } else if (content.packages && Array.isArray(content.packages)) {
    // SPDX format
    for (const p of content.packages) {
      packages.push({
        name: p.name,
        version: p.versionInfo || "unknown",
        scope: "compile",
        purl: "",
        vulnerabilities: []
      });
    }
  } else if (Array.isArray(content)) {
    // Generic array
    for (const p of content) {
      packages.push({
        name: p.name || p.packageName,
        version: p.version || "unknown",
        scope: p.scope || "compile",
        vulnerabilities: []
      });
    }
  }

  return packages;
}

function parseRuntimeLog(filePath) {
  const content = JSON.parse(fs.readFileSync(filePath, "utf8"));
  if (content.detectedRuntimePackages && Array.isArray(content.detectedRuntimePackages)) {
    return {
      metadata: content,
      packages: content.detectedRuntimePackages
    };
  } else if (Array.isArray(content)) {
    return {
      metadata: { targetUrl: "Local / Snapshot" },
      packages: content
    };
  }
  return { metadata: {}, packages: [] };
}

function normalize(str) {
  if (!str) return "";
  return str.trim().toLowerCase();
}

function main() {
  const staticPackages = parseStaticSbom(staticSbomPath);
  const runtimeData = parseRuntimeLog(runtimeLogPath);
  const runtimePackages = runtimeData.packages;

  console.log(`[1] Đọc dữ liệu đầu vào:`);
  console.log(`    • Nguồn 1 (SBOM Tĩnh): ${staticPackages.length} packages khai báo`);
  console.log(`    • Nguồn 2 (SBOM Runtime): ${runtimePackages.length} packages thực tế nạp`);

  // Tạo map runtime
  const runtimeMap = new Map();
  for (const r of runtimePackages) {
    runtimeMap.set(normalize(r.name), r);
  }

  const matchedRuntimeKeys = new Set();
  const reconciledItems = [];

  let matchedCount = 0;
  let deadOrUnusedCount = 0;
  let buildTestOnlyCount = 0;
  let versionDriftCount = 0;
  let shadowInjectedCount = 0;

  // 1. Duyệt qua toàn bộ gói trong SBOM Tĩnh
  for (const pkg of staticPackages) {
    const normName = normalize(pkg.name);
    let runtimeMatch = runtimeMap.get(normName);

    // Thử khớp lỏng (fuzzy match qua tên đuôi)
    if (!runtimeMatch) {
      for (const [k, v] of runtimeMap.entries()) {
        if (k.endsWith(":" + normName) || normName.endsWith(":" + k) || k.includes(normName) || normName.includes(k)) {
          runtimeMatch = v;
          matchedRuntimeKeys.add(k);
          break;
        }
      }
    } else {
      matchedRuntimeKeys.add(normName);
    }

    const hasRuntime = !!runtimeMatch;
    const isTest = normName.includes("test") || normName.includes("junit") || pkg.scope.toLowerCase().includes("test") || pkg.scope.toLowerCase().includes("dev");

    if (hasRuntime) {
      // Kiểm tra Version Drift
      const vStatic = (pkg.version || "").trim();
      const vRuntime = (runtimeMatch.version || "").trim();
      const isDrift = vStatic && vRuntime && vStatic.toLowerCase() !== vRuntime.toLowerCase() && vStatic !== "unknown" && vRuntime !== "unknown";

      if (isDrift) {
        versionDriftCount++;
        reconciledItems.push({
          packageName: pkg.name,
          category: "VERSION_DRIFT",
          diffType: "MODIFIED",
          declaredVersion: vStatic,
          runtimeVersion: vRuntime,
          loadedClassesCount: runtimeMatch.loadedClassesCount || 1,
          runtimeSource: runtimeMatch.runtimeSource || "V8_RUNTIME",
          technicalReason: `Lệch phiên bản: Static SBOM khai báo v${vStatic} nhưng Runtime đang nạp v${vRuntime}.`,
          remediation: `Đồng bộ lại phiên bản lockfile và build pipeline.`
        });
      } else {
        matchedCount++;
        reconciledItems.push({
          packageName: pkg.name,
          category: "MATCHED_RUNNING",
          diffType: "UNCHANGED",
          declaredVersion: vStatic,
          runtimeVersion: vRuntime,
          loadedClassesCount: runtimeMatch.loadedClassesCount || 1,
          runtimeSource: runtimeMatch.runtimeSource || "V8_RUNTIME",
          technicalReason: `Khớp 100%: Thư viện có trong khai báo và được nạp đầy đủ trong bộ nhớ.`,
          remediation: `Không cần xử lý.`
        });
      }
    } else {
      // Có trong tĩnh nhưng KHÔNG có trong runtime
      if (isTest) {
        buildTestOnlyCount++;
        reconciledItems.push({
          packageName: pkg.name,
          category: "BUILD_TEST_ONLY",
          diffType: "REMOVED",
          declaredVersion: pkg.version,
          runtimeVersion: null,
          loadedClassesCount: 0,
          runtimeSource: "EXCLUDED_FROM_PROD",
          technicalReason: `Thư viện Test/Dev chỉ phục vụ compile-time, an toàn khi không đưa vào Production.`,
          remediation: `Giữ nguyên phạm vi scope=test/devDependencies.`
        });
      } else {
        deadOrUnusedCount++;
        reconciledItems.push({
          packageName: pkg.name,
          category: "DEAD_OR_UNUSED",
          diffType: "REMOVED",
          declaredVersion: pkg.version,
          runtimeVersion: null,
          loadedClassesCount: 0,
          runtimeSource: "UNUSED_MANIFEST",
          technicalReason: `MÃ CHẾT (Dead Code): Khai báo trong SBOM tĩnh nhưng 0 byte/class được nạp vào RAM.`,
          remediation: `Gỡ bỏ khỏi package.json/pom.xml để thu hẹp bề mặt tấn công.`
        });
      }
    }
  }

  // 2. Duyệt các gói trong Runtime mà KHÔNG có trong SBOM Tĩnh -> SHADOW INJECTED
  for (const [k, rPkg] of runtimeMap.entries()) {
    if (!matchedRuntimeKeys.has(k)) {
      shadowInjectedCount++;
      reconciledItems.push({
        packageName: rPkg.name,
        category: "SHADOW_INJECTED",
        diffType: "ADDED",
        declaredVersion: null,
        runtimeVersion: rPkg.version,
        loadedClassesCount: rPkg.loadedClassesCount || 1,
        runtimeSource: rPkg.runtimeSource || "DYNAMIC_INJECTION",
        technicalReason: `THƯ VIỆN LẠ (Shadow Dependency): Đang chạy trong RAM nhưng hoàn toàn vắng mặt trong SBOM tĩnh.`,
        remediation: `Rà soát mã nguồn khẩn cấp, chặn CDN ngoại lai không rõ nguồn gốc.`
      });
    }
  }

  // Tính toán SBOM Trust Score
  const totalObserved = matchedCount + versionDriftCount + shadowInjectedCount;
  const runtimeCoverage = totalObserved > 0 ? (matchedCount + versionDriftCount) / totalObserved : 1.0;
  const buildUtility = staticPackages.length > 0 ? (matchedCount + versionDriftCount) / staticPackages.length : 1.0;
  const shadowPenalty = 1.0 / (1.0 + 0.15 * shadowInjectedCount);
  const trustScore10 = +(Math.sqrt(runtimeCoverage * buildUtility) * shadowPenalty * 10).toFixed(2);

  const report = {
    summary: {
      calculatedAt: new Date().toISOString(),
      staticSbomSource: staticSbomPath,
      runtimeLogSource: runtimeLogPath,
      targetUrl: runtimeData.metadata?.targetUrl || "N/A",
      totalStaticPackages: staticPackages.length,
      totalRuntimePackages: runtimePackages.length,
      matchedCount: matchedCount,
      buildTestOnlyCount: buildTestOnlyCount,
      deadOrUnusedCount: deadOrUnusedCount,
      shadowInjectedCount: shadowInjectedCount,
      versionDriftCount: versionDriftCount,
      sbomTrustScore10: trustScore10
    },
    packages: reconciledItems
  };

  fs.writeFileSync(outputReportPath, JSON.stringify(report, null, 2), "utf8");

  console.log(`\n================================================================`);
  console.log(`📊 KẾT QUẢ ĐỐI SÁNH TRACK CHANGES:`);
  console.log(`   ✓ Trùng khớp (Matched Running):      ${matchedCount}`);
  console.log(`   - Dead Code / Mã thừa:               ${deadOrUnusedCount}`);
  console.log(`   - Phạm vi Test/Dev (Test Only):      ${buildTestOnlyCount}`);
  console.log(`   + Thư viện Lạ (Shadow Injected):     ${shadowInjectedCount}`);
  console.log(`   ~ Lệch phiên bản (Version Drift):    ${versionDriftCount}`);
  console.log(`----------------------------------------------------------------`);
  console.log(`⭐ Điểm Tin Cậy SBOM (Trust Score):      ${trustScore10} / 10`);
  console.log(`📁 Đã lưu file báo cáo:                  ${path.resolve(outputReportPath)}`);
  console.log(`================================================================\n`);
}

main();

