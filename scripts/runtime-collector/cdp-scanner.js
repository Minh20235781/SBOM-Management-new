#!/usr/bin/env node
/**
 * cdp-scanner.js - Chromium CDP Instrumentation & Runtime Evidence Collector
 * 
 * Thu thập dữ liệu Runtime thực tế từ Google Chrome qua Chrome DevTools Protocol:
 * 1. Network Events (URL, status, size, duration, MIME, SHA-256 hash)
 * 2. JavaScript Execution Context & Script parsing (Debugger.scriptParsed)
 * 3. Execution Coverage (Profiler.startPreciseCoverage / takePreciseCoverage)
 * 4. Memory Metrics (Performance.getMetrics - JSHeapUsedSize, JSHeapTotalSize)
 * 5. Source Map & Bundle Analysis (trích xuất cấu trúc node_modules)
 * 6. Sinh CycloneDX 1.4 SBOM và file log evidence kiểm chứng
 */

const puppeteer = require('puppeteer-core');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const CHROME_PATH = process.env.CHROME_BIN || 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';

/**
 * Tính mã băm SHA-256 của nội dung
 */
function sha256(content) {
  if (!content) return '';
  return crypto.createHash('sha256').update(content).digest('hex');
}

/**
 * Phân tích tên package từ đường dẫn file trong node_modules (Source Map)
 */
function extractPackageFromNodeModulesPath(filePath) {
  if (!filePath || !filePath.includes('node_modules')) return null;

  const scopedMatch = filePath.match(/node_modules[\\/](@[^\\/]+[\\/][^\\/]+)/);
  if (scopedMatch) {
    return { name: scopedMatch[1].replace(/\\/g, '/'), subpath: filePath };
  }

  const normalMatch = filePath.match(/node_modules[\\/]([^\\/]+)/);
  if (normalMatch && !normalMatch[1].startsWith('.')) {
    return { name: normalMatch[1], subpath: filePath };
  }

  return null;
}

/**
 * Thư viện các chữ ký nhận diện thư viện bên trong mã nguồn JavaScript (Bundle Fingerprints)
 */
const PACKAGE_FINGERPRINTS = [
  {
    name: 'react',
    test: (code) => code.includes('React.createElement') || code.includes('react.element') || code.includes('__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED') || (code.includes('jsxRuntime') && code.includes('react')),
    defaultVersion: null
  },
  {
    name: 'react-dom',
    test: (code) => code.includes('react-dom') || code.includes('createRoot') || code.includes('hydrateRoot') || code.includes('ReactDOM'),
    defaultVersion: null
  },
  {
    name: 'next',
    test: (code, url) => url.includes('/_next/') || code.includes('__NEXT_DATA__') || code.includes('next/router') || code.includes('next/dist/'),
    defaultVersion: null
  },
  {
    name: 'axios',
    test: (code, url) => url.includes('axios') || code.includes('AxiosError') || code.includes('isAxiosError') || (code.includes('axios') && code.includes('createInstance')),
    defaultVersion: null
  },
  {
    name: '@supabase/supabase-js',
    test: (code, url) => url.includes('supabase') || code.includes('SupabaseClient') || code.includes('@supabase/gotrue-js') || code.includes('supabase.auth'),
    defaultVersion: null
  },
  {
    name: 'lucide-react',
    test: (code, url) => url.includes('lucide') || code.includes('createLucideIcon') || code.includes('LucideIcon'),
    defaultVersion: null
  },
  {
    name: '@tanstack/react-query',
    test: (code, url) => url.includes('query') && (code.includes('QueryClient') || code.includes('useQuery') || code.includes('@tanstack/react-query')),
    defaultVersion: null
  },
  {
    name: 'lodash',
    test: (code, url) => url.includes('lodash') || (code.includes('lodash') && code.includes('_.isObject')),
    defaultVersion: null
  },
  {
    name: 'clsx',
    test: (code) => code.includes('clsx') && code.includes('toVal'),
    defaultVersion: null
  },
  {
    name: 'tailwind-merge',
    test: (code) => code.includes('twMerge') || code.includes('tailwind-merge'),
    defaultVersion: null
  },
  {
    name: 'xlsx',
    test: (code, url) => url.includes('xlsx') || code.includes('XLSX.read') || code.includes('SheetJS'),
    defaultVersion: null
  }
];

/**
 * Nhận diện package từ URL CDN có version rõ ràng
 */
function identifyFromCdnUrl(url) {
  if (!url) return null;
  let address;
  try { address = new URL(url); } catch { return null; }
  const prefix = { 'cdn.jsdelivr.net': '/npm/', 'unpkg.com': '/' }[address.hostname];
  if (!prefix || !address.pathname.startsWith(prefix)) return null;
  const match = address.pathname.slice(prefix.length).match(/^((?:@[a-z0-9_.-]+\/)?[a-z0-9_.-]+)@(\d+\.\d+\.\d+(?:[-+][0-9a-z.-]+)?)(?:\/|$)/i);
  if (match) {
    return {
      name: match[1],
      version: match[2],
      method: 'CDN_STRUCTURED_URL',
      confidence: 'HIGH',
      evidence: `Nhận diện từ URL CDN chứa phiên bản cố định: ${match[1]}@${match[2]}`
    };
  }
  return null;
}

/**
 * Thực hiện phiên quét Chrome DevTools Protocol thực tế
 */
async function runCdpScan(targetUrl, options = {}) {
  const timeoutMs = options.timeoutMs || 30000;
  const headless = options.headless !== false;
  const sessionId = 'CDP-' + crypto.randomBytes(4).toString('hex').toUpperCase() + '-' + Date.now();
  const startTime = Date.now();

  console.error(`[CDP Instrumentation] Khởi động trình duyệt Chromium cho: ${targetUrl} (Session: ${sessionId})`);

  let browser;
  try {
    browser = await puppeteer.launch({
      executablePath: CHROME_PATH,
      headless: headless ? 'new' : false,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-gpu',
        '--disable-dev-shm-usage',
        '--window-size=1280,800'
      ]
    });

    const page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 800 });

    const cdp = await page.target().createCDPSession();

    // 1. Kích hoạt các domain CDP
    await cdp.send('Network.enable', { maxResourceBufferSize: 10485760, maxTotalBufferSize: 52428800 });
    await cdp.send('Debugger.enable');
    await cdp.send('Profiler.enable');
    await cdp.send('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
    await cdp.send('Performance.enable');

    const networkRequests = [];
    const responseBodies = new Map();
    const scriptsParsed = new Map();

    // Lắng nghe sự kiện Network
    cdp.on('Network.requestWillBeSent', (e) => {
      networkRequests.push({
        requestId: e.requestId,
        url: e.request.url,
        method: e.request.method,
        initiator: e.initiator ? e.initiator.type : 'other',
        timestamp: e.wallTime ? Math.round(e.wallTime * 1000) : Date.now(),
        startedAt: e.timestamp,
        status: null,
        mimeType: null,
        type: null,
        sizeBytes: 0,
        latencyMs: null,
        contentHash: ''
      });
    });

    cdp.on('Network.responseReceived', (e) => {
      const existing = networkRequests.findLast(r => r.requestId === e.requestId);
      if (existing) {
        existing.status = e.response.status;
        if (!e.response.fromDiskCache && !e.response.fromServiceWorker) {
          existing.backendRequestId = Object.entries(e.response.headers || {}).find(([key]) => key.toLowerCase() === 'x-sbom-request-id')?.[1];
        }
        existing.mimeType = e.response.mimeType;
        existing.type = e.type ? e.type.toLowerCase() : 'other';
        existing.fromCache = !!e.response.fromDiskCache || !!e.response.fromServiceWorker;
        existing.encodedDataLength = e.response.encodedDataLength || 0;
      }
    });

    cdp.on('Network.loadingFinished', (e) => {
      const existing = networkRequests.findLast(r => r.requestId === e.requestId);
      if (existing) {
        existing.sizeBytes = e.encodedDataLength ?? null;
        existing.latencyMs = Math.max(0, Math.round((e.timestamp - existing.startedAt) * 1000));
      }
    });

    // Lắng nghe sự kiện JavaScript Runtime
    cdp.on('Debugger.scriptParsed', (s) => {
      scriptsParsed.set(s.scriptId, {
        scriptId: s.scriptId,
        url: s.url,
        startLine: s.startLine,
        startColumn: s.startColumn,
        endLine: s.endLine,
        endColumn: s.endColumn,
        length: s.length || 0,
        sourceMapURL: s.sourceMapURL || '',
        contentHash: s.hash || '',
        hasExecutionEvidence: false,
        executedBytes: 0
      });
    });

    // 2. Mở URL mục tiêu và đợi nạp mạng hoàn tất
    console.error(`[CDP Instrumentation] Đang tải trang ${targetUrl}...`);
    const response = await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: timeoutMs });
    if (!response || response.status() >= 400) {
      throw new Error(`Không tải được ứng dụng mục tiêu (HTTP ${response?.status() ?? 'không rõ'}).`);
    }

    // Cho phép trang web thực thi các script khởi tạo trong 2 giây
    await new Promise(r => setTimeout(r, options.observeMs ?? 2000));

    // 3. Thu thập Coverage và Memory Metrics
    console.error(`[CDP Instrumentation] Thu thập Execution Coverage và Performance metrics...`);
    let coverageData = { result: [] };
    try {
      coverageData = await cdp.send('Profiler.takePreciseCoverage');
      await cdp.send('Profiler.stopPreciseCoverage');
    } catch (covErr) {
      console.error(`[CDP Instrumentation] Lỗi lấy coverage: ${covErr.message}`);
    }

    let memoryMetrics = {};
    try {
      const metrics = await cdp.send('Performance.getMetrics');
      if (metrics && metrics.metrics) {
        metrics.metrics.forEach(m => {
          memoryMetrics[m.name] = m.value;
        });
      }
    } catch (memErr) {
      console.error(`[CDP Instrumentation] Lỗi lấy memory: ${memErr.message}`);
    }

    // Đánh dấu Execution Evidence cho từng script dựa trên coverage
    if (coverageData.result) {
      coverageData.result.forEach(cov => {
        const script = scriptsParsed.get(cov.scriptId);
        if (script) {
          let executed = 0;
          cov.functions.forEach(fn => {
            fn.ranges.forEach(rng => {
              if (rng.count > 0) {
                executed += (rng.endOffset - rng.startOffset);
              }
            });
          });
          if (executed > 0) {
            script.hasExecutionEvidence = true;
            script.executedBytes = executed;
          }
        }
      });
    }

    // 4. Lấy nội dung script để tính SHA-256 và phân tích Bundle / Source Map
    console.error(`[CDP Instrumentation] Phân tích nội dung scripts và Source Maps...`);
    const identifiedPackages = new Map();

    for (const [scriptId, script] of scriptsParsed.entries()) {
      let scriptSource = '';
      try {
        const srcRes = await cdp.send('Debugger.getScriptSource', { scriptId });
        scriptSource = srcRes.scriptSource || '';
      } catch (e) {
        // bỏ qua nếu script inline hoặc bị hủy
      }

      if (scriptSource) {
        script.contentHash = sha256(scriptSource);

        // A. Kiểm tra Source Map URL nếu có
        if (script.sourceMapURL) {
          let mapContent = null;
          try {
            if (script.sourceMapURL.startsWith('data:application/json;base64,')) {
              const b64 = script.sourceMapURL.replace('data:application/json;base64,', '');
              mapContent = JSON.parse(Buffer.from(b64, 'base64').toString('utf8'));
            } else {
              const mapUrl = new URL(script.sourceMapURL, script.url || targetUrl).toString();
              const mapResp = await page.evaluate(async (u) => {
                const res = await fetch(u);
                return res.ok ? await res.json() : null;
              }, mapUrl).catch(() => null);
              mapContent = mapResp;
            }
          } catch (smErr) {}

          if (mapContent && Array.isArray(mapContent.sources)) {
            script.hasSourceMap = true;
            mapContent.sources.forEach(srcPath => {
              const extracted = extractPackageFromNodeModulesPath(srcPath);
              if (extracted) {
                const key = extracted.name.toLowerCase();
                if (!identifiedPackages.has(key)) {
                  identifiedPackages.set(key, {
                    name: extracted.name,
                    version: 'VERSION_UNKNOWN',
                    confidence: 'HIGH',
                    identificationMethod: 'SOURCE_MAP_NODE_MODULES',
                    hasExecutionEvidence: script.hasExecutionEvidence,
                    evidence: `Xác minh cấu trúc source map: ${srcPath} trong file ${script.url || 'bundle'}`,
                    scriptUrl: script.url,
                    scriptHash: script.contentHash
                  });
                }
              }
            });
          }
        }

        // B. Phân tích Fingerprint trong nội dung mã nguồn JavaScript
        PACKAGE_FINGERPRINTS.forEach(pkg => {
          if (pkg.test(scriptSource, script.url || '')) {
            const key = pkg.name.toLowerCase();
            const ver = 'VERSION_UNKNOWN';

            if (!identifiedPackages.has(key)) {
              identifiedPackages.set(key, {
                name: pkg.name,
                version: ver,
                confidence: script.hasExecutionEvidence ? 'MEDIUM' : 'LOW',
                identificationMethod: 'BUNDLE_CODE_FINGERPRINT',
                hasExecutionEvidence: script.hasExecutionEvidence,
                evidence: `Nhận diện từ chữ ký mã lệnh trong script ${script.url ? path.basename(script.url.split('?')[0]) : 'inline'} (Hash: ${script.contentHash.substring(0, 10)})`,
                scriptUrl: script.url,
                scriptHash: script.contentHash
              });
            }
          }
        });
      }
    }

    // C. Nhận diện từ Network CDN URLs
    networkRequests.forEach(req => {
      const cdn = req.status >= 200 && req.status < 300 ? identifyFromCdnUrl(req.url) : null;
      if (cdn) {
        const key = cdn.name.toLowerCase() + '@' + cdn.version;
        const fingerprint = identifiedPackages.get(cdn.name.toLowerCase());
        if (fingerprint?.scriptUrl === req.url) identifiedPackages.delete(cdn.name.toLowerCase());
        if (!identifiedPackages.has(key)) {
          identifiedPackages.set(key, {
            name: cdn.name,
            version: cdn.version,
            confidence: cdn.confidence,
            identificationMethod: cdn.method,
            hasExecutionEvidence: Array.from(scriptsParsed.values()).some((script) => script.url === req.url && script.hasExecutionEvidence),
            evidence: cdn.evidence,
            scriptUrl: req.url,
            scriptHash: req.contentHash || ''
          });
        }
      }
    });

    await browser.close();

    const endTime = Date.now();
    const durationTotalMs = endTime - startTime;

    // 5. Chuẩn hóa danh sách requests cho F12 Inspector
    const formattedRequests = networkRequests.map((r, idx) => {
      const u = r.url || '';
      const fName = u.split('/').pop()?.split('?')[0] || u;
      return {
        id: `cdp-${idx}-${Date.now()}`,
        url: u,
        fileName: fName || 'index.html',
        type: r.type || (u.endsWith('.css') ? 'stylesheet' : (u.endsWith('.js') ? 'script' : 'fetch')),
        status: r.status,
        sizeBytes: r.sizeBytes,
        durationMs: r.latencyMs,
        startTimeMs: Math.max(0, r.timestamp - startTime),
        initiator: r.initiator || 'script',
        backendRequestId: r.backendRequestId,
        detectedPackage: Array.from(identifiedPackages.values()).find(p => p.scriptUrl === u) || null,
        isLiveBrowser: true,
        collectionSource: 'CHROMIUM_CDP',
        timestamp: new Date(r.timestamp).toISOString()
      };
    });

    // 6. Xây dựng CycloneDX 1.4 Dynamic SBOM chuẩn
    const packageList = Array.from(identifiedPackages.values());
    const components = packageList.map(p => {
      const pVer = p.version && p.version !== 'VERSION_UNKNOWN' ? p.version : 'unknown';
      return {
        'bom-ref': `pkg:npm/${p.name}@${pVer}?session=${sessionId}`,
        type: 'library',
        name: p.name,
        version: p.version,
        purl: p.version && p.version !== 'VERSION_UNKNOWN' ? `pkg:npm/${p.name}@${p.version}` : `pkg:npm/${p.name}`,
        properties: [
          ...(p.scriptHash ? [{ name: 'runtime:scriptHash', value: p.scriptHash }] : []),
          { name: 'runtime:confidence', value: p.confidence },
          { name: 'runtime:identificationMethod', value: p.identificationMethod },
          { name: 'runtime:hasExecutionEvidence', value: String(p.hasExecutionEvidence) },
          { name: 'runtime:evidence', value: p.evidence },
          ...(p.scriptUrl ? [{ name: 'runtime:scriptUrl', value: p.scriptUrl }] : []),
          { name: 'runtime:collectionSource', value: 'CHROMIUM_CDP' }
        ]
      };
    });

    const cycloneDxSbom = {
      bomFormat: 'CycloneDX',
      specVersion: '1.4',
      serialNumber: `urn:uuid:${crypto.randomUUID()}`,
      version: 1,
      metadata: {
        timestamp: new Date().toISOString(),
        tools: [
          {
            vendor: 'SBOM Risk Analysis Platform',
            name: 'Chromium-CDP-Runtime-Instrumentation-Engine',
            version: '3.0.0'
          }
        ],
        component: {
          type: 'application',
          name: 'runtime-' + targetUrl.replace(/https?:\/\//, '').replace(/[^a-zA-Z0-9.-]/g, '_'),
          version: '1.0.0-cdp-runtime',
          description: `Evidence-based Dynamic SBOM collected via Chromium CDP for ${targetUrl}`
        }
      },
      components: components
    };

    const auditLog = {
      observation: {
        scenario: options.scenario || (headless ? 'Tải trang' : 'Phiên tương tác'),
        buildId: options.buildId || null,
        scope: 'Tài nguyên và script quan sát trong phiên CDP của trang.'
      },
      sessionId: sessionId,
      targetUrl: targetUrl,
      scannedAt: new Date().toISOString(),
      durationMs: durationTotalMs,
      collector: 'Chromium CDP Session (Google Chrome)',
      metrics: {
        totalNetworkRequests: formattedRequests.length,
        totalScriptsParsed: scriptsParsed.size,
        scriptsWithExecutionEvidence: Array.from(scriptsParsed.values()).filter(s => s.hasExecutionEvidence).length,
        identifiedPackageCount: packageList.length,
        jsHeapUsedBytes: memoryMetrics.JSHeapUsedSize || 0,
        jsHeapTotalBytes: memoryMetrics.JSHeapTotalSize || 0
      },
      capturedNetworkRequests: formattedRequests,
      identifiedPackages: packageList
    };

    return {
      success: true,
      sessionId: sessionId,
      targetUrl: targetUrl,
      scannedAt: new Date().toISOString(),
      durationMs: durationTotalMs,
      componentCount: components.length,
      packages: packageList,
      sbomJson: JSON.stringify(cycloneDxSbom, null, 2),
      auditLog: auditLog
    };

  } catch (error) {
    if (browser) await browser.close();
    throw error;
  }
}

// Nếu chạy trực tiếp từ CLI
if (require.main === module) {
  const targetUrl = process.argv[2] || 'https://kick-zone-web.vercel.app';
  const outputFile = process.argv[3] || null;

  const interactive = process.argv.includes('--interactive');
  runCdpScan(targetUrl, { headless: !interactive, observeMs: interactive ? 60000 : 2000,
    scenario: process.env.SBOM_SCENARIO, buildId: process.env.SBOM_BUILD_ID })
    .then(result => {
      const jsonStr = JSON.stringify(result, null, 2);
      if (outputFile) {
        fs.writeFileSync(outputFile, jsonStr, 'utf8');
        console.error(`[CDP Instrumentation] Đã ghi kết quả vào: ${outputFile}`);
      } else {
        console.log(jsonStr);
      }
      process.exit(0);
    })
    .catch(err => {
      console.error(`[CDP Instrumentation] Lỗi nghiêm trọng:`, err);
      process.exit(1);
    });
}

module.exports = { runCdpScan };

