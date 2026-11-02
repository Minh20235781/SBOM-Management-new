const puppeteer = require('puppeteer-core');
const fs = require('fs');

const CHROME_PATH = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';

async function testScan(url) {
  console.log(`Bắt đầu thử nghiệm CDP Instrumentation trên Chrome: ${url}`);
  const browser = await puppeteer.launch({
    executablePath: CHROME_PATH,
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-gpu']
  });

  const page = await browser.newPage();
  const cdp = await page.target().createCDPSession();

  const networkEvents = [];
  const scriptsParsed = [];

  await cdp.send('Network.enable');
  await cdp.send('Debugger.enable');
  await cdp.send('Profiler.enable');
  await cdp.send('Profiler.startPreciseCoverage', { callCount: true, detailed: true });

  cdp.on('Network.responseReceived', (e) => {
    networkEvents.push({
      url: e.response.url,
      status: e.response.status,
      mimeType: e.response.mimeType,
      type: e.type,
      fromDiskCache: e.response.fromDiskCache
    });
  });

  cdp.on('Debugger.scriptParsed', (s) => {
    scriptsParsed.push({
      scriptId: s.scriptId,
      url: s.url,
      hasSourceURL: !!s.hasSourceURL,
      sourceMapURL: s.sourceMapURL || ''
    });
  });

  console.log(`Đang truy cập: ${url}...`);
  await page.goto(url, { waitUntil: 'networkidle2', timeout: 30000 });

  const coverage = await cdp.send('Profiler.takePreciseCoverage');
  await cdp.send('Profiler.stopPreciseCoverage');

  console.log(`Kết quả:`);
  console.log(`- Số Network responses: ${networkEvents.length}`);
  console.log(`- Số Scripts parsed trong runtime: ${scriptsParsed.length}`);
  console.log(`- Số Scripts có coverage: ${coverage.result.length}`);

  const scriptsWithSourceMap = scriptsParsed.filter(s => s.sourceMapURL);
  console.log(`- Số Scripts có Source Map URL: ${scriptsWithSourceMap.length}`);

  await browser.close();
}

testScan('https://kick-zone-web.vercel.app').catch(err => {
  console.error('Lỗi khi chạy CDP:', err);
});

