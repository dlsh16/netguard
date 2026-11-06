const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const base = process.env.NETGUARD_PREVIEW_URL || 'http://127.0.0.1:8769';

(async () => {
  const browser = await chromium.launch({ headless: true, channel: process.env.PLAYWRIGHT_CHANNEL || undefined });
  const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  let release;
  const pending = new Promise(resolve => { release = resolve; });
  let cveRequested = false;
  try {
    await page.route('**/api/security/cves', async route => {
      cveRequested = true;
      await pending;
      await route.fulfill({ json: { total: 12, counts: { CRITICAL: 2, HIGH: 10 }, items: [] } });
    });
    await page.goto(base + '/?view=dashboard', { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => ws?.readyState === WebSocket.OPEN && state.devices.length > 0 && document.querySelector('#summary-srv-count').textContent !== '--', null, { timeout: 5000 });
    assert.ok(cveRequested);
    assert.equal(await page.locator('#summary-cve-val').innerText(), '--');
    assert.match(await page.locator('#summary-cve-status').innerText(), /로딩중/);
    assert.ok(await page.locator('#device-grid').innerText());
    const output = path.resolve(__dirname, '../data/security-preview');
    fs.mkdirSync(output, { recursive: true });
    await page.screenshot({ path: path.join(output, 'dashboard-before-nvd.png') });
    release();
    await page.waitForFunction(() => document.querySelector('#summary-cve-val').textContent === '12');
    await page.unroute('**/api/security/cves');
    await page.route('**/api/security/cves', route => route.fulfill({ status: 500, json: { detail: 'test NVD failure' } }));
    await page.evaluate(() => loadCVEs());
    assert.match(await page.locator('#summary-cve-status').innerText(), /조회 실패/);
    await page.unroute('**/api/security/cves');
    let searches = 0;
    page.on('request', request => { if (request.url().includes('/api/security/search?')) searches++; });
    await page.evaluate(() => navigateTo('security'));
    await page.waitForFunction(() => document.querySelector('.vs-results').getAttribute('aria-busy') === 'false');
    const before = searches;
    await page.evaluate(() => Promise.all(Array.from({ length: 20 }, () => SecuritySearch.render())));
    assert.equal(searches, before, 'Metric render bursts must not repeat CVE searches');
    await page.locator('#vs-refresh').click();
    await page.waitForFunction(() => document.querySelector('.vs-results').getAttribute('aria-busy') === 'false');
    assert.equal(searches, before + 1, 'Manual refresh must fetch current data');
    assert.deepEqual(errors, []);
    console.log(JSON.stringify({ passed: true, scenarios: ['dashboard and websocket before NVD', 'NVD card updates on completion', 'failed NVD is not zero vulnerabilities', 'render burst coalescing', 'explicit refresh'] }));
  } finally { release(); await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
