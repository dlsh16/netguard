/* Run against scripts/preview_security_search.py. Uses the local Playwright package. */
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const base = process.env.NETGUARD_PREVIEW_URL || 'http://127.0.0.1:8769';
const output = path.resolve(__dirname, '../data/security-preview');
fs.mkdirSync(output, { recursive: true });

(async () => {
  const browser = await chromium.launch({ headless: true, channel: process.env.PLAYWRIGHT_CHANNEL || undefined });
  const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  async function ready() {
    await page.waitForFunction(() => document.querySelector('.vs-results')?.getAttribute('aria-busy') === 'false' && !document.querySelector('#vs-result-count').textContent.includes('대기'));
  }
  async function query(text) {
    await page.locator('#vs-query').fill(text);
    await page.locator('#vs-query').press('Enter');
    await ready();
  }
  try {
    await page.goto(base);
    await ready();
    await page.locator('.vs-asset-table tbody tr').first().waitFor();
    assert.equal(await page.locator('.vs-asset-table tbody tr').count(), 6);
    await page.screenshot({ path: path.join(output, 'assets-desktop.png'), fullPage: true });
    await query('ip:10.60.8.0/24 type:switch cvss:>=7');
    assert.equal(await page.locator('.vs-asset-table tbody tr').count(), 2);
    await page.locator('.vs-asset-table [data-action="asset"]').first().click();
    await ready();
    assert.equal(await page.locator('#vs-cves-tab').getAttribute('aria-selected'), 'true');
    assert.match(await page.locator('#vs-active-asset').innerText(), /Core|2F/);
    await page.locator('#vs-reset').click(); await ready();
    await page.locator('#vs-scope').selectOption('catalog'); await ready();
    assert.match(await page.locator('#vs-result-count').innerText(), /135/);
    await page.locator('#vs-next').click(); await ready();
    assert.match(await page.locator('#vs-page-label').innerText(), /2 \/ 7/);
    await page.locator('#vs-page-size').selectOption('100'); await ready();
    assert.equal(await page.locator('.vs-cve-table tbody tr').count(), 100);
    await page.locator('#vs-page-size').selectOption('20'); await ready();
    await page.locator('#vs-distribution-toggle').click();
    await page.screenshot({ path: path.join(output, 'cves-desktop.png'), fullPage: true });
    const canvasVariety = await page.locator('#vs-cvss-chart').evaluate(canvas => {
      const pixels = canvas.getContext('2d').getImageData(0, 0, canvas.width, canvas.height).data;
      let colored = 0;
      for (let i = 0; i < pixels.length; i += 4) if (pixels[i + 3] > 0) colored++;
      return colored;
    });
    assert.ok(canvasVariety > 500, 'Distribution chart must be rendered');
    await query('cve:CVE-2099-10001');
    await page.locator('[data-action="detail"]').first().click();
    await page.locator('#vs-detail-body .vs-detail-facts').waitFor();
    assert.match(await page.locator('#vs-detail-body').innerText(), /Windows|windows/);
    assert.match(await page.locator('#vs-detail-body').innerText(), /버전 확인 필요/);
    await page.screenshot({ path: path.join(output, 'detail-desktop.png') });
    await page.keyboard.press('Escape');
    assert.equal(await page.locator('#vs-detail-dialog').evaluate(d => d.open), false);
    await page.locator('[data-action="complete"]').first().click();
    await page.locator('#vs-action-confirm').click();
    await page.waitForFunction(() => !document.querySelector('#vs-action-dialog').open);
    await ready();
    assert.equal(await page.locator('.vs-cve-table tbody tr').count(), 0);
    await page.locator('#vs-status').selectOption('completed'); await ready();
    assert.equal(await page.locator('.vs-cve-table tbody tr').count(), 1);
    await page.locator('[data-action="reopen"]').first().click();
    await page.locator('#vs-action-confirm').click();
    await page.waitForFunction(() => !document.querySelector('#vs-action-dialog').open);
    await ready();
    assert.equal(await page.locator('.vs-cve-table tbody tr').count(), 0);
    await page.locator('#vs-status').selectOption('open'); await ready();
    await query('ip:not-an-ip');
    assert.equal(await page.locator('#vs-error').isVisible(), true);
    await query('no-such-cve-or-product');
    assert.match(await page.locator('.vs-empty').innerText(), /검색 결과가 없습니다/);
    // Slow an old response; a newer result must win even when the old request finishes last.
    await page.route('**/api/security/search?*', async route => {
      if (new URL(route.request().url()).searchParams.get('q') === 'product:comware') {
        await new Promise(resolve => setTimeout(resolve, 600));
      }
      await route.continue();
    });
    await page.locator('#vs-query').fill('product:comware'); await page.locator('#vs-query').press('Enter');
    await query('cve:CVE-2099-10001');
    await page.waitForTimeout(800);
    assert.match(await page.locator('#vs-result-list').innerText(), /CVE-2099-10001/);
    await page.unroute('**/api/security/search?*');
    await page.reload(); await ready();
    assert.equal(await page.locator('#vs-query').inputValue(), 'cve:CVE-2099-10001');
    await page.locator('#vs-reset').click(); await ready();
    await page.setViewportSize({ width: 390, height: 844 });
    await page.screenshot({ path: path.join(output, 'assets-mobile.png'), fullPage: true });
    const overflow = await page.evaluate(() => {
      const page = document.querySelector('#page-security');
      const container = document.querySelector('.page-container');
      return { page: page.scrollWidth - page.clientWidth, container: container.scrollWidth - container.clientWidth, body: document.documentElement.scrollWidth - window.innerWidth };
    });
    assert.ok(Object.values(overflow).every(value => value <= 2), `Unexpected horizontal overflow: ${JSON.stringify(overflow)}`);
    await page.locator('#vs-filter-toggle').click();
    assert.equal(await page.locator('#vs-filter-sidebar').isVisible(), true);
    await page.locator('#vs-filter-toggle').click();
    await page.goto(base + '/?role=operator'); await ready();
    await page.locator('#vs-cves-tab').click(); await ready();
    assert.equal(await page.locator('[data-action="complete"], [data-action="reopen"]').count(), 0);
    assert.equal(await page.locator('.nav-item[data-page="devices"]').count(), 0);
    await page.locator('[data-action="detail"]').first().click();
    await page.locator('#vs-detail-body .vs-detail-facts').waitFor();
    await page.screenshot({ path: path.join(output, 'detail-mobile.png') });
    assert.equal(await page.locator('#vs-detail-footer [data-action]').count(), 0);
    assert.deepEqual(errors, []);
    console.log(JSON.stringify({ passed: true, scenarios: ['asset search', 'CIDR+type+CVSS', 'asset drill-down', 'catalog pagination', 'chart pixels', 'detail dialog', 'complete+restore', 'invalid+empty states', 'stale response protection', 'refresh persistence', 'mobile layout', 'operator read-only'], screenshots: output }));
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
