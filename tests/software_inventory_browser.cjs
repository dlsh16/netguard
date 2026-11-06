const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const base = process.env.NETGUARD_SOFTWARE_PREVIEW_URL || 'http://127.0.0.1:8770';

(async () => {
  const browser = await chromium.launch({ headless: true, channel: process.env.PLAYWRIGHT_CHANNEL || undefined });
  const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
  const errors = [], scenarios = [];
  page.on('pageerror', error => errors.push(error.message));
  const ready = () => page.waitForFunction(() => !['조회 중', '조회 실패'].includes(document.querySelector('#si-summary').textContent));
  async function add(field, op, value) {
    await page.locator('#si-field').selectOption(field); await page.locator('#si-op').selectOption(op);
    if (op !== 'is_empty') await page.locator('#si-value').fill(value);
    await page.locator('#si-form button[type=submit]').click(); await ready();
  }
  try {
    await page.goto(base, { waitUntil: 'domcontentloaded' }); await ready();
    assert.equal(await page.locator('#si-rows tr').count(), 50);
    assert.match(await page.locator('#si-summary').innerText(), /207/);
    assert.deepEqual(await page.locator('.si-table th').allTextContents(), ['서버명', 'IP', '소프트웨어 이름', '소프트웨어 버전']);
    scenarios.push('four columns and server-side pagination');
    await page.locator('#si-next').click(); await ready(); assert.match(await page.locator('#si-page-label').innerText(), /2 \/ 5/);
    await add('software_name', 'contains', 'tomcat');
    assert.equal(await page.locator('#si-rows tr').count(), 3);
    await page.locator('[data-server="2"]').click();
    await page.locator('#server-detail').waitFor({ state: 'visible' });
    assert.match(await page.locator('#detail-server-name').innerText(), /MBCO-MES2-DEV/);
    await page.evaluate(() => navigateTo('processes')); await ready();
    scenarios.push('server drill-down');
    const output = path.resolve(__dirname, '../data/software-preview'); fs.mkdirSync(output, { recursive: true });
    await page.screenshot({ path: path.join(output, 'software-search-desktop.png') });
    await add('software_version', 'equals', '10.1.39');
    assert.equal(await page.locator('#si-rows tr').count(), 2);
    await page.locator('[data-detail]').first().click(); await page.locator('#si-dialog').waitFor({ state: 'visible' });
    assert.match(await page.locator('#si-detail').innerText(), /10.1.39/);
    assert.match(await page.locator('#si-detail').innerText(), /Tomcat 메타데이터/);
    await page.screenshot({ path: path.join(output, 'software-detail-desktop.png') });
    const bounds = await page.locator('#si-dialog').boundingBox(); assert.ok(bounds.x > 100 && bounds.y > 50, 'Detail dialog must be centered');
    await page.keyboard.press('Escape'); scenarios.push('AND filters and detail dialog');
    await page.locator('#si-save').click(); await page.locator('#si-save-name').fill('Tomcat 10.1.39');
    await page.locator('#si-save-form button[type=submit]').click();
    await page.locator('#si-clear').click(); await ready();
    await page.locator('#si-saved').selectOption({ label: 'Tomcat 10.1.39' }); await ready();
    assert.equal(await page.locator('#si-rows tr').count(), 2);
    const downloadPromise = page.waitForEvent('download'); await page.locator('#si-export').click();
    const download = await downloadPromise; const csv = fs.readFileSync(await download.path(), 'utf8');
    assert.equal(csv.trim().split('\n').length, 3); assert.ok(csv.includes('10.1.39'));
    await page.reload(); await ready(); assert.equal(await page.locator('#si-chips .si-chip').count(), 2);
    scenarios.push('saved search, refresh persistence and filtered CSV');
    await page.locator('#si-clear').click(); await ready();
    await page.locator('#si-coverage').click();
    await page.locator('#si-dialog').waitFor({ state: 'visible' });
    assert.match(await page.locator('#si-detail').innerText(), /미수집/); assert.match(await page.locator('#si-detail').innerText(), /24시간 경과/);
    await page.keyboard.press('Escape'); scenarios.push('unreported and stale coverage');
    await add('software_version', 'is_empty', ''); assert.equal(await page.locator('#si-rows tr').count(), 1);
    assert.match(await page.locator('#si-rows').innerText(), /버전 미확인/);
    await page.locator('#si-clear').click(); await ready(); await add('software_name', 'contains', 'nodejs');
    assert.equal(await page.locator('#si-rows tr').count(), 3); scenarios.push('unknown versions and Node.js alias');
    await page.locator('#si-clear').click(); await ready(); await add('software_name', 'contains', '<script>unknown</script>');
    assert.match(await page.locator('#si-rows').innerText(), /검색 결과 없음/);
    assert.equal(await page.locator('#si-chips script').count(), 0); scenarios.push('escaped filter values and empty state');
    await page.route('**/api/software?*', route => route.fulfill({ status: 500, json: { detail: 'TEST database unavailable' } }));
    await page.locator('#si-refresh').click(); await page.locator('#si-error').waitFor({ state: 'visible' });
    assert.match(await page.locator('#si-error').innerText(), /TEST database unavailable/);
    assert.ok(await page.locator('#si-export').isDisabled());
    await page.unroute('**/api/software?*'); await page.locator('#si-clear').click(); await ready(); scenarios.push('error state with no stale actions');
    let requests = 0; page.on('request', req => { if (req.url().includes('/api/software?')) requests++; });
    await page.evaluate(() => Promise.all(Array.from({ length: 10 }, () => SoftwareInventory.render())));
    assert.equal(requests, 0); scenarios.push('background renders do not refetch inventory');
    await page.goto(base + '/?role=operator'); await ready();
    assert.ok(await page.locator('[data-page=devices]').isHidden());
    assert.equal(await page.locator('#page-processes button').filter({ hasText: /중지|장비 추가/ }).count(), 0); scenarios.push('operator read-only inventory');
    await add('software_name', 'contains', 'tomcat');
    await page.setViewportSize({ width: 390, height: 844 });
    await page.screenshot({ path: path.join(output, 'software-search-mobile.png'), fullPage: true });
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), 'Page must not overflow on mobile');
    const positions = await page.locator('.si-builder > *').evaluateAll(nodes => nodes.map(n => { const r=n.getBoundingClientRect(); return { x:r.x,y:r.y,w:r.width,h:r.height }; }));
    for (const control of positions) { assert.ok(control.x >= 52 && control.x + control.w <= 390, 'Search controls must fit the mobile content area'); assert.ok(control.h <= 50, 'Button labels must not stack vertically'); }
    for (let i=0;i<positions.length;i++) for (let j=i+1;j<positions.length;j++) { const a=positions[i], b=positions[j]; assert.ok(!(a.x < b.x+b.w-1 && a.x+a.w > b.x+1 && a.y < b.y+b.h-1 && a.y+a.h > b.y+1), 'Search controls overlap'); }
    scenarios.push('mobile layout and control bounds');
    assert.deepEqual(errors, []);
    console.log(JSON.stringify({ passed: true, scenarios }, null, 2));
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
