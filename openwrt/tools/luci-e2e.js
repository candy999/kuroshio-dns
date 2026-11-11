'use strict';
// CI：用 Playwright 實際打開 LuCI 每一頁（簡易與專業模式），檢查沒有 JavaScript 錯誤、內容有出來、可以儲存
//   BASE=http://127.0.0.1:8080 CONTAINER=owrt node openwrt/tools/luci-e2e.js
const { chromium } = require('playwright');
const { execFileSync } = require('child_process');
const fs = require('fs');

const BASE = process.env.BASE || 'http://127.0.0.1:8080';
const CONTAINER = process.env.CONTAINER || 'owrt';
const SHOTS = process.env.SHOTS || 'screenshots';
// 用法：node luci-e2e.js [candydns|kuroshio]
const NAME = process.argv[2] || 'candydns';
const TITLE = NAME === 'kuroshio' ? /黑潮 DNS/ : /優選 DNS/;
const PAGES = ['status', 'settings', 'filter', 'cdn', 'community', 'advanced', 'log'];
const uci = (...a) => execFileSync('docker', ['exec', CONTAINER, 'uci', ...a], { encoding: 'utf-8' }).trim();

let pass = 0, fail = 0;
const ok = m => { pass++; console.log(`  ✔ ${m}`); };
const bad = m => { fail++; console.log(`  ✘ ${m}`); };

(async () => {
    fs.mkdirSync(SHOTS, { recursive: true });
    const browser = await chromium.launch();
    const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
    let errors = [];
    page.on('pageerror', e => errors.push(e.message));
    page.on('console', m => { if (m.type() === 'error' && !/favicon|Failed to load resource/.test(m.text())) errors.push(m.text()); });

    await page.goto(`${BASE}/cgi-bin/luci/`);
    await page.waitForLoadState('networkidle');
    if (await page.locator('input[name=luci_username]').count()) {
        await page.fill('input[name=luci_username]', 'root');
        await page.fill('input[name=luci_password]', '');
        await page.press('input[name=luci_password]', 'Enter');
        await page.waitForLoadState('networkidle');
    } else {
        // root 沒有密碼時 LuCI 可能直接進入；不是的話印出頁面內容方便除錯
        console.log('（沒有登入表單）', page.url());
        console.log((await page.content()).slice(0, 3000));
    }
    await page.screenshot({ path: `${SHOTS}/login.png`, fullPage: true });

    const visit = async (name, mode) => {
        errors = [];
        await page.goto(`${BASE}/cgi-bin/luci/admin/services/${NAME}/${name}`);
        await page.waitForLoadState('networkidle');
        await page.waitForFunction(() => { const v = document.querySelector('#view'); return v && !v.querySelector('.spinning') && v.innerText.trim().length > 20; }, null, { timeout: 20000 }).catch(() => {});
        const text = await page.locator('#view').innerText().catch(() => '');
        await page.screenshot({ path: `${SHOTS}/${mode}-${name}.png`, fullPage: true });
        if (errors.length) bad(`${mode} ${name}：JavaScript 錯誤\n     ${errors.join('\n     ')}`);
        else if (!TITLE.test(text)) bad(`${mode} ${name}：內容沒有出來\n     ${text.slice(0, 300)}`);
        else ok(`${mode} ${name}`);
        return text;
    };

    for (const p of PAGES) await visit(p, 'simple');
    // 黑潮：每頁最下方有「關於」（核心版本、介面版本、授權、原始碼），狀態頁一定要看得到
    if (NAME === 'kuroshio') {
        await page.goto(`${BASE}/cgi-bin/luci/admin/services/${NAME}/status`);
        await page.waitForLoadState('networkidle');
        await page.waitForFunction(() => document.querySelector('.kuroshio-footer[data-ready]'), null, { timeout: 15000 }).catch(() => {});
        const text = await page.locator('#view').innerText().catch(() => '');
        /黑潮 DNS 核心/.test(text) ? ok('狀態頁有「關於」頁尾（黑潮 DNS 核心）') : bad(`狀態頁沒有「關於」頁尾\n     ${text.slice(-300)}`);
        /介面 (v\S+|未知)/.test(text) && /GPL-3\.0-or-later/.test(text) ? ok('頁尾有介面版本與授權') : bad('頁尾沒有介面版本或授權');
    }
    await page.evaluate((n) => localStorage.setItem(n + '-ui-mode', 'pro'), NAME);
    for (const p of PAGES) {
        const text = await visit(p, 'pro');
        if (p === 'advanced' && !/上游 DNS/.test(text)) bad('專業模式：進階頁沒有顯示參數');
        if (p === 'cdn' && !/跨 CDN 備援/.test(text)) bad('專業模式：CDN 頁沒有顯示細部參數');
    }

    // 儲存：在進階頁改一個數值參數，按「儲存並套用」，確認寫進 /etc/config/${NAME}
    errors = [];
    await page.goto(`${BASE}/cgi-bin/luci/admin/services/${NAME}/advanced`);
    await page.waitForLoadState('networkidle');
    const field = page.locator(`[id="widget.cbid.${NAME}.resolver.timeout_ms"]`);
    await field.fill('1777');
    await page.locator('.cbi-page-actions .cbi-button-apply, .cbi-page-actions button:has-text("Save & Apply")').first().click();
    await page.waitForTimeout(6000);
    try {
        const v = uci('-q', 'get', `${NAME}.resolver.timeout_ms`);
        v === '1777' ? ok('儲存並套用寫入 UCI') : bad(`儲存並套用寫入 UCI（實際：${v}）`);
    } catch (e) { bad(`儲存並套用寫入 UCI（${e.message.split('\n')[0]}）`); }
    await page.screenshot({ path: `${SHOTS}/after-save.png`, fullPage: true });

    // 自訂規則：編輯後存檔應寫進 /etc/<名稱>/custom-rules.txt
    await page.goto(`${BASE}/cgi-bin/luci/admin/services/${NAME}/filter`);
    await page.waitForLoadState('networkidle');
    const ta = page.locator('textarea').first();
    await ta.fill((await ta.inputValue()) + '\n||e2e-test.example^\n');
    await page.locator('.cbi-page-actions .cbi-button-save, .cbi-page-actions button:has-text("Save")').first().click();
    await page.waitForTimeout(3000);
    const rules = execFileSync('docker', ['exec', CONTAINER, 'cat', `/etc/${NAME}/custom-rules.txt`], { encoding: 'utf-8' });
    await page.screenshot({ path: `${SHOTS}/after-rules-save.png`, fullPage: true });
    /e2e-test\.example/.test(rules) ? ok('自訂規則寫入檔案')
        : bad(`自訂規則寫入檔案\n     檔案開頭：${rules.slice(0, 200)}\n     textarea 數量：${await page.locator('textarea').count()}\n     ${errors.join('\n     ')}`);

    await browser.close();
    console.log(`\n結果：${pass} 通過、${fail} 失敗`);
    process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
