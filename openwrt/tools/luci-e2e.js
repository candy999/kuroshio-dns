'use strict';
// CI：用 Playwright 實際打開 LuCI 每一頁（簡易與專業模式），檢查沒有 JavaScript 錯誤、內容有出來、可以儲存
//   BASE=http://127.0.0.1:8080 CONTAINER=owrt node openwrt/tools/luci-e2e.js
//   MOCK=1：對著 openwrt/tools/luci-mock.js（沒有 Docker 時在本機跑），UCI 與檔案改從 mock 讀
const { chromium } = require('playwright');
const { execFileSync } = require('child_process');
const fs = require('fs');

const BASE = process.env.BASE || 'http://127.0.0.1:8080';
const CONTAINER = process.env.CONTAINER || 'owrt';
const SHOTS = process.env.SHOTS || 'screenshots';
// 用法：node luci-e2e.js [candydns|kuroshio]
const NAME = process.argv[2] || 'candydns';
const TITLE = NAME === 'kuroshio' ? /黑潮 DNS/ : /優選 DNS/;
const PAGES = ['status', 'settings', 'filter', 'cdn', 'community', 'advanced', 'log'].concat(NAME === 'kuroshio' ? ['access'] : []);
const MOCK = !!process.env.MOCK;
const mockGet = async (p) => { const r = await fetch(BASE + p); if (!r.ok) throw new Error(`mock ${p}: HTTP ${r.status}`); return r.text(); };
/** uci -q get <key>；list 用空白隔開 */
const uciGet = async key => (MOCK ? (await mockGet('/__mock/uci?key=' + encodeURIComponent(key))).trim()
    : execFileSync('docker', ['exec', CONTAINER, 'uci', '-q', 'get', key], { encoding: 'utf-8' }).trim());
const readFile = async file => (MOCK ? mockGet('/__mock/file?path=' + encodeURIComponent(file))
    : execFileSync('docker', ['exec', CONTAINER, 'cat', file], { encoding: 'utf-8' }));

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

    for (const p of PAGES) {
        const text = await visit(p, 'simple');
        // 黑潮：基本設定頁要有網域與憑證、固定網域 / DDNS、DNR、存放位置
        if (NAME === 'kuroshio' && p === 'settings') {
            /網域與憑證/.test(text) && /綁定網域/.test(text) && /目前憑證/.test(text) ? ok('設定頁：網域與憑證') : bad('設定頁沒有「網域與憑證」');
            /DNR/.test(text) && /DNR 目前狀態/.test(text) ? ok('設定頁：DNR 開關與目前狀態') : bad('設定頁沒有 DNR');
            /存放位置/.test(text) ? ok('設定頁：存放位置') : bad('設定頁沒有「存放位置」');
            /目前的監聽狀態/.test(text) ? ok('設定頁：監聽狀態') : bad('設定頁沒有「目前的監聽狀態」');
            // DNR：rpcd 的 dnr 方法（kuroshio dnr）給的真正結果；mock 是條件符合，真的容器還沒有網域
            const dnr = await page.locator('#kuroshio-dnr').innerText().catch(() => '');
            (MOCK ? /dns\.example\.com/.test(dnr) && /DoH \+ DoH3/.test(dnr) && /192\.168\.1\.1/.test(dnr) : /網域/.test(dnr))
                ? ok('設定頁：DNR 顯示 kuroshio dnr 的結果') : bad(`設定頁：DNR 內容不對\n     ${dnr}`);
        }
        if (NAME === 'kuroshio' && p === 'access') {
            /只開放台灣（建議）/.test(text) && /全開放/.test(text) && /允許名單/.test(text) && /封鎖名單/.test(text) && /一律允許/.test(text) && /VPN/.test(text) && /優先於一切/.test(text)
                ? ok('連線來源頁：模式、名單與說明') : bad(`連線來源頁內容不對\n     ${text.slice(0, 300)}`);
            if (MOCK) /\d{4}-\d{2}-\d{2} 的資料/.test(text) && /57 次/.test(text) && /45\.135\.232\.0\/24/.test(text) ? ok('連線來源頁：資料日期、拒絕次數、被拒絕最多的網段') : bad('連線來源頁沒有目前狀態');
        }
        if (NAME === 'kuroshio' && p === 'status' && MOCK) {
            /連線來源/.test(text) && /只開放台灣/.test(text) && /已拒絕 57 次/.test(text) ? ok('狀態頁：連線來源摘要') : bad('狀態頁沒有連線來源摘要');
            /最久未存/.test(text) && /1\.5 小時/.test(text) && /上限 24 小時/.test(text) ? ok('狀態頁：最久未存') : bad('狀態頁沒有「最久未存」');
        }
    }
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
        if (NAME === 'kuroshio' && p === 'settings' && !/多個監聽位址/.test(text)) bad('專業模式：設定頁沒有「多個監聽位址」');
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
        const v = await uciGet(`${NAME}.resolver.timeout_ms`);
        v === '1777' ? ok('儲存並套用寫入 UCI') : bad(`儲存並套用寫入 UCI（實際：${v}）`);
    } catch (e) { bad(`儲存並套用寫入 UCI（${e.message.split('\n')[0]}）`); }
    await page.screenshot({ path: `${SHOTS}/after-save.png`, fullPage: true });

    // 黑潮：固定網域 / 自備憑證 / DDNS 出口 / IPv6 / DNR / 多位址監聽，儲存後寫進 UCI（專業模式）
    if (NAME === 'kuroshio') {
        errors = [];
        await page.goto(`${BASE}/cgi-bin/luci/admin/services/${NAME}/settings`);
        await page.waitForLoadState('networkidle');
        const w = (sec, opt) => page.locator(`[id="widget.cbid.${NAME}.${sec}.${opt}"]`);
        const field = (sec, opt) => page.locator(`[id="cbi-${NAME}-${sec}-${opt}"]`);
        /** 勾選 / 取消（LuCI 的核取方塊上面蓋著 label，直接對 input 送 click） */
        const setCheck = async (sec, opt, on) => {
            const c = page.locator(`[id="cbid.${NAME}.${sec}.${opt}"] input[type=checkbox]`).first();
            if ((await c.isChecked()) !== on) await c.evaluate(el => el.click());
        };
        /** DynamicList 加一項（有選單時輸入框在下拉選單裡，沒有時是一般的輸入框） */
        const addItem = async (sec, opt, value) => {
            const box = page.locator(`[id="cbid.${NAME}.${sec}.${opt}"]`).first();
            const dd = box.locator('.add-item .cbi-dropdown');
            if (await dd.count()) {
                await dd.locator('.open').click();
                const li = dd.locator(`li[data-value="${value}"]`).locator('visible=true');
                if (await li.count()) await li.first().click();
                else {
                    const custom = dd.locator('input.create-item-input').locator('visible=true').first();
                    await custom.fill(value);
                    await custom.press('Enter');
                }
            } else {
                const input = box.locator('.add-item input[type=text]');
                await input.fill(value);
                await input.press('Enter');
            }
        };
        try {
            await w('tls', 'domain').fill('not a domain');
            await w('tls', 'domain').blur();
            (await field('tls', 'domain').locator('.cbi-input-invalid').count()) ? ok('綁定網域：格式錯誤有標示') : bad('綁定網域：格式錯誤沒有標示');
            await w('tls', 'domain').fill('dns.example.com');
            await w('tls', 'cert_mode').selectOption('acme');
            await w('ddns', 'enabled').selectOption('0');
            (await field('tls', 'cert').isVisible()) ? bad('自動申請時不該顯示憑證檔欄位') : ok('自動申請時不顯示憑證檔欄位');
            await w('tls', 'cert_mode').selectOption('manual');
            await w('tls', 'cert').fill('/etc/ssl/example/fullchain.pem');
            await w('tls', 'key').fill('/etc/ssl/example/privkey.pem');
            (await field('ddns', 'ipv6').isVisible()) ? bad('固定網域時不該顯示 DDNS 細項') : ok('固定網域（預設）時不顯示 DDNS 細項');
            await w('ddns', 'enabled').selectOption('1');
            const hint = await field('ddns', 'ipv6').innerText();
            /IPv6/.test(hint) && /擋/.test(hint) ? ok('DDNS：IPv6 預設不發布，並說明原因') : bad(`DDNS：IPv6 沒有說明\n     ${hint}`);
            await setCheck('ddns', 'ipv6', true);
            await addItem('ddns', 'interfaces', 'pppoe-wan');
            await addItem('ddns', 'interfaces', 'wan2');
            await setCheck('main', 'dnr', false);
            await addItem('dot', 'binds', '0.0.0.0');
            await addItem('dot', 'binds', '::');
            await w('doh', 'tls').selectOption('0');
            await page.screenshot({ path: `${SHOTS}/settings-edited.png`, fullPage: true });
            await page.locator('.cbi-page-actions .cbi-button-apply, .cbi-page-actions button:has-text("Save & Apply")').first().click();
            await page.waitForTimeout(6000);
            const want = { 'tls.domain': 'dns.example.com', 'tls.cert_mode': 'manual', 'tls.cert': '/etc/ssl/example/fullchain.pem', 'tls.key': '/etc/ssl/example/privkey.pem',
                'ddns.enabled': '1', 'ddns.ipv6': '1', 'ddns.interfaces': 'pppoe-wan wan2', 'main.dnr': '0', 'dot.binds': '0.0.0.0 ::', 'doh.tls': '0' };
            for (const k of Object.keys(want)) {
                let v;
                try { v = await uciGet(`${NAME}.${k}`); } catch (e) { v = `（${e.message.split('\n')[0]}）`; }
                v === want[k] ? ok(`儲存：${k} = ${v}`) : bad(`儲存：${k} 應該是 ${want[k]}，實際 ${v}`);
            }
            // 改回固定網域：DDNS 關掉，但出口設定留著
            await page.goto(`${BASE}/cgi-bin/luci/admin/services/${NAME}/settings`);
            await page.waitForLoadState('networkidle');
            await w('ddns', 'enabled').selectOption('0');
            await setCheck('main', 'dnr', true);
            await page.locator('.cbi-page-actions .cbi-button-apply, .cbi-page-actions button:has-text("Save & Apply")').first().click();
            await page.waitForTimeout(6000);
            const en = await uciGet(`${NAME}.ddns.enabled`), keep = await uciGet(`${NAME}.ddns.interfaces`).catch(() => '');
            en === '0' && keep === 'pppoe-wan wan2' ? ok('改回固定網域：ddns.enabled = 0，出口設定保留') : bad(`改回固定網域：enabled = ${en}、interfaces = ${keep}`);
        } catch (e) { bad(`設定頁操作中斷：${e.message.split('\n')[0]}`); }
        await page.screenshot({ path: `${SHOTS}/settings-saved.png`, fullPage: true });
        if (errors.length) bad(`設定頁：JavaScript 錯誤\n     ${errors.join('\n     ')}`);
    }

    // 黑潮：連線來源（自訂 ISP、取消一組、允許 / 封鎖名單、測試 IP），儲存後寫進 UCI
    if (NAME === 'kuroshio') {
        errors = [];
        await page.evaluate((n) => localStorage.setItem(n + '-ui-mode', 'simple'), NAME);
        await page.goto(`${BASE}/cgi-bin/luci/admin/services/${NAME}/access`);
        await page.waitForLoadState('networkidle');
        const field = opt => page.locator(`[id="cbi-${NAME}-access-${opt}"]`);
        const addItem = async (opt, value) => {
            const input = page.locator(`[id="cbid.${NAME}.access.${opt}"] .add-item input[type=text]`).first();
            await input.fill(value);
            await input.press('End');   // 驗證在 keyup 時跑：fill 不會觸發，先按一個鍵
            await input.press('Enter');
        };
        try {
            (await field('groups').isVisible()) ? bad('只開放台灣時不該顯示 ISP 勾選') : ok('只開放台灣（預設）時不顯示 ISP 勾選');
            await page.locator(`[id="widget.cbid.${NAME}.access.mode.1"]`).evaluate(el => el.click());
            await page.waitForTimeout(300);
            (await field('groups').isVisible()) ? ok('自訂 ISP：顯示勾選清單') : bad('自訂 ISP：沒有顯示勾選清單');
            const box = page.locator(`[id="cbid.${NAME}.access.groups"]`);
            const ids = await box.locator('input[type=checkbox]:not([data-all])').evaluateAll(cs => cs.map(c => c.value));
            let wantGroups;
            if (ids.length) {
                // 有台灣 IP 資料（mock）：取消「其他台灣網段」
                const gt = await box.innerText();
                /中華電信/.test(gt) && /萬個位址/.test(gt) && /全選（含日後新增的 ISP）/.test(gt) ? ok('ISP 清單：名稱、位址數（萬）、全選') : bad(`ISP 清單內容不對\n     ${gt.slice(0, 200)}`);
                await box.locator('input[value=other]').evaluate(el => el.click());
                (await box.locator('input[data-all]').isChecked()) ? bad('取消一組後「全選」應該跟著取消') : ok('取消一組：全選跟著取消');
                wantGroups = ids.filter(x => x !== 'other').join(' ');
            } else {
                // 服務沒有執行（真的容器）：清單只有「全選」，取消 = 一組都不勾，要寫成 list groups ''
                await box.locator('input[data-all]').evaluate(el => el.click());
                wantGroups = '';
            }
            await addItem('allow', '10.0.0.0/33');
            (await field('allow').locator('.cbi-input-invalid').count()) ? ok('允許名單：前綴長度超過 32 有標示') : bad('允許名單：前綴長度超過 32 沒有標示');
            const allowInput = page.locator(`[id="cbid.${NAME}.access.allow"] .add-item input[type=text]`).first();
            /10\.0\.0\.0\/33/.test(await page.locator(`[id="cbid.${NAME}.access.allow"]`).innerText()) ? bad('允許名單：格式錯誤的項目被加進去') : ok('允許名單：格式錯誤的項目不加入');
            await allowInput.fill('');
            await allowInput.press('End');
            await addItem('allow', '203.0.113.0/24');
            await addItem('allow', '2001:db8::/32');
            await addItem('deny', '198.51.100.7');
            await page.fill('#kuroshio-access-ip', '168.95.1.1');
            await page.click('#kuroshio-access-test');
            await page.waitForFunction(() => /可以連進來|會被擋下|沒有回應/.test(document.getElementById('kuroshio-access-result').innerText), null, { timeout: 10000 }).catch(() => {});
            const tr = await page.locator('#kuroshio-access-result').innerText();
            (MOCK && ids.length ? /可以連進來/.test(tr) && /中華電信/.test(tr) : /可以連進來|會被擋下|沒有回應/.test(tr)) ? ok(`測試 IP：${tr.replace(/\s+/g, ' ')}`) : bad(`測試 IP 結果不對：${tr}`);
            await page.fill('#kuroshio-access-ip', '10.0.0.0/8');
            await page.click('#kuroshio-access-test');
            /請輸入一個 IP/.test(await page.locator('#kuroshio-access-result').innerText()) ? ok('測試 IP：格式錯誤不送出') : bad('測試 IP：格式錯誤沒有提示');
            await page.screenshot({ path: `${SHOTS}/access-edited.png`, fullPage: true });
            await page.locator('.cbi-page-actions .cbi-button-apply, .cbi-page-actions button:has-text("Save & Apply")').first().click();
            await page.waitForTimeout(6000);
            const want = { 'access.mode': 'custom', 'access.groups': wantGroups, 'access.allow': '203.0.113.0/24 2001:db8::/32', 'access.deny': '198.51.100.7' };
            for (const k of Object.keys(want)) {
                let v;
                try { v = await uciGet(`${NAME}.${k}`); } catch (e) { v = `（${e.message.split('\n')[0]}）`; }
                v === want[k] ? ok(`儲存：${k} = ${v || "''"}`) : bad(`儲存：${k} 應該是 ${want[k] || "''"}，實際 ${v}`);
            }
            // 改回只開放台灣：勾選的群組保留
            await page.goto(`${BASE}/cgi-bin/luci/admin/services/${NAME}/access`);
            await page.waitForLoadState('networkidle');
            await page.locator(`[id="widget.cbid.${NAME}.access.mode.0"]`).evaluate(el => el.click());
            await page.locator('.cbi-page-actions .cbi-button-apply, .cbi-page-actions button:has-text("Save & Apply")').first().click();
            await page.waitForTimeout(6000);
            const m2 = await uciGet(`${NAME}.access.mode`), g2 = await uciGet(`${NAME}.access.groups`).catch(() => '（沒有）');
            m2 === 'taiwan' && g2 === wantGroups ? ok('改回只開放台灣：勾選的群組保留') : bad(`改回只開放台灣：mode = ${m2}、groups = ${g2}`);
            if (MOCK && ids.length) {
                // 被拒絕最多的網段：一鍵加入封鎖名單
                await page.goto(`${BASE}/cgi-bin/luci/admin/services/${NAME}/access`);
                await page.waitForLoadState('networkidle');
                await page.locator('#kuroshio-access-status button[data-opt=deny][data-net="45.135.232.0/24"]').click();
                const dl = await page.locator(`[id="cbid.${NAME}.access.deny"]`).innerText();
                /45\.135\.232\.0\/24/.test(dl) ? ok('一鍵加入封鎖名單') : bad(`一鍵加入封鎖名單沒有作用\n     ${dl}`);
            }
        } catch (e) { bad(`連線來源頁操作中斷：${e.message.split('\n')[0]}`); }
        await page.screenshot({ path: `${SHOTS}/access-saved.png`, fullPage: true });
        if (errors.length) bad(`連線來源頁：JavaScript 錯誤\n     ${errors.join('\n     ')}`);
    }

    // 自訂規則：編輯後存檔應寫進 /etc/<名稱>/custom-rules.txt
    await page.goto(`${BASE}/cgi-bin/luci/admin/services/${NAME}/filter`);
    await page.waitForLoadState('networkidle');
    const ta = page.locator('textarea').first();
    await ta.fill((await ta.inputValue()) + '\n||e2e-test.example^\n');
    await page.locator('.cbi-page-actions .cbi-button-save, .cbi-page-actions button:has-text("Save")').first().click();
    await page.waitForTimeout(3000);
    const rules = await readFile(`/etc/${NAME}/custom-rules.txt`);
    await page.screenshot({ path: `${SHOTS}/after-rules-save.png`, fullPage: true });
    /e2e-test\.example/.test(rules) ? ok('自訂規則寫入檔案')
        : bad(`自訂規則寫入檔案\n     檔案開頭：${rules.slice(0, 200)}\n     textarea 數量：${await page.locator('textarea').count()}\n     ${errors.join('\n     ')}`);

    await browser.close();
    console.log(`\n結果：${pass} 通過、${fail} 失敗`);
    process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
