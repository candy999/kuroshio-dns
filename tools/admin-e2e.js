'use strict';
// CI：Windows 本機設定頁（data/admin）端對端測試。自己啟動 kuroshio（暫存設定檔、空著的埠號），用 Playwright 實際操作：
// 登入、狀態、簡易 / 專業模式、改設定並儲存（伺服器在程式內重新啟動）、原始 JSON、工具、日誌、手機寬度、深色模式、登出。
//
//   cargo build -p kuroshio && node tools/admin-e2e.js
//   KUROSHIO_BIN=path/to/kuroshio SHOTS=screenshots-admin node tools/admin-e2e.js
const { chromium } = require('playwright');
const { spawn } = require('child_process');
const fs = require('fs');
const http = require('http');
const net = require('net');
const os = require('os');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const BIN = process.env.KUROSHIO_BIN ? path.resolve(process.env.KUROSHIO_BIN) : path.join(ROOT, 'target', 'debug', process.platform === 'win32' ? 'kuroshio.exe' : 'kuroshio');
const SHOTS = path.resolve(process.env.SHOTS || 'screenshots-admin');
const WEB = path.join(ROOT, 'data', 'admin');

let pass = 0, fail = 0;
const ok = m => { pass++; console.log(`  ✔ ${m}`); };
const bad = m => { fail++; console.log(`  ✘ ${m}`); };
const check = (cond, m, detail) => (cond ? ok(m) : bad(detail ? `${m}\n     ${detail}` : m));

const freePort = () => new Promise((resolve, reject) => {
    const s = net.createServer();
    s.unref();
    s.on('error', reject);
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
});

/** 直接送 HTTP 請求（可以自己帶 Origin / Host，瀏覽器做不到） */
const raw = (port, method, p, headers, body) => new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method, path: p, headers: headers || {} }, res => {
        let data = '';
        res.on('data', c => { data += c; });
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
});

const sleep = ms => new Promise(r => setTimeout(r, ms));

(async () => {
    fs.mkdirSync(SHOTS, { recursive: true });
    if (!fs.existsSync(BIN)) {
        console.error(`找不到執行檔 ${BIN}（先 cargo build -p kuroshio，或用 KUROSHIO_BIN 指定）`);
        process.exit(2);
    }
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kuroshio-admin-'));
    const [adminPort, dnsPort] = [await freePort(), await freePort()];
    const cfgFile = path.join(dir, 'config.json');
    const initial = {
        listen: { plain: { binds: ['127.0.0.1'], port: dnsPort } },
        admin: { port: adminPort, auth: true, webDir: WEB },
        cdn: { enabled: false },
        filter: { enabled: false },
        resolver: { stripEch: true },
        system: { persistDir: path.join(dir, 'state') },
        upstream: { pinned: ['udp://127.0.0.1:9'] },
        // 設定頁不認識的欄位，存檔後要保留
        xTest: { keep: true }
    };
    fs.writeFileSync(cfgFile, JSON.stringify(initial, null, 2));

    let out = '';
    const child = spawn(BIN, ['run', '-c', cfgFile], { cwd: dir, stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, NO_COLOR: '1' } });
    child.stdout.on('data', d => { out += d; });
    child.stderr.on('data', d => { out += d; });
    let exited = null;
    child.on('exit', c => { exited = c; });

    const BASE = `http://127.0.0.1:${adminPort}`;
    let browser;
    try {
        // 等管理 API 起來
        let up = false;
        for (let i = 0; i < 100 && exited === null; i++) {
            try { const r = await raw(adminPort, 'GET', '/api/session'); if (r.status === 200) { up = true; break; } } catch (e) { /* 還沒好 */ }
            await sleep(200);
        }
        if (!up) throw new Error(`kuroshio 沒有啟動（結束碼 ${exited}）`);
        const token = fs.readFileSync(path.join(dir, 'admin.token'), 'utf-8').trim();
        console.log(`kuroshio ${BIN}\n設定頁 ${BASE}/  設定檔 ${cfgFile}`);

        // ---------------- 後端的存取控制（瀏覽器做不到的請求）
        console.log('存取控制');
        check((await raw(adminPort, 'GET', '/api/status')).status === 401, '沒登入時 /api/status 回 401');
        check((await raw(adminPort, 'GET', '/api/status', { Host: 'evil.example.com' })).status === 403, '非本機 Host 回 403（防 DNS rebinding）');
        const xs = await raw(adminPort, 'PUT', '/api/config', { Origin: 'http://evil.example', Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, '{}');
        check(xs.status === 403, '跨站 PUT（Origin 不是本機）回 403');
        check(JSON.parse(fs.readFileSync(cfgFile, 'utf-8')).xTest, '跨站 PUT 沒有改到設定檔');
        const ab = await raw(adminPort, 'GET', '/api/about');
        let about = {};
        try { about = JSON.parse(ab.body); } catch (e) { /* 下面報錯 */ }
        check(ab.status === 200 && about.license === 'GPL-3.0-or-later' && /^https:\/\//.test(about.source || ''), '/api/about 不用登入');
        const qr = await raw(adminPort, 'GET', '/api/qr');
        check(qr.status === 200 && /svg/.test(qr.headers['content-type']) && /<svg/.test(qr.body), '/api/qr 回 SVG（不用登入）');
        const js = await raw(adminPort, 'GET', '/app.js');
        check(js.status === 200 && /javascript/.test(js.headers['content-type']), '靜態檔 app.js');
        check(!/innerHTML|insertAdjacentHTML|document\.write|outerHTML/.test(js.body), 'app.js 不用 innerHTML（伺服器字串一律 textContent）');
        const fj = await raw(adminPort, 'GET', '/fields.json');
        let fields = null;
        try { fields = JSON.parse(fj.body); } catch (e) { /* 下面報錯 */ }
        check(fields && fields.groups && fields.groups.length >= 8, 'fields.json 可以解析');
        check(!/candy\.moe/.test(js.body + fj.body), '沒有寫死真實網域');

        // ---------------- 瀏覽器
        browser = await chromium.launch();
        // bypassCSP：Playwright 的 waitForFunction 在頁面裡用 new Function 建立條件，會被設定頁嚴格的 CSP 擋下；
        // 頁面自己的程式不受影響（CSP 標籤另外檢查）
        const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 }, locale: 'zh-TW', bypassCSP: true });
        const page = await ctx.newPage();
        {
            const html = fs.readFileSync(path.join(WEB, 'index.html'), 'utf-8');
            check(/Content-Security-Policy[^>]*script-src 'self'/.test(html) && !/unsafe-eval|unsafe-inline/.test(html.match(/Content-Security-Policy[^>]*>/)[0]), '設定頁有嚴格的 CSP（只允許自己的檔案）');
        }
        const errors = [];
        page.on('pageerror', e => errors.push(e.message));
        page.on('console', m => { if (m.type() === 'error' && !/favicon|Failed to load resource|ERR_CONNECTION_REFUSED|ERR_EMPTY_RESPONSE|ERR_CONNECTION_RESET/.test(m.text())) errors.push(m.text()); });
        const shot = name => page.screenshot({ path: path.join(SHOTS, `${name}.png`), fullPage: true });

        console.log('登入');
        await page.goto(`${BASE}/`);
        await page.waitForSelector('#login:not([hidden])');
        check(await page.isHidden('#main'), '沒登入時只顯示登入表單');
        await page.waitForFunction(() => /v\d/.test(document.getElementById('foot').textContent));
        const foot = await page.textContent('#foot');
        check(foot.includes('v' + about.version) && /GPL-3\.0-or-later/.test(foot) && /原始碼/.test(foot), '登入畫面也有頁尾（版本、授權、原始碼）', foot);
        check(await page.getAttribute('#foot-src', 'href') === about.source && await page.getAttribute('#foot-src', 'rel') === 'noopener noreferrer' && await page.getAttribute('#foot-src', 'target') === '_blank', '頁尾原始碼連結（新分頁、noopener noreferrer）');
        await shot('01-login');
        await page.fill('#login-token', 'wrong-token');
        await page.click('#login-form button[type=submit]');
        await page.waitForSelector('#login-err:not([hidden])');
        check(/不正確/.test(await page.textContent('#login-err')), 'token 錯誤時顯示錯誤訊息');
        check(!/login=failed/.test(page.url()), '網址列的 ?login=failed 已清掉');
        await page.goto(`${BASE}/?login=failed`);
        await page.waitForSelector('#login-err:not([hidden])');
        ok('/?login=failed 顯示錯誤');
        await page.fill('#login-token', token);
        await page.click('#login-form button[type=submit]');
        await page.waitForSelector('#main:not([hidden])');
        ok('token 正確 → 進入主畫面');

        console.log('狀態');
        await page.waitForSelector('#st-tiles .tile');
        const tiles = await page.textContent('#st-tiles');
        check(/版本/.test(tiles) && /3\.\d/.test(tiles), '狀態：版本', tiles.slice(0, 200));
        check(/cmd 直接執行/.test(tiles), '狀態：執行方式');
        check(/硬體等級/.test(tiles) && /記憶體/.test(tiles) && /拉回台灣/.test(tiles) && /p50/.test(tiles), '狀態：硬體、記憶體、拉回台灣、回應時間');
        const lst = await page.textContent('#st-listen');
        check(lst.includes(String(dnsPort)) && /DoH3/.test(lst) && /DoQ/.test(lst), '狀態：監聽埠號', lst.slice(0, 300));
        check((await page.textContent('#st-up')).includes('udp://127.0.0.1:9'), '狀態：上游列表');
        check(await page.isVisible('#notice'), '狀態頁顯示 Windows 提醒（UDP 443 / UDP 853、setup）');
        check(/UDP 443/.test(await page.textContent('#notice')) && /kuroshio\.exe setup/.test(await page.textContent('#notice')), '提醒內容');
        const t1 = await page.textContent('#st-updated');
        await page.waitForFunction(t => document.getElementById('st-updated').textContent !== t, t1, { timeout: 12000 }).then(() => ok('狀態每 5 秒自動更新'), () => bad('狀態沒有自動更新'));
        await shot('02-status');

        console.log('設定：簡易 / 專業');
        await page.evaluate(() => localStorage.removeItem('kuroshio-ui-mode'));
        await page.goto(`${BASE}/#settings`);
        await page.waitForSelector('#cfg-groups button');
        const groups = await page.$$eval('#cfg-groups button', bs => bs.map(b => b.textContent));
        check(['服務與監聽', '上游', '過濾', 'CDN', 'DDNS', '憑證', '公開頁', '社群', '系統', '日誌'].every(g => groups.some(x => x.includes(g))), '設定分類齊全', groups.join(' / '));
        check(!groups.some(x => x.includes('原始 JSON')), '簡易模式沒有原始 JSON');
        check(await page.isVisible('[data-key="listen.doh.windowsMode"]'), '服務與監聽：Windows 443 模式');
        check(await page.isVisible('[data-key="listen.plain.port"]') && !(await page.isVisible('[data-key="listen.doh.trustProxy"]')), '簡易模式隱藏專業欄位');
        check(await page.isVisible('#notice'), '服務與監聽分類也顯示 Windows 提醒');
        await shot('03-settings-simple');
        await page.click('#mode-toggle button[data-mode=pro]');
        check(await page.isVisible('[data-key="listen.doh.trustProxy"]'), '切到專業模式顯示全部欄位');
        await page.reload();
        await page.waitForSelector('#cfg-groups button');
        check(await page.evaluate(() => localStorage.getItem('kuroshio-ui-mode')) === 'pro' && await page.isVisible('[data-key="listen.doh.trustProxy"]'), '專業模式記在瀏覽器（重新整理後保留）');
        // 預設值顯示成提示文字
        const ph = await page.getAttribute('[data-key="listen.doh.port"] input', 'placeholder');
        check(/^\d+$/.test(ph || ''), '數字欄位用伺服器預設值當提示文字', ph);

        console.log('設定：修改並儲存');
        await page.selectOption('[data-key="listen.doh.windowsMode"] select', 'httpsys');
        await page.fill('[data-key="listen.doh.port"] input', 'abc');
        check(await page.isVisible('[data-key="listen.doh.port"] .err-text'), '格式錯誤時顯示錯誤');
        check(await page.isDisabled('#btn-save'), '有錯誤時不能儲存');
        await page.fill('[data-key="listen.doh.port"] input', '');
        await page.click('#cfg-groups button[data-group=upstream]');
        await page.fill('[data-key="resolver.timeoutMs"] input', '1777');
        await page.fill('[data-key="upstream.fallback"] textarea', 'udp://127.0.0.2\nudp://127.0.0.3');
        await page.uncheck('[data-key="resolver.stripEch"] input[type=checkbox]');
        await page.click('#cfg-groups button[data-group=filter]');
        check(await page.locator('[data-key="filter.lists"] tbody tr').count() >= 5, '過濾：訂閱清單表格（伺服器預設清單）');
        check(/項未儲存的變更/.test(await page.textContent('#save-msg')), '儲存列顯示未儲存的變更數', await page.textContent('#save-msg'));
        check(await page.locator('#cfg-groups .dot').count() >= 2, '有變更的分類有標示');
        await shot('04-settings-pro-edited');
        await page.click('#btn-save');
        await page.waitForFunction(() => /已儲存並套用|失敗|沒有在 30 秒/.test(document.getElementById('save-msg').textContent) || !document.getElementById('login').hidden, null, { timeout: 40000 });
        const smsg = await page.textContent('#save-msg');
        check(/已儲存並套用/.test(smsg), '儲存 → 等服務重新啟動 → 成功訊息', smsg);
        check(await page.isHidden('#login'), '重新載入後仍然是登入狀態');
        const saved = JSON.parse(fs.readFileSync(cfgFile, 'utf-8'));
        check(saved.resolver && saved.resolver.timeoutMs === 1777, '設定檔：resolver.timeoutMs = 1777');
        check(saved.listen && saved.listen.doh && saved.listen.doh.windowsMode === 'httpsys', '設定檔：listen.doh.windowsMode = httpsys');
        check(JSON.stringify(saved.upstream && saved.upstream.fallback) === '["udp://127.0.0.2","udp://127.0.0.3"]', '設定檔：清單欄位一行一個');
        check(!('stripEch' in (saved.resolver || {})), '設定檔：改回預設值的欄位被移除（只存跟預設不同的欄位）', JSON.stringify(saved.resolver));
        check(saved.listen.doh.port === undefined, '設定檔：清空的欄位不寫入');
        check(saved.xTest && saved.xTest.keep === true, '設定檔：不認識的欄位保留');
        check(saved.admin && saved.admin.webDir === WEB && saved.listen.plain.port === dnsPort && saved.filter.enabled === false, '設定檔：原本的設定保留');
        check(/設定頁更新了/.test(out) && /重新載入/.test(out), '伺服器重新載入');
        const cfgApi = await page.evaluate(() => fetch('/api/config').then(r => r.json()));
        check(cfgApi.effective.resolver.timeoutMs === 1777, '重新載入後生效（/api/config effective）');
        await page.click('#cfg-groups button[data-group=upstream]');
        check(await page.inputValue('[data-key="resolver.timeoutMs"] input') === '1777', '重新讀取後表單顯示新值');
        await shot('05-settings-saved');

        console.log('設定：原始 JSON');
        await page.click('#cfg-groups button[data-group=raw]');
        const rawText = await page.inputValue('#raw-json');
        check(JSON.parse(rawText).resolver.timeoutMs === 1777, '原始 JSON 顯示目前的使用者設定');
        await page.fill('#raw-json', '{ "listen": ');
        await page.click('#raw-save');
        check(/JSON 格式錯誤/.test(await page.textContent('#cfg-group .msg')), '原始 JSON：格式錯誤不送出');
        const bad1 = JSON.parse(rawText);
        bad1.listen.plain.port = 'x';
        await page.fill('#raw-json', JSON.stringify(bad1, null, 2));
        await page.click('#raw-save');
        await page.waitForFunction(() => /失敗/.test(document.getElementById('save-msg').textContent), null, { timeout: 10000 }).catch(() => {});
        check(/儲存失敗：.*listen\.plain\.port/.test(await page.textContent('#save-msg')), '原始 JSON：伺服器拒絕（400）時顯示原因', await page.textContent('#save-msg'));
        check(JSON.parse(fs.readFileSync(cfgFile, 'utf-8')).listen.plain.port === dnsPort, '原始 JSON：被拒絕時設定檔沒有變');
        await page.click('#btn-discard');
        check(/沒有未儲存的變更/.test(await page.textContent('#save-msg')), '放棄變更');
        await shot('06-settings-raw');

        console.log('工具');
        await page.goto(`${BASE}/#tools`);
        await page.waitForSelector('#tool-cache button');
        await page.click('#tool-cache button');
        await page.waitForSelector('#tool-cache .verdict:not([hidden])');
        check(/快取已清除/.test(await page.textContent('#tool-cache .verdict')), '清除快取');
        await page.fill('#tool-filter input[type=text]', 'ads.example.com');
        await page.click('#tool-filter button.primary');
        await page.waitForSelector('#tool-filter .verdict:not([hidden])');
        check(/過濾沒有啟用|沒有命中|封鎖|放行/.test(await page.textContent('#tool-filter .verdict')), '過濾規則檢查', await page.textContent('#tool-filter .verdict'));
        await page.fill('#tool-trace input[type=text]', 'example.com');
        await page.click('#tool-trace button.primary');
        await page.waitForFunction(() => /上游有回應|失敗/.test(document.querySelector('#tool-trace .verdict').textContent), null, { timeout: 15000 }).catch(() => {});
        check(/上游有回應/.test(await page.textContent('#tool-trace .verdict')) && /"upstreams"/.test(await page.textContent('#tool-trace pre')), '追蹤網域', await page.textContent('#tool-trace .verdict'));
        await page.waitForSelector('#tool-jobs button[data-job]');
        check(await page.locator('#tool-jobs button[data-job]').count() === 4, '排程工作列表');
        await page.click('#tool-jobs button[data-job="cdn-ranges"]');
        await page.waitForFunction(() => /已排入|沒有排入|失敗/.test(document.querySelector('#tool-jobs .verdict').textContent), null, { timeout: 10000 }).catch(() => {});
        // CDN 關閉時 CDN 的工作沒有註冊：要顯示原因，不能當成成功
        check(/沒有排入：未知的工作/.test(await page.textContent('#tool-jobs .verdict')), '立即執行排程工作（功能關閉時顯示原因）', await page.textContent('#tool-jobs .verdict'));
        check(/週日/.test(await page.textContent('#tool-jobs table')), '排程星期顯示成中文');
        await page.waitForSelector('#tool-acme .verdict:not([hidden])');
        check(/沒有啟用/.test(await page.textContent('#tool-acme .verdict')), 'ACME 沒啟用時顯示說明');
        await page.click('#tool-acme button.primary');
        await page.waitForFunction(() => /失敗/.test(document.querySelector('#tool-acme .verdict').textContent), null, { timeout: 10000 }).catch(() => {});
        check(/失敗：內建 ACME 沒有啟用/.test(await page.textContent('#tool-acme .verdict')), 'ACME 立即申請：沒啟用時顯示錯誤', await page.textContent('#tool-acme .verdict'));
        await page.click('#tool-ddns button.primary');
        await page.waitForFunction(() => /失敗/.test(document.querySelector('#tool-ddns .verdict').textContent), null, { timeout: 10000 }).catch(() => {});
        check(/DDNS 未啟用/.test(await page.textContent('#tool-ddns .verdict')), 'DDNS 立即更新：沒啟用時顯示錯誤');
        await page.selectOption('#tool-view select', '/api/cdn/status');
        await page.click('#tool-view button.primary');
        await page.waitForSelector('#tool-view .verdict:not([hidden])');
        check(/沒有啟用/.test(await page.textContent('#tool-view .verdict')), '查看資料：功能關閉時（404）顯示原因');
        await page.selectOption('#tool-view select', '/api/routing');
        await page.click('#tool-view button.primary');
        await page.waitForFunction(() => /路由/.test(document.querySelector('#tool-view .verdict').textContent), null, { timeout: 5000 }).catch(() => {});
        check(!(await page.isHidden('#tool-view pre')), '查看資料：顯示 JSON');
        await shot('07-tools');

        console.log('關於');
        await page.goto(`${BASE}/#about`);
        await page.waitForFunction(() => /GPL/.test(document.getElementById('about-kv').textContent));
        const ak = await page.textContent('#tab-about');
        check(ak.includes(about.version) && /設定頁版本/.test(ak) && /3\.0\.0-alpha\.2/.test(ak), '關於：核心版本與設定頁版本');
        check(ak.includes(about.source) && ak.includes(about.target) && /GPL-3\.0-or-later/.test(ak) && /散布/.test(ak), '關於：授權、原始碼網址、編譯平台、GPL 說明');
        check(await page.evaluate(() => { const i = document.getElementById('about-qr'); return i.complete && i.naturalWidth > 0; }), '關於：QR 碼圖片載入');
        check(await page.isVisible('#foot'), '主畫面也有頁尾');
        await shot('08-about');

        console.log('日誌');
        await page.goto(`${BASE}/#log`);
        await page.waitForFunction(() => document.getElementById('log-pre').textContent.length > 20, null, { timeout: 10000 }).catch(() => {});
        check(/管理 API/.test(await page.textContent('#log-pre')), '日誌：最近的紀錄');
        await page.fill('#log-filter', '重新載入');
        check(!/管理 API/.test(await page.textContent('#log-pre')) && /重新載入/.test(await page.textContent('#log-pre')), '日誌：關鍵字篩選');
        await page.fill('#log-filter', '');
        await shot('09-log');

        console.log('手機寬度、深色模式');
        await page.setViewportSize({ width: 360, height: 740 });
        for (const t of ['status', 'settings', 'tools', 'log', 'about']) {
            await page.goto(`${BASE}/#${t}`);
            await page.waitForTimeout(t === 'status' || t === 'tools' ? 1200 : 500);
            const w = await page.evaluate(() => document.documentElement.scrollWidth);
            check(w <= 361, `360 px 寬沒有水平捲動：${t}`, `scrollWidth = ${w}`);
            await shot(`10-mobile-${t}`);
        }
        await page.setViewportSize({ width: 1280, height: 900 });
        await page.emulateMedia({ colorScheme: 'dark' });
        await page.goto(`${BASE}/#status`);
        await page.waitForSelector('#st-tiles .tile');
        const bg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
        const rgb = (bg.match(/\d+/g) || []).slice(0, 3).map(Number);
        check(rgb.length === 3 && rgb[0] + rgb[1] + rgb[2] < 150, '深色模式（prefers-color-scheme）', bg);
        await shot('11-dark-status');
        await page.goto(`${BASE}/#settings`);
        await page.waitForSelector('#cfg-groups button');
        await shot('12-dark-settings');
        await page.emulateMedia({ colorScheme: 'light' });

        console.log('登出');
        await page.click('#logout');
        await page.waitForSelector('#login:not([hidden])');
        const st = await page.evaluate(() => fetch('/api/status').then(r => r.status));
        check(st === 401, '登出後 API 回 401');

        check(errors.length === 0, '整個過程沒有 JavaScript 錯誤', errors.join('\n     '));
    } catch (e) {
        bad(`測試中斷：${e.stack || e}`);
    } finally {
        if (browser) await browser.close();
        if (exited === null) {
            child.kill('SIGINT');
            for (let i = 0; i < 50 && exited === null; i++) await sleep(100);
            if (exited === null) child.kill('SIGKILL');
        }
        if (fail) console.log('\n---- kuroshio 輸出（最後 60 行）----\n' + out.split('\n').slice(-60).join('\n'));
        try { fs.rmSync(dir, { recursive: true, force: true }); } catch (e) { /* Windows 上檔案可能還被占用 */ }
    }
    console.log(`\n${pass} 通過，${fail} 失敗；截圖在 ${SHOTS}`);
    process.exit(fail ? 1 : 0);
})();
