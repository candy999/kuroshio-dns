'use strict';
// CI：Windows 本機設定頁（data/admin）端對端測試。自己啟動 kuroshio（暫存設定檔、空著的埠號），用 Playwright 實際操作：
// 登入、狀態、簡易 / 專業模式、改設定並儲存（伺服器在程式內重新啟動）、原始 JSON、網域與憑證 / 多網卡 / 多位址監聽 / 存放位置、連線來源、
// 社群（邀請碼、我的身分、新增好友、好友清單與動作〔模擬資料〕、事件紀錄、自動規則）、工具、備份匯出 / 匯入、日誌、手機寬度、深色模式、登出。
//
//   cargo build -p kuroshio && node tools/admin-e2e.js
//   KUROSHIO_BIN=path/to/kuroshio SHOTS=screenshots-admin node tools/admin-e2e.js
const { chromium } = require('playwright');
const { spawn, execFileSync } = require('child_process');
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
        // 台灣 IP 資料用版控裡的那一份（測試的執行檔旁邊沒有 data 目錄）
        access: { dataFile: path.join(ROOT, 'data', 'geo', 'tw-ip.json') },
        // 設定頁不認識的欄位，存檔後要保留
        xTest: { keep: true }
    };
    fs.writeFileSync(cfgFile, JSON.stringify(initial, null, 2));
    // 備份用的學習資料（CDN 關閉時服務不會動這些檔案，匯出直接讀磁碟）
    fs.mkdirSync(path.join(dir, 'state'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'state', 'cdn-domains.json'), JSON.stringify({ domains: [
        { name: 'a.example', provider: 'cloudflare', hits: 12, firstSeen: 1, lastSeen: 2, policy: 'always', v4: { verdict: 'ok', at: 100 } }] }));
    fs.writeFileSync(path.join(dir, 'state', 'blacklist.txt'), '# 測試\n203.0.113.9\n');
    // 儀表板用的統計（31 天的範例資料，見 tools/dashboard-seed.js）
    fs.writeFileSync(path.join(dir, 'state', 'stats.json'), JSON.stringify(require('./dashboard-seed.js').stats()));

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
        check((await raw(adminPort, 'GET', '/api/backup/export?kind=full')).status === 401, '沒登入時不能下載備份（401）');
        const xi = await raw(adminPort, 'POST', '/api/backup/import', { Origin: 'http://evil.example', Authorization: `Bearer ${token}` }, 'x');
        check(xi.status === 403, '跨站匯入備份（Origin 不是本機）回 403');
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
        check(/硬體/.test(tiles) && !/硬體等級/.test(tiles) && /系統記憶體/.test(tiles) && /拉回台灣/.test(tiles) && /p50/.test(tiles), '狀態：硬體（沒有等級）、記憶體、拉回台灣、回應時間');
        check(/最久未存/.test(tiles) && /上限 \d+(\.\d+)? 小時/.test(tiles), '狀態：最久未存與上限', tiles.slice(-200));
        check(/保留 [\d,]+ MB（自動）/.test(tiles) && /寬裕/.test(tiles), '狀態：記憶體控制（系統保留量、狀態）', tiles.slice(0, 400));
        check(/快取 [\d,]+ \/ [\d,]+ 筆/.test(tiles), '狀態：動態大小（快取）', tiles.slice(0, 500));
        check(/儲存空間/.test(tiles) && /保留 .*（自動）/.test(tiles), '狀態：儲存保留空間', tiles.slice(-300));
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
        check(['服務與監聽', '網域與憑證', '連線來源', '上游', '過濾', 'CDN', 'DDNS', '憑證', '公開頁', '社群', '系統', '日誌'].every(g => groups.some(x => x.includes(g))), '設定分類齊全', groups.join(' / '));
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
        const prot = page.locator('[data-key="filter.lists"] select[aria-label="保護"]');
        check(await prot.count() >= 5, '過濾（專業模式）：訂閱清單有「保護」欄');
        await prot.nth(0).selectOption('true');
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
        check(saved.filter && saved.filter.lists && saved.filter.lists[0].protect === true && !('protect' in saved.filter.lists[1]), '設定檔：清單的保護旗標存成布林、沒選的不寫', JSON.stringify(saved.filter && saved.filter.lists && saved.filter.lists.slice(0, 2)));
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

        console.log('網域與憑證、多網卡、多位址監聽、存放位置');
        // 測試憑證：有 openssl 才產生（沒有時只檢查「找不到檔案」的顯示）
        const certFile = path.join(dir, 'own', 'fullchain.pem'), keyFile = path.join(dir, 'own', 'privkey.pem');
        fs.mkdirSync(path.dirname(certFile), { recursive: true });
        let haveCert = false;
        try {
            execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '30', '-subj', '/CN=dns.example.com',
                '-addext', 'subjectAltName=DNS:dns.example.com', '-addext', 'basicConstraints=critical,CA:FALSE', '-keyout', keyFile, '-out', certFile], { stdio: 'ignore' });
            haveCert = fs.existsSync(certFile) && fs.existsSync(keyFile);
        } catch (e) { /* 沒有 openssl */ }
        const ifApi = await page.evaluate(() => fetch('/api/interfaces').then(r => r.json()));
        check(Array.isArray(ifApi.interfaces), '/api/interfaces 回網卡清單');
        // 網卡清單換成固定的內容（每台機器的網卡不一樣）
        const fakeIfaces = { interfaces: [
            { name: 'lo', label: 'lo', up: true, addrs: [{ ip: '127.0.0.1', family: 4, scope: 'loopback' }] },
            { name: 'eth0', label: '乙太網路', up: true, addrs: [{ ip: '203.0.113.25', family: 4, scope: 'public' }, { ip: '2001:db8::25', family: 6, scope: 'public' },
                { ip: '2001:db8::a1b2', family: 6, scope: 'public', temporary: true, deprecated: true }, { ip: 'fe80::1', family: 6, scope: 'linklocal' }] },
            { name: 'eth1', label: '乙太網路 2', up: true, addrs: [{ ip: '192.168.1.10', family: 4, scope: 'private' }] },
            { name: 'wlan0', label: 'Wi-Fi', up: false, addrs: [] }
        ] };
        await page.route('**/api/interfaces', r => r.fulfill({ contentType: 'application/json', body: JSON.stringify(fakeIfaces) }));
        await page.reload();
        await page.waitForSelector('#cfg-groups button');
        const field = k => `[data-key="${k}"]`;

        await page.click('#cfg-groups button[data-group=domain]');
        await page.waitForSelector('#panel-paths[data-ready]');
        const pathsText = await page.textContent('#panel-paths');
        check(pathsText.includes(cfgFile) && pathsText.includes(path.join(dir, 'state')) && /設定檔/.test(pathsText) && /憑證檔/.test(pathsText) && /私鑰檔/.test(pathsText) && /社群金鑰/.test(pathsText),
            '存放位置：列出設定檔、學習資料、憑證、金鑰的位置', pathsText.slice(0, 300));
        check(/含密鑰/.test(pathsText) && pathsText.includes(path.join(dir, 'admin.token')) && !pathsText.includes(token), '存放位置：只有路徑，沒有密鑰內容');
        check(await page.locator('#panel-paths button.copy').count() >= 6, '存放位置：每個路徑有複製按鈕');
        await ctx.grantPermissions(['clipboard-read', 'clipboard-write']).catch(() => {});
        await page.locator('#panel-paths button.copy').first().click();
        await page.waitForSelector('#toast:not([hidden])');
        check((await page.textContent('#toast')).includes('已複製：' + cfgFile), '存放位置：複製按鈕', await page.textContent('#toast'));
        check(/還沒有設定憑證/.test(await page.textContent('#panel-cert')) && /還沒有填憑證檔/.test(await page.textContent('#cert-hint')), '憑證：還沒設定時的說明');

        await page.fill(`${field('domain')} input`, 'https://dns.example.com/');
        check(await page.isVisible(`${field('domain')} .err-text`) && await page.isDisabled('#btn-save'), '綁定網域：格式錯誤不能儲存');
        await page.fill(`${field('domain')} input`, 'DNS.Example.com.');
        check(!(await page.isVisible(`${field('domain')} .err-text`)), '綁定網域：格式正確');
        check(await page.isChecked(`${field('ddns.enabled')} input[type=radio] >> nth=0`), 'DDNS 預設是「固定網域，不需要更新」');
        check(await page.isChecked(`${field('acme.enabled')} input[type=radio] >> nth=0`), '憑證預設是「使用我自己的憑證檔」');
        await page.fill(`${field('tls.cert')} input`, certFile);
        check(/要一起填/.test(await page.textContent(`${field('tls.key')} .err-text`)) && await page.isDisabled('#btn-save'), '憑證檔與私鑰檔要一起填');
        await page.fill(`${field('tls.key')} input`, keyFile);
        check(!(await page.isVisible(`${field('tls.key')} .err-text`)) && !(await page.isDisabled('#btn-save')), '兩個都填了就可以儲存');
        await page.check(`${field('acme.enabled')} input[type=radio] >> nth=1`);
        check(/會覆蓋/.test(await page.textContent('#cert-hint')), '改成自動申請而且填了憑證檔：提醒會被覆蓋');
        await page.check(`${field('acme.enabled')} input[type=radio] >> nth=0`);
        check(!(await page.locator('#cert-hint .msg').count()), '改回自己的憑證檔：提醒消失');

        // 多位址監聽（專業模式）、DoH 的 TLS 模式、IIS 站台名稱
        await page.click('#cfg-groups button[data-group=listen]');
        await page.waitForSelector('#panel-listeners[data-ready]');
        check(/沒有開啟任何加密協議/.test(await page.textContent('#panel-listeners')), '監聽狀態：沒有加密協議時的說明');
        const dotPort = await freePort();
        await page.fill(`${field('listen.dot.binds')} textarea`, '127.0.0.1\n999.1.1.1');
        check(/第 2 行/.test(await page.textContent(`${field('listen.dot.binds')} .err-text`)) && await page.isDisabled('#btn-save'), '監聽位址：不是 IP 不能儲存');
        await page.fill(`${field('listen.dot.binds')} textarea`, '127.0.0.1\n[::1]:853');
        check(await page.isVisible(`${field('listen.dot.binds')} .err-text`), '監聽位址：不接受中括號與埠號');
        await page.fill(`${field('listen.dot.binds')} textarea`, '127.0.0.1');
        const pickerOpts = await page.$$eval(`${field('listen.dot.binds')} select.picker option`, os => os.map(o => o.value));
        check(pickerOpts.includes('0.0.0.0') && pickerOpts.includes('::') && pickerOpts.includes('203.0.113.25') && pickerOpts.includes('192.168.1.10') && !pickerOpts.includes('fe80::1'),
            '監聽位址：可以從網卡位址挑選（不列鏈路本地位址）', pickerOpts.join(' '));
        // 192.0.2.1 不是這台機器的位址：綁定會失敗，用來檢查失敗原因的顯示
        await page.fill(`${field('listen.dot.binds')} textarea`, '127.0.0.1\n192.0.2.1');
        await page.selectOption(`${field('listen.doh.binds')} select.picker`, '192.168.1.10');
        await page.selectOption(`${field('listen.doh.binds')} select.picker`, '203.0.113.25');
        await page.selectOption(`${field('listen.doh.binds')} select.picker`, '192.168.1.10');
        check(await page.inputValue(`${field('listen.doh.binds')} textarea`) === '192.168.1.10\n203.0.113.25', '監聽位址：挑選的位址加到清單（不重複）');
        await page.fill(`${field('listen.dot.port')} input`, String(dotPort));
        if (haveCert) await page.check(`${field('listen.dot.enabled')} input[type=checkbox]`);
        await page.selectOption(`${field('listen.doh.tls')} select`, 'false');
        check(await page.isHidden(field('listen.doh.iisSite')), 'IIS 站台名稱：不是 IIS 反向代理模式時不顯示');
        await page.selectOption(`${field('listen.doh.windowsMode')} select`, 'iis-proxy');
        check(await page.isVisible(field('listen.doh.iisSite')) && /自動匯入/.test(await page.textContent(field('listen.doh.iisSite'))), 'IIS 站台名稱：IIS 反向代理模式才顯示，說明憑證會自動匯入並綁定');
        await page.fill(`${field('listen.doh.iisSite')} input`, 'bad/site"name');
        check(await page.isVisible(`${field('listen.doh.iisSite')} .err-text`), 'IIS 站台名稱：不允許的字元');
        await page.fill(`${field('listen.doh.iisSite')} input`, 'Default Web Site');

        // DDNS：出口（網卡）多選、IPv6 預設不發布
        await page.click('#cfg-groups button[data-group=ddns]');
        await page.waitForSelector(`${field('ddns.interfaces')} .iface`);
        const ifText = await page.textContent(field('ddns.interfaces'));
        check(/eth0/.test(ifText) && /乙太網路 2/.test(ifText) && /203\.0\.113\.25/.test(ifText) && /暫時位址/.test(ifText) && /已停用/.test(ifText) && /未連線/.test(ifText) && !/fe80::1/.test(ifText),
            'DDNS 出口：列出網卡與位址（標示暫時 / 已停用 / 未連線）', ifText.slice(0, 300));
        check(!(await page.locator(`${field('ddns.interfaces')} input[value=lo]`).count()), 'DDNS 出口：不列迴路介面');
        check(!(await page.isChecked(`${field('ddns.ipv6')} input[type=checkbox]`)) && /IPv6/.test(await page.textContent(`${field('ddns.ipv6')} .help`)) && /擋/.test(await page.textContent(`${field('ddns.ipv6')} .help`)),
            'DDNS：IPv6 預設不發布，並說明原因');
        await page.check(`${field('ddns.ipv6')} input[type=checkbox]`);
        await page.check(`${field('ddns.interfaces')} input[value=eth0]`);
        await page.check(`${field('ddns.interfaces')} input[value=eth1]`);
        await page.fill(`${field('ddns.records')} textarea`, 'not a domain');
        check(await page.isVisible(`${field('ddns.records')} .err-text`), 'DDNS 記錄：格式錯誤');
        await page.fill(`${field('ddns.records')} textarea`, '');
        check(/DDNS 沒有啟用（固定網域）/.test(await page.textContent('#panel-ddns')), 'DDNS 結果：固定網域時說明不會更新記錄');
        await shot('06b-ddns-edited');
        await page.click('#btn-save');
        await page.waitForFunction(() => /已儲存並套用|失敗|沒有在 30 秒/.test(document.getElementById('save-msg').textContent) || !document.getElementById('login').hidden, null, { timeout: 40000 });
        check(/已儲存並套用/.test(await page.textContent('#save-msg')), '儲存網域、憑證、出口、監聽位址', await page.textContent('#save-msg'));
        const cfg2 = (await page.evaluate(() => fetch('/api/config').then(r => r.json())));
        const u2 = cfg2.user;
        check(u2.domain === 'dns.example.com', '設定：domain = dns.example.com（整理成小寫、去掉結尾的點）', JSON.stringify(u2.domain));
        check(u2.tls && u2.tls.cert === certFile && u2.tls.key === keyFile, '設定：tls.cert / tls.key（自己的憑證檔）', JSON.stringify(u2.tls));
        check(u2.acme === undefined && !(u2.ddns && 'enabled' in u2.ddns) && cfg2.effective.acme.enabled === false && cfg2.effective.ddns.enabled === false, '設定：固定網域、自備憑證（不開 DDNS、不開 ACME）');
        check(u2.ddns && u2.ddns.ipv6 === true && JSON.stringify(u2.ddns.interfaces) === '["eth0","eth1"]' && !('records' in u2.ddns), '設定：ddns.ipv6 = true、ddns.interfaces = [eth0, eth1]', JSON.stringify(u2.ddns));
        check(JSON.stringify(u2.listen.dot.binds) === '["127.0.0.1","192.0.2.1"]' && JSON.stringify(u2.listen.doh.binds) === '["192.168.1.10","203.0.113.25"]', '設定：listen.dot.binds / listen.doh.binds', JSON.stringify(u2.listen));
        check(u2.listen.doh.tls === false && u2.listen.doh.windowsMode === 'iis-proxy' && u2.listen.doh.iisSite === 'Default Web Site', '設定：listen.doh.tls = false（布林）、iisSite', JSON.stringify(u2.listen.doh));
        check(JSON.stringify(cfg2.effective.acme.domains) === '["dns.example.com"]' && cfg2.effective.site.hostname === 'dns.example.com', '綁定網域自動帶到憑證與公開頁');
        const paths2 = await page.evaluate(() => fetch('/api/paths').then(r => r.json()));
        check(paths2.tls.source === 'manual' && paths2.tls.cert === certFile && paths2.tls.exists === haveCert, '/api/paths：憑證來源是自備憑證', JSON.stringify(paths2.tls));

        await page.click('#cfg-groups button[data-group=domain]');
        await page.waitForSelector('#panel-cert[data-ready]');
        const certText = await page.textContent('#panel-cert');
        check(/自己的憑證檔/.test(certText) && certText.includes(certFile), '憑證狀態：來源與位置', certText.slice(0, 200));
        if (haveCert) check(/有效（剩 \d+ 天）/.test(certText) && /CN=dns\.example\.com/.test(certText) && /有涵蓋 dns\.example\.com/.test(certText), '憑證狀態：主體、到期、有涵蓋綁定網域', certText);
        else check(/找不到檔案/.test(certText), '憑證狀態：檔案不存在時顯示（這台機器沒有 openssl，略過憑證內容檢查）', certText);
        check(await page.inputValue(`${field('domain')} input`) === 'dns.example.com', '重新讀取後顯示綁定網域');
        await shot('06c-domain');
        await page.click('#cfg-groups button[data-group=ddns]');
        await page.waitForSelector(`${field('ddns.interfaces')} .iface`);
        check(await page.isChecked(`${field('ddns.interfaces')} input[value=eth0]`) && await page.isChecked(`${field('ddns.interfaces')} input[value=eth1]`) && !(await page.isChecked(`${field('ddns.interfaces')} input[value=wlan0]`)),
            '重新讀取後出口的勾選狀態保留');
        if (haveCert) {
            await page.click('#cfg-groups button[data-group=listen]');
            await page.waitForSelector('#panel-listeners[data-ready]');
            const lt = await page.textContent('#panel-listeners');
            check(/DoT/.test(lt) && lt.includes(String(dotPort)) && /執行中/.test(lt) && /綁定失敗/.test(lt) && /192\.0\.2\.1/.test(lt), '監聽狀態：每個位址一列，綁定失敗列出原因', lt);
            await shot('06d-listeners');
            await page.goto(`${BASE}/#status`);
            await page.waitForFunction(() => /綁定失敗/.test(document.getElementById('st-listen').textContent), null, { timeout: 8000 }).catch(() => {});
            const sl = await page.textContent('#st-listen');
            check(/綁定失敗/.test(sl) && /192\.0\.2\.1/.test(sl) && /127\.0\.0\.1/.test(sl), '狀態分頁：監聽表格列出綁定失敗的位址與原因', sl);
            await page.goto(`${BASE}/#settings`);
            await page.waitForSelector('#cfg-groups button');
        } else ok('（沒有 openssl：略過加密監聽的綁定結果檢查）');
        console.log('連線來源');
        await page.click('#cfg-groups button[data-group=access]');
        await page.waitForSelector('#panel-access[data-ready]');
        const accText = await page.textContent('#panel-access');
        check(/只開放台灣/.test(accText) && /\d{4}-\d{2}-\d{2} 的資料/.test(accText) && !(await page.locator('#access-failopen').count()), '連線來源：目前狀態（模式、資料日期，資料讀得到就沒有警告）', accText.slice(0, 300));
        check(await page.isChecked(`${field('access.mode')} input[type=radio] >> nth=0`) && await page.isHidden(field('access.groups')), '預設「只開放台灣」，不顯示 ISP 勾選');
        const accDesc = await page.textContent('#cfg-group');
        check(/區網/.test(accDesc) && /好友/.test(accDesc) && /一律允許/.test(accDesc) && /VPN/.test(accDesc) && /優先於一切/.test(accDesc), '說明區網 / 本機 / 好友一律允許、VPN 與國外監測要加允許、封鎖優先於一切');
        await page.check(`${field('access.mode')} input[type=radio] >> nth=1`);
        await page.waitForSelector(`${field('access.groups')} .agroups[data-ready]`);
        check(await page.isVisible(field('access.groups')), '自訂 ISP：顯示勾選清單');
        const grText = await page.textContent(field('access.groups'));
        check(/中華電信/.test(grText) && /萬個位址/.test(grText) && /全選（含日後新增的 ISP）/.test(grText), 'ISP 清單：名稱、位址數（萬）、全選', grText.slice(0, 200));
        check(await page.isChecked(`${field('access.groups')} input[value="*"]`) && await page.isChecked(`${field('access.groups')} input[value=cht]`), '預設全選');
        check(/AS\d+/.test(grText), '專業模式：ISP 顯示 ASN');
        const allIds = await page.$$eval(`${field('access.groups')} input[type=checkbox]`, cs => cs.map(c => c.value).filter(v => v !== '*'));
        await page.uncheck(`${field('access.groups')} input[value=other]`);
        check(!(await page.isChecked(`${field('access.groups')} input[value="*"]`)), '取消一組：全選跟著取消');
        await page.fill(`${field('access.allow')} textarea`, '203.0.113.0/24\n2001:DB8::/33');
        await page.fill(`${field('access.deny')} textarea`, '198.51.100.7\n10.0.0.0/33');
        check(/第 2 行/.test(await page.textContent(`${field('access.deny')} .err-text`)) && /0～32/.test(await page.textContent(`${field('access.deny')} .err-text`)) && await page.isDisabled('#btn-save'), '封鎖名單：前綴長度超過 32 不能儲存');
        for (const badNet of ['2001:db8::/129', '300.1.1.1', 'example.com', '1.2.3.4/24/1', '[::1]']) {
            await page.fill(`${field('access.deny')} textarea`, badNet);
            check(await page.isVisible(`${field('access.deny')} .err-text`) && await page.isDisabled('#btn-save'), `封鎖名單：「${badNet}」格式錯誤`);
        }
        await page.fill(`${field('access.deny')} textarea`, '198.51.100.7');
        check(!(await page.isVisible(`${field('access.deny')} .err-text`)) && !(await page.isDisabled('#btn-save')), '格式正確就可以儲存');
        // 測試 IP（依已套用的設定：只開放台灣）
        const testIp = async ip => {
            await page.fill('#access-test-ip', ip);
            await page.press('#access-test-ip', 'Enter');
            await page.waitForFunction(() => !document.getElementById('access-test-out').hidden, null, { timeout: 5000 }).catch(() => {});
            await page.waitForTimeout(300);
            return page.textContent('#access-test-out');
        };
        let tv = await testIp('192.0.2.300');
        check(/請輸入一個 IP/.test(tv), '測試 IP：格式錯誤不送出', tv);
        tv = await testIp('168.95.1.1');
        check(/可以連進來/.test(tv) && /中華電信/.test(tv), '測試 IP：中華電信的 IP 可以連（台灣網段：中華電信）', tv);
        tv = await testIp('8.8.8.8');
        check(/會被擋下/.test(tv) && /不在允許的網段/.test(tv), '測試 IP：國外 IP 被擋', tv);
        tv = await testIp('192.168.1.5');
        check(/可以連進來/.test(tv) && /私有/.test(tv), '測試 IP：私有位址一律允許', tv);
        await shot('06f-access-edited');
        await page.click('#btn-save');
        await page.waitForFunction(() => /已儲存並套用|失敗|沒有在 30 秒/.test(document.getElementById('save-msg').textContent) || !document.getElementById('login').hidden, null, { timeout: 40000 });
        check(/已儲存並套用/.test(await page.textContent('#save-msg')), '儲存連線來源', await page.textContent('#save-msg'));
        const ua = (await page.evaluate(() => fetch('/api/config').then(r => r.json()))).user.access || {};
        const wantGroups = allIds.filter(x => x !== 'other');
        check(ua.mode === 'custom' && JSON.stringify(ua.groups) === JSON.stringify(wantGroups), '設定：access.mode = custom、access.groups = 勾選的群組（沒有 other）', JSON.stringify(ua));
        check(JSON.stringify(ua.allow) === '["203.0.113.0/24","2001:db8::/33"]' && JSON.stringify(ua.deny) === '["198.51.100.7"]', '設定：access.allow / access.deny（IPv6 轉小寫）', JSON.stringify(ua));
        await page.click('#cfg-groups button[data-group=access]');
        await page.waitForSelector('#panel-access[data-ready]');
        check(/自訂 ISP（開放 \d+ \/ \d+ 組）/.test(await page.textContent('#panel-access')), '目前狀態：自訂 ISP 與開放的組數', (await page.textContent('#panel-access')).slice(0, 200));
        tv = await testIp('203.0.113.9');
        check(/可以連進來/.test(tv) && /自訂允許 203\.0\.113\.0\/24/.test(tv), '測試 IP：允許名單', tv);
        tv = await testIp('198.51.100.7');
        check(/會被擋下/.test(tv) && /自訂封鎖/.test(tv), '測試 IP：封鎖名單', tv);
        await page.waitForSelector(`${field('access.groups')} .agroups[data-ready]`);
        check(!(await page.isChecked(`${field('access.groups')} input[value=other]`)) && await page.isChecked(`${field('access.groups')} input[value=cht]`), '重新讀取後勾選狀態保留');
        // 被拒絕最多的網段：一鍵加入封鎖 / 允許（真的拒絕要從外面連，這裡換成固定的統計）
        await page.route('**/api/access', async r => {
            const res = await r.fetch();
            const j = await res.json();
            j.denied = { total: 57, byListener: { dot: 40, doh: 17 } };
            j.topDenied = [{ net: '45.135.232.0/24', count: 31 }, { net: '2a06:4880:1000::/48', count: 26 }];
            r.fulfill({ response: res, body: JSON.stringify(j) });
        });
        await page.click('#cfg-groups button[data-group=upstream]');
        await page.click('#cfg-groups button[data-group=access]');
        await page.waitForSelector('#panel-access[data-ready]');
        check(/57 次/.test(await page.textContent('#panel-access')) && /45\.135\.232\.0\/24/.test(await page.textContent('#panel-access')), '目前狀態：拒絕次數與被拒絕最多的網段');
        await page.click('#panel-access button[aria-label="把 45.135.232.0/24 加入封鎖名單"]');
        check(await page.inputValue(`${field('access.deny')} textarea`) === '198.51.100.7\n45.135.232.0/24' && /項未儲存的變更/.test(await page.textContent('#save-msg')), '一鍵加入封鎖名單（還沒有儲存）');
        await page.click('#panel-access button[aria-label="把 2a06:4880:1000::/48 加入允許名單"]');
        check(/2a06:4880:1000::\/48/.test(await page.inputValue(`${field('access.allow')} textarea`)), '一鍵加入允許名單');
        await shot('06g-access-top');
        await page.click('#btn-discard');
        await page.unroute('**/api/access');
        await page.check(`${field('access.groups')} input[value="*"]`);
        check(await page.isChecked(`${field('access.groups')} input[value=other]`) && /未儲存/.test(await page.textContent(field('access.groups'))), '勾「全選」：每一組都勾上');
        await page.click('#btn-discard');
        await page.goto(`${BASE}/#status`);
        await page.waitForFunction(() => /連線來源自訂 ISP/.test(document.getElementById('st-tiles').textContent), null, { timeout: 8000 }).catch(() => {});
        const tilesA = await page.textContent('#st-tiles');
        check(/連線來源/.test(tilesA) && /自訂 ISP/.test(tilesA) && /已拒絕 \d+ 次/.test(tilesA), '狀態分頁：連線來源摘要', tilesA.slice(-200));
        await page.goto(`${BASE}/#settings`);
        await page.waitForSelector('#cfg-groups button');

        // 390 px：新面板不能把頁面撐寬
        await page.setViewportSize({ width: 390, height: 800 });
        for (const g of ['domain', 'ddns', 'listen', 'access']) {
            await page.click(`#cfg-groups button[data-group=${g}]`);
            await page.waitForTimeout(600);
            const w = await page.evaluate(() => document.documentElement.scrollWidth);
            check(w <= 391, `390 px 寬沒有水平捲動：設定 → ${g}`, `scrollWidth = ${w}`);
            await shot(`06e-mobile-${g}`);
        }
        await page.setViewportSize({ width: 1280, height: 900 });
        await page.unroute('**/api/interfaces');

        console.log('社群：好友邀請碼');
        await page.goto(`${BASE}/#settings`);
        await page.waitForSelector('#cfg-groups button');
        await page.click('#cfg-groups button[data-group=community]');
        await page.waitForFunction(() => /社群模式沒有啟用/.test((document.getElementById('invite-mine') || {}).textContent || ''), null, { timeout: 10000 })
            .then(() => ok('邀請碼：社群模式沒有啟用時的說明'), () => bad('邀請碼：沒有「社群模式沒有啟用」的說明'));
        await page.check(`${field('community.enabled')} input[type=checkbox]`);
        await page.click('#btn-save');
        await page.waitForFunction(() => /已儲存並套用|失敗|沒有在 30 秒/.test(document.getElementById('save-msg').textContent), null, { timeout: 40000 });
        check(/已儲存並套用/.test(await page.textContent('#save-msg')), '啟用社群模式並儲存', await page.textContent('#save-msg'));
        await page.click('#cfg-groups button[data-group=community]');
        await page.waitForSelector('#invite-code', { timeout: 10000 }).catch(() => {});
        const code1 = ((await page.textContent('#invite-code').catch(() => '')) || '').trim();
        check(/^KRS1\.[A-Z2-7]{60,}$/.test(code1), '我的邀請碼：KRS1. 開頭', code1);
        check(/^data:image\/svg\+xml/.test(await page.getAttribute('#invite-qr', 'src').catch(() => '') || ''), '我的邀請碼：QR 碼');
        check(/還沒就緒/.test(await page.textContent('#invite-mine')), '我的邀請碼：社群還沒就緒時提醒好友暫時無法加入');
        await page.click('#invite-mine button:has-text("複製邀請碼")');
        await page.waitForFunction(c => document.getElementById('toast').textContent.includes(c), code1, { timeout: 5000 }).catch(() => {});
        check((await page.textContent('#toast')).includes(code1), '我的邀請碼：複製', await page.textContent('#toast'));
        const st1 = await page.evaluate(() => fetch('/api/community/status').then(r => r.text()));
        check(!st1.includes(code1) && /"invite"/.test(st1), '狀態 API 只有邀請碼的建立時間，沒有邀請碼本身');
        page.once('dialog', d => d.dismiss());
        await page.click('#invite-mine button:has-text("重新產生")');
        await page.waitForTimeout(300);
        check((await page.textContent('#invite-code')).trim() === code1, '重新產生：按取消就不變');
        page.once('dialog', d => d.accept());
        await page.click('#invite-mine button:has-text("重新產生")');
        await page.waitForFunction(c => { const e = document.getElementById('invite-code'); return e && e.textContent.trim() !== c; }, code1, { timeout: 10000 }).catch(() => {});
        const code2 = ((await page.textContent('#invite-code').catch(() => '')) || '').trim();
        check(/^KRS1\./.test(code2) && code2 !== code1, '重新產生：確認後換成新的邀請碼', code2);
        // 貼上：打錯一個字 → 檢查碼擋下；自己的邀請碼、社群沒就緒 → 列出缺什麼
        const i = Math.floor(code2.length / 2);
        const typo = code2.slice(0, i) + (code2[i] === 'Q' ? 'R' : 'Q') + code2.slice(i + 1);
        await page.fill('#invite-input', '  ' + typo + '  ');
        await page.click('#community-invite button:has-text("加好友")');
        await page.waitForSelector('#invite-verdict', { timeout: 15000 }).catch(() => {});
        check(/檢查碼/.test(await page.textContent('#invite-result').catch(() => '')), '貼上邀請碼：打錯字時顯示檢查碼不符', await page.textContent('#invite-result').catch(() => ''));
        await page.fill('#invite-input', code2);
        await page.press('#invite-input', 'Enter');
        await page.waitForFunction(() => /就緒/.test((document.getElementById('invite-result') || {}).textContent || ''), null, { timeout: 30000 }).catch(() => {});
        const res2 = await page.textContent('#invite-result').catch(() => '');
        check(/還沒就緒/.test(res2) && await page.locator('#invite-result .invite-problems li').count() >= 1 && /完成/.test(res2) && /失敗/.test(res2), '貼上邀請碼：我這邊沒就緒時逐步列出缺什麼', res2);
        await shot('06f-community-invite');
        await page.setViewportSize({ width: 390, height: 800 });
        await page.waitForTimeout(300);
        const cw = await page.evaluate(() => document.documentElement.scrollWidth);
        check(cw <= 391, '390 px 寬沒有水平捲動：設定 → 社群（邀請碼）', `scrollWidth = ${cw}`);
        await shot('06f-mobile-community');
        await page.setViewportSize({ width: 1280, height: 900 });
        console.log('社群：我的身分、新增好友、好友與請求、事件紀錄、自動規則');
        // 真的服務：社群已啟用但還沒就緒（沒有網域），自我檢查列出缺什麼；用網域加好友 → 服務回「未就緒」
        await page.waitForFunction(() => /未就緒/.test((document.getElementById('community-status') || {}).textContent || ''), null, { timeout: 10000 }).catch(() => {});
        check(/未就緒/.test(await page.textContent('#community-status')) && await page.locator('#cm-problems li').count() >= 1,
            '我的身分：未就緒時逐條列出自我檢查的問題（真的服務）', await page.textContent('#community-status'));
        await page.click('#community-status button:has-text("重新檢查")');
        await page.waitForFunction(() => /已重新檢查/.test(document.getElementById('toast').textContent), null, { timeout: 15000 }).catch(() => {});
        check(/已重新檢查/.test(await page.textContent('#toast')), '我的身分：重新檢查（POST /api/community/check）', await page.textContent('#toast'));
        {
            // 時間用固定的台灣格式（2026-11-12 10:22），不跟瀏覽器語系（Playwright 預設是英文，舊寫法會變成 11/12/2026, 10:22:03 AM）
            const t = await page.textContent('#community-status');
            check(/\d{4}-\d{2}-\d{2} \d{2}:\d{2}/.test(t) && !/\d{1,2}\/\d{1,2}\/\d{4}|\b[AP]M\b/.test(t), '我的身分：時間是 YYYY-MM-DD HH:mm（不跟瀏覽器語系）', t);
        }
        await page.fill('#community-add-input', 'friend.example.com');
        await page.click('#community-add button:has-text("送出請求")');
        await page.waitForSelector('#community-add-result .msg', { timeout: 15000 }).catch(() => {});
        check(/未就緒/.test(await page.textContent('#community-add-result').catch(() => '')), '新增好友：服務回覆的原因顯示出來（真的服務：未就緒）', await page.textContent('#community-add-result').catch(() => ''));

        // 好友清單與動作用模擬資料（真的好友需要公開網域與憑證）：攔截 /api/community/peers、events 與各動作，記下送出的請求
        const now = Date.now();
        let peers = [
            { domain: 'in.example.net', rel: 'in', info: { asn: 3462, colo: 'TPE', rttMs: 12, jitterMs: 2, lossPct: 0 }, stats: {}, fingerprint: 'AB:CD:EF:01:23:45:67:89:AB:CD' },
            { domain: 'in2.example.net', rel: 'in', info: { asn: 17421, colo: 'KHH' }, stats: {} },
            { domain: 'friend.example.com', rel: 'friend', channel: 'doq', invitedAt: now - 86400000, friendSince: now - 86400000, lastSyncOk: now - 60000,
                info: { asn: 4780, colo: 'TPE', rttMs: 25, jitterMs: 3, lossPct: 1 }, stats: { offered: 120, invalid: 2, tried: 40, ok: 38, fail: 2 },
                scores: { node: { score: 0.9, ok: 9, fail: 0, invalid: 0 }, site: { score: 0.95, ok: 38, fail: 2, invalid: 0 } } },
            { domain: 'keys.example.org', rel: 'friend', channel: 'https', preferChannel: 'https', lastError: '連線逾時', pendingKey: { kid: 'aa', fingerprint: '11:22:33' }, stats: {} },
            { domain: 'out.example.org', rel: 'out', stats: {} },
            { domain: 'blocked.example.net', rel: 'none', myBlock: true, stats: {} }
        ];
        const posted = [];
        await page.route('**/api/community/**', async r => {
            const u = new URL(r.request().url());
            const name = u.pathname.replace('/api/community/', ''), d = u.searchParams.get('domain');
            const json = v => r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(v) });
            if (name === 'peers') return json(peers);
            if (name === 'events') return json([{ at: now, domain: 'friend.example.com', type: '成為好友', detail: '透過邀請碼加入' }, { at: now - 1000, domain: 'in.example.net', type: '收到請求', detail: '' }]);
            if (r.request().method() !== 'POST' || name === 'check' || name.startsWith('invite')) return r.continue();
            posted.push({ name, domain: d, block: u.searchParams.get('block'), channel: u.searchParams.get('channel'), method: r.request().method() });
            const p = peers.find(x => x.domain === d);
            if (name === 'accept' && p) p.rel = 'friend';
            else if (name === 'reject' && p) { p.rel = 'none'; p.rejectedUntil = now + 7 * 86400000; }
            else if (name === 'delete' && p) peers = peers.filter(x => x !== p);
            else if (name === 'unblock' && p) p.myBlock = false;
            else if (name === 'channel' && p) p.preferChannel = u.searchParams.get('channel') === 'auto' ? null : u.searchParams.get('channel');
            else if (name === 'add') peers.push({ domain: d, rel: 'out', stats: {} });
            return json({ ok: true });
        });
        const card = dm => `#community-peers .cm-peer[data-domain="${dm}"]`;
        // 重新進入分類（面板重新讀取，拿到模擬資料）
        await page.click('#cfg-groups button[data-group=community]');
        await page.waitForSelector(card('friend.example.com'), { timeout: 10000 }).catch(() => {});
        check(await page.locator('#community-peers .cm-peer').count() === 6, '好友與請求：每個對象一張卡片', String(await page.locator('#community-peers .cm-peer').count()));
        const fr = await page.textContent(card('friend.example.com')).catch(() => '');
        check(/好友/.test(fr) && /AS4780 · TPE/.test(fr) && /25 ms（抖動 3、掉包 1%）/.test(fr) && /DoQ/.test(fr) && /透過邀請碼/.test(fr) && /95%（38\/40）/.test(fr)
            && /120 \/ 違規 2/.test(fr) && /節點池 90%/.test(fr) && /網站驗證 95%/.test(fr), '好友：狀態、業者 · 機房、連線品質、管道、邀請碼加入、命中率、提供筆數、資料品質', fr);
        check(/待我審核/.test(await page.textContent(card('in.example.net'))) && /AS3462 · TPE/.test(await page.textContent(card('in.example.net'))), '待我審核的請求');
        check(/等待對方同意/.test(await page.textContent(card('out.example.org'))) && /已封鎖/.test(await page.textContent(card('blocked.example.net'))), '等待對方同意、已封鎖');
        const kc = await page.textContent(card('keys.example.org'));
        check(/連線逾時/.test(kc) && /沒有用舊金鑰簽名/.test(kc) && /指定 HTTPS/.test(kc), '最後錯誤、待確認的新金鑰、指定的管道', kc);
        check(/成為好友.*透過邀請碼加入/.test(await page.textContent('#community-events')), '事件紀錄');
        await shot('06g-community-peers');
        await page.emulateMedia({ colorScheme: 'dark' });
        await shot('06g-dark-community-peers');
        await page.setViewportSize({ width: 390, height: 800 });
        await page.waitForTimeout(300);
        const pw = await page.evaluate(() => document.documentElement.scrollWidth);
        check(pw <= 391, '390 px 寬沒有水平捲動：設定 → 社群（好友與請求）', `scrollWidth = ${pw}`);
        await page.locator('#community-peers').screenshot({ path: path.join(SHOTS, '06g-mobile-dark-community-peers.png') });
        await page.emulateMedia({ colorScheme: 'light' });
        await page.locator('#community-peers').screenshot({ path: path.join(SHOTS, '06g-mobile-community-peers.png') });
        await page.setViewportSize({ width: 1280, height: 900 });

        const lastPost = () => posted[posted.length - 1] || {};
        // 等到送出指定的動作（清單會在每個動作後重新讀取、重畫：CI 機器慢時不能只看「最後一筆」）
        const waitPost = async (name, ms = 8000) => {
            const end = Date.now() + ms;
            while (Date.now() < end) { if (lastPost().name === name) return lastPost(); await page.waitForTimeout(100); }
            return lastPost();
        };
        await page.click(`${card('in.example.net')} button:has-text("同意")`);
        await page.waitForFunction(s => !/待我審核/.test(document.querySelector(s).textContent), card('in.example.net'), { timeout: 5000 }).catch(() => {});
        check(lastPost().name === 'accept' && lastPost().domain === 'in.example.net' && lastPost().method === 'POST' && !/待我審核/.test(await page.textContent(card('in.example.net'))),
            '同意請求：POST /api/community/accept?domain=…，清單重新讀取', JSON.stringify(lastPost()));
        await page.click(`${card('in2.example.net')} button:has-text("拒絕")`);
        await page.waitForFunction(s => /已拒絕/.test(document.querySelector(s).textContent), card('in2.example.net'), { timeout: 5000 }).catch(() => {});
        check(lastPost().name === 'reject' && /已拒絕（.* 前不能再請求）/.test(await page.textContent(card('in2.example.net'))), '拒絕請求：顯示幾天內不能再請求', JSON.stringify(lastPost()));
        await page.click(`${card('friend.example.com')} button:has-text("立即同步")`);
        await page.waitForFunction(() => /已同步/.test(document.getElementById('toast').textContent), null, { timeout: 5000 }).catch(() => {});
        check(lastPost().name === 'sync' && lastPost().domain === 'friend.example.com' && /已同步/.test(await page.textContent('#toast')), '立即同步', JSON.stringify(lastPost()));
        // 「立即同步」之後清單會重新讀取並重畫：等重畫完再選，選到的才是新的選單；還是被重畫蓋掉就再選一次
        await page.waitForLoadState('networkidle').catch(() => {});
        for (let i = 0; i < 3 && lastPost().name !== 'channel'; i++) {
            await page.selectOption(`${card('friend.example.com')} select.cm-channel`, 'dot').catch(() => {});
            await waitPost('channel', 3000);
        }
        await page.waitForFunction(() => /已指定管道/.test(document.getElementById('toast').textContent), null, { timeout: 5000 }).catch(() => {});
        check(lastPost().name === 'channel' && lastPost().channel === 'dot', '指定管道（DoT 優先）', JSON.stringify(lastPost()));
        await page.waitForLoadState('networkidle').catch(() => {});
        page.once('dialog', dl => dl.dismiss());
        await page.click(`${card('friend.example.com')} button:has-text("刪除並封鎖")`);
        await page.waitForTimeout(300);
        check(lastPost().name === 'channel' && await page.locator(card('friend.example.com')).count() === 1, '刪除：按取消就不送出');
        page.once('dialog', dl => dl.accept());
        await page.click(`${card('friend.example.com')} button:has-text("刪除並封鎖")`);
        await page.waitForFunction(s => !document.querySelector(s), card('friend.example.com'), { timeout: 5000 }).catch(() => {});
        check(lastPost().name === 'delete' && lastPost().block === '1' && await page.locator(card('friend.example.com')).count() === 0, '刪除並封鎖：確認後送出 block=1，清單少一筆', JSON.stringify(lastPost()));
        page.once('dialog', dl => dl.accept());
        await page.click(`${card('keys.example.org')} button:text-is("刪除")`);
        await page.waitForFunction(s => !document.querySelector(s), card('keys.example.org'), { timeout: 5000 }).catch(() => {});
        check(lastPost().name === 'delete' && lastPost().domain === 'keys.example.org' && !lastPost().block, '刪除好友', JSON.stringify(lastPost()));
        await page.click(`${card('blocked.example.net')} button:has-text("解除封鎖")`);
        await page.waitForFunction(s => !/已封鎖/.test(document.querySelector(s).textContent), card('blocked.example.net'), { timeout: 5000 }).catch(() => {});
        check(lastPost().name === 'unblock' && await page.locator(`${card('blocked.example.net')} button:has-text("加好友")`).count() === 1, '解除封鎖後可以再加好友', JSON.stringify(lastPost()));
        await page.fill('#community-add-input', 'new.example.com');
        await page.press('#community-add-input', 'Enter');
        await page.waitForSelector(card('new.example.com'), { timeout: 5000 }).catch(() => {});
        check(lastPost().name === 'add' && lastPost().domain === 'new.example.com' && /已送出好友請求/.test(await page.textContent('#community-add-result'))
            && /等待對方同意/.test(await page.textContent(card('new.example.com')).catch(() => '')) && await page.inputValue('#community-add-input') === '',
            '新增好友（網域）：送出後清單出現「等待對方同意」', JSON.stringify(lastPost()));
        check(posted.every(x => x.method === 'POST'), '所有動作都用 POST');
        await page.unroute('**/api/community/**');

        // 自動規則：存在 community.rules，跟其他設定一起儲存
        await page.click('#community-rule-add');
        await page.fill('.cm-rule[data-index="0"] .cm-rule-name', '中華電信');
        await page.fill('#cm-r0-asn', '3462, 4780');
        await page.fill('#cm-r0-colo', 'tpe');
        await page.fill('#cm-r0-max_rtt_ms', '30');
        await page.fill('#cm-r0-min_mutual', 'abc');
        check(/格式不正確/.test(await page.textContent('#save-msg')) && await page.locator('#cm-r0-min_mutual.invalid').count() === 1, '自動規則：格式錯誤時標出來、不能儲存', await page.textContent('#save-msg'));
        await page.fill('#cm-r0-min_mutual', '');
        await page.click('#community-rule-add');
        await page.fill('.cm-rule[data-index="1"] .cm-rule-name', '封鎖測試');
        await page.selectOption('.cm-rule[data-index="1"] select', 'block');
        await page.fill('#cm-r1-domain_suffix', 'bad.example.net');
        await page.click('.cm-rule[data-index="1"] button[aria-label="第 2 條規則往上移"]');
        await page.click('.cm-rule[data-index="1"] summary');
        await shot('06h-community-rules');
        await page.setViewportSize({ width: 390, height: 800 });
        await page.waitForTimeout(300);
        const rw = await page.evaluate(() => document.documentElement.scrollWidth);
        check(rw <= 391, '390 px 寬沒有水平捲動：設定 → 社群（自動規則）', `scrollWidth = ${rw}`);
        await page.locator('#community-rules').screenshot({ path: path.join(SHOTS, '06h-mobile-community-rules.png') });
        await page.setViewportSize({ width: 1280, height: 900 });
        await page.click('#btn-save');
        await page.waitForFunction(() => /已儲存並套用|失敗|沒有在 30 秒/.test(document.getElementById('save-msg').textContent), null, { timeout: 40000 });
        const rules = (JSON.parse(fs.readFileSync(cfgFile, 'utf-8')).community || {}).rules;
        // 設定檔的鍵依字母排序：比對前先排好
        const canon = v => JSON.stringify(v, (k, x) => (x && typeof x === 'object' && !Array.isArray(x) ? Object.keys(x).sort().reduce((o, key) => { o[key] = x[key]; return o; }, {}) : x));
        check(canon(rules) === canon([
            { enabled: true, name: '封鎖測試', action: 'block', domain_suffix: ['bad.example.net'] },
            { enabled: true, name: '中華電信', action: 'accept', asn: [3462, 4780], colo: ['TPE'], max_rtt_ms: 30 }]),
        '自動規則：存進 community.rules（順序、數字、清單、大寫機房代碼）', JSON.stringify(rules));
        await page.click('#cfg-groups button[data-group=community]');
        await page.waitForSelector('.cm-rule[data-index="1"]', { timeout: 10000 }).catch(() => {});
        check(await page.inputValue('#cm-r1-asn').catch(() => '') === '3462, 4780', '自動規則：儲存後重新讀取顯示一樣的內容');
        await page.click('.cm-rule[data-index="0"] button:text-is("刪除")');
        await page.click('.cm-rule[data-index="0"] button:text-is("刪除")');
        check(/沒有規則/.test(await page.textContent('#community-rules')), '自動規則：刪除全部');
        // 關回來（後面的測試不需要社群）
        await page.uncheck(`${field('community.enabled')} input[type=checkbox]`);
        await page.click('#btn-save');
        await page.waitForFunction(() => /已儲存並套用|失敗|沒有在 30 秒/.test(document.getElementById('save-msg').textContent), null, { timeout: 40000 });

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
        check(await page.locator('#tool-jobs button[data-job]').count() === 5, '排程工作列表');
        check(/台灣 IP 清單/.test(await page.textContent('#tool-jobs table')) && /每月 1 日起（每台錯開）/.test(await page.textContent('#tool-jobs table')), '排程工作：台灣 IP 清單每月、每台錯開');
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

        console.log('備份與分享');
        await page.waitForSelector('#tool-backup #backup-full');
        check(/完整備份/.test(await page.textContent('#tool-backup')) && /私鑰/.test(await page.textContent('#tool-backup')), '備份卡片說明兩種檔案（完整備份含私鑰）');
        const download = async sel => {
            const [d] = await Promise.all([page.waitForEvent('download', { timeout: 20000 }), page.click(sel)]);
            const p = path.join(dir, d.suggestedFilename());
            await d.saveAs(p);
            return p;
        };
        const fullFile = await download('#backup-full');
        check(/^kuroshio-full-\d{8}\.kuroshio$/.test(path.basename(fullFile)) && fs.statSync(fullFile).size > 0, '下載完整備份（非空的 .kuroshio 檔）', path.basename(fullFile));
        const shareFile = await download('#backup-share');
        check(/^kuroshio-share-\d{8}\.kuroshio$/.test(path.basename(shareFile)) && fs.statSync(shareFile).size > 0, '下載分享檔（非空的 .kuroshio 檔）', path.basename(shareFile));
        const zlib = require('zlib');
        if (zlib.zstdDecompressSync) {
            const unpack = f => JSON.parse(zlib.zstdDecompressSync(fs.readFileSync(f)).toString('utf-8'));
            const fb = unpack(fullFile), sb = unpack(shareFile);
            check(fb.format === 'kuroshio-backup' && fb.kind === 'full' && fb.files['cdn-domains.json'].json.domains[0].hits === 12, '完整備份內容（含查詢次數）');
            const sd = sb.files['cdn-domains.json'].json.domains[0];
            check(sb.kind === 'share' && sd.name === 'a.example' && !('hits' in sd) && !('policy' in sd) && !('lastSeen' in sd) && !sb.files['blacklist.txt'] && !sb.files['upstreams.json'], '分享檔內容（沒有次數、時間、手動設定，也沒有上游評測與黑名單）', JSON.stringify(sd));
        }
        await page.setInputFiles('#backup-file', shareFile);
        await page.click('#tool-backup button');
        await page.waitForFunction(() => /匯入完成|失敗|沒有在 30 秒|沒有讀到/.test(document.querySelector('#tool-backup .verdict').textContent), null, { timeout: 45000 }).catch(() => {});
        const bv = await page.textContent('#tool-backup .verdict');
        const bo = await page.textContent('#tool-backup pre');
        check(/匯入完成/.test(bv) && /CDN 網域驗證紀錄/.test(bo) && !/汙染 DNS 黑名單/.test(bo), '匯入分享檔 → 服務重新啟動 → 顯示合併結果', bv + '\n     ' + bo);
        check(/匯入分享檔完成/.test(out), '伺服器記錄匯入結果');
        await shot('07b-backup');

        console.log('關於');
        await page.goto(`${BASE}/#about`);
        await page.waitForFunction(() => /GPL/.test(document.getElementById('about-kv').textContent));
        const ak = await page.textContent('#tab-about');
        check(ak.includes(about.version) && /設定頁版本/.test(ak) && /3\.0\.1/.test(ak), '關於：核心版本與設定頁版本');
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

        console.log('儀表板（共用 dashboard.js、管理 API 的完整資料）');
        {
            const dj = await raw(adminPort, 'GET', '/dashboard/dashboard.js');
            check(dj.status === 200 && /javascript/.test(dj.headers['content-type']), '靜態檔 dashboard/dashboard.js');
            check(!/innerHTML|insertAdjacentHTML|document\.write|outerHTML|setAttribute\('style'/.test(dj.body), 'dashboard.js 不用 innerHTML、不寫 style 屬性（嚴格 CSP）');
            check((await raw(adminPort, 'GET', '/dashboard/dashboard.css')).status === 200, '靜態檔 dashboard/dashboard.css');
            check((await raw(adminPort, 'GET', '/api/dashboard')).status === 401, '沒登入時 /api/dashboard 回 401');
            // 不略過 CSP 的另一個瀏覽器分頁（帶同一個登入 cookie）：CSP 擋下任何東西都會在主控台留下錯誤
            const strict = await browser.newContext({ viewport: { width: 1280, height: 900 }, locale: 'zh-TW' });
            await strict.addCookies(await ctx.cookies());
            const sp = await strict.newPage();
            const csp = [];
            sp.on('pageerror', e => csp.push(e.message));
            // CDN 沒開時節點池等 API 回 404（畫面上說明「沒有啟用」），不算錯誤
            sp.on('console', m => { if ((m.type() === 'error' && !/Failed to load resource/.test(m.text())) || /Content Security Policy|Refused to/.test(m.text())) csp.push(m.text()); });
            await sp.goto(`${BASE}/#dashboard`);
            await sp.waitForSelector('#dash-root .tiles .tile');
            await sp.waitForSelector('#dash-root #kd-live .rank-row');
            await sp.waitForTimeout(1500);
            const dt = await sp.textContent('#dash-root');
            check(/DNS 查詢/.test(dt) && /拉回台灣/.test(dt) && /已驗證可加速網站/.test(dt), '儀表板：總覽', dt.slice(0, 200));
            check(await sp.locator('#kd-overview .chart svg').count() === 1 && await sp.locator('#kd-live .chart svg').count() === 1, '儀表板：最近 60 分鐘、近 30 天的圖');
            const live = await sp.textContent('#kd-live');
            check(/youtube\.com/.test(live) && /doubleclick\.net/.test(live) && /Cloudflare/.test(live), '儀表板：熱門網站、被擋網域、CDN 排行（範例資料）', live.slice(0, 300));
            // 範例資料裡只有 1 位使用者造訪的網站：公開頁預設也列（minClients = 1），管理介面一定列
            check(/cloudflare\.com/.test(live), '儀表板：排行不受 site.minClients 限制');
            check(/快取直接回應/.test(live) && /\d+\.\d%/.test(live), '儀表板：查詢去向');
            const routing = await sp.textContent('#kd-routing');
            check(/Cloudflare/.test(routing) && /CloudFront/.test(routing) && await sp.locator('#kd-routing .gauge').count() >= 3, '儀表板：機會成本（表格與環形儀表）', routing.slice(0, 200));
            check(await sp.locator('#kd-map svg').count() >= 1, '儀表板：路由地圖');
            // 每張折線圖的 y 軸刻度（text-anchor = end 的 axis 標籤）不能重複；剛啟動的服務流量幾乎為 0，涵蓋最大值 0～1 的情況
            const dupAxes = await sp.evaluate(() => [...document.querySelectorAll('#tab-dashboard .chart svg')].map((s, i) => {
                const ends = [...s.querySelectorAll('text.axis[text-anchor="end"]')];
                // y 軸刻度在左側同一個 x（L - 8）；最後一個 x 軸標籤也是靠右對齊，但在圖的右邊，排除掉
                const lx = Math.min(...ends.map(t => +t.getAttribute('x')));
                const labels = ends.filter(t => +t.getAttribute('x') === lx).map(t => t.textContent);
                const dup = labels.filter((v, j) => labels.indexOf(v) !== j);
                return dup.length ? `第 ${i + 1} 張圖（${s.getAttribute('aria-label') || s.closest('[id]')?.id || ''}）：${labels.join(', ')}` : '';
            }).filter(Boolean));
            check(dupAxes.length === 0, '儀表板：折線圖的 y 軸刻度沒有重複', dupAxes.join(' / '));
            check((await sp.textContent('#kd-upstreams')).includes('udp://127.0.0.1:9'), '儀表板：上游（完整網址）');
            check(/沒有啟用/.test(await sp.textContent('#kd-pools')), '儀表板：CDN 沒開時說明「沒有啟用」');
            const jobs = JSON.parse((await raw(adminPort, 'GET', '/api/jobs', { Authorization: `Bearer ${token}` })).body || 'null');
            const jobNames = Object.keys((jobs && jobs.config) || {});
            const jt = await sp.textContent('#kd-jobs');
            check(jobNames.every(n => jt.includes(n)), '儀表板：排程工作', `${jobNames} / ${jt.slice(0, 200)}`);
            await sp.fill('#kd-filter input', 'ads.example.com');
            await sp.click('#kd-filter button');
            await sp.waitForSelector('#kd-filter pre:not(:empty)');
            check(/不會被擋|過濾|失敗/.test(await sp.textContent('#kd-filter pre')), '儀表板：規則檢查有結果');
            await sp.click('#dash-root .kd-seg button[data-range="7d"]');
            await sp.waitForTimeout(800);
            check(/近 7 天共/.test(await sp.textContent('#kd-live')), '儀表板：切換 7 天');
            await sp.screenshot({ path: path.join(SHOTS, '13-dashboard.png'), fullPage: true });
            await sp.setViewportSize({ width: 390, height: 844 });
            await sp.waitForTimeout(800);
            const dw = await sp.evaluate(() => document.documentElement.scrollWidth);
            check(dw <= 391, '儀表板：390 px 寬沒有水平捲動（寬表格在框裡捲動）', `scrollWidth = ${dw}`);
            await sp.screenshot({ path: path.join(SHOTS, '14-dashboard-mobile.png'), fullPage: true });
            await sp.emulateMedia({ colorScheme: 'dark' });
            await sp.setViewportSize({ width: 1280, height: 900 });
            await sp.waitForTimeout(500);
            const cardBg = await sp.evaluate(() => getComputedStyle(document.querySelector('#dash-root .tile')).backgroundColor);
            const crgb = (cardBg.match(/\d+/g) || []).slice(0, 3).map(Number);
            check(crgb.length === 3 && crgb[0] + crgb[1] + crgb[2] < 150, '儀表板：深色模式', cardBg);
            await sp.screenshot({ path: path.join(SHOTS, '15-dashboard-dark.png'), fullPage: true });
            await sp.setViewportSize({ width: 390, height: 844 });
            await sp.waitForTimeout(500);
            await sp.screenshot({ path: path.join(SHOTS, '16-dashboard-dark-mobile.png'), fullPage: true });
            check(csp.length === 0, '儀表板：沒有 JavaScript 錯誤、沒有違反 CSP', csp.join('\n     '));
            await strict.close();
            // 切到別的分頁：自動更新暫停（不再呼叫 API）
            await page.goto(`${BASE}/#dashboard`);
            await page.waitForSelector('#dash-root .tiles .tile');
            const calls = [];
            page.on('request', r => { if (/\/api\/dashboard/.test(r.url())) calls.push(r.url()); });
            await page.goto(`${BASE}/#log`);
            await page.waitForTimeout(16000);
            check(calls.length === 0, '離開儀表板分頁後不再自動更新', calls.join(' '));
        }

        console.log('手機寬度、深色模式');
        await page.setViewportSize({ width: 360, height: 740 });
        for (const t of ['status', 'dashboard', 'settings', 'tools', 'log', 'about']) {
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
