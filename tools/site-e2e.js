'use strict';
// 公開頁與詳細頁的端對端測試：自己啟動 kuroshio（DoH 用 TLS、開在 443 以外的埠，公開頁跟 DoH 同一個埠），
// 用 Playwright 打開 https://dns.example:<埠>/（瀏覽器把 dns.example 指到 127.0.0.1，自簽憑證），檢查：
// 網址、QR 碼、描述檔都帶埠號，Android 私人 DNS 的說明，共用儀表板畫出圖表與表格，淺色 / 深色、1280 / 390 px。
//
//   cargo build -p kuroshio && node tools/site-e2e.js
//   KUROSHIO_BIN=path/to/kuroshio SHOTS=screenshots-site node tools/site-e2e.js
const { chromium } = require('playwright');
const { spawn, execFileSync } = require('child_process');
const fs = require('fs');
const https = require('https');
const net = require('net');
const os = require('os');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const BIN = process.env.KUROSHIO_BIN ? path.resolve(process.env.KUROSHIO_BIN) : path.join(ROOT, 'target', 'debug', process.platform === 'win32' ? 'kuroshio.exe' : 'kuroshio');
const SHOTS = path.resolve(process.env.SHOTS || 'screenshots-site');
const HOST = 'dns.example';

let pass = 0, fail = 0;
const ok = m => { pass++; console.log(`  ✔ ${m}`); };
const bad = m => { fail++; console.log(`  ✘ ${m}`); };
const check = (cond, m, detail) => (cond ? ok(m) : bad(detail ? `${m}\n     ${detail}` : m));
const sleep = ms => new Promise(r => setTimeout(r, ms));
const freePort = () => new Promise((resolve, reject) => {
    const s = net.createServer();
    s.unref();
    s.on('error', reject);
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
});

/** 直接對 127.0.0.1 送 HTTPS 請求（SNI 與 Host 用 dns.example:埠，跟瀏覽器一樣），回 { status, headers, body } */
const fetchSite = (port, p) => new Promise((resolve, reject) => {
    const req = https.get({ host: '127.0.0.1', port, path: p, servername: HOST, headers: { Host: `${HOST}:${port}` }, rejectUnauthorized: false }, res => {
        let data = '';
        res.setEncoding('utf8');
        res.on('data', c => { data += c; });
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on('error', reject);
    req.setTimeout(5000, () => req.destroy(new Error('逾時')));
});

(async () => {
    fs.mkdirSync(SHOTS, { recursive: true });
    if (!fs.existsSync(BIN)) {
        console.error(`找不到執行檔 ${BIN}（先 cargo build -p kuroshio，或用 KUROSHIO_BIN 指定）`);
        process.exit(2);
    }
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kuroshio-site-'));
    // 自簽憑證（只給這次測試用）
    execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-days', '2',
        '-keyout', path.join(dir, 'key.pem'), '-out', path.join(dir, 'cert.pem'), '-subj', `/CN=${HOST}`, '-addext', `subjectAltName=DNS:${HOST}`], { stdio: 'ignore' });
    const [port, dnsPort, adminPort] = [await freePort(), await freePort(), await freePort()];
    const cfgFile = path.join(dir, 'config.json');
    fs.writeFileSync(cfgFile, JSON.stringify({
        listen: {
            plain: { binds: ['127.0.0.1'], port: dnsPort },
            // DoH 不在 443（例如 443 被占用改用 8443）：公開頁跟 DoH 同一個埠
            doh: { enabled: true, host: '127.0.0.1', port, tls: true, cert: path.join(dir, 'cert.pem'), key: path.join(dir, 'key.pem') }
        },
        site: { enabled: true, hostname: HOST },
        admin: { port: adminPort, auth: false },
        filter: { enabled: false },
        upstream: { pinned: ['udp://127.0.0.1:9'] },
        access: { dataFile: path.join(ROOT, 'data', 'geo', 'tw-ip.json') },
        system: { persistDir: path.join(dir, 'state'), dataDir: path.join(ROOT, 'data') }
    }, null, 2));
    fs.mkdirSync(path.join(dir, 'state'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'state', 'stats.json'), JSON.stringify(require('./dashboard-seed.js').stats()));

    let out = '';
    const child = spawn(BIN, ['run', '-c', cfgFile], { cwd: dir, stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, NO_COLOR: '1' } });
    child.stdout.on('data', d => { out += d; });
    child.stderr.on('data', d => { out += d; });
    let exited = null;
    child.on('exit', c => { exited = c; });

    const BASE = `https://${HOST}:${port}`;
    let browser;
    try {
        // dns.example 只存在這台機器上：環境有 HTTPS 代理時讓這個名稱直接連（不經過代理）
        const proxy = process.env.HTTPS_PROXY || process.env.https_proxy;
        browser = await chromium.launch({ args: [`--host-resolver-rules=MAP ${HOST} 127.0.0.1`], ...(proxy ? { proxy: { server: proxy, bypass: HOST } } : {}) });
        const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 }, deviceScaleFactor: 1, ignoreHTTPSErrors: true, locale: 'zh-TW' });
        // 等 DoH（公開頁）起來
        let up = false;
        for (let i = 0; i < 100 && exited === null; i++) {
            try { if ((await fetchSite(port, '/robots.txt')).status === 200) { up = true; break; } } catch (e) { /* 還沒好 */ }
            await sleep(200);
        }
        if (!up) throw new Error(`kuroshio 沒有啟動（結束碼 ${exited}）`);
        console.log(`kuroshio ${BIN}\n公開頁 ${BASE}/`);

        console.log('連線資訊與描述檔（DoH 在 ' + port + ' 埠）');
        const info = JSON.parse((await fetchSite(port, '/api/public/info')).body);
        check(info.doh === `${BASE}/dns-query` && info.dohPort === port && info.site === `${BASE}/`, '/api/public/info 的 DoH 網址帶埠號', JSON.stringify(info).slice(0, 200));
        const mc = (await fetchSite(port, '/apple/doh.mobileconfig')).body;
        check(mc.includes(`<key>ServerURL</key><string>${BASE}/dns-query</string>`), 'iPhone 描述檔的 ServerURL 帶埠號');
        const dj = await fetchSite(port, '/assets/dashboard.js');
        check(dj.status === 200 && /javascript/.test(dj.headers['content-type']), '共用儀表板 /assets/dashboard.js');

        const errors = [];
        for (const [scheme, w] of [['light', 1280], ['dark', 1280], ['light', 390], ['dark', 390]]) {
            const tag = `${scheme === 'dark' ? '深色' : '淺色'} ${w} px`;
            const page = await ctx.newPage();
            page.on('pageerror', e => errors.push(`${tag}：${e.message}`));
            page.on('console', m => { if (m.type() === 'error' && !/favicon/.test(m.text())) errors.push(`${tag}：${m.text()}`); });
            await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' });
            await page.setViewportSize({ width: w, height: w === 390 ? 844 : 900 });

            console.log(`公開頁（${tag}）`);
            await page.goto(`${BASE}/`);
            await page.waitForSelector('#siteRank .rank-row', { timeout: 20000 });
            await page.waitForTimeout(1500);
            const doh = await page.getAttribute('#doh', 'data-v');
            check(doh === `${BASE}/dns-query` && (await page.textContent('#doh')).includes(`${HOST}:${port}/dns-query`), '首頁的 DoH 網址帶埠號', doh);
            check((await page.textContent('#dohUrl')) === `${BASE}/dns-query` && (await page.textContent('#siteUrl')) === `${BASE}/`, '分享區的網址帶埠號');
            const win = await page.locator('[data-panel=windows]').textContent();
            check(win.includes(`${BASE}/dns-query`), 'Windows 11 的 DoH 範本帶埠號');
            const android = await page.locator('[data-panel=android]').textContent();
            check(/只支援 DoT/.test(android) && /853/.test(android) && !android.includes(`:${port}`), 'Android 私人 DNS：說明只支援 DoT 853、不提供帶埠號的網址');
            check(await page.locator('[data-panel=android] .dot-off').evaluate(n => !n.hidden), 'DoT 沒開：說明 Android 私人 DNS 不能用');
            check(await page.locator('#rt svg').count() === 1 && await page.locator('#trend svg').count() === 1 && await page.locator('#map svg').count() >= 1, '圖表：最近 60 分鐘、近 30 天、路由地圖');
            check(await page.locator('#gauges .gauge').count() >= 3 && await page.locator('#cdnRank .rank-row').count() >= 3, '圖表：各 CDN 環形儀表、CDN 排行');
            const sites = await page.locator('#siteRank').textContent();
            check(/youtube\.com/.test(sites) && /大家最常造訪的網站/.test(await page.textContent('#sitesCap')), '熱門網站（預設 site.minClients = 1）', sites.slice(0, 120));
            const sw = await page.evaluate(() => document.documentElement.scrollWidth);
            check(sw <= w + 1, '沒有水平捲動', `scrollWidth = ${sw}`);
            await page.screenshot({ path: path.join(SHOTS, `index-${scheme}-${w}.png`), fullPage: true });

            console.log(`詳細頁（${tag}）`);
            await page.goto(`${BASE}/detail/`);
            await page.waitForSelector('#overview .tiles .tile', { timeout: 20000 });
            await page.waitForSelector('#domains table tr:nth-child(3)', { timeout: 20000 });
            await page.waitForTimeout(1000);
            const dt = await page.locator('main').textContent();
            check(/DNS 查詢/.test(dt) && /上游/.test(dt) && /udp:\/\/127\.0\.0\.1:9|127\.0\.0\.1/.test(dt), '詳細頁：總覽、上游');
            check(await page.locator('#pools .card').count() >= 1 && await page.locator('#domains table tr').count() > 2, '詳細頁：節點池、CDN 網域資料庫（種子資料）');
            check(/過濾規則/.test(dt) && /排程工作/.test(dt) && /追蹤網域/.test(dt), '詳細頁：過濾、工作、追蹤');
            await page.click('.seg button[data-range="7d"]');
            await page.waitForTimeout(800);
            check(await page.getAttribute('.seg button[data-range="7d"]', 'aria-pressed') === 'true', '詳細頁：切換 7 天');
            const dsw = await page.evaluate(() => document.documentElement.scrollWidth);
            check(dsw <= w + 1, '詳細頁：沒有水平捲動（寬表格在框裡捲動）', `scrollWidth = ${dsw}`);
            await page.screenshot({ path: path.join(SHOTS, `detail-${scheme}-${w}.png`), fullPage: true });
            await page.close();
        }
        check(errors.length === 0, '沒有 JavaScript 錯誤', errors.join('\n     '));
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
