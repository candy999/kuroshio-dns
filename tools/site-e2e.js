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
const { checkFlow, checkFlowEmpty, checkOtherParts, checkDataTables } = require('./flow-check.js');

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
        // 3.5.1：對外開放時 site.minClients 的 auto 是 2；這裡測資料只有一台裝置，明確填 1 才看得到排行
        site: { enabled: true, hostname: HOST, minClients: 1 },
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

        // 3.5.1：連線去向圖的數字要跟公開 API 一致（公開頁只有彙總數字）
        const pub = JSON.parse((await fetchSite(port, '/api/public/stats?range=today')).body);
        check(Array.isArray(pub.routing) && pub.routing.length === 7 && pub.routing.every(r => r.alreadyTw + r.accelerated + r.stillAbroad === r.connections),
            '/api/public/stats 的 routing：7 家 CDN，三塊加起來等於連線數', JSON.stringify(pub.routing).slice(0, 300));
        check(pub.cdnOther && pub.cdnOther.providers === 2 && pub.crossCdn.pairsOther && pub.crossCdn.pairsOther.pairs === 2 && pub.flowsOther,
            '/api/public/stats：前幾名以外合併的 cdnOther、pairsOther、flowsOther', JSON.stringify([pub.cdnOther, pub.crossCdn.pairsOther, pub.flowsOther]));
        check(typeof pub.opportunity.savedSamples === 'number' && typeof pub.acceleration.samples === 'number', '/api/public/stats：估計值帶樣本數');
        const pubText = JSON.stringify({ routing: pub.routing, cdnOther: pub.cdnOther, opportunity: pub.opportunity });
        check(!/\.(com|net|tw|me|cc)\b|192\.0\.2|127\.0\.0/.test(pubText), '連線去向用到的公開資料只有彙總數字（沒有網域、IP）', pubText.slice(0, 200));
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
            // 3.5.1：連線去向（桌機流向圖、手機堆疊橫條）；其他圖的「其他」與「沒辨識出來」分開、估計值標樣本數
            const fr = JSON.parse((await fetchSite(port, '/api/public/stats?range=today')).body);
            for (const c of await checkFlow(page, '#flow', '#flowTable', fr.routing, w, `公開頁 ${tag}`)) check(...c);
            if (scheme === 'light' && w === 1280) for (const c of [...await checkFlowEmpty(page, '公開頁'), ...await checkOtherParts(page, '公開頁')]) check(...c);
            check(await page.locator('#gauges .gauge').count() === 6 && await page.locator('#gauges .gauge.other').count() === 1, '環形儀表：前 5 家＋「其他」一張');
            check(/其他 2 家/.test(await page.textContent('#cdnRank .rank-row.other')), 'CDN 排行：前 8 家以外合併成「其他 2 家」、排在最後');
            // 跨 CDN 卡片要等資料庫裡有測過的網站才畫（種子資料的跨 CDN 紀錄在啟動整理時清掉了）：沒有時只看說明
            if (fr.crossCdn.explored) check(await page.locator('#cross .pair.unknown').count() === 1 && /其他 2 組/.test(await page.textContent('#cross .pair.other')), '跨 CDN：改走的 CDN 沒記到的標「未辨識」，跟「其他 2 組」分開');
            else check(/資料累積中/.test(await page.textContent('#cross')), '跨 CDN：還沒有測過的網站時顯示說明');
            const oppSub = await page.textContent('#oppSub');
            check(/次量測/.test(await page.textContent('#o-ms-l')) && /個網站/.test(oppSub) || !fr.acceleration.samples, '平均縮短、網站中位數旁邊標樣本數', await page.textContent('#o-ms-l'));
            // 3.5.1：網站中位數可以是負的（台灣比較慢的網站也算）：負的寫「反而慢」、不寫「省」
            const fm = fr.acceleration.medianSavedMs;
            check(typeof fm !== 'number' || !fr.acceleration.samples || (fm < 0 ? /反而慢/.test(oppSub) && !/中位數省/.test(oppSub) : fm > 0 ? /台灣節點快/.test(oppSub) : /兩邊一樣/.test(oppSub)), '網站中位數的說明跟正負一致', `${fm} / ${oppSub}`);
            check(/\d+ 次/.test(await page.textContent('#stackLegend')), '查詢去向的比例旁邊附次數');
            await page.locator('.card:has(> #flow)').screenshot({ path: path.join(SHOTS, `flow-site-${scheme}-${w}.png`) });
            const sites = await page.locator('#siteRank').textContent();
            check(/youtube\.com/.test(sites) && /大家最常造訪的網站/.test(await page.textContent('#sitesCap')), '熱門網站（site.minClients = 1）', sites.slice(0, 120));
            const sw = await page.evaluate(() => document.documentElement.scrollWidth);
            check(sw <= w + 1, '沒有水平捲動', `scrollWidth = ${sw}`);
            // 3.5.1：展開所有數據表之後也沒有水平捲動、最後一欄捲得到（以前手機上最後一欄被切掉、滑不過去）
            for (const c of await checkDataTables(page, w, `公開頁 ${tag}`)) check(...c);
            const dupAxes = await page.evaluate(() => [...document.querySelectorAll('.chart svg')].map((s, i) => {
                const ends = [...s.querySelectorAll('text.axis[text-anchor="end"]')];
                // y 軸刻度在左側同一個 x（L - 8）；最後一個 x 軸標籤也是靠右對齊，但在圖的右邊，排除掉
                const lx = Math.min(...ends.map(t => +t.getAttribute('x')));
                const labels = ends.filter(t => +t.getAttribute('x') === lx).map(t => t.textContent);
                return labels.some((v, j) => labels.indexOf(v) !== j) ? `第 ${i + 1} 張圖：${labels.join(', ')}` : '';
            }).filter(Boolean));
            check(dupAxes.length === 0, `公開頁（${scheme} ${w} px）：折線圖的 y 軸刻度沒有重複`, dupAxes.join(' / '));
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
            for (const c of await checkDataTables(page, w, `詳細頁 ${tag}`)) check(...c);
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
