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
const PAGES = ['status', 'settings', 'filter', 'cdn', 'community', 'advanced', 'log'].concat(NAME === 'kuroshio' ? ['access', 'dashboard'] : []);
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

    /**
     * 社群頁（MOCK）：我的身分、每一種好友狀態、資料品質 / 管道 / 違規、每個動作送出的 rpcd 呼叫（路徑與參數）、確認視窗。
     * mock 的 /__mock/calls 記下所有 kuroshio action 呼叫
     */
    const communityMock = async () => {
        const callsSince = async n => JSON.parse(await mockGet('/__mock/calls?since=' + n));
        const card = d => page.locator(`.kuroshio-peer[data-domain="${d}"]`);
        const cardText = async d => (await card(d).innerText().catch(() => '')).replace(/\s+/g, ' ');
        /** 執行 fn，等到 mock 收到一個 action 呼叫，檢查路徑與參數 */
        const expectCall = async (label, fn, path, query) => {
            const n = (await callsSince(0)).length;
            try {
                await fn();
                let got = [];
                for (let i = 0; i < 50 && !got.length; i++) { await page.waitForTimeout(100); got = await callsSince(n); }
                const c = got[0];
                c && got.length === 1 && c.path === path && c.query === query ? ok(`社群頁：${label} → ${path}${query ? '?' + query : ''}`)
                    : bad(`社群頁：${label} 應該送出 ${path}?${query}，實際 ${JSON.stringify(got)}`);
            } catch (e) { bad(`社群頁：${label} 操作中斷：${e.message.split('\n')[0]}`); }
            await page.waitForTimeout(300);   // 等重新讀取完成
        };
        const button = (d, name) => card(d).getByRole('button', { name, exact: true });
        const confirm = () => page.click('#kuroshio-confirm');

        await page.waitForSelector('.kuroshio-peer', { timeout: 10000 }).catch(() => {});
        // 我的身分
        const st = (await page.locator('#kuroshio-community-status').innerText().catch(() => '')).replace(/\s+/g, ' ');
        /未就緒/.test(st) && /198\.51\.100\.7/.test((await page.locator('#kuroshio-community-problems').innerText().catch(() => ''))) ? ok('社群頁：未就緒時逐條列出問題') : bad(`社群頁：未就緒的問題沒有列出\n     ${st}`);
        /doq:\/\/dns\.example\.com:853/.test(st) && /好友 2 待我審核 1 等待對方同意 1 已封鎖 1/.test(st) && /自我檢查/.test(st)
            ? ok('社群頁：對外網址含 DoQ、好友數、自我檢查時間') : bad(`社群頁：我的身分內容不對\n     ${st}`);
        /_kuroshio\.dns\.example\.com TXT "v=k1; fp=719718821"/.test(await page.locator('#kuroshio-community-txt').innerText().catch(() => '')) && /第二管道/.test(st)
            ? ok('社群頁：TXT 記錄建議值') : bad('社群頁：沒有 TXT 記錄建議值');

        // 每一種狀態
        const states = { 'req.example.net': '待我審核', 'friend.example.net': '好友', 'wait.example.com': '等待對方同意', 'spam.example.com': '已封鎖',
            'blockedme.example.net': '對方已封鎖你', 'rejected.example.com': '已拒絕（', 'theyrejected.example.org': '對方拒絕（', 'gone.example.net': '已刪除' };
        for (const d of Object.keys(states)) {
            const b = await card(d).locator('.kuroshio-badge').innerText().catch(() => '');
            b.startsWith(states[d]) ? ok(`社群頁：${d} 狀態「${b}」`) : bad(`社群頁：${d} 狀態應該是 ${states[d]}，實際「${b}」`);
        }
        const fr = await cardText('friend.example.net');
        /420 \/ 違規 3/.test(fr) ? ok('社群頁：提供筆數 / 違規（stats.invalid）') : bad(`社群頁：沒有違規筆數\n     ${fr}`);
        /節點池 97%、網站驗證 90%、上游 DNS 50%（暫停）/.test(fr) && !/跨 CDN/.test(fr) ? ok('社群頁：資料品質（各 kind 分數、暫停、沒試過的不列）') : bad(`社群頁：資料品質不對\n     ${fr}`);
        /DoQ（指定 DoT）/.test(fr) && /透過邀請碼/.test(fr) && /90%（45\/50）/.test(fr) && /AS4780 · TPE/.test(fr) ? ok('社群頁：目前管道、指定管道、加入方式、命中率、業者') : bad(`社群頁：好友細節不對\n     ${fr}`);
        (await card('friend.example.net').locator('select.kuroshio-channel').inputValue().catch(() => '')) === 'dot' ? ok('社群頁：指定管道選單顯示目前的指定') : bad('社群頁：指定管道選單不對');
        const ks = await cardText('keyswap.example.org');
        /同步失敗：連線逾時/.test(ks) && /對方版本較舊（v1）/.test(ks) && /NEW0-KEY1-2222/.test(ks) && /成為好友/.test(ks) ? ok('社群頁：最後錯誤、舊版本、待確認的新金鑰') : bad(`社群頁：好友提醒不對\n     ${ks}`);
        /自動封鎖於/.test(await cardText('spam.example.com')) ? ok('社群頁：自動封鎖時間') : bad('社群頁：沒有自動封鎖時間');
        // 每種狀態的按鈕
        const btns = async d => (await card(d).locator('.kuroshio-peer-actions button').allInnerTexts()).join(',');
        const want = { 'req.example.net': '同意,拒絕,封鎖', 'friend.example.net': '立即同步,刪除,刪除並封鎖', 'keyswap.example.org': '立即同步,刪除,刪除並封鎖,接受新金鑰',
            'wait.example.com': '取消', 'spam.example.com': '解除封鎖', 'blockedme.example.net': '加好友', 'gone.example.net': '加好友' };
        for (const d of Object.keys(want)) {
            const b = await btns(d);
            b === want[d] ? ok(`社群頁：${d} 的按鈕 ${b}`) : bad(`社群頁：${d} 的按鈕應該是 ${want[d]}，實際 ${b}`);
        }
        await page.screenshot({ path: `${SHOTS}/simple-community-peers.png`, fullPage: true });

        // 動作與送出的 rpcd 呼叫
        await expectCall('重新檢查', () => page.click('#kuroshio-community-status button:has-text("重新檢查")'), '/api/community/check', '');
        await page.waitForFunction(() => /就緒/.test(document.getElementById('kuroshio-community-status').innerText) && !document.getElementById('kuroshio-community-problems'), null, { timeout: 5000 })
            .then(() => ok('社群頁：重新檢查後重新讀取（變成就緒）'), () => bad('社群頁：重新檢查後沒有重新讀取'));
        // 確認視窗按「取消」不送出
        const n0 = (await callsSince(0)).length;
        await page.click('#kuroshio-community-status button:has-text("更換金鑰")');
        /產生新的身分金鑰並通知所有好友/.test(await page.locator('.modal').innerText().catch(() => '')) ? ok('社群頁：更換金鑰先確認') : bad('社群頁：更換金鑰沒有確認視窗');
        await page.locator('.modal button:has-text("取消")').click();
        await page.waitForTimeout(500);
        (await callsSince(n0)).length === 0 ? ok('社群頁：確認視窗按取消不送出') : bad('社群頁：確認視窗按取消還是送出了');
        await expectCall('更換金鑰（確認）', async () => { await page.click('#kuroshio-community-status button:has-text("更換金鑰")'); await confirm(); }, '/api/community/rotate', '');
        await page.waitForFunction(() => /已換新金鑰，舊金鑰到 .* 前仍有效/.test(document.getElementById('kuroshio-community-status').innerText), null, { timeout: 5000 })
            .then(() => ok('社群頁：金鑰輪替狀態'), () => bad('社群頁：更換金鑰後沒有顯示輪替狀態'));

        await expectCall('拒絕', () => button('req.example.net', '拒絕').click(), '/api/community/reject', 'domain=req.example.net');
        await expectCall('封鎖（確認）', async () => { await button('req.example.net', '封鎖').click(); await confirm(); }, '/api/community/block', 'domain=req.example.net');
        await expectCall('同意', () => button('req.example.net', '同意').click(), '/api/community/accept', 'domain=req.example.net');
        await page.waitForFunction(() => { const c = document.querySelector('.kuroshio-peer[data-domain="req.example.net"]'); return c && c.dataset.rel === 'friend'; }, null, { timeout: 5000 })
            .then(() => ok('社群頁：同意後重新讀取（變成好友）'), () => bad('社群頁：同意後沒有重新讀取'));
        await expectCall('立即同步', () => button('friend.example.net', '立即同步').click(), '/api/community/sync', 'domain=friend.example.net');
        await expectCall('刪除（確認）', async () => { await button('friend.example.net', '刪除').click(); await confirm(); }, '/api/community/delete', 'domain=friend.example.net');
        await expectCall('刪除並封鎖（確認）', async () => { await button('friend.example.net', '刪除並封鎖').click(); await confirm(); }, '/api/community/delete', 'domain=friend.example.net&block=1');
        await expectCall('指定管道 DoQ', () => card('friend.example.net').locator('select.kuroshio-channel').selectOption('doq'), '/api/community/channel', 'domain=friend.example.net&channel=doq');
        await expectCall('指定管道 自動', () => card('friend.example.net').locator('select.kuroshio-channel').selectOption(''), '/api/community/channel', 'domain=friend.example.net&channel=auto');
        await button('keyswap.example.org', '接受新金鑰').click();
        /NEW0-KEY1-2222-3333-4444-5555-6666-7777/.test(await page.locator('.modal').innerText().catch(() => '')) ? ok('社群頁：接受新金鑰的確認視窗顯示新指紋') : bad('社群頁：接受新金鑰的確認視窗沒有新指紋');
        await expectCall('接受新金鑰（確認）', confirm, '/api/community/accept-key', 'domain=keyswap.example.org');
        await expectCall('取消請求', () => button('wait.example.com', '取消').click(), '/api/community/delete', 'domain=wait.example.com');
        await expectCall('解除封鎖', () => button('spam.example.com', '解除封鎖').click(), '/api/community/unblock', 'domain=spam.example.com');
        await expectCall('加好友（已刪除的對象）', () => button('gone.example.net', '加好友').click(), '/api/community/add', 'domain=gone.example.net');
        // 用網域加好友：失敗時顯示原因、輸入框保留；成功後清空
        await page.fill('#kuroshio-community-add-input', 'bad.example.com');
        await expectCall('新增好友（失敗）', () => page.press('#kuroshio-community-add-input', 'Enter'), '/api/community/add', 'domain=bad.example.com');
        await page.waitForFunction(() => /bad\.example\.com 沒有回應/.test(document.body.innerText), null, { timeout: 5000 })
            .then(() => ok('社群頁：新增好友失敗顯示原因'), () => bad('社群頁：新增好友失敗沒有顯示原因'));
        (await page.inputValue('#kuroshio-community-add-input')) === 'bad.example.com' ? ok('社群頁：失敗時輸入框保留') : bad('社群頁：失敗時輸入框被清空');
        await page.fill('#kuroshio-community-add-input', 'new.example.net');
        await expectCall('新增好友', () => page.click('button:has-text("送出請求")'), '/api/community/add', 'domain=new.example.net');
        (await page.inputValue('#kuroshio-community-add-input')) === '' ? ok('社群頁：送出成功後清空輸入框') : bad('社群頁：送出成功後沒有清空輸入框');
        /收到請求（人工審核）/.test(await page.locator('#view').innerText()) ? ok('社群頁：事件紀錄') : bad('社群頁：沒有事件紀錄');
        await page.screenshot({ path: `${SHOTS}/simple-community-actions.png`, fullPage: true });
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
        if (NAME === 'kuroshio' && p === 'community') {
            /好友邀請碼/.test(text) && /我的邀請碼/.test(text) && /貼上好友的邀請碼/.test(text) && /新增好友/.test(text)
                ? ok('社群頁：好友邀請碼與手動新增') : bad(`社群頁沒有邀請碼區塊\n     ${text.slice(0, 300)}`);
            if (MOCK) {
                await page.waitForSelector('#kuroshio-invite-code', { timeout: 10000 }).catch(() => {});
                const c1 = await page.inputValue('#kuroshio-invite-code').catch(() => '');
                /^KRS1\./.test(c1) && /^data:image\/svg\+xml/.test(await page.getAttribute('#kuroshio-invite-qr', 'src').catch(() => '') || '')
                    ? ok('社群頁：我的邀請碼與 QR 碼') : bad(`社群頁：邀請碼沒有出來（${c1}）`);
                await page.click('#kuroshio-invite button:has-text("複製邀請碼")');
                await page.waitForFunction(() => /已複製邀請碼|手動選取/.test(document.body.innerText), null, { timeout: 5000 })
                    .then(() => ok('社群頁：複製邀請碼'), () => bad('社群頁：複製邀請碼沒有反應'));
                await page.click('#kuroshio-invite button:has-text("重新產生")');
                await page.click('#kuroshio-invite-confirm');
                await page.waitForFunction(c => { const e = document.getElementById('kuroshio-invite-code'); return e && e.value !== c; }, c1, { timeout: 10000 })
                    .then(() => ok('社群頁：確認後重新產生邀請碼'), () => bad('社群頁：重新產生後邀請碼沒有換'));
                await page.fill('#kuroshio-invite-input', 'KRS1.TYPO');
                await page.click('#kuroshio-invite button:has-text("加好友")');
                await page.waitForSelector('#kuroshio-invite-result', { timeout: 10000 }).catch(() => {});
                /檢查碼不符/.test(await page.locator('#kuroshio-invite-out').innerText().catch(() => '')) ? ok('社群頁：貼上打錯的邀請碼顯示原因') : bad('社群頁：貼上打錯的邀請碼沒有顯示原因');
                await page.fill('#kuroshio-invite-input', ' KRS1.MOCKGOODAAAA ');
                await page.press('#kuroshio-invite-input', 'Enter');
                await page.waitForFunction(() => /已成為好友/.test((document.getElementById('kuroshio-invite-out') || {}).innerText || ''), null, { timeout: 10000 })
                    .then(() => ok('社群頁：貼上邀請碼逐步顯示結果'), () => bad('社群頁：貼上邀請碼沒有顯示結果'));
                await page.screenshot({ path: `${SHOTS}/simple-community-invite.png`, fullPage: true });
                await communityMock();
                if (errors.length) bad(`社群頁操作後 JavaScript 錯誤\n     ${errors.join('\n     ')}`);
            }
        }
        if (NAME === 'kuroshio' && p === 'access') {
            /只開放台灣（建議）/.test(text) && /全開放/.test(text) && /允許名單/.test(text) && /封鎖名單/.test(text) && /一律允許/.test(text) && /VPN/.test(text) && /優先於一切/.test(text)
                ? ok('連線來源頁：模式、名單與說明') : bad(`連線來源頁內容不對\n     ${text.slice(0, 300)}`);
            if (MOCK) /\d{4}-\d{2}-\d{2} 的資料/.test(text) && /57 次/.test(text) && /45\.135\.232\.0\/24/.test(text) ? ok('連線來源頁：資料日期、拒絕次數、被拒絕最多的網段') : bad('連線來源頁沒有目前狀態');
        }
        if (NAME === 'kuroshio' && p === 'status' && MOCK) {
            /連線來源/.test(text) && /只開放台灣/.test(text) && /已拒絕 57 次/.test(text) ? ok('狀態頁：連線來源摘要') : bad('狀態頁沒有連線來源摘要');
            /最久未存/.test(text) && /1\.5 小時/.test(text) && /上限 24 小時/.test(text) ? ok('狀態頁：最久未存') : bad('狀態頁沒有「最久未存」');
            /記憶體控制/.test(text) && /暫時停用：大廣告 清單（3000 條規則）/.test(text) && /縮小 DNS 快取/.test(text) && /保留 16 MB（自動）/.test(text) && /只轉送 DNS/.test(text) && /快取 64 \/ 64 筆/.test(text) && /儲存空間/.test(text) && !/硬體等級/.test(text) ? ok('狀態頁：記憶體控制（保留量、只轉送、動態大小、儲存空間、沒有硬體等級）') : bad('狀態頁沒有記憶體控制');
        }
    }
    // 黑潮：儀表板（共用 kuroshio/dashboard.js，資料經 rpcd 轉送；淺色 / 深色、1280 / 390 px）
    if (NAME === 'kuroshio') {
        for (const [scheme, w] of [['light', 1280], ['dark', 1280], ['light', 390], ['dark', 390]]) {
            errors = [];
            await page.emulateMedia({ colorScheme: scheme });
            await page.setViewportSize({ width: w, height: w === 390 ? 844 : 900 });
            await page.goto(`${BASE}/cgi-bin/luci/admin/services/${NAME}/dashboard`);
            await page.waitForLoadState('networkidle');
            const ready = await page.waitForSelector('#kuroshio-dashboard .tiles .tile', { timeout: 20000 }).then(() => true, () => false);
            await page.waitForTimeout(1500);
            const text = await page.locator('#view').innerText().catch(() => '');
            const sw = await page.evaluate(() => document.documentElement.scrollWidth);
            await page.screenshot({ path: `${SHOTS}/dashboard-${scheme}-${w}.png`, fullPage: true });
            const tag = `儀表板（${scheme === 'dark' ? '深色' : '淺色'} ${w} px）`;
            if (!ready) { bad(`${tag}：沒有畫出總覽\n     ${text.slice(0, 300)}`); continue; }
            /總覽/.test(text) && /DNS 查詢/.test(text) && /上游 DNS/.test(text) && /台灣節點池/.test(text) && /CDN 網域資料庫/.test(text) && /過濾規則/.test(text) && /排程工作/.test(text)
                ? ok(`${tag}：各區塊都有`) : bad(`${tag}：缺少區塊\n     ${text.slice(0, 300)}`);
            if (MOCK) {
                /youtube\.com/.test(text) && /doubleclick\.net/.test(text) && /Cloudflare/.test(text) && /udp:\/\/1\.1\.1\.1/.test(text) && /www0\.example\.com/.test(text) && /104\.18\.22\.203/.test(text) && /dns-benchmark/.test(text)
                    ? ok(`${tag}：資料來自 rpcd（統計、排行、上游、網域、節點、工作）`) : bad(`${tag}：資料不完整\n     ${text.slice(0, 400)}`);
                (await page.locator('#kuroshio-dashboard .chart svg').count()) >= 2 && (await page.locator('#kuroshio-dashboard .gauge').count()) >= 3
                    ? ok(`${tag}：圖表`) : bad(`${tag}：圖表沒有畫出來`);
            }
            sw <= w + 1 ? ok(`${tag}：沒有水平捲動`) : bad(`${tag}：頁面被撐寬（scrollWidth = ${sw}）`);
            if (scheme === 'dark') {
                const bg = await page.evaluate(() => getComputedStyle(document.querySelector('#kuroshio-dashboard .tile')).backgroundColor);
                const rgb = (bg.match(/\d+/g) || []).slice(0, 3).map(Number);
                rgb.length === 3 && rgb[0] + rgb[1] + rgb[2] < 150 ? ok(`${tag}：深色卡片`) : bad(`${tag}：深色模式沒有套用（${bg}）`);
            }
            if (errors.length) bad(`${tag}：JavaScript 錯誤\n     ${errors.join('\n     ')}`);
        }
        // 網域搜尋（伺服器分頁）與規則檢查
        await page.emulateMedia({ colorScheme: 'light' });
        await page.setViewportSize({ width: 1280, height: 900 });
        await page.goto(`${BASE}/cgi-bin/luci/admin/services/${NAME}/dashboard`);
        await page.waitForSelector('#kuroshio-dashboard #kd-domains table tr', { timeout: 20000 }).catch(() => {});
        if (MOCK) {
            await page.fill('#kd-domains input', 'www1');
            await page.waitForTimeout(1200);
            const dt = await page.locator('#kd-domains table').innerText();
            /www1\.example\.com/.test(dt) && !/www2\.example\.com/.test(dt) ? ok('儀表板：網域搜尋（rpcd 帶 q 參數）') : bad(`儀表板：網域搜尋結果不對\n     ${dt.slice(0, 200)}`);
            await page.fill('#kd-filter input', 'ads.example.com');
            await page.click('#kd-filter button');
            await page.waitForTimeout(800);
            /會被擋/.test(await page.locator('#kd-filter pre').innerText()) ? ok('儀表板：規則檢查') : bad('儀表板：規則檢查沒有結果');
        }
        await page.setViewportSize({ width: 1280, height: 900 });
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
        if (NAME === 'kuroshio' && p === 'settings') /記憶體控制/.test(text) && /記憶體保留量（MB）/.test(text) && /OOM 分數調整/.test(text) && /儲存保留空間（MB）/.test(text) && !/硬體等級/.test(text) ? ok('專業模式：設定頁有記憶體 / 儲存保留量、OOM 分數，沒有硬體等級') : bad('專業模式：設定頁沒有記憶體控制');
        if (NAME === 'kuroshio' && p === 'filter') /保護/.test(text) ? ok('專業模式：訂閱清單有「保護」欄') : bad('專業模式：訂閱清單沒有「保護」欄');
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

    // 黑潮：社群自動規則，專業模式有 require_ip_match / has_txt；存進 UCI 後簡易模式也看得到（不讓設定藏起來）
    if (NAME === 'kuroshio') {
        errors = [];
        const ruleKey = k => `${NAME}.@community_rule[-1].${k}`;
        const modalCheck = async opt => {
            const c = page.locator(`.modal [id$=".${opt}"] input[type=checkbox]`).first();
            if (!(await c.isChecked())) await c.evaluate(el => el.click());
        };
        try {
            await page.evaluate((n) => localStorage.setItem(n + '-ui-mode', 'pro'), NAME);
            await page.goto(`${BASE}/cgi-bin/luci/admin/services/${NAME}/community`);
            await page.waitForLoadState('networkidle');
            await page.locator(`[id="cbi-${NAME}-community_rule"] .cbi-section-create .cbi-button-add`).first().click();
            await page.waitForSelector('.modal [id$=".has_txt"]', { timeout: 10000 });
            const mt = await page.locator('.modal').innerText();
            /來源 IP 要在對方網域的解析結果裡/.test(mt) && /對方有設定 _kuroshio TXT 記錄/.test(mt) ? ok('自動規則（專業）：有 require_ip_match、has_txt') : bad(`自動規則（專業）：沒有 require_ip_match / has_txt\n     ${mt.slice(0, 300)}`);
            await page.locator('.modal [id$=".name"] input[type=text], .modal input[id$=".name"]').first().fill('e2e 規則');
            await modalCheck('require_ip_match');
            await modalCheck('has_txt');
            await page.locator('.modal .cbi-button-positive').first().click();
            await page.waitForTimeout(500);
            await page.locator('.cbi-page-actions .cbi-button-apply, .cbi-page-actions button:has-text("Save & Apply")').first().click();
            await page.waitForTimeout(6000);
            const got = {};
            for (const k of ['name', 'require_ip_match', 'has_txt']) { try { got[k] = await uciGet(ruleKey(k)); } catch (e) { got[k] = `（${e.message.split('\n')[0]}）`; } }
            got.name === 'e2e 規則' && got.require_ip_match === '1' && got.has_txt === '1' ? ok('自動規則：require_ip_match、has_txt 寫進 UCI') : bad(`自動規則寫進 UCI 不對：${JSON.stringify(got)}`);
            await page.evaluate((n) => localStorage.setItem(n + '-ui-mode', 'simple'), NAME);
            await page.goto(`${BASE}/cgi-bin/luci/admin/services/${NAME}/community`);
            await page.waitForLoadState('networkidle');
            await page.locator(`[id="cbi-${NAME}-community_rule"] .cbi-section-table-row .cbi-button-edit`).last().click();
            await page.waitForSelector('.modal', { timeout: 10000 });
            /對方有設定 _kuroshio TXT 記錄/.test(await page.locator('.modal').innerText()) ? ok('自動規則（簡易）：已經用到的專業條件仍然顯示') : bad('自動規則（簡易）：已經用到的專業條件被藏起來');
            await page.screenshot({ path: `${SHOTS}/community-rule-modal.png`, fullPage: true });
            await page.locator('.modal button:has-text("Dismiss"), .modal .cbi-button:not(.cbi-button-positive)').first().click().catch(() => {});
        } catch (e) { bad(`自動規則操作中斷：${e.message.split('\n')[0]}`); }
        if (errors.length) bad(`自動規則：JavaScript 錯誤\n     ${errors.join('\n     ')}`);
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
