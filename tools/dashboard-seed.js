'use strict';
// 測試用：儀表板的範例統計（stats.json 快照格式，見 crates/kuroshio/src/stats.rs 的 Day::from_json）。
// 內容固定（不用亂數），31 天、每天的查詢量、攔截、各 CDN 的機會成本、跨 CDN、匿名網站排行。
// site-e2e.js、admin-e2e.js 啟動 kuroshio 之前寫進狀態資料夾的 stats.json。

/** 台北時間的日期（YYYY-MM-DD），`offset` 天前 */
function taipeiDate(offset, now = Date.now()) {
    return new Date(now + 8 * 3600e3 - offset * 86400e3).toISOString().slice(0, 10);
}

const SITES = ['youtube.com', 'google.com', 'facebook.com', 'instagram.com', 'line.me', 'apple.com', 'icloud.com', 'netflix.com',
    'shopee.tw', 'pchome.com.tw', 'ptt.cc', 'dcard.tw', 'github.com', 'microsoft.com', 'yahoo.com', 'momoshop.com.tw', 'twitch.tv', 'cloudflare.com'];
const BLOCKED = ['doubleclick.net', 'googlesyndication.com', 'app-measurement.com', 'scorecardresearch.com', 'adnxs.com', 'criteo.com',
    'taboola.com', 'outbrain.com', 'crashlytics.com', 'appsflyer.com'];

/** 第 i 天（0 = 今天）的一筆 */
function day(i, now) {
    const w = 1 + 0.25 * Math.sin(i / 2.3) + (i % 7 === 0 ? 0.2 : 0);   // 週末多一點、有起伏
    const query = Math.round((i === 0 ? 4200 : 9800) * w);
    const hit = Math.round(query * 0.71);
    const ads = Math.round(query * 0.083), tele = Math.round(query * 0.021), mal = 3 + (i % 4), custom = 5 + (i % 3);
    const blocked = ads + tele + mal + custom;
    // 機會成本（3.5.1 起 7 家：連線去向圖取前 5 家、其餘 2 家合併成「其他」）。原本出國 = 拉回 + 仍在國外，
    // 跟 Stats::route() 一樣每一筆都能拆成三塊。Fastly 在台灣沒有節點，沒有「原本」可以比、不在這裡（跨 CDN 另外算）
    const rt = (n, acc, miss, ms) => {
        const a = Math.round(acc * w), m = Math.round(miss * w);
        return { n: Math.max(a + m, Math.round(n * w)), abroad: a + m, acc: a, miss: m, saved: ms ? a * ms : 0, savedN: ms ? a : 0 };
    };
    const route = {
        cloudflare: rt(820, 296, 34, 28.5),
        cloudfront: rt(410, 201, 49, 41.2),
        akamai: rt(260, 0, 18, 0),
        apple: rt(190, 12, 6, 18),
        azure: rt(120, 30, 22, 35),
        gcore: rt(22, 5, 4, 60),
        line: rt(14, 2, 1, 22)
    };
    const sites = {};
    SITES.forEach((s, k) => { sites[s] = [Math.round((SITES.length - k) * 37 * w), Math.max(1, 6 - (k % 6))]; });
    const blockedSites = {};
    BLOCKED.forEach((s, k) => { blockedSites[s] = [Math.round((BLOCKED.length - k) * 21 * w), Math.max(1, 4 - (k % 4))]; });
    return {
        date: taipeiDate(i, now), query, hit, miss: query - hit - blocked, blocked, blockedAds: ads, blockedTelemetry: tele, blockedMalware: mal, blockedCustom: custom,
        cdnServed: Math.round(1640 * w), cdnRewrite: Math.round(533 * w), ecsRewrite: Math.round(41 * w), crossRewrite: Math.round(27 * w),
        // 10 家 CDN（「最常用到的 CDN」列 8 家、其餘合併成「其他」）
        cdn: { cloudflare: Math.round(820 * w), cloudfront: Math.round(410 * w), akamai: Math.round(260 * w), apple: Math.round(190 * w), fastly: Math.round(150 * w),
            azure: Math.round(120 * w), gcore: Math.round(22 * w), line: Math.round(14 * w), bunny: Math.round(6 * w), cdn77: Math.round(3 * w) },
        // 10 組跨 CDN（列 8 組、其餘合併）；fastly>? 是改走的 CDN 沒記到（畫面上標「未辨識」，不併進「其他」）
        cross: { 'fastly>cloudflare': Math.round(19 * w), 'fastly>cloudfront': Math.round(6 * w), 'fastly>?': Math.round(4 * w), 'akamai>cloudflare': Math.round(3 * w),
            'fastly>akamai': Math.round(3 * w), 'bunny>cloudflare': 2, 'cdn77>cloudflare': 2, 'akamai>cloudfront': 1, 'fastly>gcore': 1, 'bunny>cloudfront': 1 },
        route, sites, blockedSites
    };
}

/** stats.json 的內容 */
function stats(now = Date.now()) {
    const days = [];
    for (let i = 30; i >= 0; i--) days.push(day(i, now));
    return { version: 1, days };
}

module.exports = { stats, taipeiDate };
