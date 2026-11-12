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
    const route = {
        cloudflare: { n: Math.round(820 * w), abroad: Math.round(330 * w), acc: Math.round(296 * w), miss: Math.round(34 * w), saved: 296 * w * 28.5, savedN: Math.round(296 * w) },
        cloudfront: { n: Math.round(410 * w), abroad: Math.round(250 * w), acc: Math.round(201 * w), miss: Math.round(49 * w), saved: 201 * w * 41.2, savedN: Math.round(201 * w) },
        fastly: { n: Math.round(150 * w), abroad: Math.round(120 * w), acc: Math.round(36 * w), miss: Math.round(84 * w), saved: 36 * w * 55, savedN: Math.round(36 * w) },
        akamai: { n: Math.round(260 * w), abroad: Math.round(18 * w), acc: 0, miss: Math.round(18 * w), saved: 0, savedN: 0 }
    };
    const sites = {};
    SITES.forEach((s, k) => { sites[s] = [Math.round((SITES.length - k) * 37 * w), Math.max(1, 6 - (k % 6))]; });
    const blockedSites = {};
    BLOCKED.forEach((s, k) => { blockedSites[s] = [Math.round((BLOCKED.length - k) * 21 * w), Math.max(1, 4 - (k % 4))]; });
    return {
        date: taipeiDate(i, now), query, hit, miss: query - hit - blocked, blocked, blockedAds: ads, blockedTelemetry: tele, blockedMalware: mal, blockedCustom: custom,
        cdnServed: Math.round(1640 * w), cdnRewrite: Math.round(533 * w), ecsRewrite: Math.round(41 * w), crossRewrite: Math.round(27 * w),
        cdn: { cloudflare: Math.round(820 * w), cloudfront: Math.round(410 * w), akamai: Math.round(260 * w), fastly: Math.round(150 * w), gcore: Math.round(22 * w) },
        cross: { 'fastly>cloudflare': Math.round(19 * w), 'fastly>cloudfront': Math.round(6 * w), 'akamai>cloudflare': Math.round(2 * w) },
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
