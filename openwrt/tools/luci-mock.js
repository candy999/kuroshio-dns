'use strict';
// 開發用：沒有 Docker 時在本機看 LuCI 頁面。用 LuCI 官方的前端檔案（luci.js、form.js…）＋假的 ubus（UCI 放在記憶體、
// kuroshio.* 回固定的範例資料），可以實際操作表單、儲存，再用 luci-e2e.js 檢查。CI 用的是真正的 OpenWrt 容器，不用這個。
//
//   1. 抓 LuCI 前端檔案（跟 OpenWrt 24.10 同一版）到任意目錄：
//        B=https://raw.githubusercontent.com/openwrt/luci/openwrt-24.10
//        for f in luci.js form.js ui.js rpc.js uci.js fs.js network.js firewall.js validation.js cbi.js tools/widgets.js tools/prng.js; do
//          mkdir -p luci/res/$(dirname $f); curl -sS -o luci/res/$f $B/modules/luci-base/htdocs/luci-static/resources/$f; done
//        curl -sS -o luci/cascade.css $B/themes/luci-theme-bootstrap/htdocs/luci-static/bootstrap/cascade.css
//   2. LUCI_DIR=luci PORT=8080 node openwrt/tools/luci-mock.js          （SERVICE=down：模擬服務沒有執行）
//   3. BASE=http://127.0.0.1:8080 MOCK=1 node openwrt/tools/luci-e2e.js kuroshio
//
// 換主題看（只是近似：用主題自己的 CSS 與它 header 範本的 HTML 骨架，不跑主題的選單 JS）：
//   THEMES='argon=/path/luci-theme-argon,vantage=/path/luci-theme-vantage/luci-theme-vantage,material=/path/material'
//   主題目錄是原始碼（有 htdocs/luci-static/<名稱>/）或只放 cascade.css 的資料夾；網址加 ?theme=argon&dark=1（dark=0 淺色、
//   不加跟著系統）。支援 bootstrap（預設）、argon、vantage、material、openwrt2020。
const fs = require('fs');
const http = require('http');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..', '..');
const LUCI = path.resolve(process.env.LUCI_DIR || 'luci');
const APP = path.join(ROOT, 'openwrt', 'luci-app-kuroshio', 'htdocs', 'luci-static', 'resources');
const PORT = +(process.env.PORT || 8080);
const DOWN = process.env.SERVICE === 'down';
const THEMES = Object.fromEntries((process.env.THEMES || '').split(',').filter(Boolean).map(kv => { const i = kv.indexOf('='); return [kv.slice(0, i), path.resolve(kv.slice(i + 1))]; }));
const BIN = process.env.KUROSHIO_BIN || path.join(ROOT, 'target', 'debug', 'kuroshio');

// ---------------- UCI（記憶體） ----------------
function parseUci(text) {
    const out = {};
    let cur = null, n = 0;
    for (const line of text.split('\n')) {
        let m;
        if ((m = /^config\s+(\S+)(?:\s+'([^']*)')?/.exec(line))) {
            const anon = m[2] === undefined;
            const name = anon ? 'cfg' + (n + 1).toString(16).padStart(2, '0') + 'abcd' : m[2];
            cur = out[name] = { '.type': m[1], '.name': name, '.anonymous': anon, '.index': n++ };
        } else if (cur && (m = /^\s+(option|list)\s+(\S+)\s+'((?:[^']|'\\'')*)'/.exec(line))) {
            const v = m[3].replace(/'\\''/g, "'");
            if (m[1] === 'option') cur[m[2]] = v;
            else (cur[m[2]] = cur[m[2]] || []).push(v);
        }
    }
    return out;
}
const uci = {
    kuroshio: parseUci(fs.readFileSync(path.join(ROOT, 'openwrt', 'kuroshio', 'files', 'kuroshio.config'), 'utf-8')),
    dhcp: { lan: { '.type': 'dhcp', '.name': 'lan', '.anonymous': false, '.index': 0, interface: 'lan',
        dhcp_option: ['162,00:2b:00:01:11:03:64:6e:73:07:65:78:61:6d:70:6c:65:03:63:6f:6d:00:04:c0:a8:01:01'],
        dnr: ['1 dns.example.com fd12:3456::1 alpn=h2,h3 port=8443 dohpath=/dns-query{?dns}'] } },
    network: {}, firewall: {}, luci: { main: { '.type': 'core', '.name': 'main', '.anonymous': false, '.index': 0, lang: 'auto' } }
};
if (process.env.UCI_SET) {
    // UCI_SET='tls.domain=dns.example.com ddns.enabled=1 ddns.interfaces=pppoe-wan,wan2'
    for (const kv of process.env.UCI_SET.split(/\s+/).filter(Boolean)) {
        const [k, v] = kv.split('='), [sec, opt] = k.split('.');
        if (uci.kuroshio[sec]) uci.kuroshio[sec][opt] = /,/.test(v) ? v.split(',') : v;
    }
}
const files = { '/etc/kuroshio/custom-rules.txt': '! 自訂規則\n',
    // 套件附帶的預設自訂規則（恢復預設自訂規則用）：跟真正的套件一樣用 rules/default-custom-rules.txt
    '/usr/share/kuroshio/default-custom-rules.txt': fs.readFileSync(path.join(ROOT, 'rules', 'default-custom-rules.txt'), 'utf-8') };

// ---------------- kuroshio 的範例資料 ----------------
const IFACES = { interfaces: [
    { name: 'lo', label: 'lo', up: true, addrs: [{ ip: '127.0.0.1', family: 4, scope: 'loopback' }] },
    { name: 'br-lan', label: 'br-lan', up: true, addrs: [{ ip: '192.168.1.1', family: 4, scope: 'private' }, { ip: 'fd12:3456::1', family: 6, scope: 'ula' }, { ip: 'fe80::1', family: 6, scope: 'linklocal' }] },
    { name: 'pppoe-wan', label: 'pppoe-wan', up: true, addrs: [{ ip: '203.0.113.25', family: 4, scope: 'public' }, { ip: '2001:db8:1::25', family: 6, scope: 'public' },
        { ip: '2001:db8:1::a1b2', family: 6, scope: 'public', temporary: true, deprecated: true }] },
    { name: 'wan2', label: 'wan2', up: true, addrs: [{ ip: '100.72.3.4', family: 4, scope: 'cgnat' }] },
    { name: 'wwan0', label: 'wwan0', up: false, addrs: [] }
] };
const PATHS = {
    configFile: null, configDir: '/etc/kuroshio', stateDir: '/etc/kuroshio/state', runtimeDir: '/tmp/kuroshio', shareDir: '/usr/share/kuroshio',
    tls: { cert: '/etc/kuroshio/cert.pem', key: '/etc/kuroshio/key.pem', source: 'manual', exists: true,
        info: { subject: 'CN=dns.example.com', issuer: 'C=US, O=Let\'s Encrypt, CN=E6', san: 'DNS:dns.example.com', validFrom: 'Mon, 02 Nov 2026 00:00:00 +0000', validTo: 'Sun, 31 Jan 2027 00:00:00 +0000', daysLeft: 80 } },
    acme: { enabled: false, account: '/etc/kuroshio/state/acme-account.json', domains: ['dns.example.com'] },
    adminToken: null, customRules: '/etc/kuroshio/custom-rules.txt', benchmarkDir: '/tmp/kuroshio/benchmark', communityKeyDir: '/etc/kuroshio/community', logFile: null
};
const DDNS = () => (uci.kuroshio.ddns.enabled === '1' ? { enabled: true, lastRun: Date.now() - 60000, error: 'wan2：取不到公網 IPv4（逾時）',
    sources: [{ interface: 'pppoe-wan', family: 4, ip: '203.0.113.25', ok: true, error: null }, { interface: 'wan2', family: 4, ip: null, ok: false, error: '取不到公網 IPv4（逾時）' }],
    records: [{ name: 'dns.example.com', type: 'A', content: '203.0.113.25', ip: '203.0.113.25', ok: true, action: 'unchanged' },
        { name: 'dns.example.com', type: 'A', content: '198.51.100.7', ip: '198.51.100.7', ok: true, action: 'kept' },
        { name: 'dns.example.com', type: 'HTTPS', ok: false, action: 'error', error: 'Cloudflare API 403' }] } : { enabled: false });
const STATUS = {
    version: '3.2.0', stats: { uptimeSec: 3700, today: { date: '2026-11-11', query: 1234, hit: 900, hitRate: 72.9, blocked: 50, blockedAds: 40, blockedTelemetry: 8, blockedMalware: 2, route: {}, latency: { hit: { p50: 1, p95: 2 }, miss: { p50: 20, p95: 80 } } } },
    cacheEntries: 800, cacheBytes: 300000, errors: { count: 0, recent: [] }, ownIp: null,
    upstreams: [{ id: 'udp://1.1.1.1', role: 'pinned', ok: 100, fail: 1, avgMs: 12 }], autoUpstreams: null,
    filter: { lists: 100000, custom: 3, domains: 90000, memoryBytes: 4000000, notice: '記憶體不足，暫時停用：大廣告 清單（3000 條規則）', unloaded: [{ name: '大廣告', rules: 3000, bytes: 27000, reason: 'memory', at: 1793000000000 }] }, cdn: { stats: {}, domains: 10 },
    jobs: { config: { 'dns-benchmark': { at: ['04:10'] } }, state: {}, running: null },
    system: { memTotalMB: 256, cores: 2, arch: 'mipsel', rssKB: 20000, memAvailableMB: 120, memory: { enabled: true, state: 'critical', stateLabel: '不足', rssKB: 30000, availKB: 6144, totalKB: 262144, reserveKB: 16384, reserveAuto: true, reserveHow: '自動：max(16 MB, 實體記憶體 5%, min_free_kbytes 1024 KB × 3)', marginKB: 8192, headroomKB: 0, psi: { someAvg10: 12.5, fullAvg10: 0.4 }, pollSec: 2, growth: false, floor: true, protectedSuspended: false, sizes: { cacheEntries: 64, cacheMax: 64, cacheConfiguredMax: 100000, cdnInRam: 0, cdnOnDiskOnly: 4200, filterListRules: 97000 }, shed: [{ step: 'cache', label: '縮小 DNS 快取', detail: '4000 → 1000 筆', freedBytes: 900000, at: 1793000000000 }], freedBytes: 900000, events: [] }, persist: { bytesToday: 2048, storage: 'flash', intervalMin: 360, effectiveIntervalMin: 720, maxAgeHours: 24, oldestUnsavedSec: 5400, forcedByAge: 1, estimatedDailyBytes: 1200000, lowSpace: false, space: { totalBytes: 50000000, freeBytes: 30000000, reserveBytes: 5000000, reserveAuto: true, reserveHow: '自動（Flash）', marginBytes: 2500000, headroomBytes: 25000000, optionalFiles: 3, optionalBytes: 1200000, keepingOptional: true, deleted: [] } } },
    listeners: { doh: 8443, doh3: null, dot: 853, doq: null, ddr: true },
    listenersDetail: [
        { proto: 'dot', bind: '0.0.0.0', port: 853, ok: true, tls: true, error: null },
        { proto: 'dot', bind: '::', port: 853, ok: false, tls: true, error: 'DoT 監聽 [::]:853 失敗: Address family not supported by protocol (os error 97)' },
        { proto: 'doh', bind: '0.0.0.0', port: 8443, ok: true, tls: true, error: null }]
};
// 連線來源（規格 08）：群組用版控裡的台灣 IP 資料，模式與名單跟著 UCI；?ip= 用簡化的判斷（只給畫面用）
const TWIP = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'geo', 'tw-ip.json'), 'utf-8'));
const ACCESS = query => {
    const a = uci.kuroshio.access || {}, list = v => [].concat(v === undefined ? [] : v).filter(x => x !== '');
    const mode = a.mode || 'taiwan', sel = a.groups === undefined ? ['*'] : list(a.groups);
    const applyTo = a.apply_to === undefined ? ['dot', 'doh', 'doq', 'doh3', 'site'] : list(a.apply_to);
    const ip = new URLSearchParams(query || '').get('ip');
    if (ip) {
        const inList = l => list(l).find(c => ip.startsWith(c.split('/')[0].replace(/\.0$/, '').replace(/::$/, ':')));
        let allowed = false, reason = '不在允許的網段';
        if (inList(a.deny)) reason = '自訂封鎖 ' + inList(a.deny);
        else if (/^(10|192\.168|127)\./.test(ip)) { allowed = true; reason = '私有 / 區網位址（永遠允許）'; }
        else if (inList(a.allow)) { allowed = true; reason = '自訂允許 ' + inList(a.allow); }
        else if (mode === 'open') { allowed = true; reason = '全開放模式'; }
        else if (/^168\.95\./.test(ip) && (mode === 'taiwan' || sel.includes('*') || sel.includes('cht'))) { allowed = true; reason = '台灣網段：中華電信（HiNet、行動上網）'; }
        return { ip, allowed, reason, mode, applyTo };
    }
    const groups = TWIP.groups.map(g => ({ id: g.id, name: g.name, note: g.note, asns: g.asns, size: g.size, cidrs: { v4: g.v4.length, v6: g.v6.length },
        enabled: mode !== 'open' && (mode === 'taiwan' || sel.includes('*') || sel.includes(g.id)), checked: sel.includes('*') || sel.includes(g.id) }));
    return { mode, applyTo, active: true, dataOk: true, failOpen: false, warning: null, generatedAt: TWIP.generatedAt, ranges: 1003, memoryBytes: 16048, dataBytes: 21312,
        denied: { total: 57, byListener: { dot: 40, doh: 17, doq: 0, doh3: 0, site: 0, community: 0, plain: 0 } },
        topDenied: [{ net: '45.135.232.0/24', count: 31 }, { net: '2a06:4880:1000::/48', count: 26 }],
        groups, selected: sel, allow: list(a.allow), deny: list(a.deny), log: a.log !== '0', localUpdate: a.local_update !== '0', dataSource: '/usr/share/kuroshio/geo/tw-ip.json', total: TWIP.total };
};
STATUS.access = { mode: 'taiwan', applyTo: ['dot', 'doh', 'doq', 'doh3', 'site'], active: true, dataOk: true, failOpen: false, warning: null, generatedAt: TWIP.generatedAt,
    ranges: 1003, memoryBytes: 16048, dataBytes: 21312, denied: { total: 57, byListener: { dot: 40, doh: 17 } }, topDenied: [] };
// 好友邀請碼（假的）：重新產生換一個；貼上時 KRS1.MOCKGOOD 開頭當成成功，其他當成檢查碼不符
// QR 碼：有 kuroshio 執行檔時借用 `kuroshio about --qr` 的真 QR 碼（內容是原始碼網址，只是讓畫面像實機），沒有就畫一個方塊
let QR = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><rect width="10" height="10" fill="#fff"/><rect x="1" y="1" width="3" height="3"/></svg>';
let QR_SOURCE = null;
try { QR_SOURCE = JSON.parse(execFileSync(BIN, ['about', '--qr'], { encoding: 'utf-8' })).qrSource || null; if (QR_SOURCE) QR = QR_SOURCE; } catch (e) { /* 沒有執行檔 */ }
let inviteN = 1;
const INVITE = () => ({ ok: true, code: 'KRS1.MOCKAAAA' + 'QZ'.repeat(20) + inviteN, createdAt: Date.now() - 3600000, domain: 'dns.example.com',
    fingerprint: '7197-1882-14EA-0AF1-8FCC-0C6C-00A3-7A4A', ready: true, problems: [], qr: QR });
const INVITE_USE = query => {
    const code = new URLSearchParams(query || '').get('code') || '';
    const fmt = { step: 'format', ok: true, text: '邀請碼格式正確：friend.example.net' };
    if (!code.startsWith('KRS1.MOCKGOOD')) return { ok: false, stage: 'format', reason: '邀請碼檢查碼不符：可能打錯字或少貼了一段，請直接複製貼上',
        steps: [{ step: 'format', ok: false, text: '邀請碼檢查碼不符：可能打錯字或少貼了一段，請直接複製貼上' }] };
    return { ok: true, stage: 'accepted', status: 'accepted', domain: 'friend.example.net', steps: [fmt, { step: 'ready', ok: true, text: '你的社群模式已就緒' },
        { step: 'identity', ok: true, text: '已取得 friend.example.net 的身分文件（經 dot）' }, { step: 'fingerprint', ok: true, text: '身分指紋相符：1111-2222-3333-4444-5555-6666-7777-8888' },
        { step: 'request', ok: true, text: '已送出好友請求（附邀請證明）' }, { step: 'accepted', ok: true, text: '對方已自動同意，成為好友；馬上開始第一次同步' }] };
};
// 社群（好友）：每一種狀態各一個對象。「重新檢查」後從未就緒變成就緒，「同意」把待審核的請求變成好友，「更換金鑰」後出現輪替；
// 其他動作只記下呼叫（luci-e2e.js 用 /__mock/calls 檢查送出的路徑與參數）
const NOW = Date.now(), H = 3600000, D = 24 * H;
const SCORE = (score, ok, fail, invalid, paused) => ({ score, ok, fail, invalid, paused: !!paused });
const NOSCORE = { node: SCORE(0, 0, 0, 0), site: SCORE(0, 0, 0, 0), cross: SCORE(0, 0, 0, 0), upstream: SCORE(0, 0, 0, 0) };
const PEER = (o) => Object.assign({ rel: 'none', myBlock: false, autoBlockAt: null, theirBlock: false, rejectedUntil: null, theirRejectUntil: null, deletedAt: null,
    fingerprint: null, endpoint: null, endpoints: [], channel: null, preferChannel: null, info: {}, ipMatch: null, hasTxt: null, proto: null,
    stats: { offered: 0, invalid: 0, tried: 0, ok: 0, fail: 0 }, scores: NOSCORE, keys: [], pendingKey: null, oldVersion: false, oldVersionSince: null,
    friendSince: null, lastContact: null, lastSyncOk: null, lastError: null, nextTry: null, shared: null, note: null, invitedAt: null }, o);
const community = {
    ready: false, rotated: false,
    peers: [
        PEER({ domain: 'req.example.net', rel: 'in', fingerprint: 'AAAA-1111-2222-3333-4444-5555-6666-7777', info: { asn: 3462, colo: 'TPE', rttMs: 9, jitterMs: 2, lossPct: 0 } }),
        PEER({ domain: 'friend.example.net', rel: 'friend', fingerprint: '1111-2222-3333-4444-5555-6666-7777-8888', channel: 'doq', preferChannel: 'dot',
            info: { asn: 4780, colo: 'TPE', rttMs: 12, jitterMs: 3, lossPct: 1 }, stats: { offered: 420, invalid: 3, tried: 50, ok: 45, fail: 5 },
            scores: { node: SCORE(0.97, 120, 2, 1), site: SCORE(0.9, 45, 5, 0), cross: SCORE(0, 0, 0, 0), upstream: SCORE(0.5, 2, 1, 1, true) },
            friendSince: NOW - 20 * D, invitedAt: NOW - 20 * D, lastSyncOk: NOW - 5 * 60000 }),
        PEER({ domain: 'keyswap.example.org', rel: 'friend', fingerprint: '9999-AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-0000', channel: 'https',
            info: { asn: 9924, colo: 'KHH', rttMs: 25, jitterMs: 8, lossPct: 2 }, stats: { offered: 10, invalid: 0, tried: 0, ok: 0, fail: 0 },
            pendingKey: { kid: 'ab12', fingerprint: 'NEW0-KEY1-2222-3333-4444-5555-6666-7777' }, oldVersion: true, oldVersionSince: NOW - 2 * D,
            lastError: '同步失敗：連線逾時', friendSince: NOW - 3 * D, lastSyncOk: NOW - 2 * D }),
        PEER({ domain: 'wait.example.com', rel: 'out' }),
        PEER({ domain: 'spam.example.com', myBlock: true, autoBlockAt: NOW - H }),
        PEER({ domain: 'blockedme.example.net', theirBlock: true }),
        PEER({ domain: 'rejected.example.com', rejectedUntil: NOW + 30 * D }),
        PEER({ domain: 'theyrejected.example.org', theirRejectUntil: NOW + 30 * D }),
        PEER({ domain: 'gone.example.net', deletedAt: NOW - D })
    ]
};
const COMMUNITY_STATUS = () => {
    const n = f => community.peers.filter(f).length;
    return { enabled: true, ready: community.ready, domain: 'dns.example.com', fingerprint: '7197-1882-14EA-0AF1-8FCC-0C6C-00A3-7A4A',
        check: { at: NOW - 10 * 60000, ready: community.ready, problems: community.ready ? [] : ['dns.example.com 解析出的 IP（198.51.100.7）跟出口 IP（203.0.113.25）不一樣'],
            cert: { validTo: '2027-01-31', daysLeft: 80 } },
        txt: { name: '_kuroshio.dns.example.com', value: 'v=k1; fp=719718821' },
        rotation: community.rotated ? { at: NOW, oldKid: 'aa', until: NOW + 7 * D } : null,
        endpoints: { doh: 'https://dns.example.com/.well-known/kuroshio', dot: 'dot://dns.example.com:853', doq: 'doq://dns.example.com:853' },
        externalConfirmed: { from: 'friend.example.net', at: NOW - H },
        counts: { friends: n(p => p.rel === 'friend'), incoming: n(p => p.rel === 'in'), outgoing: n(p => p.rel === 'out'), blocked: n(p => p.myBlock), pendingKeys: n(p => p.pendingKey) } };
};
const COMMUNITY_EVENTS = () => [{ at: NOW - H, domain: 'req.example.net', type: '收到請求', detail: '人工審核' }, { at: NOW - 2 * H, domain: 'spam.example.com', type: '自動封鎖', detail: null }];
const calls = [];
const COMMUNITY_ACTION = (p, query) => {
    const q = new URLSearchParams(query || '');
    if (p === '/api/community/check') community.ready = true;
    if (p === '/api/community/rotate') community.rotated = true;
    if (p === '/api/community/accept') community.peers.filter(x => x.domain === q.get('domain')).forEach(x => { x.rel = 'friend'; x.friendSince = Date.now(); });
    if (p === '/api/community/add' && q.get('domain') === 'bad.example.com') return { ok: false, reason: 'bad.example.com 沒有回應（連線逾時）' };
    return { ok: true };
};
// 儀表板（/api/dashboard 等）：用 tools/dashboard-seed.js 的範例統計算出跟 kuroshio 一樣格式的資料
const SEED = require(path.join(ROOT, 'tools', 'dashboard-seed.js'));
const LABELS = { cloudflare: 'Cloudflare', cloudfront: 'Amazon CloudFront', fastly: 'Fastly', akamai: 'Akamai', gcore: 'Gcore' };
const r4 = x => Math.round(x * 1e4) / 1e4, r1 = x => Math.round(x * 10) / 10;
function DASH(query) {
    const range = new URLSearchParams(query || '').get('range') || 'today';
    const days = SEED.stats().days, n = range === '30d' ? 30 : range === '7d' ? 7 : 1, keys = days.slice(-n);
    const sum = k => keys.reduce((a, d) => a + (d[k] || 0), 0);
    const route = {}, cdn = {}, sites = {}, blocked = {};
    keys.forEach(d => {
        Object.entries(d.route).forEach(([p, r]) => { const a = route[p] = route[p] || { n: 0, abroad: 0, acc: 0, miss: 0, saved: 0, savedN: 0 }; Object.keys(a).forEach(k => { a[k] += r[k]; }); });
        Object.entries(d.cdn).forEach(([p, c]) => { cdn[p] = (cdn[p] || 0) + c; });
        Object.entries(d.sites).forEach(([k, v]) => { sites[k] = (sites[k] || 0) + v[0]; });
        Object.entries(d.blockedSites).forEach(([k, v]) => { blocked[k] = (blocked[k] || 0) + v[0]; });
    });
    const rows = Object.entries(route).sort((a, b) => b[1].n - a[1].n);
    const t = rows.reduce((a, [, r]) => { Object.keys(a).forEach(k => { a[k] += r[k]; }); return a; }, { n: 0, abroad: 0, acc: 0, miss: 0, saved: 0, savedN: 0 });
    const cross = sum('crossRewrite'), q = sum('query'), blk = sum('blocked'), hit = sum('hit');
    const cdnTotal = Object.values(cdn).reduce((a, b) => a + b, 0);
    const top = (o, k) => Object.entries(o).sort((a, b) => b[1] - a[1]).slice(0, k).map(([site, count]) => ({ site, count }));
    const now = Date.now();
    return {
        generatedAt: new Date(now).toISOString(), range, days: keys.length,
        totals: { queries: q, blocked: blk, blockedAds: sum('blockedAds'), blockedMalware: sum('blockedMalware'), blockedTelemetry: sum('blockedTelemetry'), blockedCustom: sum('blockedCustom'),
            blockRate: q ? r4(blk / q) : 0, cacheHitRate: q ? r4(hit / q) : 0, cdnServed: sum('cdnServed'), cdnAccelerated: sum('cdnRewrite') + sum('ecsRewrite') + cross, accelerated: t.acc + cross },
        acceleration: { verifiedSites: 1283, sitesRoutedAbroad: 1058, medianSavedMs: 178.2, samples: 979, twNodesV4: 37, twNodesV6: 626 },
        trend: days.slice(-30).map(d => ({ date: d.date, queries: d.query, blocked: d.blocked })),
        cdn: Object.entries(cdn).sort((a, b) => b[1] - a[1]).map(([p, c]) => ({ provider: p, label: LABELS[p] || p, count: c, share: r4(c / cdnTotal) })),
        routing: rows.map(([p, a]) => ({ provider: p, label: LABELS[p] || p, connections: a.n, wouldGoAbroad: a.abroad, accelerated: a.acc, stillAbroad: a.miss,
            abroadShare: a.n ? r4(a.abroad / a.n) : 0, successRate: a.abroad ? r4(a.acc / a.abroad) : null, avgSavedMs: a.savedN ? r1(a.saved / a.savedN) : null })),
        opportunity: { connections: t.n, wouldGoAbroad: t.abroad, accelerated: t.acc + cross, stillAbroad: t.miss, otherDnsAbroadShare: t.n ? r4(t.abroad / t.n) : 0,
            oursAbroadShare: t.n ? r4(t.miss / t.n) : 0, avgSavedMs: t.savedN ? r1(t.saved / t.savedN) : null, totalSavedSec: r1(t.saved / 1000), crossAccelerated: cross },
        flows: [{ pop: 'HKG', count: 21997, fixed: 14629 }, { pop: 'NRT', count: 15891, fixed: 9576 }, { pop: 'SIN', count: 6120, fixed: 3011 }, { pop: 'LAX', count: 2410, fixed: 1203 }],
        toPops: { TPE: 26000, KHH: 2400 },
        crossCdn: { explored: 689, ok: 54, fail: 635, successRate: 0.0784, serves: cross,
            byTo: [{ provider: 'cloudflare', label: 'Cloudflare', sites: 24 }, { provider: 'cloudfront', label: 'Amazon CloudFront', sites: 4 }],
            byFrom: [{ provider: 'fastly', label: 'Fastly', explored: 196, ok: 31 }, { provider: 'akamai', label: 'Akamai', explored: 123, ok: 3 }],
            pairs: [{ from: 'fastly', fromLabel: 'Fastly', to: 'cloudflare', toLabel: 'Cloudflare', count: 23 }, { from: 'fastly', fromLabel: 'Fastly', to: 'cloudfront', toLabel: 'Amazon CloudFront', count: 7 }] },
        realtime: Array.from({ length: 60 }, (_, i) => { const qq = Math.round(60 + 25 * Math.sin(i / 5) + (i % 7) * 3); return { t: now - (59 - i) * 60000, queries: qq, blocked: Math.round(qq * 0.1), accelerated: Math.round(qq * 0.18) }; }),
        outcomes: { cache: hit, upstream: Math.max(0, q - hit - blk), ads: sum('blockedAds') + sum('blockedCustom') + sum('blockedTelemetry'), malware: sum('blockedMalware') },
        topSites: top(sites, 30), topBlocked: top(blocked, 30),
        privacy: { minClients: 1 },
        system: { uptimeSec: 3700, rules: { custom: 3, lists: 100000, byCategory: {} }, upstreams: 3, benchmarkAt: null }
    };
}
const POOLS = {
    cloudflare: { ranges: { v4: 14, v6: 7 }, scan: { tw: 78, global: 56, dead: 89 },
        v4: [{ ip: '104.18.22.203', pop: 'TPE', ms: 2.68, speed: 55.3 }, { ip: '104.18.143.105', pop: 'TPE', ms: 2.95, speed: 56.8 }, { ip: '172.67.70.39', pop: 'KHH', ms: 3.29, speed: null, bad: '速度太慢' }],
        v6: [{ ip: '2606:4700:4408::9bd1', pop: 'TPE', ms: 3.36, permanent: true }] },
    fastly: { ranges: { v4: 17, v6: 3 }, scan: { tw: 0, global: 87, dead: 0 }, v4: [{ ip: '151.101.203.124', pop: 'IAD', ms: 0.08, speed: null }], v6: [] }
};
const V6NODES = { providers: { cloudflare: { '2606:4700:4408::9bd1': { ms: 3.36, pop: 'TPE', fails: 0 } } } };
const DOMAINS = Array.from({ length: 12 }, (_, i) => ({ name: `www${i}.example.com`, provider: i % 3 ? 'cloudflare' : 'fastly', via: i % 2 ? 'cname' : 'ip', hits: 5000 - i * 300,
    firstSeen: Date.now() - 86400e3 * 9, lastSeen: Date.now() - 60e3 * (i + 1),
    base: { pop: i % 3 ? 'HKG' : 'NRT', ms: 38 + i }, v4: i % 4 === 3 ? { verdict: 'fail', reason: '憑證不符' } : { verdict: 'ok', pop: 'TPE', ms: 3.1 + i / 10 },
    cross4: i % 3 ? undefined : { verdict: i === 0 ? 'ok' : 'fail', from: 'fastly', to: 'cloudflare', origMs: 41.7, ms: 3.9, at: Date.now() - 3600e3, reason: '其他 CDN 都沒有這個網站', tried: [{ to: 'cloudflare', ok: i === 0, ms: 3.9, reason: '憑證不符' }] } }));
const DOMAINS_API = query => {
    const p = new URLSearchParams(query || ''), qq = p.get('q') || '', off = +(p.get('offset') || 0), lim = +(p.get('limit') || 1000);
    return DOMAINS.filter(d => (!qq || d.name.includes(qq)) && (!p.get('provider') || d.provider === p.get('provider')) && (p.get('cross') !== '1' || (d.cross4 && d.cross4.verdict !== 'none'))).slice(off, off + lim);
};
const BENCH = { generatedAt: Date.now() - 3 * 3600e3, counts: { total: 120, survivors: 40, eliminated: 80 }, coverage: 0.93,
    selected: [{ id: 'https://dns.example.org/dns-query', avgMs: 14.2, newItems: 12, reason: '涵蓋率最高', owner: 'Example_Org' }],
    pinned: [{ id: 'udp://1.1.1.1', avgMs: 12.4, coverageItems: 3, issues: [] }], blocked: [] };
STATUS.jobs = { config: { 'dns-benchmark': { at: ['04:10'] }, 'filter-update': { at: ['03:30'], weekdays: [1, 4] } }, state: { 'dns-benchmark': { lastCode: 0, lastEnd: Date.now() - 3600e3 } }, running: null };
STATUS.stats.topDomains = [{ name: 'www.youtube.com', count: 812 }, { name: 'i.ytimg.com', count: 640 }];
STATUS.stats.topBlocked = [{ name: 'googleads.g.doubleclick.net', count: 120 }];
STATUS.stats.topClients = [{ name: '192.168.1.23', count: 900 }, { name: 'fd12:3456::8', count: 400 }];
const API = { '/api/access': ACCESS, '/api/community/status': COMMUNITY_STATUS, '/api/community/peers': () => community.peers, '/api/community/events': COMMUNITY_EVENTS, '/api/community/invite': INVITE, '/api/status': () => STATUS, '/api/interfaces': () => IFACES, '/api/paths': () => PATHS, '/api/ddns': DDNS,
    '/api/dashboard': DASH, '/api/benchmark': () => BENCH, '/api/cdn/pools': () => POOLS, '/api/cdn/v6nodes': () => V6NODES, '/api/cdn/domains': DOMAINS_API,
    '/api/filter/check': query => (/ads\./.test(new URLSearchParams(query || '').get('name') || '') ? { action: 'block', rule: '||ads.example.com^', cat: 'ads', tier: 'list' } : { action: 'none' }),
    '/api/trace': () => ({ filter: { action: 'none' }, upstreams: [{ id: 'udp://1.1.1.1', role: 'pinned', ms: 12, cls: 'ok', answers: ['www.example.com 300 IN A 192.0.2.80'] }], ranking: [{ ip: '192.0.2.80', ok: true, ms: 3.2 }], cdn: [] }) };
let defaults = null;
try { defaults = JSON.parse(execFileSync(BIN, ['defaults', '--json'], { encoding: 'utf-8' })); } catch (e) { console.log('（沒有 kuroshio 執行檔：預設值提示不顯示）'); }

function kuroshio(method, args) {
    const wrap = (p, q) => (DOWN ? { ok: false, error: '服務沒有回應（可能尚未啟動）' } : (API[p] ? { ok: true, result: API[p](q) } : { ok: true, result: {} }));
    switch (method) {
    case 'status': return DOWN ? { running: false } : { running: true, api: wrap('/api/status') };
    case 'api': return wrap(args.path, args.query);
    // kuroshio dnr --uci --lan …（DNR=fail：模擬條件不符）
    case 'dnr': return process.env.DNR === 'fail' ? { ok: false, reason: '憑證 /etc/kuroshio/cert.pem：沒有涵蓋 dns.example.com', adn: 'dns.example.com', dhcpv4: null, odhcpd: [], protocols: [] }
        : { ok: true, reason: null, adn: 'dns.example.com', dhcpv4: '00:2b', odhcpd: [], protocols: [
            { priority: 1, alpn: ['h2', 'h3'], port: 8443, dohpath: '/dns-query{?dns}', addrs: ['192.168.1.1', 'fd12:3456::1'] },
            { priority: 2, alpn: ['dot'], port: 853, dohpath: null, addrs: ['192.168.1.1'] }] };
    case 'action':
        calls.push({ path: args.path, query: args.query || '' });
        if (/^\/api\/community\/(check|add|accept|reject|block|unblock|delete|sync|rotate|accept-key|channel)$/.test(args.path)) return { ok: true, result: COMMUNITY_ACTION(args.path, args.query) };
        if (args.path === '/api/ddns/update') return wrap('/api/ddns');
        if (args.path === '/api/community/invite/refresh') { inviteN++; return wrap('/api/community/invite'); }
        if (args.path === '/api/community/invite/use') return { ok: true, result: INVITE_USE(args.query) };
        if (args.path === '/api/persist/flush') return DOWN ? wrap(args.path) : { ok: true, result: { ok: true, files: 7, bytes: 345678, at: Date.now(), dir: '/etc/kuroshio/state' } };
        return { ok: true, result: { ok: true } };
    case 'defaults': return { result: defaults };
    case 'about': return { core: { name: '黑潮 DNS', version: '3.2.0', language: 'Rust', target: 'mock', features: ['doh', 'dot'], license: 'GPL-3.0-or-later', licenseUrl: 'https://www.gnu.org/licenses/gpl-3.0.html', source: 'https://github.com/candy999/kuroshio-dns', qrSource: QR_SOURCE }, ui: '3.2.0-r1' };
    case 'acme_status': return { running: false, log: '', cert: PATHS.tls.info };
    case 'acme_issue': return { started: true };
    case 'log': return { lines: ['kuroshio: mock'] };
    default: return {};
    }
}

function ubus(obj, method, a) {
    a = a || {};
    if (obj === 'kuroshio') return [0, kuroshio(method, a)];
    if (obj === 'uci') {
        const cfg = uci[a.config];
        switch (method) {
        case 'get':
            if (!cfg) return [4];
            if (a.section && a.option) return [0, { value: (cfg[a.section] || {})[a.option] }];
            if (a.section) return [0, { values: cfg[a.section] }];
            return [0, { values: cfg }];
        case 'set':
            if (!cfg || !cfg[a.section]) return [4];
            Object.assign(cfg[a.section], a.values);
            return [0];
        case 'delete':
            if (!cfg) return [4];
            if (a.options || a.option) [].concat(a.options || a.option).forEach(o => { if (cfg[a.section]) delete cfg[a.section][o]; });
            else delete cfg[a.section];
            return [0];
        case 'add': {
            const name = a.name || 'cfg' + Math.random().toString(16).slice(2, 8);
            cfg[name] = Object.assign({ '.type': a.type, '.name': name, '.anonymous': !a.name, '.index': Math.max(-1, ...Object.values(cfg).map(x => x['.index'])) + 1 }, a.values || {});
            return [0, { section: name }];
        }
        case 'order':
            if (!cfg) return [4];
            // 跟 rpcd 一樣：列出的區段依序排在最前面，其他的維持原本的先後
            [].concat(a.sections || []).concat(Object.values(cfg).sort((x, y) => x['.index'] - y['.index']).map(x => x['.name']))
                .filter((n, i, all) => cfg[n] && all.indexOf(n) === i).forEach((n, i) => { cfg[n]['.index'] = i; });
            return [0];
        case 'changes': return [0, { changes: {} }];
        case 'configs': return [0, { configs: Object.keys(uci) }];
        default: return [0];   // apply / confirm / rollback / order / commit
        }
    }
    if (obj === 'file') {
        if (method === 'read') return a.path in files ? [0, { data: files[a.path] }] : [4];
        if (method === 'write') { files[a.path] = a.data; return [0]; }
        if (method === 'stat') return a.path in files ? [0, { path: a.path, type: 'file', size: files[a.path].length }] : [4];
        if (method === 'remove') { delete files[a.path]; return [0]; }
        return [0, {}];
    }
    if (obj === 'session' && method === 'access') return [0, { access: true }];
    if (obj === 'system' && method === 'board') return [0, { hostname: 'OpenWrt', model: 'Mock', release: { distribution: 'OpenWrt', version: '24.10' } }];
    if (obj === 'service' && method === 'list') return [0, {}];
    if (obj === 'luci' && method === 'getFeatures') return [0, { firewall: true, ipv6: true }];
    if (obj === 'network.interface' && method === 'dump') return [0, { interface: [] }];
    return [0, {}];
}

// LuCI 核心字串的繁中翻譯（只放截圖常看到的幾個）：跟 cbi.js 的 sfh() 同一個雜湊，translations 端點送 window.TR
function sfh(str) {
    const b = Buffer.from(str, 'utf-8');
    if (!b.length) return null;
    const u16 = o => ((b[o + 1] << 8) + b[o]) >>> 0, s8 = o => (b[o] > 0x7F ? (b[o] - 256) >>> 0 : b[o]);
    let hash = b.length >>> 0, len = b.length >>> 2, off = 0, tmp;
    while (len--) {
        hash += u16(off); tmp = ((u16(off + 2) << 11) ^ hash) >>> 0; hash = ((hash << 16) ^ tmp) >>> 0; hash += hash >>> 11; off += 4;
    }
    switch (b.length & 3) {
    case 3: hash += u16(off); hash = (hash ^ (hash << 16)) >>> 0; hash = (hash ^ (s8(off + 2) << 18)) >>> 0; hash += hash >>> 11; break;
    case 2: hash += u16(off); hash = (hash ^ (hash << 11)) >>> 0; hash += hash >>> 17; break;
    case 1: hash += s8(off); hash = (hash ^ (hash << 10)) >>> 0; hash += hash >>> 1; break;
    }
    hash = (hash ^ (hash << 3)) >>> 0; hash += hash >>> 5; hash = (hash ^ (hash << 4)) >>> 0; hash += hash >>> 17;
    hash = (hash ^ (hash << 25)) >>> 0; hash += hash >>> 6;
    return (0x100000000 + hash).toString(16).substr(1);
}
const ZH = { 'Edit': '編輯', 'Delete': '刪除', 'Name': '名稱', 'Add': '新增', 'Save': '儲存', 'Save & Apply': '儲存並套用', 'Reset': '重設',
    'Dismiss': '關閉', 'Refreshing': '更新中', 'This section contains no values yet': '這個區段還沒有任何設定', 'Drag to reorder': '拖曳以排序',
    'Expand/Collapse': '展開／收合', 'Loading view…': '載入中…' };
const TR_JS = 'window.TR=' + JSON.stringify(Object.fromEntries(Object.entries(ZH).map(([k, v]) => [sfh(k), v]))) + ';';

const MIME = { '.js': 'application/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json',
    '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.woff2': 'font/woff2', '.woff': 'font/woff', '.ttf': 'font/ttf' };
/** 主題的 HTML 骨架（照各主題 header.ut / footer.ut 的結構，選單、指示燈留空） */
const SKELETON = {
    bootstrap: (dark, body) => ({ html: dark == null ? '' : ` data-darkmode="${dark}"`, css: ['/luci-static/bootstrap/cascade.css'], autoDark: dark == null,
        body: `<body class="lang_zh-tw"><header><a class="brand" href="/">OpenWrt（mock）</a></header><div id="maincontent" class="container">${body}</div>` }),
    material: (dark, body) => ({ css: ['/luci-static/material/cascade.css'],
        body: `<body class="lang_zh-tw logged-in"><header><div class="fill"><div class="container"><span class="showSide"></span><a class="brand" href="#">OpenWrt（mock）</a><span class="status" id="indicators"></span></div></div></header>
<div class="main"><div class="main-left" id="mainmenu"></div><div class="main-right"><div class="darkMask"></div><div id="maincontent"><div class="container">${body}</div></div></div></div>` }),
    openwrt2020: (dark, body) => ({ css: ['/luci-static/openwrt2020/cascade.css'],
        body: `<body class="lang_zh-tw"><div id="menubar"><span class="hostname"><a href="/">OpenWrt（mock）</a></span><span id="indicators"></span></div>
<div id="maincontainer"><div id="mainmenu"></div><div id="maincontent">${body}</div></div>` }),
    // argon：data-argon-mode normal = 跟著系統，dark / light 固定；側邊選單由 menu-argon.js 打開（這裡放一個空的，寬度才接近實機）
    argon: (dark, body) => ({ html: ` data-argon-mode="${dark == null ? 'normal' : dark ? 'dark' : 'light'}"`, css: ['/luci-static/argon/css/cascade.css'],
        head: `<style>:root{--light-primary:#5e72e4;--dark-primary:#483d8b;--dark-on-primary:#fff;--dark-link-color:#9d94e0;--dark-focus-ring:#9d94e0;--dark-control-focus:#9d94e0;--dark-progress-fill:#7b6fd0;--dark-control-ring:#7b6fd0;--dark-selected-bg:#2c2650;--dark-selected-hover-bg:#352e60;--dark-accent-ring:#7b6fd0;--dark-accent-shadow:rgba(72,61,139,.4);--blur-radius-light:10px;--blur-opacity-light:.5;--blur-radius-dark:10px;--blur-opacity-dark:.5}</style>`,
        body: `<body class="lang_zh-tw logged-in" data-page="admin-services-kuroshio"><div class="main"><div class="main-left" id="mainmenu"><div class="sidenav-header d-flex align-items-center"><a class="brand" href="#">OpenWrt</a></div><div class="sidenav"><div class="nav-container"><ul class="nav"><li class="slide active"><a class="menu" href="#">服務</a><ul class="slide-menu active"><li class="active"><a href="#">黑潮 DNS</a></li></ul></li></ul></div></div></div>
<div class="main-right"><header class="bg-primary"><div class="fill"><div class="container"><div class="flex1"><button type="button" class="showSide"></button><a class="brand" href="#">OpenWrt（mock）</a></div><div class="header-actions"><div class="status" id="indicators"></div></div></div></div></header><div class="darkMask"></div>
<div id="maincontent"><div class="container">${body}</div><footer class="mobile-hide"><div class="footer-content"><a href="#">Powered by LuCI（mock）</a></div></footer></div></div></div>` }),
    // vantage：header.ut 在 <head> 裡依偏好設 data-darkmode（預設深色）
    vantage: (dark, body) => ({ html: ` data-darkmode="${dark == null ? 'true' : dark}" data-theme="${dark == null ? 'auto' : dark ? 'dark' : 'light'}"`, autoDark: dark == null,
        css: ['/luci-static/vantage/vantage.css', '/luci-static/vantage/icons.css'],
        body: `<body class="lang_zh-tw vt-auth" data-page="admin-services-kuroshio"><div class="vt-shell"><nav class="vt-rail" id="vt-rail"><ul class="vt-rail-list" id="vt-rail-list"></ul></nav>
<div class="vt-frame"><header class="vt-topbar"><nav class="vt-crumbs"><span class="vt-crumb vt-crumb-current">黑潮 DNS</span></nav><div class="vt-top-actions"><div id="indicators" class="vt-indicators"></div></div></header>
<main id="maincontent" class="vt-main">${body}</main><footer class="vt-foot"><span>OpenWrt（mock）</span></footer></div></div>` })
};

function page(view, theme, dark) {
    const media = '/luci-static/' + (SKELETON[theme] ? theme : 'bootstrap');
    const env = {
        media, resource: '/luci-static/resources', scriptname: '/cgi-bin/luci', pathinfo: `/admin/services/kuroshio/${view}`,
        documentroot: '/www', requestpath: ['admin', 'services', 'kuroshio', view], dispatchpath: ['admin', 'services', 'kuroshio', view],
        pollinterval: 5, ubuspath: '/ubus/', sessionid: '0123456789abcdef0123456789abcdef', token: 'mocktoken',
        nodespec: { action: { type: 'view', path: `kuroshio/${view}` }, satisfied: true, readonly: false, title: '黑潮 DNS' },
        apply_rollback: 90, apply_holdoff: 1, apply_timeout: 1, apply_display: 1
    };
    const sk = (SKELETON[theme] || SKELETON.bootstrap)(dark, `<div id="tabmenu" style="display:none"></div>
<script src="/luci-static/resources/luci.js"></script><script>L = new LuCI(${JSON.stringify(env)});</script>
<div id="view"><div class="spinning">Loading view…</div><script>L.require('ui').then(function(ui) { ui.instantiateView('kuroshio/${view}'); });</script></div>`);
    // bootstrap / vantage 的「自動」：跟著系統的深淺色設 data-darkmode（跟主題自己的 header 一樣）
    const auto = sk.autoDark ? `<script>(function(){ var m = window.matchMedia('(prefers-color-scheme: dark)'), r = document.documentElement; var set = function(x) { r.setAttribute('data-darkmode', x.matches); }; set(m); m.addListener(set); })();</script>` : '';
    return `<!DOCTYPE html><html lang="zh-tw"${sk.html || ''}><head><meta charset="utf-8"><title>OpenWrt - 黑潮 DNS - LuCI（mock）</title>
<meta name="viewport" content="width=device-width, initial-scale=1">${sk.css.map(c => `<link rel="stylesheet" href="${c}">`).join('')}${sk.head || ''}
${auto}<script src="/cgi-bin/luci/admin/translations/zh-tw"></script><script src="/luci-static/resources/cbi.js"></script></head>
${sk.body}</body></html>`;
}

/** 主題的靜態檔：/luci-static/<主題>/<檔名> → 主題原始碼的 htdocs/luci-static/<主題>/，或主題資料夾本身 */
function themeFile(name, rel) {
    const dir = THEMES[name];
    if (!dir || rel.includes('..')) return null;
    for (const base of [path.join(dir, 'htdocs', 'luci-static', name), dir]) {
        const f = path.join(base, rel);
        if (fs.existsSync(f) && fs.statSync(f).isFile()) return f;
    }
    return null;
}

http.createServer((req, res) => {
    const url = new URL(req.url, 'http://x');
    const send = (code, type, body) => { res.writeHead(code, { 'content-type': type, 'cache-control': 'no-store' }); res.end(body); };
    if (url.pathname.startsWith('/ubus')) {
        let body = '';
        req.on('data', c => { body += c; });
        req.on('end', () => {
            let calls;
            try { calls = JSON.parse(body); } catch (e) { return send(400, 'text/plain', 'bad json'); }
            const one = c => {
                if (c.method === 'list') return { jsonrpc: '2.0', id: c.id, result: {} };
                const [, obj, method, args] = c.params || [];
                return { jsonrpc: '2.0', id: c.id, result: ubus(obj, method, args) };
            };
            send(200, 'application/json', JSON.stringify(Array.isArray(calls) ? calls.map(one) : one(calls)));
        });
        return;
    }
    // 給 luci-e2e.js（MOCK=1）讀結果
    // kuroshio action 呼叫紀錄（?since=N 只回第 N 筆之後的）
    if (url.pathname === '/__mock/calls') return send(200, MIME['.json'], JSON.stringify(calls.slice(+(url.searchParams.get('since') || 0))));
    if (url.pathname === '/__mock/uci') {
        const [c, sct, o] = (url.searchParams.get('key') || '').split('.');
        // 跟 uci 指令一樣支援 @type[i]（負數從後面算）
        let sec = (uci[c] || {})[sct];
        const at = /^@(\w+)\[(-?\d+)\]$/.exec(sct || '');
        if (at) {
            const list = Object.values(uci[c] || {}).filter(x => x['.type'] === at[1]).sort((a, b) => a['.index'] - b['.index']);
            sec = list[+at[2] < 0 ? list.length + +at[2] : +at[2]];
        }
        const v = (sec || {})[o];
        return send(v === undefined ? 404 : 200, 'text/plain; charset=utf-8', v === undefined ? '' : [].concat(v).join(' '));
    }
    if (url.pathname === '/__mock/file') {
        const p = url.searchParams.get('path');
        return send(p in files ? 200 : 404, 'text/plain; charset=utf-8', files[p] || '');
    }
    if (/\/admin\/translations\//.test(url.pathname)) return send(200, MIME['.js'], TR_JS);
    let m;
    if ((m = /^\/cgi-bin\/luci\/admin\/services\/kuroshio\/(\w+)$/.exec(url.pathname))) {
        const d = url.searchParams.get('dark');
        return send(200, 'text/html; charset=utf-8', page(m[1], url.searchParams.get('theme') || process.env.THEME || 'bootstrap', d == null ? null : d === '1'));
    }
    if (url.pathname === '/cgi-bin/luci/' || url.pathname === '/') return send(200, 'text/html; charset=utf-8', '<!DOCTYPE html><meta charset="utf-8"><title>LuCI mock</title><p>LuCI mock：/cgi-bin/luci/admin/services/kuroshio/settings</p>');
    if (url.pathname === '/luci-static/bootstrap/cascade.css' && !THEMES.bootstrap) return send(200, MIME['.css'], fs.readFileSync(path.join(LUCI, 'cascade.css')));
    if ((m = /^\/luci-static\/(\w+)\/([\w./-]+)$/.exec(url.pathname)) && m[1] !== 'resources') {
        const f = themeFile(m[1], m[2]);
        if (f) return send(200, MIME[path.extname(f)] || 'application/octet-stream', fs.readFileSync(f));
    }
    if ((m = /^\/luci-static\/resources\/([\w./-]+)$/.exec(url.pathname)) && !m[1].includes('..')) {
        if (/^kuroshio\/dashboard\.(js|css)$/.test(m[1])) return send(200, MIME[path.extname(m[1])], fs.readFileSync(path.join(ROOT, 'data', 'dashboard', m[1].slice(9))));
        for (const base of [APP, path.join(LUCI, 'res')]) {
            const f = path.join(base, m[1]);
            if (fs.existsSync(f) && fs.statSync(f).isFile()) return send(200, MIME[path.extname(f)] || 'application/octet-stream', fs.readFileSync(f));
        }
    }
    send(404, 'text/plain', 'not found');
}).listen(PORT, '127.0.0.1', () => console.log(`LuCI mock http://127.0.0.1:${PORT}/cgi-bin/luci/admin/services/kuroshio/settings${DOWN ? '（服務沒有執行）' : ''}`));
