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
const fs = require('fs');
const http = require('http');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..', '..');
const LUCI = path.resolve(process.env.LUCI_DIR || 'luci');
const APP = path.join(ROOT, 'openwrt', 'luci-app-kuroshio', 'htdocs', 'luci-static', 'resources');
const PORT = +(process.env.PORT || 8080);
const DOWN = process.env.SERVICE === 'down';
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
const files = { '/etc/kuroshio/custom-rules.txt': '! 自訂規則\n' };

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
    version: '3.0.0-alpha.2', stats: { uptimeSec: 3700, today: { date: '2026-11-11', query: 1234, hit: 900, hitRate: 72.9, blocked: 50, blockedAds: 40, blockedTelemetry: 8, blockedMalware: 2, route: {}, latency: { hit: { p50: 1, p95: 2 }, miss: { p50: 20, p95: 80 } } } },
    cacheEntries: 800, cacheBytes: 300000, errors: { count: 0, recent: [] }, ownIp: null,
    upstreams: [{ id: 'udp://1.1.1.1', role: 'pinned', ok: 100, fail: 1, avgMs: 12 }], autoUpstreams: null,
    filter: { lists: 100000, custom: 3, domains: 90000, memoryBytes: 4000000 }, cdn: { stats: {}, domains: 10 },
    jobs: { config: { 'dns-benchmark': { at: ['04:10'] } }, state: {}, running: null },
    system: { tier: 'small', memTotalMB: 256, cores: 2, arch: 'mipsel', rssKB: 20000, memAvailableMB: 120, persist: { bytesToday: 2048, storage: 'flash', intervalMin: 60 } },
    listeners: { doh: 8443, doh3: null, dot: 853, doq: null, ddr: true },
    listenersDetail: [
        { proto: 'dot', bind: '0.0.0.0', port: 853, ok: true, tls: true, error: null },
        { proto: 'dot', bind: '::', port: 853, ok: false, tls: true, error: 'DoT 監聽 [::]:853 失敗: Address family not supported by protocol (os error 97)' },
        { proto: 'doh', bind: '0.0.0.0', port: 8443, ok: true, tls: true, error: null }]
};
const API = { '/api/community/peers': () => [], '/api/community/events': () => [], '/api/status': () => STATUS, '/api/interfaces': () => IFACES, '/api/paths': () => PATHS, '/api/ddns': DDNS };
let defaults = null;
try { defaults = JSON.parse(execFileSync(BIN, ['defaults', '--json'], { encoding: 'utf-8' })); } catch (e) { console.log('（沒有 kuroshio 執行檔：預設值提示不顯示）'); }

function kuroshio(method, args) {
    const wrap = p => (DOWN ? { ok: false, error: '服務沒有回應（可能尚未啟動）' } : (API[p] ? { ok: true, result: API[p]() } : { ok: true, result: {} }));
    switch (method) {
    case 'status': return DOWN ? { running: false } : { running: true, api: wrap('/api/status') };
    case 'api': return wrap(args.path);
    case 'action': return args.path === '/api/ddns/update' ? wrap('/api/ddns') : { ok: true, result: { ok: true } };
    case 'defaults': return { result: defaults };
    case 'about': return { core: { name: '黑潮 DNS', version: '3.0.0-alpha.2', language: 'Rust', target: 'mock', features: ['doh', 'dot'], license: 'GPL-3.0-or-later', licenseUrl: 'https://www.gnu.org/licenses/gpl-3.0.html', source: 'https://github.com/candy999/kuroshio-dns' }, ui: '3.0.0_alpha2-r1' };
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
            cfg[name] = Object.assign({ '.type': a.type, '.name': name, '.anonymous': !a.name, '.index': Object.keys(cfg).length }, a.values || {});
            return [0, { section: name }];
        }
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

const MIME = { '.js': 'application/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json' };
function page(view) {
    const env = {
        media: '/luci-static/bootstrap', resource: '/luci-static/resources', scriptname: '/cgi-bin/luci', pathinfo: `/admin/services/kuroshio/${view}`,
        documentroot: '/www', requestpath: ['admin', 'services', 'kuroshio', view], dispatchpath: ['admin', 'services', 'kuroshio', view],
        pollinterval: 5, ubuspath: '/ubus/', sessionid: '0123456789abcdef0123456789abcdef', token: 'mocktoken',
        nodespec: { action: { type: 'view', path: `kuroshio/${view}` }, satisfied: true, readonly: false, title: '黑潮 DNS' },
        apply_rollback: 90, apply_holdoff: 1, apply_timeout: 1, apply_display: 1
    };
    return `<!DOCTYPE html><html lang="zh-tw"><head><meta charset="utf-8"><title>OpenWrt - 黑潮 DNS - LuCI（mock）</title>
<meta name="viewport" content="initial-scale=1.0"><link rel="stylesheet" href="/luci-static/bootstrap/cascade.css">
<script src="/cgi-bin/luci/admin/translations/zh-tw"></script><script src="/luci-static/resources/cbi.js"></script></head>
<body class="lang_zh-tw"><header><a class="brand" href="/">OpenWrt（mock）</a></header>
<div id="maincontent" class="container"><div id="tabmenu" style="display:none"></div>
<script src="/luci-static/resources/luci.js"></script><script>L = new LuCI(${JSON.stringify(env)});</script>
<div id="view"><div class="spinning">Loading view…</div><script>L.require('ui').then(function(ui) { ui.instantiateView('kuroshio/${view}'); });</script></div>
</div></body></html>`;
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
    if (url.pathname === '/__mock/uci') {
        const [c, sct, o] = (url.searchParams.get('key') || '').split('.');
        const v = ((uci[c] || {})[sct] || {})[o];
        return send(v === undefined ? 404 : 200, 'text/plain; charset=utf-8', v === undefined ? '' : [].concat(v).join(' '));
    }
    if (url.pathname === '/__mock/file') {
        const p = url.searchParams.get('path');
        return send(p in files ? 200 : 404, 'text/plain; charset=utf-8', files[p] || '');
    }
    if (/\/admin\/translations\//.test(url.pathname)) return send(200, MIME['.js'], '');
    let m;
    if ((m = /^\/cgi-bin\/luci\/admin\/services\/kuroshio\/(\w+)$/.exec(url.pathname))) return send(200, 'text/html; charset=utf-8', page(m[1]));
    if (url.pathname === '/cgi-bin/luci/' || url.pathname === '/') return send(200, 'text/html; charset=utf-8', '<!DOCTYPE html><meta charset="utf-8"><title>LuCI mock</title><p>LuCI mock：/cgi-bin/luci/admin/services/kuroshio/settings</p>');
    if (url.pathname === '/luci-static/bootstrap/cascade.css') return send(200, MIME['.css'], fs.readFileSync(path.join(LUCI, 'cascade.css')));
    if ((m = /^\/luci-static\/resources\/([\w./-]+)$/.exec(url.pathname)) && !m[1].includes('..')) {
        for (const base of [APP, path.join(LUCI, 'res')]) {
            const f = path.join(base, m[1]);
            if (fs.existsSync(f) && fs.statSync(f).isFile()) return send(200, MIME[path.extname(f)] || 'application/octet-stream', fs.readFileSync(f));
        }
    }
    send(404, 'text/plain', 'not found');
}).listen(PORT, '127.0.0.1', () => console.log(`LuCI mock http://127.0.0.1:${PORT}/cgi-bin/luci/admin/services/kuroshio/settings${DOWN ? '（服務沒有執行）' : ''}`));
