'use strict';
// 產生 CDN 子系統的對照向量：用 node 版 legacy-node/lib/cdn/*.js 實際判定，寫成 cases.json，
// Rust 版 crates/kuroshio-cdn/src/tests/parity.rs 讀進來逐筆比對。
//
// 執行：node tests/vectors/cdn/gen.js
// （需要 legacy-node/node_modules/dns-packet：在 legacy-node 執行 npm ci --omit=dev）
//
// 內容：CNAME 後綴判斷、回應標頭判斷 CDN 與 POP、台灣 POP、錯誤頁判斷、同一個網站判斷、
//      IP 分類（用 data/cdn 的範圍與分類檔）、改寫決策（固定的節點池與驗證結果，背景工作只記錄不執行）。
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.resolve(__dirname, '../../..');
const L = p => require(path.join(ROOT, 'legacy-node/lib', p));

// 不要動到 legacy-node/state：永久 IPv6 紀錄換成記憶體裡的空資料
const v6store = L('cdn/v6store.js');
v6store.list = () => [];
v6store.markOk = () => true;
v6store.markNotTw = () => true;
v6store.markDead = () => false;

const { providerByCname, detectFromHeaders, isTwPop, PROVIDERS } = L('cdn/providers.js');
const { looksBroken } = L('cdn/verifier.js');
const { sameSite, crossBroken } = L('cdn/cross.js');
const { PoolManager } = L('cdn/pools.js');
const { CdnOptimizer } = L('cdn/optimizer.js');
const { CidrSet } = L('cidr.js');
const iprank = L('iprank.js');
const dm = L('dnsmsg.js');

const out = { generator: 'tests/vectors/cdn/gen.js', node: process.version };

// ---------------------------------------------------------------- CNAME
out.cname = [
    'e1.dscx.akamaiedge.net', 'e1.dscx.akamaiedge.net.', 'X.CDN.CLOUDFLARE.NET', 'cloudflare.net', 'notcloudflare.net',
    'apple.com.edgekey.net', 'www.apple.com.edgekey.net', 'foo.edgekey.net', 'd111.cloudfront.net', 'cloudfront.net.evil.com',
    'dualstack.reddit.map.fastly.net', 'global.ssl.fastly.net', 'x.global.ssl.fastly.net', 'a.b-cdn.net', 'b-cdn.net.example',
    'x.vo.msecnd.net', 'x.msecnd.net', 'x.trafficmanager.net', 'azurefd-t-prod.trafficmanager.net', 'y.azurefd-t-prod.trafficmanager.net',
    'gateway.fe2.apple-dns.net', 'scontent.xx.fbcdn.net', 'www.google.com', 'ghs.google.com', 'x.l.google.com', 'legy.line-apps.com',
    'cdn.jsdelivr.net', 'kxcdn.com', 'p.kxcdn.com', 'eo.dnse1.com', 'x.eo.dnse1.com', 'dnse1.com', '', '.', 'a..b.akamai.net',
    'qwilted-cds.cqloud.com', 'x.qwilted-cds.cqloud.com', 'cqloud.com', 'user.github.io', 'shop.myshopify.com'
].map(h => ({ host: h, provider: providerByCname(h) }));

// ---------------------------------------------------------------- 台灣 POP
out.twPop = ['TPE', 'tpe51', 'KHH', 'TSA', 'RMQ', 'TXG', 'TNN', 'TPE50-C1', 'HKG', 'NRT', '', 'TP', 'XTPE', 'tnn', 'Khh9', 'seed', 'TP E']
    .map(p => ({ pop: p, tw: isTwPop(p) }));

// ---------------------------------------------------------------- 標頭判斷
const H = [
    [{ 'cf-ray': '8a1b2c3d-TPE', server: 'cloudflare' }, ''],
    [{ 'cf-ray': '8a1b2c3d' }, 'fl=1\nip=1.2.3.4\ncolo=khh\n'],
    [{ server: 'CloudFlare' }, 'colo=12 colo=NRT'],
    [{ 'x-amz-cf-pop': 'TPE52-P1', 'x-cache': 'Miss from cloudfront' }, ''],
    [{ via: '1.1 abc.cloudfront.net (CloudFront)' }, ''],
    [{ 'x-cache': 'Error from cloudfront' }, ''],
    [{ 'x-amz-cf-pop': '52-x' }, ''],
    [{ 'x-served-by': 'cache-iad-kiad7000-IAD, cache-hkg17920-HKG' }, ''],
    [{ 'x-served-by': 'cache-nrt-rjtt8900042-NRT' }, ''],
    [{ 'x-served-by': 'cache-tyo11953' }, ''],
    [{ 'x-served-by': 'cache-tyo' }, ''],
    [{ 'x-served-by': 'Cache-TYO123' }, ''],
    [{ 'x-served-by': 'origin-1' }, ''],
    [{ 'x-id': 'fr5-hw-edge-gc17' }, ''],
    [{ 'x-id': '', 'x-id-fe': 'tpe1-up-gc23' }, ''],
    [{ 'x-id': '-x' }, ''],
    [{ 'x-id': 'abcd12' }, ''],
    [{ 'x-azure-ref': '0abc Ref A: 123 Ref B: TPE30EDGE0108 Ref C: 2026' }, ''],
    [{ 'x-msedge-ref': 'Ref A: x Ref B: 12 khh' }, ''],
    [{ 'x-msedge-ref': 'Ref B: 1KHH tpe' }, ''],
    [{ server: 'AkamaiGHost' }, ''],
    [{ 'x-akamai-transformed': '9 - 0 pmb=mRUM,1' }, ''],
    [{ 'x-cache': 'TCP_HIT from a23-1-1-1.deploy.akamaitechnologies.com' }, ''],
    [{ 'x-bunny-pop': 'BunnyCDN-TW1-1103' }, ''],
    [{ 'x-pop': 'edge TPE12 x' }, ''],
    [{ 'x-edge-location': 'HKG62-C1' }, ''],
    [{ 'cdn-pop': 'sjc' }, ''],
    [{ 'x-cache-pop': 'ABC_1 DEF2' }, ''],
    [{ server: 'NGX TPE' }, ''],
    [{ server: 'nginx' }, '<html>'],
    [{}, ''],
];
out.headers = H.map(([h, body]) => {
    const per = {};
    for (const [n, p] of Object.entries(PROVIDERS)) {
        per[n] = { pop: p.pop ? p.pop(h, body) : null, is: p.isProvider ? !!p.isProvider(h) : null };
    }
    return { headers: h, body, detect: detectFromHeaders(h, body), per };
});

// ---------------------------------------------------------------- 錯誤頁 / 同一個網站
const R = (status, headers, body) => ({ ok: true, status, headers, body, ms: 10 });
const B = [
    ['cloudflare', R(403, {}, 'error code: 1034')],
    ['cloudflare', R(403, {}, 'error code:1020')],
    ['cloudflare', R(403, {}, 'Error code   1016 x')],
    ['cloudflare', R(403, {}, '<b>Error 1016</b>')],
    ['cloudflare', R(403, {}, 'Error 2016')],
    ['cloudflare', R(403, {}, 'cf-error-code')],
    ['cloudflare', R(403, {}, 'Edge IP Restricted')],
    ['cloudflare', R(525, {}, '')],
    ['cloudflare', R(531, {}, '')],
    ['cloudflare', R(200, {}, '<html>')],
    ['cloudfront', R(403, { 'x-cache': 'Error from cloudfront' }, 'The request could not be satisfied')],
    ['cloudfront', R(400, { 'x-cache': 'Error from cloudfront' }, 'Bad request.')],
    ['cloudfront', R(404, { 'x-cache': 'Error from cloudfront' }, 'nope')],
    ['cloudfront', R(301, { 'x-cache': 'Error from cloudfront' }, '')],
    ['fastly', R(421, {}, '')],
    ['fastly', R(503, {}, '')],
    ['akamai', R(400, {}, '<h1>Invalid URL</h1> Reference&#32;&#35;9.1234')],
    ['akamai', R(403, {}, 'Access Denied ... Reference #18.abc')],
    ['akamai', R(403, {}, 'Access Denied, no ref')],
    ['azure', R(404, {}, '<h2>Page not found</h2>\n... Azure Front Door ...')],
    ['azure', R(503, {}, "Our services aren't available right now")],
    ['azure', R(404, {}, 'Azure Front Door ... page not found')],
];
out.broken = B.map(([p, r]) => ({ provider: p, r, looks: looksBroken(p, r), cross: crossBroken(p, r) }));
const html = (t, st = 200, h = {}) => R(st, { 'content-type': 'text/html; charset=utf-8', ...h }, t === null ? '' : `<html><head><title>${t}</title></head></html>`);
const S = [
    [html('X'), html('X')],
    [html('X'), html('X', 403)],
    [html('X'), html('Cloudflare')],
    [html(null, 301, { location: 'https://x.com/home' }), html(null, 302, { location: 'https://x.com/home' })],
    [html(null, 301, { location: 'https://x.com/home' }), html(null, 301, { location: 'https://www.cloudflare.com/' })],
    [html(null, 302, { location: '/a?x=1' }), html(null, 302, { location: 'https://x.invalid/a?y=2' })],
    [html(null, 302, { location: 'HTTPS://X.COM:443/p' }), html(null, 302, { location: 'https://x.com/p' })],
    [html('X'), R(200, { 'content-type': 'application/json' }, '{}')],
    [html('  A \n B  '), html('A B')],
    [R(200, {}, '<TITLE lang=x>T</Title>'), R(200, {}, '<title>T</title>')],
    [R(204, {}, ''), R(200, {}, 'x')],
];
out.sameSite = S.map(([a, b]) => ({ a, b, diff: sameSite(a, b) }));

// ---------------------------------------------------------------- IP 分類
const all = ['cloudflare', 'cloudfront', 'fastly', 'gcore', 'azure'];
const pm = new PoolManager({ providers: Object.fromEntries(all.map(n => [n, { enabled: true }])) });
const sample = [];
const dataDir = path.join(ROOT, 'data/cdn');
const lines = f => { try { return fs.readFileSync(path.join(dataDir, f), 'utf-8').split(/\r?\n/).filter(l => /^\d|:/.test(l)); } catch (e) { return []; } };
const pickLines = l => [l[0], l[Math.floor(l.length / 2)], l[l.length - 1]].filter(Boolean);
for (const n of all) {
    for (const kind of ['TW', 'Global', 'Dead']) {
        for (const c of pickLines(lines(`scan/${n}-ipv4-${kind}.txt`))) {
            const b = c.split('/')[0].split('.').slice(0, 3).join('.');
            sample.push(`${b}.1`, `${b}.200`);
        }
    }
    for (const c of pickLines(lines(`ranges/${n}-ipv4.txt`))) sample.push(c.split('/')[0]);
    for (const c of pickLines(lines(`ranges/${n}-ipv6.txt`))) { const b = c.split('/')[0]; sample.push(b.endsWith('::') ? b + '1' : b); }
}
sample.push('185.199.110.133', '2606:50c0:8000::133', '8.8.8.8', '1.1.1.1', '104.16.161.36', '172.67.0.9', '151.101.67.6', '13.107.246.1',
    '2001:db8::1', '2606:4700:3030::1', '2a04:4e42::396', '127.0.0.1', '0.0.0.0', '255.255.255.255');
out.classify = [...new Set(sample)].map(ip => ({ ip, c: pm.classify(ip) }));

// ---------------------------------------------------------------- 改寫決策
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cdnvec-'));
function makeOpt(trialMode) {
    const opt = new CdnOptimizer({
        enabled: true, trialTtl: 10, v6Policy: 'drop', trialMode, dbFile: path.join(tmp, `db-${trialMode}.json`), harvestFile: path.join(tmp, `h-${trialMode}.json`),
        providers: { cloudflare: { enabled: true }, akamai: { enabled: true, ecs: true }, fastly: { enabled: true } },
        ecs: { twSubnets: [] }
    });
    clearInterval(opt.db.timer);
    opt.pools.persist = () => {};
    opt.pools.zoneNote = function (provider, ip, ok) {   // 不寫檔
        const k = `${provider}|${ip}`;
        const z = this.zone[k] || (this.zone[k] = { hit: 0, miss: 0 });
        if (ok) z.hit++; else z.miss++;
    };
    opt.pools._zone = {};
    return opt;
}
const P = {
    cfPool4: [{ ip: '104.16.161.36', ms: 3 }, { ip: '104.18.20.216', ms: 4 }],
    cfGlobal: ['104.21.0.0/24', '172.67.0.0/24'], cfTw: ['104.16.161.0/24'], cfDead: ['104.17.0.0/24'],
    cfRange4: ['104.16.0.0/13', '172.64.0.0/13'], cfRange6: ['2606:4700::/32'],
    fastlyPool4: [
        { ip: '151.101.76.2', pop: 'HKG', ms: 26, jitter: 1, loss: 0, score: 28 },
        { ip: '151.101.77.9', pop: 'HKG', ms: 27, jitter: 1, loss: 0, score: 29 },
        { ip: '151.101.0.5', pop: 'NRT', ms: 48, jitter: 2, loss: 0, score: 52 },
    ],
    fastlyPrefixes: { HKG: ['151.101.76', '151.101.77', '151.101.78'], NRT: ['151.101.0', '151.101.1'] },
};
out.pools = P;
function reset(opt, sc) {
    const cf = opt.pools.p.cloudflare;
    cf.pool4 = P.cfPool4.map(x => ({ ...x })); cf.pool6 = (sc.cfPool6 || []).map(ip => ({ ip, ms: 3 })); cf.bad = new Map();
    cf.global = new CidrSet().addMany(P.cfGlobal).finalize(); cf.tw = new CidrSet().addMany(P.cfTw).finalize();
    cf.dead = new CidrSet().addMany(P.cfDead).finalize();
    cf.range4 = new CidrSet().addMany(P.cfRange4).finalize(); cf.range6 = new CidrSet().addMany(P.cfRange6).finalize();
    cf.tw48 = new CidrSet().finalize();
    const f = opt.pools.p.fastly;
    f.pool4 = P.fastlyPool4.map(x => ({ ...x })); f.pool6 = []; f.bad = new Map(); f.bad24 = new Map(); f.prefixes = JSON.parse(JSON.stringify(P.fastlyPrefixes));
    opt.pools._zone = {};
    for (const [p, ip, ok] of sc.zone || []) opt.pools.zoneNote(p, ip, ok);
}
const svcb = (v4, v6) => {
    const parts = [Buffer.from([0, 1, 0])];
    const p = (k, v) => { const h = Buffer.alloc(4); h.writeUInt16BE(k); h.writeUInt16BE(v.length, 2); parts.push(h, v); };
    p(1, Buffer.from([2, 0x68, 0x33, 2, 0x68, 0x32]));
    p(4, Buffer.concat(v4.map(ip => Buffer.from(ip.split('.').map(Number)))));
    if (v6) { const b = Buffer.alloc(16); b.writeUInt16BE(0x2606, 0); b.writeUInt16BE(0x4700, 2); b[15] = 1; p(6, b); }
    return Buffer.concat(parts);
};
const SC = [
    { name: 'cf-trial', q: 'A', ans: [['A', '104.21.0.5'], ['A', '172.67.0.9']] },
    { name: 'cf-ok', q: 'A', ans: [['A', '104.21.0.5']], v4: { verdict: 'ok', ip: '104.16.161.36', ips: ['104.16.161.36', '104.18.20.216'] } },
    { name: 'cf-ok-partial', q: 'A', ans: [['A', '104.21.0.5']], v4: { verdict: 'ok', ip: '104.18.20.216', ips: ['104.18.20.216', '9.9.9.9'] } },
    { name: 'cf-ok-gone', q: 'A', ans: [['A', '104.21.0.5']], v4: { verdict: 'ok', ip: '1.2.3.4' } },
    { name: 'cf-fail', q: 'A', ans: [['A', '104.21.0.5']], v4: { verdict: 'fail', ip: '104.16.161.36', reason: 'x' } },
    { name: 'cf-fail-tried', q: 'A', ans: [['A', '104.21.0.5']], v4: { verdict: 'fail', ip: '104.16.161.36', reason: 'TLS（試了 2 個網段）' }, zone: [['cloudflare', '104.16.161.36', false], ['cloudflare', '104.16.161.36', false]] },
    { name: 'cf-fail-restricted', q: 'A', ans: [['A', '104.21.0.5']], v4: { verdict: 'fail', ip: '104.16.161.36', reason: 'x' }, zone: [['cloudflare', '104.16.161.36', false], ['cloudflare', '104.16.161.36', false]] },
    { name: 'cf-expired', q: 'A', ans: [['A', '104.21.0.5']], v4: { verdict: 'ok', ip: '104.16.161.36', hours: -1 } },
    { name: 'cf-unknown-pending', q: 'A', ans: [['A', '104.21.0.5']], v4: { verdict: 'unknown' } },
    { name: 'cf-tw', q: 'A', ans: [['A', '104.16.161.99']] },
    { name: 'cf-dead', q: 'A', ans: [['A', '104.17.0.9']] },
    { name: 'cf-unknown-range', q: 'A', ans: [['A', '104.20.1.1']] },
    { name: 'cf-cname', q: 'A', ans: [['CNAME', 'site.cdn.cloudflare.net'], ['A', '104.21.0.5']], v4: { verdict: 'ok', ip: '104.16.161.36' } },
    { name: 'cf-cname-only', q: 'A', ans: [['CNAME', 'x.cdn.cloudflare.net'], ['A', '9.9.9.9']] },
    { name: 'cf-mixed-other', q: 'A', ans: [['A', '9.9.9.9'], ['A', '104.21.0.5']], v4: { verdict: 'ok', ip: '104.16.161.36' } },
    { name: 'cf-mixed-faster', q: 'A', ans: [['A', '9.9.9.9'], ['A', '104.21.0.5']], cached: { '9.9.9.9': 1 } },
    { name: 'cf-v6-drop', q: 'AAAA', ans: [['AAAA', '2606:4700:3030::1'], ['AAAA', '2001:db8::1']] },
    { name: 'cf-v6-trial', q: 'AAAA', ans: [['AAAA', '2606:4700:3030::1']], cfPool6: ['2606:4700:10::1'] },
    { name: 'cf-v6-ok', q: 'AAAA', ans: [['AAAA', '2606:4700:3030::1']], cfPool6: ['2606:4700:10::1'], v6: { verdict: 'ok', ip: '2606:4700:10::1' } },
    { name: 'cf-v6-fail', q: 'AAAA', ans: [['AAAA', '2606:4700:3030::1']], cfPool6: ['2606:4700:10::1'], v6: { verdict: 'fail', ip: '2606:4700:10::1' } },
    { name: 'cf-https-trial', q: 'HTTPS', ans: [['HTTPS', ['104.21.0.7'], true]] },
    { name: 'cf-https-ok', q: 'HTTPS', ans: [['HTTPS', ['104.21.0.7'], true]], v4: { verdict: 'ok', ip: '104.16.161.36', ips: ['104.16.161.36', '104.18.20.216'] } },
    { name: 'cf-https-v6pool', q: 'HTTPS', ans: [['HTTPS', ['104.21.0.7'], true]], cfPool6: ['2606:4700:10::1'], v4: { verdict: 'ok', ip: '104.16.161.36' }, v6: { verdict: 'ok', ip: '2606:4700:10::1' } },
    { name: 'cf-https-v6trial', q: 'HTTPS', ans: [['HTTPS', ['104.21.0.7'], true]], cfPool6: ['2606:4700:10::1'], v4: { verdict: 'ok', ip: '104.16.161.36' } },
    { name: 'cf-https-tw', q: 'HTTPS', ans: [['HTTPS', ['104.16.161.7'], false]] },
    { name: 'cf-never', q: 'A', ans: [['A', '104.21.0.5']], policy: 'never' },
    { name: 'cf-always', q: 'A', ans: [['A', '104.21.0.5']], policy: 'always' },
    { name: 'cf-alias-mode', q: 'A', ans: [['A', '104.21.0.5']], trialMode: 'alias' },
    { name: 'cf-alias-mode-https', q: 'HTTPS', ans: [['HTTPS', ['104.21.0.7'], true]], trialMode: 'alias' },
    { name: 'ak-new', q: 'A', ans: [['CNAME', 'e1.dscx.akamaiedge.net'], ['A', '23.1.1.1']] },
    { name: 'ak-new-aaaa', q: 'AAAA', ans: [['CNAME', 'e1.dscx.akamaiedge.net'], ['AAAA', '2600:1400::1']] },
    { name: 'ak-ok', q: 'A', ans: [['CNAME', 'e1.dscx.akamaiedge.net'], ['A', '23.1.1.1']], ecs: { verdict: 'ok', ips4: ['23.2.2.2'], ips6: [], gainMs: 30 } },
    { name: 'ak-ok-aaaa', q: 'AAAA', ans: [['CNAME', 'e1.dscx.akamaiedge.net'], ['AAAA', '2600:1400::1']], ecs: { verdict: 'ok', ips4: ['23.2.2.2'], ips6: ['2600:1400::9'] } },
    { name: 'ak-none-slow', q: 'A', ans: [['CNAME', 'e1.dscx.akamaiedge.net'], ['A', '23.1.1.1']], ecs: { verdict: 'none' }, cached: { '23.1.1.1': 45 } },
    { name: 'ak-none-fast', q: 'A', ans: [['CNAME', 'e1.dscx.akamaiedge.net'], ['A', '23.1.1.1']], ecs: { verdict: 'none' }, cached: { '23.1.1.1': 5 } },
    { name: 'ak-none-cross', q: 'A', ans: [['CNAME', 'e1.dscx.akamaiedge.net'], ['A', '23.1.1.1']], ecs: { verdict: 'none' }, cross: { verdict: 'ok', to: 'cloudflare', ips: ['104.16.161.36'], ms: 4, origMs: 40 } },
    { name: 'bunny-nocache', q: 'A', ans: [['CNAME', 'x.b-cdn.net'], ['A', '5.5.5.5']] },
    { name: 'bunny-cross', q: 'AAAA', ans: [['CNAME', 'x.b-cdn.net'], ['AAAA', '2a02::5']], cross: { verdict: 'ok', to: 'cloudflare', ips: ['104.16.161.36'], ms: 4, origMs: 40 } },
    { name: 'fastly-faster-other', q: 'A', ans: [['A', '203.69.141.59'], ['A', '151.101.67.6']], cached: { '203.69.141.59': 6, '151.101.67.6': 64 } },
    { name: 'fastly-trial', q: 'A', ans: [['A', '185.199.110.133'], ['A', '185.199.108.133']], cached: { '185.199.110.133': 63, '185.199.108.133': 63 } },
    { name: 'fastly-ok', q: 'A', ans: [['A', '185.199.110.133'], ['A', '185.199.108.133']], cached: { '185.199.110.133': 63 }, zone: [['fastly', '151.101.76.133', true]], v4: { verdict: 'ok', ip: '151.101.76.133', algo: 2 } },
    { name: 'fastly-ok-octet-changed', q: 'A', ans: [['A', '151.101.65.140']], cached: { '151.101.65.140': 63 }, zone: [['fastly', '151.101.76.133', true]], v4: { verdict: 'ok', ip: '151.101.76.133', algo: 2 } },
    { name: 'fastly-aaaa-ok', q: 'AAAA', ans: [['AAAA', '2606:50c0:8000::133']], v4: { verdict: 'ok', ip: '151.101.76.133', algo: 2 } },
    { name: 'fastly-aaaa-trial', q: 'AAAA', ans: [['AAAA', '2606:50c0:8000::133']] },
    { name: 'fastly-close', q: 'A', ans: [['A', '151.101.65.140']], cached: { '151.101.65.140': 30 } },
    { name: 'fastly-nocache', q: 'A', ans: [['A', '151.101.65.140']] },
    { name: 'fastly-cross-a', q: 'A', ans: [['A', '151.101.1.140'], ['A', '151.101.65.140']], cross: { verdict: 'ok', to: 'cloudflare', ips: ['104.16.161.36'], ms: 4, origMs: 62 } },
    { name: 'fastly-cross-aaaa', q: 'AAAA', ans: [['AAAA', '2a04:4e42::396']], cross: { verdict: 'ok', to: 'cloudflare', ips: ['104.16.161.36'], ms: 4, origMs: 62 } },
    { name: 'fastly-cross-https', q: 'HTTPS', ans: [['HTTPS', ['151.101.1.140'], true]], cross: { verdict: 'ok', to: 'cloudflare', ips: ['104.16.161.36'], ms: 4, origMs: 62 } },
    { name: 'fastly-cross-recheck', q: 'A', ans: [['A', '151.101.1.140']], cached: { '151.101.1.140': 62 }, cross: { verdict: 'ok', to: 'cloudflare', ips: ['104.16.161.36'], ms: 4, origMs: 62, recheck: -1 } },
    { name: 'fastly-cross-wait', q: 'A', ans: [['A', '151.101.1.140']], cached: { '151.101.1.140': 62 }, cross: { verdict: 'fail' } },
    { name: 'fastly-https-trial', q: 'HTTPS', ans: [['HTTPS', ['151.101.65.140'], false]], cached: { '151.101.65.140': 63 } },
    { name: 'fastly-https-ok', q: 'HTTPS', ans: [['HTTPS', ['151.101.65.133'], true]], zone: [['fastly', '151.101.76.133', true]], v4: { verdict: 'ok', ip: '151.101.76.133', algo: 2 } },
];
const now = Date.now();
const enc = (sc) => sc.ans.map(([t, a, b]) => {
    const name = `${sc.name}.test`;
    if (t === 'HTTPS') return { type: 'UNKNOWN_65', name, ttl: 300, class: 'IN', data: svcb(a, b) };
    return { type: t, name, ttl: 300, class: 'IN', data: a };
});
const show = (m) => m.answers.map(a => a.type === 'UNKNOWN_65' ? `HTTPS ${JSON.stringify(dm.svcbHints(a.data))}` : `${a.type} ${a.data} ${a.ttl}`);
out.scenarios = [];
const opts = { original: makeOpt('original'), alias: makeOpt('alias') };
for (const sc of SC) {
    const opt = opts[sc.trialMode || 'original'];
    reset(opt, sc);
    const name = `${sc.name}.test`;
    const bg = [];
    opt.verifier.schedule = (n, p, f, o) => { bg.push(['verify', n, p, f, o || null]); };
    opt.ecs.schedule = (n, a, b) => { bg.push(['ecs', n]); };
    opt.cross.schedule = (n, from, o) => { bg.push(['cross', n, from, o]); };
    opt.pools.tryV6 = async (p, ip) => { bg.push(['tryV6', p, ip]); };
    const oc = iprank.cached, ol = iprank.latency;
    iprank.cached = ip => (sc.cached && sc.cached[ip] !== undefined) ? { ok: true, ms: sc.cached[ip] } : undefined;
    iprank.latency = async ip => { bg.push(['latency', ip]); return { ok: false, ms: Infinity }; };
    const provider = sc.name.startsWith('cf') ? 'cloudflare' : sc.name.startsWith('fastly') ? 'fastly' : sc.name.startsWith('ak') ? 'akamai' : 'bunny';
    if (sc.v4 || sc.v6 || sc.policy || sc.ecs || sc.cross) opt.db.touch(name, provider, 'ip', {});
    for (const fam of [4, 6]) {
        const v = sc[`v${fam}`];
        if (v) opt.db.setVerdict(name, fam, { ...v, hours: undefined, until: now + (v.hours || 1) * 3600e3 });
    }
    if (sc.policy) opt.db.setPolicy(name, sc.policy);
    if (sc.ecs) opt.db.setEcs(name, { ...sc.ecs, until: now + 3600e3 });
    if (sc.cross) opt.db.setCross(name, { ...sc.cross, recheck: undefined, from: provider, until: now + 86400e3, recheckAt: now + (sc.cross.recheck || 1) * 3600e3 });
    const m = { rcode: 'NOERROR', answers: enc(sc), authorities: [] };
    const qt = sc.q === 'HTTPS' ? 'UNKNOWN_65' : sc.q;
    const r = opt.apply(m, name, qt);
    iprank.cached = oc; iprank.latency = ol;
    out.scenarios.push({
        ...sc, answers: show(m),
        result: { ttlCap: r.ttlCap, tags: r.tags, provider: r.provider || null, rewritten: r.rewritten || null, crossTo: r.crossTo || null, gainMs: r.gainMs ?? null },
        bg
    });
}

fs.writeFileSync(path.join(__dirname, 'cases.json'), JSON.stringify(out, null, 1) + '\n');
console.log(`寫入 ${path.join(__dirname, 'cases.json')}：CNAME ${out.cname.length}、標頭 ${out.headers.length}、錯誤頁 ${out.broken.length}、同站 ${out.sameSite.length}、分類 ${out.classify.length}、改寫 ${out.scenarios.length}`);
process.exit(0);
