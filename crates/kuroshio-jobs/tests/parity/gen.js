'use strict';
// 產生 2.x 對照向量：node crates/kuroshio-jobs/tests/parity/gen.js > crates/kuroshio-jobs/tests/parity/vectors.json
//
// - rules：直接呼叫 legacy-node/jobs/lib/benchmark-rules.js
// - select：從 legacy-node/jobs/dns-benchmark.js 原文切出 extendedMetrics / itemsOf / greedy / greedyCsv / bestPerAsn
//   與 Phase 3 那一段（不改一個字）來跑，確保 Rust 版的選擇結果跟 2.x 完全一樣
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..', '..', '..', '..');
const R = require(path.join(root, 'legacy-node/jobs/lib/benchmark-rules.js'));
const src = fs.readFileSync(path.join(root, 'legacy-node/jobs/dns-benchmark.js'), 'utf-8');

function slice(from, to) {
    const a = src.indexOf(from);
    const b = src.indexOf(to, a + from.length);
    if (a < 0 || b < 0) throw new Error(`找不到 ${from}`);
    return src.slice(a, b);
}
const fnSrc = slice('function extendedMetrics(', '// ---------------- 主流程');
const phase3 = slice('    // Phase 3：選出執行期上游', '    const state = {');
const lib = new Function('R', `${fnSrc}\nreturn { extendedMetrics, itemsOf, greedy, greedyCsv, bestPerAsn };`)(R);
const runPhase3 = new Function('config', 'bc', 'finals', 'asnBest', 'total', 'greedy', 'itemsOf',
    `${phase3}\nreturn { selected: selected.map(x => [x.srv.id, x.newly, x.why]), covered: covered.size };`);

// 固定種子的亂數
let seed = 20261110;
const rnd = () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x80000000; };
const pick = a => a[Math.floor(rnd() * a.length)];

// ---------------- rules ----------------
const cache = JSON.parse(fs.readFileSync(path.join(root, 'data/benchmark/cidr_cache.json'), 'utf-8').replace(/^﻿/, ''));
const infos = Object.values(cache).filter((_, i) => i % 7 === 0).slice(0, 150);
const domains = fs.readFileSync(path.join(root, 'data/benchmark/web.txt'), 'utf-8').replace(/^﻿/, '').split(/\r?\n/).map(s => s.trim()).filter(Boolean);
const extra = ['x.com', 'abs.twimg.com', 'www.google.com.tw', 'a.b.co.jp', 'line-apps.com', 'net', 'foo.net.tw', 'ne.jp', 'WWW.APPLE.COM', 'localhost'];
const allDomains = [...domains, ...extra];

const kwInputs = [
    'Cloudflare, Inc. Cloudflare, Inc. AS13335 Cloudflare, Inc.',
    'G-Core Labs S.A. G-Core Labs AS199524 G-Core Labs S.A.',
    'So-net Entertainment Taiwan AS9924 So-net',
    'Chunghwa Telecom Co., Ltd. Data Communication Business Group AS3462',
    '123 1e5 0x1F 0o17 0b101 1_000 Infinity NaN ab_1 _1 e5 1e 0x',
    'Ünïcode İstanbul Straße Ελληνικά 中華電信 AS4134',
    'tab\there nbsp　ideo﻿bom\u0085nel',
    '', 'a', 'AS', 'inc llc ltd corp',
];
for (const i of infos.slice(0, 400)) kwInputs.push(i.raw.replace(/_/g, ' '));

const sameGroup = [], trusted = [], weight = [];
// 業者資訊放一張表，向量裡只放編號
const table = [...infos];
const ref = info => { table.push(info); return table.length - 1; };
const idx = () => Math.floor(rnd() * infos.length);
for (let n = 0; n < 1500; n++) {
    const a = idx(), b = idx();
    sameGroup.push([a, b, R.isSameGroup(table[a], table[b])]);
    trusted.push([a, b, R.isTrustedPartner(table[a], table[b])]);
    const d = pick(allDomains);
    weight.push([a, d, R.calculateWeight(table[a], d)]);
}
// 互信表裡的關鍵字組合（隨機抽樣很難碰到）
const kws = [...new Set([...Object.keys(R.TRUSTED_CROSS_ISPS), ...Object.keys(R.CDN_PARTNERS), ...R.TAIWAN_ISPS, ...R.GENERIC_ISP_KEYWORDS, ...R.GIANTS_ALLOWING_ISPS, 'sejong', 'zenlayer', 'random', 'Chinanet'])];
for (let n = 0; n < 800; n++) {
    const a = { raw: `X__AS${Math.floor(rnd() * 5)}`, keywords: [pick(kws), pick(kws)] };
    const b = { raw: `Y__AS${Math.floor(rnd() * 5) + 3}`, keywords: [pick(kws)] };
    const ia = ref(a), ib = ref(b);
    trusted.push([ia, ib, R.isTrustedPartner(a, b)]);
    sameGroup.push([ia, ib, R.isSameGroup(a, b)]);
}
for (const d of allDomains) {
    for (const k of ['google', 'apple', 'akamai', 'microsoft', 'facebook', 'cloudflare', 'twitter', 'line', 'netflix']) {
        const a = { raw: `${k}__AS1`, keywords: [k] };
        weight.push([ref(a), d, R.calculateWeight(a, d)]);
    }
}
const asnRaw = ['Cloudflare,_Inc.__AS13335_x', 'x__as4134', 'Unknown_ISP', 'BASS1', 'xAs12y', 'as', 'AS', 'clas99'];

// ---------------- select ----------------
const scenarios = [];
const types = ['udp', 'udp', 'udp', 'doh', 'dot', 'doq', 'tcp'];
const owners = ['A__AS1_A', 'B__AS2_B', 'C__AS3_C', 'D__AS1_D', 'Unknown', 'Unknown_ISP', 'E__AS5', 'F_no_asn'];
for (let n = 0; n < 120; n++) {
    const nSrv = 1 + Math.floor(rnd() * 20);
    const nDom = 1 + Math.floor(rnd() * 12);
    const ipPool = 2 + Math.floor(rnd() * 30);
    const servers = [];
    const universe = new Set();
    for (let i = 0; i < nSrv; i++) {
        let history = new Map();
        const copied = i > 0 && rnd() < 0.3;
        if (copied) history = new Map([...servers[Math.floor(rnd() * i)].history].map(([d, ips]) => [d, new Set(ips)]));
        const count = rnd() < 0.7 ? nDom : Math.floor(rnd() * (nDom + 1));
        for (let d = 0; d < nDom && !copied; d++) {
            if (rnd() < 0.3) continue;
            const ips = new Set();
            const k = 1 + Math.floor(rnd() * 3);
            for (let j = 0; j < k; j++) ips.add(`10.0.${Math.floor(rnd() * 2)}.${Math.floor(rnd() * ipPool)}`);
            history.set(`d${d}`, ips);
            for (const ip of ips) universe.add(`d${d}|${ip}`);
        }
        const avg = rnd() < 0.1 ? 9999 : pick([5, 10, 10, 15, 20, 30, 60, 120, 240, 260, 7.25, 12.5]);
        servers.push({ id: `s${i}`, owner: pick(owners), type: pick(types), pinned: rnd() < 0.12, latencies: new Array(count).fill(0), history, avg: () => avg, _avg: avg, ext: {} });
    }
    // 還有一些沒有任何上游覆蓋的項目（被判定汙染的 IP 也算在宇集裡）
    const total = universe.size + Math.floor(rnd() * 4);
    const totalDomains = nDom;
    const cfg = {
        upstream: { autoTypes: rnd() < 0.5 ? undefined : ['udp', 'doh', 'dot', 'doq'], autoMax: pick([undefined, 1, 2, 3, 5]) },
    };
    const bc = { coverageTarget: pick([undefined, 0.5, 0.8, 0.97, 1]), minAuto: pick([undefined, 1, 3, 4]), maxAvgLatencyMs: pick([undefined, 100, 250]) };
    const input = {
        servers: servers.map(s => ({ id: s.id, owner: s.owner, type: s.type, pinned: s.pinned, avg: s._avg, count: s.latencies.length, history: [...s.history].map(([d, ips]) => [+d.slice(1), [...ips]]) })),
        total, totalDomains, cfg, bc,
    };
    lib.extendedMetrics(servers, totalDomains);
    const finals = [...servers].sort((a, b) => a.avg() - b.avg());
    const asnBest = lib.bestPerAsn(finals);
    const g = (list, strategy) => { const r = lib.greedy(list, total, strategy); return { result: r.result.map(x => [x.srv.id, x.newly, x.total]), rest: r.rest.map(s => s.id) }; };
    const out = {
        ext: Object.fromEntries(servers.map(s => [s.id, s.ext])),
        finals: finals.map(s => s.id),
        asnBest: asnBest.map(s => s.id),
        coverage: g(finals, 'coverage'),
        latency: g(finals, 'latency'),
        asnCoverage: g(asnBest, 'coverage'),
        phase3: runPhase3(cfg, bc, finals, asnBest, total, lib.greedy, lib.itemsOf),
        csv: n % 10 === 0 ? lib.greedyCsv(finals, total, 'coverage') : null,
    };
    scenarios.push({ input, out });
}

process.stdout.write(JSON.stringify({
    keywords: kwInputs.map(s => [s, R.extractKeywords(s)]),
    asn: asnRaw.map(s => [s, R.extractAsnNumber(s)]),
    infos: table, sameGroup, trusted, weight, scenarios,
}));
