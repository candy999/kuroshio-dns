'use strict';
// 產生過濾引擎的對照向量：用 node 版 legacy-node/lib/filter.js 實際判定，寫成 cases.json，
// Rust 版 crates/kuroshio-filter/tests/parity.rs 讀進來逐筆比對。
//
// 執行：node tests/vectors/filter/gen.js
// （需要 legacy-node/node_modules/dns-packet：在 legacy-node 執行 npm ci --omit=dev）
//
// 清單內容直接寫進 node 版的快取目錄（_listFile(url)），不經過網路。
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.resolve(__dirname, '../../..');
const { FilterEngine } = require(path.join(ROOT, 'legacy-node/lib/filter.js'));
const types = require(path.join(ROOT, 'legacy-node/node_modules/dns-packet/types.js'));

// ---------------------------------------------------------------- 規則
const CUSTOM = [
    '﻿||bom-first.example^',
    '! 註解',
    '# 註解',
    '||Custom-Block.example^',
    '@@||allow.list-block.example^',
    '! @begin 遙測',
    '||tele-section.example^',
    '0.0.0.0 hosts-in-custom.example',
    '! @end',
    '# @begin MALWARE',
    '||mal-section.example^',
    '/^evil[0-9]+\\.example$/',
    '! @begin ads',
    '||ads-section.example^',
    '!@end',
    '||after-end.example^',
    '! @beginning 不是段落',
    '||not-section.example^',
    '@@*dnsotls-ds.metric.gstatic.com^',
    '||cl*.apple.com^',
    '@@||cl3.apple.com^',
    '||dup-in-custom.example^',
    '! @begin malware',
    '||dup-in-custom.example^',
    '! @begin 未知分類',
    '||unknown-section.example^',
    '! @end',
    '||only-aaaa.custom.example^$dnstype=AAAA',
    '||not-https.custom.example^$dnstype=~HTTPS',
    '||imp.custom.example^$important',
    '@@||imp.custom.example^',
    '||custom-bad.example^',
    '||custom-bad.example^$badfilter',
    '|exact-custom.example^',
    'plain-custom.example',
    '||trailing-dot.example.^',
    '||third.custom.example^$third-party',
    '  ||spaced.custom.example^  ',
    '||list-block.example^$important',
    '||mixed-tier.example^',
].join('\r\n');

const L_ADS = [
    '[Adblock Plus 2.0]',
    '! Title: 測試清單',
    '||ads.example.com^',
    '||ADS-UPPER.Example.COM^',
    '@@||good.ads.example.com^',
    '||tracker.example.net^$important',
    '@@||tracker.example.net^',
    '||third.example^$third-party',
    '||script.example^$script,important',
    '||url.example/path',
    '||url-slash.example^/',
    'example.com##.banner',
    'example.org#@#.banner',
    '||cosmetic.example$$script',
    '||onlyaaaa.list.example^$dnstype=AAAA',
    '||multi.list.example^$dnstype=A|AAAA',
    '||nottxt.list.example^$dnstype=~TXT',
    '||emptydt.list.example^$dnstype=',
    '||truedt.list.example^$dnstype',
    '||important-empty.example^$important=',
    '||client.example^$client=1.2.3.4',
    '||client-empty.example^$client=',
    '||dnsrewrite.example^$dnsrewrite=1.2.3.4',
    '||denyallow.example^$denyallow=x.com',
    '||matchcase.example^$match-case',
    '||unknownmod.example^$foo',
    '||bad.example.com^',
    '||bad.example.com^$badfilter',
    '||wild-bad*.example^',
    '||wild-bad*.example^$badfilter',
    '|exact.example.com^',
    '|exact-pipe.example.com|',
    '|prefix.example.com',
    'plain-domain.example.com',
    'plain-trailing.example.com.',
    '/^ad[0-9]+\\.regex\\.test$/',
    '/^ad[0-9]+\\.regexi\\.test$/$important',
    '/tracking\\.(foo|bar)\\.test/$dnstype=AAAA',
    '/^(?!keep)[a-z]+\\.look\\.test$/',
    '/(?<=x)lookbehind\\.test/',
    '/unterminated(/',
    '/badmod\\.test/$third-party',
    '/MiXeD\\.Case\\.Test/',
    '/^[^.]+\\.single\\.test$/',
    '||*.wild.example^',
    '||ad*.wild2.example^',
    '*wild3*.example',
    'ad*.unanchored.example^',
    '|start*.example^',
    '||end-anchor.example|',
    '||caret-mid^.example',
    '*',
    '^',
    '||x',
    '_dmarc.underscore.example',
    '-bad-.example',
    'xn--fiqs8s.example',
    '例子.台灣',
    '||例子.台灣^',
    '||ex%2e.example^',
    '  ||leading-space.example^  ',
    '||crlf.example^\r',
    '@@0.0.0.0 allow-hosts.example',
    '||dup.example^',
    '||cat-up.example^',
    '@@||mixed.example^',
    '||mixed.example^',
    '||imp-cat.example^$important',
    '||imp-arr.example^$important',
    '||list-block.example^',
    '||allow.list-block.example^',
    '||mixed-tier.example^$important',
    '||Tld',
    'single',
].join('\n');

const L_HOSTS = [
    '# hosts 格式',
    '127.0.0.1 localhost',
    '::1 localhost',
    'fe80::1%lo0 localhost',
    '0.0.0.0 0.0.0.0',
    '0.0.0.0 hosts1.example',
    '127.0.0.1 hosts2.example # 註解',
    '10.9.9.9 hidden.example',
    '1.2.3.4567 badip.example',
    '::  v6hosts.example',
    ':: ip6-localhost',
    '2001:db8::1 v6addr.example extra.example',
    'abc: hexcolon.example',
    '0.0.0.0 HOSTS-UPPER.Example',
    '0.0.0.0 trailing-dot-hosts.example.',
    '0.0.0.0 bad_domain!.example',
    '0.0.0.0\ttab.example',
    '0.0.0.0 #commented.example',
    '0.0.0.0 dup.example',
    '0.0.0.0 cat-up.example',
    '0.0.0.0 broadcasthost',
    '0.0.0.0 local',
    '||arr.example^$dnstype=AAAA',
    '||arr.example^',
    '||arr2.example^',
    '||arr2.example^$dnstype=AAAA',
    '0.0.0.0 tele-cname.example',
].join('\n');

const L_MAL = [
    '||dup.example^',
    '||cat-up.example^',
    '||mixed.example^',
    '||imp-cat.example^',
    '||imp-cat.example^$important',
    '||imp-arr.example^$important',
    '||bad.example.com^',
    '||BAD.example.com^',
    '||overlap.example^',
    '||arr.example^',
    '||arr2.example^',
    '||mal-cname.example^',
].join('\n');

const L_OFF = '||off.example^\n||ads.example.com^\n';
const L_PLAIN = 'dup.example\noverlap.example\nplain-list.example\n@@||imp-arr.example^\n';
const L_TELE = '||imp-arr.example^$important\n||overlap.example^\n||t1.example^\n';

const SELFTEST_LIST = [
    '! comment', '[Adblock Plus 2.0]',
    '||gs-loc.apple.com^',
    '||ads.example.com^',
    '||tracker.example.net^$important',
    '@@||good.ads.example.com^',
    '0.0.0.0 hosts-blocked.example.org',
    '||thirdparty.example.com^$third-party',
    '||example.org/ads/banner.js',
    'example.com##.ad-banner',
    '||onlyaaaa.example.com^$dnstype=AAAA',
    '||bad.example.com^',
    '||bad.example.com^$badfilter',
    '|exact.example.com^',
    'plain-domain.example.com',
    '/^ad[0-9]+\\.regex\\.test$/',
    '||mmstat.com^'
].join('\n');

const CRAFTED_LISTS = [
    { name: 'ads', category: 'ads', text: L_ADS },
    { name: 'hosts', category: 'telemetry', text: L_HOSTS },
    { name: 'malware', category: 'malware', text: L_MAL },
    { name: 'off', category: 'ads', enabled: false, text: L_OFF },
    { name: 'plain', category: 'ads', text: L_PLAIN },
    { name: 'tele', category: 'telemetry', text: L_TELE },
];

const SCENARIOS = [
    { name: 'crafted', relaxedModifiers: false, custom: [CUSTOM], lists: CRAFTED_LISTS, qtypes: [1, 28, 65, 16] },
    { name: 'crafted-relaxed', relaxedModifiers: true, custom: [CUSTOM], lists: CRAFTED_LISTS, qtypes: [1, 28] },
    { name: 'lists-only', relaxedModifiers: false, custom: [], lists: CRAFTED_LISTS.slice(1), qtypes: [1, 65] },
    {
        name: 'default-custom-rules',
        relaxedModifiers: false,
        customFiles: ['rules/default-custom-rules.txt'],
        lists: [{ name: 'selftest', category: 'ads', text: SELFTEST_LIST }],
        qtypes: [1, 28],
    },
];

// ---------------------------------------------------------------- 查詢名稱
const EXTRA = ['', '.', 'com', 'example', 'example.com', 'www.google.com', 'a.b.c.d.e.f.example.com', 'ad12.regex.test', 'adx.regex.test',
    'ad7.regexi.test', 'tracking.foo.test', 'x.tracking.bar.test', 'keep.look.test', 'drop.look.test', 'xlookbehind.test', 'mixed.case.test',
    'a.single.test', 'a.b.single.test', 'x.wild.example', 'wild.example', 'ad1.wild2.example', 'x.ad.wild2.example', 'awild3b.example',
    'a.wild3.example', 'ad5.unanchored.example', 'xad5.unanchored.example', 'ad5.unanchored.example.com', 'start1.example', 'xstart1.example',
    'end-anchor.example', 'x.end-anchor.example', 'caret-mid.example', 'x', 'tld', 'a.tld', 'single', 'a.single',
    'cl3.apple.com', 'cl4.apple.com', 'x.cl4.apple.com', 'dnsotls-ds.metric.gstatic.com', 'a.dnsotls-ds.metric.gstatic.com',
    'evil1.example', 'evil.example', 'x.netseer-ipaddr-assoc.abc.fbcdn.net', 'gs-loc.apple.com', 'mmstat.com', 'a.b.mmstat.com',
    'wild-bad1.example', 'prefix.example.com', 'prefix.example.community', 'x.prefix.example.com', 'exact-pipe.example.com',
    'sub.exact-pipe.example.com', 'example.com.', 'EXAMPLE.COM..', 'ads.example.com.', 'Ads.Example.Com', 'xn--fiqs8s.example',
    '例子.台灣', 'ex%2e.example', '0.0.0.0', 'allow-hosts.example', '1.2.3.4', 'a..b.dup.example', '.dup.example'];

function domainsOf(text) {
    const out = new Set();
    for (const m of text.matchAll(/[A-Za-z0-9_\-.*%一-鿿]+\.[A-Za-z0-9_\-一-鿿]+/g)) {
        const d = m[0].replace(/^[|.@*]+/, '');
        for (const fill of d.includes('*') ? ['3', 'x', ''] : ['']) out.add(d.replace(/\*/g, fill));
    }
    return [...out];
}

function variants(d, rich) {
    const v = [d, 'sub.' + d];
    const i = d.indexOf('.');
    if (i > 0) v.push(d.substring(i + 1));
    if (rich) v.push(d.toUpperCase() + '.', 'a.b.' + d, 'x' + d);
    return v;
}

// ---------------------------------------------------------------- 執行
function run(sc) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kfvec-'));
    const customRules = [];
    (sc.custom || []).forEach((t, i) => { const f = path.join(dir, `custom${i}.txt`); fs.writeFileSync(f, t); customRules.push(f); });
    for (const f of sc.customFiles || []) customRules.push(path.join(ROOT, f));
    const lists = sc.lists.map(l => ({ url: `https://vectors.invalid/${l.name}.txt`, category: l.category, name: l.name, ...(l.enabled === false ? { enabled: false } : {}) }));
    const fe = new FilterEngine({ customRules, lists, cacheDir: path.join(dir, 'cache'), relaxedModifiers: sc.relaxedModifiers });
    sc.lists.forEach((l, i) => fs.writeFileSync(fe._listFile(lists[i].url), l.text));
    const log = console.log; console.log = () => { };
    fe.load();
    console.log = log;

    const texts = [...(sc.custom || []), ...(sc.customFiles || []).map(f => fs.readFileSync(path.join(ROOT, f), 'utf-8')), ...sc.lists.map(l => l.text)];
    const rich = sc.name !== 'default-custom-rules';
    const names = new Set(EXTRA);
    for (const t of texts) for (const d of domainsOf(t)) for (const v of variants(d, rich)) names.add(v);

    const cases = [];
    for (const n of [...names].sort()) {
        for (const qt of sc.qtypes) {
            const r = fe.check(n, types.toString(qt));
            cases.push(r.action === 'none' ? [n, qt, 'none'] : [n, qt, r.action, r.tier, r.cat, r.rule]);
        }
    }

    // CNAME 鏈（同 resolver._store）
    const chains = [
        ['clean.example', ['mal-cname.example'], 1],
        ['clean.example', ['ok.example', 'tele-cname.example', 'mal-cname.example'], 1],
        ['clean.example', ['good.ads.example.com', 'ads.example.com'], 28],
        ['allow.list-block.example', ['mal-cname.example'], 1],
        ['cl3.apple.com', ['ads.example.com'], 1],
        ['ads.example.com', ['mal-cname.example'], 1],
        ['clean.example', ['ok.example', 'MAL-CNAME.example.'], 65],
        ['clean.example', [], 1],
        ['clean.example', ['onlyaaaa.list.example'], 1],
        ['clean.example', ['onlyaaaa.list.example'], 28],
    ].map(([q, targets, qt]) => {
        const self = fe.check(q, types.toString(qt));
        let hit = null;
        if (self.action !== 'allow') {
            for (const t of targets.map(t => t.toLowerCase().replace(/\.$/, ''))) {
                const f = fe.check(t, types.toString(qt));
                if (f.action === 'block') { hit = f; break; }
            }
        }
        return [q, targets, qt, hit ? hit.cat : null, hit ? hit.rule : null];
    });

    const s = fe.stats;
    return {
        name: sc.name,
        relaxedModifiers: sc.relaxedModifiers,
        custom: sc.custom || [],
        customFiles: sc.customFiles || [],
        lists: sc.lists.map(l => ({ name: l.name, category: l.category, enabled: l.enabled !== false, text: l.text })),
        stats: { custom: s.custom, lists: s.lists, byCategory: s.byCategory, skipped: s.skipped },
        cases,
        chains,
    };
}

const out = { generator: 'tests/vectors/filter/gen.js', node: process.version, scenarios: SCENARIOS.map(run) };
const dest = path.join(__dirname, 'cases.json');
// 每筆查詢一行，方便看 diff
const body = out.scenarios.map(sc => {
    const { cases, chains, ...meta } = sc;
    const head = JSON.stringify(meta).slice(0, -1);
    return `${head},\n"chains":[\n${chains.map(c => JSON.stringify(c)).join(',\n')}],\n"cases":[\n${cases.map(c => JSON.stringify(c)).join(',\n')}]}`;
});
fs.writeFileSync(dest, `{"generator":${JSON.stringify(out.generator)},"node":${JSON.stringify(out.node)},"scenarios":[\n${body.join(',\n')}]}\n`);
JSON.parse(fs.readFileSync(dest, 'utf-8'));
const total = out.scenarios.reduce((a, s) => a + s.cases.length, 0);
console.log(`已寫入 ${path.relative(ROOT, dest)}：${out.scenarios.length} 組情境、${total} 筆查詢`);
for (const s of out.scenarios) console.log(`  ${s.name}: ${s.cases.length} 筆，stats ${JSON.stringify(s.stats)}`);
