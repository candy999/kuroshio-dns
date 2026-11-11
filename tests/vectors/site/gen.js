'use strict';
// 產生公開網頁 / 使用偵測 / 統計的對照向量：用 node 版 legacy-node/lib/{site,check,stats,admin-api}.js 實際計算，
// 寫成 cases.json，Rust 版 crates/kuroshio/tests/site.rs 讀進來逐筆比對。
//
// 執行：node tests/vectors/site/gen.js（不需要 npm 套件）
//
// 內容：描述檔的固定 UUID 與識別碼（文字已改成黑潮 DNS，只比對機器讀的欄位）、主網域判斷、
//      IPv6 /64 分組、唯讀 API 清單。網域一律用保留給文件的 .example / .test。
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../../..');
const L = p => require(path.join(ROOT, 'legacy-node/lib', p));
const { Site } = L('site.js');
const { keyOf } = L('check.js');
const { siteOf } = L('stats.js');
const { READ_ONLY } = L('admin-api.js');

const pick = (xml, key) => [...xml.matchAll(new RegExp(`<key>${key}</key><string>([^<]*)</string>`, 'g'))].map(m => m[1]);

const hosts = ['dns.example', 'my-dns.home.example', 'a&b.test'];
const mobileconfig = [];
for (const h of hosts) {
    for (const kind of ['doh', 'dot']) {
        const xml = Site.prototype.mobileconfig.call({ cfg: { hostname: h } }, kind);
        mobileconfig.push({
            host: h, kind,
            uuids: pick(xml, 'PayloadUUID'),
            identifiers: pick(xml, 'PayloadIdentifier'),
            serverUrl: pick(xml, 'ServerURL'),
            serverName: pick(xml, 'ServerName')
        });
    }
}

const names = [
    'www.video.example', 'rr3---sn-x.videocdn.example', 'www.shop.example.com.tw', 'example.tw', 'news.example.co.uk', 'example.com.',
    'a.b.example.github.io', 'localhost', '1.2.3.4', '4.3.2.1.in-addr.arpa', 'nas.lan', 'printer.local', 'x.home', 'svc.internal',
    'WWW.Example.ORG', 'deep.sub.example.com.hk', 'www.example.web.app', 'a.b.c.d.example.test'
];
const sites = names.map(n => ({ name: n, site: siteOf(n) }));

// 只用正規寫法：node 版用字串切 /64，`2001:0db8:…` 這種非正規寫法會分到不同組（Rust 版以數值比對，會分在同一組）；
// 實際上 socket 給的位址都是正規寫法，兩邊結果一樣
const ips = ['192.0.2.1', '::ffff:192.0.2.1', '2001:db8:1:2::1', '2001:db8:1:2:ffff:ffff:ffff:ffff', '2001:db8:1:3::1',
    '2001:db8:1:2:0:0:0:9', 'fe80::1', '::1', '2001:db8::', '2001:db8::1:2:3:4'];
const groups = [];
for (let i = 0; i < ips.length; i++) for (let j = i + 1; j < ips.length; j++) groups.push({ a: ips[i], b: ips[j], same: keyOf(ips[i]) === keyOf(ips[j]) });

const out = { mobileconfig, sites, groups, readOnly: [...READ_ONLY].sort() };
fs.writeFileSync(path.join(__dirname, 'cases.json'), JSON.stringify(out, null, 1) + '\n');
console.log(`寫入 ${mobileconfig.length} 份描述檔、${sites.length} 個網域、${groups.length} 組 IP`);
