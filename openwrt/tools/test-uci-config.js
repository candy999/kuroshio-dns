'use strict';
// OpenWrt UCI → config 轉換測試：node openwrt/tools/test-uci-config.js（CI 也會跑）
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { parse } = require('./uci-to-json');

const ROOT = path.join(__dirname, '..', '..', 'legacy-node');
const REPO = path.join(__dirname, '..', '..');
const DEFAULT = fs.readFileSync(path.join(REPO, 'openwrt/candydns/files/candydns.config'), 'utf-8');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'candyuci-'));
// uci-config.js 安裝後與 config.js 放在同一個目錄
fs.copyFileSync(path.join(REPO, 'openwrt/candydns/files/uci-config.js'), path.join(ROOT, '.uci-config.test.js'));

let pass = 0, fail = 0;
function t(name, fn) {
    try { fn(); pass++; console.log(`  ✔ ${name}`); } catch (e) { fail++; console.log(`  ✘ ${name}\n     ${e.message}`); }
}
function load(text) {
    const f = path.join(tmp, 'uci.json');
    fs.writeFileSync(f, JSON.stringify(parse(text)));
    process.env.CANDYDNS_UCI_JSON = f;
    delete require.cache[require.resolve(path.join(ROOT, '.uci-config.test.js'))];
    return require(path.join(ROOT, '.uci-config.test.js'));
}

try {
    const gen = require('child_process').execFileSync(process.execPath, [path.join(__dirname, 'gen-uci.js')], { encoding: 'utf-8' });
    t('預設 UCI 檔與 config.js 同步（不同步請執行 node openwrt/tools/gen-uci.js > openwrt/candydns/files/candydns.config）', () => assert.strictEqual(gen, DEFAULT));

    const base = require(path.join(ROOT, 'config.js'));
    const d = load(DEFAULT);
    t('預設：dnsmasq 上游模式、只聽本機 5335', () => { assert.deepStrictEqual(d.listen.plain.binds, ['127.0.0.1', '::1']); assert.strictEqual(d.listen.plain.port, 5335); assert.strictEqual(d.resolver.localForward, undefined); });
    t('預設：固定上游清空（避免問路由器自己）', () => assert.deepStrictEqual(d.upstream.pinned, []));
    t('預設：DoH 直接 HTTPS、不信任 X-Forwarded-For', () => { assert.strictEqual(d.listen.doh.port, 8443); assert.strictEqual(d.listen.doh.trustProxy, false); assert.ok(d.listen.doh.cert); });
    t('預設：不帶入任何網域、DoH / DoT 關閉', () => {
        assert.strictEqual(d.site.hostname, ''); assert.strictEqual(d.listen.doh.enabled, false); assert.strictEqual(d.listen.dot.enabled, false);
        assert.deepStrictEqual(d.ddns.records, []);
    });
    t('預設：公開網頁關閉、DDNS 關閉', () => { assert.strictEqual(d.site.enabled, false); assert.strictEqual(d.ddns.enabled, false); });
    t('預設：數值參數沿用 config.js', () => { assert.deepStrictEqual(d.resolver, base.resolver); assert.deepStrictEqual(d.cdn.cross, base.cdn.cross); assert.deepStrictEqual(d.cdn.providers, base.cdn.providers); });
    // 載入器只帶入勾選的清單
    const baseOn = base.filter.lists.filter(l => l.enabled !== false).map(({ enabled, ...l }) => l);
    t('預設：過濾清單與 config.js 相同（只帶入預設勾選的）', () => assert.deepStrictEqual(d.filter.lists, baseOn));

    const custom = DEFAULT
        .replace("option redirect 'dnsmasq-upstream'", "option redirect 'exchange'")
        .replace("option listen_ipv6 '1'", "option listen_ipv6 '0'")
        .replace("config resolver 'resolver'", "config resolver 'resolver'\n\toption timeout_ms '2000'\n\toption fast_path '0'\n\toption cache_max ''")
        .replace("config cdn 'cdn'\n\toption enabled '1'", "config cdn 'cdn'\n\toption enabled '1'\n\toption trial_mode 'alias'\n\toption cross_min_orig_ms '30'\n\toption cross_enabled '0'")
        .replace("config cdn_provider 'fastly'\n\toption enabled '1'", "config cdn_provider 'fastly'\n\toption enabled '0'")
        .replace(/(config filter_list\n\toption enabled )'1'/, "$1'0'")
        .replace("config job 'cdn_scan'\n\toption enabled '1'\n\tlist at '03:20'\n\tlist weekday '0'", "config job 'cdn_scan'\n\toption enabled '0'\n\tlist at '02:00'\n\tlist at '14:00'\n\tlist weekday '3'\n\tlist weekday '6'")
        .replace("list pinned", "list pinned")
        .replace("config upstream 'upstream'", "config upstream 'upstream'\n\tlist pinned 'udp://168.95.1.1'\n\toption auto_max '3'")
        + "\nconfig filter_list\n\toption name 'My'\n\toption url 'https://example.com/my.txt'\n\toption category 'malware'\n";
    const c = load(custom);
    t('exchange：接管 53 埠，區網網域交給 dnsmasq（5354）', () => {
        assert.deepStrictEqual(c.listen.plain.binds, ['0.0.0.0']); assert.strictEqual(c.listen.plain.port, 53);
        assert.deepStrictEqual(c.resolver.localForward, { server: 'udp://127.0.0.1:5354', domains: ['lan'] });
    });
    t('數值、開關依預設型別轉換；空白沿用預設', () => {
        assert.strictEqual(c.resolver.timeoutMs, 2000); assert.strictEqual(c.resolver.fastPath, false); assert.strictEqual(c.resolver.cacheMax, base.resolver.cacheMax);
    });
    t('CDN 參數與跨 CDN 備援（cross_*）', () => { assert.strictEqual(c.cdn.trialMode, 'alias'); assert.strictEqual(c.cdn.cross.minOrigMs, 30); assert.strictEqual(c.cdn.cross.enabled, false); assert.strictEqual(c.cdn.providers.fastly.enabled, false); });
    t('過濾清單可停用、可新增', () => {
        assert.strictEqual(c.filter.lists.length, baseOn.length);
        assert.deepStrictEqual(c.filter.lists.at(-1), { url: 'https://example.com/my.txt', category: 'malware', name: 'My' });
        assert.ok(!c.filter.lists.some(l => l.url === baseOn[0].url));
    });
    t('排程：多個時間、星期幾、停用', () => assert.deepStrictEqual({ e: c.jobs['cdn-scan'].enabled, at: c.jobs['cdn-scan'].at, w: c.jobs['cdn-scan'].weekdays }, { e: false, at: ['02:00', '14:00'], w: [3, 6] }));
    t('固定上游與自動上游數量', () => { assert.deepStrictEqual(c.upstream.pinned, ['udp://168.95.1.1']); assert.strictEqual(c.upstream.autoMax, 3); });

    const r = load(DEFAULT.replace("option redirect 'dnsmasq-upstream'", "option redirect 'redirect'"));
    t('redirect（基本）：聽全部介面 5335、檢查來源，區網網域交給 127.0.0.1:53 的 dnsmasq', () => {
        assert.deepStrictEqual(r.listen.plain.binds, ['0.0.0.0', '::']); assert.deepStrictEqual(r.listen.plain.openBinds, []);
        assert.strictEqual(r.resolver.localForward.server, 'udp://127.0.0.1:53');
    });

    process.env.CANDYDNS_LAN_IP4 = '10.0.0.1';
    process.env.CANDYDNS_LAN_ULA = 'fd00::1';
    const h = load(DEFAULT.replace("option redirect 'dnsmasq-upstream'", "option redirect 'hijack'"));
    t('hijack：綁區網 IP 與 ULA，ULA 不檢查來源（2001: 來源也回答）', () => {
        assert.deepStrictEqual(h.listen.plain.binds, ['127.0.0.1', '10.0.0.1', '::1', 'fd00::1']);
        assert.deepStrictEqual(h.listen.plain.openBinds, ['fd00::1']);
        assert.strictEqual(h.listen.plain.port, 5335);
        assert.strictEqual(h.resolver.localForward.server, 'udp://127.0.0.1:53');
    });
    const x = load(DEFAULT.replace("option redirect 'dnsmasq-upstream'", "option redirect 'exchange'"));
    t('exchange：53 埠綁 0.0.0.0 與 ULA（不綁 :: 避免衝突）', () => {
        assert.deepStrictEqual(x.listen.plain.binds, ['0.0.0.0', '::1', 'fd00::1']); assert.strictEqual(x.listen.plain.port, 53);
    });
    const h4 = load(DEFAULT.replace("option redirect 'dnsmasq-upstream'", "option redirect 'hijack'").replace("option listen_ipv6 '1'", "option listen_ipv6 '0'"));
    t('hijack 不處理 IPv6：只綁 IPv4', () => assert.deepStrictEqual(h4.listen.plain.binds, ['127.0.0.1', '10.0.0.1']));
    delete process.env.CANDYDNS_LAN_IP4; delete process.env.CANDYDNS_LAN_ULA;

    t('社群預設關閉、沒有開 DoH / DoT 就沒有對外網址', () => {
        assert.strictEqual(d.community.enabled, false); assert.deepStrictEqual(d.community.endpoints, { doh: null, dot: null });
    });
    const cmText = DEFAULT
        .replace("option domain ''", "option domain 'dns.example.com'")
        .replace("config doh 'doh'\n\toption enabled '0'\n\toption port '8443'\n\toption open_wan '0'", "config doh 'doh'\n\toption enabled '1'\n\toption port '8443'\n\toption open_wan '1'")
        .replace("config dot 'dot'\n\toption enabled '0'", "config dot 'dot'\n\toption enabled '1'")
        .replace("config community 'community'\n\toption enabled '0'", "config community 'community'\n\toption enabled '1'\n\toption stale_days '14'\n\toption sync_interval '30'")
        + "\nconfig community_rule\n\toption name '同業者'\n\toption action 'accept'\n\toption same_asn '1'\n\toption max_rtt_ms '30'\n\tlist colo 'TPE'\n";
    const cm = load(cmText);
    t('社群：對外網址（DoH 走外網 443、DoT 853）、參數、自動規則', () => {
        assert.strictEqual(cm.community.enabled, true);
        assert.deepStrictEqual(cm.community.endpoints, { doh: 'https://dns.example.com/.well-known/candydns', dot: 'dot://dns.example.com:853' });
        assert.strictEqual(cm.community.staleDays, 14); assert.strictEqual(cm.community.syncIntervalMin, 30);
        assert.deepStrictEqual(cm.community.rules, [{ enabled: true, name: '同業者', action: 'accept', colo: ['TPE'], same_asn: '1', max_rtt_ms: '30' }]);
        assert.strictEqual(cm.community.dir, '/etc/candydns/community');
    });
} finally {
    fs.unlinkSync(path.join(ROOT, '.uci-config.test.js'));
}
console.log(`\n結果：${pass} 通過、${fail} 失敗`);
process.exit(fail ? 1 : 0);
