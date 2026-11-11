'use strict';
// 由 config.js 產生 OpenWrt 預設設定 /etc/config/candydns
//   node openwrt/tools/gen-uci.js > openwrt/candydns/files/candydns.config
// 只寫入「清單類」與基本開關；數值參數留空，LuCI 會顯示 config.js 的預設值，
// 空白就沿用預設，之後程式更新預設值時會自動跟著變。
const path = require('path');
const c = require(path.join(__dirname, '..', '..', 'legacy-node', 'config.js'));

const out = [];
const q = v => `'${String(v).replace(/'/g, `'\\''`)}'`;
const sec = (type, name) => out.push('', name ? `config ${type} ${q(name)}` : `config ${type}`);
const opt = (k, v) => out.push(`\toption ${k} ${q(typeof v === 'boolean' ? (v ? 1 : 0) : v)}`);
const lst = (k, arr) => (arr || []).forEach(v => out.push(`\tlist ${k} ${q(v)}`));

out.push('# candydns 設定（由 openwrt/tools/gen-uci.js 依 config.js 產生）');
out.push('# 用 LuCI「服務 → 優選 DNS」修改；空白的數值參數使用程式內建預設值');

sec('candydns', 'main');
opt('enabled', 0);          // 裝好先不啟用，確認設定後再到 LuCI 打開
opt('lan_zone', 'lan');
opt('wan_zone', 'wan');
opt('redirect', 'dnsmasq-upstream');
opt('dns_port', 5335);
opt('listen_ipv6', 1);
opt('exchange_port', 5354);
lst('local_domain', ['lan']);
opt('query_log', 0);
opt('admin_port', c.admin.port);
opt('data_dir', '');

// DoH / DoT 預設關閉：要給外面用時再到 LuCI 打開，並設定網域與憑證
sec('doh', 'doh'); opt('enabled', 0); opt('port', 8443); opt('open_wan', 0); opt('wan_port', 443);
sec('dot', 'dot'); opt('enabled', 0); opt('port', 853); opt('open_wan', 0);

sec('tls', 'tls');
opt('domain', '');           // 不帶入任何網域，由使用者自己填
opt('cert_mode', 'acme');
opt('acme_server', 'letsencrypt');
opt('acme_key', 'ec-256');
opt('acme_email', '');

// 不能叫 cloudflare：會和 config cdn_provider 'cloudflare' 撞名（UCI 區段名稱全檔唯一）
sec('cf_account', 'cf_account'); opt('api_token', '');

sec('ddns', 'ddns');
opt('enabled', 0);
opt('ipv4', 1); opt('ipv6', 0); opt('proxied', 0); opt('ttl', 1); opt('interval', 5); opt('ip_source', 'web');

sec('site', 'site'); opt('enabled', 0);

// 社群共享：預設關閉；自動規則（config community_rule）預設沒有，沒有符合的規則一律人工審核
sec('community', 'community'); opt('enabled', 0);

sec('upstream', 'upstream');
lst('pinned', []);
lst('fallback', c.upstream.fallback);
lst('bootstrap', c.upstream.bootstrap);
lst('last_resort', c.resolver.lastResort);
lst('auto_type', c.upstream.autoTypes);

sec('resolver', 'resolver');
sec('iprank', 'iprank');

sec('filter', 'filter'); opt('enabled', c.filter.enabled !== false);
for (const l of c.filter.lists) {
    sec('filter_list');
    opt('enabled', l.enabled !== false); opt('name', l.name); opt('url', l.url); opt('category', l.category);
}

sec('cdn', 'cdn'); opt('enabled', c.cdn.enabled !== false);
for (const [name, p] of Object.entries(c.cdn.providers)) {
    sec('cdn_provider', name);
    opt('enabled', p.enabled !== false);
    if (p.ecs) opt('ecs', 1);
    lst('seed_v4', p.seedV4);
}
sec('ecs', 'ecs');
lst('resolver', c.cdn.ecs.resolvers);
lst('tw_subnet', c.cdn.ecs.twSubnets);

for (const [name, j] of Object.entries(c.jobs)) {
    sec('job', name.replace(/-/g, '_'));
    opt('enabled', j.enabled !== false);
    lst('at', [].concat(j.at || []));
    lst('weekday', j.weekdays);
}
sec('benchmark', 'benchmark');
sec('scan', 'scan');
sec('pool', 'pool');

process.stdout.write(out.join('\n') + '\n');
