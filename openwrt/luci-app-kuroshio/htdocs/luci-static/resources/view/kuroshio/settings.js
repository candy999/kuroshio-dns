'use strict';
'require view';
'require form';
'require rpc';
'require ui';
'require tools.widgets as widgets';
'require kuroshio.common as common';

var callAcmeStatus = rpc.declare({ object: 'kuroshio', method: 'acme_status' });
var callAcmeIssue = rpc.declare({ object: 'kuroshio', method: 'acme_issue' });

function certSummary(st) {
	if (!st) return _('讀取中…');
	if (st.cert) {
		var c = st.cert;
		return _('%s，到期 %s（剩 %d 天）').format(c.san || c.subject, c.validTo, c.daysLeft);
	}
	return st.certError || _('還沒有憑證');
}

return view.extend({
	load: function() {
		return Promise.all([common.loadDefaults(), L.resolveDefault(callAcmeStatus(), null)]);
	},

	render: function(data) {
		var acme = data[1];
		var pro = common.isPro();
		var m, s, o;

		m = new form.Map('kuroshio', _('黑潮 DNS · 基本設定'),
			_('DoH / DoT / 區網 DNS，並行上游與 IP 測速、廣告過濾、CDN 走台灣節點。儲存並套用後服務會自動重新啟動。'));

		// ---------------- 服務與 DNS 接管 ----------------
		s = m.section(form.NamedSection, 'main', 'kuroshio', _('服務'));
		o = s.option(form.Flag, 'enabled', _('啟用'));
		o.rmempty = false;

		o = s.option(form.ListValue, 'redirect', _('DNS 接管方式'),
			_('區網裝置的 DNS 查詢怎麼交給本程式。不確定就選「作為 dnsmasq 的上游伺服器」。'));
		o.value('none', _('無（不接管，自行把裝置的 DNS 指到 路由器:埠號）'));
		o.value('dnsmasq-upstream', _('作為 dnsmasq 的上游伺服器（推薦，保留區網主機名稱）'));
		o.value('redirect', _('重定向 53 埠到本程式（基本：一條防火牆規則）'));
		o.value('hijack', _('積極劫持（IPv4 → 區網 IP、IPv6 → ULA，沒有 ULA 會自動建立，DHCP 也發路由器當 DNS）'));
		o.value('exchange', _('使用 53 埠取代 dnsmasq（dnsmasq 只做 DHCP 與區網主機名稱）'));
		o.default = 'dnsmasq-upstream';

		o = s.option(form.Value, 'dns_port', _('DNS 埠號'), _('本程式在區網聽的埠。「取代 dnsmasq」時固定用 53。'));
		o.datatype = 'port';
		o.placeholder = '5335';
		o.depends('redirect', 'none');
		o.depends('redirect', 'dnsmasq-upstream');
		o.depends('redirect', 'redirect');
		o.depends('redirect', 'hijack');

		o = s.option(form.Value, 'exchange_port', _('dnsmasq 改用的埠號'), _('讓出 53 埠後 dnsmasq 改聽這個埠，只回答區網主機名稱。'));
		o.datatype = 'port';
		o.placeholder = '5354';
		o.depends('redirect', 'exchange');

		o = s.option(form.Flag, 'ddr', _('自動發現（DDR）'), _('區網裝置（Windows 11、iPhone、Mac）會自動改用 DoH / DoT / DoQ 加密連線，不用手動設定。需要設定網域並開啟至少一種加密協議。'));
		o.rmempty = false;

		// ---------------- 硬體等級 ----------------
		var ss = m.section(form.NamedSection, 'system', 'system', _('硬體等級'),
			_('依記憶體自動調整快取、同時連線數、背景工作規模，低階路由器開了重功能也不會卡死。狀態頁可以看到目前的等級與記憶體用量。'));
		o = ss.option(form.ListValue, 'profile', _('等級'));
		o.value('auto', _('自動（依記憶體判斷）'));
		o.value('tiny', _('tiny（128 MB 級：基本功能，不開 QUIC、不掃網段）'));
		o.value('small', _('small（256 MB 級）'));
		o.value('standard', _('standard（512 MB – 1 GB）'));
		o.value('large', _('large（1.5 GB 以上、x86）'));
		o.default = 'auto';

		o = s.option(form.Flag, 'listen_ipv6', _('同時處理 IPv6'),
			_('積極劫持會另外建立 IPv6 規則並發送路由器的 ULA 位址（fd00::/8，不用 2001: 公網位址）；環境有 IPv6 但沒有 ULA 時會自動建立 ULA 前綴（第一次會重新載入網路，區網短暫中斷）。取代 dnsmasq 模式有 ULA 就使用。關閉時只處理 IPv4。'));
		o.default = '1';
		o.rmempty = false;

		if (pro) {
			o = s.option(form.DynamicList, 'local_domain', _('區網網域'),
				_('重定向 / 取代模式下，這些網域（以及私有 IP 的反查）交回 dnsmasq 回答。'));
			o.placeholder = 'lan';
			o.depends('redirect', 'redirect');
			o.depends('redirect', 'hijack');
			o.depends('redirect', 'exchange');

			o = s.option(widgets.ZoneSelect, 'lan_zone', _('區網防火牆區域'));
			o.default = 'lan';
			o = s.option(widgets.ZoneSelect, 'wan_zone', _('外網防火牆區域'));
			o.default = 'wan';

			o = s.option(form.DynamicList, 'allow_from', _('允許查詢的來源'), _('區網 DNS 只回答這些網段（空白用預設的私有網段）。'));
			o.datatype = 'cidr';
			o.placeholder = '192.168.0.0/16';

			o = s.option(form.Value, 'admin_port', _('管理 API 埠號'), _('只綁 127.0.0.1，LuCI 透過它讀取狀態。'));
			o.datatype = 'port';
			o.placeholder = '8054';

			o = s.option(form.Flag, 'query_log', _('記錄每筆查詢'), _('寫進系統日誌，除錯用。會很快洗掉日誌緩衝區。'));
			o = s.option(form.ListValue, 'log_level', _('日誌等級'));
			o.value('info', _('一般'));
			o.value('debug', _('除錯（更詳細）'));

			o = s.option(form.Value, 'data_dir', _('資料目錄'),
				_('評測結果、節點池、CDN 網域庫、統計的存放位置。空白 = 程式目錄；可指定到外接硬碟，例如 /mnt/sda1/kuroshio。'));
			o.placeholder = '/usr/share/kuroshio/state';
		}

		// ---------------- DoH / DoT ----------------
		s = m.section(form.NamedSection, 'doh', 'doh', _('DNS over HTTPS'), _('網址是 https://網域/dns-query。需要先在下方設定網域與憑證；只在區網使用的話不必打開。'));
		o = s.option(form.Flag, 'enabled', _('啟用'));
		o.rmempty = false;
		o = s.option(form.Value, 'port', _('監聽埠號'), _('LuCI 通常已經佔用 443，所以預設聽 8443，再由防火牆把外網 443 轉過來。'));
		o.datatype = 'port';
		o.placeholder = '8443';
		o = s.option(form.Flag, 'http3', _('HTTP/3（DoH3）'), _('同一個埠號的 UDP 也提供 DoH3（QUIC），掉包環境比較穩；開放外網時防火牆會一併加 UDP。DoH 回應會帶 Alt-Svc 告訴用戶端。記憶體 200 MB 以下的路由器不會開 QUIC。'));
		o.rmempty = false;
		o = s.option(form.Flag, 'open_wan', _('開放外網連線'), _('在防火牆加入規則，讓外網可以連到 DoH。'));
		o.rmempty = false;
		o = s.option(form.Value, 'wan_port', _('外網埠號'), _('外面看到的埠號（一般用 443）。'));
		o.datatype = 'port';
		o.placeholder = '443';
		o.depends('open_wan', '1');
		if (pro) {
			o = s.option(form.Flag, 'trust_proxy', _('信任 X-Forwarded-For'), _('只有前面還有反向代理時才打開，否則用戶端可以偽造來源 IP。'));
			o = s.option(form.Value, 'host', _('監聽位址'));
			o.datatype = 'ipaddr';
			o.placeholder = '0.0.0.0';
		}

		s = m.section(form.NamedSection, 'dot', 'dot', _('DNS over TLS'), _('Android「私人 DNS」用這個。同樣需要網域與憑證。'));
		o = s.option(form.Flag, 'enabled', _('啟用'));
		o.rmempty = false;
		o = s.option(form.Value, 'port', _('監聽埠號'));
		o.datatype = 'port';
		o.placeholder = '853';
		o = s.option(form.Flag, 'open_wan', _('開放外網連線'));
		o.rmempty = false;

		s = m.section(form.NamedSection, 'doq', 'doq', _('DNS over QUIC（DoQ）'), _('UDP 853，延遲最低；AdGuard 系列 App 支援。跟 DoT 共用憑證與「開放外網連線」設定。記憶體 200 MB 以下的路由器不會開 QUIC。'));
		o = s.option(form.Flag, 'enabled', _('啟用'));
		o.rmempty = false;
		if (pro) {
			o = s.option(form.Value, 'port', _('監聽埠號（UDP）'));
			o.datatype = 'port';
			o.placeholder = '853';
		}

		// ---------------- 憑證 ----------------
		s = m.section(form.NamedSection, 'tls', 'tls', _('憑證（Let’s Encrypt）'),
			_('用 Cloudflare DNS 驗證申請，不需要開 80 埠；到期前 30 天自動續期，DoH / DoT 會自動換上新憑證。'));
		o = s.option(form.Value, 'domain', _('網域'));
		o.datatype = 'hostname';
		o.placeholder = 'dns.example.com';

		o = s.option(form.ListValue, 'cert_mode', _('憑證來源'));
		o.value('acme', _('自動申請（Let’s Encrypt + Cloudflare DNS 驗證）'));
		o.value('manual', _('自己指定檔案'));
		o.default = 'acme';

		o = s.option(form.Value, 'acme_email', _('聯絡信箱'), _('憑證到期通知用，可留空。'));
		o.datatype = 'email';
		o.depends('cert_mode', 'acme');
		if (pro) {
			o = s.option(form.ListValue, 'acme_server', _('憑證機構'));
			o.value('letsencrypt', "Let's Encrypt");
			o.value('letsencrypt_test', _("Let's Encrypt 測試環境（不受頻率限制，憑證不被信任）"));
			o.value('zerossl', 'ZeroSSL');
			o.value('google', 'Google Trust Services');
			o.default = 'letsencrypt';
			o.depends('cert_mode', 'acme');
			o = s.option(form.ListValue, 'acme_key', _('金鑰類型'));
			o.value('ec-256', 'ECDSA P-256');
			o.value('ec-384', 'ECDSA P-384');
			o.value('2048', 'RSA 2048');
			o.value('4096', 'RSA 4096');
			o.default = 'ec-256';
			o.depends('cert_mode', 'acme');
		}
		o = s.option(form.Value, 'cert', _('憑證檔（含中繼憑證）'));
		o.placeholder = '/etc/kuroshio/cert.pem';
		o.depends('cert_mode', 'manual');
		o = s.option(form.Value, 'key', _('私鑰檔'));
		o.placeholder = '/etc/kuroshio/key.pem';
		o.depends('cert_mode', 'manual');

		o = s.option(form.DummyValue, '_cert_status', _('目前憑證'));
		o.cfgvalue = function() { return certSummary(acme); };

		o = s.option(form.Button, '_issue', _('立即申請'), _('請先「儲存並套用」網域與 Cloudflare API Token。申請約需 1～3 分鐘。'));
		o.inputtitle = _('申請 / 更新憑證');
		o.inputstyle = 'apply';
		o.depends('cert_mode', 'acme');
		o.onclick = function() {
			var box = E('div', {}, common.pre(_('啟動中…')));
			ui.showModal(_('申請憑證'), [box, E('div', { 'class': 'right' }, E('button', { 'class': 'btn', 'click': ui.hideModal }, _('關閉')))]);
			return callAcmeIssue().then(function(r) {
				if (r && r.started === false) box.firstChild.textContent = r.error;
				var tick = function() {
					return callAcmeStatus().then(function(st) {
						box.firstChild.textContent = (st.log || '') + (st.running ? '\n…' : '\n\n' + certSummary(st));
						if (st.running) window.setTimeout(tick, 3000);
					});
				};
				window.setTimeout(tick, 1500);
			});
		};

		// ---------------- Cloudflare / DDNS ----------------
		s = m.section(form.NamedSection, 'cf_account', 'cf_account', _('Cloudflare'),
			_('DDNS 與憑證申請共用。到 Cloudflare 後台「我的設定檔 → API 權杖」建立，權限：區域 → DNS → 編輯、區域 → 區域 → 讀取。'));
		o = s.option(form.Value, 'api_token', _('API Token'));
		o.password = true;

		s = m.section(form.NamedSection, 'ddns', 'ddns', _('DDNS（Cloudflare）'), _('公網 IP 變了就自動更新 DNS 記錄。'));
		o = s.option(form.Flag, 'enabled', _('啟用'));
		o.rmempty = false;
		o = s.option(form.DynamicList, 'record', _('要更新的記錄'), _('完整網域名稱，例如 home.example.com。記錄不存在會自動建立。'));
		o.datatype = 'hostname';
		o = s.option(form.Flag, 'ipv4', _('更新 IPv4（A）'));
		o.default = '1';
		o.rmempty = false;
		o = s.option(form.Flag, 'ipv6', _('更新 IPv6（AAAA）'));
		o.rmempty = false;
		o = s.option(form.ListValue, 'ip_source', _('IP 來源'));
		o.value('web', _('問 Cloudflare（推薦，在其他路由器後面也正確）'));
		o.value('interface', _('讀取網路介面'));
		o.default = 'web';
		o = s.option(widgets.DeviceSelect, 'iface4', _('IPv4 介面'), _('例如 pppoe-wan'));
		o.noaliases = true;
		o.depends('ip_source', 'interface');
		o = s.option(widgets.DeviceSelect, 'iface6', _('IPv6 介面'), _('空白 = 同 IPv4 介面'));
		o.noaliases = true;
		o.depends('ip_source', 'interface');
		o = s.option(form.Value, 'interval', _('檢查間隔（分鐘）'));
		o.datatype = 'range(1,1440)';
		o.placeholder = '5';
		if (pro) {
			o = s.option(form.Flag, 'proxied', _('經過 Cloudflare 代理（橘色雲朵）'), _('DoT 不能經過代理，給 DoH / DoT 用的記錄請保持關閉。'));
			o = s.option(form.Value, 'ttl', _('TTL（秒）'), _('1 = 自動'));
			o.datatype = 'uinteger';
			o.placeholder = '1';
			o = s.option(form.Value, 'zone', _('Zone'), _('空白 = 從記錄名稱自動判斷'));
			o.datatype = 'hostname';
			o = s.option(form.Value, 'force_hours', _('強制確認間隔（小時）'), _('IP 沒變時多久重新向 Cloudflare 確認一次記錄。'));
			o.datatype = 'uinteger';
			o.placeholder = '24';
			o = s.option(form.Value, 'url4', _('IPv4 查詢網址'));
			o.placeholder = 'https://1.1.1.1/cdn-cgi/trace';
			o = s.option(form.Value, 'url6', _('IPv6 查詢網址'));
			o.placeholder = 'https://[2606:4700:4700::1111]/cdn-cgi/trace';
		}
		o = s.option(form.Button, '_ddns_now', _('立即更新'), _('服務執行中才能使用。'));
		o.inputtitle = _('立即更新');
		o.onclick = function() {
			return common.action('/api/ddns/update').then(function(r) {
				var st = r && r.result;
				if (!r || r.ok === false || !st) return common.notify(r);
				var lines = (st.records || []).map(function(x) { return '%s %s %s：%s'.format(x.name, x.type, x.ip || '', x.ok ? x.action : x.error); });
				ui.addNotification(null, E('div', {}, [E('p', {}, st.error || _('DDNS 已更新')), common.pre(lines.join('\n'))]), st.error ? 'warning' : 'info');
			});
		};

		if (pro) {
			s = m.section(form.NamedSection, 'site', 'site', _('公開網頁'), _('Windows 版的官網與統計頁。OpenWrt 上建議關閉，改用 LuCI 狀態頁；關閉不影響 DoH。'));
			o = s.option(form.Flag, 'enabled', _('啟用'));
			o.rmempty = false;
			o = s.option(form.Value, 'min_clients', _('排行最少人數'));
			o.datatype = 'uinteger';
			o.placeholder = String(common.def('site.minClients') || 2);
			o.depends('enabled', '1');
		}

		return m.render().then(function(node) { return E([], [common.modeBar(), node, common.footer()]); });
	}
});
