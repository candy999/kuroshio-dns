'use strict';
'require view';
'require form';
'require rpc';
'require ui';
'require uci';
'require tools.widgets as widgets';
'require kuroshio.common as common';

var callAcmeStatus = rpc.declare({ object: 'kuroshio', method: 'acme_status' });
var callAcmeIssue = rpc.declare({ object: 'kuroshio', method: 'acme_issue' });
var callDnr = rpc.declare({ object: 'kuroshio', method: 'dnr' });

function certSummary(st) {
	if (!st) return _('讀取中…');
	if (st.cert) {
		var c = st.cert;
		return _('%s，到期 %s（剩 %d 天）').format(c.san || c.subject, c.validTo, c.daysLeft);
	}
	return st.certError || _('還沒有憑證');
}

var T = common.T;

/** 目前的憑證：來源、位置、有效期間、有沒有涵蓋綁定網域（/api/paths；服務沒有執行時用 acme.sh 的狀態） */
function certPanel(paths, acme) {
	var t = paths && paths.tls, mode = uci.get('kuroshio', 'tls', 'cert_mode') || 'acme', dom = uci.get('kuroshio', 'tls', 'domain') || '';
	var info = t ? t.info : (acme && acme.cert), rows = [];
	var row = function(k, v) { rows.push([k, v]); };
	row(_('來源'), mode === 'manual' ? _('自己的憑證檔（只讀取，不會申請或覆蓋）') : _('自動申請（acme.sh）'));
	if (t) {
		row(_('憑證檔'), common.pathCell(t.cert));
		row(_('私鑰檔'), common.pathCell(t.key));
	}
	var state;
	if (t && !t.exists) state = common.badge(mode === 'manual' ? _('找不到檔案（憑證檔或私鑰檔不存在）') : _('還沒有申請到憑證'), 'err');
	else if (!info) state = common.badge((acme && acme.certError) || _('還沒有憑證'), 'err');
	else if (info.daysLeft < 0) state = common.badge(_('已經過期'), 'err');
	else if (info.daysLeft < 14) state = common.badge(_('快到期（剩 %d 天）').format(info.daysLeft), 'warn');
	else state = common.badge(_('有效（剩 %d 天）').format(info.daysLeft), 'ok');
	row(_('狀態'), state);
	if (info) {
		row(_('主體'), info.subject || '-');
		row(_('涵蓋的名稱'), info.san || _('（沒有 SAN）'));
		row(_('到期'), info.validTo || '-');
		if (dom) row(_('綁定網域'), common.certCovers(info, dom) ? common.badge(_('有涵蓋 %s').format(dom), 'ok') : common.badge(_('沒有涵蓋 %s（用戶端會出現憑證錯誤）').format(dom), 'err'));
	}
	return E('div', { 'id': 'kuroshio-cert' }, [common.table([_('項目'), _('內容')], rows),
		paths ? '' : T('div', { 'class': 'cbi-value-description' }, _('服務沒有執行：只顯示 acme.sh 的憑證資訊。'))]);
}

var DDNS_ACTION = { created: _('已新增'), updated: _('已更新'), unchanged: _('沒有變'), deleted: _('已移除'), kept: _('暫時保留'), skip: _('略過'), error: _('失敗') };

/** DDNS 上一次檢查的結果：每個出口偵測到的 IP、每筆記錄 */
function ddnsPanel(st) {
	if (!st) return T('em', {}, _('服務沒有執行，無法讀取。'));
	if (st.enabled === false) return T('em', {}, _('DDNS 沒有啟用（固定網域）：不會更新 DNS 記錄。'));
	var bad = function(x) { return E('span', {}, [common.badge(DDNS_ACTION[x.action] || _('失敗'), x.action === 'skip' ? 'warn' : 'err'), T('div', { 'style': 'color:#b42318;font-size:12px' }, x.error || '')]); };
	return E('div', { 'id': 'kuroshio-ddns' }, [
		st.error ? T('p', { 'class': 'alert-message warning' }, _('上次更新有錯誤：') + st.error) : '',
		T('p', {}, _('上次檢查：') + (st.lastRun ? new Date(st.lastRun).toLocaleString() : '-')),
		common.table([_('出口（網卡）'), _('類型'), _('偵測到的 IP'), _('狀態')], [].concat(st.sources || []).map(function(x) {
			return [x.interface || _('自動（預設路由）'), 'IPv' + x.family, x.ip || '-', x.ok ? common.badge(_('正常'), 'ok') : bad(x)];
		}), _('還沒有偵測結果')),
		common.table([_('名稱'), _('類型'), _('內容'), _('結果')], [].concat(st.records || []).map(function(x) {
			return [x.name, x.type, x.content || x.ip || '-', x.ok ? common.badge(DDNS_ACTION[x.action] || x.action || '-', x.action === 'kept' ? 'warn' : 'ok') : bad(x)];
		}), _('還沒有更新過'))
	]);
}

/**
 * DNR：kuroshio dnr 判斷的結果（會發布什麼、沒發的原因；依已套用的設定）＋ dhcp.lan 裡目前實際發布的內容。
 * 舊版 rpcd 沒有 dnr 方法時，退回依設定推測原因
 */
function dnrPanel(paths, dnr) {
	var on = uci.get('kuroshio', 'main', 'dnr') !== '0';
	if (!on) return T('em', {}, _('已關閉：不發布。'));
	var opt = [].concat(uci.get('dhcp', 'lan', 'dhcp_option') || []).filter(function(x) { return /^162,/.test(x); });
	var ra = [].concat(uci.get('dhcp', 'lan', 'dnr') || []);
	var published = opt.length || ra.length;
	var pubText = [opt.length ? _('DHCPv4（選項 162）') : '', ra.length ? _('RA / DHCPv6 %d 筆').format(ra.length) : ''].filter(Boolean).join('、');
	var nodes = [];

	if (dnr && typeof dnr.ok === 'boolean' && !dnr.error) {
		if (dnr.ok) {
			nodes.push(E('div', {}, [published ? common.badge(_('發布中'), 'ok') : common.badge(_('條件符合，還沒有發布'), 'warn'),
				T('span', {}, ' ' + (published ? pubText : _('儲存並套用後就會發布。')))]));
			nodes.push(T('div', { 'style': 'margin:.4em 0' }, _('網域（ADN）：') + (dnr.adn || '-')));
			var P = { h2: 'DoH', h3: 'DoH3', dot: 'DoT', doq: 'DoQ' };
			nodes.push(common.table([_('優先順序'), _('協議'), _('埠號'), _('位址'), _('路徑')], [].concat(dnr.protocols || []).map(function(x) {
				return [String(x.priority), [].concat(x.alpn || []).map(function(a) { return P[a] || a; }).join(' + '), String(x.port),
					[].concat(x.addrs || []).join('、') || '-', x.dohpath || '-'];
			}), _('沒有協議')));
		} else {
			nodes.push(E('div', {}, [common.badge(_('目前沒有發布'), 'off'), T('span', { 'id': 'kuroshio-dnr-reason' }, ' ' + (dnr.reason || _('原因不明')))]));
			if (published) nodes.push(T('div', { 'class': 'cbi-value-description' }, _('dhcp 設定裡還有舊的 DNR 內容（%s），儲存並套用後會移除。').format(pubText)));
		}
		return E('div', { 'id': 'kuroshio-dnr' }, nodes);
	}

	// 沒有 dnr 方法（舊版）或讀不到：看 dhcp 設定，沒發時依設定推測原因
	if (published) {
		return E('div', { 'id': 'kuroshio-dnr' }, [common.badge(_('發布中'), 'ok'), T('span', {}, ' ' + pubText)]
			.concat(ra.map(function(x) { return T('code', { 'style': 'display:block;word-break:break-all;font-size:12px' }, x); })));
	}
	var why = [], dom = uci.get('kuroshio', 'tls', 'domain') || '', info = paths && paths.tls && paths.tls.info;
	if (!dom) why.push(_('還沒有填綁定網域'));
	if (!['doh', 'dot', 'doq'].some(function(k) { return uci.get('kuroshio', k, 'enabled') === '1'; })) why.push(_('沒有開啟 DoH / DoT / DoQ'));
	if (paths && (!info || info.daysLeft < 0)) why.push(_('沒有有效的憑證'));
	else if (info && dom && !common.certCovers(info, dom)) why.push(_('憑證沒有涵蓋綁定網域'));
	return E('div', { 'id': 'kuroshio-dnr' }, [common.badge(_('目前沒有發布'), 'off'), T('span', {}, ' ' + (why.length ? why.join('；') : _('條件符合的話，儲存並套用後就會發布；仍然沒有發布時原因會寫在系統日誌（DNR 沒有發：…）。'))),
		dnr && dnr.error ? T('div', { 'class': 'cbi-value-description' }, _('讀不到 DNR 的判斷結果：') + dnr.error) : '']);
}

/** 存放位置（/api/paths）：只有路徑，沒有密鑰內容 */
function pathsSection(p) {
	var body;
	if (!p) body = E('p', {}, [T('em', {}, _('服務沒有執行，無法讀取。啟用並套用後再回來看。'))]);
	else {
		var t = p.tls || {}, manual = (uci.get('kuroshio', 'tls', 'cert_mode') || 'acme') === 'manual';
		var note = function(text, share, secret) {
			return E('span', {}, [T('span', {}, text + ' '), share ? common.badge(_('其他服務可以讀取'), 'ok') : '', ' ', secret ? common.badge(_('含密鑰，請勿外流'), 'warn') : '']);
		};
		body = common.table([_('項目'), _('位置'), _('用途')], [
			[_('設定檔'), common.pathCell(p.configFile || '/etc/config/kuroshio'), note(_('UCI 設定（用這個頁面修改）。Cloudflare API Token 也在裡面。'), false, true)],
			[_('設定資料夾'), common.pathCell(p.configDir), note(_('憑證（自動申請時）、自訂規則、評測名單。'))],
			[_('憑證檔'), common.pathCell(t.cert), note(manual ? _('自己的憑證檔（PEM），黑潮 DNS 只讀取。') : _('acme.sh 申請的憑證（含中繼憑證，PEM），續期時會更新。'), !!t.cert)],
			[_('私鑰檔'), common.pathCell(t.key), note(_('憑證的私鑰（PEM）。其他服務要共用時，請確認只有需要的帳號讀得到。'), !!t.key, !!t.key)],
			[_('學習資料'), common.pathCell(p.stateDir), note(_('評測結果、節點池、CDN 網域庫、統計。'))],
			[_('執行期暫存'), common.pathCell(p.runtimeDir), note(_('放在記憶體，重新開機就清掉。'))],
			[_('程式附帶的資料'), common.pathCell(p.shareDir), note(_('內建名單，升級套件時更新。'))],
			[_('自訂規則'), common.pathCell(p.customRules), note(_('自己加的過濾規則（「過濾」頁可以編輯）。'))],
			[_('評測報表'), common.pathCell(p.benchmarkDir), note(_('每日 DNS 評測的報表。'))],
			[_('社群金鑰'), common.pathCell(p.communityKeyDir), note(_('好友社群的身分金鑰。'), false, true)]
		]);
	}
	return E('div', { 'class': 'cbi-section kuroshio-sec', 'id': 'kuroshio-paths' }, [
		T('h3', {}, _('存放位置')),
		T('div', { 'class': 'cbi-section-descr' }, _('各種檔案實際放在哪裡（已套用的設定）。其他服務（例如 uhttpd、nginx）要共用憑證時，直接讀取下面的憑證檔與私鑰檔即可。這裡只顯示路徑，不會顯示密鑰內容。')),
		E('div', { 'style': 'overflow-x:auto' }, body)
	]);
}

return view.extend({
	load: function() {
		return Promise.all([
			common.loadDefaults(),
			L.resolveDefault(callAcmeStatus(), null),
			common.fetch('/api/interfaces'),
			common.fetch('/api/paths'),
			common.fetch('/api/ddns'),
			common.fetch('/api/status', { lite: 1 }),
			uci.load('kuroshio'),
			L.resolveDefault(uci.load('dhcp'), null),
			L.resolveDefault(callDnr(), null)
		]);
	},

	render: function(data) {
		var acme = data[1];
		var ifaces = (data[2] && Array.isArray(data[2].interfaces)) ? data[2].interfaces : [];
		var paths = data[3], ddnsStatus = data[4], status = data[5], dnr = data[8];
		var pro = common.isPro();
		var m, s, o;

		/** 多位址監聽：可以從網卡位址挑選，也可以自己輸入 */
		var bindsOption = function(name, title, desc) {
			var b = s.option(form.DynamicList, name, title, desc);
			b.datatype = 'ipaddr("nomask")';
			b.placeholder = '0.0.0.0';
			b.value('0.0.0.0', '0.0.0.0（' + _('所有 IPv4 位址') + '）');
			b.value('::', '::（' + _('所有 IPv6 位址') + '）');
			ifaces.forEach(function(i) {
				(i.addrs || []).forEach(function(a) {
					// 鏈路本地位址要指定網卡才能綁定，後端不接受
					if (a.scope === 'linklocal' || a.scope === 'loopback') return;
					b.value(a.ip, a.ip + '（' + i.name + '、' + common.scopeName(a.scope) + (a.temporary ? '、' + _('暫時') : '') + (a.deprecated ? '、' + _('已停用') : '') + '）');
				});
			});
			return b;
		};

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

		o = s.option(form.Flag, 'dnr', _('用 DHCP / RA 通知加密 DNS（DNR）'),
			_('RFC 9463：在 DHCP 與 IPv6 RA 裡告訴區網裝置這台路由器有加密 DNS（網域、位址、協議），裝置不用先查詢就能改用加密連線。要有綁定網域、涵蓋網域的有效憑證，而且加密協議聽得到區網位址才會發布；條件不符就不發。IPv6（RA）需要 OpenWrt 25.12 以上。'));
		o.default = '1';
		o.rmempty = false;
		common.panel(s, '_dnr_status', _('DNR 目前狀態'), function() { return dnrPanel(paths, dnr); });

		// ---------------- 記憶體與儲存（沒有硬體等級，規格 09）----------------
		var ss = m.section(form.NamedSection, 'system', 'system', _('記憶體與儲存'),
			_('記憶體有空就多用（快取、CDN 資料庫、過濾清單），系統可用記憶體低於保留量就依序讓出來，DNS 轉送永遠不停；同時連線數依 CPU 核心數自動決定。狀態頁看得到保留量與目前的大小。'));
		ss.option(form.DummyValue, '_auto', _('調整方式')).cfgvalue = function() { return _('自動（依系統可用記憶體與 CPU 核心數）'); };
		o = ss.option(form.Flag, 'restart_fallback', _('重新啟動期間的 DNS 備援'));
		o.uciconfig = 'kuroshio';
		o.ucisection = 'main';
		o.description = _('本程式重新啟動或沒有回答時，暫時讓 dnsmasq 直接用 WAN 的上游轉送（裝置一定有 DNS；這段期間沒有過濾與 CDN 調整），回來後自動接管。取代 dnsmasq（exchange）模式不支援。');
		o.default = '1';
		o.rmempty = false;
		if (pro) {
			o = ss.option(form.Value, 'persist_max_age_hours', _('最久未存（小時）'),
				_('學到的資料至少每隔這麼久一定存一次（最多 24 小時）。越小，斷電時遺失越少，但 Flash 寫入越多。'));
			o.datatype = 'range(1,24)';
			o.placeholder = '24';
			o = ss.option(form.Value, 'storage_reserve_mb', _('儲存保留空間（MB）'),
				_('Flash 至少留這麼多給系統（opkg 安裝、改設定、jffs2 回收）。空間在保留量以上時，過濾清單的本機副本、統計這類可重建的資料大方留著（重開機更快、少下載）；低於保留量就依序刪日誌 → 清單副本 → 可重建的資料，核心資料絕不自動刪除。空白或 0 = 自動（max(1 MB, 10%)）；跟百分比都填取大的。'));
			o.datatype = 'uinteger';
			o.placeholder = '0';
			o = ss.option(form.Value, 'storage_reserve_percent', _('儲存保留空間（%）'), _('檔案系統大小的百分比（最多 90）。'));
			o.datatype = 'range(0,90)';
			o.placeholder = '0';
			o = ss.option(form.Flag, 'memory_governor', _('記憶體控制'),
				_('系統可用記憶體低於保留量時依序讓出：診斷緩衝 → DNS 快取 → CDN 冷資料移到 Flash → （真的不足時）優先順序最低的過濾清單 → 只轉送（暫停 CDN 調整、快取最小）→ 最後才暫停保護清單。區網的 DNS 轉送永遠不停，寬裕後依相反順序恢復。'));
			o.default = '1';
			o.rmempty = false;
			o = ss.option(form.Value, 'memory_reserve_mb', _('記憶體保留量（MB）'),
				_('系統可用記憶體至少留這麼多給其他程式；低於它就讓出記憶體，高於它 + 遲滯才恢復、才讓快取長大。空白或 0 = 自動：max(16 MB, 實體記憶體 5%, min_free_kbytes × 3)。'));
			o.datatype = 'uinteger';
			o.placeholder = '0';
			o.depends('memory_governor', '1');
			o = ss.option(form.Value, 'memory_reserve_percent', _('記憶體保留量（%）'), _('實體記憶體的百分比（最多 90）；跟 MB 都填取大的。'));
			o.datatype = 'range(0,90)';
			o.placeholder = '0';
			o.depends('memory_governor', '1');
			o = ss.option(form.Value, 'oom_score_adj', _('OOM 分數調整'),
				_('記憶體用完時核心挑誰停掉：負數 = 不優先挑本程式（DNS 停了等於斷網）。預設 -500：本程式要吃掉超過一半記憶體才會跟一般程式同分；-1000 = 完全豁免（不建議：真的漏記憶體時整台會卡死）。'));
			o.datatype = 'range(-1000,1000)';
			o.placeholder = '-500';
		}

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
		o = s.option(form.Value, 'wan_port', _('外網埠號'), _('外面看到的埠號（一般用 443；443 被占用時可以用其他埠，例如 8443）。公開頁的網址、iPhone 描述檔、Alt-Svc、HTTPS 記錄都用這個埠號。'));
		o.datatype = 'port';
		o.placeholder = '443';
		o.depends('open_wan', '1');
		if (pro) {
			o = s.option(form.Flag, 'trust_proxy', _('信任 X-Forwarded-For'), _('只有前面還有反向代理時才打開，否則用戶端可以偽造來源 IP。'));
			o = s.option(form.Value, 'host', _('監聽位址'), _('下面的「多個監聽位址」有填時不使用這一欄。'));
			o.datatype = 'ipaddr("nomask")';
			o.placeholder = '0.0.0.0';
			bindsOption('binds', _('多個監聽位址'), _('有填就取代「監聽位址」。IPv4 與 IPv6 可以同時寫（0.0.0.0 與 ::），也可以只聽某幾個位址。其中一個綁定失敗只記警告，其他照常。'));
			bindsOption('http3_binds', _('DoH3 的監聽位址'), _('空白 = 跟 DoH 同樣的位址。')).depends('http3', '1');
			o = s.option(form.ListValue, 'tls', _('DoH 自己做 TLS'), _('自動：有憑證就用 TLS。前面有反向代理（例如 nginx）處理 TLS 時才選「關閉」。'));
			o.value('auto', _('自動'));
			o.value('1', _('開啟（一律 TLS）'));
			o.value('0', _('關閉（純 HTTP，TLS 交給前面的反向代理）'));
			o.default = 'auto';
		}

		s = m.section(form.NamedSection, 'dot', 'dot', _('DNS over TLS'), _('Android「私人 DNS」用這個。同樣需要網域與憑證。'));
		o = s.option(form.Flag, 'enabled', _('啟用'));
		o.rmempty = false;
		o = s.option(form.Value, 'port', _('監聽埠號'));
		o.datatype = 'port';
		o.placeholder = '853';
		o = s.option(form.Flag, 'open_wan', _('開放外網連線'));
		o.rmempty = false;
		if (pro)
			bindsOption('binds', _('多個監聽位址'), _('空白 = 0.0.0.0（所有 IPv4 位址）。IPv4 與 IPv6 可以同時寫。'));

		s = m.section(form.NamedSection, 'doq', 'doq', _('DNS over QUIC（DoQ）'), _('UDP 853，延遲最低；AdGuard 系列 App 支援。跟 DoT 共用憑證與「開放外網連線」設定。記憶體 200 MB 以下的路由器不會開 QUIC。'));
		o = s.option(form.Flag, 'enabled', _('啟用'));
		o.rmempty = false;
		if (pro) {
			o = s.option(form.Value, 'port', _('監聽埠號（UDP）'));
			o.datatype = 'port';
			o.placeholder = '853';
			bindsOption('binds', _('多個監聽位址'), _('空白 = 0.0.0.0（所有 IPv4 位址）。IPv4 與 IPv6 可以同時寫。'));
		}
		common.panel(s, '_listeners', _('目前的監聽狀態'), function() {
			return status ? E('div', { 'id': 'kuroshio-listeners' }, common.listenerTable(status.listenersDetail)) : T('em', {}, _('服務沒有執行，無法讀取。'));
		}, _('DoH / DoT / DoQ 實際綁定的位址（已套用的設定）；綁定失敗會列出原因。'));

		// ---------------- 網域與憑證 ----------------
		s = m.section(form.NamedSection, 'tls', 'tls', _('網域與憑證'),
			_('DoH / DoT / DoQ 共用同一個網域與憑證。自動申請用 Cloudflare DNS 驗證，不需要開 80 埠，到期前 30 天自動續期；已經有憑證（例如其他服務在維護）就選「使用我自己的憑證檔」。'));
		o = s.option(form.Value, 'domain', _('綁定網域'), _('固定網域或 DDNS 名稱，例如 dns.example.com。憑證、社群、DDNS 記錄沒有另外填時都用它。'));
		o.datatype = 'hostname';
		o.placeholder = 'dns.example.com';
		o.validate = function(sid, v) {
			if (!v) return true;
			return (/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(v) && !/\.\d+$/.test(v)) || _('請輸入完整的網域名稱，例如 dns.example.com');
		};

		o = s.option(form.ListValue, 'cert_mode', _('憑證來源'));
		o.value('acme', _('自動申請（Let’s Encrypt + Cloudflare DNS 驗證）'));
		o.value('manual', _('使用我自己的憑證檔（只讀取，不會申請或覆蓋）'));
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
		var absPath = function(sid, v) { return !v || /^\/[^\s]*$/.test(v) || _('請輸入完整路徑（/ 開頭，不能有空白）'); };
		o = s.option(form.Value, 'cert', _('憑證檔（含中繼憑證）'), _('PEM 檔的完整路徑，例如 /etc/ssl/dns.example.com/fullchain.pem。空白 = /etc/kuroshio/cert.pem。'));
		o.placeholder = '/etc/kuroshio/cert.pem';
		o.depends('cert_mode', 'manual');
		o.retain = true;
		o.validate = absPath;
		o = s.option(form.Value, 'key', _('私鑰檔'), _('PEM 檔的完整路徑。空白 = /etc/kuroshio/key.pem。'));
		o.placeholder = '/etc/kuroshio/key.pem';
		o.depends('cert_mode', 'manual');
		o.retain = true;
		o.validate = absPath;

		common.panel(s, '_cert_status', _('目前憑證'), function() { return certPanel(paths, acme); }, _('已套用的設定。修改後請先「儲存並套用」。'));

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

		s = m.section(form.NamedSection, 'ddns', 'ddns', _('DDNS（網域的 IP 由誰更新）'),
			_('固定網域：IP 不會變，或已經由其他服務在更新，只要在上面填綁定網域。自動更新：公網 IP 變了就更新 Cloudflare 的 DNS 記錄。'));
		o = s.option(form.ListValue, 'enabled', _('更新方式'));
		o.value('0', _('固定網域，不需要更新'));
		o.value('1', _('由黑潮 DNS 自動更新（DDNS，Cloudflare）'));
		o.default = '0';
		o.rmempty = false;
		// 改回固定網域時，底下的設定留著（之後再打開不用重填）
		var dd = function(opt) { opt.depends('enabled', '1'); opt.retain = true; return opt; };
		o = dd(s.option(form.DynamicList, 'record', _('要更新的記錄'), _('完整網域名稱，例如 home.example.com。空白 = 用綁定網域。記錄不存在會自動建立。')));
		o.datatype = 'hostname';
		o = dd(s.option(form.ListValue, 'ip_source', _('IP 來源'),
			_('上網查：從每個出口各自連出去問公網 IP（路由器在其他路由器後面也正確）。讀取網路介面：直接用介面上的公網位址。')));
		o.value('web', _('上網查公網 IP（推薦）'));
		o.value('interface', _('讀取網路介面上的位址'));
		o.default = 'web';
		o = dd(s.option(form.DynamicList, 'interfaces', _('要發布的出口（網路介面）'),
			_('多條對外線路時，選擇要發布哪幾個出口的 IP，同一個名稱會發布多筆記錄。空白 = 自動（預設路由走的那一個出口）。') +
			(ifaces.length ? '' : ' ' + _('服務沒有執行，讀不到介面清單：請直接輸入介面名稱，例如 pppoe-wan。'))));
		o.placeholder = 'pppoe-wan';
		o.validate = function(sid, v) { return !v || /^[A-Za-z0-9_.@:-]{1,32}$/.test(v) || _('介面名稱只能有英數字與 . _ - @ :'); };
		ifaces.forEach(function(i) {
			// 迴路介面不會是對外的出口
			if ((i.addrs || []).length && i.addrs.every(function(a) { return a.scope === 'loopback'; })) return;
			o.value(i.name, common.ifaceText(i));
		});
		o = dd(s.option(form.Flag, 'ipv4', _('發布 IPv4（A）')));
		o.default = '1';
		o.rmempty = false;
		o = dd(s.option(form.Flag, 'ipv6', _('發布 IPv6（AAAA）'),
			_('預設關閉：不少線路（例如中華電信）會擋外面連進來的 IPv6，發布了別人反而連不上。確定外面連得進來再打開；關閉時會移除自己建立的 AAAA 記錄。')));
		o.default = '0';
		o.rmempty = false;
		o = dd(s.option(form.Value, 'interval', _('檢查間隔（分鐘）')));
		o.datatype = 'range(1,1440)';
		o.placeholder = '5';
		if (pro) {
			o = s.option(widgets.DeviceSelect, 'iface4', _('IPv4 介面（舊欄位）'), _('舊版設定：上面有選出口時不使用。'));
			o.noaliases = true;
			o.retain = true;
			o.depends({ enabled: '1', ip_source: 'interface' });
			o = s.option(widgets.DeviceSelect, 'iface6', _('IPv6 介面（舊欄位）'), _('空白 = 同 IPv4 介面'));
			o.noaliases = true;
			o.retain = true;
			o.depends({ enabled: '1', ip_source: 'interface' });
			o = dd(s.option(form.Flag, 'proxied', _('經過 Cloudflare 代理（橘色雲朵）'), _('DoT 不能經過代理，給 DoH / DoT 用的記錄請保持關閉。')));
			o = dd(s.option(form.Value, 'ttl', _('TTL（秒）'), _('1 = 自動')));
			o.datatype = 'uinteger';
			o.placeholder = '1';
			o = dd(s.option(form.Value, 'zone', _('Zone'), _('空白 = 從記錄名稱自動判斷')));
			o.datatype = 'hostname';
			o = dd(s.option(form.Value, 'force_hours', _('強制確認間隔（小時）'), _('IP 沒變時多久重新向 Cloudflare 確認一次記錄。')));
			o.datatype = 'uinteger';
			o.placeholder = '24';
			o = dd(s.option(form.Value, 'url4', _('IPv4 查詢網址')));
			o.placeholder = 'https://1.1.1.1/cdn-cgi/trace';
			o = dd(s.option(form.Value, 'url6', _('IPv6 查詢網址')));
			o.placeholder = 'https://[2606:4700:4700::1111]/cdn-cgi/trace';
		}
		common.panel(s, '_ddns_status', _('目前發布的結果'), function() { return ddnsPanel(ddnsStatus); });
		o = s.option(form.Button, '_ddns_now', _('立即更新'), _('服務執行中才能使用。'));
		o.depends('enabled', '1');
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
			o = s.option(form.Value, 'min_clients', _('排行最少人數'),
				_('公開頁的網站排行只列出至少這麼多位不同使用者造訪過的網站。預設 1 = 全部列出；不想讓訪客看到只有一台裝置去過的網站，就調高（例如 2）。LuCI 的儀表板不受限制。'));
			o.datatype = 'and(uinteger,min(1))';
			o.placeholder = String(common.def('site.minClients') || 1);
			o.depends('enabled', '1');
		}

		return m.render().then(function(node) { return E([], [common.modeBar(), node, pathsSection(paths), common.footer()]); });
	}
});
