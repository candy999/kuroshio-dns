'use strict';
'require view';
'require form';
'require ui';
'require kuroshio.common as common';

var LABELS = {
	cloudflare: 'Cloudflare', cloudfront: 'Amazon CloudFront', fastly: 'Fastly', gcore: 'Gcore', azure: 'Azure Front Door / CDN',
	akamai: 'Akamai', edgio: 'Edgio / Edgecast', cdnetworks: 'CDNetworks', tencent: _('騰訊雲 CDN / EdgeOne'),
	alibaba: _('阿里雲 CDN'), wangsu: _('網宿'), bytedance: _('字節跳動 BytePlus'), apple: 'Apple CDN'
};
var ANYCAST = { cloudflare: 1, cloudfront: 1, fastly: 1, gcore: 1, azure: 1 };

return view.extend({
	load: function() {
		return common.loadDefaults();
	},

	render: function() {
		var pro = common.isPro();
		var m, s, o;
		var num = function(name, title, path, desc, dt) { return common.num(s, null, name, title, path, desc, dt); };

		m = new form.Map('kuroshio', _('黑潮 DNS · CDN 台灣節點'),
			_('Cloudflare、CloudFront 等常把台灣用戶導去國外機房。這裡把答案換成台北、高雄節點，並先用 HTTPS 實際連線驗證網站能正常運作才換；Akamai 等 DNS 分流型 CDN 則帶台灣網段的 ECS 找出更近的節點。'));

		// ---------------- 總開關與驗證 ----------------
		s = m.section(form.NamedSection, 'cdn', 'cdn', _('節點置換'));
		if (pro) {
			s.tab('verify', _('驗證'));
			s.tab('pool', _('節點池'));
			s.tab('cross', _('跨 CDN 備援'));
			s.tab('misc', _('其他'));
		}
		// 專業模式有分頁，基本選項放在第一個分頁
		var add = function(cls, name, title, desc) { return pro ? s.taboption('verify', cls, name, title, desc) : s.option(cls, name, title, desc); };

		o = add(form.Flag, 'enabled', _('啟用 CDN 台灣節點置換'));
		o.rmempty = false;

		o = add(form.ListValue, 'trial_mode', _('未驗證的網站'),
			_('還沒驗證過的網站要怎麼回答。「先回原始結果」最穩：驗證通過後下一次查詢才換台灣節點。'));
		o.value('original', _('先回原始結果，驗證通過才換（推薦）'));
		o.value('alias', _('先換台灣節點，驗證失敗再改回'));
		o.default = common.def('cdn.trialMode') || 'original';

		o = add(form.ListValue, 'v6_policy', _('沒有台灣 IPv6 節點時'));
		o.value('drop', _('丟棄該 CDN 的 IPv6 位址（避免 IPv6 繞回國外，推薦）'));
		o.value('keep', _('保留'));
		o.default = common.def('cdn.v6Policy') || 'drop';

		if (pro) {
			var t = function(tab, name, title, path, desc, dt) { return common.num(s, tab, name, title, path, desc, dt); };
			t('verify', 'trial_ttl', _('未驗證時的 TTL（秒）'), 'cdn.trialTtl');
			t('verify', 'verify_ok_hours', _('驗證通過有效時間（小時）'), 'cdn.verifyOkHours', _('熱門網域到期前會自動複驗。'));
			t('verify', 'verify_fail_hours', _('驗證失敗後重試（小時）'), 'cdn.verifyFailHours', _('每次失敗加倍。'));
			t('verify', 'verify_fail_max_days', _('重試間隔上限（天）'), 'cdn.verifyFailMaxDays');
			t('verify', 'verify_timeout_ms', _('驗證逾時（毫秒）'), 'cdn.verifyTimeoutMs');
			t('verify', 'verify_concurrency', _('同時驗證數'), 'cdn.verifyConcurrency');
			t('verify', 'nearest_min_gain_ms', _('沒有台灣 POP 時最少快幾毫秒才換'), 'cdn.nearestMinGainMs', _('Fastly 等：換到鄰近國家節點的門檻。'));

			t('pool', 'serve_count', _('每次回幾個台灣 IP'), 'cdn.serveCount');
			t('pool', 'min_pool', _('可用節點少於幾個就重建'), 'cdn.minPool');
			t('pool', 'health_interval_min', _('節點池健檢間隔（分鐘）'), 'cdn.healthIntervalMin');
			t('pool', 'quality_interval_min', _('鄰近節點品質重測（分鐘）'), 'cdn.qualityIntervalMin', _('Fastly：海纜壅塞、掉包變多時自動換 POP。'));

			o = s.taboption('cross', form.Flag, 'cross_enabled', _('啟用跨 CDN 備援'),
				_('原本的 CDN 在台灣沒有節點（例如 Fastly）時，測試同一個網站是不是也放在 Cloudflare、CloudFront、Azure、Akamai 的台灣節點上；憑證與網頁內容都一致才採用。'));
			o.default = common.def('cdn.cross.enabled') === false ? '0' : '1';
			o.rmempty = false;
			t('cross', 'cross_min_orig_ms', _('原本延遲超過幾毫秒才嘗試'), 'cdn.cross.minOrigMs');
			t('cross', 'cross_recheck_hours', _('複驗間隔（小時）'), 'cdn.cross.recheckHours');
			t('cross', 'cross_fail_days', _('失敗後幾天再試'), 'cdn.cross.failDays');
			t('cross', 'cross_akamai_max_ms', _('Akamai 台灣節點延遲上限（毫秒）'), 'cdn.cross.akamaiMaxMs');
			t('cross', 'cross_concurrency', _('同時測試數'), 'cdn.cross.concurrency');

			t('misc', 'max_entries', _('CDN 網域資料庫上限（筆）'), 'cdn.maxEntries', _('記憶體較小的機器可以調低。'));
		}

		// ---------------- 各家 CDN ----------------
		s = m.section(form.GridSection, 'cdn_provider', _('各家 CDN'),
			_('任播型（Cloudflare、CloudFront、Fastly、Gcore、Azure）用 IP 置換；DNS 分流型（Akamai 等）用 ECS 找台灣節點。'));
		s.anonymous = false;
		s.addremove = false;
		s.sectiontitle = function(sid) { return LABELS[sid] || sid; };

		o = s.option(form.DummyValue, '_type', _('類型'));
		o.cfgvalue = function(sid) { return ANYCAST[sid] ? _('任播 · IP 置換') : _('DNS 分流 · ECS'); };
		o.modalonly = false;
		o = s.option(form.Flag, 'enabled', _('啟用'));
		o.default = '1';
		o.rmempty = false;
		o.editable = true;
		if (pro) {
			o = s.option(form.Flag, 'ecs', _('用 ECS 找台灣節點'));
			o.modalonly = true;
			o = s.option(form.Value, 'serve_count', _('每次回幾個 IP'));
			o.datatype = 'uinteger';
			o.placeholder = String(common.def('cdn.serveCount') || 4);
			o.modalonly = true;
			o = s.option(form.DynamicList, 'seed_v4', _('種子節點（IPv4）'), _('節點池還沒建立前先用這些台灣 IP，每日工作會自動更新節點池。'));
			o.datatype = 'ip4addr';
			o.modalonly = true;
		}

		// ---------------- ECS ----------------
		s = m.section(form.NamedSection, 'ecs', 'ecs', _('ECS 突破（DNS 分流型 CDN）'),
			_('帶不同的台灣網段去問支援 ECS 的 DNS，找到明顯更近且 HTTPS 驗證通過的節點才換。本機對外 IP 的 /24 會自動放在最前面。'));
		o = s.option(form.DynamicList, 'tw_subnet', _('台灣網段'), _('放你用戶實際所在的 ISP 網段效果最好。'));
		o.datatype = 'cidr4';
		if (pro) {
			o = s.option(form.DynamicList, 'resolver', _('支援 ECS 的 DNS'), _('Cloudflare 1.1.1.1 不支援 ECS。'));
			num('min_gain_ms', _('至少快幾毫秒'), 'cdn.ecs.minGainMs');
			num('min_gain_ratio', _('且至少快幾成'), 'cdn.ecs.minGainRatio', _('0.3 = 30%'), 'ufloat');
			num('result_hours', _('結果有效時間（小時）'), 'cdn.ecs.resultHours');
			num('concurrency', _('同時查詢數'), 'cdn.ecs.concurrency');
		}

		// ---------------- 工具：節點池、網域 ----------------
		var poolBox = E('div', {}, E('em', {}, _('讀取中…')));
		var loadPools = function() {
			return common.api('/api/cdn/pools').then(function(r) {
				poolBox.innerHTML = '';
				if (!r || r.ok === false) { poolBox.appendChild(E('em', {}, (r && r.error) || _('服務未啟動'))); return; }
				var rows = Object.keys(r.result || {}).map(function(k) {
					var p = r.result[k];
					var ok4 = (p.v4 || []).filter(function(x) { return !x.bad; });
					return E('tr', { 'class': 'tr' }, [
						E('td', { 'class': 'td' }, LABELS[k] || k),
						E('td', { 'class': 'td' }, '%d / %d'.format(ok4.length, (p.v4 || []).length)),
						E('td', { 'class': 'td' }, String((p.v6 || []).length)),
						E('td', { 'class': 'td' }, ok4.slice(0, 4).map(function(x) { return x.ip + (x.ms != null ? ' (' + Math.round(x.ms) + 'ms)' : ''); }).join(', ') || '-'),
						E('td', { 'class': 'td' }, p.scan ? 'TW %d · Global %d · Dead %d'.format(p.scan.tw, p.scan.global, p.scan.dead) : '-')
					]);
				});
				poolBox.appendChild(E('table', { 'class': 'table' }, [
					E('tr', { 'class': 'tr table-titles' }, [
						E('th', { 'class': 'th' }, _('CDN')), E('th', { 'class': 'th' }, _('IPv4 可用 / 全部')), E('th', { 'class': 'th' }, _('IPv6')),
						E('th', { 'class': 'th' }, _('最快節點')), E('th', { 'class': 'th' }, _('/24 掃描'))
					])
				].concat(rows)));
			});
		};

		var nameIn = E('input', { 'type': 'text', 'class': 'cbi-input-text', 'placeholder': 'www.example.com', 'style': 'max-width:22em' });
		var policy = E('select', { 'class': 'cbi-input-select' }, [
			E('option', { 'value': 'auto' }, _('自動驗證')), E('option', { 'value': 'always' }, _('一律置換')), E('option', { 'value': 'never' }, _('永不置換'))
		]);
		var out = E('div');
		var show = function(r) {
			out.innerHTML = '';
			if (!r || r.ok === false) return common.notify(r);
			out.appendChild(common.pre(JSON.stringify(r.result, null, 2)));
		};
		var name = function() { var v = nameIn.value.trim().toLowerCase(); if (!v) ui.addNotification(null, E('p', {}, _('請輸入網域')), 'warning'); return v; };
		var btn = function(label, fn, cls) { return E('button', { 'class': 'btn cbi-button ' + (cls || ''), 'click': ui.createHandlerFn(null, fn) }, label); };

		var tools = E([], [
			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, _('台灣節點池')),
				E('p', { 'class': 'cbi-section-descr' }, _('每天 05:30 重建，每 30 分鐘健檢。')),
				poolBox,
				E('div', { 'style': 'margin-top:.5em;display:flex;gap:.5em;flex-wrap:wrap' }, [
					btn(_('重新整理'), loadPools),
					btn(_('立即重建節點池'), function() { return common.action('/api/jobs/run', { name: 'cdn-pool' }).then(function(r) { common.notify(r, _('已排入背景執行，完成後自動套用')); }); }, 'cbi-button-action')
				])
			]),
			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, _('網域工具')),
				E('p', { 'class': 'cbi-section-descr' }, _('追蹤一個網域的完整解析過程，或手動指定要不要換台灣節點。')),
				E('div', { 'style': 'display:flex;gap:.5em;flex-wrap:wrap;align-items:center' }, [
					nameIn,
					btn(_('追蹤'), function() { var n = name(); if (n) return common.api('/api/trace', { name: n, type: 'A' }).then(show); }, 'cbi-button-action'),
					btn(_('重新驗證'), function() { var n = name(); if (n) return common.action('/api/cdn/verify', { name: n, family: 4 }).then(show); }),
					btn(_('ECS 突破'), function() { var n = name(); if (n) return common.action('/api/cdn/ecs', { name: n }).then(show); }),
					policy,
					btn(_('套用策略'), function() { var n = name(); if (n) return common.action('/api/cdn/policy', { name: n, policy: policy.value }).then(show); })
				]),
				out
			])
		]);

		window.setTimeout(loadPools, 100);
		return m.render().then(function(node) { return E([], [common.modeBar(), node, tools, common.footer()]); });
	}
});
