'use strict';
'require view';
'require form';
'require uci';
'require ui';
'require kuroshio.common as common';

// 連線來源限制（規格 08）：只開放台灣 / 自訂 ISP / 全開放、允許與封鎖名單、測試 IP
var T = common.T;
var KIND = { dot: 'DoT', doh: 'DoH', doq: 'DoQ', doh3: 'DoH3', site: _('公開頁'), community: _('社群共享'), plain: _('區網 DNS（53 埠）') };
var APPLY_DEFAULT = ['dot', 'doh', 'doq', 'doh3', 'site'];
var MODE = { taiwan: _('只開放台灣'), custom: _('自訂 ISP'), open: _('全開放') };

function fmtNum(n) { return (n == null || isNaN(n)) ? '-' : Number(n).toLocaleString('zh-TW'); }
/** 位址數量：一萬以上用「萬」（1,401 萬） */
function fmtWan(n) { return n >= 10000 ? fmtNum(Math.floor(n / 10000)) + ' 萬' : fmtNum(n); }

/** IP 或網段（IP/前綴長度；IPv4 0～32、IPv6 0～128），跟後端的解析一致；不接受 a.b.c.d/255.255.255.0 這種遮罩寫法 */
function checkCidr(v) {
	var m = /^([^/\s]+)(?:\/(\d{1,3}))?$/.exec(v || '');
	if (!m) return _('格式是 IP 或 IP/前綴長度，例如 203.0.113.7、198.51.100.0/24、2001:db8::/32');
	var ip = m[1], v4 = /^\d+\.\d+\.\d+\.\d+$/.test(ip);
	var okIp = v4 ? ip.split('.').every(function(x) { return +x <= 255 && (x.length === 1 || x.charAt(0) !== '0'); }) : isIPv6(ip);
	if (!okIp) return _('「%s」不是 IP 位址（不含埠號與中括號）').format(ip);
	if (m[2] != null && +m[2] > (v4 ? 32 : 128)) return v4 ? _('IPv4 的前綴長度是 0～32') : _('IPv6 的前綴長度是 0～128');
	return true;
}
function isIPv6(s) {
	if (!/^[0-9a-fA-F:.]+$/.test(s) || s.indexOf(':') < 0) return false;
	var dbl = s.split('::');
	if (dbl.length > 2) return false;
	var parts = function(p) { return p === '' ? [] : p.split(':'); };
	var all = parts(dbl[0]).concat(dbl.length === 2 ? parts(dbl[1]) : []), n = 0;
	for (var i = 0; i < all.length; i++) {
		if (all[i].indexOf('.') >= 0) {
			if (i !== all.length - 1 || !/^\d+\.\d+\.\d+\.\d+$/.test(all[i])) return false;
			n += 2;
		} else if (/^[0-9a-fA-F]{1,4}$/.test(all[i])) n++;
		else return false;
	}
	return dbl.length === 2 ? n <= 7 : n === 8;
}
function isIP(s) { return checkCidr(s) === true && s.indexOf('/') < 0; }

/**
 * 勾選清單（list）：items = [{ id, body }]；all = 「全選」的值（例如 '*'）；dflt = 沒寫時的預設。
 * 一項都不勾時寫 list xxx ''（UCI 有這個選項、內容是空的 = 一項都不要；直接刪掉的話會變回預設值）
 */
var CheckList = form.Value.extend({
	__name__: 'CBI.KuroshioCheckList',

	current: function(sid) {
		var v = uci.get('kuroshio', sid, this.option);
		return (v == null) ? (this.dflt || []).slice() : L.toArray(v).filter(function(x) { return x !== ''; });
	},

	renderWidget: function(sid) {
		var self = this, cur = this.current(sid), star = this.all != null && cur.indexOf(this.all) >= 0;
		var box = E('div', { 'id': this.cbid(sid), 'class': 'kuroshio-checklist', 'style': 'display:flex;flex-direction:column;gap:.35em' });
		var none = T('div', { 'class': 'alert-message warning', 'style': 'margin:.3em 0 0;display:' + (cur.length ? 'none' : '') }, this.noneText || _('一項都沒有勾'));
		var boxes = [];
		var sync = function() { none.style.display = boxes.some(function(c) { return c.checked; }) ? 'none' : ''; };
		var row = function(value, body, checked, strong) {
			var c = E('input', { 'type': 'checkbox', 'value': value, 'data-all': strong ? '1' : null });
			c.checked = checked;
			var lab = E('label', { 'style': 'display:flex;gap:.6em;align-items:flex-start;padding:.35em .5em;border:1px solid var(--border-color-medium,#ddd);border-radius:4px;cursor:pointer' +
				(strong ? ';background:var(--background-color-medium,rgba(0,0,0,.04))' : '') }, [c, E('div', { 'style': 'min-width:0;flex:1' }, body)]);
			box.appendChild(lab);
			return c;
		};
		var allBox = null;
		if (this.all != null) {
			allBox = row(this.all, [T('strong', {}, this.allLabel), this.allDesc ? T('div', { 'style': 'font-size:12px;opacity:.8' }, this.allDesc) : ''], star, true);
			allBox.addEventListener('change', function() {
				if (allBox.checked) boxes.forEach(function(c) { c.checked = true; });
				sync();
			});
		}
		var items = (typeof this.items === 'function') ? this.items() : (this.items || []);
		items.forEach(function(it) {
			var c = row(it.id, it.body, star || cur.indexOf(it.id) >= 0);
			c.addEventListener('change', function() { if (allBox) allBox.checked = false; sync(); });
			boxes.push(c);
		});
		// 設定裡有、但清單裡沒有的值：也列出來，可以取消
		cur.forEach(function(v) {
			if (v === self.all || items.some(function(it) { return it.id === v; })) return;
			var c = row(v, [T('strong', {}, v), ' ', common.badge(self.missingText || _('不認得'), 'warn')], true);
			c.addEventListener('change', function() { if (allBox) allBox.checked = false; sync(); });
			boxes.push(c);
		});
		box.appendChild(none);
		return box;
	},

	formvalue: function(sid) {
		var box = document.getElementById(this.cbid(sid));
		if (!box) return null;
		var all = box.querySelector('input[data-all]');
		if (all && all.checked) return [this.all];
		return [].slice.call(box.querySelectorAll('input[type=checkbox]:not([data-all])')).filter(function(c) { return c.checked; }).map(function(c) { return c.value; });
	},

	parse: function(sid) {
		// 不符合 depends 時保留原本的設定（切回「只開放台灣」再切回來不用重勾）
		if (!this.isActive(sid)) return Promise.resolve();
		var fv = this.formvalue(sid);
		if (fv == null) return Promise.resolve();
		var had = uci.get('kuroshio', sid, this.option);
		var same = function(a, b) { return a.length === b.length && a.every(function(x, i) { return x === b[i]; }); };
		if (same(fv, this.dflt || [])) {
			if (had != null) uci.unset('kuroshio', sid, this.option);
		} else if (had == null || !same(fv, this.current(sid))) {
			uci.set('kuroshio', sid, this.option, fv.length ? fv : ['']);
		}
		return Promise.resolve();
	},

	write: function() {},
	remove: function() {}
});

/** 整列寬的唯讀區塊（不佔左邊的標題欄，窄螢幕也放得下表格） */
function block(s, name, node) {
	var o = s.option(form.DummyValue, name);
	o.render = function() {
		return E('div', { 'class': 'cbi-value', 'id': 'kuroshio-panel-' + name.replace(/^_/, '') }, E('div', { 'style': 'overflow-x:auto;width:100%' }, node()));
	};
	o.write = function() {};
	o.remove = function() {};
	return o;
}

function kv(rows) {
	return E('table', { 'class': 'table' }, rows.map(function(r) {
		return E('tr', { 'class': 'tr' }, [T('td', { 'class': 'td', 'style': 'width:10em;white-space:nowrap' }, r[0]), E('td', { 'class': 'td' }, [r[1]])]);
	}));
}

return view.extend({
	load: function() {
		return Promise.all([common.loadDefaults(), uci.load('kuroshio'), common.fetch('/api/access')]);
	},

	render: function(data) {
		var acc = data[2], pro = common.isPro();
		var groups = (acc && Array.isArray(acc.groups)) ? acc.groups : [];
		var m, s, o;

		m = new form.Map('kuroshio', _('黑潮 DNS · 連線來源'),
			_('誰可以連進 DoH / DoT / DoQ / DoH3 與公開頁。黑潮 DNS 是為台灣網路調校的 DNS（台灣 CDN 節點、台灣上游），在國外使用沒有好處，所以預設只讓台灣的 IP 連進來，順便擋掉國外的掃描與濫用。只影響從外面連進來的連線，不影響路由器與區網。OpenWrt 上多數情況會直接在防火牆（nftables）丟棄，不佔程式資源。'));

		/** 把一個網段加到允許 / 封鎖名單（還沒有儲存） */
		var addTo = function(opt, net) {
			var found = m.lookupOption(opt, 'access');
			var w = found && found[0].getUIElement('access');
			if (!w) return;
			var cur = L.toArray(w.getValue());
			if (cur.indexOf(net) < 0) {
				cur.push(net);
				w.setValue(cur);
			}
			ui.addNotification(null, E('p', {}, _('已把 %s 加到%s（按「儲存並套用」才會生效）').format(net, opt === 'deny' ? _('封鎖名單') : _('允許名單'))), 'info');
		};

		// ---------------- 目前狀態 ----------------
		s = m.section(form.NamedSection, 'access', 'access', _('目前狀態'), _('已套用的設定。拒絕的次數從服務啟動後開始算。'));
		block(s, '_access_status', function() {
			if (!acc) return T('em', {}, _('服務沒有執行，無法讀取。'));
			var dn = acc.denied || {}, by = dn.byListener || {};
			var on = groups.filter(function(g) { return g.enabled; });
			var rows = [
				[_('開放對象'), T('span', {}, (MODE[acc.mode] || acc.mode || '-') + (acc.mode === 'custom' && groups.length ? _('（開放 %d / %d 組）').format(on.length, groups.length) : ''))],
				[_('套用在'), T('span', {}, [].concat(acc.applyTo || []).map(function(k) { return KIND[k] || k; }).join('、') || _('（沒有，不限制）'))],
				[_('台灣 IP 資料'), acc.generatedAt ? E('span', {}, [T('span', {}, _('%s 的資料').format(acc.generatedAt) + ' '), acc.autoUpdate ? common.badge(_('每天自動更新'), 'ok') : common.badge(_('跟著套件升級更新'), 'off')])
					: common.badge(_('讀不到'), 'err')],
				[_('已拒絕'), T('span', {}, _('%s 次').format(fmtNum(dn.total)) + (dn.total ? '（' + Object.keys(by).filter(function(k) { return by[k]; }).map(function(k) { return (KIND[k] || k) + ' ' + fmtNum(by[k]); }).join('、') + '）' : ''))]
			];
			if (pro) rows.push([_('記憶體'), T('span', {}, '%.1f KB（%s 個區間）'.format((acc.memoryBytes || 0) / 1024, fmtNum(acc.ranges)))]);
			var top = [].concat(acc.topDenied || []).slice(0, 20);
			var btn = function(text, opt, net, cls) {
				return T('button', { 'class': 'btn cbi-button ' + cls, 'style': 'padding:0 .6em;line-height:1.8em;margin:.1em', 'data-net': net, 'data-opt': opt,
					'click': function(ev) { ev.preventDefault(); addTo(opt, net); } }, text);
			};
			return E('div', { 'id': 'kuroshio-access-status' }, [
				acc.failOpen ? T('div', { 'class': 'alert-message danger', 'id': 'kuroshio-access-failopen' },
					_('台灣 IP 資料讀不到，現在不擋任何來源（封鎖名單照樣有效）') + (acc.warning ? '：' + acc.warning : '')) :
					(acc.warning ? T('div', { 'class': 'alert-message warning' }, acc.warning) : ''),
				kv(rows),
				T('h4', { 'style': 'margin:.8em 0 .3em' }, _('被拒絕最多的網段')),
				common.table([_('網段'), _('次數'), ''], top.map(function(t) {
					return [t.net, fmtNum(t.count), E('span', {}, [btn(_('加入封鎖'), 'deny', t.net, 'cbi-button-negative'), btn(_('加入允許'), 'allow', t.net, '')])];
				}), _('還沒有拒絕過任何連線')),
				top.length ? T('div', { 'class': 'cbi-value-description' }, _('IPv4 以 /24、IPv6 以 /48 為單位統計。')) : ''
			]);
		});

		// ---------------- 開放對象 ----------------
		s = m.section(form.NamedSection, 'access', 'access', _('開放對象'),
			_('區網與私有位址（192.168.x.x、10.x.x.x 等）、路由器自己、路由器各網卡所在的網段、社群好友目前的 IP 一律允許，不用加進名單。人在國外、手機漫遊、用國外的 VPN 出口，或用國外的監測服務（例如上線檢查）時連不進來：把那個 IP 加進下面的允許名單，或改成全開放。'));
		o = s.option(form.ListValue, 'mode', _('誰可以連進來'),
			_('只開放台灣：台灣各家 ISP 與其他登記在台灣的網段都能連，國外的來源連不進來。') + '<br>' +
			_('自訂 ISP：只開放下面勾選的業者，例如只給中華電信與學術網路。') + '<br>' +
			_('全開放：任何來源都能連（封鎖名單照樣有效）。'));
		o.widget = 'radio';
		o.orientation = 'vertical';
		o.value('taiwan', _('只開放台灣（建議）'));
		o.value('custom', _('自訂 ISP'));
		o.value('open', _('全開放'));
		o.default = 'taiwan';
		o.rmempty = false;

		o = s.option(CheckList, 'groups', _('開放的 ISP'),
			_('全部勾選 = 整個台灣。業者合併後網段會慢慢移到併購方，兩組都保留；大小是 0 表示已經全部移過去。') +
			(groups.length ? '' : ' ' + _('服務沒有執行或讀不到台灣 IP 資料，無法列出 ISP。')));
		o.depends('mode', 'custom');
		o.retain = true;
		o.all = '*';
		o.dflt = ['*'];
		o.allLabel = _('全選（含日後新增的 ISP）');
		o.allDesc = _('台灣 IP 資料更新後新加入的業者也自動開放。');
		o.noneText = _('一組都沒有勾：只剩區網、好友與允許名單可以連進來。');
		o.missingText = groups.length ? _('資料裡沒有這一組，不會生效') : _('已勾選（讀不到 ISP 清單）');
		o.items = groups.map(function(g) {
			var sz = g.size || {}, body = [E('div', { 'style': 'display:flex;gap:.5em;flex-wrap:wrap;align-items:center' }, [
				T('strong', {}, g.name || g.id),
				sz.v4 ? common.badge(fmtWan(sz.v4) + (sz.v4 >= 10000 ? _('個位址') : ' ' + _('個位址')), 'off') : common.badge(_('目前沒有網段'), 'warn')])];
			if (pro) {
				if (g.note) body.push(T('div', { 'style': 'font-size:12px;opacity:.8' }, g.note));
				var asns = [].concat(g.asns || []);
				var inNote = g.note && asns.every(function(n) { return g.note.indexOf(String(n)) >= 0; });
				body.push(T('div', { 'style': 'font-size:12px;opacity:.7;font-family:monospace;word-break:break-all' },
					g.id + (asns.length && !inNote ? ' · ' + asns.map(function(n) { return 'AS' + n; }).join('、') : '') +
					' · ' + _('%s 個 IPv4 網段、%s 個 IPv6 網段').format(fmtNum((g.cidrs || {}).v4), fmtNum((g.cidrs || {}).v6))));
			}
			return { id: g.id, body: body };
		});

		// ---------------- 自訂名單 ----------------
		s = m.section(form.NamedSection, 'access', 'access', _('自訂名單'),
			_('一行一個 IP 或網段（CIDR），IPv4 與 IPv6 都可以，例如 203.0.113.7、198.51.100.0/24、2001:db8::/32。'));
		o = s.option(form.DynamicList, 'allow', _('允許名單'), _('不管上面選哪一種都放行，例如人在國外的家人、公司的固定 IP、國外的監測服務。'));
		o.placeholder = '203.0.113.0/24';
		o.validate = function(sid, v) { return !v || checkCidr(v); };
		o = s.option(form.DynamicList, 'deny', _('封鎖名單'), _('優先於一切（本機除外）：區網、好友、允許名單、全開放都擋不住它。'));
		o.placeholder = '198.51.100.7';
		o.validate = function(sid, v) { return !v || checkCidr(v); };

		// ---------------- 測試 IP ----------------
		s = m.section(form.NamedSection, 'access', 'access', _('測試 IP'), _('輸入一個 IP，看它能不能連進來、是哪一條規則決定的（依已套用的設定，還沒儲存的變更不算）。'));
		block(s, '_access_test', function() {
			var inp = E('input', { 'type': 'text', 'class': 'cbi-input-text', 'id': 'kuroshio-access-ip', 'placeholder': '168.95.1.1', 'style': 'max-width:18em' });
			var out = E('div', { 'id': 'kuroshio-access-result', 'style': 'margin-top:.5em' });
			var run = function(ev) {
				if (ev) ev.preventDefault();
				var ip = inp.value.trim();
				out.replaceChildren();
				if (!isIP(ip)) { out.appendChild(common.badge(_('請輸入一個 IP 位址（不含前綴長度與埠號）'), 'warn')); return; }
				out.appendChild(T('em', {}, _('查詢中…')));
				return common.fetch('/api/access', { ip: ip }).then(function(x) {
					out.replaceChildren();
					if (!x) { out.appendChild(common.badge(_('服務沒有回應'), 'err')); return; }
					var kinds = [].concat(x.applyTo || []).map(function(k) { return KIND[k] || k; }).join('、');
					out.appendChild(common.badge(x.allowed ? _('可以連進來') : _('會被擋下'), x.allowed ? 'ok' : 'err'));
					out.appendChild(T('span', {}, ' ' + (x.reason || '') + (kinds ? _('（套用在 %s）').format(kinds) : '')));
				});
			};
			inp.addEventListener('keydown', function(ev) { if (ev.key === 'Enter') run(ev); });
			return E('div', {}, [E('div', { 'style': 'display:flex;gap:.5em;flex-wrap:wrap;align-items:center' }, [inp,
				T('button', { 'class': 'btn cbi-button cbi-button-action', 'id': 'kuroshio-access-test', 'click': run }, _('測試'))]), out]);
		});

		// ---------------- 台灣 IP 資料、套用範圍 ----------------
		s = m.section(form.NamedSection, 'access', 'access', _('台灣 IP 資料'));
		o = s.option(form.Flag, 'auto_update', _('自動更新台灣 IP 資料'),
			_('每天下載一次本專案發布的新資料（業者合併、網段變動）。格式正確、比目前的新、大小差不多才換上，存檔受 Flash 寫入限制。不開的話跟著套件升級更新。'));
		o.default = '0';
		o.rmempty = false;
		if (pro) {
			o = s.option(form.Value, 'update_url', _('更新來源網址'));
			o.placeholder = common.def('access.updateUrl') || '';
			o.validate = function(sid, v) { return !v || /^https:\/\/\S+$/.test(v) || _('請輸入 https:// 開頭的網址'); };
			o = s.option(form.Value, 'data_file', _('指定資料檔'), _('空白 = 套件附帶的 /usr/share/kuroshio/geo/tw-ip.json。'));
			o.validate = function(sid, v) { return !v || /^\/\S*$/.test(v) || _('請輸入完整路徑（/ 開頭，不能有空白）'); };

			o = s.option(CheckList, 'apply_to', _('套用在哪些服務'),
				_('社群共享預設不套用（好友的 IP 本來就一律允許）；區網 DNS（53 埠）有「允許查詢的來源」另外把關。全部取消 = 不限制任何服務。'));
			o.dflt = APPLY_DEFAULT;
			o.noneText = _('一項都沒有勾：不限制任何服務。');
			o.items = ['dot', 'doh', 'doq', 'doh3', 'site', 'community', 'plain'].map(function(k) { return { id: k, body: [T('span', {}, KIND[k])] }; });

			o = s.option(form.Flag, 'log', _('拒絕時寫進日誌'), _('每分鐘最多一行，含這一分鐘被拒絕的次數。'));
			o.default = '1';
			o.rmempty = false;
		}

		return m.render().then(function(node) { return E([], [common.modeBar(), node, common.footer()]); });
	}
});
