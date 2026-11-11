'use strict';
'require baseclass';
'require form';
'require rpc';
'require ui';

// 各頁共用：簡易 / 專業模式、程式預設值（顯示成提示文字）、呼叫後端
var MODE_KEY = 'kuroshio-ui-mode';

var callDefaults = rpc.declare({ object: 'kuroshio', method: 'defaults', expect: { result: {} } });
var callApi = rpc.declare({ object: 'kuroshio', method: 'api', params: ['path', 'query'] });
var callAction = rpc.declare({ object: 'kuroshio', method: 'action', params: ['path', 'query'] });
var callAbout = rpc.declare({ object: 'kuroshio', method: 'about' });
var aboutPromise = null;

/** 文字一律用 textContent 放進去（核心回傳的字串不當成 HTML） */
function T(tag, attrs, text) {
	var n = E(tag, attrs || {});
	n.textContent = (text == null) ? '' : String(text);
	return n;
}

function safeUrl(u) { return (typeof u === 'string' && /^https?:\/\//.test(u)) ? u : null; }

function link(href, text) {
	var u = safeUrl(href);
	return u ? T('a', { 'href': u, 'target': '_blank', 'rel': 'noopener noreferrer' }, text || u) : T('span', {}, text || '-');
}

/** 核心給的 SVG 字串（ASCII）→ data: 網址，放進 <img>（不直接插進頁面） */
function svgImg(svg, alt) {
	if (typeof svg !== 'string' || svg.indexOf('<svg') < 0) return null;
	try {
		return E('img', { 'src': 'data:image/svg+xml;base64,' + window.btoa(svg), 'alt': alt, 'width': '140', 'height': '140',
			'style': 'width:140px;height:140px;border-radius:8px;background:#fff;padding:4px;box-sizing:border-box' });
	} catch (e) { return null; }
}

var FEAT = { doh: 'DoH', doh3: 'DoH3', dot: 'DoT', doq: 'DoQ', cdn: _('CDN 台灣節點'), community: _('好友社群'), filter: _('過濾'), acme: _('自動憑證'), 'windows-service': _('Windows 服務') };

function ver(v) { return (v && v !== 'unknown') ? 'v' + v : _('未知'); }

function getPath(obj, path) {
	return String(path).split('.').reduce(function(a, k) { return (a == null) ? undefined : a[k]; }, obj);
}

return baseclass.extend({
	defaults: {},

	isPro: function() {
		try { return window.localStorage.getItem(MODE_KEY) === 'pro'; } catch (e) { return false; }
	},

	setPro: function(on) {
		try { window.localStorage.setItem(MODE_KEY, on ? 'pro' : 'simple'); } catch (e) {}
	},

	/** 讀取 config.js 的預設值；失敗時回空物件（提示文字就不顯示） */
	loadDefaults: function() {
		var self = this;
		return L.resolveDefault(callDefaults(), {}).then(function(d) { self.defaults = d || {}; return self.defaults; });
	},

	def: function(path) { return getPath(this.defaults, path); },

	api: function(path, params) { return callApi(path, this.query(params)); },
	action: function(path, params) { return callAction(path, this.query(params)); },

	query: function(params) {
		return Object.keys(params || {}).map(function(k) {
			return encodeURIComponent(k) + '=' + encodeURIComponent(params[k]);
		}).join('&');
	},

	/** 頁面最上方的模式切換列（記在瀏覽器裡，不會改到路由器設定、也不會重啟服務） */
	modeBar: function() {
		var self = this, pro = this.isPro();
		var btn = function(on, label) {
			return E('button', {
				'class': 'btn cbi-button' + ((on === pro) ? ' cbi-button-action' : ''),
				'click': function(ev) {
					ev.preventDefault();
					if (on === pro) return;
					self.setPro(on);
					window.location.reload();
				}
			}, label);
		};
		return E('div', { 'class': 'cbi-section', 'style': 'display:flex;gap:.5em;align-items:center;flex-wrap:wrap' }, [
			E('strong', {}, _('介面模式')),
			btn(false, _('簡易')),
			btn(true, _('專業')),
			E('span', { 'class': 'cbi-value-description', 'style': 'margin:0' },
				pro ? _('顯示全部參數。不確定的欄位請保持空白，會使用程式內建的預設值。')
				    : _('只顯示常用設定，避免誤改細部參數。需要微調時切換到「專業」。'))
		]);
	},

	/**
	 * 數值選項：空白 = 使用 config.js 預設值（顯示在欄位裡當提示）
	 * section.option 版本，tab 有值時用 taboption
	 */
	num: function(s, tab, name, title, defPath, desc, datatype) {
		var o = tab ? s.taboption(tab, form.Value, name, title, desc) : s.option(form.Value, name, title, desc);
		var d = this.def(defPath);
		o.datatype = datatype || 'uinteger';
		o.rmempty = true;
		if (d !== undefined && d !== null) o.placeholder = String(d);
		return o;
	},

	/** 開關選項：沒設定時顯示 config.js 的預設狀態 */
	flag: function(s, tab, name, title, defPath, desc) {
		var o = tab ? s.taboption(tab, form.Flag, name, title, desc) : s.option(form.Flag, name, title, desc);
		var d = this.def(defPath);
		o.default = (d === false) ? '0' : '1';
		o.rmempty = false;
		return o;
	},

	notify: function(res, okText) {
		if (res && res.ok === false)
			ui.addNotification(null, E('p', {}, res.error || _('操作失敗')), 'danger');
		else
			ui.addNotification(null, E('p', {}, okText || _('完成')), 'info');
		return res;
	},

	/** 「關於」資料：{ core: {...} | null, ui: "版本" }（整個頁面只問一次） */
	loadAbout: function() {
		if (!aboutPromise)
			aboutPromise = L.resolveDefault(callAbout(), {}).then(function(r) {
				return { core: (r && r.core && typeof r.core === 'object') ? r.core : null, ui: (r && r.ui) || null };
			});
		return aboutPromise;
	},

	/** 「關於」的內容：核心與介面版本、授權、原始碼網址與 QR 碼 */
	aboutBlock: function(a) {
		var c = a.core, rows = [];
		var row = function(k, v) {
			rows.push(E('tr', { 'class': 'tr' }, [T('td', { 'class': 'td', 'style': 'width:9em;white-space:nowrap' }, k), E('td', { 'class': 'td' }, [v])]));
		};
		if (c) {
			row(_('核心'), T('span', {}, (c.name || _('黑潮 DNS')) + ' ' + ver(c.version)));
			row(_('程式語言 / 平台'), T('span', {}, [c.language, c.target].filter(Boolean).join(' · ')));
			if (Array.isArray(c.features) && c.features.length)
				row(_('編入的功能'), T('span', {}, c.features.map(function(f) { return FEAT[f] || String(f); }).join(' · ')));
		} else {
			row(_('核心'), T('em', {}, _('沒有回應：找不到 /usr/bin/kuroshio 或無法執行，請確認已安裝 kuroshio 套件。')));
		}
		row(_('LuCI 介面'), T('span', {}, 'luci-app-kuroshio ' + ver(a.ui)));
		row(_('授權'), link(c && c.licenseUrl || 'https://www.gnu.org/licenses/gpl-3.0.html', (c && c.license) || 'GPL-3.0-or-later'));
		row(_('原始碼'), c ? link(c.source) : T('span', {}, '-'));

		var qr = c ? svgImg(c.qrSource, _('原始碼網址 QR 碼')) : null;
		return E('div', { 'class': 'kuroshio-about', 'style': 'display:flex;gap:1.2em;flex-wrap:wrap;align-items:flex-start' }, [
			E('div', { 'style': 'flex:1 1 22em;min-width:0' }, [
				E('table', { 'class': 'table' }, rows),
				T('p', { 'class': 'cbi-section-descr', 'style': 'margin-top:.6em' },
					_('黑潮 DNS 是開放原始碼軟體，採用 GPL-3.0-or-later 授權：可以自由使用、修改與分享；如果把修改過的版本散布給別人，必須用同樣的授權一併提供原始碼。'))
			]),
			qr ? E('div', { 'style': 'text-align:center;font-size:12px;opacity:.85' }, [qr, T('div', {}, _('掃描開啟原始碼'))]) : ''
		]);
	},

	/**
	 * 每頁最下方：「黑潮 DNS 核心 v… · 介面 v… · GPL-3.0-or-later · 原始碼」，點「關於」展開詳細資訊
	 * opts.open：一開始就展開（狀態頁）
	 */
	footer: function(opts) {
		var self = this, open = !!(opts && opts.open);
		var line = E('div', { 'style': 'display:flex;gap:.4em;flex-wrap:wrap;align-items:center;font-size:12px;opacity:.85' });
		var core = T('span', {}, _('黑潮 DNS 核心') + ' ' + _('讀取中…'));
		line.appendChild(core);
		var body = E('div', { 'style': 'margin-top:.8em' + (open ? '' : ';display:none') });
		var toggle = T('button', { 'class': 'btn cbi-button', 'style': 'margin-left:auto;padding:0 .8em;line-height:1.8em', 'aria-expanded': String(open) }, _('關於'));
		toggle.addEventListener('click', function(ev) {
			ev.preventDefault();
			var show = body.style.display === 'none';
			body.style.display = show ? '' : 'none';
			toggle.setAttribute('aria-expanded', String(show));
		});
		var box = E('div', { 'class': 'cbi-section kuroshio-footer', 'style': 'margin-top:1.5em;border-top:1px solid var(--border-color-medium,#ddd);padding-top:.6em' }, [line, body]);

		this.loadAbout().then(function(a) {
			var c = a.core;
			var sep = function() { return T('span', { 'style': 'opacity:.6' }, '·'); };
			core.textContent = _('黑潮 DNS 核心') + ' ' + (c ? ver(c.version) : _('未回應'));
			line.appendChild(sep());
			line.appendChild(T('span', {}, _('介面') + ' ' + ver(a.ui)));
			line.appendChild(sep());
			line.appendChild(link(c && c.licenseUrl || 'https://www.gnu.org/licenses/gpl-3.0.html', (c && c.license) || 'GPL-3.0-or-later'));
			if (c && safeUrl(c.source)) {
				line.appendChild(sep());
				line.appendChild(link(c.source, _('原始碼')));
			}
			line.appendChild(toggle);
			body.appendChild(self.aboutBlock(a));
			box.setAttribute('data-ready', '1');
		});
		return box;
	},

	pre: function(text) {
		return E('pre', { 'style': 'white-space:pre-wrap;max-height:30em;overflow:auto;font-size:12px' }, text);
	}
});
