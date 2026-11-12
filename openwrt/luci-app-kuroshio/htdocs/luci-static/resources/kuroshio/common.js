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

// 儀表板一打開就要讀七、八個 API，實機上第一次載入偶爾出現「XHR request aborted by browser」（連線被中斷）。
// 同時最多送 2 個（低階路由器的 uhttpd / rpcd 負擔也比較小），其餘排隊；讀取類的請求被中斷、逾時時再試兩次。
var MAX_INFLIGHT = 2;
var inflight = 0;
var waiting = [];

function pump() {
	while (inflight < MAX_INFLIGHT && waiting.length) {
		var job = waiting.shift();
		inflight++;
		job.fn().then(function(v) { inflight--; pump(); return v; }, function(e) { inflight--; pump(); throw e; })
			.then(job.resolve, job.reject);
	}
}

function limited(fn) {
	return new Promise(function(resolve, reject) {
		waiting.push({ fn: fn, resolve: resolve, reject: reject });
		pump();
	});
}

/** 連線被中斷、逾時這類暫時性的錯誤（服務沒啟動、路徑不允許不算，不重試） */
function transient(e) {
	return /abort|timed? ?out|XHR|NetworkError|Failed to fetch|Load failed/i.test(String((e && e.message) || e));
}

function rpcCall(fn, path, query, retries) {
	return limited(function() { return fn(path, query); }).catch(function(e) {
		if (retries > 0 && transient(e))
			return new Promise(function(r) { setTimeout(r, 400 * (3 - retries)); }).then(function() { return rpcCall(fn, path, query, retries - 1); });
		throw e;
	});
}

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

/*
 * 各頁共用的樣式（固定字串，不含任何資料）。顏色一律從主題的文字顏色（currentColor）調出來，
 * 淺色 / 深色、bootstrap / argon / material / openwrt2020 / vantage 都跟著主題走，不寫死白底。
 * 不支援 color-mix() 的舊瀏覽器用前一行的半透明灰色。
 */
var CSS = [
	/* 區塊：主題本身沒有內距（argon 的 .cbi-section 是 padding: 0，只有標題自己縮排）時，fitSections() 會在 <html> 加上
	   kuroshio-pad，並把 --kuroshio-inset 設成主題標題的縮排，內容才不會貼著區塊邊緣 */
	':root.kuroshio-pad #view .cbi-section.kuroshio-sec{padding:0 var(--kuroshio-inset,1rem) var(--kuroshio-inset,1rem)}',
	/* 主題的標題列自己有縮排（argon 深色時還有底色）：往外推回區塊邊緣，照主題原樣顯示 */
	':root.kuroshio-pad:not(.kuroshio-flat) #view .kuroshio-sec>h3:first-child{margin-left:calc(-1 * var(--kuroshio-inset));margin-right:calc(-1 * var(--kuroshio-inset));width:auto}',
	':root.kuroshio-pad #view .kuroshio-sec>p:first-child,:root.kuroshio-pad #view .kuroshio-sec>.cbi-section-descr{padding-left:0;padding-right:0}',
	':root.kuroshio-pad.kuroshio-flat #view .kuroshio-sec>h3:first-child{padding-top:var(--kuroshio-inset,1rem)}',
	':root.kuroshio-pad #view .cbi-section.kuroshio-sec:not(:has(>h3:first-child)){padding-top:var(--kuroshio-inset,1rem)}',
	'#view .cbi-section .cbi-section.kuroshio-sec{padding-left:0;padding-right:0}',
	'#view .kuroshio-footer{border-top:1px solid rgba(128,128,128,.25);border-top-color:color-mix(in srgb,currentColor 14%,transparent)}',
	'.kuroshio-sec{min-width:0}',
	/* 數字卡片：淡淡的底色（文字顏色的 5%）＋很淡的框，寬度不夠時自動換行，不會超出區塊 */
	'.kuroshio-tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,10.5em),1fr));gap:.6em;margin:.2em 0 .4em}',
	'.kuroshio-tile{min-width:0;box-sizing:border-box;padding:.65em .85em .7em;border-radius:8px;' +
		'background:rgba(128,128,128,.07);background:color-mix(in srgb,currentColor 5%,transparent);' +
		'border:1px solid rgba(128,128,128,.14);border-color:color-mix(in srgb,currentColor 10%,transparent);box-shadow:none;color:inherit}',
	'.kuroshio-tile-l{font-size:12px;line-height:1.4;opacity:.72;overflow-wrap:anywhere}',
	'.kuroshio-tile-v{font-size:1.35em;font-weight:600;line-height:1.3;margin:.1em 0;font-variant-numeric:tabular-nums;word-break:keep-all;overflow-wrap:break-word}',
	'.kuroshio-nb{white-space:nowrap}',
	'.kuroshio-tile-s{font-size:12px;line-height:1.45;opacity:.72;overflow-wrap:anywhere}',
	/* 表格：外面包一層可以左右捲動的框；文字靠左、數字靠右 */
	'.kuroshio-scroll{max-width:100%;overflow-x:auto;-webkit-overflow-scrolling:touch;padding-bottom:2px}',
	'.kuroshio-scroll>table{margin:0}',
	/* 捲動框裡的表頭不能 sticky（vantage 的表頭會黏在捲動框頂端、往下蓋住第一列） */
	'#view .kuroshio-scroll .table .th,#view .kuroshio-scroll .table .tr>.th{position:static}',
	'#view .kuroshio-scroll .th,#view .kuroshio-scroll .td{text-align:left}',
	/* 窄螢幕主題把表格改成一格一格的卡片（標題在左），這時數字不靠右 */
	'@media (min-width:601px){#view .kuroshio-scroll .th.kuroshio-num,#view .kuroshio-scroll .td.kuroshio-num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}}',
	'.kuroshio-row{display:flex;flex-direction:row;gap:.5em;flex-wrap:wrap;align-items:center;justify-content:flex-start}',
	'.kuroshio-modebar .cbi-value-description{margin:0;padding:0}'
].join('\n');

/** 把共用樣式放進頁面（一次） */
function injectCss() {
	if (document.getElementById('kuroshio-css')) return;
	var st = document.createElement('style');
	st.id = 'kuroshio-css';
	st.textContent = CSS;
	document.head.appendChild(st);
}
injectCss();

/**
 * 主題的區塊有沒有內距：看第一個 .kuroshio-sec 的 padding-left。沒有的話（argon）用主題標題的縮排當內距；
 * 標題也沒有縮排（不認識的主題）就用 16px，標題一起縮排。視窗大小改變時重新量（主題在手機寬度可能改縮排）。
 */
var fitTimer = null;
function fitSections(tries) {
	window.clearTimeout(fitTimer);
	var sec = document.querySelector('#view .cbi-section.kuroshio-sec');
	if (!sec || !sec.getBoundingClientRect().width) {
		if ((tries || 0) < 100) fitTimer = window.setTimeout(function() { fitSections((tries || 0) + 1); }, 100);
		return;
	}
	var root = document.documentElement;
	root.classList.remove('kuroshio-pad', 'kuroshio-flat');
	root.style.removeProperty('--kuroshio-inset');
	if (parseFloat(window.getComputedStyle(sec).paddingLeft) >= 4) return;
	var h = sec.firstElementChild && sec.firstElementChild.tagName === 'H3' ? sec.firstElementChild : null;
	var hp = h ? parseFloat(window.getComputedStyle(h).paddingLeft) : 0;
	root.style.setProperty('--kuroshio-inset', (hp >= 4 ? Math.min(hp, 32) : 16) + 'px');
	root.classList.add('kuroshio-pad');
	if (hp < 4) root.classList.add('kuroshio-flat');
}
window.addEventListener('resize', function() { window.clearTimeout(fitTimer); fitTimer = window.setTimeout(fitSections, 200); });
fitSections();

/**
 * 數字＋單位不要拆成兩行：「7,370 MB」「1 / 2 ms」「1.5 小時」包成不換行的 <span>（文字本身不變，複製、搜尋都正常）
 * 回傳節點陣列，字串一律當文字放進去
 */
var NUM_UNIT = /[>\d][\d,.]*(?:\s*\/\s*[>\d][\d,.]*)*\s*(?:MB|KB|GB|ms|%|筆|條|種|核|次|天|小時|分鐘|分)?/g;
function keepNumbers(text) {
	var s = String(text), out = [], last = 0, m;
	NUM_UNIT.lastIndex = 0;
	while ((m = NUM_UNIT.exec(s))) {
		if (!m[0]) { NUM_UNIT.lastIndex++; continue; }
		if (m.index > last) out.push(document.createTextNode(s.slice(last, m.index)));
		out.push(T('span', { 'class': 'kuroshio-nb' }, m[0]));
		last = m.index + m[0].length;
	}
	if (last < s.length) out.push(document.createTextNode(s.slice(last)));
	return out;
}

/**
 * 日期時間一律用台灣習慣的固定格式，不跟瀏覽器語系（英文瀏覽器原本會顯示 11/12/2026, 10:22:03 AM）：
 * fmtTime(t) = 2026-11-12 10:22（24 小時制）；mode 'sec' 加秒、'date' 只有日期、'time' = 10:22、'timesec' = 10:22:03。
 * 跟共用儀表板 data/dashboard/dashboard.js 的 KuroshioDashboard.fmtTime 同一份規則（LuCI 其他頁沒有載入儀表板，所以放一份在這裡）。
 */
function p2(n) { return (n < 10 ? '0' : '') + n; }
function fmtTime(t, mode) {
	if (t == null || t === '' || t === 0) return '-';
	var d = new Date(typeof t === 'number' || /^\d+$/.test(t) ? Number(t) : t);
	if (isNaN(d)) return String(t);
	var date = d.getFullYear() + '-' + p2(d.getMonth() + 1) + '-' + p2(d.getDate());
	var hm = p2(d.getHours()) + ':' + p2(d.getMinutes()), sec = ':' + p2(d.getSeconds());
	return mode === 'date' ? date : mode === 'time' ? hm : mode === 'timesec' ? hm + sec : date + ' ' + hm + (mode === 'sec' ? sec : '');
}

var SCOPE = { 'public': _('公網'), 'private': _('私有'), 'cgnat': _('電信商 CGNAT'), 'linklocal': _('鏈路本地'), 'ula': _('區網 IPv6'), 'loopback': _('本機') };
var BADGE = { ok: '#19733a', warn: '#8a5a00', err: '#b42318', off: '#6b7785' };

return baseclass.extend({
	defaults: {},

	T: T,

	/** 日期時間（固定格式，見上方 fmtTime） */
	time: fmtTime,

	/** 小標籤（狀態用）：kind = ok / warn / err / off */
	badge: function(text, kind) {
		return T('span', { 'class': 'kuroshio-badge', 'data-kind': kind || 'off',
			'style': 'display:inline-block;padding:0 .6em;border-radius:1em;font-size:12px;line-height:1.7;white-space:nowrap;color:#fff;background:' + (BADGE[kind] || BADGE.off) }, text);
	},

	/**
	 * 自己組的區塊（不是 form.js 產生的）：主題沒有區塊內距時自動補上（見 fitSections）
	 * attrs 可以帶 id 等屬性；children 可以是節點陣列
	 */
	section: function(title, children, attrs) {
		var a = Object.assign({}, attrs || {});
		a['class'] = 'cbi-section kuroshio-sec' + (a['class'] ? ' ' + a['class'] : '');
		window.setTimeout(fitSections, 0);
		return E('div', a, [title != null ? T('h3', {}, title) : ''].concat(children || []));
	},

	/** 數字卡片：label 標題、value 數字（數字與單位不會被拆開）、sub 小字說明 */
	tile: function(label, value, sub) {
		return E('div', { 'class': 'kuroshio-tile' }, [
			T('div', { 'class': 'kuroshio-tile-l' }, label),
			E('div', { 'class': 'kuroshio-tile-v' }, keepNumbers(value == null ? '-' : value)),
			sub ? E('div', { 'class': 'kuroshio-tile-s' }, keepNumbers(sub)) : ''
		]);
	},

	/** 一組數字卡片（寬度不夠自動換行） */
	tiles: function(list) {
		return E('div', { 'class': 'kuroshio-tiles' }, list.filter(Boolean));
	},

	/** 包一層可以左右捲動的框（表格太寬時不撐破區塊） */
	scroll: function(node) {
		return E('div', { 'class': 'kuroshio-scroll' }, node);
	},

	/**
	 * 表格：head = 標題陣列，rows = 每列的儲存格（字串或節點）
	 * num = 數字欄的索引（靠右對齊）；表格外面包 scroll() 才會套用對齊與捲動
	 */
	table: function(head, rows, empty, num) {
		var isNum = function(i) { return !!num && num.indexOf(i) >= 0; };
		return E('table', { 'class': 'table' }, [
			E('tr', { 'class': 'tr table-titles' }, head.map(function(h, i) { return T('th', { 'class': 'th' + (isNum(i) ? ' kuroshio-num' : '') }, h); }))
		].concat(rows.length ? rows.map(function(r) {
			return E('tr', { 'class': 'tr' }, r.map(function(c, i) {
				var td = E('td', { 'class': 'td' + (isNum(i) ? ' kuroshio-num' : ''), 'data-title': head[i] || '' });
				if (c != null && c.nodeType) td.appendChild(c);
				else td.textContent = (c == null) ? '-' : String(c);
				return td;
			}));
		}) : [E('tr', { 'class': 'tr placeholder' }, E('td', { 'class': 'td', 'colspan': head.length }, T('em', {}, empty || _('沒有資料'))))]));
	},

	/** 管理 API 的回應（rpcd 包成 { ok, result }）→ 內容；服務沒有執行或失敗時回 null */
	result: function(r) {
		return (r && r.ok !== false && r.result != null && typeof r.result === 'object') ? r.result : null;
	},

	/** 讀一個查看類 API；失敗（服務沒有執行、舊版核心）回 null */
	fetch: function(path, params) {
		var self = this;
		return L.resolveDefault(this.api(path, params), null).then(function(r) { return self.result(r); });
	},

	/** 複製文字（LuCI 常用 http://，不能用 Clipboard API，所以用選取＋複製） */
	copyButton: function(text) {
		var b = T('button', { 'class': 'btn cbi-button', 'style': 'padding:0 .6em;line-height:1.8em;margin-left:.6em', 'title': _('複製') }, _('複製'));
		b.addEventListener('click', function(ev) {
			ev.preventDefault();
			var ta = E('textarea', { 'style': 'position:fixed;left:-9999px;top:0;opacity:0', 'readonly': '' });
			ta.value = text;
			document.body.appendChild(ta);
			ta.select();
			var ok = false;
			try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
			document.body.removeChild(ta);
			b.textContent = ok ? _('已複製') : _('請手動選取');
			window.setTimeout(function() { b.textContent = _('複製'); }, 1500);
		});
		return b;
	},

	/** 路徑＋複製按鈕；沒有值時顯示「（沒有）」 */
	pathCell: function(p) {
		if (p == null || p === '') return T('em', {}, _('（沒有）'));
		return E('span', {}, [T('code', { 'style': 'word-break:break-all' }, p), this.copyButton(String(p))]);
	},

	/** 憑證（/api/paths 的 tls.info）有沒有涵蓋這個網域（含萬用字元） */
	certCovers: function(info, domain) {
		var d = String(domain || '').replace(/\.$/, '').toLowerCase();
		return String((info && info.san) || '').split(', ').some(function(n) {
			if (n.slice(0, 4) !== 'DNS:') return false;
			n = n.slice(4).toLowerCase();
			if (n === d) return true;
			var i = d.indexOf('.');
			return n.slice(0, 2) === '*.' && i > 0 && d.slice(i + 1) === n.slice(2);
		});
	},

	scopeName: function(s) { return SCOPE[s] || s || ''; },

	/** 一張網卡的說明文字：位址（公網 / 私有、暫時、已停用）、未連線 */
	ifaceText: function(i) {
		var self = this;
		var addrs = (i.addrs || []).filter(function(a) { return a.scope !== 'linklocal' && a.scope !== 'loopback'; }).map(function(a) {
			var marks = [self.scopeName(a.scope)];
			if (a.temporary) marks.push(_('暫時'));
			if (a.deprecated) marks.push(_('已停用'));
			return a.ip + '（' + marks.join('、') + '）';
		});
		return i.name + (i.up ? '' : ' [' + _('未連線') + ']') + ' — ' + (addrs.length ? addrs.join('、') : _('沒有可用的位址'));
	},

	/** 一個加密監聽位址的狀態（/api/status 的 listenersDetail） */
	listenerState: function(x) {
		if (x.ok) return this.badge(x.proto === 'doh' ? (x.tls ? _('執行中（TLS）') : _('執行中（純 HTTP）')) : _('執行中'), 'ok');
		return E('span', {}, [this.badge(_('綁定失敗'), 'err'), T('div', { 'style': 'color:#b42318;font-size:12px' }, x.error || _('原因不明（請看日誌）'))]);
	},

	/** 加密監聽的表格：每個位址一列 */
	listenerTable: function(detail) {
		var self = this, P = { doh: 'DoH（TCP）', doh3: 'DoH3（UDP）', dot: 'DoT（TCP）', doq: 'DoQ（UDP）' };
		return this.table([_('協議'), _('位址'), _('埠號'), _('狀態')], [].concat(detail || []).map(function(x) {
			return [P[x.proto] || x.proto, x.bind, x.port, self.listenerState(x)];
		}), _('沒有開啟任何加密協議（DoH / DoT / DoQ）'), [2]);
	},

	/**
	 * 表單裡的唯讀面板（目前狀態、說明）：不讀也不寫 UCI
	 * node 可以是節點或回傳節點的函式
	 */
	panel: function(s, name, title, node, desc) {
		var o = s.option(form.DummyValue, name, title);
		o.render = function() {
			var n = (typeof node === 'function') ? node() : node;
			return E('div', { 'class': 'cbi-value', 'id': 'kuroshio-panel-' + name.replace(/^_/, '') }, [
				T('label', { 'class': 'cbi-value-title' }, title),
				E('div', { 'class': 'cbi-value-field kuroshio-scroll' }, [n, desc ? T('div', { 'class': 'cbi-value-description' }, desc) : ''])
			]);
		};
		o.write = function() {};
		o.remove = function() {};
		return o;
	},

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

	api: function(path, params) { return rpcCall(callApi, path, this.query(params), 2); },
	// 動作（加好友、同步…）不自動重試：可能已經送到、只是回應被斷掉，重送會重複執行
	action: function(path, params) { return rpcCall(callAction, path, this.query(params), 0); },

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
		// 主題可能把 .cbi-section 設成直向 flex（argon），所以橫排放在裡面一層
		return E('div', { 'class': 'cbi-section kuroshio-sec' }, E('div', { 'class': 'kuroshio-row kuroshio-modebar' }, [
			E('strong', {}, _('介面模式')),
			btn(false, _('簡易')),
			btn(true, _('專業')),
			E('span', { 'class': 'cbi-value-description', 'style': 'margin:0' },
				pro ? _('顯示全部參數。不確定的欄位請保持空白，會使用程式內建的預設值。')
				    : _('只顯示常用設定，避免誤改細部參數。需要微調時切換到「專業」。'))
		]));
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
				E('div', { 'class': 'kuroshio-scroll' }, E('table', { 'class': 'table' }, rows)),
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
		var box = E('div', { 'class': 'cbi-section kuroshio-sec kuroshio-footer', 'style': 'margin-top:1.5em;padding-top:.6em' }, [line, body]);

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
