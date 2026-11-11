'use strict';
// 黑潮 DNS 本機設定頁（Windows 版；規格 02 第 6、7.2 節、規格 07）
// 原生 JS、不需要編譯。伺服器給的字串一律用 textContent 放進頁面，不組 HTML。
(function () {
	/** 這個設定頁本身的版本（核心版本由 /api/about 提供；兩者不同時「關於」分頁兩個都會顯示） */
	var UI_VERSION = '3.0.0-alpha.2';

	// ---------------------------------------------------------------- 小工具
	var $ = function (id) { return document.getElementById(id); };
	var MODE_KEY = 'kuroshio-ui-mode';  // 跟 LuCI 用同一個名稱
	var LOG_KEY = 'kuroshio-admin-log';
	var NOTICE_KEY = 'kuroshio-admin-notice';

	var store = {
		get: function (k) { try { return window.localStorage.getItem(k); } catch (e) { return null; } },
		set: function (k, v) { try { window.localStorage.setItem(k, v); } catch (e) { /* 私密瀏覽、停用儲存空間 */ } }
	};

	/** 建立元素：attrs 的 text = textContent、on* = 事件、class、其他照 setAttribute；children 可以是字串（文字節點）或元素 */
	function el(tag, attrs, children) {
		var e = document.createElement(tag);
		Object.keys(attrs || {}).forEach(function (k) {
			var v = attrs[k];
			if (v == null || v === false) return;
			if (k === 'text') e.textContent = String(v);
			else if (k === 'class') e.className = v;
			else if (k.slice(0, 2) === 'on' && typeof v === 'function') e.addEventListener(k.slice(2), v);
			else if (k === 'value') e.value = v;
			else if (k === 'checked') e.checked = !!v;
			else e.setAttribute(k, v === true ? '' : String(v));
		});
		append(e, children);
		return e;
	}
	function append(e, children) {
		[].concat(children == null ? [] : children).forEach(function (c) {
			if (c == null || c === false) return;
			e.appendChild(typeof c === 'string' || typeof c === 'number' ? document.createTextNode(String(c)) : c);
		});
		return e;
	}
	function clear(e) { while (e.firstChild) e.removeChild(e.firstChild); return e; }
	function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

	function clone(v) { return v === undefined ? undefined : JSON.parse(JSON.stringify(v)); }
	function isObj(v) { return v !== null && typeof v === 'object' && !Array.isArray(v); }
	function deepEqual(a, b) {
		if (a === b) return true;
		if (Array.isArray(a)) {
			if (!Array.isArray(b) || a.length !== b.length) return false;
			for (var i = 0; i < a.length; i++) if (!deepEqual(a[i], b[i])) return false;
			return true;
		}
		if (isObj(a) && isObj(b)) {
			var ka = Object.keys(a), kb = Object.keys(b);
			if (ka.length !== kb.length) return false;
			return ka.every(function (k) { return Object.prototype.hasOwnProperty.call(b, k) && deepEqual(a[k], b[k]); });
		}
		return false;
	}
	function getPath(obj, key) {
		return String(key).split('.').reduce(function (a, k) { return isObj(a) ? a[k] : undefined; }, obj);
	}
	function setPath(obj, key, val) {
		var ks = String(key).split('.'), o = obj;
		for (var i = 0; i < ks.length - 1; i++) {
			if (!isObj(o[ks[i]])) o[ks[i]] = {};
			o = o[ks[i]];
		}
		o[ks[ks.length - 1]] = val;
	}
	function delPath(obj, key) {
		var ks = String(key).split('.');
		(function walk(o, i) {
			if (!isObj(o)) return;
			if (i === ks.length - 1) { delete o[ks[i]]; return; }
			walk(o[ks[i]], i + 1);
			if (isObj(o[ks[i]]) && !Object.keys(o[ks[i]]).length) delete o[ks[i]];
		})(obj, 0);
	}
	/** 只留跟預設值不同的欄位（規格 02 第 4 節：config.json 只存跟預設值不同的欄位）；預設值沒有的欄位一律保留 */
	function prune(user, defs) {
		var out = {};
		Object.keys(user || {}).forEach(function (k) {
			var v = user[k], d = isObj(defs) ? defs[k] : undefined;
			if (v === null) return;  // null 在合併時等於沒寫
			if (isObj(v) && isObj(d)) {
				var p = prune(v, d);
				if (Object.keys(p).length) out[k] = p;
			} else if (d === undefined || !deepEqual(v, d)) {
				out[k] = clone(v);
			}
		});
		return out;
	}

	var nf = new Intl.NumberFormat('zh-TW');
	function fmtNum(n) { return n == null || n === '' || isNaN(n) ? '-' : nf.format(n); }
	function pct(a, b) { return b ? (100 * a / b).toFixed(1) + '%' : '-'; }
	function fmtTime(t) {
		if (!t) return '-';
		var d = new Date(typeof t === 'number' || /^\d+$/.test(t) ? Number(t) : t);
		return isNaN(d) ? String(t) : d.toLocaleString('zh-TW', { hour12: false });
	}
	function fmtUptime(s) {
		if (s == null) return '-';
		var d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
		return (d ? d + ' 天 ' : '') + (d || h ? h + ' 小時 ' : '') + m + ' 分';
	}
	/** 還沒存的時間：0 = 都存了 */
	function fmtAge(sec) {
		if (sec == null) return '-';
		if (sec <= 0) return '全部已存';
		if (sec < 3600) return Math.max(1, Math.round(sec / 60)) + ' 分鐘';
		return (sec / 3600).toFixed(1) + ' 小時';
	}
	function fmtBytes(b) {
		if (b == null) return '-';
		if (b < 1024) return b + ' B';
		if (b < 1048576) return (b / 1024).toFixed(0) + ' KB';
		return (b / 1048576).toFixed(1) + ' MB';
	}
	/** 位址數量：一萬以上用「萬」（1,401 萬），跟一般人講 IP 數量的方式一樣 */
	function fmtWan(n) {
		if (n == null || isNaN(n)) return '-';
		return n >= 10000 ? nf.format(Math.floor(n / 10000)) + ' 萬' : nf.format(n);
	}
	function pretty(v) { return typeof v === 'string' ? v : JSON.stringify(v, null, 2); }

	// ---------------------------------------------------------------- 格式檢查（後端不接受的值不寫進設定）
	/** IPv4 位址（不接受前面補 0，跟後端的解析一致） */
	function isIPv4(s) {
		var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
		return !!m && m.slice(1).every(function (x) { return +x <= 255 && (x.length === 1 || x.charAt(0) !== '0'); });
	}
	/** IPv6 位址（不含 %網卡、不含中括號） */
	function isIPv6(s) {
		if (!/^[0-9a-fA-F:.]+$/.test(s) || s.indexOf(':') < 0) return false;
		var dbl = s.split('::');
		if (dbl.length > 2) return false;
		var groups = function (part) { return part === '' ? [] : part.split(':'); };
		var all = groups(dbl[0]).concat(dbl.length === 2 ? groups(dbl[1]) : []), n = 0;
		for (var i = 0; i < all.length; i++) {
			var g = all[i];
			if (g.indexOf('.') >= 0) {
				if (i !== all.length - 1 || !isIPv4(g)) return false;
				n += 2;
			} else {
				if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return false;
				n++;
			}
		}
		return dbl.length === 2 ? n <= 7 : n === 8;
	}
	function isIP(s) { return isIPv4(s) || isIPv6(s); }
	/** IP 或網段（IP/前綴長度；IPv4 0～32、IPv6 0～128）。主機位元不是 0 也接受（後端取網段），跟後端 parse_cidr 一致 */
	function checkCidr(s) {
		var m = /^([^/\s]+)(?:\/(\d{1,3}))?$/.exec(s);
		if (!m) return { err: '格式是 IP 或 IP/前綴長度，例如 203.0.113.7、198.51.100.0/24、2001:db8::/32' };
		var v4 = isIPv4(m[1]);
		if (!v4 && !isIPv6(m[1])) return { err: '「' + m[1] + '」不是 IP 位址（不含埠號與中括號）' };
		if (m[2] == null) return { val: v4 ? m[1] : m[1].toLowerCase() };
		var n = Number(m[2]), max = v4 ? 32 : 128;
		if (n > max) return { err: (v4 ? 'IPv4' : 'IPv6') + ' 的前綴長度是 0～' + max };
		return { val: (v4 ? m[1] : m[1].toLowerCase()) + '/' + n };
	}
	/** 完整網域名稱（至少兩段；不是 IP） */
	function isDomain(s) {
		if (!s || s.length > 253) return false;
		var ls = s.split('.');
		if (ls.length < 2 || /^\d+$/.test(ls[ls.length - 1])) return false;
		return ls.every(function (l) { return /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i.test(l); });
	}
	/** validate → 檢查一個值：回 { val }（整理過的值）或 { err } */
	var VALID = {
		domain: function (s) {
			var d = s.replace(/\.$/, '').toLowerCase();
			return isDomain(d) ? { val: d } : { err: '請輸入完整的網域名稱，例如 dns.example.com（不含 https:// 與路徑）' };
		},
		record: function (s) {
			var d = s.replace(/\.$/, '').toLowerCase();
			return isDomain(d.replace(/^\*\./, '')) ? { val: d } : { err: '請輸入完整的網域名稱，例如 home.example.com' };
		},
		cidr: checkCidr,
		ip: function (s) {
			return isIP(s) ? { val: s } : { err: '請輸入 IP 位址，例如 0.0.0.0、192.168.1.10 或 ::（不含埠號、中括號與 %網卡）' };
		},
		iisSite: function (s) {
			// 跟後端 iiscert::valid_site 一樣：文字、數字、空白與 . _ - ( )，最多 128 位元組
			var bytes = window.TextEncoder ? new TextEncoder().encode(s).length : s.length * 3;
			return /^[\p{L}\p{N} ._()-]+$/u.test(s) && bytes <= 128 ? { val: s } : { err: '站台名稱只能有文字、數字、空白與 . _ - ( )' };
		}
	};
	function validate(f, s) { return f.validate && VALID[f.validate] ? VALID[f.validate](s) : { val: s }; }

	/** 複製文字到剪貼簿（設定頁在 127.0.0.1，可以用 Clipboard API；不行時退回舊方法） */
	function copyText(text) {
		var legacy = function () {
			var ta = el('textarea', { class: 'offscreen', readonly: true, 'aria-hidden': 'true' });
			ta.value = text;
			document.body.appendChild(ta);
			ta.select();
			var okc = false;
			try { okc = document.execCommand('copy'); } catch (e) { okc = false; }
			document.body.removeChild(ta);
			return okc ? Promise.resolve() : Promise.reject(new Error('copy'));
		};
		var p = navigator.clipboard && navigator.clipboard.writeText ? navigator.clipboard.writeText(text).catch(legacy) : legacy();
		return p.then(function () { toast('已複製：' + text); }, function () { toast('無法複製，請手動選取文字', true); });
	}

	var toastTimer;
	function toast(text, isErr) {
		var t = $('toast');
		t.textContent = text;
		t.className = 'toast' + (isErr ? ' err' : '');
		t.hidden = false;
		clearTimeout(toastTimer);
		toastTimer = setTimeout(function () { t.hidden = true; }, 3500);
	}

	// ---------------------------------------------------------------- 後端
	/** 呼叫管理 API；回 { status, ok, data }，網路錯誤時 status = 0。401 → 回到登入畫面 */
	function api(path, opts) {
		opts = opts || {};
		var init = { method: opts.method || 'GET', credentials: 'same-origin', cache: 'no-store', headers: {} };
		if (opts.raw !== undefined) {
			// 檔案內容（匯入備份）
			init.headers['content-type'] = 'application/octet-stream';
			init.body = opts.raw;
		} else if (opts.body !== undefined) {
			init.headers['content-type'] = 'application/json';
			init.body = typeof opts.body === 'string' ? opts.body : JSON.stringify(opts.body);
		}
		return fetch(path, init).then(function (r) {
			return r.text().then(function (t) {
				var data = null;
				try { data = t ? JSON.parse(t) : null; } catch (e) { data = t; }
				if (r.status === 401 && !opts.noAuthRedirect) showLogin('登入已過期，請重新登入。');
				return { status: r.status, ok: r.ok, data: data };
			});
		}, function (e) {
			return { status: 0, ok: false, data: { error: '連不上服務（' + e.message + '）' } };
		});
	}
	function errText(r) {
		if (r.status === 0) return r.data.error;
		var d = r.data;
		var msg = d && typeof d === 'object' && d.error ? d.error : (typeof d === 'string' && d ? d : 'HTTP ' + r.status);
		return r.status === 404 ? msg + '（這個功能沒有啟用）' : msg;
	}
	function qs(params) {
		return Object.keys(params).filter(function (k) { return params[k] !== '' && params[k] != null; })
			.map(function (k) { return encodeURIComponent(k) + '=' + encodeURIComponent(params[k]); }).join('&');
	}

	// ---------------------------------------------------------------- 狀態
	var S = {
		session: null,
		fields: null,
		cfg: null,          // GET /api/config 的回應
		cfgError: null,
		orig: {},           // 目前檔案裡的使用者設定（已去掉跟預設相同的欄位）
		work: {},           // 編輯中的使用者設定
		errors: {},         // 欄位格式錯誤：key → 訊息
		group: null,
		tab: null,
		saving: false,
		rawDirty: false,
		ifaces: null,       // GET /api/interfaces 的 Promise（網卡清單，整個頁面共用）
		live: []            // 目前這個分類裡，欄位一改就要重畫的面板
	};
	var isPro = function () { return store.get(MODE_KEY) === 'pro'; };

	// ---------------------------------------------------------------- 開始
	document.addEventListener('DOMContentLoaded', boot);

	function boot() {
		var params = new URLSearchParams(location.search);
		var failed = params.get('login') === 'failed';
		if (location.search) history.replaceState(null, '', location.pathname + location.hash);
		$('login-err').hidden = !failed;

		var nt = $('notice');
		nt.open = store.get(NOTICE_KEY) !== 'closed';
		nt.addEventListener('toggle', function () { store.set(NOTICE_KEY, nt.open ? 'open' : 'closed'); });

		bindStatic();
		loadAbout();
		api('/api/session', { noAuthRedirect: true }).then(function (r) {
			$('boot').hidden = true;
			if (!r.ok || !r.data) {
				$('boot').hidden = false;
				$('boot').textContent = '讀取失敗：' + errText(r);
				return;
			}
			S.session = r.data;
			header();
			if (S.session.auth && !S.session.loggedIn) showLogin(failed ? null : '');
			else startMain();
		});
	}

	// ---------------------------------------------------------------- 關於（版本、授權、原始碼；不用登入）
	function safeUrl(u) { return typeof u === 'string' && /^https?:\/\/[^\s]+$/i.test(u) ? u : null; }
	function loadAbout() {
		return api('/api/about', { noAuthRedirect: true }).then(function (r) {
			S.about = r.ok && isObj(r.data) ? r.data : null;
			var a = S.about || {};
			$('foot-name').textContent = '黑潮 DNS ' + (a.version ? 'v' + a.version : '');
			var lic = $('foot-license');
			if (a.license) lic.textContent = a.license;
			if (safeUrl(a.licenseUrl)) lic.href = a.licenseUrl;
			var src = $('foot-src'), u = safeUrl(a.source);
			src.textContent = u ? u.replace(/^https?:\/\//, '') : '-';
			if (u) src.href = u; else src.removeAttribute('href');
			if (S.tab === 'about') renderAbout();
		});
	}
	function renderAbout() {
		var a = S.about || {};
		var link = function (u, text) {
			var ok = safeUrl(u);
			return ok ? el('a', { href: ok, target: '_blank', rel: 'noopener noreferrer', text: text || ok }) : (text || u || '-');
		};
		var rows = [
			['名稱', a.name || '黑潮 DNS（Kuroshio DNS）'],
			['核心版本', a.version || (S.session && S.session.version) || '-'],
			['設定頁版本', UI_VERSION + (a.version && a.version !== UI_VERSION ? '（跟核心版本不同：設定頁檔案可能是別的版本）' : '')],
			['授權', a.license ? link(a.licenseUrl, a.license) : '-'],
			['原始碼', link(a.source)],
			['程式語言', a.language || '-'],
			['編譯平台', a.target || '-'],
			['功能', [].concat(a.features || []).join('、') || '-'],
			['執行方式', S.session ? (S.session.mode === 'service' ? 'Windows 服務' : 'cmd 直接執行') + ' · ' + (S.session.os || '') : '-'],
			['設定檔', (S.session && S.session.configFile) || '-']
		];
		var tb = clear($('about-kv').tBodies[0]);
		rows.forEach(function (r) { tb.appendChild(el('tr', {}, [el('th', { text: r[0] }), el('td', {}, r[1])])); });
		$('about-src').textContent = safeUrl(a.source) || '';
		if (!S.about) tb.appendChild(el('tr', {}, el('td', { colspan: 2, class: 'empty', text: '讀取不到 /api/about（核心版本較舊？）' })));
	}

	function header() {
		var s = S.session;
		$('hdr-sub').textContent = '本機設定頁 · ' + (s.version || '');
		var m = $('hdr-mode');
		m.textContent = s.mode === 'service' ? 'Windows 服務' : 'cmd 直接執行';
		m.hidden = false;
		$('logout').hidden = !s.auth;
	}

	function showLogin(msg) {
		stopTimers();
		$('main').hidden = true;
		$('login').hidden = false;
		$('logout').hidden = true;
		if (msg) {
			$('login-err').textContent = msg;
			$('login-err').hidden = false;
		}
		setTimeout(function () { $('login-token').focus(); }, 0);
	}

	function startMain() {
		$('login').hidden = true;
		$('main').hidden = false;
		var loadFields = S.fields ? Promise.resolve() : fetch('fields.json', { cache: 'no-store' })
			.then(function (r) { return r.json(); })
			.then(function (f) { S.fields = f; }, function () { S.fields = { groups: [] }; });
		Promise.all([loadFields, loadConfig()]).then(function () {
			route();
			startTimers();
		});
	}

	function loadConfig() {
		if (S.session.uci) {
			S.cfg = null;
			S.cfgError = 'uci';
			return Promise.resolve();
		}
		return api('/api/config').then(function (r) {
			if (r.status === 401) return;
			if (!r.ok) {
				S.cfg = null;
				S.cfgError = r.status === 404 ? 'uci' : errText(r);
				return;
			}
			S.cfg = r.data;
			S.cfgError = null;
			S.orig = prune(r.data.user || {}, r.data.defaults || {});
			// 編輯從「檔案原本的內容」開始：不認識的欄位、跟預設相同的欄位都先保留，存檔時才整理
			S.work = clone(isObj(r.data.user) ? r.data.user : {});
			S.errors = {};
			S.rawDirty = false;
		});
	}

	// ---------------------------------------------------------------- 分頁
	var TABS = ['status', 'settings', 'tools', 'log', 'about'];
	function route() {
		var t = location.hash.replace('#', '');
		if (TABS.indexOf(t) < 0) t = 'status';
		S.tab = t;
		document.querySelectorAll('#tabs a').forEach(function (a) {
			a.setAttribute('aria-selected', a.getAttribute('data-tab') === t ? 'true' : 'false');
		});
		TABS.forEach(function (x) { $('tab-' + x).hidden = x !== t; });
		if (t === 'status') refreshStatus();
		if (t === 'settings') renderSettings();
		noticeVisibility();
		if (t === 'tools') renderTools();
		if (t === 'log') refreshLog();
		if (t === 'about') renderAbout();
	}

	/** Windows 提醒：狀態分頁與「服務與監聽」設定才顯示 */
	function noticeVisibility() {
		$('notice').hidden = !(S.tab === 'status' || (S.tab === 'settings' && S.group === 'listen' && !S.cfgError));
	}

	function bindStatic() {
		window.addEventListener('hashchange', route);
		// 登入用 fetch 送出：伺服器的 Referrer-Policy 是 no-referrer，瀏覽器原生表單 POST 會帶 `Origin: null`，
		// 被「拒絕跨站請求」擋下；fetch 是同源 CORS 模式，一定帶真正的 Origin
		$('login-form').addEventListener('submit', function (ev) {
			ev.preventDefault();
			var btn = $('login-form').querySelector('button');
			btn.disabled = true;
			fetch('/login', {
				method: 'POST', credentials: 'same-origin', cache: 'no-store',
				headers: { 'content-type': 'application/x-www-form-urlencoded' },
				body: 'token=' + encodeURIComponent($('login-token').value.trim())
			}).then(function (r) {
				btn.disabled = false;
				if (/login=failed/.test(r.url) || !r.ok) {
					$('login-err').textContent = r.ok || r.status === 303 ? 'token 不正確，請再試一次。' : '登入失敗：HTTP ' + r.status;
					$('login-err').hidden = false;
					$('login-token').select();
					return;
				}
				location.reload();
			}, function (e) {
				btn.disabled = false;
				$('login-err').textContent = '連不上服務（' + e.message + '）';
				$('login-err').hidden = false;
			});
		});
		$('mode-toggle').addEventListener('click', function (ev) {
			var b = ev.target.closest('button[data-mode]');
			if (!b) return;
			store.set(MODE_KEY, b.getAttribute('data-mode'));
			renderSettings();
			noticeVisibility();
		});
		$('btn-save').addEventListener('click', function () { saveForm(); });
		$('btn-discard').addEventListener('click', function () {
			S.work = clone(S.cfg.user || {});
			S.errors = {};
			S.rawDirty = false;
			renderSettings();
			toast('已放棄未儲存的變更');
		});
		$('log-refresh').addEventListener('click', refreshLog);
		$('log-filter').addEventListener('input', showLog);
		var saved = {};
		try { saved = JSON.parse(store.get(LOG_KEY) || '{}') || {}; } catch (e) { saved = {}; }
		if (saved.lines) $('log-lines').value = String(saved.lines);
		if (saved.auto === false) $('log-auto').checked = false;
		var keep = function () { store.set(LOG_KEY, JSON.stringify({ lines: +$('log-lines').value, auto: $('log-auto').checked })); };
		$('log-lines').addEventListener('change', function () { keep(); refreshLog(); });
		$('log-auto').addEventListener('change', keep);
		window.addEventListener('beforeunload', function (ev) {
			if (S.cfg && isDirty() && !S.saving) { ev.preventDefault(); ev.returnValue = ''; }
		});
		document.addEventListener('visibilitychange', function () {
			if (document.visibilityState === 'visible' && !$('main').hidden) tick();
		});
	}

	// 狀態每 5 秒、日誌自動更新也是 5 秒；頁面看不到時不更新
	var timer = null;
	function startTimers() { stopTimers(); timer = setInterval(tick, 5000); }
	function stopTimers() { if (timer) clearInterval(timer); timer = null; }
	function tick() {
		if (document.visibilityState !== 'visible' || S.saving) return;
		if (S.tab === 'status') refreshStatus();
		if (S.tab === 'log' && $('log-auto').checked) refreshLog();
	}

	// ---------------------------------------------------------------- 狀態分頁
	var ROLE = { pinned: '固定', auto: '自動', fallback: '備援' };
	var statusBusy = false;

	function tile(k, v, s) {
		return el('div', { class: 'tile' }, [el('div', { class: 'k', text: k }), el('div', { class: 'v', text: v }), s ? el('div', { class: 's', text: s }) : null]);
	}
	function badge(text, kind) { return el('span', { class: 'badge ' + (kind || ''), text: text }); }
	function tableRows(tbody, rows, cols) {
		clear(tbody);
		if (!rows.length) {
			tbody.appendChild(el('tr', {}, el('td', { class: 'empty', colspan: cols, text: '沒有資料' })));
			return;
		}
		rows.forEach(function (r) {
			tbody.appendChild(el('tr', {}, r.map(function (c) {
				if (c && c.nodeType) return el('td', {}, c);
				if (c && typeof c === 'object') return el('td', { class: c.cls || '' }, c.node || c.text);
				return el('td', { text: c == null ? '-' : c });
			})));
		});
	}

	function refreshStatus() {
		if (statusBusy) return;
		statusBusy = true;
		Promise.all([api('/api/status'), S.cfg && getPath(S.cfg.effective, 'acme.enabled') ? api('/api/acme') : Promise.resolve(null)])
			.then(function (res) {
				statusBusy = false;
				var r = res[0];
				if (r.status === 401) return;
				$('st-err').hidden = r.ok;
				if (!r.ok) { $('st-err').textContent = '讀取狀態失敗：' + errText(r); return; }
				renderStatus(r.data, res[1] && res[1].ok ? res[1].data : null);
				$('st-updated').textContent = '更新於 ' + new Date().toLocaleTimeString('zh-TW', { hour12: false }) + '（每 5 秒自動更新）';
			});
	}

	function mbOf(kb) { return kb != null ? fmtNum(Math.round(kb / 1024)) : '-'; }
	/** 記憶體控制動態決定的大小（規格 09） */
	function memSizes(z) {
		if (!z) return '';
		var out = [];
		if (z.cacheEntries != null) out.push('快取 ' + fmtNum(z.cacheEntries) + ' / ' + fmtNum(z.cacheMax) + ' 筆');
		if (z.cdnInRam != null) out.push('CDN ' + fmtNum(z.cdnInRam) + ' 筆' + (z.cdnOnDiskOnly ? '（另 ' + fmtNum(z.cdnOnDiskOnly) + ' 筆在磁碟）' : ''));
		if (z.filterListRules != null) out.push('清單 ' + fmtNum(z.filterListRules) + ' 條');
		return out.join(' · ');
	}
	function renderStatus(st, acme) {
		var s = S.session, d = (st.stats && st.stats.today) || {}, sys = st.system || {}, lat = d.latency || {};
		var ms = function (x) { return x && x.p50 != null ? x.p50 + ' / ' + (x.p95 != null ? x.p95 : '>1000') + ' ms' : '-'; };
		var routeAcc = 0, routeN = 0;
		Object.keys(d.route || {}).forEach(function (k) { routeAcc += d.route[k].acc || 0; routeN += d.route[k].n || 0; });
		var f = st.filter, per = sys.persist || {}, mem = sys.memory || {};
		// 記憶體控制（規格 09）：釋出中的項目、停用中的過濾清單（停用期間少了這些保護，要明顯）
		var shed = mem.shed || [], mb = $('st-mem');
		if (mb) {
			clear(mb);
			mb.hidden = !(shed.length || (f && f.notice) || mem.floor);
			if (!mb.hidden) {
				append(mb, [
					el('h3', { text: '記憶體控制' }),
					mem.protectedSuspended ? el('p', { class: 'msg err', text: '記憶體嚴重不足：連保護清單（惡意 / 反詐騙）都暫停了，只剩自訂規則；DNS 照常轉送。記憶體回來後自動恢復。' }) :
						mem.floor ? el('p', { class: 'msg err', text: '記憶體不足：只轉送 DNS（暫停 CDN 調整、快取最小）。記憶體回來後自動恢復。' }) : null,
					f && f.notice ? el('p', { class: 'msg warn', text: f.notice }) : null,
					el('p', { class: 'muted', text: '目前：' + (mem.stateLabel || mem.state || '-') + '（系統可用 ' + mbOf(mem.availKB) + ' MB / 保留 ' + mbOf(mem.reserveKB) + ' MB）' + (mem.waiting ? ' · ' + mem.waiting : '') }),
					shed.length ? el('ul', {}, shed.map(function (x) { return el('li', { text: x.label + ' ' + (x.detail || '') + '（約 ' + fmtBytes(x.freedBytes) + '，' + fmtTime(x.at) + '）' }); })) : null
				].filter(Boolean));
			}
		}
		clear($('st-tiles'));
		append($('st-tiles'), [
			tile('版本', st.version || s.version || '-', (s.mode === 'service' ? 'Windows 服務' : 'cmd 直接執行') + ' · ' + (s.os || '')),
			tile('硬體', [sys.memTotalMB ? fmtNum(sys.memTotalMB) + ' MB' : '', sys.cores ? sys.cores + ' 核' : ''].filter(Boolean).join(' · ') || '-', sys.arch || ''),
			tile('系統記憶體', mem.availKB != null ? '可用 ' + mbOf(mem.availKB) + ' MB' : (sys.memAvailableMB != null ? '可用 ' + fmtNum(sys.memAvailableMB) + ' MB' : '-'),
				'保留 ' + mbOf(mem.reserveKB) + ' MB（' + (mem.reserveAuto ? '自動' : '設定') + '）' + (mem.headroomKB != null ? ' · 保留以上 ' + mbOf(mem.headroomKB) + ' MB' : '') +
				(mem.enabled ? ' · ' + (mem.stateLabel || mem.state) + (mem.growth === false ? '（不再長大）' : '') : '') +
				(mem.psi ? ' · PSI ' + mem.psi.someAvg10 + '%' : '')),
			tile('本程式記憶體', sys.rssKB ? (sys.rssKB / 1024).toFixed(1) + ' MB' : '-', memSizes(mem.sizes)),
			tile('已執行', fmtUptime(st.stats && st.stats.uptimeSec), '今天：' + (d.date || '-')),
			tile('今天查詢', fmtNum(d.query), '快取命中率 ' + (d.hitRate != null ? d.hitRate + '%' : '-')),
			tile('攔截', fmtNum(d.blocked), '廣告 ' + fmtNum(d.blockedAds) + ' · 遙測 ' + fmtNum(d.blockedTelemetry) + ' · 惡意 ' + fmtNum(d.blockedMalware)),
			tile('回應時間 p50 / p95', ms(lat.hit), '問上游 ' + ms(lat.miss)),
			tile('拉回台灣', fmtNum(routeAcc), 'CDN 連線的 ' + pct(routeAcc, routeN)),
			tile('CDN 台灣節點', fmtNum(d.cdnServed), '置換 ' + fmtNum(d.cdnRewrite) + ' · ECS ' + fmtNum(d.ecsRewrite) + ' · 跨 CDN ' + fmtNum(d.crossRewrite)),
			tile('快取筆數', fmtNum(st.cacheEntries), '約 ' + fmtBytes(st.cacheBytes)),
			tile('過濾規則', f ? fmtNum((f.lists || 0) + (f.custom || 0)) : '未啟用', f ? '自訂 ' + fmtNum(f.custom) + (f.domains != null ? ' · ' + fmtNum(f.domains) + ' 個網域' : '') : ''),
			st.access ? tile('連線來源', ACCESS_MODE[st.access.mode] || st.access.mode || '-',
				st.access.failOpen ? '資料讀不到，暫時不擋' : '已拒絕 ' + fmtNum((st.access.denied || {}).total) + ' 次' + (st.access.generatedAt ? ' · 資料 ' + st.access.generatedAt : '')) : null,
			tile('磁碟寫入（今天）', per.bytesToday != null ? fmtBytes(per.bytesToday) : '-', (per.storage || '') + (per.effectiveIntervalMin != null ? ' · 間隔 ' + per.effectiveIntervalMin + ' 分' : '') + (per.estimatedDailyBytes != null ? ' · 預估每天 ' + fmtBytes(per.estimatedDailyBytes) : '')),
			tile('最久未存', fmtAge(per.oldestUnsavedSec), (per.maxAgeHours != null ? '上限 ' + per.maxAgeHours + ' 小時' : '') + (per.forcedByAge ? ' · 到期強制寫入 ' + fmtNum(per.forcedByAge) + ' 次' : '') +
				(per.lowSpace ? ' · 儲存空間不足（只寫核心資料）' : '')),
			per.space && per.space.reserveBytes != null ? tile('儲存空間', per.space.freeBytes != null ? '可用 ' + fmtBytes(per.space.freeBytes) : '-',
				'保留 ' + fmtBytes(per.space.reserveBytes) + '（' + (per.space.reserveAuto ? '自動' : '設定') + '）' +
				(per.space.optionalBytes ? ' · 可重建的資料 ' + fmtBytes(per.space.optionalBytes) : '') +
				(per.space.keepingOptional === false ? ' · 空間吃緊：只留核心' : '')) : null
		]);

		// 監聽
		var eff = S.cfg ? S.cfg.effective : null, ls = st.listeners || {};
		var want = function (k) { return eff ? !!getPath(eff, k) : null; };
		var row = function (name, port, on, enabledKey) {
			var b;
			if (on) b = badge('執行中', 'ok');
			else if (enabledKey && want(enabledKey)) b = badge('已設定但沒有啟動（請看日誌）', 'warn');
			else b = badge('未開啟', 'off');
			return [name, { text: port == null ? '-' : String(port), cls: 'num' }, b];
		};
		var rows = [];
		if (eff) {
			var pe = getPath(eff, 'listen.plain.enabled') !== false;
			rows.push([
				'一般 DNS（UDP / TCP）',
				{ text: String(getPath(eff, 'listen.plain.port')) + '（' + [].concat(getPath(eff, 'listen.plain.binds') || []).join('、') + '）', cls: 'num' },
				pe ? badge('執行中', 'ok') : badge('未開啟', 'off')
			]);
		}
		// 加密協議：有每個位址的結果（listenersDetail）就一個位址一列，綁定失敗時列出原因
		var detail = [].concat(st.listenersDetail || []);
		[['doh', 'listen.doh.enabled'], ['doh3', 'listen.doh.http3'], ['dot', 'listen.dot.enabled'], ['doq', 'listen.doq.enabled']].forEach(function (p) {
			var ds = detail.filter(function (x) { return x && x.proto === p[0]; });
			if (!ds.length) { rows.push(row(PROTO[p[0]], ls[p[0]], ls[p[0]] != null, p[1])); return; }
			ds.forEach(function (x) {
				rows.push([PROTO[p[0]], { text: x.port + '（' + x.bind + '）', cls: 'num' }, listenerState(x)]);
			});
		});
		rows.push(row('DDR 自動發現', null, !!ls.ddr, 'listen.ddr'));
		rows.push(['設定頁', { text: location.port || '80', cls: 'num' }, badge('執行中', 'ok')]);
		tableRows($('st-listen').tBodies[0], rows, 3);

		// 上游
		var au = st.autoUpstreams;
		$('st-up-desc').textContent = au ? '自動上游來自 ' + fmtTime(au.generatedAt) + ' 的評測（' + fmtNum(au.count) + ' 台）。' : '還沒有每日評測結果，暫時使用固定上游與備援。';
		tableRows($('st-up').tBodies[0], (st.upstreams || []).map(function (u) {
			var n = (u.ok || 0) + (u.fail || 0), rate = n ? u.ok / n : null, h;
			if (u.paused) h = badge('暫停中', 'warn');
			else if (rate == null) h = badge('尚無查詢', 'off');
			else if (rate >= 0.9) h = badge('正常 ' + Math.round(rate * 100) + '%', 'ok');
			else if (rate >= 0.5) h = badge('不穩 ' + Math.round(rate * 100) + '%', 'warn');
			else h = badge('異常 ' + Math.round(rate * 100) + '%', 'err');
			return [{ text: u.id, cls: 'mono' }, ROLE[u.role] || u.role, { text: fmtNum(u.ok), cls: 'num' }, { text: fmtNum(u.fail), cls: 'num' }, { text: u.avgMs != null ? u.avgMs + ' ms' : '-', cls: 'num' }, h];
		}), 6);

		// 憑證、最近的錯誤
		var ex = clear($('st-extra'));
		var ac = st.access;
		if (ac && (ac.failOpen || ac.warning)) {
			ex.appendChild(el('h3', { text: '連線來源' }));
			ex.appendChild(el('p', { class: ac.failOpen ? 'msg err' : 'msg warn', id: 'st-access-warn',
				text: (ac.failOpen ? '台灣 IP 資料讀不到，現在不擋任何來源（封鎖名單照樣有效）' : '') + (ac.warning ? (ac.failOpen ? '：' : '') + ac.warning : '') }));
		}
		if (acme && acme.enabled) {
			var c = acme.certInfo;
			ex.appendChild(el('h3', { text: '憑證' }));
			ex.appendChild(el('p', { class: c && c.daysLeft != null && c.daysLeft < 14 ? 'msg warn' : 'msg info',
				text: c ? (c.san || c.subject) + '，到期 ' + c.validTo + '（剩 ' + c.daysLeft + ' 天）' : (acme.error || '還沒有憑證') }));
		}
		var errs = (st.errors && st.errors.recent) || [];
		if (errs.length) {
			ex.appendChild(el('h3', { text: '最近的錯誤（共 ' + fmtNum(st.errors.count) + ' 次）' }));
			ex.appendChild(el('pre', { class: 'out', text: errs.slice(0, 10).map(function (e) { return fmtTime(e.at) + '  ' + (e.msg || pretty(e)); }).join('\n') }));
		}
	}

	/** 一個監聽位址的狀態（/api/status 的 listenersDetail） */
	function listenerState(x) {
		if (x.ok) return badge(x.proto === 'doh' ? (x.tls ? '執行中（TLS）' : '執行中（純 HTTP）') : '執行中', 'ok');
		return el('div', {}, [badge('綁定失敗', 'err'), el('div', { class: 'cell-err', text: x.error || '原因不明（請看日誌）' })]);
	}
	var PROTO = { doh: 'DoH（TCP）', doh3: 'DoH3（UDP）', dot: 'DoT（TCP）', doq: 'DoQ（UDP）' };

	// ---------------------------------------------------------------- 設定分頁
	function defOf(f) {
		var d = S.cfg ? getPath(S.cfg.defaults, f.key) : undefined;
		return d === undefined ? f.fallbackDefault : d;
	}
	function userOf(key) { return getPath(S.work, key); }
	function effOf(f) { var u = userOf(f.key); return u === undefined ? defOf(f) : u; }
	/** 兩個欄位要一起填（憑證檔與私鑰檔）：只填一個時後端會當成沒有設定 */
	function pairErrors() {
		var out = {};
		if (!S.fields) return out;
		(S.fields.groups || []).forEach(function (g) {
			groupFields(g).forEach(function (f) {
				if (!f.pairWith) return;
				var a = userOf(f.key), b = userOf(f.pairWith);
				if ((a === undefined || a === '') && b !== undefined && b !== '') out[f.key] = '這一欄也要填（憑證檔與私鑰檔要一起填）';
			});
		});
		return out;
	}
	function allErrors() {
		var out = pairErrors();
		Object.keys(S.errors).forEach(function (k) { out[k] = S.errors[k]; });
		return out;
	}
	function isDirty() {
		if (!S.cfg) return false;
		return !deepEqual(prune(S.work, S.cfg.defaults), S.orig) || S.rawDirty;
	}
	function fieldChanged(key) {
		var w = prune(S.work, S.cfg.defaults);
		return !deepEqual(getPath(w, key), getPath(S.orig, key));
	}
	function visibleGroups() {
		var pro = isPro();
		var gs = (S.fields.groups || []).filter(function (g) { return pro || !g.pro; });
		if (pro) gs = gs.concat([{ id: 'raw', title: '原始 JSON', raw: true }]);
		return gs;
	}

	function renderSettings() {
		var pro = isPro();
		document.querySelectorAll('#mode-toggle button').forEach(function (b) {
			b.setAttribute('aria-pressed', (b.getAttribute('data-mode') === 'pro') === pro ? 'true' : 'false');
		});
		$('mode-desc').textContent = pro
			? '顯示全部參數。不確定的欄位請保持空白，會使用程式內建的預設值。'
			: '只顯示常用設定，避免誤改細部參數。需要微調時切換到「專業」。';
		var un = $('cfg-unavailable');
		if (S.cfgError || !S.cfg) {
			$('cfg-body').hidden = true;
			$('savebar').hidden = true;
			un.hidden = false;
			clear(un);
			if (S.cfgError === 'uci') {
				append(un, [el('h3', { text: '設定由 LuCI 管理' }),
					el('p', { text: '這台是 OpenWrt：設定存在 UCI（/etc/config/kuroshio），請到路由器的 LuCI「服務 → 黑潮 DNS」修改。這個頁面只能查看狀態、使用工具與日誌。' })]);
			} else {
				append(un, [el('h3', { text: '讀取設定失敗' }), el('p', { class: 'msg err', text: S.cfgError || '未知錯誤' }),
					el('button', { class: 'btn', type: 'button', text: '重試', onclick: function () { loadConfig().then(renderSettings); } })]);
			}
			return;
		}
		un.hidden = true;
		$('cfg-body').hidden = false;
		$('savebar').hidden = false;
		var gs = visibleGroups();
		if (!gs.some(function (g) { return g.id === S.group; })) S.group = gs.length ? gs[0].id : null;
		renderGroupNav();
		renderGroup();
		updateSaveBar();
	}

	function renderGroupNav() {
		var nav = clear($('cfg-groups'));
		visibleGroups().forEach(function (g) {
			var changed = !g.raw && groupFields(g).some(function (f) { return fieldChanged(f.key); });
			nav.appendChild(el('button', {
				type: 'button', 'data-group': g.id, 'aria-current': g.id === S.group ? 'true' : 'false',
				onclick: function () {
					S.group = g.id;
					renderGroupNav();
					renderGroup();
					noticeVisibility();
				}
			}, [el('span', { text: g.title }), changed ? el('span', { class: 'dot', title: '有未儲存的變更' }) : null]));
		});
	}
	function groupFields(g) {
		var out = [];
		(g.sections || []).forEach(function (s) { (s.fields || []).forEach(function (f) { out.push(f); }); });
		return out;
	}

	function renderGroup() {
		var box = clear($('cfg-group'));
		S.live = [];
		S.access = null;
		var g = visibleGroups().filter(function (x) { return x.id === S.group; })[0];
		if (!g) return;
		box.appendChild(el('h3', { text: g.title }));
		if (g.raw) { renderRaw(box); return; }
		if (g.desc) box.appendChild(el('p', { class: 'desc', text: g.desc }));
		var pro = isPro();
		(g.sections || []).forEach(function (sec) {
			if (sec.pro && !pro) return;
			var fs = (sec.fields || []).filter(function (f) { return pro || !f.pro; });
			if (!fs.length && !sec.widget) return;
			var card = el('div', { class: 'card section' }, [el('h3', { text: sec.title })]);
			if (sec.widget) card.setAttribute('data-widget', sec.widget);
			if (sec.desc) card.appendChild(el('p', { class: 'desc', text: sec.desc }));
			fs.forEach(function (f) { card.appendChild(renderField(f)); });
			if (sec.widget && WIDGETS[sec.widget]) card.appendChild(WIDGETS[sec.widget]());
			box.appendChild(card);
		});
		if (!pro && (g.sections || []).some(function (s) { return s.pro || (s.fields || []).some(function (f) { return f.pro; }); })) {
			box.appendChild(el('p', { class: 'muted', text: '這一類還有細部參數，切換到「專業」模式才會顯示。' }));
		}
		applyDepends();
	}

	function applyDepends() {
		document.querySelectorAll('#cfg-group .field[data-dep]').forEach(function (row) {
			var dep = JSON.parse(row.getAttribute('data-dep'));
			var v = effOf({ key: dep.key, fallbackDefault: undefined });
			row.hidden = (dep.values || []).indexOf(v) < 0;
		});
	}

	/** 欄位改變後：更新「已修改」標示、分類的小圓點、儲存列 */
	function changed(f, row) {
		if (row) refreshMeta(f, row);
		// 其他欄位的錯誤訊息也可能跟著變（要一起填的欄位）
		var errs = allErrors();
		document.querySelectorAll('#cfg-group .field[data-key]').forEach(function (r) {
			var et = r.querySelector('.err-text'), k = r.getAttribute('data-key');
			if (!et) return;
			et.textContent = errs[k] || '';
			et.hidden = !errs[k];
		});
		S.live.forEach(function (fn) { fn(); });
		applyDepends();
		renderGroupNav();
		updateSaveBar();
	}

	function defText(f, d) {
		if (d === undefined) return null;
		if (f.type === 'bool') return d ? '開啟' : '關閉';
		if (f.type === 'select' || f.type === 'choice') {
			var o = (f.options || []).filter(function (x) { return x.value === d; })[0];
			return o ? o.label : String(d);
		}
		if (f.type === 'ifaces') return [].concat(d || []).length ? [].concat(d).join('、') : '自動';
		if (f.type === 'accessGroups') return [].concat(d || []).indexOf('*') >= 0 ? '全部（含日後新增的 ISP）' : [].concat(d || []).join('、') || '一組都不勾';
		if (f.type === 'password') return d ? '（已設定）' : '空白';
		if (f.type === 'multi') return [].concat(d || []).join('、') || '無';
		if (f.type === 'list') return [].concat(d || []).length ? [].concat(d).join('、') : '無';
		if (f.type === 'table') return [].concat(d || []).length + ' 筆';
		if (d === '' || d === null) return '空白';
		return String(d);
	}

	function refreshMeta(f, row) {
		var meta = row.querySelector('.meta');
		clear(meta);
		var d = defOf(f), dt = defText(f, d);
		if (dt != null && f.type !== 'list' && f.type !== 'table') meta.appendChild(el('span', { text: '預設：' + dt }));
		if (f.type === 'list' || f.type === 'text' || f.type === 'host' || f.type === 'path' || f.type === 'password' || isNum(f)) {
			if (userOf(f.key) === undefined) meta.appendChild(el('span', { text: '空白 = 使用預設值' }));
		}
		if (fieldChanged(f.key)) meta.appendChild(el('span', { class: 'changed', text: '未儲存' }));
		if (userOf(f.key) !== undefined && !deepEqual(userOf(f.key), d)) {
			meta.appendChild(el('button', {
				type: 'button', class: 'linkbtn', text: '還原預設值',
				onclick: function () {
					delPath(S.work, f.key);
					delete S.errors[f.key];
					var nr = renderField(f);
					row.parentNode.replaceChild(nr, row);
					changed(f, nr);
				}
			}));
		}
		var et = row.querySelector('.err-text'), err = allErrors()[f.key];
		et.textContent = err || '';
		et.hidden = !err;
	}

	function isNum(f) { return f.type === 'int' || f.type === 'float' || f.type === 'port'; }

	function setValue(f, v) {
		delete S.errors[f.key];
		if (v === undefined) delPath(S.work, f.key);
		else setPath(S.work, f.key, v);
	}

	function parseNum(f, s) {
		if (f.type === 'float') {
			if (!/^-?(\d+\.?\d*|\.\d+)$/.test(s)) return { err: '請輸入數字' };
		} else if (!/^-?\d+$/.test(s)) return { err: '請輸入整數' };
		var n = Number(s);
		if (f.type === 'port') {
			var lo = f.allowZero ? 0 : 1;
			if (n < lo || n > 65535) return { err: '埠號範圍 ' + lo + '～65535' };
		}
		if (f.min != null && n < f.min) return { err: '最小 ' + f.min };
		if (f.max != null && n > f.max) return { err: '最大 ' + f.max };
		return { val: n };
	}

	var uid = 0;
	function renderField(f) {
		var id = 'f' + (++uid);
		var ctl = el('div', { class: 'ctl' });
		var row = el('div', { class: 'field' + (f.type === 'bool' || f.type === 'choice' ? ' bool' : ''), 'data-key': f.key }, [
			el('label', { class: 'lab', for: f.type === 'ifaces' || f.type === 'accessGroups' ? null : id }, [f.label, el('span', { class: 'key', text: f.key })]),
			ctl
		]);
		if (f.dependsOn) row.setAttribute('data-dep', JSON.stringify(f.dependsOn));
		var d = defOf(f), u = userOf(f.key);
		var input;

		if (f.type === 'bool') {
			input = el('input', { type: 'checkbox', id: id, checked: !!effOf(f) });
			input.addEventListener('change', function () {
				var v = input.checked;
				setValue(f, d !== undefined && v === d ? undefined : v);
				changed(f, row);
			});
			ctl.appendChild(el('label', { class: 'chk' }, [input, el('span', { text: '開啟' })]));
		} else if (f.type === 'select') {
			input = el('select', { id: id });
			var dl = defText(f, d);
			input.appendChild(el('option', { value: '', text: dl != null ? '預設（' + dl + '）' : '預設' }));
			var opts = (f.options || []).slice();
			if (u !== undefined && !opts.some(function (o) { return o.value === u; })) opts.push({ value: u, label: String(u) });
			// typed：值照 JSON 型別存（true / false / 字串），選項的 value 用 JSON 表示
			var enc = function (v) { return f.typed ? JSON.stringify(v) : v; };
			opts.forEach(function (o) { input.appendChild(el('option', { value: enc(o.value), text: o.label })); });
			input.value = u === undefined ? '' : enc(u);
			input.addEventListener('change', function () {
				setValue(f, input.value === '' ? undefined : (f.typed ? JSON.parse(input.value) : input.value));
				changed(f, row);
			});
			ctl.appendChild(input);
		} else if (f.type === 'choice') {
			// 單選：值可以是布林（例如 ddns.enabled）；選到預設值就不寫進設定檔
			var grp = el('div', { class: 'choice', role: 'radiogroup', 'aria-label': f.label });
			var curC = effOf(f);
			(f.options || []).forEach(function (o, i) {
				var r = el('input', { type: 'radio', name: id, id: i === 0 ? id : null, value: String(i), checked: o.value === curC });
				r.addEventListener('change', function () {
					if (!r.checked) return;
					setValue(f, d !== undefined && o.value === d ? undefined : o.value);
					changed(f, row);
				});
				grp.appendChild(el('label', { class: 'chk' + (o.desc ? ' has-desc' : '') }, [r, el('span', {}, [el('span', { text: o.label }),
					o.desc ? el('span', { class: 'opt-desc', text: o.desc }) : null])]));
			});
			ctl.appendChild(grp);
		} else if (f.type === 'ifaces') {
			ctl.appendChild(renderIfaces(f, row, id));
		} else if (f.type === 'accessGroups') {
			ctl.appendChild(renderAccessGroups(f, row, id));
		} else if (f.type === 'list') {
			var lines = u === undefined ? [] : [].concat(u);
			var dlist = [].concat(d || []);
			input = el('textarea', {
				id: id, rows: Math.max(3, Math.min(10, Math.max(lines.length, dlist.length) + 1)), spellcheck: 'false',
				placeholder: dlist.length ? dlist.join('\n') : (f.placeholder || '')
			});
			input.value = lines.join('\n');
			input.addEventListener('input', function () {
				var arr = input.value.split(/\r?\n/).map(function (x) { return x.trim(); }).filter(Boolean);
				input.classList.remove('invalid');
				var bad = null;
				arr = arr.map(function (x, i) {
					var c = validate(f, x);
					if (c.err && !bad) bad = '第 ' + (i + 1) + ' 行「' + x + '」：' + c.err;
					return c.err ? x : c.val;
				});
				if (bad) { S.errors[f.key] = bad; input.classList.add('invalid'); changed(f, row); return; }
				setValue(f, arr.length ? arr : undefined);
				changed(f, row);
			});
			ctl.appendChild(input);
			if (f.picker === 'addrs') ctl.appendChild(addrPicker(input));
			if (dlist.length) {
				ctl.appendChild(el('button', {
					type: 'button', class: 'linkbtn', text: '把預設值填進來再修改',
					onclick: function () {
						input.value = dlist.join('\n');
						input.dispatchEvent(new Event('input'));
						input.focus();
					}
				}));
			}
		} else if (f.type === 'multi') {
			var box = el('div', { class: 'multi', id: id });
			var cur = [].concat(effOf(f) || []);
			var opts2 = (f.options || []).slice();
			cur.forEach(function (v) { if (!opts2.some(function (o) { return o.value === v; })) opts2.push({ value: v, label: v }); });
			var boxes = opts2.map(function (o) {
				var c = el('input', { type: 'checkbox', value: o.value, checked: cur.indexOf(o.value) >= 0 });
				box.appendChild(el('label', { class: 'chk' }, [c, el('span', { text: o.label })]));
				return c;
			});
			box.addEventListener('change', function () {
				var arr = boxes.filter(function (c) { return c.checked; }).map(function (c) { return c.value; });
				setValue(f, d !== undefined && deepEqual(arr, d) ? undefined : arr);
				changed(f, row);
			});
			ctl.appendChild(box);
		} else if (f.type === 'table') {
			ctl.appendChild(renderTable(f, row));
			row.classList.add('wide');
			row.querySelector('.lab').removeAttribute('for');
		} else {
			// 文字、數字、路徑、密碼
			var type = f.type === 'password' ? 'password' : 'text';
			var ph = d != null && d !== '' && !isObj(d) && !Array.isArray(d) ? String(d) : (f.placeholder || '');
			if (f.type === 'password') ph = d ? '（預設值已設定）' : '';
			input = el('input', {
				type: type, id: id, placeholder: ph, spellcheck: 'false', autocomplete: f.type === 'password' ? 'new-password' : 'off',
				inputmode: isNum(f) ? (f.type === 'float' ? 'decimal' : 'numeric') : null
			});
			input.value = u === undefined || u === null ? '' : (typeof u === 'object' ? JSON.stringify(u) : String(u));
			input.addEventListener('input', function () {
				var s = input.value.trim();
				input.classList.remove('invalid');
				if (s === '') { setValue(f, undefined); changed(f, row); return; }
				if (isNum(f)) {
					var p = parseNum(f, s);
					if (p.err) { S.errors[f.key] = p.err; input.classList.add('invalid'); changed(f, row); return; }
					setValue(f, p.val);
				} else {
					if (f.pattern && !new RegExp(f.pattern).test(s)) {
						S.errors[f.key] = f.patternMsg || '格式不正確';
						input.classList.add('invalid');
						changed(f, row);
						return;
					}
					if ((f.type === 'host') && /\s/.test(s)) {
						S.errors[f.key] = '不能有空白';
						input.classList.add('invalid');
						changed(f, row);
						return;
					}
					var c = validate(f, s);
					if (c.err) {
						S.errors[f.key] = c.err;
						input.classList.add('invalid');
						changed(f, row);
						return;
					}
					setValue(f, c.val);
				}
				changed(f, row);
			});
			if (f.type === 'password') {
				var wrap = el('div', { class: 'ctl-row' });
				var show = el('button', { type: 'button', class: 'btn small', text: '顯示' });
				show.addEventListener('click', function () {
					var hidden = input.type === 'password';
					input.type = hidden ? 'text' : 'password';
					show.textContent = hidden ? '隱藏' : '顯示';
				});
				wrap.classList.add('pw');
				append(wrap, [input, show]);
				ctl.appendChild(wrap);
			} else {
				ctl.appendChild(input);
			}
		}
		if (f.help) ctl.appendChild(el('div', { class: 'help', text: f.help }));
		ctl.appendChild(el('div', { class: 'err-text', hidden: true }));
		ctl.appendChild(el('div', { class: 'meta' }));
		refreshMeta(f, row);
		return row;
	}

	// ---------------------------------------------------------------- 網卡（/api/interfaces）
	var SCOPE = { public: '公網', private: '私有', cgnat: '電信商 CGNAT', linklocal: '鏈路本地', ula: '區網 IPv6', loopback: '本機' };
	/** 網卡清單（整個頁面只問一次；force = 重新讀取）。失敗時回 null */
	function loadIfaces(force) {
		if (!S.ifaces || force) {
			S.ifaces = api('/api/interfaces').then(function (r) {
				return r.ok && r.data && Array.isArray(r.data.interfaces) ? r.data.interfaces : null;
			});
		}
		return S.ifaces;
	}
	function addrNode(a) {
		return el('span', { class: 'addr' }, [
			el('span', { class: 'mono', text: a.ip }),
			badge(SCOPE[a.scope] || a.scope || '', a.scope === 'public' ? 'ok' : 'off'),
			a.temporary ? badge('暫時位址', 'warn') : null,
			a.deprecated ? badge('已停用', 'warn') : null
		]);
	}

	/** 勾選網卡（ddns.interfaces）：列出每張網卡的位址；設定裡有、但這台電腦找不到的網卡也列出來（可以取消勾選） */
	function renderIfaces(f, row, id) {
		var box = el('div', { class: 'ifaces', id: id, role: 'group', 'aria-label': f.label }, el('p', { class: 'muted', text: '讀取網卡中…' }));
		var d = defOf(f);
		var commit = function () {
			var arr = [].slice.call(box.querySelectorAll('input[type=checkbox]')).filter(function (c) { return c.checked; }).map(function (c) { return c.value; });
			setValue(f, deepEqual(arr, d === undefined ? [] : d) ? undefined : arr);
			changed(f, row);
		};
		var draw = function (list) {
			clear(box);
			var cur = [].concat(effOf(f) || []);
			var item = function (name, body, missing) {
				var c = el('input', { type: 'checkbox', value: name, checked: cur.indexOf(name) >= 0 });
				c.addEventListener('change', commit);
				box.appendChild(el('label', { class: 'iface' + (missing ? ' missing' : '') }, [c, el('div', { class: 'iface-body' }, body)]));
			};
			if (!list) box.appendChild(el('p', { class: 'msg warn', text: '讀不到這台電腦的網卡清單（/api/interfaces）。已經設定的出口仍然列在下面。' }));
			(list || []).forEach(function (i) {
				// 迴路介面不會是對外的出口
				if ((i.addrs || []).length && i.addrs.every(function (a) { return a.scope === 'loopback'; }) && cur.indexOf(i.name) < 0) return;
				var addrs = (i.addrs || []).filter(function (a) { return a.scope !== 'linklocal' && a.scope !== 'loopback'; });
				item(i.name, [
					el('div', { class: 'iface-name' }, [el('strong', { text: i.name }), i.label && i.label !== i.name ? el('span', { class: 'muted', text: i.label }) : null,
						i.up ? null : badge('未連線', 'off')]),
					addrs.length ? el('div', { class: 'addrs' }, addrs.map(addrNode)) : el('div', { class: 'muted', text: '沒有可用的位址' })
				]);
			});
			cur.forEach(function (name) {
				if ((list || []).some(function (i) { return i.name === name; })) return;
				item(name, [el('div', { class: 'iface-name' }, [el('strong', { text: name }), badge('找不到這張網卡', 'warn')]),
					el('div', { class: 'muted', text: '名稱改了或已經移除。取消勾選就會從設定移除。' })], true);
			});
			if (!box.querySelector('input')) box.appendChild(el('p', { class: 'muted', text: '沒有找到可以當出口的網卡。' }));
			box.appendChild(el('button', { type: 'button', class: 'linkbtn', text: '重新讀取網卡', onclick: function () { loadIfaces(true).then(draw); } }));
		};
		loadIfaces().then(draw);
		return box;
	}

	// ---------------------------------------------------------------- 連線來源（/api/access，規格 08）
	var ACCESS_MODE = { taiwan: '只開放台灣', custom: '自訂 ISP', open: '全開放' };
	var ACCESS_KIND = { dot: 'DoT', doh: 'DoH', doq: 'DoQ', doh3: 'DoH3', site: '公開頁', community: '社群共享', plain: '區網 DNS' };
	/** GET /api/access（同一個分類畫面只讀一次） */
	function loadAccess() {
		if (!S.access) S.access = api('/api/access');
		return S.access;
	}

	/** 勾選開放的 ISP 群組（access.groups）：「全選」= ["*"]（之後資料新增的群組也包含）；一組都不勾 = [] */
	function renderAccessGroups(f, row, id) {
		var box = el('div', { class: 'agroups', id: id, role: 'group', 'aria-label': f.label }, el('p', { class: 'muted', text: '讀取 ISP 清單中…' }));
		var d = defOf(f), pro = isPro();
		var draw = function (r) {
			clear(box);
			var data = r.ok && isObj(r.data) ? r.data : {};
			var groups = [].concat(data.groups || []);
			var cur = [].concat(effOf(f) || []), star = cur.indexOf('*') >= 0;
			var boxes = [];
			var none = el('p', { class: 'msg warn', text: '一組都沒有勾：只剩區網、好友與允許名單可以連進來。', hidden: cur.length > 0 });
			var commit = function (arr) {
				setValue(f, d !== undefined && deepEqual(arr, d) ? undefined : arr);
				none.hidden = arr.length > 0;
				changed(f, row);
			};
			var picked = function () { return boxes.filter(function (c) { return c.checked; }).map(function (c) { return c.value; }); };
			var all = el('input', { type: 'checkbox', value: '*', checked: star });
			all.addEventListener('change', function () {
				if (all.checked) { boxes.forEach(function (c) { c.checked = true; }); commit(['*']); }
				else commit(picked());   // 取消「全選」：目前勾的照舊，只是日後新增的不再自動包含
			});
			box.appendChild(el('label', { class: 'agroup all' }, [all, el('div', { class: 'agroup-body' }, [
				el('strong', { text: '全選（含日後新增的 ISP）' }),
				el('div', { class: 'muted', text: '台灣 IP 資料更新後新加入的業者也自動開放。' })])]));
			var item = function (gid, body, missing) {
				var c = el('input', { type: 'checkbox', value: gid, checked: star || cur.indexOf(gid) >= 0 });
				c.addEventListener('change', function () { all.checked = false; commit(picked()); });
				boxes.push(c);
				box.appendChild(el('label', { class: 'agroup' + (missing ? ' missing' : '') }, [c, el('div', { class: 'agroup-body' }, body)]));
			};
			if (!r.ok) box.appendChild(el('p', { class: 'msg warn', text: '讀不到 ISP 清單（/api/access）：' + errText(r) }));
			else if (!groups.length) box.appendChild(el('p', { class: 'msg warn', text: '讀不到台灣 IP 資料，無法列出 ISP。已經設定的群組仍然列在下面。' }));
			groups.forEach(function (g) {
				var sz = g.size || {};
				var body = [el('div', { class: 'agroup-name' }, [el('strong', { text: g.name || g.id }),
					sz.v4 ? badge(fmtWan(sz.v4) + (sz.v4 >= 10000 ? '個位址' : ' 個位址'), 'off') : badge('目前沒有網段', 'warn')])];
				if (!sz.v4) body.push(el('div', { class: 'muted', text: '網段已經全部移到併購的業者（資料保留這一組，日後有網段會自動生效）。' }));
				if (pro) {
					if (g.note) body.push(el('div', { class: 'muted', text: g.note }));
					var asns = [].concat(g.asns || []).map(function (n) { return 'AS' + n; }).join('、');
					var cs = g.cidrs || {};
					// 說明裡已經列了 ASN（含持有者名稱）就不再重複
					var inNote = g.note && [].concat(g.asns || []).every(function (n) { return g.note.indexOf(String(n)) >= 0; });
					body.push(el('div', { class: 'muted mono' }, [g.id, asns && !inNote ? ' · ' + asns : '', ' · ' + fmtNum(cs.v4) + ' 個 IPv4 網段、' + fmtNum(cs.v6) + ' 個 IPv6 網段']));
				}
				item(g.id, body);
			});
			// 設定裡有、但資料裡沒有的群組（資料更新後改名或移除）：也列出來，可以取消勾選
			cur.forEach(function (gid) {
				if (gid === '*' || groups.some(function (g) { return g.id === gid; })) return;
				if (!groups.length) { item(gid, [el('div', { class: 'agroup-name' }, [el('strong', { text: gid }), badge('已勾選', 'off')])]); return; }
				item(gid, [el('div', { class: 'agroup-name' }, [el('strong', { text: gid }), badge('資料裡沒有這一組', 'warn')]),
					el('div', { class: 'muted', text: '台灣 IP 資料裡找不到，不會生效。取消勾選就會從設定移除。' })], true);
			});
			box.appendChild(none);
			box.setAttribute('data-ready', '1');
		};
		loadAccess().then(draw);
		return box;
	}

	/** 把一個網段加到允許 / 封鎖名單（編輯中的設定，還沒有儲存），重畫那個欄位 */
	function addToList(key, net) {
		var f = null;
		(S.fields.groups || []).forEach(function (g) { groupFields(g).forEach(function (x) { if (x.key === key) f = x; }); });
		if (!f) return;
		var cur = [].concat(userOf(key) || []);
		if (cur.indexOf(net) >= 0) { toast(net + ' 已經在名單裡'); return; }
		cur.push(net);
		setValue(f, cur);
		var row = document.querySelector('#cfg-group .field[data-key="' + key + '"]');
		if (row) {
			var nr = renderField(f);
			row.parentNode.replaceChild(nr, row);
			changed(f, nr);
		} else changed(f);
		toast('已把 ' + net + ' 加到' + (key === 'access.deny' ? '封鎖' : '允許') + '名單（按「儲存並套用」才會生效）');
	}

	/** 「目前狀態」：模式、資料日期、資料讀不到時不擋的警告、拒絕次數、被拒絕最多的網段 */
	function accessPanel(box, a) {
		var dn = a.denied || {}, by = dn.byListener || {};
		if (a.failOpen) box.appendChild(el('p', { class: 'msg err', id: 'access-failopen', text: '台灣 IP 資料讀不到，現在不擋任何來源（封鎖名單照樣有效）' + (a.warning ? '：' + a.warning : '。') }));
		else if (a.warning) box.appendChild(el('p', { class: 'msg warn', text: a.warning }));
		var groups = [].concat(a.groups || []);
		var on = groups.filter(function (g) { return g.enabled; });
		var modeText = ACCESS_MODE[a.mode] || a.mode || '-';
		if (a.mode === 'custom' && groups.length) modeText += '（開放 ' + on.length + ' / ' + groups.length + ' 組）';
		var rows = [
			['開放對象', modeText],
			['套用在', [].concat(a.applyTo || []).map(function (k) { return ACCESS_KIND[k] || k; }).join('、') || '（沒有，不限制）'],
			['台灣 IP 資料', a.generatedAt ? el('span', {}, [a.generatedAt + ' 的資料（' + (a.dataOrigin || '公版') + '） ', a.autoUpdate ? badge('每月在本機更新', 'ok') : badge('跟著程式升級更新', 'off'), a.update && a.update.text ? ' ' + a.update.text : ''])
				: badge('讀不到', 'err')],
			['已拒絕', fmtNum(dn.total) + ' 次' + (dn.total ? '（' + Object.keys(by).filter(function (k) { return by[k]; }).map(function (k) { return (ACCESS_KIND[k] || k) + ' ' + fmtNum(by[k]); }).join('、') + '）' : '')]
		];
		if ([].concat(a.allow || []).length || [].concat(a.deny || []).length) rows.push(['自訂名單', '允許 ' + [].concat(a.allow || []).length + ' 筆、封鎖 ' + [].concat(a.deny || []).length + ' 筆']);
		if (isPro()) {
			rows.push(['資料來源', a.dataSource ? el('span', { class: 'mono', text: a.dataSource }) : '-']);
			rows.push(['記憶體', fmtBytes(a.memoryBytes) + '（' + fmtNum(a.ranges) + ' 個區間）' + (a.dataBytes != null ? '＋群組資料 ' + fmtBytes(a.dataBytes) : '')]);
		}
		box.appendChild(kvTable(rows));
		var top = [].concat(a.topDenied || []);
		box.appendChild(el('h4', { text: '被拒絕最多的網段' }));
		box.appendChild(simpleTable(['網段', '次數', ''], top.slice(0, 20).map(function (t) {
			return [{ text: t.net, cls: 'mono' }, { text: fmtNum(t.count), cls: 'num' }, el('div', { class: 'row-btns' }, [
				el('button', { type: 'button', class: 'btn small danger', text: '加入封鎖', 'aria-label': '把 ' + t.net + ' 加入封鎖名單', onclick: function () { addToList('access.deny', t.net); } }),
				el('button', { type: 'button', class: 'btn small', text: '加入允許', 'aria-label': '把 ' + t.net + ' 加入允許名單', onclick: function () { addToList('access.allow', t.net); } })])];
		}), '還沒有拒絕過任何連線'));
		if (top.length) box.appendChild(el('p', { class: 'muted', text: 'IPv4 以 /24、IPv6 以 /48 為單位統計。' }));
	}

	/** 「測試 IP」：依已套用的設定判斷一個 IP 能不能連進來 */
	function accessTest() {
		var inp = el('input', { type: 'text', id: 'access-test-ip', placeholder: '例如 168.95.1.1 或 2001:db8::1', 'aria-label': '要測試的 IP', spellcheck: 'false', autocomplete: 'off' });
		var out = el('p', { class: 'verdict', id: 'access-test-out', hidden: true });
		var show = function (text, kind) { out.textContent = text; out.className = 'verdict ' + (kind || ''); out.hidden = false; };
		var run = function () {
			var ip = inp.value.trim();
			if (!isIP(ip)) { inp.classList.add('invalid'); show('請輸入一個 IP 位址（不含前綴長度與埠號）', 'warn'); return; }
			inp.classList.remove('invalid');
			return api('/api/access?' + qs({ ip: ip })).then(function (r) {
				if (!r.ok) return show('失敗：' + errText(r), 'err');
				var x = r.data || {};
				var kinds = [].concat(x.applyTo || []).map(function (k) { return ACCESS_KIND[k] || k; }).join('、');
				show((x.allowed ? '可以連進來' : '會被擋下') + '：' + (x.reason || '-') + (kinds ? '（套用在 ' + kinds + '）' : '') +
					(isDirty() ? '。還沒儲存的變更不算在內。' : ''), x.allowed ? 'ok' : 'err');
			});
		};
		inp.addEventListener('keydown', function (ev) { if (ev.key === 'Enter') run(); });
		return el('div', { class: 'panel access-test' }, [el('div', { class: 'ctl-row' }, [inp, actBtn('測試', 'primary', run)]), out]);
	}

	/** 清單欄位下方的「從本機位址挑選」：選了就加到清單最後一行 */
	function addrPicker(input) {
		var sel = el('select', { class: 'picker', 'aria-label': '從本機位址挑選' }, el('option', { value: '', text: '從本機位址挑選…' }));
		var add = function (ip, label) { sel.appendChild(el('option', { value: ip, text: ip + '　' + label })); };
		add('0.0.0.0', '所有 IPv4 位址');
		add('::', '所有 IPv6 位址');
		add('127.0.0.1', '只有這台電腦（IPv4）');
		add('::1', '只有這台電腦（IPv6）');
		loadIfaces().then(function (list) {
			(list || []).forEach(function (i) {
				(i.addrs || []).forEach(function (a) {
					// 鏈路本地位址要指定網卡才能綁定，後端不接受；迴路位址上面已經有了
					if (a.scope === 'linklocal' || a.scope === 'loopback') return;
					add(a.ip, (i.label || i.name) + '（' + (SCOPE[a.scope] || a.scope) + (a.temporary ? '、暫時位址' : '') + (a.deprecated ? '、已停用' : '') + (i.up ? '' : '、未連線') + '）');
				});
			});
		});
		sel.addEventListener('change', function () {
			var ip = sel.value;
			sel.value = '';
			if (!ip) return;
			var lines = input.value.split(/\r?\n/).map(function (x) { return x.trim(); }).filter(Boolean);
			if (lines.indexOf(ip) < 0) lines.push(ip);
			input.value = lines.join('\n');
			input.dispatchEvent(new Event('input'));
		});
		return sel;
	}

	// ---------------------------------------------------------------- 唯讀面板（設定分類裡的目前狀態）
	function kvTable(rows) {
		return el('div', { class: 'table-wrap' }, el('table', { class: 'kv' }, el('tbody', {}, rows.map(function (r) {
			return el('tr', {}, [el('th', { text: r[0] }), el('td', {}, r[1])]);
		}))));
	}
	function simpleTable(head, rows, emptyText) {
		var tb = el('tbody');
		tableRows(tb, rows, head.length);
		if (!rows.length && emptyText) tb.firstChild.firstChild.textContent = emptyText;
		return el('div', { class: 'table-wrap' }, el('table', {}, [el('thead', {}, el('tr', {}, head.map(function (h) { return el('th', { text: h }); }))), tb]));
	}
	/** 面板外框：先顯示「讀取中」，load() 的結果交給 draw(box, data, reload) */
	function panel(name, load, draw) {
		var box = el('div', { class: 'panel', id: 'panel-' + name }, el('p', { class: 'muted', text: '讀取中…' }));
		var run = function () {
			return load().then(function (r) {
				clear(box);
				if (!r.ok) { box.appendChild(el('p', { class: 'msg err', text: '讀取失敗：' + errText(r) })); return; }
				draw(box, r.data || {}, run);
				box.setAttribute('data-ready', '1');
			});
		};
		run();
		return box;
	}
	/** 憑證（certinfo）有沒有涵蓋這個網域（含萬用字元），跟後端 certinfo::covers 一樣 */
	function certCovers(info, domain) {
		var d = String(domain || '').replace(/\.$/, '').toLowerCase();
		return String(info.san || '').split(', ').some(function (n) {
			if (n.slice(0, 4) !== 'DNS:') return false;
			n = n.slice(4).toLowerCase();
			if (n === d) return true;
			var i = d.indexOf('.');
			return n.slice(0, 2) === '*.' && i > 0 && d.slice(i + 1) === n.slice(2);
		});
	}
	function pathCell(p) {
		if (p == null || p === '') return el('span', { class: 'muted', text: '（沒有）' });
		return el('div', { class: 'path' }, [el('span', { class: 'mono', text: p }),
			el('button', { type: 'button', class: 'btn small copy', text: '複製', 'aria-label': '複製 ' + p, onclick: function () { copyText(String(p)); } })]);
	}

	var DDNS_ACTION = { created: '已新增', updated: '已更新', unchanged: '沒有變', deleted: '已移除', kept: '暫時保留', skip: '略過', error: '失敗' };
	var WIDGETS = {
		// 每個加密協議實際綁定的位址
		listeners: function () {
			return panel('listeners', function () { return api('/api/status?lite=1'); }, function (box, st) {
				var rows = [].concat(st.listenersDetail || []).map(function (x) {
					return [PROTO[x.proto] || x.proto, { text: x.bind, cls: 'mono' }, { text: String(x.port), cls: 'num' }, listenerState(x)];
				});
				box.appendChild(simpleTable(['協議', '位址', '埠號', '狀態'], rows, '沒有開啟任何加密協議（DoH / DoT / DoQ）'));
			});
		},

		// 憑證目前的狀態（/api/paths 的 tls）＋跟編輯中的設定有關的提醒
		cert: function () {
			var hint = el('div', { id: 'cert-hint' });
			var live = function () {
				clear(hint);
				var acme = effOf({ key: 'acme.enabled' }) === true, c = userOf('tls.cert'), k = userOf('tls.key');
				if (acme && (c || k)) hint.appendChild(el('p', { class: 'msg warn', text: '選擇自動申請時，新憑證會寫到上面填的憑證檔與私鑰檔（會覆蓋原本的檔案）。不想被覆蓋請把這兩欄清空，憑證會放在設定資料夾。' }));
				else if (!acme && !c && !k) hint.appendChild(el('p', { class: 'msg info', text: '還沒有填憑證檔：DoH（直接對外）、DoT、DoQ 需要憑證才能啟動。只用一般 DNS 可以不填。' }));
			};
			S.live.push(live);
			live();
			var st = panel('cert', function () { return api('/api/paths'); }, function (box, p) {
				var t = p.tls || {}, info = t.info, dom = S.cfg ? getPath(S.cfg.effective, 'domain') : '';
				var src = { acme: '自動申請（內建 ACME）', manual: '自己的憑證檔（只讀取，不會覆蓋）', none: '還沒有設定憑證' }[t.source] || t.source || '-';
				var rows = [['來源', src]];
				if (t.cert) rows.push(['憑證檔', pathCell(t.cert)]);
				if (t.key) rows.push(['私鑰檔', pathCell(t.key)]);
				if (t.source !== 'none') {
					var state;
					if (!t.exists) state = badge(t.source === 'acme' ? '還沒有申請到憑證' : '找不到檔案（憑證檔或私鑰檔不存在）', 'err');
					else if (!info) state = badge('憑證檔讀不出來（不是 PEM 格式？）', 'err');
					else if (info.daysLeft < 0) state = badge('已經過期', 'err');
					else if (info.daysLeft < 14) state = badge('快到期（剩 ' + info.daysLeft + ' 天）', 'warn');
					else state = badge('有效（剩 ' + info.daysLeft + ' 天）', 'ok');
					rows.push(['狀態', state]);
				}
				if (info) {
					rows.push(['主體', info.subject || '-']);
					rows.push(['涵蓋的名稱', info.san || '（沒有 SAN）']);
					rows.push(['簽發者', info.issuer || '-']);
					rows.push(['到期', info.validTo || '-']);
					if (dom) rows.push(['綁定網域', certCovers(info, dom) ? badge('有涵蓋 ' + dom, 'ok') : badge('沒有涵蓋 ' + dom + '（用戶端會出現憑證錯誤）', 'err')]);
					else rows.push(['綁定網域', el('span', { class: 'muted', text: '還沒有填綁定網域，無法比對' })]);
				}
				box.appendChild(el('h4', { text: '目前的憑證（已儲存並套用的設定）' }));
				box.appendChild(kvTable(rows));
			});
			return el('div', {}, [hint, st]);
		},

		// DDNS：每個出口偵測到的 IP、每筆記錄的結果
		ddns: function () {
			return panel('ddns', function () { return api('/api/ddns'); }, function (box, st, reload) {
				if (st.enabled === false) {
					box.appendChild(el('p', { class: 'msg info', text: 'DDNS 沒有啟用（固定網域）：黑潮 DNS 不會更新 DNS 記錄。' }));
					return;
				}
				var fam = function (x) { return 'IPv' + x.family; };
				if (st.error) box.appendChild(el('p', { class: 'msg warn', text: '上次更新有錯誤：' + st.error }));
				box.appendChild(el('p', { class: 'muted', text: '上次檢查：' + fmtTime(st.lastRun) }));
				box.appendChild(el('h4', { text: '出口' }));
				box.appendChild(simpleTable(['出口（網卡）', '類型', '偵測到的 IP', '狀態'], [].concat(st.sources || []).map(function (x) {
					return [x.interface || '自動（預設路由）', fam(x), { text: x.ip || '-', cls: 'mono' },
						x.ok ? badge('正常', 'ok') : el('div', {}, [badge('失敗', 'err'), el('div', { class: 'cell-err', text: x.error || '' })])];
				}), '還沒有偵測結果'));
				box.appendChild(el('h4', { text: 'DNS 記錄' }));
				box.appendChild(simpleTable(['名稱', '類型', '內容', '結果'], [].concat(st.records || []).map(function (x) {
					var act = DDNS_ACTION[x.action] || x.action || '-';
					return [{ text: x.name, cls: 'mono' }, x.type, { text: x.content || x.ip || '-', cls: 'mono' },
						x.ok ? badge(act, x.action === 'kept' ? 'warn' : 'ok') : el('div', {}, [badge(act, x.action === 'skip' ? 'warn' : 'err'), el('div', { class: 'cell-err', text: x.error || '' })])];
				}), '還沒有更新過'));
				var msg = el('span', { class: 'muted' });
				box.appendChild(el('div', { class: 'tbl-actions' }, [
					actBtn('重新整理', 'small', function () { return reload(); }),
					actBtn('立即更新', 'small', function () {
						msg.textContent = '更新中…';
						return api('/api/ddns/update', { method: 'POST' }).then(function (r) {
							if (!r.ok) { msg.textContent = '失敗：' + errText(r); return; }
							return reload();
						});
					}), msg]));
			});
		},

		// 連線來源：目前狀態、被拒絕最多的網段
		access: function () { return panel('access', loadAccess, accessPanel); },
		accessTest: accessTest,

		// 存放位置（/api/paths）：只有路徑，沒有密鑰內容
		paths: function () {
			return panel('paths', function () { return api('/api/paths'); }, function (box, p) {
				var t = p.tls || {}, a = p.acme || {};
				var share = function () { return badge('其他服務可以讀取', 'ok'); };
				var secret = function () { return badge('含密鑰，請勿外流', 'warn'); };
				var rows = [
					['設定檔', p.configFile, '所有設定（只存跟預設值不同的欄位）。API Token 也在裡面。', [secret()]],
					['設定資料夾', p.configDir, '設定檔、登入 token、自動申請的憑證所在的資料夾。'],
					['憑證檔', t.cert, t.source === 'acme' ? '自動申請的憑證（含中繼憑證，PEM）。續期時會更新這個檔案。' : '自己的憑證檔（PEM），黑潮 DNS 只讀取。', t.cert ? [share()] : null],
					['私鑰檔', t.key, '憑證的私鑰（PEM）。其他服務要共用時，請確認只有需要的帳號讀得到。', t.key ? [share(), secret()] : null],
					['ACME 帳號', a.enabled ? a.account : null, '自動申請憑證用的帳號金鑰。', a.enabled ? [secret()] : null],
					['學習資料', p.stateDir, '評測結果、節點池、CDN 網域庫、統計。'],
					['執行期暫存', p.runtimeDir, '重新開機就可以清掉的暫存資料。'],
					['程式附帶的資料', p.shareDir, '內建名單與網頁檔，升級時更新。'],
					['自訂規則', p.customRules, '自己加的過濾規則，用記事本編輯。'],
					['評測報表', p.benchmarkDir, '每日 DNS 評測的報表。'],
					['社群金鑰', p.communityKeyDir, '好友社群的身分金鑰。', [secret()]],
					['設定頁登入 token', p.adminToken, '登入這個設定頁用的 token 檔。', [secret()]],
					['日誌檔', p.logFile, '以 Windows 服務執行時的日誌；用 cmd 執行時直接顯示在視窗裡。']
				];
				var tb = el('tbody');
				rows.forEach(function (r) {
					tb.appendChild(el('tr', {}, [
						el('th', { text: r[0] }),
						el('td', {}, [].concat(r[1] == null ? [null] : r[1]).map(pathCell)),
						el('td', { class: 'use' }, [r[2], r[3] ? el('div', { class: 'tags' }, r[3]) : null])
					]));
				});
				box.appendChild(el('div', { class: 'table-wrap' }, el('table', { class: 'paths' }, [
					el('thead', {}, el('tr', {}, ['項目', '位置', '用途'].map(function (h) { return el('th', { text: h }); }))), tb])));
				if (a.enabled && [].concat(a.domains || []).length) box.appendChild(el('p', { class: 'muted', text: '自動申請的網域：' + [].concat(a.domains).join('、') }));
			});
		}
	};

	/** 物件陣列（訂閱清單）：每一列的欄位依 columns；不認識的屬性保留 */
	function renderTable(f, row) {
		var pro = isPro();
		// 進階欄位（pro）只在專業模式顯示；沒顯示的欄位值原樣保留
		var cols = (f.columns || []).filter(function (c) { return pro || !c.pro; });
		var d = defOf(f);
		var rows = clone(userOf(f.key) !== undefined ? userOf(f.key) : (d || [])) || [];
		var wrap = el('div');
		var tbody = el('tbody');
		var commit = function () {
			var errs = [];
			rows.forEach(function (r, i) {
				cols.forEach(function (c) {
					var v = r[c.key];
					if (c.required && (v == null || v === '')) errs.push('第 ' + (i + 1) + ' 列「' + c.label + '」不能空白');
					else if (c.pattern && v && !new RegExp(c.pattern).test(v)) errs.push('第 ' + (i + 1) + ' 列：' + (c.patternMsg || '格式不正確'));
				});
			});
			if (deepEqual(rows, d)) setValue(f, undefined);
			else setValue(f, clone(rows));
			if (errs.length) S.errors[f.key] = errs.join('；');
			changed(f, row);
		};
		var draw = function () {
			clear(tbody);
			rows.forEach(function (r, i) {
				var tr = el('tr');
				cols.forEach(function (c) {
					var td = el('td', { class: c.type === 'bool' ? 'c' : '' });
					var cur = r[c.key] === undefined ? c.default : r[c.key];
					var inp;
					if (c.type === 'bool') {
						inp = el('input', { type: 'checkbox', checked: cur !== false, 'aria-label': c.label });
						inp.addEventListener('change', function () {
							if (inp.checked === c.default) delete r[c.key]; else r[c.key] = inp.checked;
							commit();
						});
					} else if (c.type === 'select') {
						inp = el('select', { 'aria-label': c.label });
						(c.options || []).forEach(function (o) { inp.appendChild(el('option', { value: String(o.value), text: o.label })); });
						if (cur && !(c.options || []).some(function (o) { return o.value === cur; })) inp.appendChild(el('option', { value: cur, text: cur }));
						inp.value = cur == null ? '' : String(cur);
						// 選項的值照原本的型別存（例如 true / false）；空白 = 不寫（用預設）
						inp.addEventListener('change', function () {
							var o = (c.options || []).filter(function (x) { return String(x.value) === inp.value; })[0];
							var v = o ? o.value : inp.value;
							if (v === '') delete r[c.key]; else r[c.key] = v;
							commit();
						});
					} else {
						inp = el('input', { type: 'text', class: c.key === 'url' ? 'url' : '', placeholder: c.placeholder || '', 'aria-label': c.label, spellcheck: 'false' });
						inp.value = cur == null ? '' : String(cur);
						inp.addEventListener('input', function () { r[c.key] = inp.value.trim(); commit(); });
					}
					td.appendChild(inp);
					tr.appendChild(td);
				});
				tr.appendChild(el('td', { class: 'c' }, el('button', {
					type: 'button', class: 'btn small danger', text: '刪除', 'aria-label': '刪除第 ' + (i + 1) + ' 列',
					onclick: function () { rows.splice(i, 1); draw(); commit(); }
				})));
				tbody.appendChild(tr);
			});
			if (!rows.length) tbody.appendChild(el('tr', {}, el('td', { class: 'empty', colspan: cols.length + 1, text: '沒有任何清單' })));
		};
		draw();
		var head = el('tr', {}, cols.map(function (c) { return el('th', { text: c.label }); }).concat([el('th')]));
		wrap.appendChild(el('div', { class: 'table-wrap' }, el('table', { class: 'tbl-edit' }, [el('thead', {}, head), tbody])));
		wrap.appendChild(el('div', { class: 'tbl-actions' }, [
			el('button', {
				type: 'button', class: 'btn small', text: '新增一列',
				onclick: function () {
					var r = {};
					cols.forEach(function (c) { if (c.type !== 'bool' && c.default !== undefined) r[c.key] = c.default; else if (c.type !== 'bool') r[c.key] = ''; });
					rows.push(r);
					draw();
					commit();
					var last = tbody.lastChild && tbody.lastChild.querySelector('input[type=text]');
					if (last) last.focus();
				}
			}),
			el('button', {
				type: 'button', class: 'btn small', text: '還原預設清單',
				onclick: function () { rows = clone(d || []); draw(); commit(); }
			})
		]));
		return wrap;
	}

	function renderRaw(box) {
		var file = S.cfg.file || '';
		box.appendChild(el('p', { class: 'desc', text: '直接編輯設定檔 ' + file + ' 的內容（只有跟預設值不同的欄位）。儲存時一樣會去掉跟預設值相同的欄位。完整的預設值可以在下方參考。' }));
		var card = el('div', { class: 'card section raw' });
		var ta = el('textarea', { id: 'raw-json', spellcheck: 'false', 'aria-label': '設定檔 JSON' });
		ta.value = JSON.stringify(prune(S.work, S.cfg.defaults), null, 2);
		var msg = el('p', { class: 'msg', hidden: true });
		ta.addEventListener('input', function () { S.rawDirty = true; msg.hidden = true; ta.classList.remove('invalid'); updateSaveBar(); });
		var parse = function () {
			var v;
			try { v = JSON.parse(ta.value); } catch (e) {
				ta.classList.add('invalid');
				msg.className = 'msg err';
				msg.textContent = 'JSON 格式錯誤：' + e.message;
				msg.hidden = false;
				return null;
			}
			if (!isObj(v)) {
				msg.className = 'msg err';
				msg.textContent = '設定必須是 JSON 物件（{ … }）';
				msg.hidden = false;
				return null;
			}
			return v;
		};
		append(card, [ta, msg, el('div', { class: 'tbl-actions' }, [
			el('button', {
				type: 'button', class: 'btn', text: '檢查格式並套用到表單', onclick: function () {
					var v = parse();
					if (!v) return;
					S.work = v;
					S.errors = {};
					S.rawDirty = false;
					msg.className = 'msg ok';
					msg.textContent = '格式正確，已套用到表單（還沒有儲存）。';
					msg.hidden = false;
					renderGroupNav();
					updateSaveBar();
				}
			}),
			el('button', {
				type: 'button', class: 'btn primary', id: 'raw-save', text: '儲存原始 JSON', onclick: function () {
					var v = parse();
					if (!v) return;
					S.work = v;
					S.errors = {};
					S.rawDirty = false;
					saveForm();
				}
			})
		])]);
		box.appendChild(card);
		var dcard = el('details', { class: 'card section' }, [el('summary', { text: '完整預設值（並行數依這台的 CPU 核心數換算，唯讀）' }),
			el('pre', { class: 'out', text: JSON.stringify(S.cfg.defaults, null, 2) })]);
		box.appendChild(dcard);
	}

	function updateSaveBar(msg, kind) {
		var m = $('save-msg');
		var nErr = Object.keys(allErrors()).length;
		if (msg) { m.textContent = msg; m.className = 'savebar-msg ' + (kind || ''); }
		else if (nErr) { m.textContent = '有 ' + nErr + ' 個欄位格式不正確'; m.className = 'savebar-msg err'; }
		else if (isDirty()) {
			var n = countChanges();
			m.textContent = n ? '有 ' + n + ' 項未儲存的變更' : '有未儲存的變更';
			m.className = 'savebar-msg';
		} else { m.textContent = '沒有未儲存的變更'; m.className = 'savebar-msg'; }
		$('btn-save').disabled = S.saving || !!nErr || !isDirty();
		$('btn-discard').disabled = S.saving || (!isDirty() && !nErr);
	}
	function countChanges() {
		var a = prune(S.work, S.cfg.defaults), b = S.orig, n = 0;
		(function walk(x, y) {
			var ks = {};
			Object.keys(x || {}).concat(Object.keys(y || {})).forEach(function (k) { ks[k] = 1; });
			Object.keys(ks).forEach(function (k) {
				var p = x ? x[k] : undefined, q = y ? y[k] : undefined;
				if (isObj(p) && isObj(q)) walk(p, q);
				else if (isObj(p) && q === undefined) walk(p, {});
				else if (isObj(q) && p === undefined) walk({}, q);
				else if (!deepEqual(p, q)) n++;
			});
		})(a, b);
		return n;
	}

	// ---------------------------------------------------------------- 儲存
	function saveForm() {
		if (S.saving) return;
		var rawTa = $('raw-json');
		if (S.rawDirty && rawTa) {
			// 在原始 JSON 編輯後直接按下方的「儲存並套用」：用編輯框的內容
			var v;
			try { v = JSON.parse(rawTa.value); } catch (e) { updateSaveBar('原始 JSON 格式錯誤：' + e.message, 'err'); return; }
			if (!isObj(v)) { updateSaveBar('設定必須是 JSON 物件（{ … }）', 'err'); return; }
			S.work = v;
			S.errors = {};
			S.rawDirty = false;
		}
		var nErr = Object.keys(allErrors()).length;
		if (nErr) { updateSaveBar('請先修正格式不正確的欄位', 'err'); return; }
		var body = prune(S.work, S.cfg.defaults);
		var defs = S.cfg.defaults;
		var oldPort = getPath(S.cfg.effective, 'admin.port'), newPort = getPath(body, 'admin.port');
		if (newPort === undefined) newPort = getPath(defs, 'admin.port');
		var adminOff = getPath(body, 'admin.enabled') === false;
		S.saving = true;
		updateSaveBar('儲存中…', 'busy');
		api('/api/config', { method: 'PUT', body: JSON.stringify(body, null, 2) + '\n' }).then(function (r) {
			if (r.status === 401) { S.saving = false; return; }
			if (!r.ok) {
				S.saving = false;
				if (r.status === 404) { S.cfgError = 'uci'; renderSettings(); return; }
				updateSaveBar('儲存失敗：' + errText(r), 'err');
				toast('儲存失敗：' + errText(r), true);
				return;
			}
			if (adminOff || (newPort && String(newPort) !== String(location.port || oldPort))) {
				S.saving = false;
				var url = 'http://' + location.hostname + ':' + newPort + '/';
				updateSaveBar(adminOff ? '已儲存。設定頁已關閉（admin.enabled = false），之後要改設定請直接編輯設定檔。'
					: '已儲存。設定頁改到新的埠號：' + url + '（舊網址不能再用）', 'ok');
				S.orig = body;
				S.cfg.user = clone(body);
				return;
			}
			updateSaveBar('已儲存，服務重新啟動中…', 'busy');
			waitRestart().then(function (back) {
				S.saving = false;
				if (!back) {
					updateSaveBar('服務沒有在 30 秒內回來。新設定可能有問題（例如埠號被占用），請看執行視窗或日誌檔。設定已經寫入：' + (S.cfg.file || ''), 'err');
					return;
				}
				api('/api/session', { noAuthRedirect: true }).then(function (s) {
					if (s.ok && s.data) S.session = s.data;
					if (S.session.auth && !S.session.loggedIn) { showLogin('設定已套用，請重新登入。'); return; }
					loadConfig().then(function () {
						renderSettings();
						updateSaveBar('已儲存並套用（' + new Date().toLocaleTimeString('zh-TW', { hour12: false }) + '）', 'ok');
						toast('設定已儲存並套用');
					});
				});
			});
		});
	}

	/** 存檔後伺服器會在程式內重新啟動（設定頁也會斷線約 1 秒）：先等它斷線，再等它回來 */
	function waitRestart() {
		var t0 = Date.now(), down = false;
		var poll = function () {
			if (Date.now() - t0 > 30000) return Promise.resolve(false);
			return fetch('/api/session', { cache: 'no-store', credentials: 'same-origin' }).then(function (r) {
				if (r.ok && (down || Date.now() - t0 > 3000)) return true;
				return sleep(300).then(poll);
			}, function () {
				down = true;
				return sleep(300).then(poll);
			});
		};
		return sleep(400).then(poll);
	}

	// ---------------------------------------------------------------- 工具分頁
	var toolsBuilt = false;
	var JOBS = { 'dns-benchmark': 'DNS 評測', 'cdn-ranges': 'CDN IP 範圍', 'cdn-scan': 'CDN 網段分類', 'cdn-pool': '台灣節點池', 'tw-ip': '台灣 IP 清單' };
	var QTYPES = ['A', 'AAAA', 'HTTPS', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'SRV'];

	function toolCard(id, title, desc, wide) {
		var out = el('pre', { class: 'out', hidden: true });
		var verdict = el('p', { class: 'verdict', hidden: true });
		var body = el('div', { class: 'ctl-row' });
		var card = el('div', { class: 'card tool' + (wide ? ' wide' : ''), id: 'tool-' + id }, [el('h3', { text: title }), desc ? el('p', { text: desc }) : null, body, verdict, out]);
		card.show = function (text, kind, data) {
			verdict.textContent = text || '';
			verdict.className = 'verdict ' + (kind || '');
			verdict.hidden = !text;
			out.hidden = data === undefined;
			if (data !== undefined) out.textContent = pretty(data);
		};
		card.body = body;
		return card;
	}
	/** 按鈕：執行時停用，結果交給 done(r) */
	function actBtn(text, cls, fn) {
		var b = el('button', { type: 'button', class: 'btn ' + (cls || ''), text: text });
		b.addEventListener('click', function () {
			if (b.disabled) return;
			b.disabled = true;
			Promise.resolve(fn()).then(function () { b.disabled = false; }, function () { b.disabled = false; });
		});
		return b;
	}
	function typeSelect() {
		var s = el('select', { 'aria-label': '查詢類型' });
		QTYPES.forEach(function (t) { s.appendChild(el('option', { value: t, text: t })); });
		return s;
	}
	function nameInput(ph, label) { return el('input', { type: 'text', placeholder: ph, 'aria-label': label, spellcheck: 'false', autocomplete: 'off' }); }

	function renderTools() {
		if (toolsBuilt) { refreshJobs(); refreshAcme(); refreshDdns(); return; }
		toolsBuilt = true;
		var box = clear($('tools'));

		// 清除快取
		var cache = toolCard('cache', '清除快取', '清掉所有 DNS 快取，下一次查詢重新問上游。');
		cache.body.appendChild(actBtn('清除快取', 'primary', function () {
			return api('/api/cache/flush', { method: 'POST' }).then(function (r) {
				r.ok ? cache.show('快取已清除', 'ok', r.data) : cache.show('失敗：' + errText(r), 'err');
			});
		}));
		box.appendChild(cache);

		// 規則檢查
		var fc = toolCard('filter', '過濾規則檢查', '看一個網域會不會被擋、是哪一條規則。');
		var fn = nameInput('ads.example.com', '要檢查的網域'), ft = typeSelect();
		var doCheck = function () {
			var n = fn.value.trim();
			if (!n) { fc.show('請輸入網域', 'warn'); return; }
			return api('/api/filter/check?' + qs({ name: n, type: ft.value })).then(function (r) {
				if (!r.ok) return fc.show('失敗：' + errText(r), 'err');
				var x = r.data || {};
				var v = x.enabled === false ? '過濾沒有啟用' : x.action === 'block' ? '會被封鎖' : x.action === 'allow' ? '白名單放行' : '沒有命中任何規則';
				var tier = x.tier ? '（' + (x.tier === 'custom' ? '自訂規則' : '訂閱清單') + '）' : '';
				fc.show(v + (x.rule ? ' — ' + x.rule : '') + tier, x.action === 'block' ? 'err' : x.action === 'allow' ? 'ok' : '', x);
			});
		};
		fn.addEventListener('keydown', function (ev) { if (ev.key === 'Enter') doCheck(); });
		append(fc.body, [fn, ft, actBtn('檢查', 'primary', doCheck), actBtn('立即更新清單', '', function () {
			fc.show('下載訂閱清單中…', '');
			return api('/api/filter/update', { method: 'POST' }).then(function (r) {
				r.ok ? fc.show('已重新下載訂閱清單' + (r.data && r.data.changed != null ? '（' + (r.data.changed ? '有更新' : '沒有變化') + '）' : ''), 'ok', r.data)
					: fc.show('失敗：' + errText(r), 'err');
			});
		})]);
		box.appendChild(fc);

		// 追蹤
		var tc = toolCard('trace', '追蹤網域', '完整追蹤一個網域：過濾、每個上游的回答、IP 測速、快取、CDN。');
		var tn = nameInput('www.example.com', '要追蹤的網域'), tt = typeSelect();
		var doTrace = function () {
			var n = tn.value.trim();
			if (!n) { tc.show('請輸入網域', 'warn'); return; }
			tc.show('追蹤中…', '');
			return api('/api/trace?' + qs({ name: n, type: tt.value })).then(function (r) {
				if (!r.ok) return tc.show('失敗：' + errText(r), 'err');
				var ups = (r.data && r.data.upstreams) || [];
				var good = ups.filter(function (u) { return !u.error; });
				var fastest = good[0];
				tc.show(good.length + ' / ' + ups.length + ' 個上游有回應' + (fastest ? '，最快 ' + fastest.ms + ' ms（' + fastest.id + '）' : ''), good.length ? 'ok' : 'warn', r.data);
			});
		};
		tn.addEventListener('keydown', function (ev) { if (ev.key === 'Enter') doTrace(); });
		append(tc.body, [tn, tt, actBtn('追蹤', 'primary', doTrace)]);
		box.appendChild(tc);

		// 排程工作
		var jc = toolCard('jobs', '排程工作', '到時間會在背景自動執行；也可以現在就跑一次。', true);
		jc.table = el('tbody');
		jc.body.appendChild(el('div', { class: 'table-wrap' }, el('table', {}, [el('thead', {}, el('tr', {}, ['工作', '排程', '下次', '上次結束', '結果', ''].map(function (h) { return el('th', { text: h }); }))), jc.table])));
		jc.body.classList.add('block');
		box.appendChild(jc);

		// 憑證
		var ac = toolCard('acme', '憑證（ACME）', '用 Cloudflare DNS 驗證向 Let’s Encrypt 申請或續期。申請約需 1～3 分鐘。');
		var force = el('input', { type: 'checkbox' });
		append(ac.body, [actBtn('立即申請', 'primary', function () {
			ac.show('啟動中…', '');
			return api('/api/acme/issue' + (force.checked ? '?force=1' : ''), { method: 'POST' }).then(function (r) {
				if (!r.ok) return ac.show('失敗：' + errText(r), 'err');
				return sleep(1500).then(function () { return pollAcme(ac, Date.now()); });
			});
		}), el('label', { class: 'chk' }, [force, el('span', { text: '還沒到期也重新申請' })])]);
		box.appendChild(ac);

		// DDNS
		var dc = toolCard('ddns', 'DDNS', '公網 IP 變了就更新 Cloudflare 的 DNS 記錄。');
		dc.body.appendChild(actBtn('立即更新', 'primary', function () {
			dc.show('更新中…', '');
			return api('/api/ddns/update', { method: 'POST' }).then(function (r) {
				if (!r.ok) return dc.show('失敗：' + errText(r), 'err');
				var st = r.data || {};
				var lines = (st.records || []).map(function (x) { return x.name + ' ' + x.type + ' ' + (x.ip || '') + '：' + (x.ok ? x.action : x.error); });
				dc.show(st.error ? '有錯誤：' + st.error : 'DDNS 已更新', st.error ? 'warn' : 'ok', lines.length ? lines.join('\n') + '\n\n' + pretty(st) : st);
			});
		}));
		box.appendChild(dc);

		// 查看資料
		var vc = toolCard('view', '查看資料', '讀取管理 API 的原始資料（唯讀）。功能沒有啟用時會顯示原因。', true);
		var sel = el('select', { 'aria-label': '資料' });
		[['/api/upstreams', '上游'], ['/api/routing', '今天的 CDN 路由統計'], ['/api/cdn/status', 'CDN 台灣節點狀態'], ['/api/cdn/pools', '台灣節點池'],
			['/api/cdn/summary', 'CDN 網域摘要'], ['/api/cdn/domains?limit=100', 'CDN 網域資料庫（前 100 筆）'], ['/api/community/status', '社群：我的狀態'],
			['/api/community/peers', '社群：好友'], ['/api/community/events', '社群：紀錄'], ['/api/benchmark', '每日評測結果'], ['/api/sysinfo', '硬體資訊']]
			.forEach(function (o) { sel.appendChild(el('option', { value: o[0], text: o[1] })); });
		append(vc.body, [sel, actBtn('讀取', 'primary', function () {
			return api(sel.value).then(function (r) {
				r.ok ? vc.show(sel.options[sel.selectedIndex].text, '', r.data == null ? '（沒有資料）' : r.data) : vc.show(errText(r), 'warn');
			});
		})]);
		box.appendChild(vc);

		box.appendChild(backupCard());

		refreshJobs();
		refreshAcme();
		refreshDdns();
	}

	// ---------------------------------------------------------------- 備份與分享
	/** 匯入結果（/api/backup/last-import）→ 一類一行 */
	function importLines(r) {
		var words = [['added', '新增'], ['updated', '更新'], ['kept', '保留本機'], ['skipped', '略過']];
		return (r.items || []).map(function (i) {
			var parts = words.filter(function (w) { return i[w[0]] > 0; }).map(function (w) { return w[1] + ' ' + fmtNum(i[w[0]]); });
			return (i.label || i.file) + '：' + (parts.length ? parts.join('、') : '沒有變動') +
				(i.note ? '（' + i.note + '）' : '') + (i.error ? '【錯誤：' + i.error + '】' : '');
		});
	}
	function previewText(p) {
		return (p.kindLabel || '備份') + (p.core ? '，黑潮 DNS ' + p.core : '') + (p.exportedAt ? '，' + fmtTime(p.exportedAt) + ' 匯出' : '') +
			'：' + (p.files || []).map(function (f) { return f.label + ' ' + fmtNum(f.count) + ' ' + f.unit; }).join('、');
	}
	function backupCard() {
		var bc = toolCard('backup', '備份與分享', '換電腦、重灌，或把學到的資料分享給朋友。匯入是「合併」：本機比較新的資料會留著，不會被蓋掉。', true);
		bc.insertBefore(el('ul', { class: 'notes' }, [
			el('li', {}, [el('strong', { text: '完整備份' }), '：全部學習資料、自訂規則、社群身分與好友。含私鑰，請自己保管，不要給別人。']),
			el('li', {}, [el('strong', { text: '分享給朋友' }), '：CDN 網域驗證紀錄（只有網域名稱與驗證結果，不含查詢次數與時間）、台灣節點池（匯入的一方只當候選，本機驗證通過才使用）。上游評測與黑名單由每台機器自己判定，不放進分享檔。沒有身分、金鑰、統計與自訂規則。'])
		]), bc.body);
		var file = el('input', { type: 'file', accept: '.kuroshio', 'aria-label': '選擇要匯入的 .kuroshio 檔', id: 'backup-file' });
		var imp = actBtn('匯入', '', function () {
			var f = file.files && file.files[0];
			if (!f) { bc.show('請先選擇 .kuroshio 檔', 'warn'); return; }
			bc.show('上傳中…', '');
			return f.arrayBuffer().then(function (buf) {
				return api('/api/backup/import', { method: 'POST', raw: buf });
			}).then(function (r) {
				if (r.status === 401) return;
				if (!r.ok) return bc.show('匯入失敗：' + errText(r), 'err');
				var pv = r.data && r.data.preview ? previewText(r.data.preview) : '';
				bc.show('檔案沒問題，服務重新啟動並合併中…', '', pv);
				return waitRestart().then(function (back) {
					if (!back) return bc.show('服務沒有在 30 秒內回來，請看日誌。', 'err', pv);
					return api('/api/backup/last-import').then(function (x) {
						var d = x.data || {};
						if (!x.ok || d.none) return bc.show('服務已重新啟動，但沒有讀到匯入結果：' + (x.ok ? '請看日誌' : errText(x)), 'warn');
						if (d.ok === false) return bc.show('匯入失敗：' + (d.error || '部分資料寫入失敗'), 'err', importLines(d).join('\n'));
						file.value = '';
						bc.show('匯入完成（' + (d.kindLabel || '') + '）', 'ok', pv + '\n\n' + importLines(d).join('\n'));
						toast('匯入完成');
					});
				});
			});
		});
		append(bc.body, [
			el('a', { class: 'btn primary', id: 'backup-full', href: '/api/backup/export?kind=full', download: '', text: '下載完整備份' }),
			el('a', { class: 'btn', id: 'backup-share', href: '/api/backup/export?kind=share', download: '', text: '下載分享檔' }),
			el('span', { class: 'sep-v', 'aria-hidden': 'true' }),
			file, imp
		]);
		api('/api/backup/last-import').then(function (x) {
			var d = x.ok && x.data;
			if (d && !d.none && d.importedAt) bc.show('上次匯入：' + fmtTime(d.importedAt) + (d.ok === false ? '（失敗）' : ''), d.ok === false ? 'warn' : '', importLines(d).join('\n') || undefined);
		});
		return bc;
	}

	function refreshJobs() {
		var jc = $('tool-jobs');
		if (!jc) return;
		return api('/api/jobs').then(function (r) {
			var tb = jc.table;
			if (!r.ok || !r.data) {
				tableRows(tb, [], 6);
				jc.show(r.ok ? '排程器沒有啟動' : '讀取失敗：' + errText(r), 'warn');
				return;
			}
			var j = r.data, cfg = j.config || {}, state = j.state || {}, next = j.nextRun || {}, detail = j.detail || {};
			var running = j.running && j.running.name;
			var queue = (j.queue || []).map(function (q) { return q.name || q; });
			tableRows(tb, Object.keys(cfg).map(function (n) {
				var c = cfg[n], s = state[n] || {};
				var b = el('button', { type: 'button', class: 'btn small', 'data-job': n, text: '立即執行' });
				if (running === n || queue.indexOf(n) >= 0) b.disabled = true;
				b.addEventListener('click', function () {
					b.disabled = true;
					api('/api/jobs/run?' + qs({ name: n }), { method: 'POST' }).then(function (x) {
						if (!x.ok) jc.show('失敗：' + errText(x), 'err');
						else if (x.data && x.data.ok === false) jc.show('沒有排入：' + (x.data.error || '原因不明') + '（相關功能沒有啟用時，例如 CDN 關閉，CDN 的工作不會執行）', 'warn', x.data);
						else jc.show('已排入背景執行：' + (JOBS[n] || n), 'ok', x.data);
						setTimeout(refreshJobs, 800);
					});
				});
				var sched = (c.monthDays ? '每月 ' + [].concat(c.monthDays).join('、') + ' 日' + (c.jitterDays ? '起（每台錯開）' : '') + ' ' : '') + [].concat(c.at || []).join(', ') + (c.weekdays ? '（' + [].concat(c.weekdays).map(function (w) { return '週' + ('日一二三四五六'.charAt(+w) || w); }).join('、') + '）' : '') + (c.enabled === false ? ' 已停用' : '');
				var res = running === n ? '執行中…' : queue.indexOf(n) >= 0 ? '排隊中' : s.lastCode === 0 ? '成功' : s.lastCode == null ? '-' : '失敗（' + s.lastCode + '）';
				// 有自己進度的工作（台灣 IP 清單）：顯示進度、暫停原因、上次結果
				if (detail[n] && detail[n].text) res = detail[n].text;
				return [JOBS[n] || n, sched, fmtTime(next[n]), fmtTime(s.lastEnd), res, b];
			}), 6);
		});
	}

	function acmeText(st) {
		if (!st || st.enabled === false) return ['內建 ACME 沒有啟用：到「設定 → 憑證」打開「自動申請憑證」並儲存。', 'warn'];
		var c = st.certInfo;
		if (st.running) return ['申請中…', ''];
		if (st.error) return ['上次申請失敗：' + st.error, 'err'];
		if (c) return [(c.san || c.subject) + '，到期 ' + c.validTo + '（剩 ' + c.daysLeft + ' 天）', c.daysLeft < 14 ? 'warn' : 'ok'];
		return ['還沒有憑證', 'warn'];
	}
	function refreshAcme() {
		var ac = $('tool-acme');
		if (!ac) return;
		return api('/api/acme').then(function (r) {
			if (!r.ok) return ac.show('讀取失敗：' + errText(r), 'err');
			var t = acmeText(r.data);
			ac.show(t[0], t[1], r.data);
		});
	}
	function pollAcme(ac, t0) {
		return api('/api/acme').then(function (r) {
			if (!r.ok) return ac.show('讀取失敗：' + errText(r), 'err');
			var t = acmeText(r.data);
			ac.show(t[0], t[1], r.data);
			if (r.data && r.data.running && Date.now() - t0 < 300000) return sleep(3000).then(function () { return pollAcme(ac, t0); });
		});
	}
	function refreshDdns() {
		var dc = $('tool-ddns');
		if (!dc) return;
		return api('/api/ddns').then(function (r) {
			if (!r.ok) return dc.show('讀取失敗：' + errText(r), 'err');
			var st = r.data || {};
			if (st.enabled === false) dc.show('DDNS 沒有啟用：到「設定 → DDNS」打開並儲存。', 'warn');
			else dc.show(st.error ? '上次更新有錯誤：' + st.error : '上次更新：' + fmtTime(st.lastRun), st.error ? 'warn' : 'ok', st);
		});
	}

	// ---------------------------------------------------------------- 日誌分頁
	var logLines = [], logBusy = false;
	function refreshLog() {
		if (logBusy) return;
		logBusy = true;
		api('/api/log?lines=' + encodeURIComponent($('log-lines').value)).then(function (r) {
			logBusy = false;
			if (r.status === 401) return;
			logLines = r.ok && r.data ? (r.data.lines || []) : ['讀取失敗：' + errText(r)];
			showLog();
		});
	}
	function showLog() {
		var pre = $('log-pre');
		var atBottom = pre.scrollHeight - pre.scrollTop - pre.clientHeight < 40;
		var kw = $('log-filter').value.trim().toLowerCase();
		var ls = kw ? logLines.filter(function (l) { return String(l).toLowerCase().indexOf(kw) >= 0; }) : logLines;
		pre.textContent = ls.length ? ls.join('\n') : (kw ? '沒有符合的紀錄' : '沒有紀錄');
		if (atBottom || !pre.dataset.seen) pre.scrollTop = pre.scrollHeight;
		pre.dataset.seen = '1';
	}
})();
