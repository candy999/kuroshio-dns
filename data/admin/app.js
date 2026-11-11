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
	function fmtBytes(b) {
		if (b == null) return '-';
		if (b < 1024) return b + ' B';
		if (b < 1048576) return (b / 1024).toFixed(0) + ' KB';
		return (b / 1048576).toFixed(1) + ' MB';
	}
	function pretty(v) { return typeof v === 'string' ? v : JSON.stringify(v, null, 2); }

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
		rawDirty: false
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

	function renderStatus(st, acme) {
		var s = S.session, d = (st.stats && st.stats.today) || {}, sys = st.system || {}, lat = d.latency || {};
		var ms = function (x) { return x && x.p50 != null ? x.p50 + ' / ' + (x.p95 != null ? x.p95 : '>1000') + ' ms' : '-'; };
		var routeAcc = 0, routeN = 0;
		Object.keys(d.route || {}).forEach(function (k) { routeAcc += d.route[k].acc || 0; routeN += d.route[k].n || 0; });
		var f = st.filter, per = sys.persist || {};
		clear($('st-tiles'));
		append($('st-tiles'), [
			tile('版本', st.version || s.version || '-', (s.mode === 'service' ? 'Windows 服務' : 'cmd 直接執行') + ' · ' + (s.os || '')),
			tile('硬體等級', sys.tier || '-', [sys.memTotalMB ? fmtNum(sys.memTotalMB) + ' MB' : '', sys.cores ? sys.cores + ' 核' : '', sys.arch || ''].filter(Boolean).join(' · ')),
			tile('記憶體', sys.rssKB ? (sys.rssKB / 1024).toFixed(1) + ' MB' : '-', '系統可用 ' + (sys.memAvailableMB != null ? fmtNum(sys.memAvailableMB) + ' MB' : '-') + (sys.pressure && sys.pressure !== 'normal' ? ' · 記憶體偏低' : '')),
			tile('已執行', fmtUptime(st.stats && st.stats.uptimeSec), '今天：' + (d.date || '-')),
			tile('今天查詢', fmtNum(d.query), '快取命中率 ' + (d.hitRate != null ? d.hitRate + '%' : '-')),
			tile('攔截', fmtNum(d.blocked), '廣告 ' + fmtNum(d.blockedAds) + ' · 遙測 ' + fmtNum(d.blockedTelemetry) + ' · 惡意 ' + fmtNum(d.blockedMalware)),
			tile('回應時間 p50 / p95', ms(lat.hit), '問上游 ' + ms(lat.miss)),
			tile('拉回台灣', fmtNum(routeAcc), 'CDN 連線的 ' + pct(routeAcc, routeN)),
			tile('CDN 台灣節點', fmtNum(d.cdnServed), '置換 ' + fmtNum(d.cdnRewrite) + ' · ECS ' + fmtNum(d.ecsRewrite) + ' · 跨 CDN ' + fmtNum(d.crossRewrite)),
			tile('快取筆數', fmtNum(st.cacheEntries), '約 ' + fmtBytes(st.cacheBytes)),
			tile('過濾規則', f ? fmtNum((f.lists || 0) + (f.custom || 0)) : '未啟用', f ? '自訂 ' + fmtNum(f.custom) + (f.domains != null ? ' · ' + fmtNum(f.domains) + ' 個網域' : '') : ''),
			tile('磁碟寫入（今天）', per.bytesToday != null ? fmtBytes(per.bytesToday) : '-', (per.storage || '') + (per.intervalMin ? ' · 最短間隔 ' + per.intervalMin + ' 分' : ''))
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
		rows.push(row('DoH（TCP）', ls.doh, ls.doh != null, 'listen.doh.enabled'));
		rows.push(row('DoH3（UDP）', ls.doh3, ls.doh3 != null, 'listen.doh.http3'));
		rows.push(row('DoT（TCP）', ls.dot, ls.dot != null, 'listen.dot.enabled'));
		rows.push(row('DoQ（UDP）', ls.doq, ls.doq != null, 'listen.doq.enabled'));
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

	// ---------------------------------------------------------------- 設定分頁
	function defOf(f) {
		var d = S.cfg ? getPath(S.cfg.defaults, f.key) : undefined;
		return d === undefined ? f.fallbackDefault : d;
	}
	function userOf(key) { return getPath(S.work, key); }
	function effOf(f) { var u = userOf(f.key); return u === undefined ? defOf(f) : u; }
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
		var g = visibleGroups().filter(function (x) { return x.id === S.group; })[0];
		if (!g) return;
		box.appendChild(el('h3', { text: g.title }));
		if (g.raw) { renderRaw(box); return; }
		if (g.desc) box.appendChild(el('p', { class: 'desc', text: g.desc }));
		var pro = isPro();
		(g.sections || []).forEach(function (sec) {
			if (sec.pro && !pro) return;
			var fs = (sec.fields || []).filter(function (f) { return pro || !f.pro; });
			if (!fs.length) return;
			var card = el('div', { class: 'card section' }, [el('h3', { text: sec.title })]);
			if (sec.desc) card.appendChild(el('p', { class: 'desc', text: sec.desc }));
			fs.forEach(function (f) { card.appendChild(renderField(f)); });
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
		applyDepends();
		renderGroupNav();
		updateSaveBar();
	}

	function defText(f, d) {
		if (d === undefined) return null;
		if (f.type === 'bool') return d ? '開啟' : '關閉';
		if (f.type === 'select') {
			var o = (f.options || []).filter(function (x) { return x.value === d; })[0];
			return o ? o.label : String(d);
		}
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
		var et = row.querySelector('.err-text');
		et.textContent = S.errors[f.key] || '';
		et.hidden = !S.errors[f.key];
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
		var row = el('div', { class: 'field' + (f.type === 'bool' ? ' bool' : ''), 'data-key': f.key }, [
			el('label', { class: 'lab', for: id }, [f.label, el('span', { class: 'key', text: f.key })]),
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
			opts.forEach(function (o) { input.appendChild(el('option', { value: o.value, text: o.label })); });
			input.value = u === undefined ? '' : u;
			input.addEventListener('change', function () {
				setValue(f, input.value === '' ? undefined : input.value);
				changed(f, row);
			});
			ctl.appendChild(input);
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
				setValue(f, arr.length ? arr : undefined);
				changed(f, row);
			});
			ctl.appendChild(input);
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
					setValue(f, s);
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

	/** 物件陣列（訂閱清單）：每一列的欄位依 columns；不認識的屬性保留 */
	function renderTable(f, row) {
		var cols = f.columns || [];
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
						(c.options || []).forEach(function (o) { inp.appendChild(el('option', { value: o.value, text: o.label })); });
						if (cur && !(c.options || []).some(function (o) { return o.value === cur; })) inp.appendChild(el('option', { value: cur, text: cur }));
						inp.value = cur || '';
						inp.addEventListener('change', function () { r[c.key] = inp.value; commit(); });
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
		var dcard = el('details', { class: 'card section' }, [el('summary', { text: '完整預設值（' + (S.cfg.tier || '') + ' 等級，唯讀）' }),
			el('pre', { class: 'out', text: JSON.stringify(S.cfg.defaults, null, 2) })]);
		box.appendChild(dcard);
	}

	function updateSaveBar(msg, kind) {
		var m = $('save-msg');
		var nErr = Object.keys(S.errors).length;
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
		var nErr = Object.keys(S.errors).length;
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
	var JOBS = { 'dns-benchmark': 'DNS 評測', 'cdn-ranges': 'CDN IP 範圍', 'cdn-scan': 'CDN 網段分類', 'cdn-pool': '台灣節點池' };
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
			el('li', {}, [el('strong', { text: '分享給朋友' }), '：CDN 網域驗證紀錄（只有網域名稱與驗證結果，不含查詢次數與時間）、台灣節點池（匯入的一方只當候選，本機驗證通過才使用；上游評測與黑名單不會被匯入）。沒有身分、金鑰、統計與自訂規則。'])
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
			var j = r.data, cfg = j.config || {}, state = j.state || {}, next = j.nextRun || {};
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
				var sched = [].concat(c.at || []).join(', ') + (c.weekdays ? '（' + [].concat(c.weekdays).map(function (w) { return '週' + ('日一二三四五六'.charAt(+w) || w); }).join('、') + '）' : '') + (c.enabled === false ? ' 已停用' : '');
				var res = running === n ? '執行中…' : queue.indexOf(n) >= 0 ? '排隊中' : s.lastCode === 0 ? '成功' : s.lastCode == null ? '-' : '失敗（' + s.lastCode + '）';
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
