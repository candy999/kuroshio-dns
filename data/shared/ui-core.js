/*!
 * 黑潮 DNS 介面共用邏輯（LuCI kuroshio/ui.js、Windows 設定頁 data/admin/app.js 共用；第三方韌體也可以直接載入）
 * 授權：GPL-3.0-or-later
 *
 * 只放跟介面框架無關的純函式（不碰 DOM、不發請求），載入後是全域的 KuroshioUiCore：
 *   fmtTime(t, mode, tzOffsetMin)   日期時間固定格式（2026-11-12 10:22）
 *   fmtBytes(b)                     位元組 → B / KB / MB
 *   certCovers(info, domain)        憑證的 SAN 有沒有涵蓋這個網域（含萬用字元）
 *   restorePlan(cur, defs, removeOwn)  「恢復預設清單」的比對結果
 *   restoreSummary(changes, tr)     「恢復預設清單」的變更清單（文字，畫面由各介面自己組）
 *   format(template, args)          %s / %d 代換
 * 每個函式的輸入與預期輸出在 data/shared/ui-core.tests.json（CI 用 tools/ui-core-test.js 檢查）。
 *
 * 寫法限制：
 *   - ES5 語法（舊瀏覽器、各家路由器韌體的網頁都能直接載入），不是 ES module
 *   - Padavan 的 httpd 會解析 .js 檔裡的模板標記，所以這個檔（以及 data/ 底下所有 .js / .css）
 *     不能出現「小於＋百分比」「百分比＋大於」「小於＋井號」「井號＋大於」這四種兩字元組合，
 *     註解、字串、正規表示式都算（CI 的 tools/check-data-assets.js 會檢查）
 */
(function (root) {
	'use strict';

	function p2(n) { return (n < 10 ? '0' : '') + n; }

	/**
	 * 日期時間一律用台灣習慣的固定格式，不跟瀏覽器語系（英文瀏覽器原本會顯示 11/12/2026, 10:22:03 AM）：
	 * fmtTime(t) = 2026-11-12 10:22（24 小時制）；mode 'sec' 加秒、'date' 只有日期、'time' = 10:22、'timesec' = 10:22:03。
	 * t 可以是毫秒、毫秒字串或 ISO 字串；空的回 '-'，看不懂的原樣回傳。
	 * tzOffsetMin：指定時區（UTC 往東幾分鐘，台灣 = 480）；不給 = 瀏覽器的本地時區（測試用來固定結果）。
	 * 跟共用儀表板 data/dashboard/dashboard.js 的 KuroshioDashboard.fmtTime 同一份規則。
	 */
	function fmtTime(t, mode, tzOffsetMin) {
		if (t === null || t === undefined || t === '' || t === 0) return '-';
		var d = new Date(typeof t === 'number' || /^\d+$/.test(t) ? Number(t) : t);
		if (isNaN(d)) return String(t);
		var Y, M, D, h, m, s;
		if (typeof tzOffsetMin === 'number') {
			var u = new Date(d.getTime() + tzOffsetMin * 60000);
			Y = u.getUTCFullYear(); M = u.getUTCMonth(); D = u.getUTCDate(); h = u.getUTCHours(); m = u.getUTCMinutes(); s = u.getUTCSeconds();
		} else {
			Y = d.getFullYear(); M = d.getMonth(); D = d.getDate(); h = d.getHours(); m = d.getMinutes(); s = d.getSeconds();
		}
		var date = Y + '-' + p2(M + 1) + '-' + p2(D);
		var hm = p2(h) + ':' + p2(m), sec = ':' + p2(s);
		return mode === 'date' ? date : mode === 'time' ? hm : mode === 'timesec' ? hm + sec : date + ' ' + hm + (mode === 'sec' ? sec : '');
	}

	/** 位元組：1023 B、12 KB（整數）、1.5 MB（一位小數）；null / undefined 回 '-' */
	function fmtBytes(b) {
		if (b === null || b === undefined) return '-';
		if (b < 1024) return b + ' B';
		if (b < 1048576) return (b / 1024).toFixed(0) + ' KB';
		return (b / 1048576).toFixed(1) + ' MB';
	}

	/** 憑證（certinfo：san = "DNS:a.example.com, DNS:*.example.com"）有沒有涵蓋這個網域（含萬用字元），跟後端 certinfo::covers 一樣 */
	function certCovers(info, domain) {
		var d = String(domain || '').replace(/\.$/, '').toLowerCase();
		return String((info && info.san) || '').split(', ').some(function (n) {
			if (n.slice(0, 4) !== 'DNS:') return false;
			n = n.slice(4).toLowerCase();
			if (n === d) return true;
			var i = d.indexOf('.');
			return n.slice(0, 2) === '*.' && i > 0 && d.slice(i + 1) === n.slice(2);
		});
	}

	/** 依序代換 %s / %d（%d 取整數）；%% = 百分比符號本身 */
	function format(template, args) {
		var i = 0;
		args = args || [];
		return String(template).replace(/%([sd%])/g, function (all, k) {
			if (k === '%') return '%';
			var v = args[i++];
			return k === 'd' ? String(parseInt(v, 10)) : String(v);
		});
	}

	/**
	 * 「恢復預設清單」要怎麼改：比對目前的過濾清單與這個版本的預設清單。
	 * cur / defs：{ name, url, category, enabled(布林), protect(布林或 undefined) }；cur 可以多帶 ref（LuCI 的 UCI 區段 ID）。
	 * 對應方式：先用網址找，找不到再用名稱找（所以只改了網址的預設清單會被改回預設網址）。
	 * 網址不在預設裡的是使用者自己加的：保留、排在預設清單後面（removeOwn = true 時移除）。
	 * 回傳 { result, changes }：
	 *   result：新的清單順序，[{ def（整理過的預設）, raw（傳進來的原始物件）, from（對應到 cur 的第幾個，-1 = 新增）}
	 *           或 { own（整理過的自訂清單）, raw, from }]
	 *   changes：{ add, remove, url, enabled, other, keep, reorder, count }（count = 變更項目數，0 = 不需要變更）
	 */
	function restorePlan(curRaw, defsRaw, removeOwn) {
		var norm = function (x) {
			var p = x.protect;
			return { name: String(x.name || ''), url: String(x.url || '').trim(), category: x.category || 'ads', enabled: x.enabled !== false,
				protect: (p === undefined || p === null || p === '') ? undefined : !!p, ref: x.ref };
		};
		curRaw = curRaw || [];
		defsRaw = defsRaw || [];
		var cur = curRaw.map(norm), defs = defsRaw.map(norm);
		var used = cur.map(function () { return false; }), match = defs.map(function () { return -1; });
		var find = function (test) {
			for (var j = 0; j < cur.length; j++) if (!used[j] && test(cur[j])) { used[j] = true; return j; }
			return -1;
		};
		defs.forEach(function (d, i) { match[i] = find(function (c) { return c.url === d.url; }); });
		defs.forEach(function (d, i) { if (match[i] < 0) match[i] = find(function (c) { return c.name !== '' && c.name === d.name; }); });
		var defUrl = {};
		defs.forEach(function (d) { defUrl[d.url] = true; });
		var ch = { add: [], remove: [], url: [], enabled: [], other: [], keep: [], reorder: false, count: 0 };
		var result = [];
		defs.forEach(function (d, i) {
			var j = match[i];
			result.push({ def: d, raw: defsRaw[i], from: j });
			if (j < 0) { ch.add.push(d); return; }
			var c = cur[j], o = [];
			if (c.url !== d.url) ch.url.push({ name: d.name, from: c.url, to: d.url });
			if (c.enabled !== d.enabled) ch.enabled.push({ name: d.name, from: c.enabled, to: d.enabled });
			if (c.name !== d.name) o.push({ what: 'name', from: c.name, to: d.name });
			if (c.category !== d.category) o.push({ what: 'category', from: c.category, to: d.category });
			if (c.protect !== d.protect) o.push({ what: 'protect', from: c.protect, to: d.protect });
			if (o.length) ch.other.push({ name: d.name, diffs: o });
		});
		cur.forEach(function (c, j) {
			if (used[j]) return;
			var own = !defUrl[c.url];
			if (own && !removeOwn) { result.push({ own: c, raw: curRaw[j], from: j }); ch.keep.push(c); }
			else ch.remove.push({ name: c.name, url: c.url, own: own });
		});
		var order = result.filter(function (r) { return r.from >= 0; }).map(function (r) { return r.from; });
		ch.reorder = order.some(function (v, i) { return i > 0 && v < order[i - 1]; });
		ch.count = ch.add.length + ch.remove.length + ch.url.length + ch.enabled.length + ch.other.length + (ch.reorder ? 1 : 0);
		return { result: result, changes: ch };
	}

	var CAT = { ads: '廣告 / 追蹤', telemetry: '遙測 / 驗證', malware: '惡意 / 詐騙' };

	/**
	 * 「恢復預設清單」確認畫面的變更清單（只有文字，節點由各介面自己組）。
	 * changes：restorePlan 回傳的 changes；tr：翻譯函式（LuCI 傳 _，不給 = 原文）。
	 * 回傳 { empty, blocks }：沒有變更時 empty 是提示文字、blocks 是空陣列；
	 * 有變更時 empty = null，blocks = [{ cls（add / remove / url / enabled / other / reorder / keep）, title, items: [文字] }]，
	 * 沒有項目的區塊不列出。
	 */
	function restoreSummary(ch, tr) {
		var t = typeof tr === 'function' ? tr : function (s) { return s; };
		if (!ch || !ch.count) return { empty: t('目前的訂閱清單已經跟這個版本的預設一樣，不需要變更。'), blocks: [] };
		var onOff = function (v) { return v ? t('啟用') : t('停用'); };
		var prot = function (v) { return v === undefined ? t('自動') : v ? t('保護') : t('不保護'); };
		var cat = function (v) { return CAT[v] ? t(CAT[v]) : v; };
		var blocks = [];
		var block = function (cls, title, items) { if (items.length) blocks.push({ cls: cls, title: title, items: items }); };
		var otherText = function (o) {
			return o.name + '：' + o.diffs.map(function (x) {
				if (x.what === 'name') return format(t('名稱「%s」→「%s」'), [x.from, x.to]);
				if (x.what === 'category') return format(t('分類「%s」→「%s」'), [cat(x.from), cat(x.to)]);
				return format(t('保護「%s」→「%s」'), [prot(x.from), prot(x.to)]);
			}).join('、');
		};
		block('add', format(t('會新增（%d）'), [ch.add.length]), ch.add.map(function (d) { return d.name + '（' + onOff(d.enabled) + '）'; }));
		block('remove', format(t('會移除（%d）'), [ch.remove.length]), ch.remove.map(function (d) { return (d.name || d.url) + (d.own ? t('（自己加的）') : t('（重複的預設清單）')); }));
		block('url', format(t('網址改回預設（%d）'), [ch.url.length]), ch.url.map(function (d) { return d.name + '：' + d.from + ' → ' + d.to; }));
		block('enabled', format(t('啟用狀態改回預設（%d）'), [ch.enabled.length]), ch.enabled.map(function (d) { return d.name + '：' + onOff(d.from) + ' → ' + onOff(d.to); }));
		block('other', format(t('名稱 / 分類 / 保護改回預設（%d）'), [ch.other.length]), ch.other.map(otherText));
		if (ch.reorder) block('reorder', t('順序'), [t('改回預設的順序（自己加的清單排在預設清單後面）')]);
		block('keep', format(t('保留你自己加的清單（%d，排在預設清單後面）'), [ch.keep.length]), ch.keep.map(function (d) { return d.name || d.url; }));
		return { empty: null, blocks: blocks };
	}

	var core = {
		fmtTime: fmtTime,
		fmtBytes: fmtBytes,
		certCovers: certCovers,
		format: format,
		restorePlan: restorePlan,
		restoreSummary: restoreSummary
	};

	if (root) root.KuroshioUiCore = core;
	if (typeof module === 'object' && module.exports) module.exports = core;
})(typeof window !== 'undefined' ? window : (typeof self !== 'undefined' ? self : null));
