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
 *   chainView(chain, tr, now)       /api/status 的 chain（串接模式）→ 狀態頁顯示用的資料（下游與上游兩種角色）
 *   benchScope(b, tr)               /api/benchmark 的 tiers、probe（評測範圍、惡意網站探測）→ 一行摘要
 *   controlSummary(list, tr)        /api/benchmark 的 protected[]（對照組）→ 一行摘要
 *   regionLabel(u, tr)              上游的地區（region、regionSource、near）→「台灣」「鄰近（註冊地 GB）」「註冊地 GB」「鄰近」
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
	 * cur / defs：{ name, url, category, enabled(布林), protect(布林或 undefined), bypass(布林；'1' 也算) }；cur 可以多帶 ref（LuCI 的 UCI 區段 ID）。
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
				protect: (p === undefined || p === null || p === '') ? undefined : !!p,
				// 繞過防護：只有標成 true 的才帶（沒有標 = undefined，跟 false 一樣；整理過的結果不多一欄）
				bypass: (x.bypass === true || x.bypass === 1 || x.bypass === '1') ? true : undefined, ref: x.ref };
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
			if (c.bypass !== d.bypass) o.push({ what: 'bypass', from: c.bypass, to: d.bypass });
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
		var yes = function (v) { return v ? t('是') : t('否'); };
		var blocks = [];
		var block = function (cls, title, items) { if (items.length) blocks.push({ cls: cls, title: title, items: items }); };
		var otherText = function (o) {
			return o.name + '：' + o.diffs.map(function (x) {
				if (x.what === 'name') return format(t('名稱「%s」→「%s」'), [x.from, x.to]);
				if (x.what === 'category') return format(t('分類「%s」→「%s」'), [cat(x.from), cat(x.to)]);
				if (x.what === 'bypass') return format(t('繞過防護「%s」→「%s」'), [yes(x.from), yes(x.to)]);
				return format(t('保護「%s」→「%s」'), [prot(x.from), prot(x.to)]);
			}).join('、');
		};
		block('add', format(t('會新增（%d）'), [ch.add.length]), ch.add.map(function (d) { return d.name + '（' + onOff(d.enabled) + '）'; }));
		block('remove', format(t('會移除（%d）'), [ch.remove.length]), ch.remove.map(function (d) { return (d.name || d.url) + (d.own ? t('（自己加的）') : t('（重複的預設清單）')); }));
		block('url', format(t('網址改回預設（%d）'), [ch.url.length]), ch.url.map(function (d) { return d.name + '：' + d.from + ' → ' + d.to; }));
		block('enabled', format(t('啟用狀態改回預設（%d）'), [ch.enabled.length]), ch.enabled.map(function (d) { return d.name + '：' + onOff(d.from) + ' → ' + onOff(d.to); }));
		block('other', format(t('名稱 / 分類 / 保護 / 繞過防護改回預設（%d）'), [ch.other.length]), ch.other.map(otherText));
		if (ch.reorder) block('reorder', t('順序'), [t('改回預設的順序（自己加的清單排在預設清單後面）')]);
		block('keep', format(t('保留你自己加的清單（%d，排在預設清單後面）'), [ch.keep.length]), ch.keep.map(function (d) { return d.name || d.url; }));
		return { empty: null, blocks: blocks };
	}

	// ---------------------------------------------------------------- 串接模式（3.4.0）
	var CHAIN_JOB = { 'dns-benchmark': 'DNS 評測', 'cdn-pool': '台灣節點池', 'cdn-scan': 'CDN 網段分類', 'cdn-ranges': 'CDN IP 範圍' };
	var CHAIN_KIND = { upstreams: '上游評測結果', 'cdn-pools': 'CDN 節點池', 'cdn-v6': 'CDN IPv6 節點', 'cdn-ranges': 'CDN 官方範圍', 'filter-copy': '過濾清單副本' };
	var CHAIN_ERR = {
		'no-room': '這台留不下副本', 'not-subscribed': '這台沒有訂閱這份清單', 'newer-format': '格式比這台新', 'hash-mismatch': '內容跟清單對不上',
		'too-large': '太大', 'memory': '記憶體不夠，這次沒有同步', 'no-share': '上游還沒有共用結果', 'no-response': '上游沒有回應', 'no-tcp': '上游不能用 TCP 傳'
	};
	/** 下游角色的原因（state = released）：這幾種是「上游的情況」，不是異常，用一般樣式 */
	var CHAIN_CALM = { 'not-allowed': 1, 'upstream-too-old': 1, 'unsupported': 1, 'gone': 1 };
	var DAY_MS = 86400000;

	/**
	 * /api/status 的 chain（規格 10 的 1.10、3.7、4.5）→ 狀態頁顯示用的資料。不判斷狀態轉移、不拼狀態句子：
	 * 主要的句子直接用 API 給的 text、serving.text、serving.note，這裡只把其他欄位整理成「標籤：值」。
	 * tr：翻譯函式（LuCI 傳 _，不給 = 原文）；now：現在的毫秒（判斷公鑰是不是 24 小時內換過；不給 = Date.now()）。
	 * 回傳 { down, up }，兩個一定都有（狀態頁兩個區塊都要顯示）：
	 *   down：{ badge: { text, kind（ok / warn / off）}, text, warn（true = text 用提醒樣式）, rows: [{ label, value }],
	 *           objects: [{ name, at, imported, state, ok }]（共用結果）, skipped: [工作名稱] 或 null（沒有串接時） }
	 *   up：  { badge, text, warn, note, rows, downstreams: [{ fingerprint, address, version, firstSeen, lastSeen, nat }] }
	 */
	function chainView(c, tr, now) {
		var t = typeof tr === 'function' ? tr : function (s) { return s; };
		if (typeof now !== 'number') now = Date.now();
		c = c || {};
		var row = function (rows, label, value) { if (value !== null && value !== undefined && value !== '') rows.push({ label: t(label), value: String(value) }); };
		var errText = function (e) { return CHAIN_ERR[e] ? t(CHAIN_ERR[e]) + '（' + e + '）' : String(e); };

		// 下游角色：這台向上游黑潮拿資料
		var down = { badge: null, text: c.text || t('沒有串接的資料'), warn: false, rows: [], objects: [], skipped: null };
		var keyChanged = !!(c.upstream && c.upstream.keyChangedAt && now - c.upstream.keyChangedAt < DAY_MS);
		if (c.enabled === false) down.badge = { text: t('已關閉'), kind: 'off' };
		else if (c.state === 'chained') down.badge = c.backupActive ? { text: t('串接中（暫時用自己的上游）'), kind: 'warn' } : { text: t('串接中'), kind: 'ok' };
		else if (c.state === 'detected' || c.state === 'verifying') down.badge = { text: t('驗證中'), kind: 'warn' };
		else if (c.state === 'released') down.badge = { text: t('沒有串接'), kind: CHAIN_CALM[c.reason] ? 'off' : 'warn' };
		else down.badge = { text: t('沒有偵測到'), kind: 'off' };
		// 「會重複使用網路」（上游不提供、自己的 chain 關著）與異常都用提醒樣式，整句照 API 原樣顯示
		down.warn = down.badge.kind === 'warn' || keyChanged || /重複/.test(down.text);
		var u = c.upstream;
		if (u) {
			row(down.rows, '上游位址', u.address ? u.address + (u.via === 'intercept' ? t('（經攔截）') : '') + (u.proto ? ' · ' + String(u.proto).toUpperCase() : '') : null);
			row(down.rows, '上游版本', u.version ? t('黑潮') + ' ' + u.version : null);
			row(down.rows, '上游指紋', u.fingerprint);
			if (keyChanged) row(down.rows, '換過的舊指紋', (u.previousFingerprint || '?') + format(t('（%s 換過）'), [fmtTime(u.keyChangedAt)]));
			if (c.state === 'chained') {
				row(down.rows, '串接層數', format(t('%d 層（上限 4 層）'), [u.depth || 2]));
				if (u.viaNat) row(down.rows, '經 NAT', t('是：上游看到的是另一台 NAT 的位址'));
				row(down.rows, '串接開始', u.since ? fmtTime(u.since) : null);
				row(down.rows, '上游最後確認（心跳）', u.lastOkAt ? fmtTime(u.lastOkAt, 'sec') : null);
			}
			if (u.failures) row(down.rows, '連續失敗', format(t('%d 次'), [u.failures]));
			var r = u.registered;
			if (r) row(down.rows, '向上游登記', r.ok ? format(t('已登記 %d 個主機名稱，到期 %s'), [r.names || 0, fmtTime(r.expiresAt)])
				: t('登記失敗') + (r.error ? '：' + r.error : ''));
		}
		if (c.backupActive) row(down.rows, '目前的上游', t('暫時用自己的加密上游'));
		if (c.retryAt) row(down.rows, '下次重試', fmtTime(c.retryAt, 'sec'));
		var sh = c.shared;
		if (sh) {
			row(down.rows, '共用結果上次同步', sh.lastSyncAt ? fmtTime(sh.lastSyncAt) + (sh.error ? ' · ' + errText(sh.error) : '') : (sh.error ? errText(sh.error) : t('還沒同步')));
			row(down.rows, '共用結果下次同步', sh.nextSyncAt ? fmtTime(sh.nextSyncAt) : null);
			down.objects = (sh.objects || []).map(function (o) {
				return {
					name: (CHAIN_KIND[o.kind] ? t(CHAIN_KIND[o.kind]) : o.kind) + (o.name ? ' ' + o.name : ''),
					at: fmtTime(o.at), imported: fmtTime(o.importedAt),
					state: o.error ? t('沒有匯入') + '：' + errText(o.error) : o.fresh ? t('新鮮') : t('過期（照排程自己做）'),
					ok: !!o.fresh && !o.error
				};
			});
			down.skipped = (sh.skippedJobs || []).map(function (j) { return CHAIN_JOB[j] ? t(CHAIN_JOB[j]) : j; });
		}

		// 上游角色：這台提供資料給下游黑潮
		var s = c.serving;
		var up = { badge: { text: t('沒有資料'), kind: 'off' }, text: t('還沒有上游角色的資料（服務啟動中）'), warn: false, note: null, rows: [], downstreams: [] };
		if (s) {
			var ds = s.downstreams || [];
			up.text = s.text || '';
			up.note = s.allowDownstream ? (s.note || null) : null;
			up.warn = !s.allowDownstream;
			up.badge = s.allowDownstream ? { text: ds.length ? format(t('提供中（%d 台）'), [ds.length]) : t('提供中'), kind: 'ok' } : { text: t('不提供'), kind: 'off' };
			// 節點金鑰第一次需要時才建立（有下游來問、或社群用到）：還沒有時指紋是 null
			row(up.rows, '這台的指紋', s.fingerprint || t('還沒有節點金鑰（第一次需要時才建立）'));
			row(up.rows, '節點 ID', s.nodeId);
			var sc = s.share;
			if (s.allowDownstream && sc) {
				row(up.rows, '共用結果', sc.ready ? format(t('已準備好（快取 %s）'), [fmtBytes(sc.cacheBytes || 0)]) : t('還沒準備好（這台還沒有評測結果或節點池）'));
				if (sc.requests) row(up.rows, '下游拿過', format(t('%d 次'), [sc.requests]) + (sc.lastAt ? format(t('，最近 %s'), [fmtTime(sc.lastAt)]) : ''));
			}
			var pr = s.probes;
			if (pr && (pr.count24h || !s.allowDownstream)) row(up.rows, '24 小時內來問過的下游', format(t('%d 次'), [pr.count24h || 0]) + (pr.lastAt ? format(t('，最近 %s'), [fmtTime(pr.lastAt)]) : ''));
			var rf = s.refused || {};
			var refused = [];
			if (rf.rate) refused.push(format(t('太頻繁 %d'), [rf.rate]));
			if (rf.notPrivate) refused.push(format(t('不是區網來源 %d'), [rf.notPrivate]));
			if (rf.notAllowed) refused.push(format(t('沒有開放 %d'), [rf.notAllowed]));
			row(up.rows, '拒絕的串接查詢', refused.join('、'));
			up.downstreams = ds.map(function (d) {
				return { fingerprint: d.fingerprint || '-', address: d.address || '-', version: d.version || '-',
					firstSeen: fmtTime(d.firstSeen), lastSeen: fmtTime(d.lastSeen), nat: d.viaNat ? t('經 NAT') : '' };
			});
		}
		return { down: down, up: up };
	}

	/**
	 * 每日評測的對照組（/api/benchmark 的 protected[]，3.5.0）→ 一行摘要：
	 * 「對照組 44 台：判出 30、沒判出 2、沒測到 12；回歸 0」。沒有對照組（空的、舊版沒有這個欄位）回 null。
	 * result：detected（判出過濾）、passed（沒判出）、untested（沒測到）；regress = true 是以前判得出、今天沒判出
	 */
	function controlSummary(list, tr) {
		var t = typeof tr === 'function' ? tr : function (s) { return s; };
		if (!list || !list.length) return null;
		var n = { detected: 0, passed: 0, untested: 0 }, reg = 0;
		list.forEach(function (c) {
			if (c && n.hasOwnProperty(c.result)) n[c.result]++;
			if (c && c.regress === true) reg++;
		});
		return format(t('對照組 %d 台：判出 %d、沒判出 %d、沒測到 %d；回歸 %d'), [list.length, n.detected, n.passed, n.untested, reg]);
	}

	/**
	 * 每日評測測了哪些（/api/benchmark 的 tiers、probe，3.5.0）→ 一行摘要；舊版沒有 tiers 回 null。
	 *   tiers.mode = 'a'：小機器的減量，只測 A 級加少數 B 級；'ab'：全部都測
	 *   probe.malware.state：ok（有判斷）、invalid／fuse／no-reference（今天失效，沒拿來判斷）、off／empty（沒有跑，不顯示）
	 */
	function benchScope(b, tr) {
		var t = typeof tr === 'function' ? tr : function (s) { return s; };
		var ti = b && b.tiers;
		if (!ti || !ti.mode) return null;
		var n = function (v) { return typeof v === 'number' ? v : 0; };
		var out = ti.mode === 'a'
			? format(t('評測範圍：只測 A 級（A 級 %d、依歷史拉上來的 B 級 %d、沿用 %d、補位 %d、探索 %d；其餘 B 級 %d 個今天不測）'),
				[n(ti.a), n(ti.promoted) + n(ti.trial), n(ti.incumbent), n(ti.fill), n(ti.explore), n(ti.skippedB)])
			: t('評測範圍：全部都測');
		var m = b.probe && b.probe.malware;
		if (m && m.state === 'ok') out += format(t('；惡意網站探測：%d 台有擋（不選）'), [n(m.blockedBy)]);
		else if (m && (m.state === 'invalid' || m.state === 'fuse' || m.state === 'no-reference')) out += t('；惡意網站探測今天失效，沒有拿來判斷');
		return out;
	}

	/**
	 * 上游的地區（/api/upstreams、/api/status 的 upstreams[]，或 upstreams.json 的 selected[]；3.5.0）→ 顯示文字。
	 * 評測用 ip-api 查到的國別是 IP 的「註冊地」，任播的公共 DNS 在東京的節點也會標成 GB、AU，所以不寫成實際位置：
	 *   regionSource = 'tw-net'（位址在台灣網段）：「台灣」
	 *   註冊地、near：「鄰近（註冊地 GB）」；註冊地、不 near：「註冊地 GB」
	 *   沒有國別：near 是「鄰近」，否則 ''（不顯示）
	 * 沒有 regionSource（舊版）一律當註冊地。跟 data/dashboard/dashboard.js 的 KuroshioDashboard.regionLabel 同一份規則
	 */
	function regionLabel(u, tr) {
		var t = typeof tr === 'function' ? tr : function (s) { return s; };
		if (!u) return '';
		var region = u.region ? String(u.region) : '', near = u.near === true;
		if (region && u.regionSource === 'tw-net') return t('台灣');
		if (region) return format(t(near ? '鄰近（註冊地 %s）' : '註冊地 %s'), [region]);
		return near ? t('鄰近') : '';
	}

	var core = {
		fmtTime: fmtTime,
		fmtBytes: fmtBytes,
		certCovers: certCovers,
		format: format,
		restorePlan: restorePlan,
		restoreSummary: restoreSummary,
		chainView: chainView,
		controlSummary: controlSummary,
		benchScope: benchScope,
		regionLabel: regionLabel
	};

	if (root) root.KuroshioUiCore = core;
	if (typeof module === 'object' && module.exports) module.exports = core;
})(typeof window !== 'undefined' ? window : (typeof self !== 'undefined' ? self : null));
