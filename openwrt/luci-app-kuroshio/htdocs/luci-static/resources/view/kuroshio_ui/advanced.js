'use strict';
'require view';
'require form';
'require fs';
'require rpc';
'require ui';
'require kuroshio.ui as common';

var BENCH = '/etc/kuroshio/benchmark/';
// 這些檔案只放「自己加的」：程式附帶的預設名單（/usr/share/kuroshio/benchmark）每次評測都會自動一起測，升級套件就更新
var MINE = _('只放自己要加的；程式附帶的預設名單會自動一起測，升級時更新。');
var FILES = [
	['iplist.txt', _('一般 DNS 候選名單'), _('一行一個 IP。') + MINE],
	['dohlist.txt', _('DoH 候選名單'), _('一行一個 https:// 網址（每一個也會自動用 HTTP/3 測）。') + MINE],
	['dotlist.txt', _('DoT 候選名單'), _('一行一個 tls://主機[:埠]。') + MINE],
	['doqlist.txt', _('DoQ 候選名單'), _('一行一個 quic://主機[:埠]。') + MINE],
	['web.txt', _('評測用網域'), _('用來判斷各 DNS 速度、汙染、封殺的網域。') + MINE],
	['blacklist.txt', _('自己加的淘汰名單'), _('不想讓評測使用的 DNS，一行一個。')],
	['/etc/kuroshio/state/blacklist.txt', _('評測自動淘汰的 DNS'), _('每一筆都實際驗證過：回答的 IP 用網域檢查憑證不符，或連續 3 天無法驗證。刪掉那行即可恢復。')]
];
var path = function(f) { return f.charAt(0) === '/' ? f : BENCH + f; };

// ---------------- 備份與分享 ----------------
var BACKUP_OUT = '/tmp/kuroshio-backup.kuroshio';
var BACKUP_IN = '/tmp/kuroshio-import.kuroshio';
var callExport = rpc.declare({ object: 'kuroshio', method: 'backup_export', params: ['kind'] });
var callImport = rpc.declare({ object: 'kuroshio', method: 'backup_import' });

/** 文字一律用 textContent（核心回傳的字串不當成 HTML） */
function T(tag, attrs, text) {
	var n = E(tag, attrs || {});
	n.textContent = (text == null) ? '' : String(text);
	return n;
}

function fmtTime(ms) { return common.time(ms); }

/** 匯入結果：一類一行 */
function reportLines(r) {
	var words = [['added', _('新增')], ['updated', _('更新')], ['kept', _('保留本機')], ['skipped', _('略過')]];
	return (Array.isArray(r.items) ? r.items : []).map(function(i) {
		var parts = words.filter(function(w) { return i[w[0]] > 0; }).map(function(w) { return w[1] + ' ' + i[w[0]]; });
		return (i.label || i.file) + '：' + (parts.length ? parts.join('、') : _('沒有變動')) +
			(i.note ? '（' + i.note + '）' : '') + (i.error ? '【' + _('錯誤') + '：' + i.error + '】' : '');
	});
}

function previewLine(p) {
	if (!p || !Array.isArray(p.files)) return '';
	return (p.kindLabel || '') + (p.core ? ' · ' + _('黑潮 DNS') + ' ' + p.core : '') + (p.exportedAt ? ' · ' + fmtTime(p.exportedAt) + ' ' + _('匯出') : '') + '：' +
		p.files.map(function(f) { return f.label + ' ' + f.count + ' ' + f.unit; }).join('、');
}

/** 讓瀏覽器下載 rpcd 匯出的檔案，下載後刪掉路由器上的暫存檔（完整備份含私鑰） */
function exportBackup(kind, btn, out) {
	btn.disabled = true;
	out.textContent = _('匯出中…');
	return callExport(kind).then(function(r) {
		if (!r || !r.ok) throw new Error((r && r.error) || _('匯出失敗'));
		return fs.read_direct(BACKUP_OUT, 'blob').then(function(blob) {
			var url = URL.createObjectURL(blob);
			var a = E('a', { 'href': url, 'download': r.name || 'kuroshio.kuroshio', 'style': 'display:none' });
			document.body.appendChild(a);
			a.click();
			window.setTimeout(function() { URL.revokeObjectURL(url); a.remove(); }, 2000);
			out.textContent = _('已下載') + ' ' + (r.name || '') + '（' + Math.ceil((r.size || blob.size) / 1024) + ' KB）';
			return L.resolveDefault(fs.remove(BACKUP_OUT), null);
		});
	}).catch(function(e) {
		out.textContent = '';
		ui.addNotification(null, T('p', {}, _('匯出失敗：') + (e.message || e)), 'danger');
	}).then(function() { btn.disabled = false; });
}

function importBackup(btn, out) {
	btn.disabled = true;
	return ui.uploadFile(BACKUP_IN).then(function() {
		out.textContent = _('匯入中：服務會重新啟動並合併資料，約需幾秒…');
		return callImport();
	}).then(function(r) {
		if (!r || r.ok === false) throw new Error((r && r.error) || _('匯入失敗'));
		out.textContent = '';
		if (r.pending) {
			out.textContent = r.note || _('已送出，服務重新啟動後合併');
			return;
		}
		var lines = reportLines(r);
		out.appendChild(T('strong', {}, _('匯入完成')));
		var pv = previewLine(r.preview);
		if (pv) out.appendChild(T('div', { 'style': 'opacity:.8' }, pv));
		out.appendChild(T('pre', { 'style': 'white-space:pre-wrap;font-size:12px' }, lines.join('\n')));
		ui.addNotification(null, T('p', {}, _('匯入完成')), 'info');
	}).catch(function(e) {
		// 使用者在上傳視窗按取消：不顯示錯誤
		if (e && /cancel/i.test(e.message || '')) { out.textContent = ''; return; }
		out.textContent = '';
		ui.addNotification(null, T('p', {}, _('匯入失敗：') + ((e && e.message) || e)), 'danger');
	}).then(function() { btn.disabled = false; });
}

/** 「備份與分享」：簡易、專業模式都顯示 */
function backupSection() {
	var out = E('div', { 'style': 'margin-top:.6em' });
	var btn = function(label, cls, fn) {
		var b = T('button', { 'class': 'btn cbi-button ' + cls }, label);
		b.addEventListener('click', function(ev) { ev.preventDefault(); fn(b); });
		return b;
	};
	return E('div', { 'class': 'cbi-section kuroshio-sec', 'id': 'kuroshio-backup' }, [
		T('h3', {}, _('備份與分享')),
		T('p', { 'class': 'cbi-section-descr' }, _('換路由器時把累積的學習資料帶過去，或分享給朋友手動匯入。匯入是「合併」：本機比較新的資料會留著，不會被蓋掉。')),
		E('ul', { 'style': 'margin:.4em 0 .8em 1.2em;list-style:disc' }, [
			E('li', {}, [T('strong', {}, _('完整備份')), T('span', {}, _('：全部學習資料、自訂規則、社群身分與好友。含私鑰，請自己保管，不要給別人。'))]),
			E('li', {}, [T('strong', {}, _('分享給朋友')), T('span', {}, _('：CDN 網域驗證紀錄（只有網域名稱與驗證結果，不含查詢次數與時間）、台灣節點池（匯入的一方只當候選，本機驗證通過才使用）。上游評測與黑名單由每台機器自己判定，不放進分享檔。沒有身分、金鑰、統計與自訂規則。'))])
		]),
		E('div', { 'style': 'display:flex;gap:.5em;flex-wrap:wrap;align-items:center' }, [
			btn(_('下載完整備份'), 'cbi-button-action', function(b) { return exportBackup('full', b, out); }),
			btn(_('下載分享檔'), '', function(b) { return exportBackup('share', b, out); }),
			btn(_('匯入 .kuroshio 檔…'), 'cbi-button-apply', function(b) { return importBackup(b, out); })
		]),
		out
	]);
}

var WEEKDAYS = [_('週日'), _('週一'), _('週二'), _('週三'), _('週四'), _('週五'), _('週六')];
var JOBS = {
	dns_benchmark: _('DNS 評測（選出最佳上游組合、剔除汙染）'),
	cdn_ranges: _('抓 CDN 官方 IP 範圍'),
	cdn_scan: _('CDN 網段分類（台灣 / 國外 / 失效）'),
	cdn_pool: _('重建台灣節點池（延遲、掉包、下載速度）')
};

// 瀏覽器快取：LuCI 用固定的 ?v=（LuCI 本身的版本）載入外掛的檔案，升級黑潮之後瀏覽器可能還拿到舊的 common.js，
// 新功能就會按了沒反應。版本對不上時重新下載本外掛的所有檔案（更新瀏覽器快取）再重新整理一次；還是對不上就提示
var BUILD = '3.5.0';
if (common.build !== BUILD) (function() {
	var key = 'kuroshio-ui-refresh-' + BUILD;
	var v = L.env.resource_version ? '?v=' + L.env.resource_version : '';
	var files = ['kuroshio/ui', 'view/kuroshio_ui/access', 'view/kuroshio_ui/advanced', 'view/kuroshio_ui/cdn', 'view/kuroshio_ui/community', 'view/kuroshio_ui/dashboard', 'view/kuroshio_ui/filter', 'view/kuroshio_ui/log', 'view/kuroshio_ui/settings', 'view/kuroshio_ui/status'];
	var tried = false;
	try { tried = !!window.sessionStorage.getItem(key); window.sessionStorage.setItem(key, '1'); } catch (e) {}
	if (!tried && window.fetch)
		// kuroshio/ui-core.js（共用邏輯）由 kuroshio/ui.js 用 ?v=BUILD 載入，一起更新
		Promise.all(files.map(function(f) { return L.env.base_url + '/' + f + '.js' + v; }).concat([L.env.base_url + '/kuroshio/ui-core.js?v=' + BUILD])
			.map(function(u) { return fetch(u, { cache: 'reload' }).catch(function() {}); }))
			.then(function() { window.location.reload(); });
	else
		ui.addNotification(null, E('p', {}, _('瀏覽器還在用舊版黑潮 DNS 的介面檔案（快取），部分功能可能沒有反應。請清除這個網站的瀏覽資料，或改用無痕視窗開啟。')), 'warning');
})();

return view.extend({
	load: function() {
		// 最後一個是 common.ready（共用邏輯 ui-core.js 載入完成），render 前拿掉
		return Promise.all([common.loadDefaults()].concat(FILES.map(function(f) {
			return L.resolveDefault(fs.read(path(f[0])), '');
		}), [common.ready])).then(function(r) { return r.slice(0, -1); });
	},

	render: function(data) {
		var files = data.slice(1);
		var m, s, o;
		var num = function(name, title, path, desc, dt) { return common.num(s, null, name, title, path, desc, dt); };

		if (!common.isPro()) {
			return E([], [
				common.modeBar(),
				E('div', { 'class': 'cbi-section kuroshio-sec' }, [
					E('h2', {}, _('黑潮 DNS · 進階')),
					E('p', {}, _('這裡是上游、解析時間、測速、排程與評測的細部參數。為了避免誤改，請先切換到「專業」模式。'))
				]),
				backupSection(),
				common.footer()
			]);
		}

		m = new form.Map('kuroshio', _('黑潮 DNS · 進階'), _('空白欄位使用程式內建預設值（顯示在欄位裡）。'));

		// ---------------- 上游 ----------------
		s = m.section(form.NamedSection, 'upstream', 'upstream', _('上游 DNS'),
			_('格式：udp://IP、tcp://IP、tls://主機、https://主機/dns-query。每日評測會自動選出最佳組合，以下是固定參與與備援。'));
		o = s.option(form.DynamicList, 'pinned', _('固定上游'), _('每次查詢都參與、不會被評測淘汰。不要填路由器自己。'));
		o = s.option(form.DynamicList, 'fallback', _('備援'), _('固定與自動上游都失敗時才用。'));
		o = s.option(form.DynamicList, 'bootstrap', _('Bootstrap'), _('解析 DoH / DoT 上游主機名稱用，只能填 IP。'));
		o.datatype = 'ipaddr';
		o = s.option(form.DynamicList, 'last_resort', _('最後手段'), _('所有上游都沒回應時。'));
		num('auto_max', _('自動上游最多幾台'), 'upstream.autoMax');
		o = s.option(form.MultiValue, 'auto_type', _('自動上游可用協定'));
		o.value('udp', 'UDP');
		o.value('doh', 'DoH');
		o.value('dot', 'DoT');
		// 上游成敗照整輪判斷（3.5.0 F4）
		common.flag(s, null, 'round_aware_failures', _('上游成敗照整輪判斷'), 'upstream.roundAwareFailures',
			_('別的上游先答完、這台還沒回來就被取消的（來不及），也記下來：沒有延遲紀錄的不再永遠排第一，連續 8 次都來不及、而且沒成功過才算 1 次失敗。大家都答不出來的那一輪（網域本身壞掉、整台斷網）不算個別上游失敗；SERVFAIL 另外計。關掉＝3.4.x 的記法。'));
		// 路徑檢查（3.3.6）
		common.flag(s, null, 'path_check', _('路徑檢查'), 'upstream.pathCheck',
			_('啟動後、每 6 小時、WAN 變動時檢查路上有沒有人動手腳：一般 DNS 被接走（上游路由器、業者）、「不存在」被改成廣告頁、加密協定被擋、TLS 中途攔截、IPv6 能不能用。評測與上游選擇照結果調整。'));
		o = s.option(form.ListValue, 'intercept_policy', _('一般 DNS 被接走時'),
			_('路上有人把 53 埠接走時，一般 DNS 的答案其實都是攔截者給的。'));
		o.value('skip-plain', _('評測不測一般 DNS（建議）'));
		o.value('warn', _('只提醒，照常測'));
		o.value('ignore', _('不理會'));
		o.default = 'skip-plain';
		// 串接（3.4.0）：只有這兩個開關，預設都開；兩邊都開才通訊
		common.flag(s, null, 'chain', _('串接上游的黑潮'), 'upstream.chain',
			_('辨識上游的黑潮並自動串接：直接用它的評測結果與 CDN 節點池（過濾清單由這台自己下載）。關閉時把上游黑潮當成一般的 DNS 攔截（跟 3.3.7 的「一般 DNS 被接走的網路」一樣），這台會自己重做評測、CDN 掃描、下載清單，重複使用網路。路徑檢查關閉時也不會串接。'));
		common.flag(s, null, 'allow_downstream', _('提供資料給下游的黑潮'), 'upstream.allowDownstream',
			_('提供資料給接在後面的黑潮（串接、評測結果、CDN 節點池，並放行它解析自己的上游）。關閉時仍然回答「我是黑潮」，但下游會自己重做評測、CDN 掃描、下載清單，重複浪費網路資源（含這台的頻寬）。開著時區網裡任何會講這個協定的裝置都拿得到；有啟用「繞過防護」清單、要管住區網裝置的環境請關閉。'));
		o = s.option(form.ListValue, 'ipv6', _('用 IPv6 連上游'),
			_('自動：依這台的 IPv6 路由判斷，連線遇到「沒有路由」會暫停 IPv6 10 分鐘。路由器的 IPv6 關閉時可以選「不用」。'));
		o.value('auto', _('自動'));
		o.value('1', _('使用'));
		o.value('0', _('不用'));
		o.default = 'auto';

		// ---------------- 解析 ----------------
		s = m.section(form.NamedSection, 'resolver', 'resolver', _('解析行為'));
		num('timeout_ms', _('上游逾時（毫秒）'), 'resolver.timeoutMs');
		num('collect_window_ms', _('收集其他上游答案的時間（毫秒）'), 'resolver.collectWindowMs', _('第一個回應之後再等多久，用來合併 IP 測速。'));
		common.flag(s, null, 'fast_path', _('先回第一個正常回應'), 'resolver.fastPath');
		num('fast_path_ttl', _('快速回應的 TTL（秒）'), 'resolver.fastPathTtl', _('測速排序完成後，下一次查詢就拿到最佳 IP。'));
		common.flag(s, null, 'rank_ips', _('合併所有上游 IP 並測速排序'), 'resolver.rankIps');
		num('max_ips', _('每個回應最多幾個 IP'), 'resolver.maxIps');
		num('max_ttl', _('TTL 上限（秒）'), 'resolver.maxTtl');
		num('min_ttl', _('TTL 下限（秒）'), 'resolver.minTtl');
		num('negative_max_ttl', _('不存在網域的 TTL 上限（秒）'), 'resolver.negativeMaxTtl');
		num('serve_stale_sec', _('過期後仍可先回舊資料（秒）'), 'resolver.serveStaleSec');
		num('prefetch_threshold_sec', _('剩餘 TTL 低於幾秒就預取'), 'resolver.prefetchThresholdSec');
		num('prefetch_recent_sec', _('最近幾秒內有人查才預取'), 'resolver.prefetchRecentSec');
		num('cache_max', _('快取筆數上限'), 'resolver.cacheMax');
		common.flag(s, null, 'send_ecs', _('對上游附帶 ECS（本機對外 IP 的 /24）'), 'resolver.sendEcs');
		common.flag(s, null, 'android_probe_fast', _('Android 私人 DNS 驗證查詢立即回覆'), 'resolver.androidProbeFast');
		// 背景補問（3.4.0）
		o = s.option(form.ListValue, 'backfill', _('背景補問'),
			_('只同時問最快幾台上游時（同時問幾個上游有限制），CDN 相關的查詢與抽樣的查詢在回答之後，於背景再問這次沒問到的上游，合併節點與比對汙染。不增加回答的等待。'));
		o.value('cdn', _('CDN 相關與抽樣（建議）'));
		o.value('off', _('不補問（3.3.7 的行為）'));
		o.default = 'cdn';
		num('backfill_sample', _('非 CDN 查詢每幾次抽一次補問'), 'resolver.backfillSample', _('0 = 不抽樣（CDN 相關的照樣補問）。'));

		s = m.section(form.NamedSection, 'iprank', 'iprank', _('IP 測速'), _('以 TCP 連線測量每個 IP 的延遲。'));
		num('port', _('測速埠號'), 'iprank.port', null, 'port');
		num('timeout_ms', _('逾時（毫秒）'), 'iprank.timeoutMs');
		num('ok_ttl_sec', _('成功結果保留（秒）'), 'iprank.okTtlSec');
		num('fail_ttl_sec', _('失敗結果保留（秒）'), 'iprank.failTtlSec');
		num('concurrency', _('同時測速數'), 'iprank.concurrency');

		// ---------------- 排程 ----------------
		s = m.section(form.NamedSection, 'main', 'kuroshio', _('補跑時段'));
		o = s.option(form.Value, 'catchup_window', _('補跑只在這段時間'),
			_('台北時間，例如 01:00-06:00（可以跨午夜）。剛刷機、學習資料不見、或很久沒跑時的補跑（DNS 評測、CDN 掃描等）只在這段時間進行，期間先用預設上游；排定時間與手動執行不受影響。空白 = 開機後幾分鐘就補跑。'));
		o.placeholder = '01:00-06:00';
		o.rmempty = true;
		o.validate = function(id, v) { return !v || /^([01]\d|2[0-3]):[0-5]\d-([01]\d|2[0-3]):[0-5]\d$/.test(v) || _('格式：HH:MM-HH:MM'); };

		s = m.section(form.GridSection, 'job', _('排程工作（台北時間）'), _('到時間以獨立程序在背景執行，不影響 DNS 回應。路由器在排定時間沒開機，下次啟動會自動補跑。'));
		s.anonymous = false;
		s.addremove = false;
		s.sectiontitle = function(sid) { return JOBS[sid] || sid; };
		o = s.option(form.Flag, 'enabled', _('啟用'));
		o.default = '1';
		o.rmempty = false;
		o.editable = true;
		o = s.option(form.DynamicList, 'at', _('時間'), _('HH:MM，可以多個'));
		o.validate = function(id, v) { return !v || /^([01]\d|2[0-3]):[0-5]\d$/.test(v) || _('格式：HH:MM'); };
		o.textvalue = function(sid) { return [].concat(this.cfgvalue(sid) || []).join(', '); };
		o = s.option(form.MultiValue, 'weekday', _('星期'), _('都不選 = 每天'));
		WEEKDAYS.forEach(function(w, i) { o.value(String(i), w); });
		o.textvalue = function(sid) {
			var v = [].concat(this.cfgvalue(sid) || []);
			return v.length ? v.map(function(i) { return WEEKDAYS[+i]; }).join(' ') : _('每天');
		};
		o = s.option(form.Value, 'start_delay_sec', _('補跑延遲（秒）'));
		o.datatype = 'uinteger';
		o.modalonly = true;
		o = s.option(form.Value, 'timeout_min', _('逾時（分鐘）'));
		o.datatype = 'uinteger';
		o.modalonly = true;

		// ---------------- 評測參數 ----------------
		s = m.section(form.NamedSection, 'benchmark', 'benchmark', _('每日 DNS 評測'));
		num('concurrency', _('同時測試數'), 'benchmark.concurrency');
		num('timeout_ms', _('逾時（毫秒）'), 'benchmark.timeoutMs');
		num('max_timeouts', _('容許逾時次數'), 'benchmark.maxTimeouts');
		num('coverage_target', _('涵蓋率目標'), 'benchmark.coverageTarget', _('0.97 = 97%'), 'ufloat');
		// 上游多樣性（3.4.0）
		o = s.option(form.ListValue, 'coverage_region', _('覆蓋上游的範圍'),
			_('鄰近優先：選「覆蓋」上游時先選鄰近的（台灣、日本、香港、新加坡，或延遲低的任播上游），CDN 才比較會回亞洲的節點；還有名額才選其他的。'));
		o.value('near', _('鄰近優先（建議）'));
		o.value('any', _('不分遠近（3.3.7 的行為）'));
		o.default = 'near';
		// 分級評測（3.5.0）
		o = s.option(form.ListValue, 'tiers', _('評測範圍'),
			_('預設名單分成 A 級（經營者明確的公共 DNS、電信商）與 B 級（品質都過、經營者看不出來）。只用 A 級：只測、只選 A 級與自己加的上游，B 級一個都不測，連前一天選上的 B 級也不用；介意 B 級的人選這個（A 級的經營者或類型不夠時只在 judge.log 寫明，不從 B 級補）。自動：記憶體小於 256 MB 時減量（A 級為主，B 級只測前一天選上的、補位最多 32 個與輪流探索 40 個，B 級仍可能選上），其他全部都測。'));
		o.value('auto', _('自動（依記憶體）'));
		o.value('a', _('只用 A 級（B 級不測、不選）'));
		o.value('ab', _('全部都測'));
		o.default = 'auto';
		// 惡意網站探測（3.5.0）
		o = s.option(form.Flag, 'malware_probe', _('惡意網站探測'),
			_('評測時用探測網域判出「有擋惡意網站的 DNS」，這類不選來用（不記可疑、不進黑名單）。探測網域是 probe.txt（手動指定，可以留空）加上從這台已下載的惡意類清單抽樣的。評測只做 DNS 查詢、不連線；但抽到的是還在活動的惡意網域，線路上的資安設備可能把這台記成「有裝置中毒」（每天十幾個查詢）。企業或學校網路建議關掉。'));
		o.default = '1';
		o.rmempty = false;
		// 探測網域從已下載的清單抽樣（3.5.0 F10）
		o = common.flag(s, null, 'probe_sample', _('探測網域從已下載的清單抽樣'), 'benchmark.probeSample',
			_('每次評測前從這台已經下載的惡意類過濾清單（本機副本）抽 40 個網域，先確認還解析得到（留最多 20 個），再跟 probe.txt 合併；有回答的至少 6 個、擋了一半以上才算有擋。TW165、TWNIC-RPZ、新註冊網域不抽。記憶體吃緊、清單停用中、沒有本機副本時這次不抽（不為了抽樣多下載）。關掉＝只用 probe.txt。'));
		o.depends('malware_probe', '1');
		num('near_max_ms', _('鄰近的延遲上限（毫秒）'), 'benchmark.nearMaxMs', _('最低延遲在這以內就算鄰近（不管國別）；台灣、日本、香港、新加坡的上游放寬到兩倍。'));
		num('min_auto', _('至少選幾台'), 'benchmark.minAuto');
		num('max_avg_latency_ms', _('平均延遲上限（毫秒）'), 'benchmark.maxAvgLatencyMs');
		num('keep_days', _('報表保留天數'), 'benchmark.keepDays');

		s = m.section(form.NamedSection, 'scan', 'scan', _('CDN 網段掃描'));
		num('samples_per_subnet', _('每個 /24 抽樣幾個 IP'), 'scan.samplesPerSubnet');
		num('concurrency', _('同時連線數'), 'scan.concurrency');
		num('max_per_sec', _('每秒最多新連線'), 'scan.maxPerSec', _('每秒最多開始幾個探測；預設依 CPU 核心數（每核心 50，50～200），小記憶體減量時再減半。避免一秒上千條新連線塞滿連線追蹤表。'));
		num('timeout_ms', _('逾時（毫秒）'), 'scan.timeoutMs');

		s = m.section(form.NamedSection, 'pool', 'pool', _('節點池建立'));
		num('candidates_per_provider', _('每家 CDN 候選 IP 數'), 'pool.candidatesPerProvider');
		num('pool_size', _('節點池大小'), 'pool.poolSize');
		num('speed_top', _('取前幾名測下載速度'), 'pool.speedTop');
		num('speed_seconds', _('每次下載測速秒數'), 'pool.speedSeconds');
		o = s.option(form.Flag, 'relative_speed', _('測速用相對評分'),
			_('節點慢不慢跟同一家其他節點比（低於中位數的一半才算慢），「幾乎一樣」的範圍依實際傳輸時間決定，速度分不出來的節點由延遲決定名次。關掉＝3.4.x：低於 1 MB/s 算慢、5% 以內才算一樣、直接比速度。'));
		o.default = common.def('pool.relativeSpeed') === false ? '0' : '1';
		o.rmempty = false;

		// ---------------- 評測名單檔案 ----------------
		s = m.section(form.NamedSection, 'benchmark', 'benchmark', _('評測名單'), _('修改後下一次評測生效，可以到狀態頁「立即執行」DNS 評測。'));
		FILES.forEach(function(f, i) {
			var content = files[i] || '';
			o = s.option(form.TextValue, '_file_' + i, f[1], f[2]);
			o.rows = 8;
			o.monospace = true;
			o.wrap = 'off';
			o.cfgvalue = function() { return content; };
			o.write = function(sid, value) {
				value = String(value || '').replace(/\r\n/g, '\n');
				if (value === content) return;
				content = value;
				return fs.write(path(f[0]), value.replace(/\n*$/, '\n'));
			};
			o.remove = function() { return this.write(null, ''); };
		});

		return m.render().then(function(node) { return E([], [common.modeBar(), node, backupSection(), common.footer()]); });
	}
});
