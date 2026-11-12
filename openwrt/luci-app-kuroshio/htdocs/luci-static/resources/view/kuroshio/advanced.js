'use strict';
'require view';
'require form';
'require fs';
'require rpc';
'require ui';
'require kuroshio.common as common';

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

function fmtTime(ms) {
	return ms ? new Date(ms).toLocaleString('zh-TW', { hour12: false }) : '-';
}

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

return view.extend({
	load: function() {
		return Promise.all([common.loadDefaults()].concat(FILES.map(function(f) {
			return L.resolveDefault(fs.read(path(f[0])), '');
		})));
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

		s = m.section(form.NamedSection, 'iprank', 'iprank', _('IP 測速'), _('以 TCP 連線測量每個 IP 的延遲。'));
		num('port', _('測速埠號'), 'iprank.port', null, 'port');
		num('timeout_ms', _('逾時（毫秒）'), 'iprank.timeoutMs');
		num('ok_ttl_sec', _('成功結果保留（秒）'), 'iprank.okTtlSec');
		num('fail_ttl_sec', _('失敗結果保留（秒）'), 'iprank.failTtlSec');
		num('concurrency', _('同時測速數'), 'iprank.concurrency');

		// ---------------- 排程 ----------------
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
		num('min_auto', _('至少選幾台'), 'benchmark.minAuto');
		num('max_avg_latency_ms', _('平均延遲上限（毫秒）'), 'benchmark.maxAvgLatencyMs');
		num('keep_days', _('報表保留天數'), 'benchmark.keepDays');

		s = m.section(form.NamedSection, 'scan', 'scan', _('CDN 網段掃描'));
		num('samples_per_subnet', _('每個 /24 抽樣幾個 IP'), 'scan.samplesPerSubnet');
		num('concurrency', _('同時連線數'), 'scan.concurrency');
		num('timeout_ms', _('逾時（毫秒）'), 'scan.timeoutMs');

		s = m.section(form.NamedSection, 'pool', 'pool', _('節點池建立'));
		num('candidates_per_provider', _('每家 CDN 候選 IP 數'), 'pool.candidatesPerProvider');
		num('pool_size', _('節點池大小'), 'pool.poolSize');
		num('speed_top', _('取前幾名測下載速度'), 'pool.speedTop');
		num('speed_seconds', _('每次下載測速秒數'), 'pool.speedSeconds');

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
