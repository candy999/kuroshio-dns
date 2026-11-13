'use strict';
'require view';
'require poll';
'require rpc';
'require uci';
'require ui';
'require kuroshio.common as common';

var callStatus = rpc.declare({ object: 'kuroshio', method: 'status' });
var callAcmeStatus = rpc.declare({ object: 'kuroshio', method: 'acme_status' });

var MODES = {
	'none': _('不接管'),
	'dnsmasq-upstream': _('作為 dnsmasq 的上游'),
	'redirect': _('重定向 53 埠（基本）'),
	'hijack': _('積極劫持'),
	'exchange': _('取代 dnsmasq（53 埠）')
};
var JOBS = { 'dns-benchmark': _('DNS 評測'), 'cdn-ranges': _('CDN IP 範圍'), 'cdn-scan': _('CDN 網段分類'), 'cdn-pool': _('台灣節點池'), 'tw-ip': _('台灣 IP 清單') };

function fmtNum(n) { return (n == null) ? '-' : Number(n).toLocaleString(); }
function pct(a, b) { return b ? (100 * a / b).toFixed(1) + '%' : '-'; }
function fmtTime(t, mode) { return common.time(t, mode); }
function fmtBytes(b) {
	if (b == null) return '-';
	if (b < 1024) return b + ' B';
	if (b < 1048576) return (b / 1024).toFixed(0) + ' KB';
	return (b / 1048576).toFixed(1) + ' MB';
}
/* 還沒存的時間：0 = 都存了 */
function fmtAge(s) {
	if (s == null) return '-';
	if (s <= 0) return _('全部已存');
	if (s < 3600) return _('%d 分鐘').format(Math.max(1, Math.round(s / 60)));
	return _('%s 小時').format((s / 3600).toFixed(1));
}
function fmtUptime(s) {
	if (s == null) return '-';
	var d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
	return (d ? d + _('天') + ' ' : '') + h + _('小時') + ' ' + m + _('分');
}

/** 表格（外面包一層可以左右捲動的框）；num = 數字欄（靠右） */
function table(head, rows, num) {
	return common.scroll(common.table(head, rows, null, num));
}

function mbOf(kb) { return kb != null ? fmtNum(Math.round(kb / 1024)) : '-'; }

/* 記憶體控制動態決定的大小（規格 09） */
function memSizes(z) {
	if (!z) return '';
	var out = [];
	if (z.cacheEntries != null) out.push(_('快取 %s / %s 筆').format(fmtNum(z.cacheEntries), fmtNum(z.cacheMax)));
	if (z.cdnInRam != null) out.push(_('CDN %s 筆').format(fmtNum(z.cdnInRam)) + (z.cdnOnDiskOnly ? _('（另 %s 筆在 Flash）').format(fmtNum(z.cdnOnDiskOnly)) : ''));
	if (z.filterListRules != null) out.push(_('清單 %s 條').format(fmtNum(z.filterListRules)));
	return out.join(' · ');
}

var tile = function(label, value, sub) { return common.tile(label, value, sub); };

// 瀏覽器快取：LuCI 用固定的 ?v=（LuCI 本身的版本）載入外掛的檔案，升級黑潮之後瀏覽器可能還拿到舊的 common.js，
// 新功能就會按了沒反應。版本對不上時重新下載本外掛的所有檔案（更新瀏覽器快取）再重新整理一次；還是對不上就提示
var BUILD = '3.2.1';
if (common.build !== BUILD) (function() {
	var key = 'kuroshio-ui-refresh-' + BUILD;
	var v = L.env.resource_version ? '?v=' + L.env.resource_version : '';
	var files = ['kuroshio/common', 'view/kuroshio/access', 'view/kuroshio/advanced', 'view/kuroshio/cdn', 'view/kuroshio/community', 'view/kuroshio/dashboard', 'view/kuroshio/filter', 'view/kuroshio/log', 'view/kuroshio/settings', 'view/kuroshio/status'];
	var tried = false;
	try { tried = !!window.sessionStorage.getItem(key); window.sessionStorage.setItem(key, '1'); } catch (e) {}
	if (!tried && window.fetch)
		Promise.all(files.map(function(f) { return fetch(L.env.base_url + '/' + f + '.js' + v, { cache: 'reload' }).catch(function() {}); }))
			.then(function() { window.location.reload(); });
	else
		ui.addNotification(null, E('p', {}, _('瀏覽器還在用舊版黑潮 DNS 的介面檔案（快取），部分功能可能沒有反應。請清除這個網站的瀏覽資料，或改用無痕視窗開啟。')), 'warning');
})();

return view.extend({
	load: function() {
		return Promise.all([uci.load('kuroshio'), L.resolveDefault(callStatus(), {}), L.resolveDefault(callAcmeStatus(), null)]);
	},

	/** 立即儲存學習資料（POST /api/persist/flush）：顯示時間、寫了幾份、多大 */
	flushNow: function() {
		return common.action('/api/persist/flush').then(function(r) {
			var x = common.result(r);
			if (!x || x.ok === false) return common.notify({ ok: false, error: (x && x.error) || (r && r.error) || _('儲存失敗') });
			var at = fmtTime(x.at, 'sec');
			common.notify(r, x.files ? _('已儲存學習資料（%s）：寫了 %d 份快照，共 %s').format(at, x.files, fmtBytes(x.bytes))
				: _('已儲存學習資料（%s）：沒有新的變動，不需要寫入').format(at));
		});
	},

	runJob: function(name) {
		return common.action('/api/jobs/run', { name: name }).then(function(r) { common.notify(r, _('已排入背景執行')); });
	},

	renderBody: function(st, acme) {
		var self = this;
		var enabled = uci.get('kuroshio', 'main', 'enabled') === '1';
		var mode = uci.get('kuroshio', 'main', 'redirect') || 'dnsmasq-upstream';
		var api = st && st.api && st.api.ok ? st.api.result : null;

		var head = common.section(_('服務'), [
			E('p', {}, [
				common.badge(st && st.running ? _('執行中') : (enabled ? _('未執行（請看日誌）') : _('已停用')), st && st.running ? 'ok' : (enabled ? 'err' : 'off')),
				' · ', _('DNS 接管：'), MODES[mode] || mode,
				api ? ' · ' + _('已執行 ') + fmtUptime(api.stats && api.stats.uptimeSec) : ''
			])
		]);
		if (!api) return E([], [head]);

		var d = (api.stats && api.stats.today) || {};
		var q = d.query || 0;
		var cdn = (api.cdn && api.cdn.stats) || {};
		var routeAcc = 0, routeN = 0;
		Object.keys(d.route || {}).forEach(function(k) { routeAcc += d.route[k].acc || 0; routeN += d.route[k].n || 0; });

		var tiles = common.section(_('今天'), [
			common.tiles([
				tile(_('查詢'), fmtNum(q), _('快取命中 ') + pct(d.hit || 0, q)),
				tile(_('攔截'), fmtNum(d.blocked), _('廣告 %s · 遙測 %s · 惡意 %s').format(fmtNum(d.blockedAds), fmtNum(d.blockedTelemetry), fmtNum(d.blockedMalware))),
				tile(_('拉回台灣'), fmtNum(routeAcc), _('CDN 連線的 ') + pct(routeAcc, routeN)),
				tile(_('CDN 置換'), fmtNum(cdn.rewrites), _('ECS %s · 跨 CDN %s').format(fmtNum(cdn.ecsRewrites), fmtNum(cdn.crossRewrites))),
				tile(_('快取筆數'), fmtNum(api.cacheEntries), _('CDN 網域庫 ') + fmtNum(api.cdn && api.cdn.domains)),
				tile(_('過濾規則'), fmtNum(api.filter && (api.filter.lists + api.filter.custom)), _('自訂 ') + fmtNum(api.filter && api.filter.custom))
			])
		]);

		// 硬體與效能（3.0）
		var sys = api.system || {}, per = sys.persist || {}, lat = d.latency || {}, ls = api.listeners || {}, mem = sys.memory || {};
		var ms = function(x) { return x && x.p50 != null ? x.p50 + ' / ' + (x.p95 != null ? x.p95 : '>1000') + ' ms' : '-'; };
		var protos = ['doh', 'doh3', 'dot', 'doq'].filter(function(k) { return ls[k]; }).map(function(k) { return { doh: 'DoH', doh3: 'DoH3', dot: 'DoT', doq: 'DoQ' }[k] + ':' + ls[k]; });
		var hw = common.section(_('硬體與效能'), [
			common.tiles([
				tile(_('硬體'), (sys.memTotalMB ? sys.memTotalMB + ' MB · ' : '') + (sys.cores || '?') + _(' 核'), sys.arch || ''),
				tile(_('系統記憶體'), mem.availKB != null ? _('可用 %s MB').format(mbOf(mem.availKB)) : (sys.memAvailableMB != null ? _('可用 %s MB').format(sys.memAvailableMB) : '-'),
					_('保留 %s MB（%s）').format(mbOf(mem.reserveKB), mem.reserveAuto ? _('自動') : _('設定')) +
					(mem.headroomKB != null ? _(' · 保留以上 %s MB').format(mbOf(mem.headroomKB)) : '') +
					(mem.enabled ? ' · ' + (mem.stateLabel || mem.state) + (mem.growth === false ? _('（不再長大）') : '') : '') +
					(mem.psi ? ' · PSI ' + mem.psi.someAvg10 + '%' : '')),
				tile(_('本程式記憶體'), sys.rssKB ? (sys.rssKB / 1024).toFixed(1) + ' MB' : '-', memSizes(mem.sizes)),
				tile(_('快取命中率'), d.hitRate != null ? d.hitRate + '%' : '-', _('預取 %s · 斷線回舊資料 %s').format(fmtNum(d.prefetch), fmtNum(d.stale))),
				tile(_('回應時間 p50 / p95'), ms(lat.hit), _('問上游 ') + ms(lat.miss)),
				tile(_('Flash 寫入（今天）'), per.bytesToday != null ? (per.bytesToday / 1024).toFixed(0) + ' KB' : '-', (per.storage || '') + _(' · 間隔 ') + (per.effectiveIntervalMin != null ? per.effectiveIntervalMin : (per.intervalMin || '-')) + _(' 分') +
					(per.estimatedDailyBytes != null ? _(' · 預估每天 ') + (per.estimatedDailyBytes / 1024).toFixed(0) + ' KB' : '')),
				tile(_('最久未存'), fmtAge(per.oldestUnsavedSec), (per.maxAgeHours != null ? _('上限 %s 小時').format(per.maxAgeHours) : '') +
					(per.forcedByAge ? _(' · 到期強制寫入 %s 次').format(fmtNum(per.forcedByAge)) : '') + (per.lowSpace ? _(' · 儲存空間不足（只寫核心資料）') : '')),
				per.space && per.space.reserveBytes != null ? tile(_('儲存空間'), per.space.freeBytes != null ? _('可用 %s KB').format(fmtNum(Math.round(per.space.freeBytes / 1024))) : '-',
					_('保留 %s KB（%s）').format(fmtNum(Math.round(per.space.reserveBytes / 1024)), per.space.reserveAuto ? _('自動') : _('設定')) +
					(per.space.optionalBytes ? _(' · 可重建的資料 %s KB').format(fmtNum(Math.round(per.space.optionalBytes / 1024))) : '') +
					(per.space.keepingOptional === false ? _(' · 空間吃緊：只留核心') : '')) : '',
				tile(_('加密協議'), protos.length ? protos.length + _(' 種') : _('未開啟'), protos.join(' · ') + (ls.ddr ? ' · DDR' : '')),
				tile(_('過濾記憶體'), api.filter && api.filter.memoryBytes != null ? (api.filter.memoryBytes / 1048576).toFixed(1) + ' MB' : '-', api.filter && api.filter.domains != null ? fmtNum(api.filter.domains) + _(' 個網域') : '')
			])
		]);

		// 記憶體控制（規格 09）：釋出中的項目、停用中的過濾清單（停用期間少了這些保護，要明顯）
		var shed = mem.shed || [], fl = api.filter || {};
		var memSec = (shed.length || fl.notice || mem.floor) ? common.section(_('記憶體控制'), [
			mem.protectedSuspended ? E('div', { 'class': 'alert-message danger' }, _('記憶體嚴重不足：連保護清單（惡意 / 反詐騙）都暫停了，只剩自訂規則；DNS 照常轉送。記憶體回來後自動恢復。'))
				: (mem.floor ? E('div', { 'class': 'alert-message danger' }, _('記憶體不足：只轉送 DNS（暫停 CDN 調整、快取最小）。記憶體回來後自動恢復。')) : ''),
			fl.notice ? E('div', { 'class': 'alert-message warning' }, fl.notice) : '',
			E('p', {}, _('目前：%s（系統可用 %s MB / 保留 %s MB）').format(mem.stateLabel || mem.state || '-', mbOf(mem.availKB), mbOf(mem.reserveKB)) +
				(mem.waiting ? ' · ' + mem.waiting : '')),
			shed.length ? table([_('已釋出'), _('內容'), _('約'), _('時間')], shed.map(function(x) {
				return [x.label, x.detail || '', (x.freedBytes / 1024).toFixed(0) + ' KB', fmtTime(x.at)];
			}), [2]) : ''
		], { 'id': 'kuroshio-memory' }) : '';

		// 連線來源限制（規格 08）：模式、拒絕次數、資料日期；資料讀不到時不擋，要明顯提醒
		var ac = api.access;
		var accSec = ac ? common.section(_('連線來源'), [
			ac.failOpen ? E('div', { 'class': 'alert-message danger' }, _('台灣 IP 資料讀不到，現在不擋任何來源（封鎖名單照樣有效）') + (ac.warning ? '：' + ac.warning : ''))
				: (ac.warning ? E('div', { 'class': 'alert-message warning' }, ac.warning) : ''),
			E('p', {}, [
				E('strong', {}, { taiwan: _('只開放台灣'), custom: _('自訂 ISP'), open: _('全開放') }[ac.mode] || ac.mode || '-'),
				' · ', _('已拒絕 %s 次（啟動後）').format(fmtNum(ac.denied && ac.denied.total)),
				ac.generatedAt ? ' · ' + _('台灣 IP 資料 %s').format(ac.generatedAt) : '',
				' · ', E('a', { 'href': L.url('admin/services/kuroshio/access') }, _('設定'))
			])
		], { 'id': 'kuroshio-access' }) : '';

		// 加密監聽：每個位址一列，綁定失敗列出原因
		var detail = [].concat(api.listenersDetail || []);
		var lsSec = detail.length ? common.section(_('加密監聽'), [
			common.scroll(common.listenerTable(detail))
		], { 'id': 'kuroshio-listeners' }) : '';

		var ups = (api.upstreams || []).map(function(u) {
			var role = { pinned: _('固定'), auto: _('自動'), fallback: _('備援') }[u.role] || u.role;
			return [u.id, role, fmtNum(u.ok), fmtNum(u.fail), u.avgMs != null ? u.avgMs + ' ms' : '-', u.paused ? _('暫停中') : ''];
		});
		var upSec = common.section(_('上游'), [
			E('p', { 'class': 'cbi-section-descr' }, api.autoUpstreams ? _('自動上游來自 %s 的評測').format(api.autoUpstreams.generatedAt) : _('還沒有每日評測結果，暫時使用固定上游與備援。')),
			table([_('上游'), _('角色'), _('成功'), _('失敗'), _('平均延遲'), ''], ups, [2, 3, 4])
		]);

		var jobs = api.jobs || {};
		var jobRows = Object.keys(jobs.config || {}).map(function(n) {
			var c = jobs.config[n], s = (jobs.state || {})[n] || {};
			var running = jobs.running && jobs.running.name === n;
			return [
				JOBS[n] || n,
				(c.monthDays ? _('每月 %s 日').format([].concat(c.monthDays).join(',')) + (c.jitterDays ? _('起（每台錯開）') : '') + ' ' : '') + [].concat(c.at || []).join(', ') + (c.weekdays ? ' (' + c.weekdays.join(',') + ')' : '') + (c.enabled === false ? ' ' + _('已停用') : ''),
				running ? _('執行中…') : fmtTime(s.lastEnd),
				(jobs.detail && jobs.detail[n] && jobs.detail[n].text) || (s.lastCode === 0 ? _('成功') : (s.lastCode == null ? '-' : _('失敗（%s）').format(s.lastCode))),
				E('button', { 'class': 'btn cbi-button', 'disabled': running ? '' : null, 'click': ui.createHandlerFn(self, 'runJob', n) }, _('立即執行'))
			];
		});
		var jobSec = common.section(_('排程工作'), [table([_('工作'), _('排程'), _('上次結束'), _('結果'), ''], jobRows)]);

		var extra = [];
		if (acme) {
			var c = acme.cert;
			extra.push([_('憑證'), c ? _('%s · 到期 %s（剩 %d 天）').format(c.san || c.subject, c.validTo, c.daysLeft) : (acme.certError || '-')]);
		}
		if (api.ownIp) extra.push([_('網域目前指向'), (api.ownIp.ips || []).join(', ') + (api.ownIp.changedAt ? _('（%s 變更）').format(fmtTime(api.ownIp.changedAt)) : '')]);
		var infoSec = common.section(_('其他'), [table([_('項目'), _('內容')], extra)]);

		var actions = common.section(_('操作'), [
			E('div', { 'class': 'kuroshio-row' }, [
				E('button', { 'class': 'btn cbi-button', 'click': ui.createHandlerFn(self, function() { return common.action('/api/cache/flush').then(function(r) { common.notify(r, _('快取已清除')); }); }) }, _('清除快取')),
				E('button', { 'class': 'btn cbi-button', 'click': ui.createHandlerFn(self, function() { return common.action('/api/filter/update').then(function(r) { common.notify(r, _('已重新下載過濾清單')); }); }) }, _('更新過濾清單')),
				E('button', { 'class': 'btn cbi-button', 'click': ui.createHandlerFn(self, function() { return common.action('/api/ddns/update').then(function(r) { common.notify(r, _('DDNS 已更新')); }); }) }, _('立即更新 DDNS'))
			]),
			E('div', { 'class': 'kuroshio-row', 'style': 'margin-top:.6em' }, [
				E('button', { 'class': 'btn cbi-button cbi-button-action', 'id': 'kuroshio-persist-flush', 'click': ui.createHandlerFn(self, 'flushNow') }, _('立即儲存學習資料')),
				E('span', { 'class': 'cbi-value-description', 'style': 'margin:0' }, _('更新韌體或要斷電前先按一下，學到的資料會馬上寫進儲存空間'))
			])
		]);

		var errs = (api.errors && api.errors.recent) || [];
		var errSec = errs.length ? common.section(_('最近的錯誤（共 %d 次）').format(api.errors.count), [
			common.pre(errs.slice(0, 10).map(function(e) { return fmtTime(e.at, 'sec') + '  ' + e.msg; }).join('\n'))
		]) : '';

		return E([], [head, tiles, hw, memSec, accSec, lsSec, upSec, jobSec, infoSec, actions, errSec]);
	},

	render: function(data) {
		var self = this, acme = data[2];
		var box = E('div', {}, this.renderBody(data[1], acme));
		poll.add(function() {
			return L.resolveDefault(callStatus(), {}).then(function(st) {
				box.replaceChildren(self.renderBody(st, acme));
			});
		}, 10);
		return E([], [E('h2', {}, _('黑潮 DNS · 狀態')), box, common.footer({ open: true })]);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
