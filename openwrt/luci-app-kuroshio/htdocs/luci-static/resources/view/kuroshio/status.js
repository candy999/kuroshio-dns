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
var JOBS = { 'dns-benchmark': _('DNS 評測'), 'cdn-ranges': _('CDN IP 範圍'), 'cdn-scan': _('CDN 網段分類'), 'cdn-pool': _('台灣節點池') };

function fmtNum(n) { return (n == null) ? '-' : Number(n).toLocaleString(); }
function pct(a, b) { return b ? (100 * a / b).toFixed(1) + '%' : '-'; }
function fmtTime(t) { return t ? new Date(t).toLocaleString() : '-'; }
function fmtUptime(s) {
	if (s == null) return '-';
	var d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
	return (d ? d + _('天') + ' ' : '') + h + _('小時') + ' ' + m + _('分');
}

function table(head, rows) {
	return E('table', { 'class': 'table' }, [
		E('tr', { 'class': 'tr table-titles' }, head.map(function(h) { return E('th', { 'class': 'th' }, h); }))
	].concat(rows.length ? rows.map(function(r) {
		return E('tr', { 'class': 'tr' }, r.map(function(c) { return E('td', { 'class': 'td' }, c); }));
	}) : [E('tr', { 'class': 'tr placeholder' }, E('td', { 'class': 'td', 'colspan': head.length }, E('em', {}, _('沒有資料'))))]));
}

function tile(label, value, sub) {
	return E('div', { 'style': 'flex:1 1 9em;min-width:9em;padding:.6em .8em;border:1px solid var(--border-color-medium,#ddd);border-radius:6px' }, [
		E('div', { 'style': 'font-size:12px;opacity:.75' }, label),
		E('div', { 'style': 'font-size:1.5em;font-weight:600' }, value),
		sub ? E('div', { 'style': 'font-size:12px;opacity:.75' }, sub) : ''
	]);
}

return view.extend({
	load: function() {
		return Promise.all([uci.load('kuroshio'), L.resolveDefault(callStatus(), {}), L.resolveDefault(callAcmeStatus(), null)]);
	},

	runJob: function(name) {
		return common.action('/api/jobs/run', { name: name }).then(function(r) { common.notify(r, _('已排入背景執行')); });
	},

	renderBody: function(st, acme) {
		var self = this;
		var enabled = uci.get('kuroshio', 'main', 'enabled') === '1';
		var mode = uci.get('kuroshio', 'main', 'redirect') || 'dnsmasq-upstream';
		var api = st && st.api && st.api.ok ? st.api.result : null;

		var head = E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, _('服務')),
			E('p', {}, [
				E('strong', { 'style': 'color:' + (st && st.running ? 'green' : 'red') },
					st && st.running ? _('執行中') : (enabled ? _('未執行（請看日誌）') : _('已停用'))),
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

		var tiles = E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, _('今天')),
			E('div', { 'style': 'display:flex;gap:.6em;flex-wrap:wrap' }, [
				tile(_('查詢'), fmtNum(q), _('快取命中 ') + pct(d.hit || 0, q)),
				tile(_('攔截'), fmtNum(d.blocked), _('廣告 %s · 遙測 %s · 惡意 %s').format(fmtNum(d.blockedAds), fmtNum(d.blockedTelemetry), fmtNum(d.blockedMalware))),
				tile(_('拉回台灣'), fmtNum(routeAcc), _('CDN 連線的 ') + pct(routeAcc, routeN)),
				tile(_('CDN 置換'), fmtNum(cdn.rewrites), _('ECS %s · 跨 CDN %s').format(fmtNum(cdn.ecsRewrites), fmtNum(cdn.crossRewrites))),
				tile(_('快取筆數'), fmtNum(api.cacheEntries), _('CDN 網域庫 ') + fmtNum(api.cdn && api.cdn.domains)),
				tile(_('過濾規則'), fmtNum(api.filter && (api.filter.lists + api.filter.custom)), _('自訂 ') + fmtNum(api.filter && api.filter.custom))
			])
		]);

		// 硬體與效能（3.0）
		var sys = api.system || {}, per = sys.persist || {}, lat = d.latency || {}, ls = api.listeners || {};
		var ms = function(x) { return x && x.p50 != null ? x.p50 + ' / ' + (x.p95 != null ? x.p95 : '>1000') + ' ms' : '-'; };
		var protos = ['doh', 'doh3', 'dot', 'doq'].filter(function(k) { return ls[k]; }).map(function(k) { return { doh: 'DoH', doh3: 'DoH3', dot: 'DoT', doq: 'DoQ' }[k] + ':' + ls[k]; });
		var hw = E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, _('硬體與效能')),
			E('div', { 'style': 'display:flex;gap:.6em;flex-wrap:wrap' }, [
				tile(_('硬體等級'), sys.tier || '-', (sys.memTotalMB ? sys.memTotalMB + ' MB · ' : '') + (sys.cores || '?') + _(' 核 ') + (sys.arch || '')),
				tile(_('記憶體'), sys.rssKB ? (sys.rssKB / 1024).toFixed(1) + ' MB' : '-', _('可用 ') + (sys.memAvailableMB != null ? sys.memAvailableMB + ' MB' : '-') + (sys.pressure && sys.pressure !== 'normal' ? ' · ' + _('記憶體偏低') : '')),
				tile(_('快取命中率'), d.hitRate != null ? d.hitRate + '%' : '-', _('預取 %s · 斷線回舊資料 %s').format(fmtNum(d.prefetch), fmtNum(d.stale))),
				tile(_('回應時間 p50 / p95'), ms(lat.hit), _('問上游 ') + ms(lat.miss)),
				tile(_('Flash 寫入（今天）'), per.bytesToday != null ? (per.bytesToday / 1024).toFixed(0) + ' KB' : '-', (per.storage || '') + _(' · 最短間隔 ') + (per.intervalMin || '-') + _(' 分')),
				tile(_('加密協議'), protos.length ? protos.length + _(' 種') : _('未開啟'), protos.join(' · ') + (ls.ddr ? ' · DDR' : '')),
				tile(_('過濾記憶體'), api.filter && api.filter.memoryBytes != null ? (api.filter.memoryBytes / 1048576).toFixed(1) + ' MB' : '-', api.filter && api.filter.domains != null ? fmtNum(api.filter.domains) + _(' 個網域') : '')
			])
		]);

		// 連線來源限制（規格 08）：模式、拒絕次數、資料日期；資料讀不到時不擋，要明顯提醒
		var ac = api.access;
		var accSec = ac ? E('div', { 'class': 'cbi-section', 'id': 'kuroshio-access' }, [
			E('h3', {}, _('連線來源')),
			ac.failOpen ? E('div', { 'class': 'alert-message danger' }, _('台灣 IP 資料讀不到，現在不擋任何來源（封鎖名單照樣有效）') + (ac.warning ? '：' + ac.warning : ''))
				: (ac.warning ? E('div', { 'class': 'alert-message warning' }, ac.warning) : ''),
			E('p', {}, [
				E('strong', {}, { taiwan: _('只開放台灣'), custom: _('自訂 ISP'), open: _('全開放') }[ac.mode] || ac.mode || '-'),
				' · ', _('已拒絕 %s 次（啟動後）').format(fmtNum(ac.denied && ac.denied.total)),
				ac.generatedAt ? ' · ' + _('台灣 IP 資料 %s').format(ac.generatedAt) : '',
				' · ', E('a', { 'href': L.url('admin/services/kuroshio/access') }, _('設定'))
			])
		]) : '';

		// 加密監聽：每個位址一列，綁定失敗列出原因
		var detail = [].concat(api.listenersDetail || []);
		var lsSec = detail.length ? E('div', { 'class': 'cbi-section', 'id': 'kuroshio-listeners' }, [
			E('h3', {}, _('加密監聽')),
			E('div', { 'style': 'overflow-x:auto' }, common.listenerTable(detail))
		]) : '';

		var ups = (api.upstreams || []).map(function(u) {
			var role = { pinned: _('固定'), auto: _('自動'), fallback: _('備援') }[u.role] || u.role;
			return [u.id, role, fmtNum(u.ok), fmtNum(u.fail), u.avgMs != null ? u.avgMs + ' ms' : '-', u.paused ? _('暫停中') : ''];
		});
		var upSec = E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, _('上游')),
			E('p', { 'class': 'cbi-section-descr' }, api.autoUpstreams ? _('自動上游來自 %s 的評測').format(api.autoUpstreams.generatedAt) : _('還沒有每日評測結果，暫時使用固定上游與備援。')),
			table([_('上游'), _('角色'), _('成功'), _('失敗'), _('平均延遲'), ''], ups)
		]);

		var jobs = api.jobs || {};
		var jobRows = Object.keys(jobs.config || {}).map(function(n) {
			var c = jobs.config[n], s = (jobs.state || {})[n] || {};
			var running = jobs.running && jobs.running.name === n;
			return [
				JOBS[n] || n,
				[].concat(c.at || []).join(', ') + (c.weekdays ? ' (' + c.weekdays.join(',') + ')' : '') + (c.enabled === false ? ' ' + _('已停用') : ''),
				running ? _('執行中…') : fmtTime(s.lastEnd),
				s.lastCode === 0 ? _('成功') : (s.lastCode == null ? '-' : _('失敗（%s）').format(s.lastCode)),
				E('button', { 'class': 'btn cbi-button', 'disabled': running ? '' : null, 'click': ui.createHandlerFn(self, 'runJob', n) }, _('立即執行'))
			];
		});
		var jobSec = E('div', { 'class': 'cbi-section' }, [E('h3', {}, _('排程工作')), table([_('工作'), _('排程'), _('上次結束'), _('結果'), ''], jobRows)]);

		var extra = [];
		if (acme) {
			var c = acme.cert;
			extra.push([_('憑證'), c ? _('%s · 到期 %s（剩 %d 天）').format(c.san || c.subject, c.validTo, c.daysLeft) : (acme.certError || '-')]);
		}
		if (api.ownIp) extra.push([_('網域目前指向'), (api.ownIp.ips || []).join(', ') + (api.ownIp.changedAt ? _('（%s 變更）').format(fmtTime(api.ownIp.changedAt)) : '')]);
		var infoSec = E('div', { 'class': 'cbi-section' }, [E('h3', {}, _('其他')), table([_('項目'), _('內容')], extra)]);

		var actions = E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, _('操作')),
			E('div', { 'style': 'display:flex;gap:.5em;flex-wrap:wrap' }, [
				E('button', { 'class': 'btn cbi-button', 'click': ui.createHandlerFn(self, function() { return common.action('/api/cache/flush').then(function(r) { common.notify(r, _('快取已清除')); }); }) }, _('清除快取')),
				E('button', { 'class': 'btn cbi-button', 'click': ui.createHandlerFn(self, function() { return common.action('/api/filter/update').then(function(r) { common.notify(r, _('已重新下載過濾清單')); }); }) }, _('更新過濾清單')),
				E('button', { 'class': 'btn cbi-button', 'click': ui.createHandlerFn(self, function() { return common.action('/api/ddns/update').then(function(r) { common.notify(r, _('DDNS 已更新')); }); }) }, _('立即更新 DDNS'))
			])
		]);

		var errs = (api.errors && api.errors.recent) || [];
		var errSec = errs.length ? E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, _('最近的錯誤（共 %d 次）').format(api.errors.count)),
			common.pre(errs.slice(0, 10).map(function(e) { return fmtTime(e.at) + '  ' + e.msg; }).join('\n'))
		]) : '';

		return E([], [head, tiles, hw, accSec, lsSec, upSec, jobSec, infoSec, actions, errSec]);
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
