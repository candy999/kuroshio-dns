'use strict';
'require view';
'require form';
'require fs';
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
				E('div', { 'class': 'cbi-section' }, [
					E('h2', {}, _('黑潮 DNS · 進階')),
					E('p', {}, _('這裡是上游、解析時間、測速、排程與評測的細部參數。為了避免誤改，請先切換到「專業」模式。'))
				]),
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

		return m.render().then(function(node) { return E([], [common.modeBar(), node, common.footer()]); });
	}
});
