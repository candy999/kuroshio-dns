'use strict';
'require view';
'require poll';
'require rpc';
'require ui';
'require kuroshio.ui as common';

var callLog = rpc.declare({ object: 'kuroshio', method: 'log', params: ['lines'], expect: { lines: [] } });

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
	load: function() { return Promise.all([L.resolveDefault(callLog(300), []), common.ready]).then(function(r) { return r[0]; }); },

	render: function(lines) {
		var pre = E('pre', { 'style': 'white-space:pre-wrap;font-size:12px;max-height:70vh;overflow:auto' });
		var follow = E('input', { 'type': 'checkbox', 'checked': '' });
		var show = function(l) {
			pre.textContent = (l && l.length) ? l.join('\n') : _('沒有紀錄（服務可能還沒啟動）');
			if (follow.checked) pre.scrollTop = pre.scrollHeight;
		};
		show(lines);
		// 查詢紀錄（3.5.0）：只在記憶體；暫時開啟 10 分鐘（最長 60 分鐘，到時間自動關閉）
		var RESULT = { hit: _('快取'), miss: _('上游'), blocked: _('擋掉'), stale: _('過期資料') };
		var qState = E('p', { 'class': 'cbi-section-descr', 'id': 'kuroshio-qlog-state' });
		var qName = E('input', { 'type': 'search', 'placeholder': _('網域（包含這段文字）') });
		var qBody = E('div', { 'id': 'kuroshio-qlog' });
		var loadQ = function() {
			var q = { limit: 200 };
			if (qName.value.trim()) q.name = qName.value.trim();
			return common.api('/api/querylog', q).then(function(r) {
				var d = (r && r.result) || {};
				qState.textContent = d.enabled ? (_('開啟中') + (d.until ? _('，到 %s 自動關閉').format(new Date(d.until).toLocaleTimeString()) : '') + '：' + (d.size || 0) + _(' 筆')) : _('沒有開啟');
				var rows = (d.entries || []).map(function(e) {
					return [new Date(e.at).toLocaleTimeString(), e.client, e.name, String(e.type), (RESULT[e.result] || e.result) + (e.rcode ? ' (rcode ' + e.rcode + ')' : ''), e.ms + ' ms', e.source || ''];
				});
				qBody.textContent = '';
				qBody.appendChild(common.scroll(common.table([_('時間'), _('來源'), _('網域'), _('類型'), _('結果'), _('延遲'), _('答案來源')], rows, _('沒有紀錄'))));
			});
		};
		var qBtn = function(label, minutes, cls) {
			return E('button', { 'class': 'btn cbi-button ' + (cls || ''), 'click': ui.createHandlerFn(null, function() {
				return common.action('/api/querylog/enable', { minutes: String(minutes) }).then(loadQ);
			}) }, label);
		};
		loadQ();
		poll.add(function() { return L.resolveDefault(callLog(300), []).then(show).then(loadQ); }, 5);
		return E([], [
			E('h2', {}, _('黑潮 DNS · 日誌')),
			E('div', { 'class': 'cbi-section kuroshio-sec' }, [
				E('label', { 'style': 'display:inline-flex;gap:.4em;align-items:center' }, [follow, _('自動捲到最新')]),
				pre
			]),
			E('div', { 'class': 'cbi-section kuroshio-sec' }, [
				E('h3', {}, _('查詢紀錄')),
				E('p', { 'class': 'cbi-section-descr' }, _('每一筆查詢的網域、來源、結果與延遲，除錯用。只在記憶體、不寫磁碟、不進備份；暫時開啟最長 60 分鐘，到時間自動關閉。')),
				qState,
				E('div', { 'style': 'display:flex;gap:.5em;flex-wrap:wrap;align-items:center;margin-bottom:.5em' }, [
					qBtn(_('開啟 10 分鐘'), 10, 'cbi-button-action'), qBtn(_('關閉'), 0), qName,
					E('button', { 'class': 'btn cbi-button', 'click': ui.createHandlerFn(this, loadQ) }, _('重新整理'))
				]),
				qBody
			]),
			common.footer()
		]);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
