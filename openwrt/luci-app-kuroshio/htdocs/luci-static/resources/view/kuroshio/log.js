'use strict';
'require view';
'require poll';
'require rpc';
'require ui';
'require kuroshio.common as common';

var callLog = rpc.declare({ object: 'kuroshio', method: 'log', params: ['lines'], expect: { lines: [] } });

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
	load: function() { return L.resolveDefault(callLog(300), []); },

	render: function(lines) {
		var pre = E('pre', { 'style': 'white-space:pre-wrap;font-size:12px;max-height:70vh;overflow:auto' });
		var follow = E('input', { 'type': 'checkbox', 'checked': '' });
		var show = function(l) {
			pre.textContent = (l && l.length) ? l.join('\n') : _('沒有紀錄（服務可能還沒啟動）');
			if (follow.checked) pre.scrollTop = pre.scrollHeight;
		};
		show(lines);
		poll.add(function() { return L.resolveDefault(callLog(300), []).then(show); }, 5);
		return E([], [
			E('h2', {}, _('黑潮 DNS · 日誌')),
			E('div', { 'class': 'cbi-section kuroshio-sec' }, [
				E('label', { 'style': 'display:inline-flex;gap:.4em;align-items:center' }, [follow, _('自動捲到最新')]),
				E('p', { 'class': 'cbi-section-descr' }, _('要看每一筆查詢，請在「基本設定 → 專業模式 → 記錄每筆查詢」打開。')),
				pre
			]),
			common.footer()
		]);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
