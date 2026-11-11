'use strict';
'require view';
'require poll';
'require rpc';
'require kuroshio.common as common';

var callLog = rpc.declare({ object: 'kuroshio', method: 'log', params: ['lines'], expect: { lines: [] } });

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
			E('div', { 'class': 'cbi-section' }, [
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
