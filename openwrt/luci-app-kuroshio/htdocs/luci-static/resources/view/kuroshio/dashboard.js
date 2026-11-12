'use strict';
'require view';
'require kuroshio.common as common';

// 儀表板：跟公開頁、Windows 設定頁共用同一份 kuroshio/dashboard.js（套件從 data/dashboard/ 安裝進來）。
// 資料經 rpcd（kuroshio.api）轉送到本機管理 API，是完整資料（排行不受公開頁的人數門檻限制）；
// 公開頁關著也能用，不需要開任何埠。圖表在瀏覽器畫，路由器只給 JSON。

/** 載入一個靜態檔（script / link），完成或失敗都會 resolve：true = 成功 */
function loadAsset(tag, url) {
	return new Promise(function(resolve) {
		var n = document.createElement(tag);
		if (tag === 'script') n.src = url;
		else { n.rel = 'stylesheet'; n.href = url; }
		n.onload = function() { resolve(true); };
		n.onerror = function() { resolve(false); };
		document.head.appendChild(n);
	});
}

/** 呼叫管理 API（經 rpcd）：服務沒有回應、路徑不允許時 reject，讓儀表板在那一區顯示原因 */
function call(path, params) {
	return common.api(path, params).then(function(r) {
		if (!r || r.ok === false) throw new Error((r && r.error) || _('服務沒有回應（可能尚未啟動）'));
		return r.result;
	});
}

return view.extend({
	load: function() {
		if (window.KuroshioDashboard) return Promise.resolve(true);
		return Promise.all([
			loadAsset('link', L.resource('kuroshio/dashboard.css')),
			loadAsset('script', L.resource('kuroshio/dashboard.js'))
		]).then(function(r) { return r[1] && !!window.KuroshioDashboard; });
	},

	render: function(ok) {
		var root = E('div', { 'class': 'kd-theme', 'id': 'kuroshio-dashboard' });
		if (ok) {
			var KD = window.KuroshioDashboard;
			KD.mount(root, {
				adapter: KD.callAdapter(call),
				sections: KD.ADMIN_SECTIONS,
				idPrefix: 'kd-',
				rich: true,
				toolbar: true,
				domainsMode: 'server',
				showErrors: true,
				refreshMs: 15000
			});
		} else {
			root.appendChild(common.T('p', { 'class': 'alert-message warning' },
				_('讀不到 /luci-static/resources/kuroshio/dashboard.js（luci-app-kuroshio 安裝不完整？請重新安裝）')));
		}
		return E([], [
			E('h2', {}, _('黑潮 DNS · 儀表板')),
			E('p', { 'class': 'cbi-section-descr' },
				_('查詢量、加速成效、上游、CDN 台灣節點與網域資料庫、過濾規則、排程工作。資料直接從路由器上的服務讀取（完整資料，不受公開頁的人數門檻限制）；公開網頁關著也看得到，不需要開任何埠。')),
			root,
			common.footer()
		]);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
