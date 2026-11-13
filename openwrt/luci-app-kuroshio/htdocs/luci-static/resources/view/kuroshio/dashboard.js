'use strict';
'require view';
'require ui';
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

/** 'rgb(1, 2, 3)' / 'rgba(1, 2, 3, .5)' → [r, g, b, a]；看不懂回 null */
function rgba(s) {
	var m = /^rgba?\(([\d.]+),\s*([\d.]+),\s*([\d.]+)(?:,\s*([\d.]+))?\)$/.exec(String(s || '').trim());
	return m ? [+m[1], +m[2], +m[3], m[4] == null ? 1 : +m[4]] : null;
}
/** a 疊在 b 上（a 的透明度）、或 a 與 b 依比例 t 混合 */
function over(a, b) { return [0, 1, 2].map(function(i) { return a[i] * a[3] + b[i] * (1 - a[3]); }).concat(1); }
function mix(a, b, t) { return [0, 1, 2].map(function(i) { return a[i] * t + b[i] * (1 - t); }).concat(1); }
function css(c) { return 'rgb(' + c.slice(0, 3).map(Math.round).join(', ') + ')'; }

/**
 * 儀表板的顏色跟著目前的 LuCI 主題（bootstrap / argon / material / vantage…，淺色或深色）：
 * 放一個看不見的 .cbi-section 量主題的卡片底色、框線、圓角、陰影與文字顏色，算成儀表板的變數（只用量到的顏色，不含任何資料）。
 * 主題的區塊是透明的（bootstrap）就用頁面底色加一點文字色當卡片底色。深淺色由文字亮度判斷，不看 data-darkmode（argon 沒有）。
 */
function followTheme(root, tries) {
	if (!root.isConnected) {
		if ((tries || 0) < 100) window.setTimeout(function() { followTheme(root, (tries || 0) + 1); }, 50);
		return;
	}
	var host = root.parentNode;
	var probe = E('div', { 'class': 'cbi-section', 'aria-hidden': 'true' }, E('h3', {}, 'x'));
	probe.style.cssText = 'position:absolute;visibility:hidden;pointer-events:none;left:0;top:0;width:200px';
	host.appendChild(probe);
	var ps = window.getComputedStyle(probe), hs = window.getComputedStyle(probe.firstChild);
	// 頁面底色：往上找第一個不透明的背景
	var page = null;
	for (var n = host; n && n.nodeType === 1 && !page; n = n.parentNode) {
		var c = rgba(window.getComputedStyle(n).backgroundColor);
		if (c && c[3] > 0.9) page = c;
	}
	var fg = rgba(hs.color) || rgba(ps.color) || [0, 0, 0, 1];
	var dark = (0.2126 * fg[0] + 0.7152 * fg[1] + 0.0722 * fg[2]) > 140;
	page = page || (dark ? [24, 24, 27, 1] : [255, 255, 255, 1]);
	var sec = rgba(ps.backgroundColor), themed = !!(sec && sec[3] > 0.05);
	var card = themed ? over(sec, page) : mix(fg, page, 0.04);
	var bw = parseFloat(ps.borderTopWidth) || 0, bc = rgba(ps.borderTopColor);
	// 框線：主題卡片有框就用主題的；主題卡片沒框（靠陰影或底色區分）就不加；透明卡片加一條很淡的
	var edge = bw > 0 && bc && bc[3] > 0 ? css(over(bc, card)) : (themed ? 'transparent' : css(mix(fg, card, 0.1)));
	var radius = parseFloat(ps.borderTopLeftRadius);
	var vars = {
		'--text': css(fg), '--text-2': css(mix(fg, card, 0.8)), '--text-3': css(mix(fg, card, 0.64)),
		'--bg': css(page), '--glass': css(card), '--glass-2': css(mix(fg, card, 0.06)), '--glass-edge': edge,
		'--line': css(mix(fg, card, 0.13)), '--grid': css(mix(fg, card, 0.07)), '--chip': css(mix(fg, card, 0.07)), '--track': css(mix(fg, card, 0.09)),
		'--shadow': (ps.boxShadow && ps.boxShadow !== 'none') ? ps.boxShadow : 'none',
		'--kd-radius': (radius >= 0 && radius <= 24 ? radius : 10) + 'px'
	};
	host.removeChild(probe);
	Object.keys(vars).forEach(function(k) { root.style.setProperty(k, vars[k]); });
	root.setAttribute('data-kd-host', dark ? 'dark' : 'light');
}

// 瀏覽器快取：LuCI 用固定的 ?v=（LuCI 本身的版本）載入外掛的檔案，升級黑潮之後瀏覽器可能還拿到舊的 common.js，
// 新功能就會按了沒反應。版本對不上時重新下載本外掛的所有檔案（更新瀏覽器快取）再重新整理一次；還是對不上就提示
var BUILD = '3.2.0';
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
		if (window.KuroshioDashboard) return Promise.resolve(true);
		return Promise.all([
			loadAsset('link', L.resource('kuroshio/dashboard.css')),
			loadAsset('script', L.resource('kuroshio/dashboard.js'))
		]).then(function(r) { return r[1] && !!window.KuroshioDashboard; });
	},

	render: function(ok) {
		var root = E('div', { 'class': 'kd-theme', 'id': 'kuroshio-dashboard' });
		followTheme(root);
		// 主題跟著系統切換深淺色時重新量
		try { window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function() { window.setTimeout(function() { followTheme(root); }, 50); }); } catch (e) {}
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
