'use strict';
'require view';
'require form';
'require fs';
'require ui';
'require kuroshio.common as common';

var RULES = '/etc/kuroshio/custom-rules.txt';

return view.extend({
	load: function() {
		return Promise.all([
			common.loadDefaults(),
			L.resolveDefault(fs.read(RULES), '')
		]);
	},

	render: function(data) {
		var rules = data[1] || '';
		var pro = common.isPro();
		var m, s, o;

		m = new form.Map('kuroshio', _('黑潮 DNS · 廣告過濾'),
			_('判定順序：自訂規則是最高原則，命中就不看任何訂閱清單（白名單 @@ 也會蓋過所有清單）；沒有命中才看訂閱清單。支援 AdGuard / hosts 語法，也會檢查 CNAME 鏈。'));

		s = m.section(form.NamedSection, 'filter', 'filter', _('過濾'));
		o = s.option(form.Flag, 'enabled', _('啟用過濾'));
		o.rmempty = false;
		if (pro) {
			common.num(s, null, 'update_interval_hours', _('清單更新間隔（小時）'), 'filter.updateIntervalHours');
			o = common.flag(s, null, 'relaxed_modifiers', _('寬鬆套用瀏覽器規則'), 'filter.relaxedModifiers',
				_('EasyList 這類瀏覽器清單有很多帶 $third-party、$script 修飾詞的規則。關閉（預設，同 AdGuard Home）= 略過這些規則；打開 = 整個網域封鎖，擋得更多但可能誤殺。'));
		}

		// ---------------- 訂閱清單 ----------------
		s = m.section(form.GridSection, 'filter_list', _('訂閱清單'), _('分類一層一層往上疊：廣告為底，遙測疊在上面，惡意在最上層。同一個網域出現在多份清單時只算一次，歸到最上層的分類（例如同時在廣告與惡意清單 → 算惡意）。統計依分類分開計算。hosts 格式裡寫的 IP 一律不採用，只當成封鎖該網域。'));
		s.anonymous = true;
		s.addremove = true;
		s.sortable = true;
		s.nodescriptions = true;

		o = s.option(form.Flag, 'enabled', _('啟用'));
		o.default = '1';
		o.rmempty = false;
		o.editable = true;
		o = s.option(form.Value, 'name', _('名稱'));
		o.rmempty = false;
		o = s.option(form.Value, 'url', _('網址'));
		o.rmempty = false;
		o.validate = function(id, v) { return /^https?:\/\/\S+$/.test(v) || _('請輸入 http:// 或 https:// 開頭的網址'); };
		o.textvalue = function(sid) {
			var v = this.cfgvalue(sid) || '';
			return v.length > 60 ? v.slice(0, 57) + '…' : v;
		};
		o = s.option(form.ListValue, 'category', _('分類'));
		o.value('ads', _('廣告 / 追蹤'));
		o.value('telemetry', _('遙測 / 驗證'));
		o.value('malware', _('惡意 / 詐騙'));
		o.default = 'ads';

		// ---------------- 自訂規則 ----------------
		s = m.section(form.NamedSection, 'filter', 'filter', _('自訂規則'),
			E([], [
				_('最高原則：這裡的規則永遠優先於所有訂閱清單。一行一條，例：||ads.example.com^ 封鎖、@@||good.example.com^ 白名單、! 或 # 開頭是註解。存檔後 3 秒內生效，不用重啟。'),
				E('br'),
				_('分類段落：用「! @begin 分類」開頭、「! @end」結尾，把一段規則標成 廣告 / 遙測 / 惡意（也可以寫 ads / telemetry / malware），統計就會歸到該分類；段落外的規則算「自訂」。標記本身是註解，AdGuard Home 也能直接讀。'),
				E('pre', { 'style': 'margin:.4em 0;font-size:12px' }, '! @begin 遙測\n||telemetry.example.com^\n! @end')
			]));
		o = s.option(form.TextValue, '_rules');
		o.rows = 20;
		o.monospace = true;
		o.wrap = 'off';
		o.cfgvalue = function() { return rules; };
		o.write = function(sid, value) {
			value = String(value || '').replace(/\r\n/g, '\n');
			if (value === rules) return;
			rules = value;
			return fs.write(RULES, value.replace(/\n*$/, '\n'));
		};
		o.remove = function() { return this.write(null, ''); };

		// ---------------- 檢查工具 ----------------
		var out = E('div');
		var input = E('input', { 'type': 'text', 'class': 'cbi-input-text', 'placeholder': 'ads.example.com', 'style': 'max-width:24em' });
		var check = function() {
			var name = input.value.trim();
			if (!name) return;
			return common.api('/api/filter/check', { name: name }).then(function(r) {
				if (!r || r.ok === false) return common.notify(r);
				var x = r.result || {};
				var verdict = x.action === 'block' ? _('會被封鎖') : x.action === 'allow' ? _('白名單放行') : _('沒有命中任何規則');
				out.innerHTML = '';
				out.appendChild(E('p', {}, [E('strong', {}, verdict), x.rule ? ' — ' + x.rule : '', x.tier ? '（' + (x.tier === 'custom' ? _('自訂規則') : _('訂閱清單')) + '）' : '']));
				out.appendChild(common.pre(JSON.stringify(x, null, 2)));
			});
		};
		input.addEventListener('keydown', function(ev) { if (ev.key === 'Enter') { ev.preventDefault(); check(); } });

		var tools = E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, _('規則檢查')),
			E('div', { 'style': 'display:flex;gap:.5em;flex-wrap:wrap' }, [
				input,
				E('button', { 'class': 'btn cbi-button cbi-button-action', 'click': ui.createHandlerFn(this, check) }, _('檢查')),
				E('button', {
					'class': 'btn cbi-button',
					'click': ui.createHandlerFn(this, function() {
						return common.action('/api/filter/update').then(function(r) { common.notify(r, _('已重新下載訂閱清單')); });
					})
				}, _('立即更新清單'))
			]),
			out
		]);

		return m.render().then(function(node) { return E([], [common.modeBar(), node, tools, common.footer()]); });
	}
});
