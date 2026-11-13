'use strict';
'require view';
'require form';
'require fs';
'require ui';
'require uci';
'require dom';
'require kuroshio.common as common';

var RULES = '/etc/kuroshio/custom-rules.txt';
// 這個版本的預設自訂規則（套件附帶，升級時更新）
var DEFAULT_RULES = '/usr/share/kuroshio/default-custom-rules.txt';
var CONF = 'kuroshio';

/** 換行統一、去掉結尾空白再比較（記事本存成 CRLF 也算一樣） */
function sameText(a, b) {
	var n = function(t) { return String(t || '').replace(/\r\n/g, '\n').replace(/\s+$/, ''); };
	return n(a) === n(b);
}

/** UCI 的 filter_list 區段 → restorePlan 用的格式 */
function currentLists() {
	return uci.sections(CONF, 'filter_list').map(function(x) {
		var p = x.protect;
		return { ref: x['.name'], name: x.name, url: x.url, category: x.category, enabled: x.enabled !== '0',
			protect: (p == null || p === '') ? undefined : p === '1' };
	});
}

return view.extend({
	load: function() {
		return Promise.all([
			common.loadDefaults(),
			L.resolveDefault(fs.read(RULES), '')
		]);
	},

	render: function(data) {
		var self = this;
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

		// 「新增」按鈕旁邊加「恢復預設清單」
		var addButtons = s.renderSectionAdd;
		s.renderSectionAdd = function() {
			var node = addButtons.apply(this, arguments);
			node.appendChild(E('button', {
				'class': 'cbi-button cbi-button-neutral', 'id': 'kuroshio-restore-lists', 'style': 'margin-left:.5em',
				'title': _('把訂閱清單改回這個版本的預設；自己加的清單會保留'),
				'click': ui.createHandlerFn(self, 'restoreLists', m)
			}, _('恢復預設清單')));
			return node;
		};

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
		if (pro) {
			o = s.option(form.ListValue, 'protect', _('保護'),
				_('記憶體不足時也不暫時停用。自動 = 惡意 / 詐騙類保護（例如 165 反詐騙），其他不保護。'));
			o.value('', _('自動'));
			o.value('1', _('保護'));
			o.value('0', _('不保護'));
			o.optional = true;
		}

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
		var rulesOpt = o;

		o = s.option(form.Button, '_reset_rules', ' ');
		o.inputtitle = _('恢復預設自訂規則');
		o.inputstyle = 'reset';
		o.cfgvalue = function() { return null; };
		o.write = o.remove = function() {};
		o.onclick = function() {
			ui.showModal(_('恢復預設自訂規則'), [
				E('p', {}, _('把自訂規則換成這個版本的預設規則。編輯框裡還沒儲存的修改也會被取代。')),
				E('p', {}, _('目前的內容會先備份成 %s（只保留最近一次）。').format(RULES + '.bak')),
				E('div', { 'class': 'right' }, [
					E('button', { 'class': 'btn', 'click': ui.hideModal }, _('取消')), ' ',
					E('button', { 'class': 'btn cbi-button-negative', 'id': 'kuroshio-rules-confirm', 'click': ui.createHandlerFn(self, function() {
						ui.hideModal();
						return resetRules();
					}) }, _('恢復預設'))
				])
			]);
		};

		/** 編輯框與比較用的內容換成 text（已經寫進檔案了，存檔時不會再寫一次） */
		var showRules = function(text) {
			rules = String(text || '').replace(/\r\n/g, '\n');
			var w = rulesOpt.getUIElement('filter');
			if (w) w.setValue(rules);
		};
		// 預設規則從套件附帶的檔案讀；讀不到時改請服務處理（服務會用執行檔內建的預設規則）
		var resetRules = function() {
			return L.resolveDefault(fs.read(DEFAULT_RULES), null).then(function(def) {
				if (def == null || !def.trim()) {
					return common.action('/api/filter/reset-rules').then(function(r) {
						var x = common.result(r);
						if (!x) return common.notify(r);
						return L.resolveDefault(fs.read(RULES), '').then(function(t) {
							showRules(t);
							common.notify(r, x.changed === false ? _('自訂規則已經是這個版本的預設，不需要變更。')
								: _('已恢復預設自訂規則，3 秒內生效。原本的內容備份在 %s').format(x.backup || RULES + '.bak'));
						});
					});
				}
				return L.resolveDefault(fs.read(RULES), null).then(function(cur) {
					if (cur != null && sameText(cur, def)) {
						showRules(def);
						return common.notify({}, _('自訂規則已經是這個版本的預設，不需要變更。'));
					}
					var backup = (cur == null) ? Promise.resolve() : fs.write(RULES + '.bak', cur);
					return backup.then(function() { return fs.write(RULES, def); }).then(function() {
						showRules(def);
						common.notify({}, cur == null ? _('已恢復預設自訂規則，3 秒內生效。')
							: _('已恢復預設自訂規則，3 秒內生效。原本的內容備份在 %s').format(RULES + '.bak'));
					});
				});
			}).catch(function(e) {
				common.notify({ ok: false, error: _('恢復預設自訂規則失敗：%s').format(e.message || e) });
			});
		};

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

		var tools = E('div', { 'class': 'cbi-section kuroshio-sec' }, [
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
	},

	/**
	 * 恢復預設清單：預設值來自 rpcd 的 defaults（kuroshio defaults --json），不寫死在介面裡。
	 * 先把表單裡還沒存的修改暫存，列出會改什麼，確認後改 UCI（暫存），再按「儲存並套用」生效
	 */
	restoreLists: function(m) {
		var defs = ((common.defaults || {}).filter || {}).lists;
		if (!Array.isArray(defs) || !defs.length)
			return common.notify({ ok: false, error: _('讀不到這個版本的預設清單（kuroshio defaults --json 沒有回應），沒有變更。') });
		return m.save(null, true).then(function() {
			var cur = currentLists();
			var own = E('input', { 'type': 'checkbox', 'id': 'kuroshio-restore-own' });
			var box = E('div', { 'id': 'kuroshio-restore-summary' });
			var plan = null;
			var okBtn = E('button', { 'class': 'btn cbi-button-negative', 'id': 'kuroshio-restore-confirm', 'click': ui.createHandlerFn(this, function() {
				ui.hideModal();
				return applyRestore(m, cur, plan);
			}) }, _('恢復預設清單'));
			var draw = function() {
				plan = common.restorePlan(cur, defs, own.checked);
				dom.content(box, common.restoreSummary(plan.changes));
				okBtn.disabled = !plan.changes.count;
			};
			own.addEventListener('change', draw);
			ui.showModal(_('恢復預設清單'), [
				E('p', {}, _('把訂閱清單改回這個版本的預設：名稱、網址、分類、啟用狀態與順序。網址不在預設裡的清單是你自己加的，會保留並排在預設清單後面（啟用狀態不變）。')),
				box,
				E('p', {}, E('label', {}, [own, ' ', _('一併移除我自己加的清單')])),
				E('p', { 'class': 'cbi-value-description' }, _('按下「恢復預設清單」後，還要按頁面下方的「儲存並套用」才會生效。')),
				E('div', { 'class': 'right' }, [E('button', { 'class': 'btn', 'click': ui.hideModal }, _('取消')), ' ', okBtn])
			]);
			draw();
		}, function(e) {
			common.notify({ ok: false, error: _('表單裡有格式不正確的欄位，請先修正：%s').format(e && e.message || e) });
		});
	}
});

/**
 * 依 restorePlan 改 UCI（暫存，還沒套用）。分兩次存：
 * 第一次新增、改值、排順序；第二次才刪除區段與選項（LuCI 同一次存檔裡有刪除時不會送出順序）
 */
function applyRestore(m, cur, plan) {
	var order = [], unset = [], keep = {};
	plan.result.forEach(function(r) {
		var sid;
		if (r.own) {
			sid = r.own.ref;
		} else {
			var d = r.def, old = r.from >= 0 ? cur[r.from] : null;
			sid = old ? old.ref : uci.add(CONF, 'filter_list');
			uci.set(CONF, sid, 'name', d.name);
			uci.set(CONF, sid, 'url', d.url);
			uci.set(CONF, sid, 'category', d.category);
			uci.set(CONF, sid, 'enabled', d.enabled ? '1' : '0');
			if (d.protect !== undefined) uci.set(CONF, sid, 'protect', d.protect ? '1' : '0');
			else if (old && old.protect !== undefined) unset.push(sid);
		}
		if (r.from >= 0) keep[r.from] = true;
		order.push(sid);
	});
	order.forEach(function(sid) { uci.move(CONF, sid, null); });
	return uci.save().then(function() {
		cur.forEach(function(c, j) { if (!keep[j]) uci.remove(CONF, c.ref); });
		unset.forEach(function(sid) { uci.unset(CONF, sid, 'protect'); });
		return uci.save();
	}).then(function() { return m.load(); }).then(function() { return m.reset(); }).then(function() {
		var ch = plan.changes;
		common.notify({}, _('已改成這個版本的預設清單（%d 項變更），按下方「儲存並套用」後生效。').format(ch.count));
	}).catch(function(e) {
		common.notify({ ok: false, error: _('恢復預設清單失敗：%s').format(e && e.message || e) });
	});
}
