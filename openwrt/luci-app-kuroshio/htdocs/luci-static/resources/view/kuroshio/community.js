'use strict';
'require view';
'require form';
'require poll';
'require ui';
'require kuroshio.common as common';

var REL = { friend: _('好友'), out: _('等待對方同意'), 'in': _('待我審核'), none: '-' };

function fmtTime(t) { return t ? new Date(t).toLocaleString() : '-'; }

function peerState(p) {
	if (p.rel === 'friend') return REL.friend;
	if (p.myBlock) return _('已封鎖');
	if (p.theirBlock) return _('對方已封鎖你');
	if (p.rel === 'none' && p.rejectedUntil && p.rejectedUntil > Date.now()) return _('已拒絕（%s 前不能再請求）').format(new Date(p.rejectedUntil).toLocaleDateString());
	if (p.rel === 'none' && p.theirRejectUntil && p.theirRejectUntil > Date.now()) return _('對方拒絕（%s 前不能再請求）').format(new Date(p.theirRejectUntil).toLocaleDateString());
	if (p.rel === 'none' && p.deletedAt) return _('已刪除');
	return REL[p.rel] || p.rel;
}

return view.extend({
	load: function() {
		return Promise.all([
			common.loadDefaults(),
			L.resolveDefault(common.api('/api/community/status'), null)
		]);
	},

	act: function(path, params, okText) {
		var self = this;
		return common.action(path, params).then(function(r) {
			var res = r && r.result;
			if (!r || r.ok === false) return common.notify(r);
			if (res && res.ok === false) return ui.addNotification(null, E('p', {}, res.reason || _('操作失敗')), 'warning');
			ui.addNotification(null, E('p', {}, okText || _('完成')), 'info');
			return self.refresh();
		});
	},

	renderStatus: function(st) {
		if (!st || st.ok === false || !st.result) return E('div', { 'class': 'cbi-section' }, E('em', {}, _('服務沒有在執行，或社群模式沒有啟用。')));
		var s = st.result;
		if (!s.enabled) return E('div', { 'class': 'cbi-section' }, E('em', {}, _('社群模式沒有啟用：在下方打開並「儲存並套用」。')));
		var c = s.check || {};
		return E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, _('我的身分')),
			E('table', { 'class': 'table' }, [
				E('tr', { 'class': 'tr' }, [E('td', { 'class': 'td left', 'width': '25%' }, _('狀態')),
					E('td', { 'class': 'td left' }, s.ready ? E('strong', { 'style': 'color:green' }, _('就緒')) : E('span', { 'style': 'color:#c00' }, _('未就緒：') + (c.problems || []).join('；')))]),
				E('tr', { 'class': 'tr' }, [E('td', { 'class': 'td left' }, _('網域')), E('td', { 'class': 'td left' }, s.domain || '-')]),
				E('tr', { 'class': 'tr' }, [E('td', { 'class': 'td left' }, _('公鑰指紋')), E('td', { 'class': 'td left' }, E('code', {}, s.fingerprint))]),
				E('tr', { 'class': 'tr' }, [E('td', { 'class': 'td left' }, _('對外網址')), E('td', { 'class': 'td left' }, [s.endpoints.doh, s.endpoints.dot].filter(Boolean).join('　') || '-')]),
				E('tr', { 'class': 'tr' }, [E('td', { 'class': 'td left' }, _('憑證')), E('td', { 'class': 'td left' }, c.cert ? _('%s 到期（剩 %d 天）').format(c.cert.validTo, c.cert.daysLeft) : '-')]),
				E('tr', { 'class': 'tr' }, [E('td', { 'class': 'td left' }, _('外部連線')), E('td', { 'class': 'td left' },
					s.externalConfirmed ? _('已由 %s 於 %s 連入確認').format(s.externalConfirmed.from, fmtTime(s.externalConfirmed.at)) : _('還沒有其他節點連進來過（加好友時對方會回連驗證）'))])
			]),
			E('div', { 'style': 'margin-top:.5em' }, E('button', { 'class': 'btn cbi-button', 'click': ui.createHandlerFn(this, 'act', '/api/community/check', {}, _('已重新檢查')) }, _('重新檢查')))
		]);
	},

	renderPeers: function(peers) {
		var self = this;
		var btn = function(label, path, params, cls, ok) {
			return E('button', { 'class': 'btn cbi-button ' + (cls || ''), 'click': ui.createHandlerFn(self, 'act', path, params, ok) }, label);
		};
		var rows = (peers || []).map(function(p) {
			var d = p.domain, acts = [];
			if (p.rel === 'in') acts.push(btn(_('同意'), '/api/community/accept', { domain: d }, 'cbi-button-positive', _('已同意')),
				btn(_('拒絕'), '/api/community/reject', { domain: d }, '', _('已拒絕')), btn(_('封鎖'), '/api/community/block', { domain: d }, 'cbi-button-negative', _('已封鎖')));
			else if (p.rel === 'friend') acts.push(btn(_('立即同步'), '/api/community/sync', { domain: d }, '', _('已同步')),
				btn(_('刪除'), '/api/community/delete', { domain: d }, 'cbi-button-negative', _('已刪除')),
				btn(_('刪除並封鎖'), '/api/community/delete', { domain: d, block: '1' }, 'cbi-button-negative', _('已刪除並封鎖')));
			else if (p.rel === 'out') acts.push(btn(_('取消'), '/api/community/delete', { domain: d }, '', _('已取消')));
			if (p.myBlock) acts.push(btn(_('解除封鎖'), '/api/community/unblock', { domain: d }, '', _('已解除封鎖')));
			else if (p.rel === 'none') acts.push(btn(_('加好友'), '/api/community/add', { domain: d }, 'cbi-button-action', _('已送出請求')));
			var info = p.info || {}, st = p.stats || {};
			var hit = st.tried ? Math.round(100 * (st.ok || 0) / st.tried) + '%（' + st.ok + '/' + st.tried + '）' : '-';
			return [
				E('div', {}, [E('strong', {}, d), p.fingerprint ? E('div', { 'style': 'font-size:11px;opacity:.7' }, p.fingerprint.slice(0, 19) + '…') : '']),
				E('div', {}, [peerState(p), p.lastError ? E('div', { 'style': 'font-size:11px;color:#c00' }, p.lastError) : '']),
				(info.asn ? 'AS' + info.asn : '-') + (info.colo ? ' · ' + info.colo : ''),
				info.rttMs != null ? _('%d ms（抖動 %d、掉包 %d%%）').format(info.rttMs, info.jitterMs || 0, info.lossPct || 0) : '-',
				fmtTime(p.lastSyncOk),
				(st.offered || 0) + (st.violations ? ' / ' + _('違規 %d').format(st.violations) : ''),
				hit,
				E('div', { 'style': 'display:flex;gap:.3em;flex-wrap:wrap' }, acts)
			];
		});
		var head = [_('網域'), _('狀態'), _('業者 · 機房'), _('連線品質'), _('最後同步'), _('提供筆數'), _('命中率'), ''];
		return E('table', { 'class': 'table' }, [E('tr', { 'class': 'tr table-titles' }, head.map(function(h) { return E('th', { 'class': 'th' }, h); }))]
			.concat(rows.length ? rows.map(function(r) { return E('tr', { 'class': 'tr' }, r.map(function(c) { return E('td', { 'class': 'td' }, c); })); })
				: [E('tr', { 'class': 'tr placeholder' }, E('td', { 'class': 'td', 'colspan': head.length }, E('em', {}, _('還沒有好友'))))]));
	},

	/** 我的邀請碼：只有這裡拿得到（其他 API 都沒有邀請碼本身） */
	loadInvite: function() {
		var self = this;
		return L.resolveDefault(common.api('/api/community/invite'), null).then(function(r) { self.drawInvite(r); });
	},

	drawInvite: function(r) {
		var self = this, box = this.inviteBox, res = r && r.result;
		if (!r || r.ok === false || !res || (res.ok === undefined && !res.code)) {
			box.replaceChildren(E('em', {}, _('服務沒有在執行，或社群模式沒有啟用：啟用並「儲存並套用」後才有邀請碼。')));
			return;
		}
		if (!res.ok) {
			box.replaceChildren(E('em', {}, res.reason || _('無法產生邀請碼')));
			return;
		}
		var code = E('input', { 'type': 'text', 'class': 'cbi-input-text', 'id': 'kuroshio-invite-code', 'readonly': 'readonly', 'value': res.code,
			'style': 'width:100%;font-family:monospace;font-size:12px' });
		var copy = function() {
			var done = function() { ui.addNotification(null, E('p', {}, _('已複製邀請碼')), 'info'); };
			// LuCI 常常用 http 開（不是安全環境，沒有 Clipboard API）：退回選取文字 + execCommand
			var legacy = function() {
				code.focus();
				code.select();
				var ok = false;
				try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
				if (ok) done(); else ui.addNotification(null, E('p', {}, _('無法自動複製，請手動選取邀請碼')), 'warning');
			};
			if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(res.code).then(done, legacy);
			legacy();
		};
		var refresh = function() {
			ui.showModal(_('重新產生邀請碼'), [
				E('p', {}, _('重新產生後，舊的邀請碼立刻失效（已經加入的好友不受影響）。確定要重新產生嗎？')),
				E('div', { 'class': 'right' }, [
					E('button', { 'class': 'btn', 'click': ui.hideModal }, _('取消')), ' ',
					E('button', { 'class': 'btn cbi-button-negative', 'id': 'kuroshio-invite-confirm', 'click': ui.createHandlerFn(self, function() {
						ui.hideModal();
						return common.action('/api/community/invite/refresh', {}).then(function(x) {
							self.drawInvite(x);
							if (x && x.result && x.result.ok) ui.addNotification(null, E('p', {}, _('已重新產生邀請碼，舊的已失效')), 'info');
						});
					}) }, _('重新產生'))
				])
			]);
		};
		var qr = res.qr ? E('img', { 'id': 'kuroshio-invite-qr', 'alt': _('我的邀請碼 QR 碼'), 'width': 160, 'height': 160,
			'style': 'background:#fff;padding:4px;border-radius:4px', 'src': 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(res.qr) }) : '';
		box.replaceChildren(E('div', {}, [
			res.ready ? '' : E('p', { 'style': 'color:#b36b00' }, _('社群模式還沒就緒（%s）：好友暫時無法用這個邀請碼加你。').format((res.problems || []).join('；'))),
			E('div', { 'style': 'display:flex;gap:1em;flex-wrap:wrap;align-items:flex-start' }, [qr,
				E('div', { 'style': 'flex:1 1 18em;min-width:0' }, [code,
					E('div', { 'style': 'font-size:12px;opacity:.75;margin:.3em 0' }, _('建立於 %s　身分指紋 %s').format(fmtTime(res.createdAt), res.fingerprint || '-')),
					E('div', { 'style': 'display:flex;gap:.5em;flex-wrap:wrap' }, [
						E('button', { 'class': 'btn cbi-button', 'click': copy }, _('複製邀請碼')),
						E('button', { 'class': 'btn cbi-button cbi-button-negative', 'click': refresh }, _('重新產生'))]),
					E('p', { 'style': 'font-size:12px;opacity:.75' }, _('邀請碼等同好友密碼：只給想加的好友，可以重複使用；外流時按「重新產生」，舊的立刻失效。'))])])
		]));
	},

	useInvite: function(input, out) {
		var self = this, code = input.value.replace(/\s+/g, '');
		if (!code) { out.replaceChildren(E('em', {}, _('請先貼上好友的邀請碼'))); return; }
		out.replaceChildren(E('em', {}, _('驗證中…（會回連對方確認身分，最多約 30 秒）')));
		return common.action('/api/community/invite/use', { code: code }).then(function(r) {
			var d = r && r.result;
			if (!r || r.ok === false || !d) { out.replaceChildren(E('p', { 'style': 'color:#c00' }, (r && r.error) || _('服務沒有在執行，或社群模式沒有啟用'))); return; }
			if (d.error && !d.steps) { out.replaceChildren(E('p', { 'style': 'color:#c00' }, d.error)); return; }
			var steps = (d.steps || []).map(function(s) {
				return E('li', {}, [E('strong', { 'style': 'color:' + (s.ok ? 'green' : '#c00') }, s.ok ? _('完成') : _('失敗')), ' ', s.text]);
			});
			var verdict = d.ok ? (d.stage === 'accepted' ? _('已成為好友：%s').format(d.domain) : _('已送出請求，等待 %s 審核').format(d.domain)) : (d.reason || _('加好友失敗'));
			out.replaceChildren(E('div', { 'id': 'kuroshio-invite-result' }, [
				E('ol', {}, steps),
				(d.problems || []).length ? E('ul', { 'class': 'kuroshio-invite-problems' }, d.problems.map(function(p) { return E('li', {}, p); })) : '',
				E('p', { 'style': 'font-weight:bold;color:' + (d.ok ? 'green' : '#c00') }, verdict)]));
			if (d.ok) { input.value = ''; return self.refresh(); }
		});
	},

	refresh: function() {
		var self = this;
		return Promise.all([
			L.resolveDefault(common.api('/api/community/status'), null),
			L.resolveDefault(common.api('/api/community/peers'), null),
			L.resolveDefault(common.api('/api/community/events'), null)
		]).then(function(r) {
			self.statusBox.replaceChildren(self.renderStatus(r[0]));
			self.peerBox.replaceChildren(self.renderPeers(r[1] && r[1].result));
			var ev = (r[2] && r[2].result) || [];
			self.eventBox.replaceChildren(common.pre(ev.slice(0, 80).map(function(e) {
				return fmtTime(e.at) + '  ' + e.domain + '  ' + e.type + (e.detail ? '（' + e.detail + '）' : '');
			}).join('\n') || _('沒有紀錄')));
		});
	},

	render: function(data) {
		var self = this, pro = common.isPro();
		var m, s, o;

		this.statusBox = E('div', {}, this.renderStatus(data[1]));
		this.peerBox = E('div', {}, E('em', {}, _('讀取中…')));
		this.eventBox = E('div');
		this.inviteBox = E('div', {}, E('em', {}, _('讀取中…')));
		var inviteInput = E('input', { 'type': 'text', 'class': 'cbi-input-text', 'id': 'kuroshio-invite-input', 'placeholder': 'KRS1.…',
			'spellcheck': 'false', 'autocomplete': 'off', 'style': 'flex:1 1 18em;min-width:0;font-family:monospace' });
		var inviteOut = E('div', { 'id': 'kuroshio-invite-out' });
		var useInvite = function() { return self.useInvite(inviteInput, inviteOut); };
		inviteInput.addEventListener('keydown', function(ev) { if (ev.key === 'Enter') { ev.preventDefault(); useInvite(); } });

		var input = E('input', { 'type': 'text', 'class': 'cbi-input-text', 'placeholder': 'dns.friend.com', 'style': 'max-width:22em' });
		var add = function() {
			var d = input.value.trim();
			if (!d) return;
			return self.act('/api/community/add', { domain: d }, _('已送出好友請求')).then(function() { input.value = ''; });
		};
		input.addEventListener('keydown', function(ev) { if (ev.key === 'Enter') { ev.preventDefault(); add(); } });

		// 頁面標題放最上面（表單在頁面下半部）
		var header = E([], [
			E('h2', {}, _('黑潮 DNS · 社群')),
			E('div', { 'class': 'cbi-map-descr' }, _('跟好友交換台灣節點池、網站驗證結果、上游 DNS。只分享自己驗證過的資料；收到的資料一律在本機驗證後才使用，CDN 官方範圍外的 IP 直接丟掉。'))
		]);
		m = new form.Map('kuroshio');

		s = m.section(form.NamedSection, 'community', 'community', _('設定'),
			_('需要先在「基本設定」設好網域、憑證，並打開 DoH 或 DoT 其中一種（共享走同一個加密連線，不另開埠）。'));
		o = s.option(form.Flag, 'enabled', _('啟用社群模式'));
		o.rmempty = false;
		o = common.flag(s, null, 'share_domains', _('分享網站驗證結果'), 'community.shareDomains', _('只分享網域雜湊，不公開網站名稱。'));
		o = common.flag(s, null, 'share_upstreams', _('分享上游 DNS'), 'community.shareUpstreams', _('好友收到後只當每日評測的候選。'));
		common.num(s, null, 'stale_days', _('好友幾天連不上就自動刪除'), 'community.staleDays');
		if (pro) {
			common.num(s, null, 'reject_days', _('拒絕後幾天才能再請求'), 'community.rejectDays');
			common.num(s, null, 'sync_interval', _('多久向好友拉一次資料（分鐘）'), 'community.syncIntervalMin');
			common.num(s, null, 'max_friends', _('好友數上限'), 'community.maxFriends', _('達到上限後，自動同意的請求改成人工審核。'));
			common.num(s, null, 'min_hit_rate', _('命中率下限'), 'community.minHitRate', _('好友給的資料在我這邊驗證成功的比例（0～1），試過 20 次以上還低於這個就自動刪除。0 = 不檢查。'), 'ufloat');
			common.num(s, null, 'pow_bits', _('好友請求的工作量證明難度'), 'community.powBits', _('越高越難灌請求，但對方送請求也越久。'));
		}

		// 自動規則
		s = m.section(form.GridSection, 'community_rule', _('自動規則'),
			_('收到好友請求時由上往下比對，第一條「所有有填的條件都符合」的規則決定動作；都不符合就等人工審核。你刪除過的對象一律人工審核。'));
		s.anonymous = true;
		s.addremove = true;
		s.sortable = true;
		s.nodescriptions = true;
		o = s.option(form.Flag, 'enabled', _('啟用'));
		o.default = '1';
		o.rmempty = false;
		o.editable = true;
		o = s.option(form.Value, 'name', _('名稱'));
		o = s.option(form.ListValue, 'action', _('動作'));
		o.value('accept', _('同意'));
		o.value('manual', _('人工審核'));
		o.value('reject', _('拒絕'));
		o.value('block', _('封鎖'));
		o.default = 'accept';
		o = s.option(form.DynamicList, 'domain_suffix', _('網域結尾'), _('例如 friend.com'));
		o.modalonly = true;
		o = s.option(form.DynamicList, 'asn', _('電信業者 ASN'), _('例如 3462（中華電信）、4780（Seednet）、9924（台灣固網）、17421（遠傳）'));
		o.datatype = 'uinteger';
		o.modalonly = true;
		o = s.option(form.Flag, 'same_asn', _('跟我同一家電信業者'));
		o.modalonly = true;
		o = s.option(form.DynamicList, 'colo', _('Cloudflare 機房'), _('對方自報，例如 TPE、KHH'));
		o.modalonly = true;
		o = s.option(form.Value, 'max_rtt_ms', _('延遲上限（毫秒）'));
		o.datatype = 'uinteger';
		o.modalonly = true;
		o = s.option(form.Value, 'max_jitter_ms', _('抖動上限（毫秒）'));
		o.datatype = 'uinteger';
		o.modalonly = true;
		o = s.option(form.Value, 'max_loss', _('掉包率上限（%）'));
		o.datatype = 'range(0,100)';
		o.modalonly = true;
		o = s.option(form.Value, 'min_age_days', _('對方至少運作幾天'), _('對方自報，只能證明「至少」'));
		o.datatype = 'uinteger';
		o.modalonly = true;
		o = s.option(form.Value, 'min_mutual', _('至少幾個共同好友'));
		o.datatype = 'uinteger';
		o.modalonly = true;
		o = s.option(form.Value, 'max_friends', _('我的好友數少於'));
		o.datatype = 'uinteger';
		o.modalonly = true;

		var tools = E([], [
			E('div', { 'class': 'cbi-section', 'id': 'kuroshio-invite' }, [
				E('h3', {}, _('好友邀請碼')),
				E('p', { 'class': 'cbi-section-descr' }, _('互加好友最快的方法：把「我的邀請碼」傳給朋友，朋友貼到他的黑潮 DNS 就會自動成為好友，馬上開始交換資料。雙方都要先符合社群條件（網域、DoH / DoT / DoQ 至少一種、網域解析得到）。')),
				E('h4', {}, _('我的邀請碼')),
				this.inviteBox,
				E('h4', {}, _('貼上好友的邀請碼')),
				E('div', { 'style': 'display:flex;gap:.5em;flex-wrap:wrap' }, [inviteInput,
					E('button', { 'class': 'btn cbi-button cbi-button-action', 'click': ui.createHandlerFn(this, useInvite) }, _('加好友'))]),
				inviteOut
			]),
			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, _('新增好友')),
				E('p', { 'class': 'cbi-section-descr' }, _('輸入對方的網域（非標準埠可以寫成 網域:埠）。對方會回連驗證你的網域與憑證；你的出口 IP 必須跟網域解析出的 IP 一樣。')),
				E('div', { 'style': 'display:flex;gap:.5em;flex-wrap:wrap' }, [input,
					E('button', { 'class': 'btn cbi-button cbi-button-action', 'click': ui.createHandlerFn(this, add) }, _('送出請求'))])
			]),
			E('div', { 'class': 'cbi-section' }, [E('h3', {}, _('好友與請求')), this.peerBox]),
			E('div', { 'class': 'cbi-section' }, [E('h3', {}, _('事件紀錄')), this.eventBox])
		]);

		this.refresh();
		this.loadInvite();
		poll.add(L.bind(this.refresh, this), 15);
		return m.render().then(function(node) { return E([], [common.modeBar(), header, self.statusBox, tools, node, common.footer()]); });
	}
});
