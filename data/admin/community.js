'use strict';
// 黑潮 DNS 本機設定頁：社群（好友）面板。功能、用語跟 LuCI「服務 → 黑潮 DNS → 社群」一樣（規格 03 第 10 節）：
// 我的身分與自我檢查、新增好友（網域）、好友與請求（同意 / 拒絕 / 封鎖 / 刪除 / 解除封鎖 / 立即同步 / 指定管道）、
// 事件紀錄、自動規則（存在 community.rules，跟其他設定一起「儲存並套用」）。
// 掛在 app.js 的 WIDGETS 上（設定 → 社群）；伺服器給的字串一律用 textContent 放進頁面。
(function () {
	var K = window.KuroshioAdmin;
	if (!K) return;
	var el = K.el, clear = K.clear, api = K.api, badge = K.badge, actBtn = K.actBtn, fmtTime = K.fmtTime, toast = K.toast;

	var REL = { friend: '好友', out: '等待對方同意', 'in': '待我審核', none: '-' };
	var CHANNEL = { doq: 'DoQ', dot: 'DoT', https: 'HTTPS' };
	var KIND = { node: '節點池', site: '網站驗證', cross: '跨 CDN', upstream: '上游 DNS' };
	var POLL_MS = 15000;

	function day(t) { return new Date(t).toLocaleDateString('zh-TW'); }

	/** 狀態文字（跟 LuCI 的 peerState 一樣） */
	function peerState(p) {
		var now = Date.now();
		if (p.rel === 'friend') return REL.friend;
		if (p.myBlock) return '已封鎖';
		if (p.theirBlock) return '對方已封鎖你';
		if (p.rel === 'none' && p.rejectedUntil && p.rejectedUntil > now) return '已拒絕（' + day(p.rejectedUntil) + ' 前不能再請求）';
		if (p.rel === 'none' && p.theirRejectUntil && p.theirRejectUntil > now) return '對方拒絕（' + day(p.theirRejectUntil) + ' 前不能再請求）';
		if (p.rel === 'none' && p.deletedAt) return '已刪除';
		return REL[p.rel] || p.rel;
	}
	function stateKind(p) {
		if (p.rel === 'friend') return 'ok';
		if (p.rel === 'in') return 'warn';
		if (p.myBlock || p.theirBlock) return 'err';
		return p.rel === 'out' ? '' : 'off';
	}

	// ---------------------------------------------------------------- 資料與更新
	// 同一份資料畫在好幾個面板上：任何動作之後一起重新讀取；面板離開頁面後就不再更新
	var boxes = { status: [], peers: [], events: [] };
	var DRAW = {};
	var last = {};
	var timer = null, busy = null;

	function alive(list) { return list.filter(function (b) { return document.body.contains(b); }); }
	function refresh() {
		if (busy) return busy;
		busy = Promise.all([api('/api/community/status'), api('/api/community/peers'), api('/api/community/events')]).then(function (r) {
			busy = null;
			last = { status: r[0], peers: r[1], events: r[2] };
			var any = false;
			Object.keys(boxes).forEach(function (k) {
				boxes[k] = alive(boxes[k]);
				boxes[k].forEach(function (b) { DRAW[k](b, last[k]); });
				if (boxes[k].length) any = true;
			});
			if (!any && timer) { clearInterval(timer); timer = null; }
		});
		return busy;
	}
	function mount(kind, box) {
		boxes[kind].push(box);
		if (!timer) {
			timer = setInterval(function () { if (document.visibilityState === 'visible') refresh(); }, POLL_MS);
		}
		// 同一次畫面的幾個面板一起讀（下一個 tick 才送出）
		setTimeout(refresh, 0);
		return box;
	}
	/** 404 = 社群模式沒有啟用（服務沒有建立社群模組） */
	function offText() { return '社群模式沒有啟用：在下方「設定」打開「啟用社群模式」並儲存後才能使用。'; }
	function failBox(box, r) {
		box.appendChild(el('p', { class: r.status === 404 ? 'msg info' : 'msg err', text: r.status === 404 ? offText() : '讀取失敗：' + K.errText(r) }));
	}

	/** 送出動作（POST，參數放網址）；成功後重新讀取全部面板 */
	function act(path, params, okText, out) {
		var q = K.qs(params || {});
		return api(path + (q ? '?' + q : ''), { method: 'POST' }).then(function (r) {
			var d = r.data || {};
			var msg, kind;
			if (!r.ok) { msg = r.status === 404 ? offText() : '失敗：' + K.errText(r); kind = 'err'; }
			else if (d.ok === false) { msg = d.reason || '操作失敗'; kind = 'warn'; }
			else { msg = okText || '完成'; kind = 'ok'; }
			if (out) {
				clear(out);
				out.appendChild(el('p', { class: 'msg ' + kind, text: msg }));
			}
			toast(msg, kind !== 'ok');
			return refresh().then(function () { return kind === 'ok'; });
		});
	}

	// ---------------------------------------------------------------- 我的身分
	DRAW.status = function (box, r) {
		clear(box);
		if (!r.ok) { failBox(box, r); return; }
		var s = r.data || {};
		if (!s.enabled) { box.appendChild(el('p', { class: 'msg info', text: '社群模式沒有啟用：在下方打開並「儲存並套用」。' })); return; }
		var c = s.check || {}, ep = s.endpoints || {}, n = s.counts || {};
		var problems = [].concat(c.problems || []);
		var rows = [
			['狀態', s.ready ? badge('就緒', 'ok') : el('div', {}, [badge('未就緒', 'err'),
				el('ul', { class: 'cm-problems', id: 'cm-problems' }, problems.map(function (p) { return el('li', { text: p }); }))])],
			['網域', s.domain || '-'],
			['公鑰指紋', el('code', { text: s.fingerprint || '-' })],
			['對外網址', [ep.doh, ep.dot, ep.doq].filter(Boolean).join('　') || '-'],
			['憑證', c.cert && c.cert.validTo ? c.cert.validTo + ' 到期（剩 ' + c.cert.daysLeft + ' 天）' : '-'],
			['外部連線', s.externalConfirmed ? '已由 ' + s.externalConfirmed.from + ' 於 ' + fmtTime(s.externalConfirmed.at) + ' 連入確認' : '還沒有其他節點連進來過（加好友時對方會回連驗證）'],
			['好友', '好友 ' + (n.friends || 0) + '　待我審核 ' + (n.incoming || 0) + '　等待對方同意 ' + (n.outgoing || 0) + '　已封鎖 ' + (n.blocked || 0)],
			['自我檢查', c.at ? fmtTime(c.at) : '-']
		];
		if (s.txt && s.txt.value && s.domain) {
			rows.push(['TXT 記錄（選用）', el('div', {}, [
				el('div', { class: 'mono', text: s.txt.name + '  TXT  "' + s.txt.value + '"' }),
				el('div', { class: 'muted', text: '有設定時好友會多比對一次金鑰（第二管道）；沒設定也可以。' })])]);
		}
		if (s.rotation) rows.push(['金鑰輪替', '已換新金鑰，舊金鑰到 ' + fmtTime(s.rotation.until) + ' 前仍有效（好友會自動更新）']);
		var tb = el('tbody');
		rows.forEach(function (x) { tb.appendChild(el('tr', {}, [el('th', { text: x[0] }), el('td', {}, x[1])])); });
		box.appendChild(el('div', { class: 'table-wrap' }, el('table', { class: 'kv' }, tb)));
		box.appendChild(el('div', { class: 'tbl-actions' }, [
			actBtn('重新檢查', 'small', function () { return act('/api/community/check', {}, '已重新檢查'); }),
			actBtn('更換金鑰', 'small danger', function () {
				if (!window.confirm('產生新的身分金鑰並通知所有好友（舊金鑰在過渡期內仍有效）。確定要更換嗎？')) return;
				return act('/api/community/rotate', {}, '已更換金鑰並通知好友');
			})
		]));
	};
	function communityStatus() {
		return mount('status', el('div', { class: 'cm', id: 'community-status' }, el('p', { class: 'muted', text: '讀取中…' })));
	}

	// ---------------------------------------------------------------- 新增好友（網域）
	function communityAdd() {
		var input = el('input', { type: 'text', id: 'community-add-input', placeholder: 'dns.friend.com', 'aria-label': '好友的網域', spellcheck: 'false', autocomplete: 'off' });
		var out = el('div', { id: 'community-add-result', 'aria-live': 'polite' });
		var add = function () {
			var d = input.value.trim();
			if (!d) return;
			clear(out);
			out.appendChild(el('p', { class: 'muted', text: '送出中…（會回連對方確認身分，最多約 30 秒）' }));
			return act('/api/community/add', { domain: d }, '已送出好友請求', out).then(function (ok) { if (ok) input.value = ''; });
		};
		input.addEventListener('keydown', function (ev) { if (ev.key === 'Enter') { ev.preventDefault(); add(); } });
		return el('div', { id: 'community-add' }, [el('div', { class: 'tbl-actions cm-add' }, [input, actBtn('送出請求', 'primary', add)]), out]);
	}

	// ---------------------------------------------------------------- 好友與請求
	function quality(p) {
		var sc = p.scores || {};
		var parts = Object.keys(KIND).map(function (k) {
			var x = sc[k];
			if (!x || !(x.ok + x.fail + x.invalid)) return null;
			return KIND[k] + ' ' + Math.round(100 * x.score) + '%' + (x.paused ? '（暫停）' : '');
		}).filter(Boolean);
		return parts.length ? parts.join('、') : '-';
	}
	function peerCard(p) {
		var d = p.domain, info = p.info || {}, st = p.stats || {};
		var btn = function (label, path, params, cls, ok, confirmText) {
			return actBtn(label, 'small ' + (cls || ''), function () {
				if (confirmText && !window.confirm(confirmText)) return;
				return act(path, params, ok);
			});
		};
		var acts = [];
		if (p.rel === 'in') {
			acts.push(btn('同意', '/api/community/accept', { domain: d }, 'primary', '已同意'),
				btn('拒絕', '/api/community/reject', { domain: d }, '', '已拒絕'),
				btn('封鎖', '/api/community/block', { domain: d }, 'danger', '已封鎖', '封鎖 ' + d + '？對方之後的請求一律不受理。'));
		} else if (p.rel === 'friend') {
			acts.push(btn('立即同步', '/api/community/sync', { domain: d }, '', '已同步'),
				btn('刪除', '/api/community/delete', { domain: d }, 'danger', '已刪除', '刪除好友 ' + d + '？'),
				btn('刪除並封鎖', '/api/community/delete', { domain: d, block: '1' }, 'danger', '已刪除並封鎖', '刪除並封鎖 ' + d + '？對方之後的請求一律不受理。'));
		} else if (p.rel === 'out') {
			acts.push(btn('取消', '/api/community/delete', { domain: d }, '', '已取消'));
		}
		if (p.myBlock) acts.push(btn('解除封鎖', '/api/community/unblock', { domain: d }, '', '已解除封鎖'));
		else if (p.rel === 'none') acts.push(btn('加好友', '/api/community/add', { domain: d }, 'primary', '已送出請求'));
		if (p.pendingKey) {
			acts.push(btn('接受新金鑰', '/api/community/accept-key', { domain: d }, '', '已接受新金鑰',
				'確定是 ' + d + ' 本人換的金鑰嗎？新指紋：' + (p.pendingKey.fingerprint || '-')));
		}
		if (p.rel === 'friend') {
			var sel = el('select', { 'aria-label': '指定管道', class: 'cm-channel' });
			[['', '管道：自動'], ['doq', 'DoQ 優先'], ['dot', 'DoT 優先'], ['https', 'HTTPS 優先']].forEach(function (o) {
				sel.appendChild(el('option', { value: o[0], text: o[1] }));
			});
			sel.value = p.preferChannel || '';
			sel.addEventListener('change', function () {
				sel.disabled = true;
				act('/api/community/channel', { domain: d, channel: sel.value || 'auto' }, '已指定管道').then(function () { sel.disabled = false; });
			});
			acts.push(sel);
		}

		var hit = st.tried ? Math.round(100 * (st.ok || 0) / st.tried) + '%（' + st.ok + '/' + st.tried + '）' : '-';
		var kv = [
			['業者 · 機房', (info.asn ? 'AS' + info.asn : '-') + (info.colo ? ' · ' + info.colo : '')],
			['連線品質', info.rttMs != null ? info.rttMs + ' ms（抖動 ' + (info.jitterMs || 0) + '、掉包 ' + (info.lossPct || 0) + '%）' : '-'],
			['最後同步', fmtTime(p.lastSyncOk)],
			['提供筆數', (st.offered || 0) + (st.invalid ? ' / 違規 ' + st.invalid : '')],
			['命中率', hit],
			['資料品質', quality(p)],
			['管道', p.channel ? (CHANNEL[p.channel] || p.channel) + (p.preferChannel ? '（指定 ' + (CHANNEL[p.preferChannel] || p.preferChannel) + '）' : '') : '-'],
			['加入', p.invitedAt ? '透過邀請碼，' + fmtTime(p.invitedAt) : (p.friendSince ? '成為好友 ' + fmtTime(p.friendSince) : '-')]
		];
		var notes = [];
		if (p.lastError) notes.push(el('p', { class: 'cell-err', text: p.lastError }));
		if (p.oldVersion) notes.push(el('p', { class: 'msg warn', text: '對方版本較舊（v1），每 6 小時重試' }));
		if (p.pendingKey) notes.push(el('p', { class: 'msg warn', text: '對方換了金鑰，但沒有用舊金鑰簽名：確認是對方本人換的才接受。新指紋 ' + (p.pendingKey.fingerprint || '-') }));
		if (p.autoBlockAt) notes.push(el('p', { class: 'muted', text: '自動封鎖於 ' + fmtTime(p.autoBlockAt) }));
		return el('div', { class: 'cm-peer', 'data-domain': d, 'data-rel': p.rel }, [
			el('div', { class: 'cm-peer-head' }, [
				el('strong', { class: 'mono', text: d }),
				badge(peerState(p), stateKind(p)),
				p.fingerprint ? el('span', { class: 'muted mono', text: String(p.fingerprint).slice(0, 19) + '…' }) : null
			]),
			notes.length ? el('div', {}, notes) : null,
			el('dl', { class: 'cm-kv' }, kv.map(function (x) { return el('div', {}, [el('dt', { text: x[0] }), el('dd', { text: x[1] })]); })),
			acts.length ? el('div', { class: 'tbl-actions' }, acts) : null
		]);
	}
	DRAW.peers = function (box, r) {
		clear(box);
		if (!r.ok) { failBox(box, r); return; }
		var peers = [].concat(r.data || []);
		if (!peers.length) { box.appendChild(el('p', { class: 'muted cm-empty', text: '還沒有好友' })); return; }
		peers.forEach(function (p) { box.appendChild(peerCard(p)); });
	};
	function communityPeers() {
		return mount('peers', el('div', { class: 'cm cm-peers', id: 'community-peers' }, el('p', { class: 'muted', text: '讀取中…' })));
	}

	// ---------------------------------------------------------------- 事件紀錄
	DRAW.events = function (box, r) {
		clear(box);
		if (!r.ok) { failBox(box, r); return; }
		var ev = [].concat(r.data || []);
		box.appendChild(el('pre', { class: 'out cm-events', text: ev.slice(0, 80).map(function (e) {
			return fmtTime(e.at) + '  ' + e.domain + '  ' + e.type + (e.detail ? '（' + e.detail + '）' : '');
		}).join('\n') || '沒有紀錄' }));
	};
	function communityEvents() {
		return mount('events', el('div', { class: 'cm', id: 'community-events' }, el('p', { class: 'muted', text: '讀取中…' })));
	}

	// ---------------------------------------------------------------- 自動規則（community.rules）
	var ACTIONS = [['accept', '同意'], ['manual', '人工審核'], ['reject', '拒絕'], ['block', '封鎖']];
	// 條件：跟 LuCI 的自動規則欄位一樣（list = 一行一個或用逗號分開；uint = 非負整數）
	var CONDS = [
		{ key: 'domain_suffix', type: 'list', label: '網域結尾', help: '例如 friend.com' },
		{ key: 'asn', type: 'list', num: true, label: '電信業者 ASN', help: '例如 3462（中華電信）、4780（Seednet）、9924（台灣固網）、17421（遠傳）' },
		{ key: 'same_asn', type: 'bool', label: '跟我同一家電信業者' },
		{ key: 'colo', type: 'list', upper: true, label: 'Cloudflare 機房', help: '對方自報，例如 TPE、KHH' },
		{ key: 'max_rtt_ms', type: 'uint', label: '延遲上限（毫秒）' },
		{ key: 'max_jitter_ms', type: 'uint', label: '抖動上限（毫秒）' },
		{ key: 'max_loss', type: 'uint', max: 100, label: '掉包率上限（%）' },
		{ key: 'min_age_days', type: 'uint', label: '對方至少運作幾天', help: '對方自報，只能證明「至少」' },
		{ key: 'min_mutual', type: 'uint', label: '至少幾個共同好友' },
		{ key: 'max_friends', type: 'uint', label: '我的好友數少於' },
		{ key: 'require_ip_match', type: 'bool', pro: true, label: '來源 IP 要在對方網域的解析結果裡' },
		{ key: 'has_txt', type: 'bool', pro: true, label: '對方有設定 _kuroshio TXT 記錄' }
	];
	var RULES_KEY = 'community.rules';

	function listText(v) { return [].concat(v == null ? [] : v).join(', '); }
	function condSummary(r) {
		var parts = CONDS.filter(function (c) {
			var v = r[c.key];
			return c.type === 'bool' ? v === true || v === 1 || v === '1' : (Array.isArray(v) ? v.length : v != null && v !== '');
		}).map(function (c) { return c.type === 'bool' ? c.label : c.label + ' ' + listText(r[c.key]); });
		return parts.length ? parts.join('；') : '沒有條件（所有請求都符合）';
	}
	/** 檢查一個條件的輸入；回 { val } 或 { err }，val = undefined 表示不填 */
	function parseCond(c, s) {
		s = String(s).trim();
		if (c.type === 'list') {
			var arr = s.split(/[\s,，、]+/).filter(Boolean);
			if (!arr.length) return { val: undefined };
			for (var i = 0; i < arr.length; i++) {
				var x = arr[i];
				if (c.num) {
					if (!/^\d{1,10}$/.test(x)) return { err: c.label + '「' + x + '」要是數字' };
				} else if (c.upper) {
					if (!/^[A-Za-z]{3}$/.test(x)) return { err: c.label + '「' + x + '」要是三個英文字母' };
				} else if (!/^\.?[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.?$/.test(x)) {
					return { err: c.label + '「' + x + '」不是網域' };
				}
			}
			return { val: arr.map(function (x) { return c.num ? Number(x) : (c.upper ? x.toUpperCase() : x.toLowerCase()); }) };
		}
		if (!s) return { val: undefined };
		if (!/^\d{1,9}$/.test(s)) return { err: c.label + '要是非負整數' };
		var n = Number(s);
		if (c.max != null && n > c.max) return { err: c.label + '最大 ' + c.max };
		return { val: n };
	}

	function communityRules() {
		var orig = K.value(RULES_KEY);
		var rules = JSON.parse(JSON.stringify(Array.isArray(orig) ? orig : []));
		var errs = {};
		var list = el('div', { class: 'cm-rules', id: 'community-rules' });
		var commit = function () {
			var e = Object.keys(errs).map(function (k) { return errs[k]; });
			K.setValue(RULES_KEY, JSON.parse(JSON.stringify(rules)), e.length ? e.join('；') : null);
		};
		var draw = function () {
			clear(list);
			if (!rules.length) list.appendChild(el('p', { class: 'muted cm-empty', text: '沒有規則：所有請求都等人工審核' }));
			rules.forEach(function (r, i) {
				var en = el('input', { type: 'checkbox', checked: r.enabled !== false && r.enabled !== 0 && r.enabled !== '0', 'aria-label': '啟用第 ' + (i + 1) + ' 條規則' });
				en.addEventListener('change', function () { r.enabled = en.checked; commit(); });
				var name = el('input', { type: 'text', class: 'cm-rule-name', placeholder: '名稱', 'aria-label': '第 ' + (i + 1) + ' 條規則的名稱', value: r.name || '' });
				name.addEventListener('input', function () { if (name.value.trim()) r.name = name.value.trim(); else delete r.name; commit(); });
				var action = el('select', { 'aria-label': '第 ' + (i + 1) + ' 條規則的動作' });
				ACTIONS.forEach(function (a) { action.appendChild(el('option', { value: a[0], text: a[1] })); });
				action.value = r.action || 'manual';
				action.addEventListener('change', function () { r.action = action.value; commit(); });
				var move = function (to) {
					return function () {
						var x = rules.splice(i, 1)[0];
						rules.splice(to, 0, x);
						errs = {};
						draw();
						commit();
					};
				};
				var summary = el('span', { class: 'muted', text: condSummary(r) });
				var conds = el('div', { class: 'cm-conds' });
				CONDS.filter(function (c) { return K.isPro() || !c.pro || r[c.key] != null; }).forEach(function (c) {
					var id = 'cm-r' + i + '-' + c.key;
					var errKey = i + '.' + c.key;
					var row;
					if (c.type === 'bool') {
						var cb = el('input', { type: 'checkbox', id: id, checked: r[c.key] === true || r[c.key] === 1 || r[c.key] === '1' });
						cb.addEventListener('change', function () { if (cb.checked) r[c.key] = true; else delete r[c.key]; summary.textContent = condSummary(r); commit(); });
						row = el('label', { class: 'chk cm-cond' }, [cb, el('span', { text: c.label })]);
					} else {
						var inp = el('input', { type: 'text', id: id, spellcheck: 'false', autocomplete: 'off', inputmode: c.type === 'uint' || c.num ? 'numeric' : null,
							value: c.type === 'list' ? listText(r[c.key]) : (r[c.key] == null ? '' : String(r[c.key])) });
						var et = el('span', { class: 'err-text', hidden: true });
						inp.addEventListener('input', function () {
							var p = parseCond(c, inp.value);
							inp.classList.toggle('invalid', !!p.err);
							et.textContent = p.err || '';
							et.hidden = !p.err;
							if (p.err) errs[errKey] = '第 ' + (i + 1) + ' 條規則：' + p.err;
							else {
								delete errs[errKey];
								if (p.val === undefined) delete r[c.key]; else r[c.key] = p.val;
							}
							summary.textContent = condSummary(r);
							commit();
						});
						row = el('div', { class: 'cm-cond' }, [el('label', { for: id, text: c.label }), inp,
							c.help ? el('span', { class: 'muted', text: c.help }) : null, et]);
					}
					conds.appendChild(row);
				});
				list.appendChild(el('div', { class: 'cm-rule', 'data-index': String(i) }, [
					el('div', { class: 'cm-rule-head' }, [el('label', { class: 'chk' }, [en, el('span', { text: '啟用' })]), name, action,
						el('span', { class: 'cm-rule-btns' }, [
							el('button', { type: 'button', class: 'btn small', text: '↑', title: '往上移', 'aria-label': '第 ' + (i + 1) + ' 條規則往上移', disabled: i === 0, onclick: move(i - 1) }),
							el('button', { type: 'button', class: 'btn small', text: '↓', title: '往下移', 'aria-label': '第 ' + (i + 1) + ' 條規則往下移', disabled: i === rules.length - 1, onclick: move(i + 1) }),
							el('button', { type: 'button', class: 'btn small danger', text: '刪除', 'aria-label': '刪除第 ' + (i + 1) + ' 條規則',
								onclick: function () { rules.splice(i, 1); errs = {}; draw(); commit(); } })
						])]),
					el('details', { class: 'cm-rule-conds' }, [el('summary', {}, ['條件：', summary]), conds])
				]));
			});
		};
		draw();
		return el('div', {}, [list, el('div', { class: 'tbl-actions' }, [
			el('button', {
				type: 'button', class: 'btn small', id: 'community-rule-add', text: '新增規則',
				onclick: function () {
					rules.push({ enabled: true, name: '', action: 'accept' });
					draw();
					commit();
					var d = list.lastChild && list.lastChild.querySelector('details');
					if (d) d.open = true;
					var n = list.lastChild && list.lastChild.querySelector('.cm-rule-name');
					if (n) n.focus();
				}
			})]),
			el('p', { class: 'muted', text: '規則改完按下方「儲存並套用」才會生效。' })]);
	}

	K.widgets.communityStatus = communityStatus;
	K.widgets.communityAdd = communityAdd;
	K.widgets.communityPeers = communityPeers;
	K.widgets.communityEvents = communityEvents;
	K.widgets.communityRules = communityRules;
})();
