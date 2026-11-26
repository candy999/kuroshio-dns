'use strict';
// 「CDN 連線去向」圖（3.5.1，data/dashboard/dashboard.js 的 cdnFlow）的瀏覽器檢查：site-e2e.js、admin-e2e.js 共用。
// 數字跟 API 一致（前 5 家、其餘合併成「其他」、沒辨識出來的另外一塊；三塊加起來等於連線數）、
// 桌機是 SVG 流向圖、手機寬度（小於 600 px）是每家 CDN 一條堆疊橫條、沒有水平捲動、沒有資料與只有一兩筆時的空狀態。

/** 照 API 的 routing[] 算出圖上應該有的節點：[{ key, n, tw, acc, still }]，最後一筆是合計 */
function expectFlow(routing, top = 5) {
    const unk = p => !p || p === '?';
    const one = r => ({ key: r.provider || '', n: r.connections, tw: r.alreadyTw, acc: r.accelerated, still: r.stillAbroad });
    const rows = routing.filter(r => r.connections > 0).sort((a, b) => b.connections - a.connections);
    const named = rows.filter(r => !unk(r.provider)).map(one), u = rows.filter(r => unk(r.provider)).map(one);
    const sum = (list, key) => list.reduce((m, r) => ({ key, n: m.n + r.n, tw: m.tw + r.tw, acc: m.acc + r.acc, still: m.still + r.still }), { key, n: 0, tw: 0, acc: 0, still: 0 });
    const nodes = named.slice(0, top);
    if (named.length > top) nodes.push(sum(named.slice(top), '_other'));
    if (u.length) nodes.push(sum(u, '_unknown'));
    return [...nodes, sum(rows.map(one), '_total')];
}

/**
 * 檢查一張連線去向圖。`sel` 是圖的容器（.flowchart），`tableSel` 是它的數據表，`routing` 是 API 的 routing[]，`w` 是視窗寬度。
 * 回傳 [[條件, 說明, 細節], …]，由呼叫端逐條 check()
 */
async function checkFlow(page, sel, tableSel, routing, w, tag) {
    const out = [];
    const exp = expectFlow(routing);
    const got = await page.evaluate(([s, t]) => {
        const box = document.querySelector(s), tb = document.querySelector(t);
        const num = x => Number(String(x).split('（')[0].replace(/[^\d.]/g, ''));
        const rows = [...tb.querySelectorAll('tr')].slice(1).map(tr => {
            const c = [...tr.cells].map(td => td.textContent);
            return { key: tr.dataset.key, n: num(c[1]), tw: num(c[2]), acc: num(c[3]), still: num(c[4]), label: c[0] };
        });
        const stacks = [...box.querySelectorAll('.flow-stack')].map(st => [...st.children].reduce((a, d) => a + parseFloat(d.style.width), 0));
        const r = box.getBoundingClientRect();
        return {
            mode: box.dataset.mode, rows, svg: box.querySelectorAll('svg').length,
            leftNodes: [...box.querySelectorAll('svg rect.node:not(.part)')].map(n => ({ key: n.dataset.key, n: +n.dataset.n })),
            partNodes: [...box.querySelectorAll('svg rect.node.part')].map(n => ({ key: n.dataset.key, n: +n.dataset.n })),
            bandSum: [...box.querySelectorAll('svg path.band')].reduce((a, p) => a + +p.dataset.n, 0),
            bars: box.querySelectorAll('.flow-bars .flow-row').length, stacks, right: r.right, legend: box.querySelectorAll('.flow-legend i').length,
            note: (box.querySelector('.flow-note') || {}).textContent || ''
        };
    }, [sel, tableSel]);
    const same = (a, b) => a.length === b.length && a.every((x, i) => x.key === b[i].key && ['n', 'tw', 'acc', 'still'].every(k => Math.abs(x[k] - b[i][k]) < 0.5));
    out.push([same(got.rows, exp), `${tag}：連線去向的數據表跟 API 一致（前 5 家＋其他＋合計）`, JSON.stringify({ got: got.rows, exp }).slice(0, 600)]);
    const total = exp[exp.length - 1];
    out.push([got.rows.every(r => Math.abs(r.tw + r.acc + r.still - r.n) < 0.5), `${tag}：三塊加起來等於連線數`, JSON.stringify(got.rows).slice(0, 300)]);
    out.push([got.legend === 3, `${tag}：圖例三塊（顏色＋圖樣＋文字）`, String(got.legend)]);
    if (exp.some(r => r.key === '_other')) out.push([/其他 \d+ 家.*合併/.test(got.note), `${tag}：說明「其他」是合併起來的`, got.note]);
    if (w >= 600) {
        out.push([got.mode === 'svg' && got.svg === 1 && got.bars === 0, `${tag}：桌機是兩段式流向圖（SVG）`, `${got.mode} svg=${got.svg} bars=${got.bars}`]);
        out.push([same(got.leftNodes.map(n => ({ ...n, tw: 0, acc: 0, still: 0 })), exp.slice(0, -1).map(r => ({ key: r.key, n: r.n, tw: 0, acc: 0, still: 0 }))),
            `${tag}：左邊的節點依連線數排序、寬度跟 API 一致`, JSON.stringify(got.leftNodes)]);
        out.push([got.partNodes.length === 3 && Math.abs(got.partNodes[0].n - total.tw) < .5 && Math.abs(got.partNodes[1].n - total.acc) < .5 && Math.abs(got.partNodes[2].n - total.still) < .5,
            `${tag}：右邊三塊（原本就在台灣、拉回台灣、仍在國外）`, JSON.stringify(got.partNodes)]);
        out.push([Math.abs(got.bandSum - total.n) < .5, `${tag}：流線加起來等於全部連線`, `${got.bandSum} / ${total.n}`]);
    } else {
        out.push([got.mode === 'bars' && got.svg === 0 && got.bars === exp.length - 1, `${tag}：手機寬度改成每家 CDN 一條堆疊橫條`, `${got.mode} svg=${got.svg} bars=${got.bars}`]);
        out.push([got.stacks.every(x => Math.abs(x - 100) < 0.01), `${tag}：每條橫條是 100%`, got.stacks.join(', ')]);
        out.push([got.right <= w + 0.5, `${tag}：連線去向沒有超出畫面`, String(got.right)]);
    }
    return out;
}

/** 空狀態：沒有資料、只有一兩筆時不畫圖；沒辨識出來的 CDN 跟「其他」分開 */
async function checkFlowEmpty(page, tag) {
    const r = await page.evaluate(() => {
        const KD = window.KuroshioDashboard;
        const d = document.createElement('div'); d.className = 'chart flowchart'; const t = document.createElement('table');
        (document.querySelector('.kd') || document.body).appendChild(d);
        const res = {};
        const run = (k, rows) => { const x = KD.cdnFlow(d, t, rows); res[k] = { mode: x.mode, svg: d.querySelectorAll('svg').length, text: d.textContent, rows: t.rows.length, keys: x.nodes.map(n => n.key) }; };
        run('none', []);
        run('zero', [{ provider: 'cloudflare', label: 'Cloudflare', connections: 0, wouldGoAbroad: 0, accelerated: 0, stillAbroad: 0 }]);
        run('few', [{ provider: 'cloudflare', label: 'Cloudflare', connections: 2, wouldGoAbroad: 1, accelerated: 1, stillAbroad: 0, alreadyTw: 1 }]);
        // 舊版核心沒有 alreadyTw：用 連線 − 拉回 − 仍在國外；provider 空白 = 沒辨識出來，跟量小合併的「其他」分開
        const many = ['cloudflare', 'cloudfront', 'akamai', 'apple', 'azure', 'gcore', 'line'].map((p, i) => ({ provider: p, label: p, connections: 700 - i * 100, wouldGoAbroad: 50, accelerated: 30, stillAbroad: 20 }));
        many.push({ provider: '', label: '', connections: 40, wouldGoAbroad: 10, accelerated: 4, stillAbroad: 6 });
        run('many', many);
        res.many.tw = KD.flowRows(many).total.tw;
        d.remove();
        return res;
    });
    return [
        [r.none.mode === 'empty' && r.none.svg === 0 && /資料累積中/.test(r.none.text) && r.none.rows === 0, `${tag}：連線去向沒有資料時顯示「資料累積中」、不畫圖`, JSON.stringify(r.none)],
        [r.zero.mode === 'empty' && r.zero.svg === 0, `${tag}：連線數都是 0 也是空狀態`, JSON.stringify(r.zero)],
        [r.few.mode === 'few' && r.few.svg === 0 && /只比對了 2 次/.test(r.few.text) && r.few.rows === 3, `${tag}：只有一兩筆時說明累積中、不畫圖，數據表照樣列`, JSON.stringify(r.few)],
        [JSON.stringify(r.many.keys) === JSON.stringify(['cloudflare', 'cloudfront', 'akamai', 'apple', 'azure', '_other', '_unknown']) && r.many.tw === 2800 - 350 + 30,
            `${tag}：前 5 家＋「其他」＋「未辨識的 CDN」分開；沒有 alreadyTw 時用 連線 − 拉回 − 仍在國外`, JSON.stringify(r.many)]
    ];
}

/**
 * 其他圖的「其他」與「沒辨識出來」（3.5.1）：跨 CDN 的配對、路由地圖的數據表。用固定的資料直接呼叫，
 * 不受測試環境的 CDN 資料庫影響
 */
async function checkOtherParts(page, tag) {
    const r = await page.evaluate(() => {
        const KD = window.KuroshioDashboard;
        const host = document.querySelector('.kd') || document.body;
        const c = document.createElement('div'); c.className = 'card glass cross'; host.appendChild(c);
        KD.crossCard(c, {
            explored: 10, ok: 4, fail: 6, successRate: .4, serves: 30, byFrom: [], byTo: [{ provider: '?', label: '?', sites: 1 }],
            pairs: [{ from: 'fastly', fromLabel: 'Fastly', to: 'cloudflare', toLabel: 'Cloudflare', count: 20 }, { from: 'fastly', fromLabel: 'Fastly', to: '?', toLabel: '?', count: 6 }],
            pairsOther: { pairs: 3, count: 4 }
        });
        const pairs = [...c.querySelectorAll('.pair')].map(p => p.className + '|' + p.textContent);
        c.remove();
        const m = document.createElement('div'); m.className = 'mapwrap chart'; m.style.width = '800px'; host.appendChild(m);
        const t = document.createElement('table'), note = document.createElement('span');
        KD.routeMap(m, t, [{ pop: 'NRT', count: 50, fixed: 30 }, { pop: 'ZZZ', count: 7, fixed: 0 }], { TPE: 30 }, note, { pops: 4, count: 9, fixed: 2 });
        const rows = [...t.rows].map(tr => tr.className + '|' + tr.textContent);
        m.remove();
        return { pairs, rows, note: note.textContent };
    });
    return [
        [r.pairs.length === 3 && /unknown/.test(r.pairs[1]) && /未辨識的 CDN/.test(r.pairs[1]) && /other/.test(r.pairs[2]) && /其他 3 組/.test(r.pairs[2]),
            `${tag}：跨 CDN 配對的「未辨識」跟「其他 3 組」分開、其他排最後`, JSON.stringify(r.pairs)],
        [r.rows.length === 4 && /unknown/.test(r.rows[2]) && /ZZZ（沒辨識出位置/.test(r.rows[2]) && /other/.test(r.rows[3]) && /其他 4 個機房/.test(r.rows[3]),
            `${tag}：路由地圖的數據表：沒辨識出位置的機房跟「其他 4 個機房」分開`, JSON.stringify(r.rows)],
        [/沒辨識出位置/.test(r.note) && /合併成「其他」/.test(r.note), `${tag}：路由地圖的說明分開寫沒辨識出來與合併的`, r.note]
    ];
}

module.exports = { expectFlow, checkFlow, checkFlowEmpty, checkOtherParts };
