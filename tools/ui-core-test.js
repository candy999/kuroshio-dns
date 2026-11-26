'use strict';
// CI：介面共用邏輯 data/shared/ui-core.js 的測試向量（data/shared/ui-core.tests.json）逐一檢查，不需要瀏覽器、不需要安裝套件
//   node tools/ui-core-test.js
// 另外用同一組 fmtTime、regionLabel 向量檢查共用儀表板 data/dashboard/dashboard.js 的 KuroshioDashboard.fmtTime（兩份規則必須一致）
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.resolve(__dirname, '..');
const vectors = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'shared', 'ui-core.tests.json'), 'utf-8'));
// 沒有指定時區參數的 fmtTime 案例用固定的本地時區（在任何 Date 運算之前設定）
process.env.TZ = vectors.tz || 'Asia/Taipei';

const core = require(path.join(ROOT, 'data', 'shared', 'ui-core.js'));
// 一般瀏覽器的載入方式：沒有 module，只有 window
const win = {};
vm.runInNewContext(fs.readFileSync(path.join(ROOT, 'data', 'shared', 'ui-core.js'), 'utf-8'), { window: win });
const dash = {};
vm.runInNewContext(fs.readFileSync(path.join(ROOT, 'data', 'dashboard', 'dashboard.js'), 'utf-8'), { window: dash, Intl });

let pass = 0, fail = 0;
const norm = v => (v === undefined ? undefined : JSON.parse(JSON.stringify(v)));
const check = (ok, msg) => { if (ok) pass++; else { fail++; console.log(`  ✘ ${msg}`); } };
const TR = { bracket: s => '[' + s + ']' };
// 參數 "bracket" 換成翻譯函式的函式
const TAKES_TR = ['restoreSummary', 'controlSummary', 'benchScope', 'regionLabel', 'upstreamExtra', 'paceView', 'cdnStoreText', 'agoText', 'freshnessView', 'findingsView', 'reachView', 'pathsView', 'ispGroupText'];

check(win.KuroshioUiCore && typeof win.KuroshioUiCore.restorePlan === 'function', '以一般 <script> 載入時有全域的 KuroshioUiCore');
const fns = Object.keys(core);
for (const fn of fns) check(Array.isArray(vectors[fn]) && vectors[fn].length > 0, `${fn} 有測試向量`);

for (const fn of Object.keys(vectors)) {
    if (!Array.isArray(vectors[fn])) continue;
    if (typeof core[fn] !== 'function') { check(false, `ui-core.js 沒有 ${fn}`); continue; }
    vectors[fn].forEach((c, i) => {
        const args = c.args.map(a => (typeof a === 'string' && TR[a] && TAKES_TR.indexOf(fn) >= 0) ? TR[a] : a);
        const label = `${fn} #${i + 1}${c.name ? '（' + c.name + '）' : ''}`;
        let got;
        try { got = norm(core[fn].apply(null, args)); } catch (e) { check(false, `${label}：${e.message}`); return; }
        const ok = JSON.stringify(got) === JSON.stringify(c.expect);
        check(ok, `${label}\n     參數 ${JSON.stringify(c.args)}\n     預期 ${JSON.stringify(c.expect)}\n     實際 ${JSON.stringify(got)}`);
        if (fn === 'regionLabel' && typeof c.args[1] !== 'string') {
            const d = dash.KuroshioDashboard.regionLabel.apply(null, args);
            check(d === c.expect, `${label}：dashboard.js 的 regionLabel 結果不同（${JSON.stringify(d)}，預期 ${JSON.stringify(c.expect)}）`);
        }
        if (fn === 'fmtTime' && args.length < 3) {
            const d = dash.KuroshioDashboard.fmtTime.apply(null, args);
            check(d === c.expect, `${label}：dashboard.js 的 fmtTime 結果不同（${JSON.stringify(d)}，預期 ${JSON.stringify(c.expect)}）`);
        }
    });
}

// 3.5.1：百分比的規則兩份一致（dashboard.js 不是數字時顯示 —，其他跟 ui-core.js 的 pct 一樣）
(vectors.pct || []).forEach((c, i) => {
    if (c.args.length > 2) return;
    const want = typeof c.args[0] === 'number' ? c.expect : '—';
    const d = dash.KuroshioDashboard.pct.apply(null, c.args);
    check(d === want, `pct #${i + 1}${c.name ? '（' + c.name + '）' : ''}：dashboard.js 的 pct 結果不同（${JSON.stringify(d)}，預期 ${JSON.stringify(want)}）`);
});
// 只有 dashboard.js 有的函式（向量在 ui-core.tests.json 的 dashboard 底下）
for (const [fn, list] of Object.entries(vectors.dashboard || {})) {
    if (!Array.isArray(list)) continue;
    if (typeof dash.KuroshioDashboard[fn] !== 'function') { check(false, `dashboard.js 沒有 ${fn}`); continue; }
    list.forEach((c, i) => {
        let got;
        try { got = norm(dash.KuroshioDashboard[fn].apply(null, c.args)); } catch (e) { check(false, `dashboard ${fn} #${i + 1}：${e.message}`); return; }
        check(JSON.stringify(got) === JSON.stringify(c.expect), `dashboard ${fn} #${i + 1}${c.name ? '（' + c.name + '）' : ''}\n     預期 ${JSON.stringify(c.expect)}\n     實際 ${JSON.stringify(got)}`);
    });
}

console.log(`ui-core 測試向量：通過 ${pass}，失敗 ${fail}`);
process.exit(fail ? 1 : 0);
