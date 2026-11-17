'use strict';
// CI：data/ 底下所有 .js、.css 不能出現 Padavan httpd 會當成模板標記解析的四種兩字元組合
// （小於＋百分比、百分比＋大於、小於＋井號、井號＋大於），註解、字串、正規表示式都算。
// 第三方韌體（Padavan）直接把 data/dashboard/、data/shared/ 的檔案放進網頁目錄，出現這些字元時 httpd 會把檔案弄壞。
// 需要時用字串相加拆開（例如 '<' + '%'）。
//   node tools/check-data-assets.js
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const DATA = path.join(ROOT, 'data');
// 用字元碼組出來，這支檢查程式本身也不含這些組合
const LT = String.fromCharCode(60), GT = String.fromCharCode(62), PCT = '%', HASH = '#';
const BAD = [LT + PCT, PCT + GT, LT + HASH, HASH + GT];

const walk = d => fs.readdirSync(d, { withFileTypes: true })
    .flatMap(e => (e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)]));

let files = 0, hits = 0;
for (const f of walk(DATA).filter(f => /\.(js|css)$/i.test(f)).sort()) {
    files++;
    fs.readFileSync(f, 'utf-8').split('\n').forEach((line, i) => {
        for (const b of BAD) {
            let at = line.indexOf(b);
            while (at >= 0) {
                hits++;
                console.log(`  ✘ ${path.relative(ROOT, f)}:${i + 1}:${at + 1}：出現「${b}」（Padavan httpd 會當成模板標記）`);
                at = line.indexOf(b, at + 1);
            }
        }
    });
}
console.log(hits ? `data/ 的 .js / .css：${hits} 處不允許的字元組合` : `data/ 的 .js / .css（${files} 個檔案）沒有 Padavan httpd 會解析的字元組合`);
process.exit(hits ? 1 : 0);
