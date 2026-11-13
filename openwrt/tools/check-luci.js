'use strict';
// CI：LuCI 頁面語法檢查（LuCI 的 view 最外層有 return，所以包成函式再解析）＋ JSON 檔格式
const fs = require('fs');
const path = require('path');
const root = path.join(__dirname, '..', process.argv[2] || 'luci-app-candydns');
let fail = 0;
const walk = d => fs.readdirSync(d, { withFileTypes: true }).flatMap(e => e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)]);
for (const f of walk(root)) {
    const src = fs.readFileSync(f, 'utf-8');
    try {
        if (f.endsWith('.js')) new Function(src);   // eslint-disable-line no-new-func
        else if (f.endsWith('.json')) JSON.parse(src);
        else continue;
        console.log(`  ✔ ${path.relative(root, f)}`);
    } catch (e) { fail++; console.log(`  ✘ ${path.relative(root, f)}：${e.message}`); }
}
// 介面檔案的版本標記（common.js 的 BUILD 與每個頁面的 BUILD）要跟 Cargo.toml 的版本一致：
// 頁面用它判斷瀏覽器是不是還在用快取的舊檔案，改版時忘了改就會一直誤判
const cargo = path.join(__dirname, '..', '..', 'Cargo.toml');
if (fs.existsSync(cargo)) {
    const want = (fs.readFileSync(cargo, 'utf-8').match(/^version = "([^"]+)"/m) || [])[1];
    for (const f of walk(root).filter(f => f.endsWith('.js'))) {
        const m = fs.readFileSync(f, 'utf-8').match(/^var BUILD = '([^']*)';/m);
        if (!m) continue;
        if (m[1] === want) console.log(`  ✔ ${path.relative(root, f)}：BUILD ${m[1]}`);
        else { fail++; console.log(`  ✘ ${path.relative(root, f)}：BUILD ${m[1]}，Cargo.toml 是 ${want}`); }
    }
}
process.exit(fail ? 1 : 0);
