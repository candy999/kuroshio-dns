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
process.exit(fail ? 1 : 0);
