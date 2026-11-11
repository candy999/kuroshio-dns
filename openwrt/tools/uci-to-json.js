'use strict';
// 測試用：把 UCI 設定檔文字轉成 `ubus call uci get` 的 JSON 格式
//   node openwrt/tools/uci-to-json.js /etc/config/candydns
const fs = require('fs');

function parse(text) {
    const values = {};
    let cur = null, anon = 0, index = 0;
    const unq = s => s.replace(/^'(.*)'$/s, '$1').replace(/^"(.*)"$/s, '$1').replace(/'\\''/g, "'");
    for (const raw of text.split('\n')) {
        const line = raw.trim();
        if (!line || line.startsWith('#')) continue;
        const m = line.match(/^(config|option|list)\s+(\S+)(?:\s+(.*))?$/);
        if (!m) continue;
        if (m[1] === 'config') {
            const name = m[3] ? unq(m[3]) : `cfg${(anon++).toString(16).padStart(6, '0')}`;
            // 跟真正的 uci 一樣：同名區段型別不同就是錯誤（整個檔案讀不進來）
            if (values[name] && values[name]['.type'] !== m[2]) throw new Error(`UCI 解析錯誤：區段 '${name}' 同時是 ${values[name]['.type']} 與 ${m[2]}`);
            cur = values[name] = { '.anonymous': !m[3], '.type': m[2], '.name': name, '.index': index++ };
        } else if (cur && m[1] === 'option') cur[m[2]] = unq(m[3] || '');
        else if (cur) (cur[m[2]] = Array.isArray(cur[m[2]]) ? cur[m[2]] : []).push(unq(m[3] || ''));
    }
    return { values };
}

if (require.main === module) process.stdout.write(JSON.stringify(parse(fs.readFileSync(process.argv[2], 'utf-8'))));
module.exports = { parse };
