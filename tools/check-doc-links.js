'use strict';
// 文件的相對連結檢查：repo 裡每一份 .md 的相對連結（[文字](路徑)、![圖](路徑)、<img src>、<a href>）
// 都要指得到檔案；帶 #錨點 的要對得到那份 Markdown 的標題（照 GitHub 產生錨點的規則）或 id／name。
// 外部網址（http、https、mailto）不檢查。手動執行，不接進 CI：
//
//   node tools/check-doc-links.js            檢查全部
//   node tools/check-doc-links.js README.md docs/guide   只檢查這些檔案或資料夾
//
// 有斷掉的連結時結束碼是 1。
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const SKIP_DIRS = new Set(['.git', 'target', 'node_modules', 'vendor', '.claude']);

/** 列出資料夾底下所有 .md */
function listMd(dir, out = []) {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
        if (e.isDirectory()) {
            if (!SKIP_DIRS.has(e.name) && !e.name.startsWith('screenshots')) listMd(path.join(dir, e.name), out);
        } else if (e.name.endsWith('.md')) out.push(path.join(dir, e.name));
    }
    return out;
}

/** 拿掉程式碼區塊（``` 與 ~~~）與行內程式碼，保留行數，連結的行號才對得上 */
function stripCode(text) {
    const lines = text.split('\n');
    let fence = null;
    return lines.map(line => {
        const m = line.match(/^\s*(`{3,}|~{3,})/);
        if (fence) {
            if (m && m[1][0] === fence[0] && m[1].length >= fence.length) fence = null;
            return '';
        }
        if (m) { fence = m[1]; return ''; }
        return line.replace(/(`+)[\s\S]*?\1/g, '');
    }).join('\n');
}

/** GitHub 的標題錨點：小寫、拿掉標點與符號（保留文字、數字、底線、連字號、空白），空白換成連字號 */
function slug(heading) {
    const text = heading
        .replace(/!\[[^\]]*\]\([^)]*\)/g, '')          // 圖片
        .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')        // 連結只留文字
        .replace(/<[^>]+>/g, '')                        // HTML 標籤
        .replace(/`/g, '')
        .replace(/\*+/g, '');
    return text.trim().toLowerCase().replace(/[^\p{L}\p{M}\p{N}\p{Pc}\- ]/gu, '').replace(/ /g, '-');
}

const anchorCache = new Map();
/** 一份 Markdown 的所有錨點（標題，重複的加 -1、-2；加上 id／name） */
function anchorsOf(file) {
    if (anchorCache.has(file)) return anchorCache.get(file);
    const set = new Set();
    const seen = new Map();
    const text = stripCodeBlocksOnly(fs.readFileSync(file, 'utf8'));
    for (const line of text.split('\n')) {
        const h = line.match(/^ {0,3}#{1,6}\s+(.*?)\s*#*\s*$/);
        if (h) {
            const base = slug(h[1]);
            const n = seen.get(base) || 0;
            set.add(n ? `${base}-${n}` : base);
            seen.set(base, n + 1);
        }
        for (const m of line.matchAll(/<a\s[^>]*?(?:id|name)="([^"]+)"/g)) set.add(m[1]);
    }
    anchorCache.set(file, set);
    return set;
}

/** 只拿掉程式碼區塊（標題裡的行內程式碼要留著算錨點） */
function stripCodeBlocksOnly(text) {
    let fence = null;
    return text.split('\n').map(line => {
        const m = line.match(/^\s*(`{3,}|~{3,})/);
        if (fence) {
            if (m && m[1][0] === fence[0] && m[1].length >= fence.length) fence = null;
            return '';
        }
        if (m) { fence = m[1]; return ''; }
        return line;
    }).join('\n');
}

/** 一份檔案裡的連結：{ line, target } */
function linksOf(file) {
    const out = [];
    const lines = stripCode(fs.readFileSync(file, 'utf8')).split('\n');
    lines.forEach((line, i) => {
        // [文字](路徑 "標題")、![圖](路徑)；路徑可以用 <> 包起來
        for (const m of line.matchAll(/!?\[(?:[^\]\\]|\\.)*\]\(\s*(<[^>]*>|[^)\s]+)(?:\s+"[^"]*")?\s*\)/g)) {
            out.push({ line: i + 1, target: m[1].replace(/^<|>$/g, '') });
        }
        for (const m of line.matchAll(/<(?:img|a|source)\s[^>]*?(?:src|href|srcset)="([^"]+)"/g)) out.push({ line: i + 1, target: m[1] });
    });
    // 參考式連結：[名稱]: 路徑
    lines.forEach((line, i) => {
        const m = line.match(/^ {0,3}\[[^\]]+\]:\s*(\S+)/);
        if (m) out.push({ line: i + 1, target: m[1] });
    });
    return out;
}

function check(files) {
    const errors = [];
    let count = 0;
    for (const file of files) {
        const rel = path.relative(ROOT, file);
        for (const { line, target } of linksOf(file)) {
            if (/^[a-z][a-z0-9+.-]*:/i.test(target) || target.startsWith('//')) continue;   // 外部網址、mailto
            count++;
            let [p, hash] = target.split('#');
            try { p = decodeURIComponent(p); hash = hash === undefined ? undefined : decodeURIComponent(hash); } catch (e) { /* 照原樣 */ }
            const dest = p ? (p.startsWith('/') ? path.join(ROOT, p) : path.resolve(path.dirname(file), p)) : file;
            if (!fs.existsSync(dest)) { errors.push(`${rel}:${line}  找不到檔案：${target}`); continue; }
            if (hash === undefined || hash === '') continue;
            if (!dest.endsWith('.md')) continue;   // 程式碼檔的 #L12 之類不檢查
            if (!anchorsOf(dest).has(hash.toLowerCase())) {
                errors.push(`${rel}:${line}  找不到錨點：${target}（${path.relative(ROOT, dest)} 裡沒有這個標題）`);
            }
        }
    }
    return { errors, count };
}

const args = process.argv.slice(2);
const files = args.length
    ? args.flatMap(a => { const p = path.resolve(a); return fs.statSync(p).isDirectory() ? listMd(p) : [p]; })
    : listMd(ROOT);
const { errors, count } = check(files);
for (const e of errors) console.log(`✘ ${e}`);
console.log(`${files.length} 份文件、${count} 個相對連結：${errors.length ? `${errors.length} 個斷掉` : '全部指得到'}`);
process.exit(errors.length ? 1 : 0);
