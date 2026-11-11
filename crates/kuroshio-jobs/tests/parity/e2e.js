'use strict';
// 用 2.x 的 jobs/dns-benchmark.js 跑 tests/benchmark.rs 的同一組假 DNS 伺服器，印出結果對照。
// 需要先在 legacy-node/ 執行 npm ci --omit=dev。用法：node crates/kuroshio-jobs/tests/parity/e2e.js
// （2.x 不讀 dotlist.txt / stamps.txt，DoH 會真的連網路，所以這裡只放 UDP 候選）
const fs = require('fs');
const os = require('os');
const path = require('path');
const dgram = require('dgram');
const root = path.join(__dirname, '..', '..', '..', '..', 'legacy-node');
const dnsPacket = require(path.join(root, 'node_modules/dns-packet'));
const R = require(path.join(root, 'jobs/lib/benchmark-rules.js'));

function honest(name, n) {
    switch (name) {
        case 'one.one.one.one': return ['1.1.1.1', '1.0.0.1'];
        case 'www.alpha.com': return [`93.1.0.${n}`];
        case 'cdn.beta.com': return [`94.2.0.${n}`];
        case 'video.gamma.net': return [`95.3.0.${n}`];
        default: return 'NX';
    }
}

function mock(host, delay, f) {
    return new Promise(resolve => {
        const s = dgram.createSocket('udp4');
        s.on('message', (buf, peer) => {
            const q = dnsPacket.decode(buf);
            const name = q.questions[0].name;
            const r = f(name);
            if (r === 'DROP') return;
            setTimeout(() => {
                const resp = { type: 'response', id: q.id, flags: dnsPacket.RECURSION_DESIRED | dnsPacket.RECURSION_AVAILABLE, questions: q.questions, answers: [] };
                if (r === 'NX') resp.rcode = 'NXDOMAIN', resp.flags |= 3;
                else resp.answers = r.map(ip => ({ type: 'A', name, ttl: 60, data: ip }));
                s.send(dnsPacket.encode(resp), peer.port, peer.address);
            }, delay);
        });
        s.bind(0, host, () => { s.unref(); resolve(`${host}:${s.address().port}`); });
    });
}

(async () => {
    const s1 = await mock('127.1.0.1', 0, n => honest(n, 1));
    const s2 = await mock('127.2.0.1', 20, n => honest(n, 2));
    const s3 = await mock('127.3.0.1', 0, n => n === 'www.alpha.com' ? ['96.4.0.1'] : honest(n, 1));
    const s4 = await mock('127.4.0.1', 0, n => n === 'cdn.beta.com' ? ['0.0.0.0'] : honest(n, 1));
    const s5 = await mock('127.5.0.1', 120, n => honest(n, 1));
    const s6 = await mock('127.6.0.1', 0, () => 'DROP');
    const s7 = await mock('127.7.0.1', 0, n => n === 'one.one.one.one' ? ['9.9.9.9'] : honest(n, 1));
    const s8 = await mock('127.8.0.1', 0, n => n === 'one.one.one.one' ? honest(n, 1) : 'DROP');
    const pinned = await mock('127.9.0.1', 5, n => n === 'www.alpha.com' ? ['96.4.0.1'] : honest(n, 1));
    const s10 = await mock('127.1.0.10', 0, n => honest(n, 1));

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kuroshio-node-e2e-'));
    const list = path.join(dir, 'benchmark');
    const out = path.join(dir, 'state/benchmark');
    fs.mkdirSync(list, { recursive: true });
    fs.mkdirSync(out, { recursive: true });
    fs.writeFileSync(path.join(list, 'iplist.txt'), [s1, s2, s3, s4, s5, s6, s7, s8, s10].join('\n'));
    fs.writeFileSync(path.join(list, 'web.txt'), 'www.alpha.com\ncdn.beta.com\nvideo.gamma.net\ndead.example\n');
    fs.writeFileSync(path.join(list, 'blacklist.txt'), `# 黑名單\n${s10}  # 測試\n`);
    // ASN：先放進快取，2.x 就不會去問 ip-api
    const cache = {};
    const add = (k, isp, as) => { cache[k] = { raw: `${isp}__${as}`.replace(/\s+/g, '_'), keywords: R.extractKeywords(`${isp} ${isp} ${as}`) }; };
    add('93.1', 'Alpha Networks', 'AS100 Alpha Networks');
    add('94.2', 'Beta Hosting', 'AS200 Beta Hosting');
    add('95.3', 'Gamma Cloud', 'AS300 Gamma Cloud');
    add('96.4', 'Evil Corp', 'AS666 Evil Corp');
    for (let i = 1; i <= 9; i++) add(`127.${i}`, `Owner${i} Ltd`, `AS90${i} Owner${i}`);
    fs.writeFileSync(path.join(out, 'cidr_cache.json'), JSON.stringify(cache));

    const config = {
        upstream: { pinned: [`udp://${pinned}`], autoTypes: ['udp', 'doh', 'dot'], autoMax: 3, autoStateFile: path.join(dir, 'state/upstreams.json') },
        benchmark: { dir: list, outDir: out, timeoutMs: 300, concurrency: 4, maxTimeouts: 1, minAuto: 3 },
    };
    const job = require(path.join(root, 'jobs/dns-benchmark.js'));
    const origLog = console.log; console.log = () => {};
    await job(config);
    console.log = origLog;
    const st = JSON.parse(fs.readFileSync(config.upstream.autoStateFile, 'utf-8'));
    const name = { [s1]: 's1', [s2]: 's2', [s3]: 's3', [s4]: 's4', [s5]: 's5', [s6]: 's6', [s7]: 's7', [s8]: 's8', [`udp://${pinned}`]: 'pinned' };
    console.log(JSON.stringify({
        selected: st.selected.map(x => [name[x.id], x.type, x.reason, x.newItems, x.owner]),
        universe: st.universe, coverage: st.coverage, counts: st.counts,
        blocked: st.blocked.map(b => [name[b.dns], b.domain, b.reason, b.pinned]),
        pinned: st.pinned.map(p => [name[p.id], p.coverageItems, p.issues]),
        blacklist: fs.readFileSync(path.join(list, 'blacklist.txt'), 'utf-8').split('\n').filter(l => l.includes(s3)).map(l => l.replace(s3, 's3')),
        eliminated: fs.readFileSync(path.join(out, st.date, 'eliminated.csv'), 'utf-8').replace(/^﻿/, '').split('\n').slice(1).map(l => { const [id, ...rest] = l.split(','); return [name[id], ...rest].join(','); }).sort(),
    }, null, 1));
    fs.rmSync(dir, { recursive: true, force: true });
    process.exit(0);
})();
