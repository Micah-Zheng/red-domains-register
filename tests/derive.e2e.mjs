// derive.mjs 推导结果的 DNS 合法性回归测试。
//
// 存在理由：§8.4 初版要求 A 档「随主记录下发阻挡性 CAA」，而 A 档主记录恒为
// CNAME —— CNAME 不得与任何其它类型共存（RFC 1034 §3.6.2、RFC 2181 §10.1）。
// Cloudflare 的 API 不拦这种写入，三条记录全部返回 success:true，对账还判定
// 「已一致」，但权威解析层只应答 CAA、静默丢弃 CNAME，名字直接不解析。
// 这类故障不抛异常、不显红、日志里全是成功 —— 只有在推导层断言才能挡住。
//
// 下面第一组断言的是**不变量**（任何名字上有 CNAME 就不许有别的类型），
// 不是某个具体用例，这样换个档位组合再犯同样的错也会被抓住。

import { deriveRecords } from '../scripts/derive.mjs';

let pass = 0; const fails = [];
const ok = (c, m) => { if (c) { pass++; console.log(`  ok   ${m}`); } else { fails.push(m); console.log(`  FAIL ${m}`); } };

const OWNER = { github: 'someone', contact_hash: `sha256:${'0'.repeat(64)}` };
const doc = (record, extra = {}) => ({
  description: '一段足够长的、说明用途的真实描述文本', owner: OWNER,
  record, check: { mode: 'tcp', port: 443 }, ...extra,
});

// 覆盖四种主记录类型 × 橙灰云 × C 档声明，尽量把组合铺开。
const MATRIX = [
  ['A 档 橙云 CNAME', doc({ type: 'CNAME', value: 'user.github.io' })],
  ['B 档 灰云 CNAME', doc({ type: 'CNAME', value: 'user.github.io' }, { proxied: false })],
  ['B 档 灰云 A', doc({ type: 'A', value: '203.0.113.10' }, { proxied: false })],
  ['B 档 灰云 AAAA', doc({ type: 'AAAA', value: '2001:db8::1' }, { proxied: false })],
  ['B 档 SRV', doc({ type: 'SRV', value: 'mc.example.com', priority: 0, weight: 5, port: 25565 }, { proxied: false })],
  ['C 档 自签 A', doc({ type: 'A', value: '203.0.113.10' }, { proxied: false, tls: { public_cert: true } })],
  ['C 档 自签 CNAME', doc({ type: 'CNAME', value: 'app.fly.dev' }, { proxied: false, tls: { public_cert: true } })],
  ['C 档 带 DNS-01 委派', doc({ type: 'A', value: '203.0.113.10' },
    { proxied: false, tls: { public_cert: true, acme_dns_delegate: 'x.acme-dns.io' } })],
];

console.log('=== 不变量：同一名字上有 CNAME 就不得有其它类型 ===');
for (const [label, d] of MATRIX) {
  const { records } = deriveRecords({ prefix: 'myapp', zone: 'tcp.red', doc: d });
  const byName = new Map();
  for (const r of records) {
    if (!byName.has(r.name)) byName.set(r.name, new Set());
    byName.get(r.name).add(r.type);
  }
  const bad = [...byName].filter(([, ts]) => ts.has('CNAME') && ts.size > 1);
  ok(bad.length === 0,
    `${label} —— ${bad.length ? `${bad[0][0]} 上 CNAME 与 ${[...bad[0][1]].filter((t) => t !== 'CNAME')} 共存` : '无 CNAME 共存冲突'}`);
}

console.log('\n=== 档位矩阵：谁该有叶子 CAA ===');
const caaCount = (d) => deriveRecords({ prefix: 'myapp', zone: 'tcp.red', doc: d })
  .records.filter((r) => r.type === 'CAA' && r.name === 'myapp').length;
// 判据是主记录类型，不只是档位。
ok(caaCount(MATRIX[0][1]) === 0, 'A 档橙云 CNAME 不下发叶子 CAA（协议不允许，策略上移至 apex）');
ok(caaCount(MATRIX[1][1]) === 0, 'B 档灰云 CNAME 不下发叶子 CAA（同上；CA 还会跟随 CNAME 到目标查）');
ok(caaCount(MATRIX[2][1]) === 2, 'B 档灰云 A 下发 issue + issuewild 两条（同名合法）');
ok(caaCount(MATRIX[3][1]) === 2, 'B 档灰云 AAAA 下发两条');
ok(caaCount(MATRIX[4][1]) === 2, 'B 档 SRV 下发两条（SRV 与 CAA 同名合法）');
ok(caaCount(MATRIX[5][1]) === 0, 'C 档不下发阻挡性 CAA，否则用户签不了证书');
ok(caaCount(MATRIX[6][1]) === 0, 'C 档 CNAME 同样不下发');

console.log('\n=== 伴生记录仍在各自的名字上 ===');
const delegated = deriveRecords({ prefix: 'myapp', zone: 'tcp.red', doc: MATRIX[7][1] }).records;
ok(delegated.some((r) => r.name === '_acme-challenge.myapp' && r.type === 'CNAME'),
  '_acme-challenge.<前缀> 委派照常下发（不同标签，与主记录无冲突）');
ok(delegated.filter((r) => r.name === '_acme-challenge.myapp').length === 1,
  '_acme-challenge.<前缀> 上只有 CNAME 一条，未被叠加 CAA');

console.log('\n=== 库内真实申请文件 ===');
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
for (const zone of ['tcp.red', 'udp.red']) {
  const dir = join(ROOT, 'domains', zone);
  if (!existsSync(dir)) continue;
  for (const f of readdirSync(dir).filter((x) => x.endsWith('.json'))) {
    const prefix = f.slice(0, -5);
    const { records } = deriveRecords({ prefix, zone, doc: JSON.parse(readFileSync(join(dir, f), 'utf8')) });
    const names = new Map();
    for (const r of records) names.set(r.name, [...(names.get(r.name) ?? []), r.type]);
    const bad = [...names].filter(([, ts]) => ts.includes('CNAME') && ts.length > 1);
    ok(bad.length === 0, `domains/${zone}/${f} 推导结果无 CNAME 共存冲突`);
  }
}

console.log(`\n${pass}/${pass + fails.length} 通过`);
if (fails.length) process.exit(1);
