// protect.mjs 回归测试。
// 这些断言挡住的是「静默删除生产记录」类故障：白名单方向写反、通配跨点、
// legacy 快照匹配过松/过严。全部失败都不会在运行时报错，只会在用户投诉时暴露。

import { readFileSync } from 'node:fs';
import { createProtector } from '../scripts/protect.mjs';

const infra = JSON.parse(readFileSync(new URL('../data/infra-records.json', import.meta.url), 'utf8'));
const protect = createProtector(infra);

const TUNNEL = 'aeb48423-55c3-45a8-9da7-5861021cb9d4.cfargotunnel.com';
const cases = [
  // —— 基础设施白名单
  ['_psl TXT 值合规', { zone: 'tcp.red', name: '_psl', type: 'TXT', content: 'https://github.com/publicsuffix/list/pull/2222' }, 'infra_whitelist'],
  ['_psl TXT 值不合规', { zone: 'tcp.red', name: '_psl', type: 'TXT', content: 'evil' }, 'none'],
  ['apex CAA', { zone: 'tcp.red', name: '@', type: 'CAA', content: '' }, 'infra_whitelist'],
  ['zone 级 * CAA', { zone: 'udp.red', name: '*', type: 'CAA', content: '' }, 'infra_whitelist'],
  ['apex SPF', { zone: 'tcp.red', name: '@', type: 'TXT', content: '"v=spf1 include:x ~all"' }, 'infra_whitelist'],
  ['_dmarc', { zone: 'udp.red', name: '_dmarc', type: 'TXT', content: 'v=DMARC1' }, 'infra_whitelist'],
  ['apex MX', { zone: 'tcp.red', name: '@', type: 'MX', content: 'route1.mx.cloudflare.net' }, 'infra_whitelist'],
  ['www 任意类型', { zone: 'tcp.red', name: 'www', type: 'AAAA', content: '::1' }, 'infra_whitelist'],
  ['DKIM 单标签', { zone: 'tcp.red', name: 'cf2024-1._domainkey', type: 'TXT', content: 'v=DKIM1' }, 'infra_whitelist'],
  ['DKIM 在 notify 下', { zone: 'tcp.red', name: 'sel._domainkey.notify', type: 'TXT', content: 'v=DKIM1' }, 'infra_whitelist'],
  ['_acme-challenge apex', { zone: 'tcp.red', name: '_acme-challenge', type: 'TXT', content: 'abc' }, 'infra_whitelist'],
  ['_acme-challenge.<前缀>', { zone: 'tcp.red', name: '_acme-challenge.myapp', type: 'CNAME', content: 'acme.example.com' }, 'infra_whitelist'],
  ['单标签通配不跨点', { zone: 'tcp.red', name: '_acme-challenge.a.b', type: 'CNAME', content: 'x' }, 'none'],

  // —— 通配方向：DNS 子标签在左侧。写成 notify.** 会让下面三条全部漏保护。
  ['notify 自身', { zone: 'tcp.red', name: 'notify', type: 'MX', content: 'x' }, 'infra_whitelist'],
  ['send.notify', { zone: 'tcp.red', name: 'send.notify', type: 'TXT', content: 'x' }, 'infra_whitelist'],
  ['bounce.notify', { zone: 'tcp.red', name: 'bounce.notify', type: 'CNAME', content: 'x' }, 'infra_whitelist'],
  ['前缀相似不误伤 notifyme', { zone: 'tcp.red', name: 'notifyme', type: 'CNAME', content: 'x' }, 'none'],
  ['notify 未授权 zone', { zone: 'udp.red', name: 'send.notify', type: 'TXT', content: 'x' }, 'none'],

  // —— 上线前既有记录（never_touch）
  ['api 隧道 tcp.red', { zone: 'tcp.red', name: 'api', type: 'CNAME', content: TUNNEL }, 'legacy_reserved'],
  ['sg Tailscale', { zone: 'tcp.red', name: 'sg', type: 'A', content: '100.119.63.21' }, 'legacy_reserved'],
  ['ota 8.8.8.8', { zone: 'udp.red', name: 'ota', type: 'A', content: '8.8.8.8' }, 'legacy_reserved'],
  ['同名同型内容不符 → 人工', { zone: 'tcp.red', name: 'api', type: 'CNAME', content: 'attacker.example.com' }, 'legacy_conflict'],

  // —— 用户申请：必须可管理，否则下发/对账全被挡死
  ['用户主记录', { zone: 'tcp.red', name: 'myblog', type: 'CNAME', content: 'user.github.io' }, 'none'],
  ['用户 CAA', { zone: 'tcp.red', name: 'myblog', type: 'CAA', content: '' }, 'none'],
  ['用户 A 记录', { zone: 'udp.red', name: 'mcserver', type: 'A', content: '203.0.114.9' }, 'none'],
];

let pass = 0;
for (const [desc, rec, expect] of cases) {
  const r = protect(rec);
  const got = r ? r.source : 'none';
  if (got === expect) { console.log(`  ok   ${desc}`); pass += 1; }
  else console.log(`  FAIL ${desc}\n       期望 ${expect}，实得 ${got}`);
}
console.log(`\n${pass}/${cases.length} 通过`);
if (pass !== cases.length) process.exit(1);

// legacy 快照完整性：条数与声明不符说明快照过期，对账前必须重新生成。
const legacy = infra.legacy_reserved;
const actual = legacy.records.length;
if (actual !== legacy.record_count) {
  console.log(`\nFAIL legacy 快照条数不符：声明 ${legacy.record_count}，实际 ${actual}`);
  process.exit(1);
}
const byZone = {};
for (const r of legacy.records) byZone[r.zone] = (byZone[r.zone] ?? 0) + 1;
for (const [z, n] of Object.entries(legacy.count_by_zone)) {
  if (byZone[z] !== n) {
    console.log(`\nFAIL ${z} 条数不符：声明 ${n}，实际 ${byZone[z] ?? 0}`);
    process.exit(1);
  }
}
// occupied_prefixes 必须覆盖 legacy 里的每个非基础设施前缀，否则申请者会拿到
// 一条覆盖运营者隧道的记录。
const infraNames = new Set(['@', 'www', '_psl', '_dmarc', '_acme-challenge', 'notify', '_mta-sts', '_smtp._tls', '_cf-custom-hostname']);
const occ = new Set(infra.occupied_prefixes.prefixes);
const missing = [...new Set(legacy.records.map((r) => r.name))]
  .filter((n) => !infraNames.has(n) && !n.includes('_domainkey') && !n.startsWith('_acme-challenge.') && !n.startsWith('_cf-custom-hostname.'))
  .filter((n) => !occ.has(n));
if (missing.length) {
  console.log(`\nFAIL legacy 前缀未列入 occupied_prefixes：${missing.join('、')}`);
  process.exit(1);
}
console.log('legacy 快照自检通过（条数、分区、occupied 覆盖）');
