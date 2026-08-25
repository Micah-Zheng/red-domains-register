// 阶段 ③.5：下发后验证权威确实已应答（PLAN §8.3）。
//
// 存在理由 —— 2026-08-25 亲历：Cloudflare 的 API 返回 success:true、记录出现在
// GET /dns_records、面板里看得到、cf-sync 判「已一致」、reconcile 报「孤儿 0」，
// 而权威 NS 对该名字一律 NODATA。那次故障期间 11 条新记录只有 1 条真正下发。
// 整条流水线全绿，域名不解析，用户会收到一封「已开通」的邮件。
// §8.3 把这个称作最差的失败模式，因为邮件与 DNS 不是原子操作：
//   「CF API 返回 200 不等于权威已应答。必须验证通过后才写侧仓 state=ACTIVE 并发信。」
//
// 本脚本就是那道闸门。验证不过 → 退出码 1 → workflow 开 Issue 且**不发邮件**。
//
// 为什么直接问权威而不是问 1.1.1.1/8.8.8.8：公共解析器有正负缓存，
// 既可能把「刚生效」读成没生效（旧的否定缓存），也可能把「已撤销」读成还在。
// 只有 zone 自己的权威 NS 能回答「此刻你到底服不服务这个名字」。

import { writeFileSync } from 'node:fs';
import { Resolver } from 'node:dns/promises';
import { deriveRecords } from './derive.mjs';
import { newlyAddedApps } from './changed-apps.mjs';

const OUT = process.env.VERIFY_REPORT ?? 'verify-report.json';
const TIMEOUT_MS = Number(process.env.VERIFY_TIMEOUT_MS ?? 180_000);
const INTERVAL_MS = Number(process.env.VERIFY_INTERVAL_MS ?? 10_000);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** zone 的权威 NS 的 IP。查它们本身要用系统解析器。 */
async function authoritativeServers(zone) {
  const sys = new Resolver();
  const ns = await sys.resolveNs(zone);
  const ips = [];
  for (const host of ns) {
    try { ips.push(...await sys.resolve4(host)); } catch { /* 单台查不到不致命 */ }
  }
  if (!ips.length) throw new Error(`拿不到 ${zone} 任何权威 NS 的地址（NS: ${ns.join('、')}）`);
  return ips;
}

/** 一条期望记录是否已被权威应答。返回 null 表示已生效，字符串表示未生效的原因。 */
async function checkRecord(res, rec, zone) {
  const fqdn = rec.name === '@' ? zone : `${rec.name}.${zone}`;
  try {
    // 橙云记录会被 CF 展平：权威返回的是 CF 的 A，而不是 CNAME。
    if (rec.proxied) {
      const a = await res.resolve4(fqdn);
      return a.length ? null : '无 A 应答';
    }
    switch (rec.type) {
      case 'CNAME': {
        const c = await res.resolveCname(fqdn);
        return c.length ? null : '无 CNAME 应答';
      }
      case 'A': return (await res.resolve4(fqdn)).length ? null : '无 A 应答';
      case 'AAAA': return (await res.resolve6(fqdn)).length ? null : '无 AAAA 应答';
      case 'SRV': return (await res.resolveSrv(fqdn)).length ? null : '无 SRV 应答';
      case 'CAA': return (await res.resolveCaa(fqdn)).length ? null : '无 CAA 应答';
      default: return null;   // 未知类型不阻断下发
    }
  } catch (e) {
    return e.code ?? e.message;
  }
}

const { skipped, apps } = newlyAddedApps({ before: process.env.BEFORE_SHA, after: process.env.AFTER_SHA });
if (skipped) console.log(skipped);

if (!apps.length) {
  console.log('本次无新增申请，无需验证。');
  writeFileSync(OUT, JSON.stringify({ verified: [], failed: [], checked: 0 }, null, 2));
  process.exit(0);
}

// 期望记录集由 derive.mjs 推导 —— 与 cf-sync 下发时用的是同一个函数，
// 不重新实现，否则两边对「该有哪些记录」的认知会漂移。
const targets = [];
for (const app of apps) {
  const { records } = deriveRecords({ prefix: app.prefix, zone: app.zone, doc: app.doc });
  for (const rec of records) targets.push({ app, rec });
}
console.log(`本次新增 ${apps.length} 份申请，推导出 ${targets.length} 条记录，开始验证权威应答。`);
console.log(`超时 ${TIMEOUT_MS / 1000}s，每 ${INTERVAL_MS / 1000}s 重试一次。\n`);

const resolvers = new Map();
for (const zone of new Set(apps.map((a) => a.zone))) {
  const ips = await authoritativeServers(zone);
  const r = new Resolver();
  r.setServers(ips);
  resolvers.set(zone, r);
  console.log(`  ${zone} 权威 NS：${ips.join('、')}`);
}
console.log('');

const pending = new Map(targets.map((t, i) => [i, t]));
const verified = []; const deadline = Date.now() + TIMEOUT_MS;
let round = 0;

while (pending.size && Date.now() < deadline) {
  round += 1;
  for (const [i, t] of [...pending]) {
    const why = await checkRecord(resolvers.get(t.app.zone), t.rec, t.app.zone);
    if (why === null) {
      const fqdn = t.rec.name === '@' ? t.app.zone : `${t.rec.name}.${t.app.zone}`;
      console.log(`  ✅ ${t.rec.type} ${fqdn}（第 ${round} 轮）`);
      verified.push({ file: t.app.file, zone: t.app.zone, prefix: t.app.prefix, type: t.rec.type, fqdn });
      pending.delete(i);
    }
  }
  if (pending.size && Date.now() + INTERVAL_MS < deadline) await sleep(INTERVAL_MS);
  else break;
}

const failed = [...pending.values()].map((t) => ({
  file: t.app.file, zone: t.app.zone, prefix: t.app.prefix, type: t.rec.type,
  fqdn: t.rec.name === '@' ? t.app.zone : `${t.rec.name}.${t.app.zone}`,
}));

writeFileSync(OUT, JSON.stringify({
  verified, failed, checked: targets.length,
  timeoutMs: TIMEOUT_MS, rounds: round,
}, null, 2));

console.log(`\n验证结束：已生效 ${verified.length} / ${targets.length}，未生效 ${failed.length}。`);
if (failed.length) {
  for (const f of failed) console.log(`  ❌ ${f.type} ${f.fqdn} —— 超时未被权威应答`);
  console.log('\nCloudflare 已接受写入但权威尚未应答。**不发送开通通知** —— '
    + '用户收到「已生效」而实际解析不到，是最差的失败模式（PLAN §8.3）。');
  process.exit(1);
}
console.log('全部记录已被权威应答，可以发送开通通知。');
