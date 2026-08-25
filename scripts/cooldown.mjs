// 删除申请文件 = 释放前缀 → 写入冷却名单（PLAN §9 生命周期、§781）。
//
// 存在理由：data/cooldown.json 一直是只读不写的 —— r_notInCooldown 认真地读它，
// 而全仓没有任何一处写它。于是 r_deleteOwnOnly 给用户的提示语
// 「释放后进入冷却期，期间他人也无法申请」是一句空话：删完前缀立刻可被抢注。
//
// 冷却期防的是**残留信任**：旧域名可能还在别人的书签、第三方白名单、已发出的
// 邮件链接和搜索索引里。立刻转给下一个人，等于把这些残留流量交给陌生人 ——
// 而且新持有人完全无需做任何恶意行为就能收到，这是结构性的钓鱼便利。
//
// 孪生前缀一并冷却：消费端 r_notInCooldown 只按 prefix 匹配、不区分 zone，
// 所以一条记录天然同时锁住 tcp.red 与 udp.red，符合 §781 的要求。

import { readFileSync, writeFileSync } from 'node:fs';
import { deletedApps } from './changed-apps.mjs';

const PATH = process.env.COOLDOWN_PATH ?? 'data/cooldown.json';
// 自助释放按 voluntary。滥用撤销（180 天）走的是另一条人工路径，
// 那条路径需要判定滥用性质，不能从一次 push 推断出来，故不在本脚本内自动化。
const REASON = process.env.COOLDOWN_REASON ?? 'voluntary';

const today = new Date();
const iso = (d) => d.toISOString().slice(0, 10);

const data = JSON.parse(readFileSync(PATH, 'utf8'));
const days = data.default_periods_days?.[REASON];
if (typeof days !== 'number') {
  throw new Error(`cooldown.json 的 default_periods_days 里没有 "${REASON}"，无法决定冷却时长`);
}

const { skipped, apps } = deletedApps({
  before: process.env.BEFORE_SHA, after: process.env.AFTER_SHA,
});
if (skipped) { console.log(skipped); process.exit(0); }
if (!apps.length) { console.log('本次无申请文件被删除，冷却名单不变。'); process.exit(0); }

const release = new Date(today);
release.setUTCDate(release.getUTCDate() + days);
const releaseAt = iso(release);

const entries = data.entries ?? [];
let added = 0, extended = 0;

for (const app of apps) {
  const prefix = app.prefix.toLowerCase();
  const existing = entries.find((e) => String(e.prefix).toLowerCase() === prefix);
  if (existing) {
    // 已在冷却中又被再次释放：取更晚的那个，绝不缩短。缩短会让「反复
    // 申请-释放」成为绕过冷却的手段。
    if (releaseAt > existing.release_at) {
      console.log(`  ${prefix}：冷却延长 ${existing.release_at} → ${releaseAt}`);
      existing.release_at = releaseAt; existing.reason = REASON; extended += 1;
    } else {
      console.log(`  ${prefix}：已在冷却中且到期更晚（${existing.release_at}），不变`);
    }
    continue;
  }
  entries.push({
    prefix,
    release_at: releaseAt,
    reason: REASON,
    released_from: app.file,
    released_on: iso(today),
    // owner 仅作审计留痕。base 里若是坏 JSON 就拿不到，此时仍要冷却 ——
    // 记录损坏不该成为跳过冷却的理由。
    former_owner: app.doc?.owner?.github ?? null,
  });
  console.log(`  ${prefix}：加入冷却，${releaseAt} 之后方可再申请（${days} 天，${REASON}）`);
  added += 1;
}

if (!added && !extended) { console.log('冷却名单无需变更。'); process.exit(0); }

data.entries = entries.sort((a, b) => String(a.prefix).localeCompare(String(b.prefix)));
data.updated = iso(today);
writeFileSync(PATH, `${JSON.stringify(data, null, 2)}\n`);
console.log(`\n冷却名单已更新：新增 ${added}，延长 ${extended}，共 ${entries.length} 条。`);
