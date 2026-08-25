// 阶段 ③：DNS 下发。只在已合并的 main 上运行，持 CF 凭据。
//
// 输入：domains/ 下的申请文件（主干已合并的状态）
// 输出：Cloudflare 里与之一致的记录集
//
// 安全设计（PLAN §6 / §9.1）：
//  · 绝不 checkout PR 代码 —— 本脚本跑在 main 上下文，凭据不暴露给提交者。
//  · 每条写操作前过 protect()：命中基础设施白名单或 legacy 快照即跳过。
//    这是防止「一次下发拆掉运营者全部隧道」的最后一道闸。
//  · 默认 dry-run。要真正写入必须显式 --apply（§9.1 要求先跑一周 dry-run）。
//  · 只增改，不删除。删除由 reconcile.mjs 负责，且有独立的 dry-run 门禁 ——
//    把删除混进下发路径，一个推导 bug 就会造成不可逆的批量摘除。

import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { deriveRecords, recordKey, sameContent, isGitopsManaged } from './derive.mjs';
import { createProtector } from './protect.mjs';
import { createClient, toFqdn, toRelative } from './cf.mjs';

const root = resolve(process.argv[2] ?? '.');
const APPLY = process.argv.includes('--apply');
const ZONES = ['tcp.red', 'udp.red'];

const infra = JSON.parse(readFileSync(join(root, 'data/infra-records.json'), 'utf8'));
const protect = createProtector(infra);
const cf = createClient({ token: process.env.CF_API_TOKEN, dryRun: !APPLY });

/** 读取全部申请文件，按「申请」分组推导期望记录。
 *  刻意不摊平成单一记录集：主记录若冲突，同一申请的伴生记录（CAA、DNS-01 委派）
 *  必须一起搁置。否则会留下「CAA 已写、主记录没写」的孤儿状态 —— 那条 CAA 会
 *  阻挡该名字上所有 CA 的签发，且因为主记录不存在，排查时很难想到是它。 */
function desiredByZone() {
  const out = new Map(ZONES.map((z) => [z, []]));
  for (const zone of ZONES) {
    const dir = join(root, 'domains', zone);
    if (!existsSync(dir)) continue;
    for (const f of readdirSync(dir).sort()) {
      if (!f.endsWith('.json')) continue;
      const prefix = f.slice(0, -5);
      let doc;
      try {
        doc = JSON.parse(readFileSync(join(dir, f), 'utf8'));
      } catch (e) {
        // 主干上不该存在坏 JSON（阶段 ① 会拦），但真出现时必须响亮失败：
        // 静默跳过等于用户的记录永远不下发，且没人知道。
        throw new Error(`domains/${zone}/${f} 解析失败：${e.message}`);
      }
      const { records } = deriveRecords({ prefix, zone, doc });
      // 主记录 = 与申请前缀同名且类型为申请声明的类型；其余为伴生记录。
      const mainType = String(doc.record.type).toUpperCase();
      const main = records.find((r) => r.name === prefix && r.type === mainType);
      const companions = records.filter((r) => r !== main);
      out.get(zone).push({ prefix, file: `domains/${zone}/${f}`, main, companions, records });
    }
  }
  return out;
}

/** 拉取 CF 现状，折成相对名并按记录键索引。 */
async function currentByZone() {
  const out = new Map();
  for (const zone of ZONES) {
    const zid = await cf.zoneId(zone);
    const live = await cf.listRecords(zid);
    const idx = new Map();
    for (const r of live) {
      const rel = toRelative(r.name, zone);
      const norm = { ...r, name: rel, zone };
      const k = recordKey(norm);
      // CF 允许同名同型多条（如两条 A 做轮询）。recordKey 对 A/CNAME 不含内容，
      // 故同键可能撞车；保留全部候选，diff 时再逐条比。
      if (!idx.has(k)) idx.set(k, []);
      idx.get(k).push(norm);
    }
    out.set(zone, { zoneId: zid, index: idx, all: live.length });
  }
  return out;
}

const plan = { create: [], update: [], skip: [], conflict: [], held: [] };

const desired = desiredByZone();
const current = await currentByZone();

for (const zone of ZONES) {
  const { zoneId, index } = current.get(zone);

  for (const app of desired.get(zone)) {
    // 判定一条期望记录相对 CF 现状的动作。
    const classify = (rec) => {
      const guard = protect({ ...rec, zone });
      if (guard) return { action: 'conflict', reason: guard.reason, source: guard.source };

      const existing = index.get(recordKey(rec)) ?? [];
      if (existing.find((e) => sameContent(rec, e))) {
        return { action: 'skip', id: existing.find((e) => sameContent(rec, e)).id, why: '已一致' };
      }
      const ours = existing.find((e) => isGitopsManaged(e.comment));
      if (ours) return { action: 'update', id: ours.id, from: ours };
      if (existing.length) {
        return {
          action: 'conflict',
          reason: `CF 已有同名同型记录但无 gitops 标记（内容：${existing.map((e) => e.content ?? JSON.stringify(e.data)).join('、')}），可能是手工添加`,
          source: 'unmanaged_conflict',
        };
      }
      return { action: 'create' };
    };

    // 主记录先判。它冲突就意味着这个名字不归我们管，整组搁置。
    const mainVerdict = app.main ? classify(app.main) : null;
    if (mainVerdict?.action === 'conflict') {
      plan.conflict.push({ zone, rec: app.main, file: app.file, ...mainVerdict });
      for (const c of app.companions) {
        plan.held.push({ zone, rec: c, file: app.file, why: `主记录冲突（${mainVerdict.source}），伴生记录一并搁置` });
      }
      continue;
    }

    for (const rec of app.records) {
      const v = rec === app.main ? mainVerdict : classify(rec);
      const item = { zone, zoneId, rec, file: app.file, ...v };
      if (v.action === 'create') plan.create.push(item);
      else if (v.action === 'update') plan.update.push(item);
      else if (v.action === 'skip') plan.skip.push(item);
      else plan.conflict.push(item);
    }
  }
}

// —— 输出计划
const label = APPLY ? '执行' : 'DRY-RUN（不写入，加 --apply 才真正下发）';
console.log(`\n=== DNS 下发计划 · ${label} ===`);
for (const zone of ZONES) {
  const c = current.get(zone);
  const apps = desired.get(zone);
  const n = apps.reduce((a, x) => a + x.records.length, 0);
  console.log(`  ${zone}: CF 现有 ${c.all} 条，${apps.length} 份申请推导出 ${n} 条`);
}
const fmt = (r) => `${r.type} ${r.name} ${r.content ?? JSON.stringify(r.data)}${r.proxied ? ' [橙云]' : ''}`;
console.log(`\n新建 ${plan.create.length} 条：`);
for (const p of plan.create) console.log(`  + ${p.zone}  ${fmt(p.rec)}`);
console.log(`\n更新 ${plan.update.length} 条：`);
for (const p of plan.update) console.log(`  ~ ${p.zone}  ${fmt(p.rec)}\n      原值 ${p.from.content ?? JSON.stringify(p.from.data)}`);
console.log(`\n跳过 ${plan.skip.length} 条（已一致）`);
if (plan.held.length) {
  console.log(`\n搁置 ${plan.held.length} 条（主记录冲突，避免留下孤儿 CAA）：`);
  for (const p of plan.held) console.log(`  · ${p.zone}  ${fmt(p.rec)}\n      ${p.why}`);
}
if (plan.conflict.length) {
  console.log(`\n⚠ 冲突 ${plan.conflict.length} 条 —— 不自动处理，须人工确认：`);
  for (const p of plan.conflict) console.log(`  ! ${p.zone}  ${fmt(p.rec)}\n      [${p.source}] ${p.reason}`);
}

// —— 执行
if (APPLY) {
  let ok = 0; const failed = [];
  for (const p of plan.create) {
    try { await cf.createRecord(p.zoneId, { ...p.rec, name: toFqdn(p.rec.name, p.zone) }); ok += 1; }
    catch (e) { failed.push({ p, e }); }
  }
  for (const p of plan.update) {
    try { await cf.updateRecord(p.zoneId, p.id, { ...p.rec, name: toFqdn(p.rec.name, p.zone) }); ok += 1; }
    catch (e) { failed.push({ p, e }); }
  }
  console.log(`\n下发完成：成功 ${ok} 条，失败 ${failed.length} 条`);
  for (const { p, e } of failed) console.log(`  ✗ ${p.zone} ${fmt(p.rec)}：${e.message}`);
  if (failed.length) process.exit(1);
} else {
  console.log('\n未写入任何记录。确认计划无误后加 --apply。');
}

// 冲突不阻塞下发（其余记录仍应处理），但要让 CI 显出黄灯。
if (plan.conflict.length) process.exitCode = 2;
