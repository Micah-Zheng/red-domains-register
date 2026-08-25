// 每日对账：Git（唯一事实源）↔ Cloudflare（实际生效）。
//
// 为什么必须有（PLAN §9.2）：两边一定会漂移。运营者在 CF 面板手工改了记录、
// 下发中途失败留下半套记录、用户 PR 删了 JSON 但下发那步没跑成。其中最危险的
// 是「JSON 已删、CF 记录仍在」—— 前缀在仓库里显示可申请，实际仍解析到前任
// owner 的服务器；若那台机器已易主，就是一个挂在我们域名下的钓鱼站。
//
// 四类漂移：
//   missing   Git 有 / CF 无        → 下发漏了，补
//   drifted   两边都有但内容不同     → 以 Git 为准改回（仅限带 gitops 标记的）
//   orphan    CF 有 / Git 无        → 申请已撤销但记录还在，删
//   unmanaged CF 有 / Git 无 / 无标记 → 手工记录，只报告不动
//
// 删除门禁（三重，缺一不可）：
//   1. protect() 未命中
//   2. 记录带 gitops 标记（证明是我们下发的）
//   3. 单次删除数 ≤ MAX_DELETE，超限直接中止 —— 推导 bug 会让全部记录看起来
//      都是孤儿，没有这道闸就是一次性拆掉整个 zone。

import { readdirSync, readFileSync, existsSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { deriveRecords, recordKey, sameContent, isGitopsManaged } from './derive.mjs';
import { createProtector } from './protect.mjs';
import { createClient, toFqdn, toRelative } from './cf.mjs';

const root = resolve(process.argv[2] ?? '.');
const APPLY = process.argv.includes('--apply');
const ALLOW_DELETE = process.argv.includes('--allow-delete');
const MAX_DELETE = Number(process.env.MAX_DELETE ?? 5);
const ZONES = ['tcp.red', 'udp.red'];

const infra = JSON.parse(readFileSync(join(root, 'data/infra-records.json'), 'utf8'));
const protect = createProtector(infra);
const cf = createClient({ token: process.env.CF_API_TOKEN, dryRun: !APPLY });

function desiredIndex(zone) {
  const idx = new Map();
  const dir = join(root, 'domains', zone);
  if (!existsSync(dir)) return idx;
  for (const f of readdirSync(dir).sort()) {
    if (!f.endsWith('.json')) continue;
    const prefix = f.slice(0, -5);
    const doc = JSON.parse(readFileSync(join(dir, f), 'utf8'));
    for (const r of deriveRecords({ prefix, zone, doc }).records) {
      const k = recordKey(r);
      if (!idx.has(k)) idx.set(k, []);
      idx.get(k).push({ rec: r, prefix, file: `domains/${zone}/${f}` });
    }
  }
  return idx;
}

// 前置断言：申请目录必须存在且非空。
//
// 若 domains/ 未正确 checkout（浅克隆、路径错、CI 少了一步），desiredIndex 会
// 返回空集，于是 CF 上每一条带 gitops 标记的记录都被判为孤儿。MAX_DELETE 能挡住
// 后果，但那是靠数量巧合，不是靠语义 —— 一旦哪天有人为了清一批积压孤儿把上限
// 调高，这个 bug 就会直接拆掉整个 zone。所以在算孤儿之前先证明事实源是完整的。
const appCount = ZONES.reduce((n, z) => {
  const dir = join(root, 'domains', z);
  return n + (existsSync(dir) ? readdirSync(dir).filter((f) => f.endsWith('.json')).length : 0);
}, 0);
if (appCount === 0) {
  console.error('✗ 中止：domains/ 下没有任何申请文件。');
  console.error(`  检查过的路径：${ZONES.map((z) => join(root, 'domains', z)).join('、')}`);
  console.error('  空事实源会让 CF 上全部记录被判为孤儿。这几乎总是 checkout 或路径问题，');
  console.error('  而不是「所有申请都被撤销了」。对账不在此状态下继续。');
  process.exit(1);
}
console.log(`事实源：${appCount} 份申请`);

const report = { missing: [], drifted: [], orphan: [], unmanaged: [], protected: [], generatedAt: null };

for (const zone of ZONES) {
  const zid = await cf.zoneId(zone);
  const live = await cf.listRecords(zid);
  const want = desiredIndex(zone);

  const liveIdx = new Map();
  for (const r of live) {
    const norm = { ...r, name: toRelative(r.name, zone), zone };
    const k = recordKey(norm);
    if (!liveIdx.has(k)) liveIdx.set(k, []);
    liveIdx.get(k).push(norm);
  }

  // 方向一：Git → CF
  for (const [k, entries] of want) {
    for (const { rec, prefix, file } of entries) {
      const cands = liveIdx.get(k) ?? [];
      if (!cands.length) {
        report.missing.push({ zone, zoneId: zid, rec, prefix, file });
        continue;
      }
      if (cands.some((c) => sameContent(rec, c))) continue;
      const ours = cands.find((c) => isGitopsManaged(c.comment));
      if (ours) {
        report.drifted.push({
          zone, zoneId: zid, rec, prefix, file, id: ours.id,
          liveValue: ours.content ?? JSON.stringify(ours.data),
        });
      } else {
        report.unmanaged.push({
          zone, rec, prefix, file,
          note: `Git 期望此记录，但 CF 上同名同型记录无 gitops 标记（${cands.map((c) => c.content ?? JSON.stringify(c.data)).join('、')}）`,
        });
      }
    }
  }

  // 方向二：CF → Git（找孤儿）
  for (const [k, cands] of liveIdx) {
    for (const c of cands) {
      const guard = protect(c);
      if (guard) { report.protected.push({ zone, rec: c, reason: guard.reason, source: guard.source }); continue; }

      const wanted = (want.get(k) ?? []).some((w) => sameContent(w.rec, c));
      if (wanted) continue;
      // 同键存在但内容不同的情况已在方向一记为 drifted，此处不重复计。
      if (want.has(k)) continue;

      if (isGitopsManaged(c.comment)) {
        report.orphan.push({
          zone, zoneId: zid, id: c.id, rec: c,
          note: '带 gitops 标记但 Git 中已无对应申请 —— 申请被撤销/删除后残留',
        });
      } else {
        report.unmanaged.push({
          zone, rec: c,
          note: 'CF 上存在但 Git 无对应申请，且无 gitops 标记 —— 疑为手工添加，不自动处理',
        });
      }
    }
  }
}

// —— 报告
const fmt = (r) => `${r.type} ${r.name} ${r.content ?? JSON.stringify(r.data)}`;
const mode = APPLY ? '执行' : 'DRY-RUN';
console.log(`\n=== Git ↔ Cloudflare 对账 · ${mode} ===`);
console.log(`  缺失 ${report.missing.length} · 漂移 ${report.drifted.length} · 孤儿 ${report.orphan.length} · 手工 ${report.unmanaged.length} · 受保护 ${report.protected.length}`);

if (report.missing.length) {
  console.log(`\n[缺失] Git 有但 CF 无 —— 下发漏了，应补：`);
  for (const p of report.missing) console.log(`  + ${p.zone}  ${fmt(p.rec)}   ← ${p.file}`);
}
if (report.drifted.length) {
  console.log(`\n[漂移] 两边都有但内容不同 —— 以 Git 为准改回：`);
  for (const p of report.drifted) console.log(`  ~ ${p.zone}  ${fmt(p.rec)}\n      CF 现值 ${p.liveValue}   ← ${p.file}`);
}
if (report.orphan.length) {
  console.log(`\n[孤儿] CF 有但 Git 无（带 gitops 标记）—— 应删：`);
  for (const p of report.orphan) console.log(`  - ${p.zone}  ${fmt(p.rec)}\n      ${p.note}`);
  console.log(`  ⚠ 孤儿记录仍在对外解析。若目标机器已易主，这是挂在我们域名下的失控端点。`);
}
if (report.unmanaged.length) {
  console.log(`\n[手工] 需人工判断，脚本不动：`);
  for (const p of report.unmanaged) console.log(`  ? ${p.zone}  ${fmt(p.rec)}\n      ${p.note}`);
}

// —— 执行修复
if (APPLY) {
  let fixed = 0; const failed = [];
  for (const p of report.missing) {
    try { await cf.createRecord(p.zoneId, { ...p.rec, name: toFqdn(p.rec.name, p.zone) }); fixed += 1; }
    catch (e) { failed.push([p, e]); }
  }
  for (const p of report.drifted) {
    try { await cf.updateRecord(p.zoneId, p.id, { ...p.rec, name: toFqdn(p.rec.name, p.zone) }); fixed += 1; }
    catch (e) { failed.push([p, e]); }
  }
  console.log(`\n补齐/纠正 ${fixed} 条，失败 ${failed.length} 条`);
  for (const [p, e] of failed) console.log(`  ✗ ${p.zone} ${fmt(p.rec)}：${e.message}`);

  if (report.orphan.length) {
    if (!ALLOW_DELETE) {
      console.log(`\n未删除任何孤儿记录。删除需显式 --allow-delete（这是不可逆操作）。`);
      process.exitCode = 2;
    } else if (report.orphan.length > MAX_DELETE) {
      console.log(`\n✗ 中止删除：孤儿 ${report.orphan.length} 条超过上限 ${MAX_DELETE}。`);
      console.log(`  正常运行时孤儿是个别现象。数量异常通常意味着推导逻辑或申请目录出了问题`);
      console.log(`  （例如 domains/ 未正确 checkout），此时删除会拆掉大量在用记录。`);
      console.log(`  确认无误后用 MAX_DELETE=${report.orphan.length} 重跑。`);
      process.exitCode = 1;
    } else {
      let del = 0;
      for (const p of report.orphan) {
        try { await cf.deleteRecord(p.zoneId, p.id); del += 1; console.log(`  - 已删 ${p.zone} ${fmt(p.rec)}`); }
        catch (e) { console.log(`  ✗ 删除失败 ${p.zone} ${fmt(p.rec)}：${e.message}`); }
      }
      console.log(`\n删除孤儿 ${del} 条`);
    }
  }
  if (failed.length) process.exitCode = 1;
} else {
  console.log(`\n未做任何修改。补齐/纠正加 --apply；删除孤儿再加 --allow-delete。`);
}

report.generatedAt = process.env.RECONCILE_TIMESTAMP ?? null;
if (process.env.RECONCILE_REPORT) {
  writeFileSync(process.env.RECONCILE_REPORT, JSON.stringify(report, null, 2));
  console.log(`\n报告已写入 ${process.env.RECONCILE_REPORT}`);
}
if (report.missing.length || report.drifted.length || report.orphan.length) process.exitCode ||= 2;
