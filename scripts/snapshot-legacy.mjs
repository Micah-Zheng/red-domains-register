#!/usr/bin/env node
/**
 * 重新生成 data/infra-records.json 的 legacy_reserved 与 occupied_prefixes 段。
 *
 * 为什么需要它：legacy_reserved 是一份时间点快照，是阻止 §9.3 对账任务
 * 删除运营者既有服务的唯一屏障。运营者手工改动 DNS 后快照即过期——
 * 新增的记录不在快照里，下一次对账就会把它删掉。
 *
 * 用法：CF_API_TOKEN=... node scripts/snapshot-legacy.mjs [--dry-run]
 *
 * 只读 Cloudflare，只写本地 JSON。绝不修改 DNS。
 */
import { readFileSync, writeFileSync } from 'node:fs';

const FILE = new URL('../data/infra-records.json', import.meta.url);
const DRY = process.argv.includes('--dry-run');
const TOKEN = process.env.CF_API_TOKEN;

if (!TOKEN) {
  console.error('缺少 CF_API_TOKEN 环境变量');
  process.exit(1);
}

async function cf(path) {
  const res = await fetch(`https://api.cloudflare.com/client/v4/${path}`, {
    headers: { Authorization: `Bearer ${TOKEN}` },
  });
  const body = await res.json();
  if (!body.success) {
    throw new Error(`CF API ${path} 失败: ${JSON.stringify(body.errors)}`);
  }
  return body;
}

async function allRecords(zoneId) {
  const out = [];
  for (let page = 1; ; page++) {
    const { result, result_info } = await cf(
      `zones/${zoneId}/dns_records?per_page=100&page=${page}`
    );
    out.push(...result);
    if (!result_info || page >= result_info.total_pages) break;
  }
  return out;
}

const infra = JSON.parse(readFileSync(FILE, 'utf8'));
const zoneNames = infra.zones.map((z) => (typeof z === 'string' ? z : z.name));

const { result: zones } = await cf('zones?per_page=50');
const targets = zones.filter((z) => zoneNames.includes(z.name));

if (targets.length !== zoneNames.length) {
  const found = targets.map((z) => z.name);
  throw new Error(
    `zone 数量不符：期望 ${zoneNames.join(',')}，实际拿到 ${found.join(',') || '(空)'}。` +
      '令牌权限可能不足，中止以免生成不完整的快照。'
  );
}

const legacy = [];
const prefixes = new Set();

for (const zone of targets) {
  for (const r of await allRecords(zone.id)) {
    const rel = r.name === zone.name ? '@' : r.name.slice(0, -(zone.name.length + 1));
    legacy.push({
      zone: zone.name,
      name: rel,
      type: r.type,
      content: r.content,
      proxied: r.proxied ?? false,
    });
    // 申请前缀是紧邻 zone 的那一段；跳过 _acme-challenge 等验证类标签
    if (rel !== '@') {
      const label = rel.split('.').pop();
      if (!label.startsWith('_')) prefixes.add(label);
    }
  }
}

legacy.sort(
  (a, b) =>
    a.zone.localeCompare(b.zone) ||
    a.name.localeCompare(b.name) ||
    a.type.localeCompare(b.type) ||
    a.content.localeCompare(b.content)
);

const countByZone = {};
for (const r of legacy) countByZone[r.zone] = (countByZone[r.zone] ?? 0) + 1;

const prev = infra.legacy_reserved?.record_count ?? 0;
const occupied = [...prefixes].sort();
const today = new Date().toISOString().slice(0, 10);

// 记录数骤降通常意味着令牌权限收缩或 API 分页出错，而不是运营者真的删了服务。
// 宁可中止也不要写入一份会让对账任务放开删除的空快照。
if (prev > 0 && legacy.length < prev * 0.5) {
  throw new Error(
    `记录数从 ${prev} 骤降到 ${legacy.length}（超过一半消失）。` +
      '这更可能是令牌权限或分页问题，而非真实删除。已中止；确认无误后手工覆盖。'
  );
}

console.log(`记录 ${prev} → ${legacy.length}`, countByZone);
console.log(`禁止申请前缀 ${infra.occupied_prefixes?.count ?? 0} → ${occupied.length}`);

const added = occupied.filter((p) => !(infra.occupied_prefixes?.prefixes ?? []).includes(p));
const removed = (infra.occupied_prefixes?.prefixes ?? []).filter((p) => !occupied.includes(p));
if (added.length) console.log('  新增占用:', added.join(' '));
if (removed.length) console.log('  释放占用:', removed.join(' '));

if (DRY) {
  console.log('--dry-run，未写入');
  process.exit(0);
}

infra.legacy_reserved.records = legacy;
infra.legacy_reserved.record_count = legacy.length;
infra.legacy_reserved.count_by_zone = countByZone;
infra.legacy_reserved.snapshot_taken = today;
infra.occupied_prefixes.prefixes = occupied;
infra.occupied_prefixes.count = occupied.length;
infra.updated = today;

writeFileSync(FILE, JSON.stringify(infra, null, 2) + '\n');
console.log('已写入 data/infra-records.json');
