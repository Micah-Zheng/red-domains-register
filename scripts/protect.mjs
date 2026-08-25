// 记录保护判定：一条 CF 记录是否**禁止**被自动化摘除或覆盖。
//
// 这是 infra-records.json 的消费方，实现该文件 match 段声明的语义：
//   `@`  = zone apex
//   `*`  = 单标签通配（不跨点）
//   `**` = 多标签通配（跨点）
//   match: exact | wildcard | regex
//
// 两道屏障，任一命中即保护：
//   1. records[]        —— 基础设施白名单（PSL/CAA/DKIM/SPF/MX/apex/www…）
//   2. legacy_reserved  —— 上线前既有记录快照，policy: never_touch
//
// 为什么必须有：对账逻辑会把「CF 有、Git 无」判为孤儿并删除。运营者的 64 条
// 既有记录（Cloudflare Tunnel、Tailscale、邮件）都没有申请文件，不挡住就会被
// 一次性拆掉。删掉 _psl 会中断 PSL 收录；删掉 DKIM 会让通知邮件全进垃圾箱。

const norm = (s) => String(s ?? '').toLowerCase().replace(/\.$/, '');

/** 把 infra-records.json 的通配 name 编译成正则。 */
function wildcardToRegex(pattern) {
  // 先按 ** / * 切分，其余部分整体转义，避免 `_acme-challenge.*` 里的 `.` 被当通配。
  const parts = norm(pattern).split(/(\*\*|\*)/);
  const body = parts.map((p) => {
    if (p === '**') return '.*';           // 跨点
    if (p === '*') return '[^.]+';         // 单标签，不跨点
    return p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }).join('');
  return new RegExp(`^${body}$`);
}

function nameMatches(entry, relName) {
  const target = norm(relName);
  const pat = norm(entry.name);
  switch (entry.match) {
    case 'exact': return target === pat;
    case 'wildcard': return wildcardToRegex(entry.name).test(target);
    case 'regex': return new RegExp(entry.pattern).test(relName);
    default: return target === pat;   // 未声明 match 时按 exact，fail-closed 偏保护
  }
}

function typeMatches(entry, type) {
  return entry.type === '*' || String(entry.type).toUpperCase() === String(type).toUpperCase();
}

function valueMatches(entry, record) {
  if (!entry.value_pattern) return true;
  // value_pattern 用于区分同名同型的多条记录（如 apex 上 SPF TXT 与其他 TXT）。
  const content = record.content ?? '';
  return new RegExp(entry.value_pattern).test(String(content).replace(/^"|"$/g, ''));
}

/**
 * @param {object} infra  data/infra-records.json
 * @returns {(rec: {name: string, type: string, content?: string, zone: string}) => null | {reason: string, source: string, entry?: object}}
 *   rec.name 为相对 zone 的名字（`@` 表示 apex）。返回 null 表示不受保护。
 */
export function createProtector(infra) {
  const entries = infra.records ?? [];
  const legacy = infra.legacy_reserved?.records ?? [];

  // legacy 建索引：zone|name|type|content 全等才算命中，避免「同名但内容已改」
  // 的记录被错误保护（那种情况属于漂移，该走人工确认）。
  const legacyIndex = new Map();
  for (const r of legacy) {
    const k = `${norm(r.zone)}|${norm(r.name)}|${String(r.type).toUpperCase()}`;
    if (!legacyIndex.has(k)) legacyIndex.set(k, []);
    legacyIndex.get(k).push(r);
  }

  return function protect(rec) {
    const zone = norm(rec.zone);
    const relName = rec.name;

    // 屏障 1：基础设施白名单
    for (const e of entries) {
      if (e.zones && !e.zones.map(norm).includes(zone)) continue;
      if (!typeMatches(e, rec.type)) continue;
      if (!nameMatches(e, relName)) continue;
      if (!valueMatches(e, rec)) continue;
      return {
        reason: e.$comment?.split('。')[0] ?? `基础设施白名单：${e.name} ${e.type}`,
        source: 'infra_whitelist',
        permanent: !!e.permanent,
        managed_by: e.managed_by,
        entry: e,
      };
    }

    // 屏障 2：上线前既有记录快照（never_touch）
    const k = `${zone}|${norm(relName)}|${String(rec.type).toUpperCase()}`;
    const cands = legacyIndex.get(k);
    if (cands?.length) {
      const c = norm(rec.content);
      const exact = cands.find((x) => norm(x.content) === c);
      if (exact) {
        return {
          reason: `上线前既有记录（snapshot ${infra.legacy_reserved?.snapshot_taken}），policy: never_touch`,
          source: 'legacy_reserved',
          permanent: true,
          managed_by: 'operator',
          entry: exact,
        };
      }
      // 同名同型但内容不同：既有记录被手工改过，或我们要写的值会覆盖它。
      // 不自动放行也不自动删除 —— 标为需人工确认。
      return {
        reason: `与上线前既有记录同名同型但内容不同（快照值：${cands.map((x) => x.content).join('、')}），可能是手工改动或快照过期`,
        source: 'legacy_conflict',
        permanent: false,
        managed_by: 'operator',
        needsHuman: true,
        entry: cands[0],
      };
    }

    return null;
  };
}
