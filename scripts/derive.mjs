// 从申请文件推导「该名字应有的完整记录集」。
//
// 这是下发（cf-sync）与对账（reconcile）的**唯一**事实源。两边必须调用同一个
// 函数，否则一定漂移 —— PLAN §9.1 结尾要求的正是这一点：对账要比对完整记录集
// （主记录 + 按档位的 CAA + 可选 ACME 委派），而不是只比主记录、把伴生记录
// 当成多余而摘掉。
//
// 记录形状对齐 Cloudflare API /zones/{id}/dns_records，name 用相对 zone 的名字
// （`@` 表示 apex），由 cf-sync 在调用前补成 FQDN。

import { deriveTier } from './validate.mjs';

// CF 合法 TTL：1 = auto，其余须落在 60–86400。橙云记录 TTL 由 CF 接管，恒为 1。
export const TTL_AUTO = 1;
export const TTL_MIN = 60;
export const TTL_MAX = 86400;

/** A/B 档下发的阻挡性 CAA：任何 CA 都不得为该名字签发证书。 */
export const CAA_DENY = [
  { flags: 0, tag: 'issue', value: ';' },
  { flags: 0, tag: 'issuewild', value: ';' },
];

export function normalizeTtl(ttl, proxied) {
  // 橙云下 TTL 无意义且 CF 会拒绝非 1 的值。
  if (proxied) return TTL_AUTO;
  if (ttl === undefined || ttl === null) return TTL_AUTO;
  if (ttl === TTL_AUTO) return TTL_AUTO;
  return Math.min(TTL_MAX, Math.max(TTL_MIN, ttl));
}

/**
 * @param {{prefix: string, zone: string, doc: object}} input
 * @returns {{tier: string, records: Array<object>}}
 *   records 为该前缀在该 zone 下**应当存在的全部记录**。对账时：
 *   这个集合之外、且落在 domains/ 命名空间内的同名记录 → 多余，可摘除。
 */
export function deriveRecords({ prefix, zone, doc }) {
  const tier = deriveTier(doc);
  const proxied = doc.proxied ?? true;
  const ttl = normalizeTtl(doc.ttl, proxied);
  const records = [];

  // —— 主记录
  const main = { name: prefix, type: doc.record.type, ttl, comment: gitopsComment(tier) };
  if (doc.record.type === 'SRV') {
    // SRV 经不了代理（D7），schema 已强制 proxied:false。CF 的 SRV 用 data 对象，
    // 不用 content 字符串 —— 写成 content 会被静默接受但解析不出来。
    main.data = {
      priority: doc.record.priority,
      weight: doc.record.weight,
      port: doc.record.port,
      target: stripDot(doc.record.value),
    };
  } else {
    main.content = stripDot(doc.record.value);
    main.proxied = proxied;
  }
  records.push(main);

  // —— CAA：A/B 档下发阻挡性 CAA，C 档不下发（否则用户签不了证书）
  // SRV 也落在 B 档并拿到阻挡 CAA。SRV 目标（如 mc.example.com）不在本 zone 内，
  // 所以这条 CAA 通常挡的是用户并不使用的名字，无害。但若用户日后在同前缀上
  // 加 A/AAAA 跑 HTTPS，就会被自己的 CAA 挡住签发 —— 那时应改声明 tls 转 C 档。
  // 保守方向（默认挡住）是对的：漏挡会静默耗尽共享的 LE 配额。
  //
  // **主记录是 CNAME 时绝不下发同名 CAA。** CNAME 不得与任何其它类型共存
  // （RFC 1034 §3.6.2、RFC 2181 §10.1）。Cloudflare 的 API 不拦这种写入 ——
  // 三条记录全部返回 success:true、面板里也都在 —— 但权威解析层遇到冲突会
  // 只应答 CAA，把 CNAME 静默丢弃。表现是：下发日志全绿、对账判定「已一致」、
  // 而这个名字**根本不解析**。实测 micah-pages.tcp.red 与 smoketest.tcp.red
  // 都因此完全不可用，删掉两条叶子 CAA 后当场恢复解析。
  //
  // 后果是 A 档（橙云，主记录恒为 CNAME）的叶子 deny-CAA 在 DNS 协议层面不可
  // 实现，§8.4 档位表里那一行做不到。这类名字的签发策略改由 zone apex 的 CAA
  // 承担：橙云记录被 CF 展平成 A，CA 在该名字上查 CAA 得 NODATA，按 RFC 8659
  // 上溯到 apex。但 apex 必须放行 CF Universal SSL 可能用到的 CA（含
  // letsencrypt.org），所以 A 档用户仍可走 HTTP-01 自签 —— §8.4 想防的「批量
  // 注册刷证书抽干共享池」在 CAA 这一层已无手段，只剩 §6 的每账号注册配额。
  // 这是已知缺口，不是可以靠调参数补上的东西，见 PLAN §8.4 的「DNS 层硬约束」。
  //
  // 灰云 CNAME（B 档）更彻底：CA 会跟随 CNAME 到目标名字上查 CAA（RFC 8659 §3），
  // 我们在本 zone 内的任何 CAA 都管不到它。
  //
  // 主记录为 A / AAAA / SRV 时同名 CAA 合法，照常下发。
  const mainIsCname = String(doc.record.type).toUpperCase() === 'CNAME';
  if ((tier === 'A' || tier === 'B') && !mainIsCname) {
    for (const caa of CAA_DENY) {
      records.push({
        name: prefix, type: 'CAA', ttl: TTL_AUTO, data: { ...caa },
        comment: gitopsComment(tier, 'CAA 阻挡：该档位不允许自签公信证书'),
      });
    }
  }

  // —— C 档可选的 DNS-01 委派
  if (doc.tls?.acme_dns_delegate) {
    records.push({
      name: `_acme-challenge.${prefix}`, type: 'CNAME',
      content: stripDot(doc.tls.acme_dns_delegate),
      proxied: false, ttl: TTL_AUTO,
      comment: gitopsComment(tier, 'DNS-01 委派'),
    });
  }

  return { tier, records, zone, prefix };
}

/**
 * 记录归属标记。写进 CF 的 comment 字段，让对账能区分
 * 「本服务下发的」与「手工加的 / 来源不明的」。
 * §9.1 规定来源不明的记录不自动摘除，只标记待人工确认。
 */
export const GITOPS_TAG = 'red-domains:gitops';
export function gitopsComment(tier, note) {
  return note ? `${GITOPS_TAG} tier=${tier} ${note}` : `${GITOPS_TAG} tier=${tier}`;
}
export const isGitopsManaged = (comment) => String(comment ?? '').includes(GITOPS_TAG);

const stripDot = (s) => String(s).replace(/\.$/, '');

/** 记录身份键。用于 diff：同键视为同一条记录，只比对内容差异。 */
export function recordKey(r) {
  const base = `${String(r.name).toLowerCase()}|${r.type}`;
  // CAA 同名同型可有多条，须把 tag 纳入键；SRV 同理（同名可挂多个目标）。
  if (r.type === 'CAA') return `${base}|${r.data?.tag ?? ''}`;
  if (r.type === 'SRV') return `${base}|${r.data?.target ?? ''}|${r.data?.port ?? ''}`;
  return base;
}

/** 内容等价判断。CF 返回的字段比我们写入的多，只比对我们管理的那些。 */
export function sameContent(want, got) {
  if (want.type !== got.type) return false;
  if (want.type === 'CAA') {
    return String(want.data?.tag) === String(got.data?.tag)
      && String(want.data?.value) === String(got.data?.value)
      && Number(want.data?.flags ?? 0) === Number(got.data?.flags ?? 0);
  }
  if (want.type === 'SRV') {
    return ['priority', 'weight', 'port'].every((k) => Number(want.data?.[k]) === Number(got.data?.[k]))
      && stripDot(want.data?.target ?? '').toLowerCase() === stripDot(got.data?.target ?? '').toLowerCase();
  }
  const c1 = stripDot(want.content ?? '').toLowerCase();
  const c2 = stripDot(got.content ?? '').toLowerCase();
  if (c1 !== c2) return false;
  if ((want.proxied ?? false) !== (got.proxied ?? false)) return false;
  // 橙云记录的 TTL 由 CF 强制为 1，不参与比对，避免无穷 update 循环。
  if (!want.proxied && Number(want.ttl) !== Number(got.ttl)) return false;
  return true;
}
