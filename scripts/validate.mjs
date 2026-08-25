#!/usr/bin/env node
/**
 * 阶段 ① 硬规则引擎（PLAN.md §6）。
 *
 * 本文件是**唯一有权说 PASS 的组件**。AI 分流（阶段 ②）只能把 PASS 降级为
 * REVIEW / REJECT，永不能提权（C4）。
 *
 * 三条不变量：
 *   1. 无凭据。按 C1，本阶段跑在 pull_request 事件里，读不到任何 secret，
 *      因此所有配额与占用判定都基于公开主干的文件内容。
 *   2. 无副作用。规则是纯函数，不发起网络写、不改文件。可本地自测。
 *   3. 短路语义。任一 REJECT 立即停止；无 REJECT 但有 REVIEW 则 REVIEW；全清则 PASS。
 *
 * 用法：
 *   node scripts/validate.mjs --file domains/tcp.red/myapp.json --actor micahzheng
 *   node scripts/validate.mjs --file <f> --actor <a> --report validation-report.json
 *
 * 退出码：0 = PASS，1 = REVIEW，2 = REJECT，3 = 内部错误（视同 REVIEW，转人工）。
 */
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { readFileSync, readdirSync, existsSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

export const RULESET_VERSION = 1;

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const ZONES = ['tcp.red', 'udp.red'];
const FILENAME_RE = /^[a-z0-9]([a-z0-9-]{2,61}[a-z0-9])?\.json$/;

const readJson = (p) => JSON.parse(readFileSync(p, 'utf8'));

/**
 * 该码点是否为不可见字符：C0/C1 控制字符、软连字符、零宽与格式字符、
 * 双向覆写字符、行分隔符、BOM。后几类是同形异义与视觉欺骗的主要载体，
 * 出现在 description 里几乎只有一种解释。
 *
 * 用码点判断而非正则字符类：这些字符写进源码就是一串肉眼不可见的字节，
 * 谁 review 都看不出改动，也容易在复制粘贴中丢失。
 */
function isInvisibleCodePoint(cp) {
  if (cp <= 0x1f || (cp >= 0x7f && cp <= 0x9f)) return true; // C0 / DEL / C1
  if (cp === 0xad) return true;                              // 软连字符
  if (cp >= 0x200b && cp <= 0x200f) return true;             // 零宽 + LRM/RLM
  if (cp >= 0x202a && cp <= 0x202e) return true;             // 双向嵌入/覆写
  if (cp === 0x2028 || cp === 0x2029) return true;           // 行/段分隔符
  if (cp >= 0x2060 && cp <= 0x2064) return true;             // word joiner 等
  if (cp >= 0x2066 && cp <= 0x2069) return true;             // 双向隔离
  if (cp === 0xfeff) return true;                            // BOM
  if (cp >= 0xfff9 && cp <= 0xfffb) return true;             // 交错注释标记
  if (cp >= 0xe0000 && cp <= 0xe007f) return true;           // tag 字符
  return false;
}

/** NFKC, lowercase, trim。data/*.json 的 match 契约要求消费方这样做。 */
const norm = (s) => String(s ?? '').normalize('NFKC').toLowerCase().trim();

/** 剥离不可见字符，用于 description 的语义判断。 */
export function stripInvisible(s) {
  let out = '';
  for (const ch of String(s ?? '').normalize('NFKC')) {
    if (!isInvisibleCodePoint(ch.codePointAt(0))) out += ch;
  }
  return out;
}

/** 该字符串是否含不可见字符。schema 的 pattern 也挡，此处给出可读的理由。 */
export const hasInvisible = (s) =>
  [...String(s ?? '')].some((ch) => isInvisibleCodePoint(ch.codePointAt(0)));

/**
 * 加载仓库状态。这是唯一读盘的地方，便于测试注入。
 * 缺失数据文件按 fail-closed 处理：抛错，退出码 3，转人工。
 * 不做静默降级 —— reserved.json 读不到却继续放行，等于保留词保护整体失效。
 */
export function loadRepoState(root = ROOT) {
  const state = {
    reserved: readJson(join(root, 'data/reserved.json')),
    cnameAllowlist: readJson(join(root, 'data/cname-allowlist.json')),
    cooldown: readJson(join(root, 'data/cooldown.json')),
    infra: readJson(join(root, 'data/infra-records.json')),
    schema: readJson(join(root, 'schema/domain.schema.json')),
    existing: new Map(),
  };

  // 主干已有申请：前缀 -> { zones, owners, contacts }
  for (const zone of ZONES) {
    const dir = join(root, 'domains', zone);
    if (!existsSync(dir)) continue;
    for (const f of readdirSync(dir)) {
      if (!f.endsWith('.json')) continue;
      const prefix = norm(f.replace(/\.json$/, ''));
      let doc;
      try {
        doc = readJson(join(dir, f));
      } catch {
        continue; // 主干里的坏文件不该阻塞新申请；reconcile 会单独报出来
      }
      if (!state.existing.has(prefix)) {
        state.existing.set(prefix, { zones: new Set(), owners: new Set(), contacts: new Set() });
      }
      const e = state.existing.get(prefix);
      e.zones.add(zone);
      if (doc?.owner?.github) e.owners.add(norm(doc.owner.github));
      if (doc?.owner?.contact_hash) e.contacts.add(norm(doc.owner.contact_hash));
    }
  }
  return state;
}

/** 判定 record.value 是否落在免挑战托管商名单内（C5 的例外）。 */
export function isAllowlistedCname(value, allowlist) {
  const v = norm(value).replace(/\.$/, '');
  return allowlist.suffixes.some(({ suffix }) => v === suffix || v.endsWith('.' + suffix));
}

/** 从文件路径解析 { zone, prefix }；非 domains/<zone>/<x>.json 形态返回 null。 */
export function parsePath(filePath) {
  const parts = filePath.replace(/\\/g, '/').split('/').filter(Boolean);
  const i = parts.indexOf('domains');
  if (i === -1 || parts.length - i !== 3) return null;
  const [, zone, file] = parts.slice(i);
  if (!ZONES.includes(zone)) return null;
  return { zone, file, prefix: norm(file.replace(/\.json$/, '')) };
}

/** 推导四档（D7）。schema 无 tier 字段，档位由 proxied / tls 组合决定。 */
export function deriveTier(doc) {
  const proxied = doc?.proxied ?? true;
  if (proxied) return 'A';
  return doc?.tls ? 'C' : 'B';
}

// ---------------------------------------------------------------------------
// 规则契约
//
// 每条规则是 (ctx) => null | { rule, verdict, message, hint? }
//   ctx = { filePath, zone, prefix, doc, actor, changedFiles, state, ajv, tier }
// 返回 null 表示通过。message 面向申请者，会出现在 PR 评论里，因此要给出
// 可操作的下一步，而不只是"不合规"。
// ---------------------------------------------------------------------------

const reject = (rule, message, hint) => ({ rule, verdict: 'REJECT', message, hint });
const review = (rule, message, hint) => ({ rule, verdict: 'REVIEW', message, hint });

// ---- REJECT：结构性违规，无申诉价值 --------------------------------------

const r_schemaValid = (ctx) => {
  const validate = ctx.ajv.compile(ctx.state.schema);
  if (validate(ctx.doc)) return null;
  const detail = validate.errors
    .slice(0, 5)
    .map((e) => `${e.instancePath || '(根)'} ${e.message}`)
    .join('；');
  return reject('r_schemaValid', `不符合 schema/domain.schema.json：${detail}`,
    '本地先跑 node scripts/validate.mjs --file <你的文件> --actor <你的用户名>');
};

const r_singleFileChange = (ctx) => {
  const domainFiles = ctx.changedFiles.filter((f) => parsePath(f));
  const otherFiles = ctx.changedFiles.filter((f) => !parsePath(f));
  if (otherFiles.length) {
    return reject('r_singleFileChange',
      `PR 只能新增 domains/<zone>/<前缀>.json，但还改动了：${otherFiles.slice(0, 5).join('、')}`,
      '把无关改动拆成独立 PR');
  }
  if (domainFiles.length > 1) {
    return reject('r_singleFileChange',
      `一个 PR 只能申请一个前缀，当前包含 ${domainFiles.length} 个：${domainFiles.join('、')}`,
      'D2 的成对锁定会自动为你同时占住 tcp.red 与 udp.red，不需要各提一个文件');
  }
  return null;
};

const r_filenameRegex = (ctx) => {
  if (FILENAME_RE.test(ctx.file)) return null;
  const stem = ctx.file.replace(/\.json$/, '');
  let why = '需为单层小写 ASCII，4 至 63 字符，只含字母数字与连字符，且不以连字符起止';
  if (stem.length < 4) why = `长度 ${stem.length}，不足 4 字符（D5：1 至 3 字符前缀全部保留）`;
  else if (stem.includes('.')) why = '含点号，前缀必须是单层（C3）';
  else if (/[A-Z]/.test(stem)) why = '含大写字母，文件名须全小写';
  else if (/^-|-$/.test(stem)) why = '以连字符起始或结尾，DNS 标签不允许';
  else if (!/^[\x20-\x7e]*$/.test(stem)) why = '含非 ASCII 字符（C3 要求单层 ASCII）';
  return reject('r_filenameRegex', `文件名 ${ctx.file} 不合规：${why}`);
};

const r_notReserved = (ctx) => {
  const { reserved } = ctx.state;
  const p = ctx.prefix;
  for (const list of reserved.match.exact_lists) {
    if ((reserved[list] ?? []).includes(p)) {
      return reject('r_notReserved',
        `前缀 ${p} 在保留池 ${list} 中，不开放申请`,
        '保留池针对钓鱼冒充与基础设施安全，不是抢注；换一个与既有品牌、基础设施名无关的前缀即可');
    }
  }
  for (const { pattern, reason } of reserved.patterns ?? []) {
    if (new RegExp(pattern).test(p)) {
      return reject('r_notReserved', `前缀 ${p} 命中保留规则：${reason}`);
    }
  }
  return null;
};

const r_prefixAvailable = (ctx) => {
  const occupied = ctx.state.infra.occupied_prefixes?.prefixes ?? [];
  if (occupied.includes(ctx.prefix)) {
    return reject('r_prefixAvailable',
      `前缀 ${ctx.prefix} 已被本服务自身的基础设施占用`,
      '这类前缀两个 zone 都不可用（D2 成对锁定），请另选');
  }
  const e = ctx.state.existing.get(ctx.prefix);
  if (!e) return null;
  // D2：前缀成对锁定。他人已占任一 zone，则整个前缀不可用。
  const others = [...e.owners].filter((o) => o !== norm(ctx.actor));
  if (others.length) {
    return reject('r_prefixAvailable',
      `前缀 ${ctx.prefix} 已由他人占用（${[...e.zones].join('、')}）`,
      'D2：一个前缀在两个 zone 上成对锁定，不拆分给不同的人');
  }
  if (e.zones.has(ctx.zone)) {
    return reject('r_prefixAvailable',
      `你已经申请过 ${ctx.prefix}.${ctx.zone}`,
      '要改配置请直接编辑那个文件，不要重复新增');
  }
  return null;
};

const r_notInCooldown = (ctx) => {
  const entry = (ctx.state.cooldown.entries ?? []).find((e) => norm(e.prefix) === ctx.prefix);
  if (!entry) return null;
  if (ctx.today > entry.release_at) return null;
  return reject('r_notInCooldown',
    `前缀 ${ctx.prefix} 处于冷却期，${entry.release_at} 之后才可再申请`,
    '冷却期用于让旧域名的残留信任（书签、第三方白名单、搜索索引）自然过期，避免流量被转交给新持有人');
};

const r_ownerMatchesActor = (ctx) => {
  if (!ctx.actor) {
    return reject('r_ownerMatchesActor', '缺少 PR actor，无法核对 owner.github');
  }
  if (norm(ctx.doc?.owner?.github) === norm(ctx.actor)) return null;
  return reject('r_ownerMatchesActor',
    `owner.github（${ctx.doc?.owner?.github}）与提交者（${ctx.actor}）不一致`,
    '只能为自己申请；代他人提交无法建立所有权与后续联系渠道');
};

const r_publicUnicastTarget = (ctx) => {
  // schema 的 pattern 已挡住绝大多数私网段。此处补 schema 表达不了的部分，
  // 并把理由写清楚 —— 用户看到"pattern 不匹配"是不知道自己填错了什么的。
  const { type, value } = ctx.doc?.record ?? {};
  if (type !== 'A' && type !== 'AAAA') return null;
  const v = norm(value);
  const bad = [
    [/^0\./, '0.0.0.0/8 保留段'],
    [/^10\./, 'RFC1918 私网 10/8'],
    [/^127\./, '回环 127/8'],
    [/^169\.254\./, '链路本地 169.254/16'],
    [/^192\.168\./, 'RFC1918 私网 192.168/16'],
    [/^172\.(1[6-9]|2\d|3[01])\./, 'RFC1918 私网 172.16/12'],
    [/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./, 'CGNAT 100.64/10（Tailscale 等覆盖网络地址，公网不可达）'],
    [/^19[89]\.1[89]\./, '基准测试保留段 198.18/15'],
    [/^192\.0\.2\./, '文档示例段 192.0.2/24'],
    [/^198\.51\.100\./, '文档示例段 198.51.100/24'],
    [/^203\.0\.113\./, '文档示例段 203.0.113/24'],
    [/^(22[4-9]|2[3-5]\d)\./, '组播或保留高段'],
    [/^::1?$/, 'IPv6 回环或未指定地址'],
    [/^f[cd]/, 'IPv6 ULA fc00::/7'],
    [/^fe[89ab]/, 'IPv6 链路本地 fe80::/10'],
    [/^ff/, 'IPv6 组播 ff00::/8'],
    [/^2001:db8:/, 'IPv6 文档段 2001:db8::/32'],
  ];
  for (const [re, why] of bad) {
    if (re.test(v)) {
      return reject('r_publicUnicastTarget',
        `record.value ${value} 落在 ${why}，公网无法路由到它`,
        '填你的服务器真实公网地址；若只在内网/隧道里可达，本服务无法为你分发');
    }
  }
  return null;
};

const r_noCnameLoop = (ctx) => {
  const { type, value } = ctx.doc?.record ?? {};
  if (type !== 'CNAME' && type !== 'SRV') return null;
  const v = norm(value).replace(/\.$/, '');
  for (const zone of ZONES) {
    if (v === zone || v.endsWith('.' + zone)) {
      return reject('r_noCnameLoop',
        `${type} 目标 ${value} 指回本服务（${zone}），会造成解析环`,
        '指向你自己的托管商地址或服务器主机名');
    }
  }
  return null;
};

const r_contactHashFormat = (ctx) => {
  const h = ctx.doc?.owner?.contact_hash;
  if (!/^sha256:[0-9a-f]{64}$/.test(String(h ?? ''))) {
    return reject('r_contactHashFormat',
      'owner.contact_hash 须为 sha256: 加 64 位小写十六进制',
      '明文邮箱只填在 PR 模板的对应字段里，不要写进 JSON（D3）');
  }
  // 一次性邮箱域名的阻断刻意不放在这里：contact_hash 是盐化哈希，无法反查
  // 域名，公开主干上做不到这件事。该判断由侧仓 bot 在拿到明文邮箱时执行
  // （D3），发确认信失败即转 REVIEW。
  return null;
};

const r_checkModeCoherent = (ctx) => {
  const { mode, port } = ctx.doc?.check ?? {};
  const type = ctx.doc?.record?.type;
  const proxied = ctx.doc?.proxied ?? true;

  if ((type === 'A' || type === 'AAAA') && mode === 'dns') {
    return reject('r_checkModeCoherent',
      'A/AAAA 记录不能用 check.mode: dns',
      'DNS 查得到只证明记录写对了，证明不了那台机器活着。改用 http（Web 服务）或 tcp（其他协议）');
  }
  if ((mode === 'http' || mode === 'tcp') && port == null) {
    return reject('r_checkModeCoherent', `check.mode: ${mode} 必须填 check.port`);
  }
  if (mode === 'tcp' && proxied) {
    return reject('r_checkModeCoherent',
      'check.mode: tcp 需要 proxied: false',
      '橙云只代理 HTTP/HTTPS，裸 TCP 探测打到的是 CF 边缘而非你的源站。跑非 HTTP 服务请走 B 档灰云');
  }
  if (mode === 'manual' && !ctx.doc?.check?.reason) {
    return reject('r_checkModeCoherent', 'check.mode: manual 必须填 check.reason 说明为何无法自动探测');
  }
  return null;
};

// ---- REVIEW：需要人类判断，不是拒绝 --------------------------------------
//
// 这一组全部可申诉、可重试。设计意图是"拿不准就转人工"，而不是把边缘情况
// 一律挡在门外 —— 公益服务的价值在于让正当用途顺利通过，误杀的代价比多看
// 一眼高得多。

const r_descriptionMeaningful = (ctx) => {
  const raw = ctx.doc?.description ?? '';
  if (hasInvisible(raw)) {
    return reject('r_descriptionMeaningful',
      'description 含零宽或双向覆写字符',
      '这类字符是视觉欺骗的载体，请用普通文字描述用途');
  }
  const clean = stripInvisible(raw).trim();
  if (clean.length < 5) {
    return reject('r_descriptionMeaningful',
      `description 剥离不可见字符后仅 ${clean.length} 字符，不足 5`);
  }
  // 占位符检测。两个坑：
  //   1. 不能写成 /^(test|demo|asdf)$/ —— 那些词全短于 schema 的 minLength: 5，
  //      永远走不到这里。真实占位符是 "test site"、"placeholder for now"。
  //   2. 不能纯靠空格分词 —— "测试用网站" 没有空格，会被当成一个未知词放过。
  // 做法：把占位词与停用词从字符串里整体剔除，看剩余的实义内容有多少。
  // 中文按剩余字符数、拉丁按剩余词数分别兜底。
  const lower = clean.toLowerCase();
  const FILLER = [
    // 中文（无空格，需按子串剔除）
    '测试用', '测试', '占位', '随便', '暂无', '待定', '示例', '样例', '我的',
    '网站', '主页', '首页', '页面', '临时', '什么都没有', '没什么', '啥也没有',
    '这是', '那是', '就是', '写点', '写个', '弄个', '搞个', '放点', '一个', '啥的',
    // 语气词与虚指代词是封闭类（有限集），可以安全穷举；实义词组合不行。
    '什么', '啥', '一下', '点儿', '吧', '啦', '呢', '嘛', '哦', '呀', '的', '了', '着', '过',
    // 拉丁
    'placeholder', 'testing', 'tests', 'test', 'demos', 'demo', 'example',
    'sample', 'asdf', 'qwerty', 'lorem', 'ipsum', 'foobar', 'foo', 'bar', 'baz',
    'todo', 'tbd', 'temp', 'tmp', 'whatever', 'idk', 'nothing', 'stuff',
    'website', 'webpage', 'homepage', 'site', 'page', 'web', 'thing', 'things',
    'something', 'anything', 'none', 'null', 'n/a', 'na',
    // 停用词：单独出现不构成信息
    'just', 'only', 'for', 'now', 'the', 'a', 'an', 'my', 'mine', 'our', 'some',
    'this', 'that', 'it', 'is', 'are', 'of', 'to', 'and', 'or', 'with', 'in', 'on',
  ];
  let residue = lower;
  for (const w of FILLER) residue = residue.split(w).join(' ');
  residue = residue.replace(/[\s,，。.、;；:：/|_+()（）【】\[\]"'`~!?！？*#-]+/g, '').replace(/[0-9]+/g, '');
  // 门槛取值的权衡：CJK 要求 3 字以上。2 字放行会让"这是测试"剩「这是」、
  // "随便写点"剩「写点」这类虚词组合蒙混过关，而中文虚词的组合方式穷举不完，
  // 靠扩词表追不上。宁可让极短的中文描述走一次 REVIEW —— 误判的代价是人看
  // 一眼，漏判的代价是无法判断 D7 影音分发意图就放行。
  const cjk = [...residue].filter((c) => /[一-鿿぀-ヿ가-힯]/.test(c)).length;
  if (cjk === 0 && residue.length < 3) {
    return review('r_descriptionMeaningful',
      `description "${clean}" 剔除占位词后无实义内容，无法判断用途`,
      '写一句话说明这个域名要指向什么服务，例如"个人博客，Hugo 静态站"或"小范围朋友的 Minecraft 服务器"。D7 需要据此判断是否属于影音分发用途');
  }
  if (cjk > 0 && cjk < 3) {
    return review('r_descriptionMeaningful',
      `description "${clean}" 剔除占位词后仅剩 ${cjk} 个汉字，信息量不足`,
      '写一句话说明用途即可');
  }
  // 单字重复（aaaaa、啊啊啊啊啊）能过 minLength，同样没有信息量。
  if (new Set(clean.replace(/\s/g, '')).size <= 2) {
    return review('r_descriptionMeaningful',
      `description "${clean}" 是重复字符，无法判断实际用途`,
      '写一句话说明用途即可');
  }
  return null;
};

const r_accountAge = (ctx) => {
  const days = ctx.actorMeta?.accountAgeDays;
  if (days == null) {
    return review('r_accountAge', '无法获取 GitHub 账号年龄，转人工核验');
  }
  if (days >= 30) return null;
  return review('r_accountAge',
    `GitHub 账号仅注册 ${days} 天（阈值 30 天）`,
    '新账号不代表恶意，人工确认后即可通过；这条规则挡的是批量注册刷号');
};

const r_accountActivity = (ctx) => {
  const m = ctx.actorMeta;
  if (!m) return review('r_accountActivity', '无法获取账号活动信息，转人工核验');
  if ((m.publicRepos ?? 0) > 0 || (m.publicGists ?? 0) > 0 || (m.followers ?? 0) > 0) return null;
  return review('r_accountActivity',
    '该账号无任何公开仓库、Gist 或关注者',
    '这只是一个信号而非结论 —— 很多人的确只用 GitHub 提 PR。人工看一眼即可');
};

const r_quotaPerUser = (ctx) => {
  // D1/D2：跨 zone 合并计数，成对锁定的一个前缀只算 1 个。
  const actor = norm(ctx.actor);
  let n = 0;
  for (const [prefix, e] of ctx.state.existing) {
    if (prefix !== ctx.prefix && e.owners.has(actor)) n++;
  }
  if (n < 3) return null;
  return review('r_quotaPerUser',
    `你已持有 ${n} 个前缀（软上限 3），本次申请转人工`,
    '有正当理由（多个独立项目、社区共用）说明一下即可放行；上限用于防止单人囤积');
};

const r_quotaPerContact = (ctx) => {
  const hash = norm(ctx.doc?.owner?.contact_hash);
  let n = 0;
  const owners = new Set();
  for (const [prefix, e] of ctx.state.existing) {
    if (prefix !== ctx.prefix && e.contacts.has(hash)) {
      n++;
      for (const o of e.owners) owners.add(o);
    }
  }
  if (n < 3) return null;
  const multi = owners.size > 1 ? `，涉及 ${owners.size} 个 GitHub 账号` : '';
  return review('r_quotaPerContact',
    `同一联系方式已关联 ${n} 个前缀（软上限 3）${multi}`,
    '这条与账号配额并列，防的是换号不换人');
};

const r_rateLimit24h = (ctx) => {
  const m = ctx.actorMeta;
  if (m?.prCount24h != null && m.prCount24h > 2) {
    return review('r_rateLimit24h',
      `你在 24 小时内已提交 ${m.prCount24h} 个申请（上限 2）`,
      '明天再来即可，无需重开 PR');
  }
  if (m?.globalNew24h != null && m.globalNew24h > 50) {
    return review('r_rateLimit24h',
      `全局 24 小时新增 ${m.globalNew24h} 个申请，超过异常阈值 50，全部转人工`,
      '这不是针对你 —— 异常涌入期间所有申请都会人工过一遍');
  }
  return null;
};

const r_bareIpTarget = (ctx) => {
  const { type } = ctx.doc?.record ?? {};
  if (type !== 'A' && type !== 'AAAA') return null;
  return review('r_bareIpTarget',
    `记录指向裸 IP（${ctx.doc.record.value}），需确认该地址确实属于你`,
    '按 C5 完成所有权挑战即可；指向托管商域名（见 data/cname-allowlist.json）可免挑战');
};

const r_ownershipChallenge = (ctx) => {
  // C5：目标所有权必须验证，否则可构造指向他人资源的悬空 CNAME 并借本域名的
  // 信任实施钓鱼。免挑战的唯一例外是名单内托管商 —— 它们自己要求所有权验证。
  const { type, value } = ctx.doc?.record ?? {};
  if (type === 'CNAME' && isAllowlistedCname(value, ctx.state.cnameAllowlist)) return null;
  if (ctx.challengeVerified === true) return null;
  return review('r_ownershipChallenge',
    '目标所有权挑战尚未通过',
    '按 PR 模板里的挑战串在目标侧放一条 TXT 记录，然后在 PR 里回复 /recheck；这一步可重试，不会因此关闭申请');
};

const r_manualCheckMode = (ctx) => {
  if (ctx.doc?.check?.mode !== 'manual') return null;
  return review('r_manualCheckMode',
    'check.mode: manual 首次申请需人工确认',
    `你填的理由是："${ctx.doc.check.reason}"。确认无法自动探测后即放行（D4）`);
};

const r_tierCoherent = (ctx) => {
  // 档位与声明的一致性。schema 已挡死硬冲突，这里补语义层面的可疑组合。
  const tier = ctx.tier;
  if (tier === 'C' && !ctx.doc.tls?.public_cert && !ctx.doc.tls?.acme_dns_delegate) {
    return review('r_tierCoherent', 'tls 对象存在但未声明 public_cert 或 acme_dns_delegate，意图不明');
  }
  // C 档一律过预算闸门。acme_dns_delegate 同样消耗注册域的 LE 配额（50 证书/
  // 7 天，按注册域计，是外部限制无法绕过），而且 DNS-01 正是签通配证书的
  // 途径，用量可能高于 public_cert。早期版本只检查 public_cert，DNS-01
  // 委派会直接 PASS —— 那是配额被静默耗尽的入口。
  if (tier === 'C') {
    // C 档消耗共享证书配额（§8.4），需要预算闸门参与判定。
    return review('r_tierCoherent',
      'C 档（自签公信证书）需经证书预算闸门',
      '若预算见底，申请会进队列而非被拒；也可改用 A 档（橙云免费 HTTPS）立即通过');
  }
  return null;
};

export const HARD_RULES = [
  // REJECT 组：顺序有意义 —— 先挡结构性问题，再查占用与归属
  r_schemaValid,
  r_singleFileChange,
  r_filenameRegex,
  r_notReserved,
  r_prefixAvailable,
  r_notInCooldown,
  r_ownerMatchesActor,
  r_publicUnicastTarget,
  r_noCnameLoop,
  r_contactHashFormat,
  r_checkModeCoherent,
  r_descriptionMeaningful,
  // REVIEW 组
  r_accountAge,
  r_accountActivity,
  r_quotaPerUser,
  r_quotaPerContact,
  r_rateLimit24h,
  r_bareIpTarget,
  r_ownershipChallenge,
  r_manualCheckMode,
  r_tierCoherent,
];

// ---------------------------------------------------------------------------
// 引擎
// ---------------------------------------------------------------------------

/**
 * 跑完整规则表。纯函数：不读盘、不发网络请求、不写文件。
 *
 * 短路语义（§6）：任一 REJECT 立即停止后续规则 —— 结构性违规之后的判定
 * 多半是噪音（例如 schema 都没过，配额计数没有意义）。无 REJECT 时收集
 * 全部 REVIEW，让人工一次看到所有待确认项，而不是修一条冒一条。
 */
export function runRules(input) {
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  addFormats(ajv);

  const parsed = parsePath(input.filePath);
  if (!parsed) {
    return {
      verdict: 'REJECT',
      ruleset_version: RULESET_VERSION,
      findings: [reject('r_filePathShape',
        `${input.filePath} 不是合法的申请路径`,
        '路径须为 domains/tcp.red/<前缀>.json 或 domains/udp.red/<前缀>.json')],
    };
  }

  const ctx = {
    ...input,
    ...parsed,
    ajv,
    tier: deriveTier(input.doc),
    today: input.today ?? new Date().toISOString().slice(0, 10),
  };

  const findings = [];
  for (const rule of HARD_RULES) {
    let out;
    try {
      out = rule(ctx);
    } catch (err) {
      // 规则本身抛错时按 fail-closed 转人工，绝不当成通过。
      out = review(rule.name, `规则执行异常：${err.message}`, '这是本服务的 bug，请在 PR 里 @ 运营者');
    }
    if (!out) continue;
    findings.push(out);
    if (out.verdict === 'REJECT') break;
  }

  const verdict = findings.some((f) => f.verdict === 'REJECT')
    ? 'REJECT'
    : findings.length
      ? 'REVIEW'
      : 'PASS';

  return {
    verdict,
    ruleset_version: RULESET_VERSION,
    zone: ctx.zone,
    prefix: ctx.prefix,
    tier: ctx.tier,
    paired_zones: ZONES,
    findings,
  };
}

const EXIT = { PASS: 0, REVIEW: 1, REJECT: 2 };

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) continue;
    const key = a.slice(2).replace(/-([a-z])/g, (_, c) => c.toUpperCase());
    const next = argv[i + 1];
    if (next && !next.startsWith('--')) { out[key] = next; i++; } else { out[key] = true; }
  }
  return out;
}

function render(report) {
  const icon = { PASS: 'PASS', REVIEW: 'REVIEW', REJECT: 'REJECT' }[report.verdict];
  const lines = [`${icon}  ${report.prefix ?? '?'}  (档位 ${report.tier ?? '?'}，ruleset v${report.ruleset_version})`];
  for (const f of report.findings) {
    lines.push(`  [${f.verdict}] ${f.rule}`);
    lines.push(`      ${f.message}`);
    if (f.hint) lines.push(`      提示：${f.hint}`);
  }
  if (report.verdict === 'PASS') {
    lines.push(`  全部 ${HARD_RULES.length} 条规则通过。合并后将在 ${ZONES.join(' 与 ')} 上成对下发。`);
  }
  return lines.join('\n');
}

// 仅在直接执行时跑 CLI；被 import 时只导出纯函数，便于测试。
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    const args = parseArgs(process.argv.slice(2));
    if (!args.file) {
      console.error('用法: node scripts/validate.mjs --file domains/<zone>/<前缀>.json --actor <github-用户名>');
      process.exit(3);
    }
    const filePath = String(args.file);
    const state = loadRepoState();
    const doc = readJson(join(ROOT, filePath));
    const changedFiles = args.changedFiles
      ? String(args.changedFiles).split(',').map((s) => s.trim()).filter(Boolean)
      : [filePath];

    const actorMeta = args.actorMeta ? readJson(String(args.actorMeta)) : null;

    const report = runRules({
      filePath,
      doc,
      actor: args.actor ? String(args.actor) : null,
      changedFiles,
      state,
      actorMeta,
      challengeVerified: args.challengeVerified === true || args.challengeVerified === 'true',
    });

    console.log(render(report));
    if (args.report) {
      writeFileSync(String(args.report), JSON.stringify(report, null, 2) + '\n');
    }
    process.exit(EXIT[report.verdict]);
  } catch (err) {
    // 内部错误一律退 3（转人工），绝不退 0。fail-closed。
    console.error(`内部错误：${err.message}`);
    process.exit(3);
  }
}
