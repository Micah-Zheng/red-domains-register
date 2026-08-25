// 端到端回归：真实 data/ 状态 + 真实 schema，覆盖四档判定与短路语义。
// 跑法：node tests/validate.e2e.mjs
import { readdirSync } from 'node:fs';
import { runRules, loadRepoState } from '../scripts/validate.mjs';

const state = loadRepoState();
const HASH = 'sha256:' + 'a'.repeat(64);
const meta = { accountAgeDays: 400, publicRepos: 5, followers: 3, prCount24h: 1, globalNew24h: 2 };

const base = (o = {}) => ({
  description: '个人博客，Hugo 静态站',
  owner: { github: 'Micah-Zheng', contact_hash: HASH },
  record: { type: 'CNAME', value: 'micahzheng.github.io' },
  check: { mode: 'http', port: 443 },
  ...o,
});

// 删除路径的公共 override：走真实存在的 smoketest.json，与 CI 实际情形一致。
const DEL = {
  filePath: 'domains/tcp.red/smoketest.json',
  changedFiles: ['domains/tcp.red/smoketest.json'],
  changeKind: 'D',
};

const run = (doc, over = {}) => runRules({
  filePath: 'domains/tcp.red/myblog.json', doc, actor: 'Micah-Zheng',
  changedFiles: ['domains/tcp.red/myblog.json'], state, actorMeta: meta,
  challengeVerified: true, today: '2026-08-25', ...over,
});

const cases = [
  // —— 正常路径
  ['A 档 白名单 CNAME + 挑战已过', run(base()), 'PASS', 'A'],
  ['B 档 灰云 Minecraft', run(base({ proxied: false, record: { type: 'A', value: '203.0.114.9' }, check: { mode: 'tcp', port: 25565 }, description: '朋友的 Minecraft 服务器' })), 'REVIEW', 'B'],
  ['C 档 ACME DNS-01 委派', run(base({ proxied: false, tls: { acme_dns_delegate: 'acme.example.com' }, record: { type: 'CNAME', value: 'app.fly.dev' }, check: { mode: 'http', port: 443 } })), 'REVIEW', 'C'],
  ['C 档 自签公信证书', run(base({ proxied: false, tls: { public_cert: true }, record: { type: 'A', value: '203.0.114.9' }, check: { mode: 'http', port: 443 } })), 'REVIEW', 'C'],
  ['manual 探测模式', run(base({ check: { mode: 'manual', reason: '服务仅在特定时段开放' } })), 'REVIEW', 'A'],

  // —— 所有权与身份
  ['挑战未通过', run(base({ record: { type: 'CNAME', value: 'self-hosted.example.com' } }), { challengeVerified: false }), 'REVIEW', 'A'],
  ['owner 与 actor 不符', run(base({ owner: { github: 'someoneelse', contact_hash: HASH } })), 'REJECT', 'A'],
  ['明文邮箱冒充 hash', run(base({ owner: { github: 'Micah-Zheng', contact_hash: 'me@example.com' } })), 'REJECT', 'A'],

  // —— 目标地址
  ['私网 IP 192.168', run(base({ proxied: false, record: { type: 'A', value: '192.168.1.10' }, check: { mode: 'tcp', port: 8080 } })), 'REJECT', 'B'],
  ['CGNAT 100.119', run(base({ proxied: false, record: { type: 'A', value: '100.119.5.5' }, check: { mode: 'tcp', port: 22 } })), 'REJECT', 'B'],
  ['CNAME 指回自有 zone', run(base({ record: { type: 'CNAME', value: 'other.tcp.red' } })), 'REJECT', 'A'],

  // —— 橙云与探测的一致性
  ['橙云 + tcp 探测', run(base({ check: { mode: 'tcp', port: 25565 } })), 'REJECT', 'A'],
  ['A 记录 + dns 探测', run(base({ proxied: false, record: { type: 'A', value: '203.0.114.9' }, check: { mode: 'dns' } })), 'REJECT', 'B'],

  // —— 前缀池
  ['保留词 api', run(base(), { filePath: 'domains/tcp.red/api.json' }), 'REJECT', 'A'],
  ['3 字符短前缀', run(base(), { filePath: 'domains/tcp.red/abc.json' }), 'REJECT', 'A'],
  ['非法路径', run(base(), { filePath: 'evil/x.json' }), 'REJECT', undefined],

  // —— description
  ['占位 description', run(base({ description: 'test site' })), 'REVIEW', 'A'],

  // —— 账号信誉与速率
  ['新账号 3 天', run(base(), { actorMeta: { ...meta, accountAgeDays: 3 } }), 'REVIEW', 'A'],
  ['24h 内 5 个 PR', run(base(), { actorMeta: { ...meta, prCount24h: 5 } }), 'REVIEW', 'A'],

  // —— 更新已有申请（§7 允许 owner 改自己的记录）
  ['修改自己的记录 换目标', run(base({ record: { type: 'CNAME', value: 'micahzheng.pages.dev' } }),
    { filePath: 'domains/tcp.red/smoketest.json', changedFiles: ['domains/tcp.red/smoketest.json'], changeKind: 'M' }),
    'PASS', 'A'],
  ['新增时前缀已被自己占用', run(base(),
    { filePath: 'domains/tcp.red/smoketest.json', changedFiles: ['domains/tcp.red/smoketest.json'], changeKind: 'A' }),
    'REJECT', 'A'],
  ['改他人的文件', run(base({ owner: { github: 'someoneelse', contact_hash: HASH } }),
    { filePath: 'domains/tcp.red/smoketest.json', changedFiles: ['domains/tcp.red/smoketest.json'], changeKind: 'M' }),
    'REJECT', 'A'],

  // —— PR 边界
  ['夹带脚本文件', run(base(), { changedFiles: ['domains/tcp.red/myblog.json', 'scripts/cf-sync.mjs'] }), 'REJECT', 'A'],
  ['一 PR 两个前缀', run(base(), { changedFiles: ['domains/tcp.red/a.json', 'domains/tcp.red/b.json'] }), 'REJECT', 'A'],

  // —— 删除 / 释放前缀（changeKind 'D'）
  // doc 来自 base 分支的原文件，鉴权只看其中的 owner.github。
  ['释放自己的前缀', run(base(), { ...DEL }), 'REVIEW', 'A'],
  ['删他人的前缀', run(base({ owner: { github: 'someoneelse', contact_hash: HASH } }), { ...DEL }), 'REJECT', 'A'],
  ['运营者代删他人前缀', run(base({ owner: { github: 'someoneelse', contact_hash: HASH } }),
    { ...DEL, authorAssociation: 'OWNER' }), 'REVIEW', 'A'],
  ['外部贡献者伪称 OWNER 无效', run(base({ owner: { github: 'someoneelse', contact_hash: HASH } }),
    { ...DEL, authorAssociation: 'CONTRIBUTOR' }), 'REJECT', 'A'],
  ['删除时缺 actor', run(base(), { ...DEL, actor: '' }), 'REJECT', 'A'],
  // 删除不该被"申请内容"类规则拦住 —— 被删的记录本来就在库里，无需重新合规。
  ['删除保留词记录不被 notReserved 拦', run(base(),
    { ...DEL, filePath: 'domains/tcp.red/api.json', changedFiles: ['domains/tcp.red/api.json'] }), 'REVIEW', 'A'],
  ['删除时占位 description 不拦', run(base({ description: 'test site' }), { ...DEL }), 'REVIEW', 'A'],
  ['删除时挑战未过不拦', run(base(), { ...DEL, challengeVerified: false }), 'REVIEW', 'A'],
  // 但结构性边界仍然生效：删除 PR 同样不许夹带其他文件。
  ['删除夹带 workflow 文件', run(base(),
    { ...DEL, changedFiles: ['domains/tcp.red/smoketest.json', '.github/workflows/03-cf-sync.yml'] }), 'REJECT', 'A'],

  // —— 运营者配额豁免（速率豁免，持有量不豁免）
  ['运营者 24h 内 5 个 PR 不限速', run(base(),
    { actorMeta: { ...meta, prCount24h: 5 }, authorAssociation: 'OWNER' }), 'PASS', 'A'],
  ['运营者仍受全局涌入阈值约束', run(base(),
    { actorMeta: { ...meta, globalNew24h: 80 }, authorAssociation: 'OWNER' }), 'REVIEW', 'A'],
];

let pass = 0, fail = 0;
for (const [name, rep, wantV, wantT] of cases) {
  if (rep.verdict === wantV && rep.tier === wantT) { pass++; console.log(`  ok   ${name}`); }
  else {
    fail++;
    console.log(`  FAIL ${name}`);
    console.log(`       判定 ${rep.verdict} (期望 ${wantV}) / 档位 ${rep.tier} (期望 ${wantT})`);
    for (const f of rep.findings) console.log(`       - ${f.rule}: ${f.verdict} — ${f.message}`);
  }
}

// REJECT 应立即短路，不继续累积 findings
const short = run(base({ owner: { github: 'x', contact_hash: 'bad' } }));
const shortOk = short.findings.length === 1;
if (!shortOk) fail++; else pass++;
console.log(`  ${shortOk ? 'ok  ' : 'FAIL'} REJECT 后短路（findings=${short.findings.length}）`);

// exclude：CI 检出的是合并后的树，新增的申请文件已在工作区。loadRepoState 必须
// 把它剔除，否则每个新申请都会撞上自己的前缀（r_prefixAvailable 只放行 'M'）。
// 用真实已存在的申请文件当样本：不剔除时它算已占用，剔除后应当可用。
{
  const existingFiles = readdirSync('domains/tcp.red').filter((f) => f.endsWith('.json'));
  if (existingFiles.length === 0) {
    console.log('  skip 自撞回归：domains/tcp.red 下暂无申请文件可用作样本');
  } else {
    const sample = existingFiles[0];
    const prefix = sample.replace(/\.json$/, '');
    const path = `domains/tcp.red/${sample}`;

    const withSelf = loadRepoState();
    const occupied = withSelf.existing.has(prefix);

    const excluded = loadRepoState(undefined, new Set([path]));
    const freed = !excluded.existing.has(prefix);

    if (occupied && freed) { pass++; console.log(`  ok   exclude 剔除本次变更文件（${prefix}）`); }
    else {
      fail++;
      console.log(`  FAIL exclude 剔除本次变更文件（${prefix}）`);
      console.log(`       未剔除时应占用=${occupied}，剔除后应释放=${freed}`);
    }

    // 端到端：新增一个与工作区同名的申请，剔除后不该被 r_prefixAvailable 拒。
    const rep = runRules({
      filePath: path, doc: base(), actor: 'Micah-Zheng',
      changedFiles: [path], state: excluded, actorMeta: meta,
      challengeVerified: true, today: '2026-08-25', changeKind: 'A',
    });
    const notSelfRejected = !rep.findings.some((f) => f.rule === 'r_prefixAvailable');
    if (notSelfRejected) { pass++; console.log('  ok   新增申请不被自身前缀拒绝'); }
    else {
      fail++;
      console.log('  FAIL 新增申请不被自身前缀拒绝');
      for (const f of rep.findings) console.log(`       - ${f.rule}: ${f.verdict} — ${f.message}`);
    }
  }
}

console.log(`\n${pass}/${pass + fail} 通过`);
process.exit(fail ? 1 : 0);
