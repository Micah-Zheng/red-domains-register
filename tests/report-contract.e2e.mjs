// report.json 契约测试。
//
// 存在原因：阶段①产出 report.json，阶段②的 ai-triage 和 pr-comment 消费它，
// 三者跑在不同 job、经 artifact 传递，没有任何类型检查会发现字段名对不上。
// 曾经真的对不上 —— 消费端读 errors/warnings/application/challenge.ok，
// 而生产端产出 findings/doc/challenge.verified。后果不是报错，是评论渲染成
// 一个没有任何内容的空标题：所有分支静默跳过，用户看不到该改什么。
//
// 所以这里不用手写 fixture（手写 fixture 正是当初没发现问题的原因），
// 而是调真实的 runRules() 拿到真实形状，再喂给消费端。

import { runRules, loadRepoState, parsePath } from '../scripts/validate.mjs';
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

let pass = 0; const fails = [];
const ok = (c, m) => { if (c) { pass += 1; console.log(`  ok   ${m}`); } else { fails.push(m); console.log(`  FAIL ${m}`); } };

console.log('\n=== report.json 生产端 → 消费端契约 ===');

// ---- 1. 用真实 runRules 产出 report ------------------------------------
const state = loadRepoState();
const file = 'domains/tcp.red/smoketest.json';
const doc = JSON.parse(readFileSync(file, 'utf8'));
const { zone, prefix } = parsePath(file);

const produced = {
  ...runRules({
    filePath: file, doc, actor: 'Micah-Zheng', changedFiles: [file], state,
    actorMeta: { accountAgeDays: 900, publicRepos: 12, followers: 30, prCount24h: 1, globalNew24h: 3 },
    changeKind: 'M', challengeVerified: true,
  }),
  file, actor: 'Micah-Zheng',
  actor_meta: { accountAgeDays: 900, publicRepos: 12, followers: 30, prCount24h: 1, globalNew24h: 3 },
  challenge: { verified: true, detail: ['已在 https://micahzheng.github.io/... 验证'] },
  changed_files: [file],
  doc,
  expectedToken: 'a'.repeat(64),
  prNumber: 42,
};

// ---- 2. 断言生产端契约 -------------------------------------------------
const REQUIRED = ['verdict', 'ruleset_version', 'zone', 'prefix', 'tier', 'findings', 'doc', 'file'];
for (const k of REQUIRED) ok(produced[k] !== undefined, `生产端产出 ${k}`);
ok(Array.isArray(produced.findings), 'findings 是数组');
ok(produced.errors === undefined && produced.warnings === undefined,
   '不存在 errors/warnings（消费端不得读它们）');
ok(produced.application === undefined, '不存在 application 包装层');
for (const f of produced.findings) {
  ok(typeof f.rule === 'string' && ['REJECT', 'REVIEW'].includes(f.verdict),
     `finding ${f.rule} 形状合规`);
}

// ---- 3. 消费端必须真的渲染出内容 ---------------------------------------
const dir = mkdtempSync(join(tmpdir(), 'contract-'));
const rp = join(dir, 'report.json');
const tp = join(dir, 'triage.json');

function render(report, triage) {
  writeFileSync(rp, JSON.stringify(report));
  writeFileSync(tp, JSON.stringify(triage));
  return execFileSync('node', ['scripts/pr-comment.mjs'],
    { encoding: 'utf8', env: { ...process.env, REPORT_PATH: rp, TRIAGE_PATH: tp, REPO: '', PR_NUMBER: '' } });
}

// PASS：应出现域名，不应有空的"必须修正"
const out1 = render(produced, { final: produced.verdict, shadowMode: true });
ok(out1.includes(`${prefix}.${zone}`), '评论含申请域名');
ok(out1.includes(produced.ruleset_version), '评论含规则集版本');

// REJECT + findings：每条 finding 的 rule 与 message 都必须出现
const rejected = {
  ...produced,
  verdict: 'REJECT',
  findings: [
    { rule: 'r_targetAllowlist', verdict: 'REJECT', message: '目标不在允许列表内', hint: '换用受支持的托管商' },
    { rule: 'r_prefixReserved', verdict: 'REVIEW', message: '前缀过短，需人工确认' },
  ],
  challenge: { verified: false, reason: '无法读取挑战文件', detail: ['404', 'DNS: A=1.2.3.4'] },
};
const out2 = render(rejected, { final: 'REJECT', shadowMode: false });
for (const f of rejected.findings) {
  ok(out2.includes(f.rule), `评论含 ${f.rule}`);
  ok(out2.includes(f.message), `评论含 ${f.rule} 的说明`);
}
ok(out2.includes(rejected.findings[0].hint), '评论含修复提示');
ok(out2.includes('所有权验证未通过'), '评论含挑战失败区块');
ok(out2.includes('.well-known'), '评论含挑战文件路径');
ok(out2.includes('404'), '评论含探测详情');
ok(!/### 必须修正\s*\n\s*\n\s*---/.test(out2), '"必须修正"区块非空');

// SKIP：不该渲染成"状态未知"
const out3 = render({ verdict: 'SKIP', reason: '本 PR 未改动申请文件', changed_files: ['README.md'], prNumber: 1 },
                    { final: 'SKIP' });
ok(out3.includes('无需校验'), 'SKIP 有专属标题');
ok(!out3.includes('状态未知'), 'SKIP 不落到未知分支');

// ---- 4. ai-triage 也必须读到真实字段 -----------------------------------
const stub = join(dir, 'stub.mjs');
writeFileSync(stub, `
let captured = '';
globalThis.fetch = async (_u, o) => {
  const b = JSON.parse(o.body);
  // OpenAI 兼容形状：messages[0] 是 system，用户内容在 role==='user' 那条。
  captured = b.messages.find((m) => m.role === 'user').content;
  process.on('exit', () => console.log('PROMPT>>>' + captured));
  return new Response(JSON.stringify({choices:[{message:{tool_calls:[{
    function:{name:'submit_verdict',arguments:JSON.stringify(
      {verdict:'looks_fine',reasons:[],confidence:0.9,signals:['none']})}}]}}]}),{status:200});
};
await import('${process.cwd()}/scripts/ai-triage.mjs');
`);
writeFileSync(rp, JSON.stringify(produced));
const out4 = execFileSync('node', [stub], {
  encoding: 'utf8',
  env: { ...process.env, REPORT_PATH: rp, TRIAGE_OUT: join(dir, 'o.json'),
         AI_API_KEY: 'fake', AI_SHADOW_MODE: 'true' },
});
const prompt = out4.split('PROMPT>>>')[1] ?? '';
ok(prompt.includes(doc.description), 'AI prompt 含申请说明（非 undefined）');
ok(prompt.includes(doc.record.value), 'AI prompt 含解析目标');
ok(prompt.includes(doc.owner.github), 'AI prompt 含提交者账号');
ok(!prompt.includes('undefined'), 'AI prompt 无 undefined 字段');

console.log(`\n${pass}/${pass + fails.length} 通过`);
if (fails.length) { console.log('\n失败项：'); for (const m of fails) console.log(`  · ${m}`); process.exit(1); }
