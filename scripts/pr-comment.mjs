// 阶段 ②：把判定结果贴成 PR 评论 + 打标签。
//
// 两个必须注意的点：
//
// 1. 提交者可控文本进入 Markdown 前必须转义。PLAN v1 的邮件模板用裸 replace
//    拼接，那既是 HTML 注入也是 Markdown 注入 —— 一个 description 里塞
//    </details><script> 或反引号就能破坏评论结构、伪造成"系统已批准"的样子。
//    这里统一走 mdCode()：放进代码围栏，并处理围栏本身被闭合的情况。
//
// 2. 评论要复用而非叠加。同一个 PR 反复推送会产生一长串评论，用户找不到最新
//    结论。用隐藏锚点找回自己上次的评论并编辑。

import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { CHALLENGE_PATH } from './challenge.mjs';

const ANCHOR = '<!-- red-domains:verdict -->';
const report = JSON.parse(readFileSync(process.env.REPORT_PATH ?? 'report.json', 'utf8'));
const triage = JSON.parse(readFileSync(process.env.TRIAGE_PATH ?? 'triage.json', 'utf8'));
const repo = process.env.REPO;
const pr = report.prNumber;

/** 把不可信文本放进代码围栏。若文本自身含围栏，加长外层围栏使其无法闭合。 */
function mdCode(s) {
  const text = String(s ?? '').slice(0, 1000);
  const longest = Math.max(0, ...[...text.matchAll(/`+/g)].map((m) => m[0].length));
  const fence = '`'.repeat(Math.max(3, longest + 1));
  return `${fence}\n${text.replace(/\r/g, '')}\n${fence}`;
}
/** 行内不可信文本：转义反引号并限长。 */
const inline = (s) => `\`${String(s ?? '').slice(0, 200).replace(/`/g, 'ˋ')}\``;

function gh(args, body) {
  const a = ['api', '-H', 'accept: application/vnd.github+json', ...args];
  if (body !== undefined) a.push('--input', '-');
  return execFileSync('gh', a, { input: body, encoding: 'utf8' });
}

// 字段名以 ci-validate.mjs / validate.mjs 的实际产出为准：
//   verdict / ruleset_version / zone / prefix / tier / findings[] / file
//   / actor / actor_meta / challenge / changed_files
// findings 是单一扁平数组，每项自带 verdict（REJECT|REVIEW），不是 errors/warnings 两个数组。
const zone = report.zone ?? 'tcp.red';
const prefix = report.prefix ?? '?';
const doc = report.doc ?? {};
const target = doc.record?.value ?? report.challenge?.target ?? '';
const rtype = doc.record?.type ?? '';
const findings = report.findings ?? [];
const rejects = findings.filter((f) => f.verdict === 'REJECT');
const reviews = findings.filter((f) => f.verdict !== 'REJECT');

// 最终结论取阶段①与 triage 的**更严格者**。
// 不无条件信 triage：两个文件经 artifact 分别传递，理论上可能错配（重跑、
// artifact 串号）。阶段①是确定性事实源，triage 只被允许在其之上收紧。
const RANK = { SKIP: -1, PASS: 0, REVIEW: 1, REJECT: 2 };
const stage1 = report.verdict ?? 'REVIEW';
const claimed = triage.final ?? stage1;
const final = (RANK[claimed] ?? 1) >= (RANK[stage1] ?? 1) ? claimed : stage1;
if (final !== claimed) {
  console.log(`⚠️ triage 报告 ${claimed} 宽于阶段① ${stage1}，以阶段①为准（疑为报告错配）。`);
}

const icon = { PASS: '✅', REVIEW: '👀', REJECT: '❌', SKIP: '⏭️' }[final] ?? '❔';
const title = { PASS: '校验通过', REVIEW: '需要人工复核', REJECT: '校验未通过', SKIP: '无需校验' }[final] ?? '状态未知';

const lines = [ANCHOR, `## ${icon} ${title}`, ''];
lines.push(`申请：${inline(`${prefix}.${zone}`)}${rtype ? ` ${rtype}` : ''}${target ? ` → ${inline(target)}` : ''}`
  + (report.tier ? `　档位 ${inline(report.tier)}` : ''), '');

if (rejects.length) {
  lines.push('### 必须修正', '');
  for (const f of rejects) {
    lines.push(`- **${f.rule}** ${f.message}`);
    if (f.hint) lines.push(`  - ${f.hint}`);
  }
  lines.push('');
}
if (reviews.length) {
  lines.push('### 需要人工确认', '');
  for (const f of reviews) {
    lines.push(`- **${f.rule}** ${f.message}`);
    if (f.hint) lines.push(`  - ${f.hint}`);
  }
  lines.push('');
}

// challenge 的实际字段是 verified / skipped / reason / detail[]，不是 ok/path/expected。
const ch = report.challenge;
if (ch && ch.verified === false) {
  lines.push('### 所有权验证未通过', '');
  lines.push(`${ch.reason ?? '未通过'}`, '');
  lines.push(`需要证明你控制 ${inline(target || '目标主机')}：把下面这串写入该主机的`, '');
  lines.push(`路径 ${inline(CHALLENGE_PATH)}`, '');
  if (report.expectedToken) lines.push(mdCode(report.expectedToken));
  if (ch.detail?.length) {
    lines.push('', '<details><summary>本次探测详情</summary>', '', mdCode(ch.detail.join('\n')), '', '</details>');
  }
  lines.push('');
} else if (ch?.skipped) {
  lines.push(`_所有权验证已跳过：${ch.skipped}_`, '');
}

if (triage.ai?.signals?.length && !triage.ai.signals.includes('none')) {
  lines.push('### 自动分流标记', '', triage.ai.signals.join('、'), '');
  if (triage.shadowMode) lines.push('_影子模式：仅记录，不影响本次结论。_', '');
}
if (final === 'REVIEW') lines.push('已转人工复核，运营者会尽快处理。无需重复提交。', '');
if (final === 'PASS') lines.push('合并后会自动下发 DNS，生效通常在数分钟内。', '');
if (report.verdict === 'SKIP') lines.push(report.reason ?? '本 PR 未改动申请文件。', '');

lines.push('---', `<sub>由自动校验生成 · 规则集 ${report.ruleset_version ?? 'n/a'}</sub>`);
const body = lines.join('\n');

if (!repo || !pr) {
  console.log('未提供 REPO / prNumber，仅打印评论内容：\n');
  console.log(body);
  process.exit(0);
}

// 找回自己上次的评论
let existing = null;
try {
  const list = JSON.parse(gh([`/repos/${repo}/issues/${pr}/comments?per_page=100`]));
  existing = list.find((c) => String(c.body ?? '').includes(ANCHOR));
} catch (e) {
  console.log(`列出评论失败（继续新建）：${e.message}`);
}

const payload = JSON.stringify({ body });
try {
  if (existing) {
    gh(['-X', 'PATCH', `/repos/${repo}/issues/comments/${existing.id}`], payload);
    console.log(`已更新评论 #${existing.id}`);
  } else {
    gh(['-X', 'POST', `/repos/${repo}/issues/${pr}/comments`], payload);
    console.log('已新建评论');
  }
} catch (e) {
  console.log(`贴评论失败：${e.message}`);
  process.exitCode = 1;
}

// 标签：三种状态互斥，先清再打。
const LABELS = { PASS: 'validated', REVIEW: 'needs-review', REJECT: 'changes-requested' };
if (!LABELS[final]) { console.log(`verdict=${final}，不打标签。`); process.exit(0); }
for (const [k, name] of Object.entries(LABELS)) {
  if (k === final) continue;
  try { gh(['-X', 'DELETE', `/repos/${repo}/issues/${pr}/labels/${name}`]); } catch { /* 本来没有 */ }
}
try {
  gh(['-X', 'POST', `/repos/${repo}/issues/${pr}/labels`], JSON.stringify({ labels: [LABELS[final]] }));
  console.log(`已打标签 ${LABELS[final]}`);
} catch (e) {
  console.log(`打标签失败：${e.message}`);
}
