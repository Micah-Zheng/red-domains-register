// Workflow 凭据边界自检。
//
// 为什么值得单独一个测试：三段式的全部安全性都压在「哪一段拿到哪些 secret」上，
// 而这个约束只存在于 YAML 里 —— 没有类型系统、没有运行时检查会拦住有人把
// pull_request 改成 pull_request_target 顺手加个 CF_API_TOKEN。那种改动看起来
// 只是「让 CI 能贴评论了」，实际是把 zone 控制权交给任意 PR 提交者。
//
// 不引 YAML 依赖：只做保守的块级切分。文中注释常需要提到被禁用的事件名来解释
// 原因，所以判定必须基于结构位置，而不是全文出现与否。

import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const DIR = '.github/workflows';
let pass = 0; const fails = [];
const ok = (c, m) => { if (c) { pass += 1; console.log(`  ok   ${m}`); } else { fails.push(m); console.log(`  FAIL ${m}`); } };

/** 去掉行注释（保守：只处理行首空白后紧跟 # 的整行注释）。 */
const stripComments = (s) => s.split('\n').filter((l) => !/^\s*#/.test(l)).join('\n');

/** 取顶层键 key 到下一个顶层键之间的块。 */
function topBlock(src, key) {
  const lines = stripComments(src).split('\n');
  const start = lines.findIndex((l) => new RegExp(`^${key}:`).test(l));
  if (start === -1) return null;
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i += 1) {
    if (/^[A-Za-z_]/.test(lines[i])) { end = i; break; }
  }
  return lines.slice(start, end).join('\n');
}

const files = readdirSync(DIR).filter((f) => f.endsWith('.yml')).sort();
console.log(`\n=== Workflow 凭据边界（${files.length} 个文件）===`);

const DEPLOY_SECRETS = ['CF_API_TOKEN', 'RESEND_API_KEY'];

for (const f of files) {
  const src = readFileSync(join(DIR, f), 'utf8');
  const body = stripComments(src);
  const onBlock = topBlock(src, 'on') ?? '';
  const stage = f.slice(0, 2);
  console.log(`\n${f}`);

  // 全局铁律：pull_request_target 在本项目任何 workflow 中都不允许。
  // 它带全部 secrets 在主干上下文运行，与「checkout PR 代码」组合即 pwn request。
  ok(!/^\s+pull_request_target:/m.test(onBlock),
     'on: 块内无 pull_request_target');

  const usesDeploySecret = DEPLOY_SECRETS.some((s) => body.includes(`secrets.${s}`));
  const checksOutPr = /pull_request\.head\.(sha|ref)|github\.event\.pull_request\.head/.test(body)
    || /ref:\s*\$\{\{\s*github\.head_ref/.test(body);

  // 核心不变式：持有下发凭据的 job 绝不 checkout PR 可控代码。
  ok(!(usesDeploySecret && checksOutPr),
     usesDeploySecret ? '持有下发凭据但不检出 PR 代码' : '不持有下发凭据（检出 PR 代码无妨）');

  if (stage === '01') {
    ok(/^\s+pull_request:/m.test(onBlock), '阶段①：由 pull_request 触发');
    ok(!usesDeploySecret, '阶段①：不引用 CF/Resend 凭据');
    ok(/contents:\s*read/.test(body) && !/contents:\s*write/.test(body),
       '阶段①：contents 只读');
    ok(body.includes('--ignore-scripts'), '阶段①：npm ci 关闭安装钩子');
  }

  if (stage === '02') {
    // 阶段②只拿 AI 凭据，且必须以 workflow_run 方式脱离 PR 上下文。
    ok(/workflow_run:/.test(onBlock), '阶段②：由 workflow_run 触发');
    ok(!usesDeploySecret, '阶段②：不引用 CF/Resend 凭据');
    ok(!checksOutPr, '阶段②：不检出 PR 代码（只读 diff 文本）');
  }

  if (stage === '05') {
    // 阶段⑤由 issue_comment 触发，那是主干上下文且带 secrets。它的安全性完全
    // 依赖「只检出 main、PR 文件走 API」这一条：一旦 checkout 了 PR 代码，
    // 提交者改一行 validate.mjs 就能让自己的申请全绿并自助放行。
    ok(/issue_comment:/.test(onBlock), '阶段⑤：由 issue_comment 触发');
    ok(/ref:\s*main/.test(body), '阶段⑤：显式检出 main');
    ok(!checksOutPr, '阶段⑤：不检出 PR 代码');
    ok(!usesDeploySecret, '阶段⑤：不引用 CF/Resend 凭据（重试不下发）');
    // 必须限制谁能触发，否则路人可替他人反复触发校验刷 API 配额。
    ok(/author_association|comment\.user\.login/.test(src),
       '阶段⑤：限制了可触发的评论者');
    ok(body.includes('--ignore-scripts'), '阶段⑤：npm ci 关闭安装钩子');
  }

  if (stage === '03') {
    // 阶段③是唯一持有下发凭据的一段，只能在已合并的 main 上跑。
    ok(/^\s+push:/m.test(onBlock) || /workflow_dispatch:/.test(onBlock),
       '阶段③：由 push(main) 或手动触发');
    ok(!/pull_request/.test(onBlock), '阶段③：不由任何 PR 事件触发');
    ok(!checksOutPr, '阶段③：不检出 PR 代码');
  }
}

// —— YAML 结构合法性（不引解析器，只抓一类致命写法）
//
// 2026-08-26 实际踩到：06-cooldown.yml 的 `run: |` 块里写了
// `git commit -m "第一行\n\n第二行"`，后续行顶格。`run: |` 是 YAML 块标量，
// 靠缩进界定范围，顶格行会提前终止块、随后被当成顶层键解析 —— 整个 workflow
// 文件非法。GitHub 的表现极具误导性：run 在 0 秒内失败，名字显示成原始文件路径
// 而不是 workflow 的 name，日志里没有任何一行说「YAML 语法错误」。
//
// 上面那些断言全是正则扫描，扫的是文本而非结构，所以一个语法上根本无法运行的
// workflow 可以让它们全绿。这条补的正是那个盲区。
console.log('\n=== YAML 结构：块标量内不得出现顶格行 ===');
for (const f of readdirSync(DIR).filter((x) => x.endsWith('.yml'))) {
  const lines = readFileSync(join(DIR, f), 'utf8').split('\n');
  const offenders = [];
  let seenKey = false;
  lines.forEach((l, i) => {
    if (/^[A-Za-z_][\w.-]*\s*:/.test(l)) { seenKey = true; return; }   // 合法顶层键
    if (!seenKey) return;                                                // 文件头注释等
    if (l.trim() === '') return;
    if (/^\s/.test(l)) return;                                          // 有缩进，正常
    if (/^(#|---|\.\.\.)/.test(l)) return;                              // 注释与文档分隔
    offenders.push(`${i + 1}:${l.slice(0, 40)}`);
  });
  ok(offenders.length === 0,
    `${f} 无顶格续行${offenders.length ? ` —— 第 ${offenders.join('、')}` : ''}`);
}

console.log(`\n${pass}/${pass + fails.length} 通过`);
if (fails.length) { console.log('\n失败项：'); for (const m of fails) console.log(`  · ${m}`); process.exit(1); }
