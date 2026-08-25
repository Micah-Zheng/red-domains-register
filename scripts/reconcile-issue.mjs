// 阶段 ④：对账发现漂移时开 issue。
//
// 复用同一个 issue 而非每天新开：漂移往往连续多天存在（比如一条孤儿记录没人
// 处理），每天一个新 issue 只会把仓库刷满而没人看。用固定标记找回并追加评论。

import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';

const MARK = '<!-- red-domains:reconcile-drift -->';
const repo = process.env.REPO;
const runUrl = process.env.RUN_URL ?? '';
const path = process.argv[2] ?? 'reconcile.json';

let r;
try { r = JSON.parse(readFileSync(path, 'utf8')); }
catch (e) { console.log(`无法读取对账报告：${e.message}`); process.exit(0); }

const missing = r.missing ?? [], drifted = r.drifted ?? [], orphans = r.orphans ?? [];
const total = missing.length + drifted.length + orphans.length;
if (!total) { console.log('无漂移，不开 issue。'); process.exit(0); }
if (!repo) { console.log(`发现 ${total} 处漂移，但未提供 REPO，仅打印。`); console.log(JSON.stringify(r, null, 2)); process.exit(0); }

const gh = (args, body) => execFileSync('gh',
  ['api', '-H', 'accept: application/vnd.github+json', ...args, ...(body !== undefined ? ['--input', '-'] : [])],
  { input: body, encoding: 'utf8' });

const sec = (title, items, fmt) => items.length
  ? [`### ${title}（${items.length}）`, '', ...items.slice(0, 25).map(fmt),
     items.length > 25 ? `_…另有 ${items.length - 25} 条，详见 artifact_` : '', ''].filter((l) => l !== '')
  : [];

const body = [
  MARK,
  `Git 与 Cloudflare 存在 ${total} 处不一致。`,
  '',
  ...sec('CF 缺失（Git 有，CF 无）', missing, (m) => `- \`${m.name}\` ${m.type} → \`${m.content}\``),
  ...sec('内容漂移（两边不同，疑为面板手工改动）', drifted,
        (d) => `- \`${d.name}\` ${d.type}：CF 为 \`${d.actual}\`，应为 \`${d.expected}\``),
  ...sec('孤儿记录（CF 有，Git 无 —— 仍在对外解析）', orphans,
        (o) => `- \`${o.name}\` ${o.type} → \`${o.content}\``),
  '---',
  orphans.length
    ? '**孤儿记录需要注意**：这些域名仍然可以解析，但仓库里已无对应申请。如果是被删除的申请没清理干净，属于正常清理；如果来源不明，需要确认是否有人绕过流程直接改了面板。'
    : '缺失与漂移可通过手动运行 04-reconcile（勾选 apply）修复。',
  '',
  runUrl ? `[查看本次运行](${runUrl})` : '',
].filter(Boolean).join('\n');

let issue = null;
try {
  const list = JSON.parse(gh([`/repos/${repo}/issues?state=open&labels=reconcile&per_page=50`]));
  issue = list.find((i) => String(i.body ?? '').includes(MARK));
} catch (e) { console.log(`查找现有 issue 失败：${e.message}`); }

try {
  if (issue) {
    gh(['-X', 'POST', `/repos/${repo}/issues/${issue.number}/comments`],
       JSON.stringify({ body: `${body}\n\n<sub>本次对账追加</sub>` }));
    console.log(`已在 issue #${issue.number} 追加评论`);
  } else {
    const created = JSON.parse(gh(['-X', 'POST', `/repos/${repo}/issues`],
      JSON.stringify({ title: `对账发现 ${total} 处 DNS 不一致`, body, labels: ['reconcile'] })));
    console.log(`已新建 issue #${created.number}`);
  }
} catch (e) {
  console.log(`开 issue 失败：${e.message}`);
  process.exitCode = 1;
}
