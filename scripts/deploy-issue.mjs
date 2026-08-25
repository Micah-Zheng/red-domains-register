// 下发后权威未应答时开 Issue（PLAN §8.3：「任一记录下发失败 → 开 Issue @管理员，
// 且不发成功邮件」）。
//
// 复用同一个 issue：这类故障往往是上游持续一段时间，每次 run 新开一个只会刷屏。

import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';

const MARK = '<!-- red-domains:deploy-unverified -->';
const repo = process.env.REPO;
const runUrl = process.env.RUN_URL ?? '';
const path = process.argv[2] ?? process.env.VERIFY_REPORT ?? 'verify-report.json';

let r;
try { r = JSON.parse(readFileSync(path, 'utf8')); }
catch (e) { console.log(`无法读取验证报告：${e.message}`); process.exit(0); }

const failed = r.failed ?? [];
if (!failed.length) { console.log('无未生效记录，不开 issue。'); process.exit(0); }
if (!repo) { console.log(`${failed.length} 条未生效，但未提供 REPO，仅打印。`); console.log(JSON.stringify(r, null, 2)); process.exit(0); }

const gh = (args, body) => execFileSync('gh',
  ['api', '-H', 'accept: application/vnd.github+json', ...args, ...(body !== undefined ? ['--input', '-'] : [])],
  { input: body, encoding: 'utf8' });

const body = [
  MARK,
  `下发已写入 Cloudflare，但 **${failed.length} 条记录在 ${r.timeoutMs / 1000}s 内未被权威 NS 应答**（共检查 ${r.checked} 条，重试 ${r.rounds} 轮）。`,
  '',
  '### 未生效',
  '',
  ...failed.map((f) => `- \`${f.fqdn}\` ${f.type} — 来自 \`${f.file}\``),
  '',
  '### 已按 §8.3 处置',
  '',
  '- **未发送开通通知**。邮件与 DNS 不是原子操作，用户收到「已生效」而实际解析不到是最差的失败模式。',
  '- Cloudflare 侧记录已写入，无需重新下发；权威恢复后重跑本 workflow 即可完成通知。',
  '',
  '### 排查方向',
  '',
  '1. `dig +short <名字> @<zone 的权威 NS>` —— 直接问权威，别问公共解析器（有正负缓存）。',
  '2. 若 API `GET /dns_records` 里有记录而权威 NODATA，是 Cloudflare 控制面与数据面不同步，非本仓库问题。',
  '   2026-08-25 曾遇到一次：11 条新记录只有 1 条真正下发，持续约 1 小时，期间 API、面板、对账全部显示正常。',
  '3. 状态页与社区：https://www.cloudflarestatus.com/ 、https://community.cloudflare.com/',
  '',
  runUrl ? `运行记录：${runUrl}` : '',
].filter((l) => l !== '').join('\n');

const found = JSON.parse(gh([`/search/issues?q=${encodeURIComponent(`repo:${repo} is:issue is:open "${MARK}"`)}`]));
const hit = found.items?.[0];

if (hit) {
  gh(['-X', 'POST', `/repos/${repo}/issues/${hit.number}/comments`], JSON.stringify({ body }));
  console.log(`已在 issue #${hit.number} 追加评论。`);
} else {
  const out = JSON.parse(gh(['-X', 'POST', `/repos/${repo}/issues`],
    JSON.stringify({ title: '下发后权威未应答，已阻止开通通知', body })));
  console.log(`已开 issue #${out.number}。`);
}
