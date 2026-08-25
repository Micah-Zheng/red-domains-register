// 阶段 ①：硬规则校验。由 pull_request 事件触发。
//
// 凭据边界：本段**不持有** CF_API_TOKEN / RESEND_API_KEY / AI 凭据。
// fork 的 pull_request 事件里 secrets 本就为空，这不是额外加固而是事实。
// 因此本段可以安全地 checkout PR 代码 —— 即便 PR 内含恶意脚本，也没有凭据可偷。
// 绝不可把本段改成 pull_request_target：那会让 PR 可控代码在带全部 secrets 的
// 主干上下文里运行（pwn request）。
//
// 输出：写 report.json 供阶段 ② 读取；同时在 stdout 打人类可读结论。
// 退出码恒为 0 —— 判定结果通过 report.json 传递，让 REJECT 也能正常贴评论。

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { runRules, loadRepoState, isAllowlistedCname, parsePath } from './validate.mjs';
import { verifyChallenge, expectedToken, CHALLENGE_PATH } from './challenge.mjs';

const OUT = process.env.REPORT_PATH ?? 'report.json';

function gh(path) {
  const token = process.env.GITHUB_TOKEN;
  const url = `https://api.github.com${path}`;
  const args = ['-sS', '-H', 'accept: application/vnd.github+json'];
  if (token) args.push('-H', `authorization: Bearer ${token}`);
  args.push(url);
  try {
    return JSON.parse(execFileSync('curl', args, { encoding: 'utf8', timeout: 15000 }));
  } catch {
    return null; // 取不到信誉数据时按最保守值处理，见下
  }
}

function changedFiles() {
  // /recheck（阶段⑤）只检出 main，本地没有 PR 的 head commit，git diff 无从计算。
  // 那条路径改用 GitHub API 取文件清单落到 CHANGED_FILES，格式为每行 "状态\t路径"
  // 或纯路径（纯路径按 'M' 处理：重试场景下前缀占用已在首次校验查过，
  // 按 M 处理不会把用户自己的既有记录误判成冲突）。
  const listFile = process.env.CHANGED_FILES;
  if (listFile && existsSync(listFile)) {
    return readFileSync(listFile, 'utf8').split('\n').map((l) => l.trim()).filter(Boolean)
      .map((l) => {
        const parts = l.split(/\t/);
        if (parts.length > 1) {
          const st = parts[0];
          return { path: parts[parts.length - 1], kind: st.startsWith('R') ? 'A' : st[0] };
        }
        return { path: parts[0], kind: 'M' };
      });
  }
  const base = process.env.BASE_SHA;
  const head = process.env.HEAD_SHA;
  if (!base || !head) return [];
  const out = execFileSync('git', ['diff', '--name-status', '--diff-filter=ACMRT', `${base}...${head}`],
    { encoding: 'utf8' });
  // 保留状态位：'A' 新增 vs 'M' 修改，决定 r_prefixAvailable 是否查占用。
  // R（重命名）折算成 A —— 改前缀等于申请一个新名字。
  return out.split('\n').map((l) => l.trim()).filter(Boolean).map((l) => {
    const [st, ...rest] = l.split(/\t/);
    const path = rest[rest.length - 1];
    return { path, kind: st.startsWith('R') ? 'A' : st[0] };
  });
}

async function actorReputation(login, repo) {
  const u = gh(`/users/${encodeURIComponent(login)}`);
  // 取不到就填 0 —— 0 会命中"新账号"阈值转 REVIEW，符合 fail-closed。
  const created = u?.created_at ? Date.parse(u.created_at) : Date.now();
  const accountAgeDays = Math.floor((Date.now() - created) / 86400000);

  // 该申请者 24h 内在本仓开的 PR 数
  const since = new Date(Date.now() - 86400000).toISOString();
  const q = `repo:${repo}+type:pr+author:${login}+created:>${since}`;
  const mine = gh(`/search/issues?q=${q}&per_page=1`);
  const all = gh(`/search/issues?q=repo:${repo}+type:pr+created:>${since}&per_page=1`);

  return {
    accountAgeDays,
    publicRepos: u?.public_repos ?? 0,
    followers: u?.followers ?? 0,
    prCount24h: mine?.total_count ?? 99,     // 取不到按超限处理
    globalNew24h: all?.total_count ?? 0,
  };
}

const changes = changedFiles();
const files = changes.map((c) => c.path);
const applications = changes.filter((c) => parsePath(c.path));

if (applications.length === 0) {
  const report = {
    verdict: 'SKIP',
    reason: '本 PR 未新增或修改任何 domains/<zone>/<prefix>.json',
    changed_files: files,
    prNumber: Number(process.env.PR_NUMBER) || undefined,
  };
  writeFileSync(OUT, JSON.stringify(report, null, 2));
  console.log('无申请文件变更，跳过校验。');
  process.exit(0);
}

const state = loadRepoState();
// PR_AUTHOR 是 workflow 传入的名字；PR_ACTOR 作为别名保留，两者都接受。
// 曾经这里只读 PR_ACTOR 而 workflow 只传 PR_AUTHOR，导致 actor 恒为空 ——
// 所有涉及提交者身份的规则（归属一致、配额、账号年龄）都在对空账号做判断，
// 且挑战串算错。空 actor 会被 r_ownerMatchesActor 拦成人工，不会误放行，
// 但自动化实际上是瘸的。tests/report-contract.e2e.mjs 现在断言这一点。
const actor = (process.env.PR_AUTHOR ?? process.env.PR_ACTOR ?? '').toLowerCase();
if (!actor) console.log('⚠️ PR_AUTHOR/PR_ACTOR 均未设置，涉及提交者身份的规则将全部转人工。');
const repo = process.env.GITHUB_REPOSITORY ?? '';
const salt = process.env.CHALLENGE_SALT ?? '';
const actorMeta = await actorReputation(actor, repo);

// 一个 PR 只允许一个申请文件（r_singleFile 会拦），这里仍按数组处理以便
// 把"提交了 3 个文件"这件事完整报给用户，而不是只报第一个。
const filePath = applications[0].path;
const changeKind = applications[0].kind;
let doc = null;
let parseError = null;
try {
  doc = JSON.parse(readFileSync(filePath, 'utf8'));
} catch (err) {
  parseError = err.message;
}

let challenge = { verified: false, reason: '未执行' };
let challengeToken = null;
if (doc) {
  const { prefix } = parsePath(filePath);
  const allowlisted = doc?.record?.type === 'CNAME'
    && isAllowlistedCname(doc.record.value, state.cnameAllowlist);
  try { challengeToken = expectedToken(prefix, doc?.owner?.github, salt); }
  catch { challengeToken = null; }   // salt 未配置时不阻断校验，只是评论里不显示串
  try {
    challenge = await verifyChallenge({ prefix, doc, salt, allowlisted });
  } catch (err) {
    challenge = { verified: false, reason: `挑战校验异常：${err.message}` };
  }
}

const report = doc
  ? {
      ...runRules({
        filePath, doc, actor, changedFiles: files, state, actorMeta,
        changeKind, challengeVerified: challenge.verified,
      }),
      file: filePath,
      actor,
      actor_meta: actorMeta,
      challenge,
      changed_files: files,
      // 下游（阶段②的 AI 分流与评论渲染）需要申请原文与挑战串。
      // 这里显式带上，避免消费端去猜字段或重新读文件 —— 阶段②不检出 PR 代码，
      // report.json 是它能看到 PR 内容的唯一通道。
      doc,
      challenge_path: CHALLENGE_PATH,
      expectedToken: challengeToken,
      prNumber: Number(process.env.PR_NUMBER) || undefined,
    }
  : {
      verdict: 'REJECT',
      file: filePath,
      actor,
      findings: [{
        rule: 'r_jsonParse', verdict: 'REJECT',
        message: `${filePath} 不是合法 JSON：${parseError}`,
        hint: '用 `node -e "JSON.parse(require(\'fs\').readFileSync(process.argv[1],\'utf8\'))" <文件>` 本地自检',
      }],
      changed_files: files,
      prNumber: Number(process.env.PR_NUMBER) || undefined,
    };

writeFileSync(OUT, JSON.stringify(report, null, 2));

const icon = { PASS: '✅', REVIEW: '🔍', REJECT: '❌', SKIP: '⏭️' }[report.verdict] ?? '?';
console.log(`${icon} ${report.verdict}  ${filePath}  档位 ${report.tier ?? '-'}`);
if (challenge.skipped) console.log(`   挑战：${challenge.skipped}`);
else if (challenge.detail) console.log(`   挑战：${challenge.verified ? '通过' : challenge.reason} — ${challenge.detail.join('；')}`);
for (const f of report.findings ?? []) {
  console.log(`   [${f.verdict}] ${f.rule}: ${f.message}`);
  if (f.hint) console.log(`      → ${f.hint}`);
}
