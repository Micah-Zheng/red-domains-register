// workflow 传出的环境变量 ↔ 脚本读入的环境变量，必须对得上。
//
// 存在理由：曾经 01-validate.yml 传 PR_AUTHOR 而 ci-validate.mjs 读 PR_ACTOR，
// 两边从不相交，actor 恒为空。这类错位不会抛异常 —— 脚本读到 undefined 后
// 静默走 fail-closed 分支，CI 全绿、测试全过、每个真实 PR 都莫名转人工。
// 手写 fixture 抓不到它（fixture 自己设的 env 一定自洽），只有比对两侧真实
// 文本才能发现。

import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
let pass = 0; const fails = [];
const ok = (c, m) => { if (c) { pass++; console.log(`  ok   ${m}`); } else { fails.push(m); console.log(`  FAIL ${m}`); } };

console.log('=== workflow env ↔ 脚本 process.env 契约 ===');

// GitHub 与 runner 自带的变量，不需要 workflow 显式传。
const AMBIENT = new Set([
  'GITHUB_TOKEN', 'GITHUB_REPOSITORY', 'GITHUB_OUTPUT', 'GITHUB_ENV',
  'GITHUB_STEP_SUMMARY', 'GITHUB_SERVER_URL', 'GITHUB_RUN_ID', 'GITHUB_SHA',
  'GITHUB_EVENT_NAME', 'GITHUB_WORKSPACE', 'CI', 'HOME', 'PATH',
]);

const wfDir = join(ROOT, '.github/workflows');
const workflows = readdirSync(wfDir).filter((f) => f.endsWith('.yml'));

// 收集每个 workflow 里 `run: node scripts/X.mjs` 与其 step 的 env 名字。
// 按 step 粒度切分：同一 job 的不同 step 有各自的 env 块。
const provided = new Map();   // script -> Set(env names)
for (const wf of workflows) {
  const text = readFileSync(join(wfDir, wf), 'utf8');
  const steps = text.split(/\n(?=\s*- )/);
  for (const step of steps) {
    const scripts = [...step.matchAll(/node\s+(scripts\/[A-Za-z0-9._-]+\.mjs)/g)].map((m) => m[1]);
    if (!scripts.length) continue;
    const envNames = [...step.matchAll(/^\s{8,}([A-Z][A-Z0-9_]*):\s/gm)].map((m) => m[1]);
    for (const s of scripts) {
      if (!provided.has(s)) provided.set(s, new Set());
      for (const n of envNames) provided.get(s).add(n);
    }
  }
}

ok(provided.size > 0, `从 workflow 中解析出 ${provided.size} 个被调用脚本`);

// 每个脚本实际读取的 env 名字，含它 import 的本地模块。
function readsOf(script) {
  const seen = new Set(); const names = new Set();
  const walk = (rel) => {
    if (seen.has(rel)) return; seen.add(rel);
    let text;
    try { text = readFileSync(join(ROOT, rel), 'utf8'); } catch { return; }
    for (const m of text.matchAll(/process\.env\.([A-Z][A-Z0-9_]*)/g)) names.add(m[1]);
    for (const m of text.matchAll(/process\.env\[['"]([A-Z][A-Z0-9_]*)['"]\]/g)) names.add(m[1]);
    for (const m of text.matchAll(/from\s+['"]\.\/([A-Za-z0-9._-]+\.mjs)['"]/g)) walk(`scripts/${m[1]}`);
  };
  walk(script);
  return names;
}

// 脚本读的每个非环境变量，必须至少有一个 workflow 传了它 —— 否则它在生产中恒为
// undefined。可选变量用 ?? 兜底不算豁免：兜底值掩盖的正是这类错位。
const allProvided = new Set([...provided.values()].flatMap((s) => [...s]));
const OPTIONAL = new Set([
  'REPORT_PATH', 'TRIAGE_PATH', 'CHALLENGE_PATH', 'DRY_RUN', 'MAX_DELETE',
  'ALLOW_DELETE', 'STATE_PATH',
  // 向后兼容别名：PR_AUTHOR 的旧名，脚本两者都接受。
  'PR_ACTOR',
  // 有合理兜底、允许 workflow 不传的可选配置。
  'AI_MODEL', 'MAIL_FROM', 'CONTACT_STORE_URL', 'CONTACT_STORE_REPO',
]);

// 由子进程（gh CLI）而非脚本自身读取的变量：workflow 必须传，但脚本里不会出现
// process.env.X。反向检查要豁免它们，否则会把正确接线报成漂移。
const SUBPROCESS = new Set(['GH_TOKEN']);

for (const [script] of provided) {
  for (const name of readsOf(script)) {
    if (AMBIENT.has(name) || OPTIONAL.has(name)) continue;
    ok(allProvided.has(name), `${script} 读的 ${name} 有 workflow 传入`);
  }
}

// 反向：workflow 传了但没人读的变量，是配置漂移的信号。
for (const [script, names] of provided) {
  const reads = readsOf(script);
  for (const n of names) {
    if (OPTIONAL.has(n) || SUBPROCESS.has(n)) continue;
    ok(reads.has(n), `${script} 确实读取了 workflow 传入的 ${n}`);
  }
}

console.log(`\n${pass}/${pass + fails.length} 通过`);
if (fails.length) { console.log('失败项：'); fails.forEach((f) => console.log(`  - ${f}`)); process.exit(1); }
