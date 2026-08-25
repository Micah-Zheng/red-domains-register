// 前缀冷却写入的集成测试。
//
// 存在理由：data/cooldown.json 此前是**只读不写**的 —— r_notInCooldown 认真地
// 读它，而全仓没有任何一处写它。于是 r_deleteOwnOnly 对用户说的
// 「释放后进入冷却期，期间他人也无法申请」是一句空话。这类"规则读一个永远
// 为空的数据源"的缺陷不会报错、不会显红，只会让防护静默失效。
//
// 所以这里必须端到端验：真删文件 → 真跑写入 → 再用真实的规则引擎确认拦得住。
// 只断言"文件被写了"是不够的，写出来的形状对不上消费端照样白搭。

import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, cpSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runRules, loadRepoState } from '../scripts/validate.mjs';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..');
let pass = 0; const fails = [];
const ok = (c, m) => { if (c) { pass += 1; console.log(`  ok   ${m}`); } else { fails.push(m); console.log(`  FAIL ${m}`); } };

const dir = mkdtempSync(join(tmpdir(), 'cooldown-'));
const git = (...a) => execFileSync('git', a, { cwd: dir, encoding: 'utf8' });
git('init', '-q', '-b', 'main');
git('config', 'user.email', 't@example.com');
git('config', 'user.name', 'T');
git('config', 'commit.gpgsign', 'false');
mkdirSync(join(dir, 'domains/tcp.red'), { recursive: true });
mkdirSync(join(dir, 'data'), { recursive: true });
cpSync(join(REPO, 'data/cooldown.json'), join(dir, 'data/cooldown.json'));

const APP = JSON.stringify({
  description: '冷却期集成测试用的申请文件，说明需足够长以通过有效性检查。',
  owner: { github: 'SomeOwner', contact_hash: `sha256:${'0'.repeat(64)}` },
  record: { type: 'CNAME', value: 'x.github.io' },
  check: { mode: 'http', port: 443 },
}, null, 2);

writeFileSync(join(dir, 'domains/tcp.red/released.json'), APP);
git('add', '-A'); git('commit', '-q', '-m', 'add');
const BEFORE = git('rev-parse', 'HEAD').trim();
execFileSync('git', ['rm', '-q', 'domains/tcp.red/released.json'], { cwd: dir });
git('commit', '-q', '-m', 'release');
const AFTER = git('rev-parse', 'HEAD').trim();

const run = (reason = 'voluntary') => execFileSync('node', [join(REPO, 'scripts/cooldown.mjs')], {
  cwd: dir, encoding: 'utf8',
  env: { ...process.env, BEFORE_SHA: BEFORE, AFTER_SHA: AFTER, COOLDOWN_PATH: 'data/cooldown.json', COOLDOWN_REASON: reason },
});
const read = () => JSON.parse(readFileSync(join(dir, 'data/cooldown.json'), 'utf8'));

console.log('=== 释放前缀写入冷却名单 ===');
run();
const e = read().entries.find((x) => x.prefix === 'released');
ok(!!e, '写入了 released 的冷却条目');
ok(/^\d{4}-\d{2}-\d{2}$/.test(e?.release_at ?? ''), `release_at 为 YYYY-MM-DD（${e?.release_at}）`);
ok(e?.former_owner === 'SomeOwner', '记下了原持有者（从 base 读，文件已不在工作区）');

const days = Math.round((Date.parse(e.release_at) - Date.parse(e.released_on)) / 86400000);
ok(days === 30, `voluntary 冷却 30 天（实际 ${days}）`);

console.log('\n=== 消费端真的拦得住 ===');
// 用临时仓库的 cooldown.json 覆盖真实状态，再跑真实规则引擎。
const state = loadRepoState(undefined, new Set(['domains/tcp.red/released.json']));
state.cooldown = read();
const verdict = runRules({
  filePath: 'domains/tcp.red/released.json',
  doc: JSON.parse(APP), actor: 'someoneelse',
  changedFiles: ['domains/tcp.red/released.json'], state,
  actorMeta: { accountAgeDays: 3000, publicRepos: 5, followers: 3, prCount24h: 0 },
  changeKind: 'A', challengeVerified: true, authorAssociation: 'CONTRIBUTOR',
});
ok(verdict.verdict === 'REJECT', `他人立刻抢注被拒（实际 ${verdict.verdict}）`);
ok((verdict.findings ?? []).some((f) => f.rule === 'r_notInCooldown'), '由 r_notInCooldown 拦下');

console.log('\n=== 反复释放不得缩短冷却 ===');
const before = read().entries.find((x) => x.prefix === 'released').release_at;
run('operator_reclaim');   // 该原因是 0 天，若实现有误会把冷却抹掉
const after = read().entries.find((x) => x.prefix === 'released').release_at;
ok(after === before, `更短的冷却不覆盖更长的（${before} 保持不变）`);
ok(read().entries.filter((x) => x.prefix === 'released').length === 1, '同一前缀不重复入列');

rmSync(dir, { recursive: true, force: true });
console.log(`\n${pass}/${pass + fails.length} 通过`);
if (fails.length) process.exit(1);
