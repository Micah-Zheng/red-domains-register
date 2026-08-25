// 删除路径的集成测试：真起一个 git 仓库、真跑 ci-validate.mjs、真读 report.json。
//
// 存在理由：这条路径的行为取决于 changedFiles() 的 --diff-filter、从 base 分支
// git show 取原文、以及 report 三元分支这三者的配合，任何一环写错都不会抛异常，
// 只会让删除**静默不受鉴权约束**或者**永远无法进行**。单测 runRules() 覆盖不到
// 这些——它们全在脚本层。所以这里不手写 fixture，而是造真实的 git 历史。
//
// gh() 走 curl 取账号信誉，测试里用 PATH 抢占一个假 curl 做隔离，
// 保证不发真实网络请求（取不到信誉数据时脚本按 fail-closed 处理，符合预期）。

import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..');
let pass = 0; const fails = [];
const ok = (c, m) => { if (c) { pass += 1; console.log(`  ok   ${m}`); } else { fails.push(m); console.log(`  FAIL ${m}`); } };

const dir = mkdtempSync(join(tmpdir(), 'delpath-'));
// report.json 必须落在 git 仓库**之外**：写进仓库会被 git add -A 一起提交，
// 下一轮删除就变成「PR 里夹带了其他文件」，被 r_singleFileChange 先行拦下——
// 测的就不再是删除鉴权，而且失败原因极具误导性。
const out = mkdtempSync(join(tmpdir(), 'delout-'));
const bin = join(out, 'bin');
mkdirSync(bin, { recursive: true });
// 假 curl：任何请求都回空 JSON，等价于"信誉数据取不到"，脚本走 fail-closed。
writeFileSync(join(bin, 'curl'), '#!/bin/sh\necho "{}"\n');
chmodSync(join(bin, 'curl'), 0o755);

const git = (...a) => execFileSync('git', a, { cwd: dir, encoding: 'utf8' });
git('init', '-q', '-b', 'main');
git('config', 'user.email', 't@example.com');
git('config', 'user.name', 'T');
git('config', 'commit.gpgsign', 'false');
mkdirSync(join(dir, 'domains/tcp.red'), { recursive: true });

const APP = (owner) => JSON.stringify({
  description: '一段足够长的、说明真实用途的描述文本，用于通过说明有效性检查。',
  owner: { github: owner, contact_hash: `sha256:${'0'.repeat(64)}` },
  record: { type: 'CNAME', value: 'user.github.io' },
  check: { mode: 'http', port: 443 },
}, null, 2);

writeFileSync(join(dir, 'domains/tcp.red/broken.json'), '{ this is not json');
writeFileSync(join(dir, 'domains/tcp.red/mine.json'), APP('Micah-Zheng'));
writeFileSync(join(dir, 'domains/tcp.red/theirs.json'), APP('SomeoneElse'));
git('add', '-A'); git('commit', '-q', '-m', 'base');
const BASE = git('rev-parse', 'HEAD').trim();

/** 删掉一个文件，跑 ci-validate，返回 report.json */
function runDelete(file, { actor = 'Micah-Zheng', assoc = 'CONTRIBUTOR' } = {}) {
  git('checkout', '-q', BASE);
  rmSync(join(dir, file));
  git('add', '-A'); git('commit', '-q', '-m', `delete ${file}`);
  const HEAD = git('rev-parse', 'HEAD').trim();
  const rp = join(out, 'report.json');
  execFileSync('node', [join(REPO, 'scripts/ci-validate.mjs')], {
    cwd: dir, encoding: 'utf8',
    env: { ...process.env, PATH: `${bin}:${process.env.PATH}`,
           BASE_SHA: BASE, HEAD_SHA: HEAD, PR_AUTHOR: actor,
           PR_AUTHOR_ASSOCIATION: assoc, REPORT_PATH: rp,
           GITHUB_REPOSITORY: 'Micah-Zheng/red-domains-register', GITHUB_TOKEN: '' },
  });
  return JSON.parse(readFileSync(rp, 'utf8'));
}

console.log('=== 删除 base 里已损坏的记录 ===');
const r1 = runDelete('domains/tcp.red/broken.json');
ok(r1.verdict === 'REVIEW', `坏 JSON 的删除转人工而非拒绝（实际 ${r1.verdict}）`);
ok((r1.findings ?? []).some((f) => f.rule === 'r_deleteUnparsable'),
  '给出 r_deleteUnparsable，说明为何无法自动鉴权');
ok(!(r1.findings ?? []).some((f) => f.verdict === 'PASS'),
  '不因读不到 owner 就自动放行');

console.log('\n=== 鉴权仍然生效（防止上面的放宽开出洞）===');
const r2 = runDelete('domains/tcp.red/theirs.json');
ok(r2.verdict === 'REJECT', `删他人记录被拒（实际 ${r2.verdict}）`);
ok((r2.findings ?? []).some((f) => f.rule === 'r_deleteOwnOnly'), '由 r_deleteOwnOnly 拦下');

const r3 = runDelete('domains/tcp.red/mine.json');
ok(r3.verdict === 'REVIEW', `释放自己的前缀转人工（实际 ${r3.verdict}）`);

const r4 = runDelete('domains/tcp.red/theirs.json', { assoc: 'OWNER' });
ok(r4.verdict === 'REVIEW', `运营者代删转人工（实际 ${r4.verdict}）`);

rmSync(dir, { recursive: true, force: true });
rmSync(out, { recursive: true, force: true });
console.log(`\n${pass}/${pass + fails.length} 通过`);
if (fails.length) process.exit(1);
