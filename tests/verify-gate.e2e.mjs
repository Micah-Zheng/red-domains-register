// 下发验证闸门的集成测试（PLAN §8.3）。
//
// 真起 git 仓库、真跑 verify-dns.mjs、真查权威 NS。不用 fixture：这道闸门
// 存在的全部意义是「别相信 CF API 说的成功」，用假数据测它等于把它要防的
// 那件事假设成不会发生。
//
// 正例用 smoketest（主干固定件，一直在解析）；反例用一个库里没有、CF 里
// 也没有的前缀。反例必须退出码非零 —— 那是 workflow 据以跳过发信的信号。

import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..');
let pass = 0; const fails = [];
const ok = (c, m) => { if (c) { pass += 1; console.log(`  ok   ${m}`); } else { fails.push(m); console.log(`  FAIL ${m}`); } };

const dir = mkdtempSync(join(tmpdir(), 'verifygate-'));
const out = mkdtempSync(join(tmpdir(), 'verifyout-'));
const git = (...a) => execFileSync('git', a, { cwd: dir, encoding: 'utf8' });
git('init', '-q', '-b', 'main');
git('config', 'user.email', 't@example.com');
git('config', 'user.name', 'T');
git('config', 'commit.gpgsign', 'false');
mkdirSync(join(dir, 'domains/tcp.red'), { recursive: true });
writeFileSync(join(dir, 'README.md'), 'base');
git('add', '-A'); git('commit', '-q', '-m', 'base');
const BASE = git('rev-parse', 'HEAD').trim();

const APP = JSON.stringify({
  description: '验证闸门集成测试用的申请文件，说明需足够长以通过有效性检查。',
  owner: { github: 'Micah-Zheng', contact_hash: `sha256:${'0'.repeat(64)}` },
  record: { type: 'CNAME', value: 'micahzheng.github.io' },
  check: { mode: 'http', port: 443 },
}, null, 2);

/** 新增一个申请文件并跑验证，返回 { code, report }。 */
function runVerify(prefix) {
  git('checkout', '-q', BASE);
  // git 不跟踪空目录：checkout 回 BASE 会把 domains/tcp.red 一并移除，
  // 必须重建再写，否则第二次调用就 ENOENT。
  mkdirSync(join(dir, 'domains/tcp.red'), { recursive: true });
  writeFileSync(join(dir, `domains/tcp.red/${prefix}.json`), APP);
  git('add', '-A'); git('commit', '-q', '-m', `add ${prefix}`);
  const HEAD = git('rev-parse', 'HEAD').trim();
  const rp = join(out, 'verify-report.json');
  let code = 0;
  try {
    execFileSync('node', [join(REPO, 'scripts/verify-dns.mjs')], {
      cwd: dir, encoding: 'utf8', stdio: 'pipe',
      env: { ...process.env, BEFORE_SHA: BASE, AFTER_SHA: HEAD, VERIFY_REPORT: rp,
             VERIFY_TIMEOUT_MS: '20000', VERIFY_INTERVAL_MS: '5000' },
    });
  } catch (e) { code = e.status ?? 1; }
  return { code, report: JSON.parse(readFileSync(rp, 'utf8')) };
}

console.log('=== 正例：名字已在权威上解析 ===');
const good = runVerify('smoketest');
ok(good.code === 0, `退出码 0（实际 ${good.code}）—— workflow 据此放行通知`);
ok(good.report.verified.length === good.report.checked,
  `全部 ${good.report.checked} 条记录被权威应答`);
ok(good.report.failed.length === 0, '无未生效记录');

console.log('\n=== 反例：申请存在但权威查不到 ===');
const bad = runVerify('zznotdeployed7x');
ok(bad.code !== 0, `退出码非零（实际 ${bad.code}）—— workflow 据此跳过通知并开 Issue`);
ok(bad.report.failed.length > 0, '报告里列出了未生效的名字');
ok(bad.report.verified.length === 0, '未把任何记录误判为已生效');
ok(bad.report.failed[0].fqdn === 'zznotdeployed7x.tcp.red', '未生效项带完整 FQDN 供排查');

console.log('\n=== 无新增申请时不应阻塞下发 ===');
git('checkout', '-q', BASE);
const rp2 = join(out, 'empty.json');
execFileSync('node', [join(REPO, 'scripts/verify-dns.mjs')], {
  cwd: dir, encoding: 'utf8', stdio: 'pipe',
  env: { ...process.env, BEFORE_SHA: BASE, AFTER_SHA: BASE, VERIFY_REPORT: rp2 },
});
ok(JSON.parse(readFileSync(rp2, 'utf8')).checked === 0, '无新增申请时退出码 0 且不检查任何记录');

rmSync(dir, { recursive: true, force: true });
rmSync(out, { recursive: true, force: true });
console.log(`\n${pass}/${pass + fails.length} 通过`);
if (fails.length) process.exit(1);
