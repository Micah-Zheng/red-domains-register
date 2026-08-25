// notify.mjs 读的申请文件字段 ↔ schema 实际定义的字段，必须对得上。
//
// 存在理由：notify.mjs 曾读 app.prefix、app.zone、app.contact.emailHash、
// app.emailHash、app.target —— 五个字段 schema 里一个都不存在。读到 undefined
// 后每条申请都停在「跳过（无 emailHash）」，一封开通邮件也发不出去；而这一步
// 在 03-deploy.yml 里是 continue-on-error:true，于是整条通知链路可以长期全绿地
// 什么都不做，直到用户来问「怎么没收到邮件」才会暴露。
//
// 和 env-contract 同理：手写 fixture 抓不到这类错位（fixture 自己一定自洽），
// 只有拿真实源码去比对真实 schema 才有意义。

import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
let pass = 0; const fails = [];
const ok = (c, m) => { if (c) { pass++; console.log(`  ok   ${m}`); } else { fails.push(m); console.log(`  FAIL ${m}`); } };

// 「本次新增了哪些申请」的逻辑已抽到 changed-apps.mjs（notify 与 verify-dns
// 共用同一个事实源）。契约不变，只是要连同该模块一起扫描 —— 否则断言会
// 因为「在 notify.mjs 里找不到」而假绿。
const raw = readFileSync(join(ROOT, 'scripts/notify.mjs'), 'utf8')
  + '\n' + readFileSync(join(ROOT, 'scripts/changed-apps.mjs'), 'utf8');
// 必须先剥注释再扫描：这些 bug 的说明文字里正好写着那批不存在的字段名
// （「旧实现读 app.prefix、app.zone……」），不剥就会把注释当成代码报假阳性。
// 顺序要紧：**先剥行注释，再剥块注释**。反过来会踩坑 —— notify.mjs 的文件头
// 里有一行 `// ...domains/*.json 里只有邮箱哈希...`，那个 `/*` 位于行注释内部，
// 但块注释正则不认得这一点，会把它当成块注释开头一路吞到下一个 `*/`，
// 连带删掉中间上千字符的真实代码。那样断言扫的是一份被啃过的源码，
// 会毫无征兆地假绿或假红。
const src = raw.replace(/^\s*\/\/.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, '');
const schema = JSON.parse(readFileSync(join(ROOT, 'schema/domain.schema.json'), 'utf8'));
const top = new Set(Object.keys(schema.properties));

console.log('=== notify.mjs 读的字段必须在 schema 里 ===');
// 申请文件被解析进变量 app，取它的一级属性名（含可选链）。
// 申请文件被解析进 doc（notify）或 app.doc（changed-apps），两种写法都要扫。
const read = [...src.matchAll(/\b(?:doc|app\.doc)\??\.\s*(\w+)/g)].map((m) => m[1]);
ok(read.length > 0, `找到 ${read.length} 处申请文件字段读取`);
for (const f of [...new Set(read)]) {
  ok(top.has(f), `app.${f} —— schema 定义了 ${f}${top.has(f) ? '' : `（schema 只有：${[...top].join('、')}）`}`);
}

console.log('\n=== 二级字段 ===');
const nested = [...src.matchAll(/\b(?:doc|app\.doc)\??\.\s*(\w+)\??\.\s*(\w+)/g)];
for (const [, parent, child] of nested) {
  const props = schema.properties[parent]?.properties ?? {};
  ok(Object.hasOwn(props, child), `app.${parent}.${child} —— schema 的 ${parent} 定义了 ${child}`);
}

console.log('\n=== 已知陷阱的定点断言 ===');
for (const ghost of ['app.prefix', 'app.zone', 'app.emailHash', 'app.target']) {
  ok(!src.includes(ghost), `不再读不存在的字段 ${ghost}`);
}
ok(/domains\\?\/\(\[\^\/\]\+\)\\?\/\(\[\^\/\]\+\)\\?\.json/.test(src) || /domains\\\/\(/.test(src),
  '前缀与 zone 从文件路径 domains/<zone>/<prefix>.json 解析（schema 里没有这两个字段）');
ok(/replace\(\/\^sha256:\/,\s*''\)/.test(src),
  'contact_hash 去掉 `sha256:` 前缀再去侧存储换地址（侧存储文件名是纯 64 位十六进制）');
ok(/throw new Error\(/.test(src.slice(src.indexOf('export function newlyAddedApps'))),
  'git diff 失败时抛错而非降级成「本次无新增申请」');

// §8.3：通知必须以权威验证为前提，且缺报告时失败而非放行。
ok(/VERIFY_REPORT/.test(src), '通知读取下发验证报告');
ok(/verifiedSet\.has\(/.test(src), '只给权威已确认应答的名字发信');
ok(/text/.test(src) && /subject:/.test(src),
  '邮件带 text/plain 副本（纯 HTML 是被归入「广告」目录的主要信号）');

console.log('\n=== 下发 workflow 必须给足 checkout 深度 ===');
const wf = readFileSync(join(ROOT, '.github/workflows/03-deploy.yml'), 'utf8');
ok(/fetch-depth:\s*0/.test(wf),
  '03-deploy.yml 设了 fetch-depth: 0 —— 浅克隆里 event.before 不存在，git diff 会报 bad object');

console.log(`\n${pass}/${pass + fails.length} 通过`);
if (fails.length) process.exit(1);
