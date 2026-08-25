// 阶段 ③：开通通知邮件。
//
// PII 边界（PLAN §4.2）：公开仓库的 domains/*.json 里只有邮箱哈希，没有明文。
// 明文只在私有侧存储中，本脚本用哈希去换取地址。这样做的原因是 Git 历史不可
// 撤销 —— 明文邮箱一旦提交进公开仓库，GDPR 的删除权就无法真正履行，
// force-push 改写历史也已被各种镜像和 GitHub 的 API 缓存留存。
//
// 未配置私有存储时静默跳过而非报错：邮件是增值功能，DNS 已经生效了。

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const RESEND = process.env.RESEND_API_KEY;
const STORE = process.env.CONTACT_STORE_TOKEN;
const before = process.env.BEFORE_SHA;
const after = process.env.AFTER_SHA ?? 'HEAD';
const FROM = process.env.MAIL_FROM ?? 'tcp.red <noreply@send.notify.tcp.red>';
const CONTACT_STORE_REPO = process.env.CONTACT_STORE_REPO ?? 'red-domains-contacts';

if (!RESEND) { console.log('未配置 RESEND_API_KEY，跳过通知。'); process.exit(0); }

/** 本次 push 新增的申请文件。删除和修改不发开通邮件。 */
function newlyAdded() {
  if (!before || /^0+$/.test(before)) {
    console.log('无 before SHA（首次推送或强推），跳过通知以免群发历史条目。');
    return [];
  }
  let out;
  try {
    out = execFileSync('git', ['diff', '--name-status', '--diff-filter=A', before, after, '--', 'domains/'], { encoding: 'utf8' });
  } catch (e) {
    console.log(`git diff 失败，跳过通知：${e.message}`);
    return [];
  }
  return out.trim().split('\n').filter(Boolean)
    .map((l) => l.split('\t')[1]).filter((f) => f?.endsWith('.json'));
}

/** 用邮箱哈希向私有侧存储换明文地址。 */
async function resolveEmail(hash) {
  if (!STORE) return null;
  // 侧存储地址不写死 owner：早先的兜底里是字面量 OWNER，真实运行会打到不存在的
  // 仓库，404 后本函数返回 null，通知被静默跳过 —— 用户收不到邮件而日志只说"跳过"。
  // 现在优先用显式配置，否则按当前仓库 owner 推导；两者都拿不到就抛错。
  const base = process.env.CONTACT_STORE_URL || (() => {
    const owner = (process.env.GITHUB_REPOSITORY ?? '').split('/')[0];
    if (!owner) throw new Error('CONTACT_STORE_URL 与 GITHUB_REPOSITORY 均不可用，无法定位联系人存储');
    return `https://api.github.com/repos/${owner}/${CONTACT_STORE_REPO}/contents`;
  })();
  try {
    const res = await fetch(`${base}/by-hash/${hash}.json`, {
      headers: { authorization: `Bearer ${STORE}`, accept: 'application/vnd.github.raw' },
    });
    if (!res.ok) { console.log(`  侧存储返回 ${res.status}，跳过该条`); return null; }
    const rec = await res.json();
    return rec.email ?? null;
  } catch (err) {
    // 配置类错误必须可见，不能和"这个哈希查不到"混为一谈。
    console.log(`  取联系人失败：${err.message}`);
    return null;
  }
}

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const files = newlyAdded();
if (!files.length) { console.log('本次无新增申请，无需通知。'); process.exit(0); }
console.log(`本次新增 ${files.length} 条，准备通知。`);

let sent = 0, skipped = 0;
for (const f of files) {
  let app;
  try { app = JSON.parse(readFileSync(f, 'utf8')); } catch { console.log(`  跳过 ${f}（解析失败）`); skipped += 1; continue; }
  const fqdn = `${app.prefix}.${app.zone ?? 'tcp.red'}`;
  const hash = app.contact?.emailHash ?? app.emailHash;
  if (!hash) { console.log(`  跳过 ${fqdn}（无 emailHash）`); skipped += 1; continue; }

  const to = await resolveEmail(hash);
  if (!to) { console.log(`  跳过 ${fqdn}（私有存储无此哈希，可能用户已请求删除）`); skipped += 1; continue; }

  const html = `<div style="font-family:system-ui,-apple-system,sans-serif;line-height:1.6;max-width:520px">
<h2 style="margin:0 0 16px">${esc(fqdn)} 已开通</h2>
<p>你申请的二级域名已生效，指向 <code>${esc(app.target ?? app.records?.[0]?.content)}</code>。</p>
<p>DNS 在全球生效通常需要几分钟。如果暂时打不开，先等一会儿再试。</p>
<p style="color:#666;font-size:14px">
需要修改或注销，回到仓库提一个新的 PR 即可。<br>
本邮件由自动流程发出，请勿直接回复。</p>
</div>`;

  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { authorization: `Bearer ${RESEND}`, 'content-type': 'application/json' },
      body: JSON.stringify({ from: FROM, to, subject: `${fqdn} 已开通`, html }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status} ${(await res.text()).slice(0, 160)}`);
    // 只打印 FQDN，绝不把邮箱地址写进公开的 Actions 日志。
    console.log(`  已发送 ${fqdn}`);
    sent += 1;
  } catch (e) {
    console.log(`  发送失败 ${fqdn}：${e.message}`);
    skipped += 1;
  }
}
console.log(`通知完成：成功 ${sent}，跳过 ${skipped}。`);
