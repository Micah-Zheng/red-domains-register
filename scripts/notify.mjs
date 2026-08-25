// 阶段 ③：开通通知邮件。
//
// PII 边界（PLAN §4.2）：公开仓库的 domains/*.json 里只有邮箱哈希，没有明文。
// 明文只在私有侧存储中，本脚本用哈希去换取地址。这样做的原因是 Git 历史不可
// 撤销 —— 明文邮箱一旦提交进公开仓库，GDPR 的删除权就无法真正履行，
// force-push 改写历史也已被各种镜像和 GitHub 的 API 缓存留存。
//
// 未配置私有存储时静默跳过而非报错：邮件是增值功能，DNS 已经生效了。

import { readFileSync } from 'node:fs';
import { newlyAddedApps } from './changed-apps.mjs';

const RESEND = process.env.RESEND_API_KEY;
const STORE = process.env.CONTACT_STORE_TOKEN;
const FROM = process.env.MAIL_FROM ?? 'tcp.red <noreply@send.notify.tcp.red>';
const CONTACT_STORE_REPO = process.env.CONTACT_STORE_REPO ?? 'red-domains-contacts';
const VERIFY_REPORT = process.env.VERIFY_REPORT ?? 'verify-report.json';

if (!RESEND) { console.log('未配置 RESEND_API_KEY，跳过通知。'); process.exit(0); }

// —— 只给「权威已确认应答」的名字发信（PLAN §8.3）。
//
// 报告由 verify-dns.mjs 产出。读不到就**直接失败**，不做「姑且发吧」的降级：
// 这道闸门存在的全部意义就是防止「用户收到已开通、而域名解析不到」，
// 一旦允许在缺报告时照发，闸门等于不存在。2026-08-25 的 Cloudflare 故障中，
// 11 条新记录只有 1 条真正下发，而 API、面板、对账全部显示正常。
let verifiedSet;
try {
  const vr = JSON.parse(readFileSync(VERIFY_REPORT, 'utf8'));
  verifiedSet = new Set((vr.verified ?? []).map((v) => v.file));
} catch (e) {
  throw new Error(
    `读不到下发验证报告 ${VERIFY_REPORT}：${e.message}\n`
    + '通知必须在 verify-dns.mjs 之后运行 —— 未经权威确认不得发送开通邮件（PLAN §8.3）。');
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

const { skipped: skipReason, apps } = newlyAddedApps({
  before: process.env.BEFORE_SHA, after: process.env.AFTER_SHA,
});
if (skipReason) console.log(skipReason);
if (!apps.length) { console.log('本次无新增申请，无需通知。'); process.exit(0); }
console.log(`本次新增 ${apps.length} 条，准备通知。`);

let sent = 0, skipped = 0;
for (const app of apps) {
  const { file: f, zone, prefix, doc } = app;
  const fqdn = `${prefix}.${zone}`;

  // 未通过权威验证的一律不发。verify-dns.mjs 失败时 workflow 本就不会走到这里，
  // 这里是第二道保险：万一将来有人把步骤顺序调乱，也不会发出假的开通通知。
  if (!verifiedSet.has(f)) {
    console.log(`  跳过 ${fqdn}（权威未确认应答，不发开通通知）`); skipped += 1; continue;
  }

  // 侧存储的文件名是纯 64 位十六进制，不带 `sha256:` 前缀，须剥掉再去换地址。
  const hash = String(doc.owner?.contact_hash ?? '').replace(/^sha256:/, '');
  if (!/^[0-9a-f]{64}$/.test(hash)) {
    console.log(`  跳过 ${fqdn}（owner.contact_hash 缺失或格式不对）`); skipped += 1; continue;
  }

  const to = await resolveEmail(hash);
  if (!to) { console.log(`  跳过 ${fqdn}（私有存储无此哈希，可能用户已请求删除）`); skipped += 1; continue; }

  const target = doc.record?.value;

  // 文案与结构按「事务性邮件」而非「通知类营销邮件」来写。
  // 2026-08-25 实测：QQ 邮箱把首封开通邮件归入了「广告」目录（不是垃圾箱，
  // 说明域名信誉没问题，是内容分类）。已知的分类信号里，纯 HTML 而无
  // text/plain 副本是最强的一个 —— 正规事务性邮件几乎都是 multipart。
  // 另外去掉了大标题与灰色小字页脚这类版式，它们是典型的营销版式特征。
  const text = [
    `${fqdn} 已开通。`,
    '',
    `解析目标：${target}`,
    '',
    'DNS 在全球生效通常需要几分钟，如果暂时打不开请稍后再试。',
    '需要修改或注销，回到仓库提一个新的 PR 即可。',
    '',
    '本邮件由自动流程发出，请勿直接回复。',
  ].join('\n');

  const html = `<div style="font-family:system-ui,-apple-system,sans-serif;line-height:1.6;max-width:520px">
<p>${esc(fqdn)} 已开通。</p>
<p>解析目标：<code>${esc(target)}</code></p>
<p>DNS 在全球生效通常需要几分钟，如果暂时打不开请稍后再试。<br>
需要修改或注销，回到仓库提一个新的 PR 即可。</p>
<p>本邮件由自动流程发出，请勿直接回复。</p>
</div>`;

  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { authorization: `Bearer ${RESEND}`, 'content-type': 'application/json' },
      body: JSON.stringify({ from: FROM, to, subject: `${fqdn} 已开通`, html, text }),
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
