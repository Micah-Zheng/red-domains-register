// 所有权挑战校验。跑在阶段 ②（无 CF/Resend 凭据），只做出站 HTTP 与 DNS 查询。
//
// 挑战串 = sha256(prefix + github_login + CHALLENGE_SALT)，salt 公开在 README。
//
// 公开的 salt 不是密钥 —— 这是刻意的，不是疏漏。挑战要证明的命题只有一个：
// "申请者控制 record.value 指向的那台主机"。校验方式是**对着 record.value
// 抓文件**，所以即便任何人都能算出任意 prefix+login 的串，也仍然必须能在目标
// 主机上放文件才能通过。把 salt 藏起来只会让申请者无法自助排查。
//
// 由此也解释了一个看似的漏洞：串里不含目标地址，攻击者是否能拿自己域名下的
// 合法文件去申请指向受害者服务器的记录？不能 —— 抓取发生在 record.value 上，
// 指向受害者就抓到受害者的站，那里没有这个文件。
//
// 真正的残余风险是共享托管：若攻击者与受害者在同一台主机且能写 well-known
// 路径，挑战会误过。这类目标应落在 REVIEW 由人判断，不在本模块处理。

import { createHash } from 'node:crypto';
import { Resolver } from 'node:dns/promises';

export const CHALLENGE_PATH = '/.well-known/red-domains-challenge.txt';
const TIMEOUT_MS = 8000;
const MAX_BYTES = 4096;
const MAX_REDIRECTS = 3;

export function expectedToken(prefix, githubLogin, salt) {
  if (!salt) throw new Error('CHALLENGE_SALT 未设置');
  return createHash('sha256')
    .update(`${prefix}${String(githubLogin).toLowerCase()}${salt}`)
    .digest('hex');
}

/** 用公共递归解析器查 A/AAAA，避免受 runner 本地 DNS 缓存影响。 */
async function resolveTarget(host) {
  const r = new Resolver({ timeout: 5000, tries: 2 });
  r.setServers(['1.1.1.1', '8.8.8.8']);
  const out = { a: [], aaaa: [], cname: [] };
  for (const [key, fn] of [['a', 'resolve4'], ['aaaa', 'resolve6'], ['cname', 'resolveCname']]) {
    try { out[key] = await r[fn](host); } catch { /* 缺记录不是错误 */ }
  }
  return out;
}

/**
 * 抓挑战文件。刻意不跟随跨主机重定向 —— 跟随会让"目标把 /.well-known 302 到
 * 任意第三方"成为绕过手段。同主机的 http→https 升级是允许的。
 */
async function fetchChallenge(host) {
  const attempts = [`https://${host}${CHALLENGE_PATH}`, `http://${host}${CHALLENGE_PATH}`];
  const errors = [];
  for (const start of attempts) {
    let url = start;
    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      const ctl = new AbortController();
      const timer = setTimeout(() => ctl.abort(), TIMEOUT_MS);
      try {
        const res = await fetch(url, {
          redirect: 'manual', signal: ctl.signal,
          headers: { 'user-agent': 'red-domains-challenge/1 (+https://github.com/tcp-red)' },
        });
        if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
          const next = new URL(res.headers.get('location'), url);
          if (next.hostname !== new URL(url).hostname) {
            errors.push(`${url} 重定向到其他主机 ${next.hostname}（不跟随）`);
            break;
          }
          url = next.toString();
          continue;
        }
        if (!res.ok) { errors.push(`${url} 返回 HTTP ${res.status}`); break; }
        const buf = new Uint8Array(await res.arrayBuffer());
        return { ok: true, url, body: new TextDecoder().decode(buf.slice(0, MAX_BYTES)) };
      } catch (err) {
        errors.push(`${url} ${err.name === 'AbortError' ? `超时（${TIMEOUT_MS}ms）` : err.message}`);
        break;
      } finally {
        clearTimeout(timer);
      }
    }
  }
  return { ok: false, errors };
}

/**
 * @returns {Promise<{verified: boolean, skipped?: string, reason?: string, detail?: string[]}>}
 * 失败一律 fail-closed：返回 verified:false，由调用方转 REVIEW（可重试），不是 REJECT。
 */
export async function verifyChallenge({ prefix, doc, salt, allowlisted }) {
  if (allowlisted) {
    return { verified: true, skipped: '目标在免挑战托管商白名单内（平台自身已验证域名归属）' };
  }
  const target = doc?.record?.value;
  if (!target) return { verified: false, reason: 'record.value 缺失' };

  const want = expectedToken(prefix, doc?.owner?.github, salt);

  // A/AAAA 目标没有主机名可发 SNI/Host，直接对 IP 抓 HTTPS 基本必失败；
  // 仍然尝试，因为部分申请者会同时配好证书。失败即转人工。
  const host = target.replace(/\.$/, '');
  const dns = await resolveTarget(host);
  const got = await fetchChallenge(host);
  if (!got.ok) {
    return {
      verified: false,
      reason: `无法读取 ${CHALLENGE_PATH}`,
      detail: [...got.errors, `DNS: A=${dns.a.join(',') || '-'} AAAA=${dns.aaaa.join(',') || '-'} CNAME=${dns.cname.join(',') || '-'}`],
    };
  }
  const body = got.body.trim().toLowerCase();
  const first = body.split(/\s+/)[0] ?? '';
  if (first !== want) {
    return {
      verified: false,
      reason: '挑战串不匹配',
      detail: [`读到 ${JSON.stringify(body.slice(0, 80))}`, `期望 ${want}`, `来源 ${got.url}`],
    };
  }
  return { verified: true, skipped: undefined, detail: [`已在 ${got.url} 验证`] };
}
