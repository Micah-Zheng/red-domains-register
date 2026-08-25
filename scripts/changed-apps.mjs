// 「本次 push 新增了哪些申请」—— 下发验证与开通通知的唯一事实源。
//
// 抽成共享模块而不是两边各写一遍：notify.mjs 曾经自己猜字段（读 app.prefix、
// app.contact.emailHash 等 schema 里根本不存在的名字），每条申请都停在
// 「无 emailHash」，一封邮件也发不出去，而日志只说「本次无新增申请」。
// 验证与通知一旦对不上，症状会是「验证说没生效、邮件照发」这类最难查的错位。

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

/** 路径 → { zone, prefix }。申请文件里没有这两个字段，只能从路径取。 */
export function parseAppPath(file) {
  const m = /^domains\/([^/]+)\/([^/]+)\.json$/.exec(file);
  return m ? { zone: m[1], prefix: m[2] } : null;
}

/**
 * 本次 push 新增（--diff-filter=A）的申请文件。修改与删除不算。
 * @throws 计算失败时**抛错**，绝不降级成空数组 —— 见下方注释。
 */
export function newlyAddedApps({ before, after = 'HEAD', cwd } = {}) {
  if (!before || /^0+$/.test(before)) {
    return { skipped: '无 before SHA（首次推送或强推），跳过以免误判历史条目', apps: [] };
  }
  let out;
  try {
    out = execFileSync('git', ['diff', '--name-status', '--diff-filter=A', before, after, '--', 'domains/'],
      { encoding: 'utf8', cwd });
  } catch (e) {
    // 绝不 return [] —— 那会把「算不出来」伪装成「本次没有新增」。真实事故：
    // checkout 浅克隆导致 before SHA 不存在，git 报 fatal: bad object，
    // 旧实现 catch 后返回空数组，于是每一次下发的开通邮件都被静默吞掉。
    throw new Error(
      `无法计算本次 push 的新增申请（${before}..${after}）：${e.message}\n`
      + '若是 "bad object"：checkout 深度不够，03-deploy.yml 需要 fetch-depth: 0。');
  }
  const apps = [];
  for (const line of out.trim().split('\n').filter(Boolean)) {
    const file = line.split(/\t/).pop();
    const parsed = parseAppPath(file);
    if (!parsed) continue;
    apps.push({ file, ...parsed, doc: JSON.parse(readFileSync(file, 'utf8')) });
  }
  return { skipped: null, apps };
}
