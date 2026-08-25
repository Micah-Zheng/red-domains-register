// Cloudflare DNS API 薄封装。
//
// 设计约束：
//  1. 只在已合并的 main 上运行（阶段 ③），凭据不进 PR 上下文 —— 见 PLAN §6 的
//     pwn request 分析。本模块不做权限判断，调用方负责。
//  2. 全部写操作可 dry-run。首次上线与对账都要求先跑 dry-run（§9.1）。
//  3. 出错不静默。CF 的 success:false 会带 errors 数组，必须抛出，否则
//     "下发成功但记录不存在" 会一直到用户投诉才被发现。

const API = 'https://api.cloudflare.com/client/v4';

export class CloudflareError extends Error {
  constructor(message, { status, errors, path }) {
    super(message);
    this.name = 'CloudflareError';
    this.status = status;
    this.errors = errors ?? [];
    this.path = path;
  }
}

export function createClient({ token, dryRun = false, fetchImpl = globalThis.fetch }) {
  if (!token && !dryRun) throw new Error('缺少 CF_API_TOKEN（dry-run 模式下可省略）');

  async function call(method, path, body) {
    const isWrite = method !== 'GET';
    if (isWrite && dryRun) {
      return { __dryRun: true, method, path, body };
    }
    const res = await fetchImpl(`${API}${path}`, {
      method,
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    let json;
    const text = await res.text();
    try {
      json = JSON.parse(text);
    } catch {
      throw new CloudflareError(`CF 返回非 JSON（HTTP ${res.status}）：${text.slice(0, 200)}`,
        { status: res.status, path });
    }
    if (!res.ok || json.success === false) {
      const detail = (json.errors ?? []).map((e) => `${e.code} ${e.message}`).join('; ');
      throw new CloudflareError(`CF ${method} ${path} 失败（HTTP ${res.status}）：${detail || '无错误详情'}`,
        { status: res.status, errors: json.errors, path });
    }
    return json;
  }

  /** 列出 zone 下全部 DNS 记录，自动翻页。 */
  async function listRecords(zoneId) {
    const out = [];
    let page = 1;
    for (;;) {
      // per_page 上限 100。忘记翻页是这里最容易犯的错：zone 超过 100 条记录后
      // 对账会把未翻到的记录判为「CF 无 / Git 有」而重复创建，或反向误判为孤儿。
      const r = await call('GET', `/zones/${zoneId}/dns_records?page=${page}&per_page=100`);
      out.push(...r.result);
      const info = r.result_info ?? {};
      if (!info.total_pages || page >= info.total_pages) break;
      page += 1;
    }
    return out;
  }

  const createRecord = (zoneId, rec) => call('POST', `/zones/${zoneId}/dns_records`, rec);
  const updateRecord = (zoneId, id, rec) => call('PUT', `/zones/${zoneId}/dns_records/${id}`, rec);
  const deleteRecord = (zoneId, id) => call('DELETE', `/zones/${zoneId}/dns_records/${id}`);

  /** 按名字解析 zone id。缓存，避免每条记录都查一次。 */
  const zoneCache = new Map();
  async function zoneId(zoneName) {
    if (zoneCache.has(zoneName)) return zoneCache.get(zoneName);
    const r = await call('GET', `/zones?name=${encodeURIComponent(zoneName)}`);
    const hit = r.result?.[0];
    if (!hit) throw new CloudflareError(`找不到 zone ${zoneName}（检查 token 的 zone 权限）`, { path: '/zones' });
    zoneCache.set(zoneName, hit.id);
    return hit.id;
  }

  return { call, listRecords, createRecord, updateRecord, deleteRecord, zoneId, dryRun };
}

/** 相对名 → FQDN。`@` 表示 apex。 */
export const toFqdn = (name, zone) => (name === '@' ? zone : `${name}.${zone}`);
/** FQDN → 相对名，供对账把 CF 返回的名字折回申请文件的命名空间。 */
export function toRelative(fqdn, zone) {
  const f = String(fqdn).toLowerCase().replace(/\.$/, '');
  const z = String(zone).toLowerCase();
  if (f === z) return '@';
  return f.endsWith(`.${z}`) ? f.slice(0, -(z.length + 1)) : f;
}
