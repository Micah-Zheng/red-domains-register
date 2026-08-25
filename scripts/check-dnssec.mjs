// DS ↔ DNSKEY 信任链一致性检查。
//
// 存在理由：本项目的两个域在注册商（DNSPod / 腾讯云）上开着 clientUpdateProhibited。
// 该锁会挡住注册局侧对域名对象的一切更新 —— **包括 DS 记录**。而 zone 又开着
// CF 托管的 DNSSEC。两者叠加：万一 Cloudflare 轮换 KSK，新 DS 推不到注册局，
// 信任链断裂，两个域会对所有验证型解析器整体 SERVFAIL。
//
// 这个失败模式比「记录不解析」更隐蔽：DNS 记录本身完好、面板正常、对账正常、
// 不做校验的解析器也正常 —— 只有开启 DNSSEC 校验的解析器（1.1.1.1、8.8.8.8、
// 以及绝大多数 ISP 递归）会拒绝解析。也就是说，你自己 dig 可能一切正常，
// 而真实用户全都打不开。
//
// 实现用 DoH JSON 而非 Node 的 dns 模块：后者没有 resolveDs。
// 刻意**不只问 Cloudflare** —— 被检查的一方不该同时当裁判。以 Google 为准，
// 与 Cloudflare 交叉比对，两者不一致时视为可疑并报错。

const ZONES = (process.env.DNSSEC_ZONES ?? 'tcp.red,udp.red').split(',').map((z) => z.trim()).filter(Boolean);

const PROVIDERS = [
  { name: 'Google', url: (n, t) => `https://dns.google/resolve?name=${n}&type=${t}`, headers: {} },
  { name: 'Cloudflare', url: (n, t) => `https://cloudflare-dns.com/dns-query?name=${n}&type=${t}`,
    headers: { accept: 'application/dns-json' } },
];

async function query(provider, name, type) {
  const res = await fetch(provider.url(name, type), { headers: provider.headers });
  if (!res.ok) throw new Error(`${provider.name} 返回 HTTP ${res.status}`);
  const j = await res.json();
  // 归一化：不同解析器返回的十六进制摘要大小写不同（Google 大写、Cloudflare
  // 小写），而 DNS 里它不区分大小写。不归一会把「两家完全一致」误判成
  // 「DS 正在变更中」—— 一个永远报警的检查等于没有检查。
  // 只对 DS 的摘要段做大小写归一；DNSKEY 的 base64 公钥**区分大小写**，不能动。
  return (j.Answer ?? [])
    .filter((a) => a.type === (type === 'DS' ? 43 : 48))
    .map((a) => (type === 'DS' ? a.data.trim().toUpperCase() : a.data.trim()));
}

let bad = 0;

for (const zone of ZONES) {
  console.log(`\n=== ${zone} ===`);
  let dsByProvider = {};
  let dnskey = [];
  try {
    for (const p of PROVIDERS) dsByProvider[p.name] = (await query(p, zone, 'DS')).sort();
    dnskey = await query(PROVIDERS[0], zone, 'DNSKEY');
  } catch (e) {
    console.log(`  ❌ 查询失败：${e.message}`); bad += 1; continue;
  }

  const [a, b] = Object.values(dsByProvider);
  if (JSON.stringify(a) !== JSON.stringify(b)) {
    console.log('  ❌ 两个解析器看到的 DS 不一致，可能正处于 DS 变更传播中：');
    for (const [n, v] of Object.entries(dsByProvider)) console.log(`     ${n}: ${v.join(' | ') || '（无）'}`);
    bad += 1; continue;
  }
  const ds = a;

  if (!ds.length) {
    console.log('  ⚠ 注册局没有 DS —— zone 未签名或 DNSSEC 已关闭。');
    console.log('    若本应开启 DNSSEC，说明信任链已断或被人关掉，需要核实。');
    bad += 1; continue;
  }

  // DS:     "<keyTag> <alg> <digestType> <digest>"
  // DNSKEY: "<flags> <protocol> <alg> <publicKey>"
  const dsTags = ds.map((d) => { const [tag, alg] = d.split(/\s+/); return `${tag}/${alg}`; });
  const ksks = dnskey.map((k) => k.split(/\s+/)).filter(([flags]) => Number(flags) === 257);

  console.log(`  注册局 DS   ：${dsTags.join('、')}`);
  console.log(`  zone DNSKEY ：${dnskey.length} 条，其中 KSK ${ksks.length} 条`);

  // key tag 需按 RFC 4034 附录 B 计算，这里用一个更稳的等价判断：
  // 取 zone 权威公布的 KSK，逐个算 tag，看是否有 DS 与之匹配。
  const tagOf = (flags, proto, alg, keyB64) => {
    const rdata = Buffer.concat([Buffer.from([flags >> 8, flags & 0xff, proto, alg]), Buffer.from(keyB64, 'base64')]);
    let t = 0;
    for (let i = 0; i < rdata.length; i += 1) t += (i & 1) ? rdata[i] : rdata[i] << 8;
    t += (t >> 16) & 0xffff;
    return t & 0xffff;
  };
  const kskTags = ksks.map(([f, p, alg, key]) => `${tagOf(+f, +p, +alg, key)}/${alg}`);
  console.log(`  KSK key tag ：${kskTags.join('、') || '（无）'}`);

  const matched = dsTags.some((t) => kskTags.includes(t));
  if (matched) {
    console.log('  ✅ 信任链一致：注册局的 DS 指向 zone 当前的某个 KSK。');
  } else {
    bad += 1;
    console.log('  ❌ 信任链断裂：注册局的 DS 与 zone 当前的 KSK 对不上。');
    console.log('     后果：所有开启 DNSSEC 校验的解析器会拒绝解析本域 —— 相当于整域下线。');
    console.log('     最可能的原因：Cloudflare 轮换了 KSK，而注册商的 clientUpdateProhibited 锁');
    console.log('     挡住了 DS 更新。处置：DNSPod 解锁 → 用 CF 面板给出的新 DS 更新注册局 → 重新加锁。');
  }
}

if (bad) { console.log(`\n${bad} 个 zone 存在问题。`); process.exit(1); }
console.log('\n全部 zone 的 DNSSEC 信任链一致。');
