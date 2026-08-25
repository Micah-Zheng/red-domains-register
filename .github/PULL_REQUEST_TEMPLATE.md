<!-- 申请 <前缀>.tcp.red。完整规则见 README。 -->

## 申请的域名

`____.tcp.red`

## 用途

<!-- 一句话说明，附项目或个人主页链接。这段会由自动化和维护者阅读。 -->

## 自查清单

- [ ] 文件放在 `domains/tcp.red/<前缀>.json`，文件名与申请的前缀一致
- [ ] 前缀为 4 至 63 字符的小写字母、数字、连字符
- [ ] `owner.github` 是我自己的 GitHub 用户名（与提交本 PR 的账号相同）
- [ ] `owner.contact_hash` 是我邮箱的 sha256，不是明文
- [ ] 解析目标由我控制
- [ ] 已完成所有权挑战（放好 `/.well-known/red-domains-challenge.txt` 或 TXT 记录），或目标在白名单内
- [ ] 本地跑过 `npm run validate`

## 挑战方式

- [ ] HTTP 文件
- [ ] DNS TXT 记录
- [ ] 目标在白名单内，无需挑战

---

提交后自动化会贴出校验结论。挑战失败多半是还没传播开——放好之后回复 `/recheck` 即可重验，不用推新 commit。
