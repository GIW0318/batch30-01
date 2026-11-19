# GSB Bugfix Task
## 题面
递归解析器打开 DNSSEC 后，伪造应答还是能过：RRset 没有 RRSIG 也返回；DS 的 key tag 和算法跟信任锚对不上；RRSIG 的 key tag、签名者名和 zone 不一致也接受；签名过期或尚未生效不拦；original TTL 和 RRset TTL 不一致时直接信；wildcard 展开没有 labels 证明；多条 RRSIG 里只要有一条乱写就通过；验签回调返回 false 仍返回记录；class 不是 IN 也收；畸形签名直接抛未捕获异常。dnssec_verify.py 的 15 条用例全红。要求 RRset 必须有签名、DS 与信任锚匹配、RRSIG 的 key tag/signer/zone 对齐、有效期窗口、original TTL 校验、wildcard labels 正确、多条签名取有效的一条、验签失败拒绝、class 必须为 IN、非法输入抛 ValueError。

## 运行方式
```bash
python -m pytest tests -q
```

## 平台字段

所属领域：安全
子方向：网络与通信安全
任务类型：Bugfix
语言 / 框架：Python 3, pytest
环境可复现等级：有外部依赖，未容器化
