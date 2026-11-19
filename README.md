# GSB Bugfix Task
## 题面
资源服务器加 DPoP 后，持有证明被绕过：typ 不是 dpop+jwt 也收；alg=none 直接过；jwk 带私钥参数也接受；jkt 和令牌里的 cnf 不绑定；htm 大小写不一致也放行；htu 忽略 query/fragment/默认端口；ath 缺失或不是当前 token 的哈希；jti 不查重；iat 太旧或未来也收；nonce 不匹配继续；验签失败还返回 claims；方法小写也通过。dpop_verify.py 15 条测试全红。要求 typ 固定、拒绝 none/弱算法、拒绝带私钥的 jwk、jkt 与 cnf 精确绑定、htm 大写精确、htu 归一化、ath 校验、jti 一次性、iat 时间窗、nonce 绑定、验签失败拒绝。

## 运行方式
```bash
python -m pytest tests -q
```

## 平台字段

所属领域：安全
子方向：身份认证
任务类型：Bugfix
语言 / 框架：Python 3, pytest
环境可复现等级：有外部依赖，未容器化
