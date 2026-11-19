# GSB Bugfix Task
## 题面
企业门户做单点退出时，通知令牌没有按 OIDC 退出口径验：issuer 和 audience 只判空；会话标识 sid 缺失、空串或非字符串也照样清会话；sub 和 sid 同时缺失不报错；events 里没有 backchannel-logout 事件仍执行；把带 nonce 的登录令牌混进退出通知；签发时间和过期时间不比较；同一个通知编号可以重复投递；typ 写成普通 JWT 也收；none 算法和验签失败都放行；audience 是列表时只核第一项。oidc_logout.py 的 15 条用例全红。要求 issuer/audience 精确、sub 或 sid 至少一个且类型正确、events 必须含 backchannel-logout、拒绝 nonce、校验签发/过期、通知编号一次性、typ 固定、拒绝 none 和验签失败、audience 列表逐项匹配。

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
