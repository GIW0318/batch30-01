# GSB Bugfix Task
## 题面
能力令牌换成 macaroon 后，衰减和第三方授权失效：签名只拼 identifier，追加 caveat 后旧签名还能用；action=read 能匹配 action=readwrite；tenant、时间、action 多条 caveat 没有全部校验；未知 caveat 被忽略，格式错的直接跳过；过期时间不拦；第三方 caveat 没 discharge 也放行，discharge 不验签；nonce 可重放；identifier 为空也收；乱序或重复 caveat 处理不一致；带 or 的 caveat 被当普通字符串。macaroon_guard.py 15 条测试全红。要求 HMAC 链覆盖全部 caveat，caveat 精确解析，action/tenant/time 全满足，未知/畸形/过期拒绝，第三方必须有 discharge 且验签，nonce 一次性。

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
