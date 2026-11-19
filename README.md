# GSB Bugfix Task
## 题面
工作负载身份用 SPIFFE 后，信任域和路径都没卡住：别的 trust domain 签的 SVID 也收；/ns/default/sa/api-evil 被当成 api；X509 和 JWT 不区分，JWT audience 不查；有效期和 bundle 轮换时间不看；serial 可重放；不存在的 bundle_id 也验签通过；ID 里带 query、fragment、大写域名或 .. 都放过。spiffe_svid.py 目前 15 条测试全红。需要按 segment 匹配路径、精确校验 trust domain、分开处理两种 SVID、校验 audience/有效期/bundle/serial，并拒绝畸形 ID。

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
