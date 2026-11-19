# GSB Bugfix Task
## 题面
堡垒机改用 SSH 证书登录后，证书校验出问题：CA 只按 key_id 字符串匹配；证书类型不区分 user/host；principals 不做白名单；valid_after/valid_before 不校验；未知 critical option 被忽略；source-address 限制不生效；force-command 没带回调用方；serial 不查吊销表；验签失败还继续；key_id 为空也接受；host 通配 principal 不匹配；valid_before 早于 valid_after 也能过。ssh_cert.py 的 15 条测试全红。要求按 CA 公钥验签、类型与用途匹配、principals 白名单和 host 通配、有效期窗口、未知 critical option 拒绝、source-address 按客户端 IP 校验、force-command 返回、serial 吊销检查。

## 运行方式
```bash
python -m pytest tests -q
```

## 平台字段

所属领域：安全
子方向：系统安全
任务类型：Bugfix
语言 / 框架：Python 3, pytest
环境可复现等级：有外部依赖，未容器化
