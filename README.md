# GSB Bugfix Task
## 题面
HTTP/2 入口的流状态机在高压下失守：偶数流号能过，流号回退会重开旧流；并发流超限还收 HEADERS；RST 打空流不报错；伪头重复或出现在普通头后面也接受；connection 头和大写头名被转发；te 除了 trailers 还放行 gzip；头大小只看解压后；SETTINGS 调低并发后新流继续开；协议错误不进 GOAWAY。h2_stream_guard.py 的 15 条用例现在全挂。要求流号奇数递增、并发上限动态生效、RST 只打已打开流、伪头唯一且前置、拒绝逐跳头/大写头/非 trailers 的 te、压缩前后都限大小、协议错误进 GOAWAY。

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
