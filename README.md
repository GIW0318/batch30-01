# GSB Bugfix Task
## 题面
CI 流水线对外开放后，工作流注入和权限放大一起出现：pull_request_target 里 checkout PR 头；run 拼 pull_request.title 或 issue.title；permissions 写 write-all；action 用 @main 浮动标签；fork 的 pull_request 把 secrets 传进构建；公共仓库跑 self-hosted；id-token 写权限又没有 environment；workflow_run 直接消费未信任 artifact；checkout 保留凭据；run 里 eval 环境变量；artifact 下载不校验来源。ci_workflow.py 的 15 条用例全红。要求识别不可信触发器和 PR 头 checkout、run 中的事件表达式一律报注入、权限最小化、action 固定完整 SHA、fork 不传 secrets、公共仓库禁用 self-hosted、id-token 绑定 environment、workflow_run 校验 artifact 来源、关闭持久凭据、禁止 eval。

## 运行方式
```bash
python -m pytest tests -q
```

## 平台字段

所属领域：安全
子方向：其他
任务类型：Bugfix
语言 / 框架：Python 3, pytest
环境可复现等级：有外部依赖，未容器化
