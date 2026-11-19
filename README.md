# GSB Bugfix Task
## 题面
企业目录的 SCIM 同步开始串租户：filter 里塞一个 or 就能查到别的租户用户，password 等字段也能当条件；引号、括号和 not 嵌套后优先级错；分页传零或负数绕过上限；排序字段直接拼查询；PATCH 能改 tenantId；组同步会把外租户成员带进来；属性名大小写不同被当成两个字段。scim_filter.py 要重写过滤器、分页和 PATCH 路径校验；测试文件 tests/test_scim_filter.py 目前 15 条全红。租户条件必须强制注入，属性/操作符走白名单，非法输入统一抛 ValueError。

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
