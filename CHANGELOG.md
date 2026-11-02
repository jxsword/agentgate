# Changelog

## 0.3.0 (2026-11-03)

运维与治理强化（SRS §3.8）：

- **`agentgate check`** 策略模拟器：不启动上游即可打印决策与命中规则；`--cases` 批量断言供 CI 使用
- **上游调用超时** `call_timeout_seconds`（默认 120s）：挂死的上游不再拖垮网关，`upstream_timeout` 审计
- **工具调用限流**：server 策略 `rate_limit: {calls, window_seconds}` 滑动窗口，超限 fail-closed + `retry_after`
- **Web 控制台认证**：`AGENTGATE_UI_TOKEN` 强制 token；无 token 拒绝非回环绑定
- **grants.json 跨进程锁**：msvcrt/fcntl 独占锁 + 读时重载，并发写不再丢失更新
- **`agentgate report`**：按 agent/tool 汇总决策、拒绝率，`--since` 过滤，table/json/csv 输出
- **打包与 CI**：Dockerfile（非 root）+ compose 示例、GitHub Actions 3 平台矩阵、策略 JSON Schema

## 0.2.0 (2026-11-03)

V1.2（SRS §3.7）：

- **Web 审批台** `agentgate ui`：浏览器批准/拒绝、撤销委托、审计查看
- **多 agent 单进程 HTTP**：`--agent all`，每 agent `/<agent>/mcp`，共享上游连接
- **OPA 策略后端** `policy_backend_url`：本地显式规则优先，回落查询外部决策端点，故障 fail-closed
- **策略热更新**：mtime 轮询 2s 原子换入，非法策略自动回退
- **凭据注入**：上游 headers/env 支持 `${ENV_VAR}`，缺失拒绝启动
- **审计轮转**：10MB 自动轮转，历史保留

## 0.1.x (2026-11-02)

V0.1/V1.1（SRS §3.1-3.6）：

- 核心网关：stdio 代理、工具命名空间、声明式策略（glob/args_match/回退链）、fail-closed
- 人类审批（文件协议）+ 限时范围委托（TTL、tool+args 绑定、撤销）
- 追加式审计（fsync）、prompt injection 防御性错误呈现、上游故障隔离
- V1.1：prompts/resources 代理、HTTP 入口、审批 HMAC 签名
