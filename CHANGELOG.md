# Changelog

## 0.6.0 (2026-11-03)

组合与洞察（SRS §3.11）+ GitHub 工程化：

- **策略组合** `extends: base.yaml`：递归深合并（dict 逐键、标量/列表覆盖）、循环检测、相对路径解析——多环境策略不再复制粘贴
- **委托用量视图** `agentgate report --grants`：审计 grant_id 与 grants.json 关联——每个委托的使用次数、状态、审批人，并标记"已不在册"的引用（table/json）
- **委托详情** `agentgate grants <id>`：范围、参数绑定、创建/过期时间、审批人
- **GitHub 工程化**：私有仓库 + Actions 3 平台矩阵调试（修复 anyio 跨任务 cancel scope 的 http e2e 模式、裁剪矩阵节约私有额度、.gitattributes 行尾规范、README CI 徽章）
- **杂项**：JSON Schema 补 `extends`；pytest-asyncio loop-scope 告警清理；示例策略内联 redact/rate_limit 注释

## 0.5.1 (2026-11-03)

- **控制台会话认证**：`/login` 表单换签 HttpOnly + SameSite=strict 会话 cookie（8h），浏览器免每次 URL token；`/logout` 注销；未认证访问 `/` 重定向登录页（API 路径仍 401）
- **`agentgate log -f`**：审计跟随模式（支持 --filter/--grep），轮转自动重置读取位置
- **威胁模型文档** `docs/security.md`：OWASP Agentic Top 10 / T01-T17 / MAESTRO / TC260 3.0 威胁→缓解映射、fail-closed 清单、"明确不防"边界

## 0.5.0 (2026-11-03)

多租户与审计体验（SRS §3.10）：

- **按请求身份路由**：`--agent all --http --trust-agent-header`——单一 `/mcp` 端点按 `X-Agentgate-Agent` 请求头路由到对应 agent 的策略与上游；缺失/未知身份 401（fail-closed）
- **参数脱敏**：server 策略 `redact: [键名 glob]`——审批展示、stderr 提示与 `audit_arguments` 输出打码；`arguments_hash` 与 `tool+args` 委托绑定始终使用真实参数
- **审计查询**：`agentgate log --filter key=value --grep text`
- **`agentgate demo`**：一条命令跑通端到端演示（allowlist 防护）
- **基准脚本**：`scripts/bench.py` 输出 tools/call 延迟百分位（本机 p50 8.5ms / p95 10.2ms，含上游往返）

## 0.4.0 (2026-11-03)

加固与运维（SRS §3.9）：

- **审计哈希链防篡改**：每条记录携带前一条的 sha256；`agentgate log --verify` 校验全部审计文件（编辑/删除即断链）；轮转文件为独立链
- **`agentgate validate`**：不启动网关即可校验策略并输出摘要
- **审批拒绝理由**：CLI `--reason` / 控制台拒绝表单；理由随拒绝文本回传 agent，并纳入 HMAC 签名载荷（防签名后篡改）
- **pending 残留清理**：网关启动时移除超过 ask-timeout 的遗留审批文件（崩溃残留）
- **/healthz 与 /status 端点**：HTTP 模式运维探针（agent、上游、on_ask、超时配置、限流窗口占用）
- **tools/list 缓存**：`list_cache_seconds`（默认 30s）聚合快照，客户端频繁轮询不再打到上游
- **systemd 部署样例**：gateway（多 agent HTTP）与 console 单元，含加固项与环境变量密钥
- **审计完整参数开关**：`audit_arguments: true`（默认关，仅哈希），全决策路径含未知工具
- **`check --diff`**：两份策略对同一组用例的决策差异标记（策略变更影响分析）
- **PyPI 发布工作流**：tag 触发 trusted publishing

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
