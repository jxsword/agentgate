# agentgate

[![CI](https://github.com/jxsword/agentgate/actions/workflows/ci.yml/badge.svg)](https://github.com/jxsword/agentgate/actions/workflows/ci.yml)

**Agent 原生 MCP 授权网关**：每次工具调用逐次鉴权、危险操作人类审批、审批可转为限时范围委托（scoped delegation）、全程追加式审计（哈希链防篡改）。

对标 Permit.io MCP Gateway / Auth0 for GenAI 的**开源自托管替代**。选型依据见仓库上层 `research/调研报告_agent项目选型.md`（方向 C1：商业三家闭源验证需求，开源空白）。

```mermaid
graph LR
    CC["MCP 客户端（Claude Code / Cursor）"] -->|stdio / --http| G["agentgate 网关<br/>策略: allow / deny / ask + 限流 + 超时"]
    G -->|"allow → 代理"| U[上游 MCP 服务器 ×N]
    G -->|"ask → 人工"| H["审批：CLI / Web 控制台<br/>（可签发限时范围委托）"]
    G -->|deny + 审计留痕| X[（不执行）]
    G -.->|audit.jsonl 哈希链| A["agentgate log --verify / report"]
```

## 30 秒上手

```bash
pip install -e .
# 用示例策略启动网关（对 MCP 客户端表现为一个普通 MCP 服务器）
python -m agentgate run --config policies/example.yaml --agent claude-code

# Claude Code 接入（一行）：
claude mcp add agentgate -- python -m agentgate run --config policies/example.yaml --agent claude-code
```

策略里 `ask` 的工具被调用时，网关会打印审批指引并在 `--allow` 之前一直阻塞该调用：

```bash
agentgate pending                 # 查看待审批
agentgate approve <id> --allow    # 批准（可带 delegation：限时、绑定参数）
agentgate log -n 50               # 查看审计
agentgate grants                  # 查看有效委托
agentgate revoke <grant_id>       # 即时撤销
```

## 特性

- **fail-closed**：无规则、异常、未知工具、审批超时一律拒绝；默认决策 `deny`
- **声明式策略**：YAML——agent × server × 工具 glob × 参数条件（`args_match`）× 决策
- **人类审批**：文件式协议 + **Web 审批台**（`agentgate ui`），无需了解 MCP
- **范围委托**：批准一次 = 在 TTL 内（可选绑定到完全相同参数）重复放行，可随时 revoke
- **审计**：JSONL 追加式、fsync 落盘、10MB 自动轮转，每次调用必有决策留痕
- **prompts/resources 代理**（V1.1）：协议完整覆盖，server 级能力开关
- **HTTP 入口**（V1.1/V1.2）：`--http HOST:PORT`；`--agent all` 单进程多 agent（`/<agent>/mcp`）
- **审批签名**（V1.1）：`AGENTGATE_APPROVAL_SECRET` 环境变量启用 HMAC 验签，伪造裁决失效
- **热更新**（V1.2）：策略文件改动 2 秒内生效，非法策略自动回退
- **外部策略后端**（V1.2）：`policy_backend_url` 对接 OPA 风格决策端点，故障 fail-closed
- **凭据注入**（V1.2）：上游 headers/env 支持 `${ENV_VAR}` 引用，缺变量拒绝启动
- **调用超时**（v0.3）：`call_timeout_seconds` 挂死上游不拖垮网关
- **限流**（v0.3）：server 级滑动窗口 `rate_limit`，超限 fail-closed
- **策略模拟器**（v0.3）：`agentgate check` 不启动上游即可验证策略（可进 CI）
- **审计报表**（v0.3）：`agentgate report` 按 agent/tool 汇总，table/json/csv
- **控制台认证**（v0.3）：`AGENTGATE_UI_TOKEN`；跨进程 grants 文件锁
- **打包**（v0.3）：非 root Dockerfile + compose 示例 + GitHub Actions 3 平台矩阵 + 策略 JSON Schema
- **审计防篡改**（v0.4）：哈希链 + `agentgate log --verify`，取证级日志完整性
- **validate/healthz/status**（v0.4）：策略校验命令、HTTP 运维探针、审批拒绝理由回传、tools/list 缓存、systemd 样例
- **按请求身份路由**（v0.5）：`--trust-agent-header` 单端口多 agent（fail-closed 401）
- **参数脱敏**（v0.5）：server 策略 `redact`，审批展示/审计打码，委托绑定不受影响
- **审计查询与一键演示**（v0.5）：`log --filter/--grep`、`agentgate demo`、`scripts/bench.py`
- **策略组合与诊断**（v0.6）：`extends` 基座复用、`agentgate doctor` 环境体检、`report --grants` 委托用量、`grants <id>` 详情

## 文档

- [用户使用手册](docs/manual.md) —— 安装、策略编写、审批工作流、排障
- [需求规格（SRS V1.0）](docs/srs.md) —— 功能/非功能需求、追踪矩阵、审核日志
- [设计文档](docs/design.md) —— 架构图、时序图、状态图、数据模型、安全设计

## 测试

```bash
pip install -e ".[dev]"
pytest            # 39 tests: 单元 + 真实子进程端到端
```

## 状态与已知局限（v0.1）

- stdio 入口（HTTP 入口 / Web 审批台 / prompts-resources 代理为路线图 EX-1/2/4）
- 审批文件未做密码学签名（同机信任域假设；签名方案见 EX-3）
- `grants.json` 运行期单写者（网关）；损坏时按更严格方向降级
- 更多：见 `docs/design.md` §6 与 `docs/manual.md` 排障一节

License: Apache-2.0
