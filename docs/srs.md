# agentgate 软件需求规格说明书（SRS）

> 项目：agentgate —— Agent 原生 MCP 授权网关
> 文档版本：V0.1（草稿）→ V1.0（定稿，见 8.3 变更历史）
> 开发模型：瀑布（依据：需求已由调研与决策记录确认、文档驱动、阶段交付）
> 审核方式说明：用户已预先授权"4 小时内不介入，由执行方连续自行复审 2 轮修正补充后继续执行"（用户消息，2026-11-02）。三轮预设审核压缩为两轮执行，每轮有实际修正内容，记录于审核日志（8.4）。
> 需求来源：`research/调研报告_agent项目选型.md`、`docs/decision_log.md`（DR-001 方向、DR-002 技术栈）、用户消息（2026-11-02：完整项目、需求/设计文档、可运行、实测、单测、git 管理、用户手册）。

## 1. 引言

### 1.1 目的
定义 agentgate v0.1（及 v1.x 路线）的功能与非功能需求，作为设计、开发、测试与验收的唯一依据。

### 1.2 范围
**做**：一个运行于 MCP 客户端与上游 MCP 服务器之间的 stdio 授权网关。对每次工具调用执行声明式策略鉴权（allow/deny/ask）、人类审批与带 TTL 的范围委托（scoped delegation）、追加式审计日志。提供 CLI（run/pending/approve/log/grants/revoke）。支持 stdio 与 streamable HTTP 两类上游。
**不做**（v0.1）：网关自身的 HTTP 服务入口、Web 审批台、审批防重放密码学绑定、prompts/resources 代理、多租户管理、策略热更新（见第 7 章扩展清单）。

### 1.3 读者对象
项目维护者（个人开发者）、自托管 AI agent 用户、安全评审者、后续贡献者。

### 1.4 术语定义
| 术语 | 定义 |
|---|---|
| MCP | Model Context Protocol，Anthropic 发起的模型-工具互操作开放协议 |
| 网关/Gateway | 位于 MCP 客户端与上游服务器之间的代理进程，对客户端表现为普通 MCP 服务器 |
| 上游/Upstream | 被网关代理的真实 MCP 服务器 |
| 工具/Tool | MCP tools/call 的可调用单元；网关内命名空间为 `<server>--<tool>` |
| 决策/Decision | 策略引擎对一次工具调用的判定：allow / deny / ask；grant 表示命中已授权委托 |
| 人类委托/Delegation | 人类对一次 ask 调用批准后产生的、带 TTL 且绑定范围的可重复授权（grant） |
| 审计日志/Audit | 追加式 JSONL 文件，记录每次决策与审批事件 |
| 失败关闭/Fail-closed | 任何不确定情形（无规则、异常、超时）一律拒绝 |
| state 目录 | 网关运行时状态（审计、待审批请求、委托授权）所在目录，默认 `.agentgate` |

### 1.5 参考资料
- OWASP《Top 10 for Agentic Applications 2026》（ASI03 身份与权限滥用）、《Agentic AI Threats & Mitigations v1.1》（T03 权限攻陷）
- OWASP Agent Control Standard（ACS，2026-09）：hooks + 策略强制点接口
- 五眼联盟《Careful Adoption of Agentic AI Services》（权限蔓延首要风险）
- TC260《人工智能安全治理框架 3.0》智能体风险管理框架（工具越权、持续监测与审计）
- MCP 规范 2026-07-28（modelcontextprotocol.io）、MCP Python SDK 2.3
- 调研报告：`research/调研报告_agent项目选型.md`（C1 候选论证）

## 2. 总体描述

### 2.1 产品愿景
对标 Permit.io MCP Gateway / Auth0 for GenAI 的**开源实现**：让任何 MCP 客户端（Claude Code、Cursor 等）在接入上游工具前必须经过策略检查，危险操作由人类显式批准并可按范围限时委托，全程留痕可审计。1-2 年窗口内企业 agent 治理刚需（详见调研报告 §一 T1/T2/T6）。

### 2.2 用户特征
- **主用户**：自托管 agent 开发者（个人/小团队），双栈能力，会改 YAML、会用 CLI；
- **审批人**：运行 agent 的操作者本人或团队成员，通过另一终端执行 `agentgate approve`；
- **审计读者**：事后排查"agent 到底做了什么"的开发者/安全人员。

### 2.3 运行环境
- OS：Windows 10/11、Linux、macOS（Python asyncio + 子进程跨平台）
- 运行时：Python ≥ 3.11；依赖：`mcp>=2.3`、`pyyaml>=6`
- 客户端：任何支持 stdio MCP 的客户端（Claude Code / Cursor / 自研客户端）

### 2.4 约束条件
- 冲刺交付约束：v0.1 需在单次连续工作会话内完成并通过全部测试；
- fail-closed 为硬约束：策略异常、上游异常、审批超时均不得放行；
- 审计不可静默丢失：写入需 flush+fsync；
- 不得在源码、示例、测试中写入任何可用凭据字面量（凭据仅来自环境变量）。

### 2.5 假设与依赖
- **assumption-1**：单网关进程同一时刻服务一个 agent 身份（stdio 客户端一对一）；多 agent 通过多进程/多策略文件实现。
- **assumption-2**：审批人与网关在同一台机器共享文件系统（v0.1 文件式审批通道）。
- **assumption-3**：MCP 客户端在网关 stderr 上不会把 human 可读提示当作协议错误（Claude Code 实测为日志通道）。

## 3. 功能需求

### 3.1 模块：网关代理（GW）

#### FR-GW-001 stdio 网关运行 P0 V1.0
| 字段 | 内容 |
|---|---|
| 功能描述 | 网关以 MCP stdio 服务器形态运行，成为客户端与上游间的唯一通道 |
| 触发条件 | CLI `agentgate run --config <yaml> --agent <name>` |
| 输入 | 策略 YAML 路径、agent 身份名、可选 state 目录/on_ask/超时覆盖 |
| 处理逻辑 | 1. 加载并校验策略 2. 建立 state 目录 3. 连接全部已配置上游 4. 以 `agentgate-<agent>` 名义向客户端提供 stdio MCP 服务 |
| 输出 | 客户端完成 initialize 后可 list/call 工具；启动/连接事件写入 stderr 与审计 |
| 异常处理 | 策略文件缺失/非法：退出码 2 并输出可读错误；全部上游连接失败：退出并不提供空服务 |
| 前置条件 | Python ≥ 3.11，依赖已安装 |
| 后置条件 | audit 记录 `gateway_start`/`gateway_stop` 事件 |

#### FR-GW-002 多上游聚合与工具命名空间 P0 V1.0
多个上游（`servers:` 配置）的工具聚合呈现为 `<server>--<tool>`，避免重名冲突；工具描述透传。未命名空间化或未知 server 的 tools/call 一律返回 isError 结果（fail-closed），错误信息提示正确的命名空间用法。

#### FR-GW-003 tools/list 代理 P0 V1.0
聚合所有上游的完整工具清单（含分页遍历）；单个上游 list 失败不阻塞其他上游（降级返回其余工具，stderr 告警）。

#### FR-GW-004 tools/call 策略拦截与代理 P0 V1.0
每次 tools/call 依次经过：命名空间解析 → 策略引擎判定 → 按 decision 执行（allow/grant 直接代理；deny 返回 isError；ask 进入审批流）。**每次调用产生审计记录**（事件 `call`，含 agent/server/tool/参数哈希/命中规则/决策）。

#### FR-GW-005 失败关闭的错误呈现 P0 V1.0
deny/ask 超时/审批拒绝/上游异常均以 MCP isError 结果返回给人可读的原因文本（含命中规则），绝不静默吞掉；对应审计事件分别为 `call_denied`/`ask_denied`/`upstream_error`。

#### FR-GW-006 上游故障隔离 P1 V1.0
单个上游启动失败不终止网关（stderr + `upstream_error` 审计），但该上游工具不可用；全部上游失败则拒绝启动。上游运行中调用异常转换为 isError 并审计。

### 3.2 模块：策略引擎（PL）

#### FR-PL-001 策略加载与校验 P0 V1.0
YAML 策略加载（version=1）；非法 decision/bind/缺失字段/类型错误以 `ConfigError` 报出**用户可读**错误（含位置语义如 `agents.*.servers.fs.tools."x"`）。决策词汇表：allow/deny/ask；全局 `default_decision` 仅允许同词汇表。

#### FR-PL-002 规则匹配 P0 V1.0
工具名 glob（fnmatch，大小写敏感）；规则按文件顺序首个命中生效；`args_match` 以点路径取参 + glob 匹配字符串化值，**参数缺失视为不匹配**（fail-closed）；args_match 不满足时规则跳过、继续评估。

#### FR-PL-003 决策回退链 P0 V1.0
委托 grant 命中 > agent·server 工具规则 > agent·server default > 全局 `default_decision`（默认 deny）。未配置 agent 或 server 直接落到全局默认。

#### FR-PL-004 Agent 身份 P0 V1.0
agent 身份来自 CLI `--agent`（必填）；同一策略文件可含多个 agent 段；委托 grant 绑定到 agent 身份，跨 agent 不可复用。

### 3.3 模块：审批与委托（AP）

#### FR-AP-001 ask 生成待审批请求 P0 V1.0
决策为 ask 且 `on_ask=pending` 时：写 `state/pending/<id>.json`（id、agent、server、tool、arguments、参数哈希、命中规则、delegation 配置）；stderr 打印审批指引；阻塞该调用等待（异步，不阻塞其他调用）。

#### FR-AP-002 CLI 审批 P0 V1.0
`agentgate pending` 列出待审；`agentgate approve <id> --allow|--deny [--approver NAME]` 写 `decisions/<id>.json` 完成裁决。无对应待审 id 时报错退出码 1。

#### FR-AP-003 带范围与时限的委托授权 P0 V1.0
审批 allow 且策略声明 delegation 时创建 grant：绑定 (agent, server, tool)，`bind: tool+args` 时绑定参数规范化哈希（JSON sort_keys）；TTL 过期自动失效；grant 命中的调用决策记为 `grant` 并留痕 grant_id。创建事件 `grant_created` 留痕 TTL/bind/approver。

#### FR-AP-004 委托撤销 P1 V1.0
`agentgate revoke <grant_id>` 即时撤销；`agentgate grants [--all]` 列出（默认仅有效）。

#### FR-AP-005 无人值守模式 P1 V1.0
`on_ask: deny`（或 CLI 覆盖）时 ask 决策立即拒绝（审计 `ask_denied`, reason=unattended），用于 CI/无人工场景。

#### FR-AP-006 审批超时失败关闭 P0 V1.0
`ask_timeout_seconds`（默认 300，可配/CLI 覆盖）内无裁决：调用拒绝，审计 `ask_denied` reason=approval timeout，pending 文件清理。

### 3.4 模块：审计（AU）

#### FR-AU-001 追加式审计日志 P0 V1.0
JSONL、每行一个 JSON 对象（ts/event/字段按字母序）；写入 flush+fsync；覆盖事件集：`gateway_start/stop`、`call`（allow/grant/ask_allowed 代理前）、`call_result`、`call_denied`、`approval_requested`、`ask_denied`、`grant_created`、`upstream_error`。字段至少含 agent/server/tool/命中规则/决策/请求或授权 id。

#### FR-AU-002 审计查看 P1 V1.0
`agentgate log [-n N]` 输出最近 N 条（默认 20）原始 JSONL。

#### FR-AU-003 参数留痕 P0 V1.0
审计记录参数哈希（canonical JSON）；arguments 原文仅写入 `approval_requested` 的 pending 文件（供人类审阅），审计日志默认不含完整参数（降低敏感数据扩散面）。

### 3.6 模块：V1.1 增量需求（依据 DR-003，用户授权的扩展）

#### FR-GW-007 HTTP 网关入口 P1 V1.1
`agentgate run --http HOST:PORT` 以 streamable HTTP 对外服务（路径 `/mcp`），多个客户端共享一个网关进程；agent 身份仍来自 `--agent`。localhost 绑定时 SDK 自动启用 DNS rebinding 防护。审计 `gateway_start` 增加 transport/http 字段。

#### FR-GW-008 prompts/resources 代理 P1 V1.1
prompts（命名空间 `<server>--<prompt>`）与 resources（URI 原样保留）按策略代理：`list_prompts/get_prompt/list_resources/read_resource/list_resource_templates`。URI 路由按各允许 server 的 listing 建立；未知 URI 在允许的 server 上逐个探测。拒绝与未知均以对应 Result 类型的可读文本返回（fail-closed），并审计 `prompt_call/prompt_denied/resource_call/resource_denied`。

#### FR-PL-005 能力开关 P1 V1.1
server 策略级 `prompts:` / `resources:` 键，取值仅 allow|deny（默认 deny）；`ask` 不适用于只读列举。非法取值在加载期报错。

#### FR-AP-007 审批签名 P1 V1.1
设置环境变量 `AGENTGATE_APPROVAL_SECRET` 后，`approve` 写入的决策附带 HMAC-SHA256 签名（载荷：id|allow|approver|decided_at|arguments_hash），网关验签；未签名/验签失败一律视为拒绝（fail-closed），审计 `approval_signature_invalid`。密钥仅来自环境变量（NFR-SEC-003）。

### 3.7 模块：V1.2 增量需求（路线图收尾）

#### FR-GW-009 HTTP 上游凭据注入 P1 V1.2
HTTP 上游 headers 与 env 值支持 `${ENV_VAR}` 引用，加载期解析；缺失变量导致加载失败（fail-closed）。凭据永不写入策略文件（NFR-SEC-003）。

#### FR-GW-010 策略热更新 P1 V1.2
网关每 2s 轮询策略文件 mtime；变更后重新加载并原子换入（决策规则/默认值/args_match 即时生效）。非法新策略保留旧策略并审计 `policy_reload_failed`；成功审计 `policy_reloaded`。agents/servers 集合变更需重启（文档明示）。`--no-watch` 关闭。

#### FR-GW-011 多 agent 单进程 HTTP P2 V1.2
`--agent all --http HOST:PORT`：每个策略内 agent 挂载 `/<agent>/mcp`；上游连接共享（MCP 会话支持并发请求），授权按 agent 隔离。

#### FR-AU-004 审计轮转 P2 V1.2
审计文件超过 10MB 轮转为 `audit-<时间戳>.jsonl`，历史保留不截断。

#### FR-CLI-005 Web 审批台 P1 V1.2
`agentgate ui [--state-dir D --host H --port P]`：服务端渲染页面展示待审批（批准/拒绝按钮，走与 CLI 完全相同的 one-vote + HMAC 签名路径，审批人记为 `web:<name>`）、有效委托（撤销按钮，逐请求重读 grants.json）、审计尾部（5s 自动刷新）。默认绑定 127.0.0.1。

#### FR-PL-006 外部策略后端适配（OPA） P2 V1.2
配置 `policy_backend_url` 后启用 OPA 适配器：本地显式规则优先；回落默认值时查询外部端点 `POST {input:{agent,server,tool,arguments}}`，接受 `{"result":{"decision":...}}` 或 `{"decision":...}}`，decision 仅 allow/deny/ask；传输错误/非 2xx/非法词一律 fail-closed 拒绝并留痕规则名 `opa:error` / `opa:invalid`。

### 3.8 模块：V0.3 增量需求（运维与治理强化）

#### FR-CLI-006 策略模拟器 P1 V0.3
`agentgate check`：对给定 agent/server/tool/arguments 输出决策（动作+命中规则），不启动上游；`--cases` 批量 JSON（含可选 `expect` 断言，存在不匹配时退出码 1，供 CI 策略测试）。仅评估本地规则（不查询外部策略后端）。

#### FR-GW-012 上游调用超时 P1 V0.3
server 级 `call_timeout_seconds`（默认 120s，0=关闭）：上游超时转为可读 isError + `upstream_timeout` 审计；判定对 SDK 的多种超时包装（TimeoutError / McpError 文本 / ExceptionGroup）均生效。

#### FR-PL-007 工具调用限流 P1 V0.3
server 策略级 `rate_limit: {calls, window_seconds}`（滑动窗口，内存实现）：仅门控 allow/grant/ask 决策（显式 deny 不受影响）；ask 尝试计入窗口；超限 fail-closed（含 retry_after），审计 `rate_limited`。

#### FR-CLI-007 Web 控制台认证 P1 V0.3
环境变量 `AGENTGATE_UI_TOKEN` 设置后控制台所有请求强制携带 token（Bearer 头或 `?token=`，表单内嵌）；未设置时拒绝绑定非回环地址（fail-closed）。

#### FR-AP-008 委托存储跨进程锁 P1 V0.3
grants.json 写路径加独占文件锁（msvcrt/fcntl，有限重试）：锁→重读→修改→原子写，消除网关与 CLI 并发 read-modify-write 竞态；读路径依赖原子替换保证一致。

#### FR-AU-005 审计汇总报表 P2 V0.3
`agentgate report`：按 agent×tool 汇总 allow/grant、ask→ok、denied 计数与拒绝率；`--since` ISO 过滤；table/json/csv 三种输出；包含已轮转审计文件。

#### FR-OPS-001 打包与 CI P2 V0.3
Dockerfile（非 root slim）+ docker-compose 示例（gateway+console）；GitHub Actions 3 平台 × Python 3.11/3.13 矩阵；策略 JSON Schema（编辑器补全）。

### 3.9 模块：V0.4 增量需求（取证与运维收尾）

#### FR-AU-006 审计哈希链 P1 V0.4
每条审计记录携带 `prev`（前一条完整行的 sha256，创世为 64 零）；`agentgate log --verify` 校验全部审计文件（含轮转文件，各自独立链）；对记录的就地修改/删除会使链断裂并被定位；无 `prev` 的历史记录跳过（向前兼容）。

#### FR-CLI-008 策略校验命令 P2 V0.4
`agentgate validate`：仅加载校验并输出摘要（server/agent 数、规则数、限流与能力开关），非法退出码 1。

#### FR-AP-009 审批理由 P1 V0.4
裁决可带 reason（CLI `--reason`、控制台拒绝表单）：拒绝理由回传 agent（isError 文本）并写入审计；reason 纳入 HMAC 签名载荷，签名后不可篡改。

#### FR-GW-013 pending 残留清理 P2 V0.4
网关启动时移除 mtime 早于 ask_timeout 的 pending 文件（活等待不可能超过超时）并审计 `pending_cleanup`。

#### FR-OPS-002 健康与状态端点 P2 V0.4
HTTP 模式暴露 `/healthz`（存活）与 `/status`（agent、上游 serverInfo、on_ask、超时配置）；多 agent 模式为进程级聚合。

#### FR-GW-014 tools/list 缓存 P2 V0.4
`list_cache_seconds`（默认 30s，0=关闭）：聚合工具清单短 TTL 缓存，热更新换入新配置后自然生效。

#### FR-OPS-003 systemd 部署样例 P3 V0.4
deploy/ 提供 gateway（多 agent HTTP）与 console 单元样例，含加固指令与环境变量密钥占位。

#### FR-AU-007 审计完整参数开关 P3 V0.4
`audit_arguments: true` 时审计记录附加完整 arguments（默认关闭仅哈希），适用于全部决策路径（含未知工具与策略错误）。

#### FR-CLI-009 策略差异模拟 P3 V0.4
`agentgate check --config A --diff B --cases`：标记两组策略决策不一致的用例（`~ diff: A=x vs B=y`），用于策略变更影响分析。

#### FR-OPS-004 PyPI 发布流水线 P3 V0.4
`.github/workflows/publish.yml`：`v*` tag 触发构建并经 PyPI trusted publishing 发布。

### 3.10 模块：V0.5 增量需求（多租户与审计体验）

#### FR-GW-015 按请求身份路由 P1 V0.5
`--agent all --http --trust-agent-header`：`/mcp` 端点按 `X-Agentgate-Agent` 头路由至对应 agent（各自策略与共享上游）；头缺失或未知一律 401（fail-closed，无默认 agent）。未启用时保持 `/<agent>/mcp` 路径路由。

#### FR-PL-008 参数脱敏 P1 V0.5
server 策略 `redact: [键名 glob]`：审批展示（pending 文件、stderr 提示）与 `audit_arguments` 输出中命中键的值打码为 `***`（仅顶层键，嵌套不递归——已在测试中明示）；`arguments_hash` 与 `tool+args` 委托绑定使用真实参数，安全语义不受脱敏影响。

#### FR-AU-008 审计查询 P2 V0.5
`agentgate log --filter key=value`（可重复）与 `--grep`：审计记录的键值/子串过滤查询。

#### FR-CLI-010 一键演示 P3 V0.5
`agentgate demo`：运行捆绑演示（gateway+上游+脚本化客户端），路径白名单防护。

#### FR-OPS-005 基准脚本 P3 V0.5
`scripts/bench.py`：tools/call 全链路延迟百分位（min/p50/p95/p99/max）。


### 3.5 模块：CLI（CLI）

#### FR-CLI-001 run P0 V1.0
见 FR-GW-001；`--state-dir` 覆盖 state 目录；`--on-ask`/`--ask-timeout` 覆盖策略。

#### FR-CLI-002 pending P0 V1.0
见 FR-AP-002；损坏的 pending 文件以 `{"id":..., "error":"corrupt"}` 呈现而非崩溃。

#### FR-CLI-003 log P1 V1.0
见 FR-AU-002。

#### FR-CLI-004 grants/revoke P1 V1.0
见 FR-AP-004。

## 4. 非功能需求

| 编号 | 指标 | 目标值 | 测量条件 | 优先级 | 验证方法 |
|---|---|---|---|---|---|
| NFR-PERF-001 | 网关就绪时间（进程启动→initialize 完成） | ≤ 3 s | 本机（Win11, Python 3.14），单 stdio 上游 | P1 | e2e 测试计时断言 |
| NFR-PERF-002 | 网关自身代理开销（不含上游执行与审批等待） | P95 ≤ 50 ms | 本机，连续 100 次 echo 调用 | P1 | e2e 计时统计 |
| NFR-SEC-001 | 失败关闭完备性 | 任何引擎/上游异常、未知工具、审批超时均不放行（0 例外部可达调用绕过策略） | 全部异常路径单测+e2e | **P0** | 专项测试 |
| NFR-SEC-002 | 审计完整性 | 每次 tools/call（无论结果）≥ 1 条决策审计记录 | e2e 后核对 audit.jsonl 行数与调用数一致 | **P0** | e2e 断言 |
| NFR-SEC-003 | 凭据零硬编码 | 源码/示例/测试中无可工作凭据字面量 | 代码复审 + grep | **P0** | 复审清单 |
| NFR-AVAIL-001 | 跨平台 | Windows/Linux/macOS 三平台测试策略可运行（本冲刺实测 Windows，其余为同构代码路径） | CI 矩阵（后续） | P2 | pytest 全绿 |
| NFR-MAINT-001 | 单元测试覆盖 | 核心模块（config/policy/grants/approvals/audit）语句覆盖率 ≥ 85% | pytest-cov | P1 | coverage 报告 |
| NFR-MAINT-002 | 策略错误可读性 | ConfigError 信息包含出错位置语义与期望值 | 全部非法配置用例断言 | P1 | 单测 |
| NFR-COMPAT-001 | MCP 兼容 | 与 MCP 2026-07-28 规范 stdio 客户端可完成 initialize/tools 全流程 | 以官方 SDK ClientSession 实测 | P0 | e2e |

## 5. 外部接口需求

### 5.1 用户界面
v0.1 无 GUI。交互面：CLI（stdout 人读文本）+ stderr 运行日志（含审批指引）。

### 5.2 硬件接口
无特殊要求。

### 5.3 软件接口
- **对 MCP 客户端**：stdio MCP 服务器（tools 能力）；`agentgate-<agent>` 服务器名。
- **对上游**：stdio（command/args/env）与 streamable HTTP（url/headers）；headers 值必须来自策略文件或环境变量，禁止硬编码（对齐 NFR-SEC-003）。
- **审批通道（文件接口）**：`state/pending/<id>.json`（网关写/CLI 读）、`state/decisions/<id>.json`（CLI 写/网关读轮询 0.2s）。

### 5.4 通信接口
本地 stdio 管道；上游 HTTP 走 streamable HTTP（TLS 由 httpx 默认策略）。

## 6. 其他需求

### 6.1 数据需求（文件而非数据库）
| 文件 | 格式 | 说明 |
|---|---|---|
| `state/audit.jsonl` | JSONL | 追加式审计（FR-AU-001） |
| `state/pending/*.json` | JSON | 待审批请求（含完整 arguments 供人类审阅） |
| `state/decisions/*.json` | JSON | 人类裁决（allow/approver/时间） |
| `state/grants.json` | JSON 数组 | 委托授权；原子写（tmp+replace） |

### 6.2 操作需求
- 启动顺序：加载策略 → 连接上游 → serve；退出时审计 `gateway_stop`。
- 日志全部走 stderr；stdout 专用 MCP 协议（不得污染）。

### 6.3 国际化
v0.1 输出为英文（错误信息面向开发者）；代码与文档 UTF-8，策略 YAML 支持中文注释。

## 7. 未来扩展功能

> 状态（2026-11-03）：EX-1/2/3/4/5/6 已分别于 V1.1/V1.2 实现并移入 §3.6/§3.7；下表保留原规划记录。EX-7 仍未排期。

| 编号 | 功能 | 描述 | 预期价值 | 建议版本 | 优先级 | 接口预留说明 |
|---|---|---|---|---|---|---|
| EX-1 | HTTP 网关入口 | 以 streamable HTTP 对外服务，多客户端共享 | 团队共享网关 | V2.0 | E-P1 | Gateway.build_server() 与 stdio 解耦已预留；serve() 参数化传输 |
| EX-2 | Web 审批台 | 浏览器查看 pending/audit 并裁决 | 移动审批 | V2.0 | E-P2 | ApprovalManager 读写接口已收敛为文件协议，可换实现 |
| EX-3 | 签名审批（防重放） | 审批凭证绑定主体/委托链/动作哈希，HMAC 签名 | 对齐 ACS/防止审批挪用 | V2.0 | E-P1 | decision JSON 已含 id+approver+时间，预留扩展字段 |
| EX-4 | prompts/resources 代理 | 透传 prompts/list、resources/* | 协议覆盖完整 | V1.1 | E-P1 | Server 构造器 add_request_handler 可直接挂载 |
| EX-5 | OPA/FGA 策略后端 | 策略引擎适配外部策略引擎 | 企业策略栈复用 | V2.0 | E-P2 | PolicyEngine.evaluate 为唯一判定入口，可实现同签名适配器 |
| EX-6 | 密钥出口代理 | upstream egress secrets 注入 | 凭据不落策略文件 | V2.0 | E-P2 | ServerConfig.env 已支持环境变量来源 |
| EX-7 | 多 agent 并存 | 单进程多 agent 身份路由 | 减少进程数 | V2.0 | E-P3 | 记录即可 |

## 8. 附录

### 8.1 需求追踪矩阵（需求 ↔ 设计 ↔ 测试）

| 需求 | 设计章节 | 测试 |
|---|---|---|
| FR-GW-001/002/003/004/005 | design.md §3/§4 | tests/test_e2e.py::test_full_flow |
| FR-GW-006 | design.md §4.4 | test_e2e（坏上游用例） |
| FR-PL-001 | design.md §4.1 | tests/test_policy.py::TestConfig |
| FR-PL-002/003/004 | design.md §4.1 | tests/test_policy.py::TestPolicyEngine/TestArgsMatch |
| FR-AP-001/002/006 | design.md §4.2/§4.3 | test_e2e（ask→approve→grant）、test_approvals.py |
| FR-AP-003/004 | design.md §4.2 | tests/test_policy.py::TestGrants、test_e2e |
| FR-AP-005 | design.md §4.3 | test_e2e::test_on_ask_deny |
| FR-AU-001/002/003 | design.md §4.5 | test_audit.py、test_e2e 审计计数 |
| FR-CLI-001..004 | design.md §4.6 | test_cli.py |
| NFR-SEC-001/002 | design.md §4.4 | 专项断言（见上） |

### 8.2 待确认事项清单
（空。用户已预先授权自行裁决；本冲刺内全部待确认项已按 fail-closed 原则裁定并记录于 8.4 审核日志。）

### 8.3 变更历史
| 版本 | 日期 | 变更内容 | 原因 |
|---|---|---|---|
| V0.1 | 2026-11-02 | 初稿 | 阶段2产出 |
| V1.0 | 2026-11-02 | 两轮复审修正后定稿（见 8.4） | 用户预授权的自行复审 |
| V1.1 | 2026-11-02 | 依据 DR-003 追加 §3.6 增量需求：FR-GW-007（HTTP 入口）、FR-GW-008（prompts/resources 代理）、FR-PL-005（能力开关）、FR-AP-007（审批签名）；§7 扩展清单中 EX-1/3/4 移入本版实现 | 用户授权的扩展决策 |
| V1.2 | 2026-11-02 | 追加 §3.7 增量需求：FR-GW-009（headers 凭据注入）、FR-GW-010（策略热更新）、FR-GW-011（多 agent 单进程 HTTP）、FR-AU-004（审计轮转）、FR-CLI-005（Web 审批台）、FR-PL-006（OPA 后端适配）；§7 扩展清单中 EX-2/5/6 移入本版实现，路线图全部条目落地 | 用户指示"继续扩展实现所有功能" |
| V1.3/产品 v0.3 | 2026-11-03 | 追加 §3.8：FR-CLI-006（策略模拟器）、FR-GW-012（调用超时）、FR-PL-007（限流）、FR-CLI-007（控制台认证）、FR-AP-008（委托锁）、FR-AU-005（报表）、FR-OPS-001（打包与 CI） | 用户授权的持续迭代（时间盒至 4:10） |
| 产品 v0.4 | 2026-11-03 | 追加 §3.9：FR-AU-006（审计哈希链）、FR-CLI-008（validate）、FR-AP-009（审批理由）、FR-GW-013（pending 清理）、FR-OPS-002（健康端点）、FR-GW-014（list 缓存）、FR-OPS-003（systemd 样例） | 用户授权的持续迭代 |

### 8.4 审核日志（两轮自行复审）
**第 1 轮（完整性）**——发现并修正：① 补 FR-AU-003（参数留痕边界：审计默认不含完整参数，仅哈希；pending 文件含原文供人类审阅），原稿未定义敏感参数扩散面；② 补 NFR-COMPAT-001 与 NFR-PERF-001/002 量化（原稿性能/兼容为定性）；③ 补 FR-GW-006 上游故障隔离与"全部失败拒绝启动"语义；④ 8.1 矩阵补充 NFR 映射。
**第 2 轮（一致性与可执行性）**——发现并修正：① 统一决策词汇表（allow/deny/ask + grant/ask_allowed 为审计标签）并写入 FR-PL-001，消除 policy.py 审计标签与 SRS 表述不一致；② FR-AP-006 明确超时后 pending 文件清理行为；③ 修正 EX-4 的版本归属（V1.1）并补充接口预留；④ 为每条 P0 需求核对测试用例标题可写出（可执行性核验）。
