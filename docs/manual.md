# agentgate 用户使用手册

> 适用版本：v0.1 ｜ 上手示例见 README，本文是完整参考。

## 1. 安装

要求：Python ≥ 3.11（Windows / Linux / macOS）。

```bash
cd agentgate
pip install -e .            # 运行所需
pip install -e ".[dev]"     # 含 pytest，跑测试用
```

验证安装：

```bash
agentgate --version         # agentgate 0.1.0
```

## 2. 核心概念（30 秒）

- **网关**：一个普通 MCP 服务器进程，插在 MCP 客户端与你的真实工具服务器（上游）之间。
- **命名空间**：上游 `demo` 的工具 `read_file` 在客户端看到的名字是 `demo--read_file`。
- **策略**：YAML 文件，声明哪个 agent 对哪个 server 的哪些工具可以 allow / deny / ask。
- **ask**：需要人类点头的调用——网关挂起该调用并生成审批请求，你在任意终端批准/拒绝。
- **委托（grant）**：批准 `ask` 调用时若策略配置了 `delegation`，会生成一张"限时通行证"：TTL 内重复调用免审批（可选绑定到完全相同的参数），随时 `revoke`。
- **审计**：`.agentgate/audit.jsonl`，追加式 JSONL，每次调用必有决策留痕。

## 3. 编写策略

```yaml
# policy.yaml
version: 1
default_decision: deny        # 全局兜底，永远建议 deny
on_ask: pending               # pending=生成审批并等待；deny=无人值守直接拒（CI）
ask_timeout_seconds: 300      # ask 等待人类的时限，超时=拒绝

state_dir: .agentgate         # 审计/待审批/委托 的存放目录（相对 CWD）

servers:                      # 上游 MCP 服务器
  fs:
    transport: stdio
    command: python
    args: ["-m", "my_fs_server"]
    env:                      # 额外环境变量（凭据请从外部环境注入，勿写进本文件）
      FS_ROOT: "/srv/data"
  remote:
    transport: http
    url: "https://internal.example.com/mcp"
    # 注意：v0.1 不支持 headers 配置（会拒绝加载），见手册 §7 局限

agents:                       # agent 身份 -> 各 server 的策略
  claude-code:
    servers:
      fs:
        default: ask          # 没有命中规则的工具 → ask
        prompts: allow        # V1.1：prompts/resources 能力开关（默认 deny）
        resources: allow
        tools:
          "list_*": allow
          "read_file": allow
          "write_file":
            decision: ask
            args_match:                     # 参数条件：全部满足才算命中本规则
              path: "/srv/data/*"           # 点路径取参 + glob（缺参=不匹配）
            delegation:                     # 批准后自动发委托
              ttl_seconds: 600
              bind: tool+args               # tool=仅按工具；tool+args=绑定完全相同参数
          "delete_*": deny
```

规则要点：
- 工具名用 glob（`fnmatch`，大小写敏感），按书写顺序首个命中生效；
- `args_match` 不满足时**跳过该规则**继续往下匹配（不是直接拒绝）；
- 回退链：委托 grant → 工具规则 → server `default` → 全局 `default_decision`；
- 未在 `agents:` 里声明的 agent 直接落到全局默认（deny）。

## 4. 启动与接入

### 4.1 启动网关

```bash
agentgate run --config policy.yaml --agent claude-code
```

常用覆盖参数：`--state-dir DIR`、`--on-ask pending|deny`、`--ask-timeout 秒`。
策略加载失败（YAML 错、字段非法）会以可读错误退出（退出码 2）。

### 4.1.1 HTTP 模式（多客户端共享，V1.1）

```bash
agentgate run --config policy.yaml --agent claude-code --http 127.0.0.1:8080
# 多 agent 单进程（V1.2）：每个 agent 在 /<agent>/mcp
agentgate run --config policy.yaml --agent all --http 127.0.0.1:8080
```

- 客户端以 streamable HTTP 连接 `http://127.0.0.1:8080/mcp`（多 agent 时为 `/<agent>/mcp`）；
- 单 agent 模式一个网关进程可同时服务多个客户端连接；`--agent all` 则服务策略内全部 agent（上游连接共享，授权按 agent 隔离）；
- localhost 绑定自动启用 DNS rebinding 防护。

### 4.1.2 审批签名（V1.1，可选加固）

```bash
export AGENTGATE_APPROVAL_SECRET="<随机长随机串>"   # 网关与审批终端使用同一环境变量
```

设置后，`agentgate approve` 的裁决自动附 HMAC 签名，网关验签后才生效；未签名或伪造的裁决文件一律按拒绝处理并审计 `approval_signature_invalid`。密钥只从环境变量读取，不要写进策略文件或脚本。

### 4.1.3 策略热更新（V1.2，默认开启）

修改策略文件保存后约 2 秒内自动生效（决策规则、默认值、args_match）；非法新策略会保留旧策略并审计 `policy_reload_failed`。`agents:`/`servers:` 集合变更仍需重启。`--no-watch` 可关闭。

### 4.1.4 Web 审批台（V1.2）

```bash
agentgate ui --state-dir .agentgate --port 8756    # 默认 http://127.0.0.1:8756/
```

浏览器中直接批准/拒绝待审请求、撤销委托、查看审计尾部（5 秒自动刷新）。与 CLI 走完全相同的裁决路径（one-vote + HMAC 签名），审批人记录为 `web:<名字>`。默认只绑定本机回环地址。

### 4.1.5 外部策略后端（OPA，V1.2，可选）

```yaml
policy_backend_url: "http://127.0.0.1:8181/v1/data/agentgate/decision"
```

配置后：本地显式规则仍然优先；落到默认值（无规则命中/无该 agent 段）时向该端点 POST `{"input": {agent, server, tool, arguments}}`，返回 `{"result": {"decision": "allow|deny|ask"}}`（或顶层 `decision` 字段）。后端任何故障一律按 deny 处理（fail-closed）。

### 4.1.6 HTTP 上游凭据（V1.2）

```yaml
servers:
  remote:
    transport: http
    url: "https://internal.example.com/mcp"
    headers:
      Authorization: "Bearer ${MY_TOKEN_ENV}"   # 启动时从环境变量解析
```

`${VAR}` 在加载期解析，变量缺失直接拒绝启动（凭据永不写入策略文件）。env 值同样支持 `${VAR}`。

### 4.1.7 调用超时（v0.3）

```yaml
servers:
  demo:
    call_timeout_seconds: 60    # 默认 120s；0 = 不限时
```

上游超时转为可读 isError 并审计 `upstream_timeout`；挂死的上游不会阻塞网关其他调用。

### 4.1.8 调用限流（v0.3）

```yaml
agents:
  claude-code:
    servers:
      demo:
        rate_limit: { calls: 30, window_seconds: 60 }   # 滑动窗口
```

仅门控会被放行的调用（allow/grant/ask）；显式 deny 不受影响。ask 尝试计入窗口（审批后被拒也算一次尝试）。超限返回可读错误（含 retry-after）并审计 `rate_limited`。窗口在内存中，重启即清零。

### 4.1.9 策略模拟器（v0.3）

```bash
# 单例：打印决策与命中规则，不启动上游
agentgate check --config policy.yaml --agent claude-code \
  --server demo --tool write_file --args '{"path": "sandbox/a.txt"}'

# 批量（供 CI）：expect 不匹配时退出码 1
agentgate check --config policy.yaml --agent claude-code --cases cases.json
```

cases.json 格式：`[{"server": "...", "tool": "...", "arguments": {...}, "expect": "allow"}]`。
注意：模拟器只评估本地规则，不查询 `policy_backend_url` 外部后端（保证确定性）。

### 4.1.10 审计报表（v0.3）

```bash
agentgate report                                  # 表格：按 agent×tool 汇总
agentgate report --format csv > report.csv        # CSV 导出
agentgate report --format json --since 2026-11-03T00:00:00+08:00
```

### 4.1.11 控制台认证（v0.3）

```bash
export AGENTGATE_UI_TOKEN="<随机长随机串>"
agentgate ui --host 0.0.0.0     # 未设 token 时拒绝绑定非回环地址
```

设置后所有控制台请求（含表单提交）必须携带 token（`Authorization: Bearer` 或 `?token=`，页面表单自动内嵌）。

### 4.1.13 审计防篡改校验（v0.4）

每条审计记录链式携带前一条的哈希。事后校验：

```bash
agentgate log --verify        # 校验全部审计文件（含轮转文件）
# agentgate-....jsonl: OK - chain intact (12/12 records chained)
```

任何就地编辑/删除都会被定位（`TAMPERED`，退出码 1）。取证时先用它证明日志完整，再做 `report` 分析。

### 4.1.14 其他 v0.4 快捷项

- `agentgate validate --config policy.yaml`：只校验不启动，输出策略摘要
- 拒绝理由：`agentgate approve <id> --deny --reason "..."`（或控制台拒绝表单），理由回传给 agent 并计入签名
- `/healthz`、`/status`：HTTP 网关模式运维探针
- `list_cache_seconds: 0`：关闭 tools/list 缓存（默认 30s）
- `deploy/*.service`：systemd 部署样例（含加固项）
- 网关启动自动清理超过 ask-timeout 的遗留审批文件

### 4.1.15 v0.5 快捷项

- **按请求身份路由**：`agentgate run --config p.yaml --agent all --http 0.0.0.0:8080 --trust-agent-header`
  → 客户端在 streamable HTTP 请求头带 `X-Agentgate-Agent: <agent>`；缺失/未知身份 401（fail-closed）。
  适合多客户端共享单端口、各自身份隔离的场景。
- **参数脱敏**：server 策略 `redact: ["password", "api_*", "token"]`——审批展示与
  `audit_arguments` 审计输出打码为 `***`；哈希与 `tool+args` 委托绑定不受影响（安全语义不变）。
- **审计查询**：`agentgate log --filter event=call_denied --filter agent=bot`、`--grep sandbox`
- **一键演示**：`agentgate demo`（自动跑通 allow→审批→grant→deny→prompts/resources 全流程）
- **基准**：`python scripts/bench.py -n 500`（本机实测 p50≈8.5ms / p95≈10.2ms，含上游往返）

### 4.1.16 v0.6 快捷项

- **策略组合**：`extends: base.yaml`（相对路径；基座深合并、子文件覆盖；循环检测报错）。多环境共用基座、只覆盖差异
- **委托用量**：`agentgate report --grants`——每个委托被使用的次数/状态/审批人，识别"已不在册"的引用（table/json）
- **委托详情**：`agentgate grants <id>`
- **按请求身份路由**（v0.5）在 `--agent all --http` 上叠加 `--trust-agent-header`：客户端请求头 `X-Agentgate-Agent: <agent>`，缺失/未知 401

### 4.1.17 环境诊断（v0.6）

```bash
agentgate doctor --config policy.yaml          # 环境与策略体检
agentgate doctor --config policy.yaml --reach  # 同时探测上游可达性
```

检查项：Python 版本、mcp/pyyaml 依赖、state 目录可写、**审计哈希链完整性**（含轮转文件）、策略加载；`--reach` 会逐个启动/停止上游验证连通。任何 ✗ 退出码 1——排障第一步先跑它。

### 4.1.18 监控与部署（v0.7）

- **Prometheus**：HTTP 模式抓取 `http://127.0.0.1:8080/metrics`——`agentgate_tool_calls_total{agent,server,tool,outcome}`（allowed/denied/rate_limited）与 `agentgate_upstreams_up`
- **审计多进程**：轮转文件名带 pid，多网关共享 state 目录不再互相覆盖
- **HTTPS 暴露**：见 `docs/deploy-https.md`（Caddy/nginx 反代 + 安全清单）

### 4.1.19 策略自测与取证（v0.7）

- **策略内嵌用例**：策略文件加 `tests:` 键，CI 用 `agentgate check --config p.yaml --agent bot --selftest` 防策略漂移（用例即文档）：

  ```yaml
  tests:
    - {server: demo, tool: delete_file, expect: deny}
    - {server: demo, tool: write_file, arguments: {path: "sandbox/x"}, expect: ask}
  ```

- **授权用量告警**：策略加 `grant_usage_alert: 50`——某委托被使用 50 次时审计 `grant_usage_alert` 并打 stderr 警告（进程生命周期计数，重启清零）。
- **取证**：`agentgate incident <grant_id>`——重建该委托的完整时间线（审批→签发→每次使用→结果）并核验审计链完整性。

### 4.1.20 批量审批与治理检查（v0.7）

- **批量裁决**：`agentgate approve --all --allow|--deny [--approver NAME]`——一键处理全部待审（逐请求走同一 one-vote + 签名路径）；紧急场景优先逐条审。
- **策略治理**：`agentgate lint --config p.yaml`——语义检查（区别于 validate 的语法检查）：
  - FAIL：`default_decision != deny`、`"*"` 通配规则（blanket allow）
  - WARN：`on_ask=deny` 无人值守模式、`default=allow` 无规则、暴露 prompts/resources 无审批门、`rate_limit` 阈值偏宽（>1000/窗口）、delegation 落在 deny 规则上（防御性检查，实际加载期已被拒）

### 4.1.12 Docker 部署（v0.3）

```bash
docker build -t agentgate .
AGENTGATE_UI_TOKEN=xxx docker compose up -d      # gateway(:8080) + console(:8756)
```

镜像以非 root 运行；策略只读挂载、state 走卷。编辑器补全：策略文件头部加 `# yaml-language-server: $schema=./policy.schema.json`。

### 4.2 Claude Code 接入

```bash
claude mcp add agentgate -- agentgate run --config /abs/path/policy.yaml --agent claude-code
```

### 4.3 Cursor / 其他客户端

在 MCP 配置中添加 stdio 服务器：command=`agentgate`，args=`["run","--config","<绝对路径>","--agent","claude-code"]`。
（路径务必用绝对路径，或确保客户端工作目录正确。）

## 5. 审批工作流

当 agent 调用了 `ask` 工具（如 `fs--write_file`）：

1. **网关终端**打印审批指引：请求 id、工具全名、参数、命中规则、`agentgate approve <id>` 命令；
2. （可选）`agentgate pending` 查看全部待审；
3. **另一个终端**裁决：

```bash
agentgate approve 1a2b3c4d5e6f --allow              # 批准（有 delegation 配置则自动发委托）
agentgate approve 1a2b3c4d5e6f --deny --approver alice   # 拒绝并留痕审批人
```

4. 同一请求**只能裁决一次**（重复 approve 报错），裁决文件消费后即清理；
5. 超时未裁决 → 拒绝（fail-closed），pending 文件清理。

委托管理：

```bash
agentgate grants            # 有效委托（id / 范围 / 过期时间 / 审批人）
agentgate grants --all      # 含已过期
agentgate revoke <id>       # 即时撤销
```

## 6. 审计

```bash
agentgate log -n 50         # 最近 50 条
```

事件类型：`gateway_start/stop`、`call`（allow/grant/ask_allowed 代理前后各一条）、`call_denied`、`approval_requested`、`ask_denied`、`grant_created`、`upstream_error`、`policy_error`、`policy_reloaded/policy_reload_failed`（V1.2 热更新）、`prompt_call/prompt_denied/resource_call/resource_denied`（V1.1）、`approval_signature_invalid`（V1.1）。审计文件超 10MB 自动轮转为 `audit-<时间戳>.jsonl`，历史保留。

设计取舍：审计记录**参数哈希**（canonical JSON）而非完整参数；完整参数仅出现在 pending 审批文件里供人审阅。事故复盘：`call` 的 `arguments_hash` 与 `grant` 的绑定哈希同构，可精确对账"哪次调用、哪条规则、谁批的"。

## 7. 已知局限（v0.1）

| 局限 | 说明 | 规划 |
|---|---|---|
| HTTP 入口（单 agent） | `--http` 单 agent 多连接；多 agent 用 `--agent all`（每 agent 独立命名空间 `/<agent>/mcp`，共享上游连接） | —（已实现多 agent） |
| prompts/resources 无 ask | 能力开关只有 allow/deny（只读列举不走人工审批） | 按需扩展 |
| prompts/resources 仅透传 | prompt 参数不做 args_match 级过滤 | 按需扩展 |
| 热更新边界 | agents/servers 集合变更需重启；决策规则/默认值/args_match 即时生效 | — |
| grants.json 单写者 | 运行期由网关独占写；CLI/控制台并发 revoke 有竞态；文件损坏自动清空（更严格方向） | V1.3 |
| 策略不热更新 | 已实现（默认开启，`--no-watch` 关闭）；仅 agents/servers 集合需重启 | — |
| Web 控制台无认证 | 默认绑定 127.0.0.1，暴露到网络需自备反向代理认证 | V1.3 |

## 8. 排障

| 现象 | 原因与处理 |
|---|---|
| 客户端连不上 / 工具列表为空 | 看 stderr：某上游启动失败会被隔离（`upstream_error`）；全部失败则网关拒绝启动。检查 `command/args` 路径（建议绝对路径）与 `env` |
| 调用返回 "unknown tool" | 必须用命名空间名 `server--tool`（见 `tools/list`） |
| 策略错误退出码 2 | 错误信息含位置语义（如 `agents.*.servers.fs.tools."x"`），按提示修正 YAML |
| approve 报 "no pending approval request" | 请求已被消费（已裁决/超时清理），用 `agentgate pending` 确认 |
| approve 报 "already decided" | 一个请求一次裁决，防重复投票 |
| 审批超时 | agent 侧会收到超时拒绝；可调大 `ask_timeout_seconds` |
| Windows 下子进程启动失败 | 确认 `command` 可执行；需要系统环境变量时网关已合并默认环境，自定义 `env` 会叠加而非替换 |

## 9. 运行自带演示

```bash
cd agentgate
agentgate run --config policies/example.yaml --agent claude-code   # 终端 1
# 用任意 MCP 客户端连入并调用 demo--write_file；
# 终端 2：
agentgate pending
agentgate approve <id> --allow
agentgate log -n 20
```

自动化验证：`pytest`（39 个测试，含真实子进程端到端链路）。
