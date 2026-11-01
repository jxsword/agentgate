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
```

- 客户端以 streamable HTTP 连接 `http://127.0.0.1:8080/mcp`；
- 一个网关进程可同时服务多个客户端连接；agent 身份仍来自 `--agent`；
- 多 agent 需求：每个 agent 一个进程/端口（身份不走 HTTP 头，避免信任问题）；
- localhost 绑定自动启用 DNS rebinding 防护。

### 4.1.2 审批签名（V1.1，可选加固）

```bash
export AGENTGATE_APPROVAL_SECRET="<随机长随机串>"   # 网关与审批终端使用同一环境变量
```

设置后，`agentgate approve` 的裁决自动附 HMAC 签名，网关验签后才生效；未签名或伪造的裁决文件一律按拒绝处理并审计 `approval_signature_invalid`。密钥只从环境变量读取，不要写进策略文件或脚本。

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

事件类型：`gateway_start/stop`、`call`（allow/grant/ask_allowed 代理前后各一条）、`call_denied`、`approval_requested`、`ask_denied`、`grant_created`、`upstream_error`、`policy_error`。

设计取舍：审计记录**参数哈希**（canonical JSON）而非完整参数；完整参数仅出现在 pending 审批文件里供人审阅。事故复盘：`call` 的 `arguments_hash` 与 `grant` 的绑定哈希同构，可精确对账"哪次调用、哪条规则、谁批的"。

## 7. 已知局限（v0.1）

| 局限 | 说明 | 规划 |
|---|---|---|
| HTTP 入口单 agent | 一个 HTTP 网关进程服务一个 agent 身份（多连接可共享） | 多 agent 路由 |
| prompts/resources 无 ask | 能力开关只有 allow/deny（只读列举不走人工审批） | 按需扩展 |
| prompts/resources 仅透传 | prompt 参数不做 args_match 级过滤 | 按需扩展 |
| HTTP 上游不支持 headers | 配置了会拒绝加载（fail at load） | EX-6 密钥出口 |
| grants.json 单写者 | 运行期由网关独占写；CLI 并发 revoke 有竞态；文件损坏自动清空（更严格方向） | V1.2 |
| 策略不热更新 | 改策略需重启网关 | 路线图外 |
| 审计文件未轮转 | 长期运行需自行 logrotate | V1.2 |

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
