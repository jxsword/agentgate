# agentgate 威胁模型（threat model）

> 版本：v0.5 ｜ 映射：OWASP Agentic Top 10 (2026)、OWASP T01-T17、CSA MAESTRO、TC260《AI 安全治理框架 3.0》智能体专章
> 本文档面向 agentgate 的使用者与评审者，说明"防什么、不防什么、为什么"。

## 1. 资产与信任边界

| 项 | 说明 |
|---|---|
| 信任边界 1 | MCP 客户端（agent）↔ 网关：agent 是**不可信**的——它可能被提示注入操纵（OWASP LLM01/ASI01） |
| 信任边界 2 | 网关 ↔ 上游 MCP 服务器：上游是**半可信**的（策略决定能否触达） |
| 信任边界 3 | 人类审批终端 / Web 控制台 ↔ state 目录：**同机同信任域**（v0.5 假设，见 §4 局限） |

核心资产：上游工具能触达的数据与系统（文件、数据库、内部 API）；审计日志的完整性。

## 2. 威胁 → 缓解映射

| 威胁（出处） | 场景 | agentgate 缓解 | 残余风险 |
|---|---|---|---|
| ASI03 / T03 权限滥用与跨 agent 委托 | agent A 冒用 agent B 的授权 | grant 绑定 agent 身份不可跨用（FR-PL-004）；HTTP 按请求身份路由 fail-closed 401（FR-GW-015） | stdio 模式单客户端假设 |
| 五眼"权限蔓延" | 规则越写越宽 | 默认 deny 回退链；`agentgate check`（含 --diff）让放宽策略的影响在合并前可见 | 人为策略纪律 |
| ASI02 工具滥用 | 合法工具被用于恶意参数 | `args_match` 参数级规则；`rate_limit` 滑动窗口限速（FR-PL-007） | 语义级滥用（参数合法但意图恶意）不在 v0.5 范围 |
| ASI06 / T01 记忆与上下文投毒 | 上游返回的内容携带注入指令 | 上游响应按工具调用粒度代理（每次都过策略）；建议配合上游侧注入检测（超出本项目范围，见调研报告 G4） | 网关不做内容级注入检测 |
| ASI10 / T13 失控 agent | agent 循环疯狂调用/烧钱 | ask 人工闸门 + TTL 过期 + revoke；per-server rate_limit；`call_timeout_seconds`（挂死隔离）；`upstream_timeout` 审计 | 无全局预算账户（见路线图） |
| T08 抵赖 / 事后无法追责 | "agent 到底做了什么？" | 追加式 fsync 审计 + 哈希链防篡改 + `log --verify`；决策/审批/授权三类事件全覆盖（FR-AU-001/006） | 链起点可信假设（genesis 本地生成） |
| ASI09 / T10 审批疲劳攻击 | 轰炸审批让人无脑点允许 | 每请求一次投票（one-vote）；拒绝理由回传减少"再试一次"循环；rate_limit 同时限流 ask | 无审批频率上限（可加，未做） |
| 审批伪造（本机攻击者） | 恶意进程写 decisions 文件放行 | `AGENTGATE_APPROVAL_SECRET` HMAC 签名（含 reason 字段）；未签名一律拒绝（FR-AP-007） | 密钥同机可读则失效——同信任域假设 |
| 控制台暴露 | Web 审批台被未授权访问 | 默认 127.0.0.1；非回环必须 `AGENTGATE_UI_TOKEN`；登录签发 HttpOnly+SameSite=strict 会话 cookie（J1） | 无 HTTPS（部署方前置反代） |
| 凭据泄漏 | 策略文件进 git 带密钥 | headers/env 仅支持 `${ENV_VAR}` 引用，缺变量拒绝启动；凭据永不入文件（NFR-SEC-003） | 环境变量本身的管理超出范围 |
| 审计敏感数据扩散 | 审计记录含明文参数 | 默认仅参数哈希；`audit_arguments` 显式开启且可与 `redact` 叠加（打码后落盘） | redact 仅顶层键（文档明示） |

## 3. Fail-closed 清单（全部有测试）

无规则命中 → deny；策略引擎异常 → deny（`policy_error`）；未知工具/命名空间 → deny；审批超时 → deny；审批签名无效 → deny；限流超限 → deny；上游启动全失败 → 网关拒绝启动；策略热更新非法 → 保留旧策略。

## 4. 明确不防（v0.5 范围外）

1. **提示注入内容检测**——网关是授权层不是检测层（见调研报告 G4：开源检测器对间接注入近乎失效，属独立赛道）；
2. **上游服务器自身的恶意行为**（工具描述投毒等供应链风险）——建议搭配 mcp 扫描器（调研方向 C4）；
3. **同机 root 攻击者**——可读所有 state 与密钥；v0.5 威胁模型假设审批终端与网关同信任域；
4. **审批人被社会工程**——技术手段无法完全防御，审计链至少保证事后可追责；
5. **密码学强审计锚定**（Merkle/签名时间戳）——哈希链防本地篡改，跨机公开可验证留痕属未来工作（EX-3 深化）。

## 5. 安全默认值速查

`default_decision: deny` ｜ `on_ask: pending`（超时 deny）｜ prompts/resources 默认 deny ｜ 无 rate_limit 配置不限流（建议配置）｜ 审计仅参数哈希 ｜ 控制台仅回环 ｜ HTTP headers 必须环境变量引用。
