"""Policy and gateway configuration loading/validation.

The YAML schema (v1):

    version: 1
    default_decision: deny          # global fallback: allow | deny | ask
    state_dir: .agentgate           # optional, default ".agentgate" under CWD

    servers:                        # upstream MCP servers the gateway proxies
      fs:
        transport: stdio            # stdio | http
        command: python             # stdio only
        args: ["-m", "demo_server"]
        env: {"DEMO_SANDBOX": "..."}

    agents:
      claude-code:
        servers:
          fs:
            default: ask            # decision when no tool rule matches
            tools:
              "echo": allow
              "read_*": allow
              "write_file":
                decision: ask
                args_match:
                  path: "*/sandbox/*"
                delegation:
                  ttl_seconds: 3600
                  bind: tool        # tool | tool+args
              "risky_*": deny
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

ALLOW = "allow"
DENY = "deny"
ASK = "ask"
DECISIONS = (ALLOW, DENY, ASK)
BINDS = ("tool", "tool+args")


class ConfigError(ValueError):
    """Raised when the policy file is invalid. Message is user-facing."""


@dataclass
class DelegationConfig:
    ttl_seconds: int = 3600
    bind: str = "tool"

    def __post_init__(self) -> None:
        if self.bind not in BINDS:
            raise ConfigError(f"delegation.bind must be one of {BINDS}, got {self.bind!r}")
        if self.ttl_seconds <= 0:
            raise ConfigError("delegation.ttl_seconds must be > 0")


@dataclass
class ToolRule:
    pattern: str
    decision: str
    args_match: dict[str, str] | None = None
    delegation: DelegationConfig | None = None

    def __post_init__(self) -> None:
        if self.decision not in DECISIONS:
            raise ConfigError(f"tool decision must be one of {DECISIONS}, got {self.decision!r}")
        if self.decision != ASK and self.delegation is not None:
            raise ConfigError(
                f"delegation is only valid on 'ask' rules (pattern {self.pattern!r})"
            )


@dataclass
class ServerPolicy:
    """Per-agent policy for one upstream server."""

    default: str = DENY
    rules: list[ToolRule] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.default not in DECISIONS:
            raise ConfigError(f"server policy default must be one of {DECISIONS}, got {self.default!r}")


@dataclass
class AgentPolicy:
    servers: dict[str, ServerPolicy] = field(default_factory=dict)


@dataclass
class ServerConfig:
    name: str
    transport: str = "stdio"
    # stdio
    command: str | None = None
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    # http (streamable HTTP)
    url: str | None = None
    headers: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.transport not in ("stdio", "http"):
            raise ConfigError(f"servers.{self.name}.transport must be 'stdio' or 'http'")
        if self.transport == "stdio" and not self.command:
            raise ConfigError(f"servers.{self.name}: stdio transport requires 'command'")
        if self.transport == "http" and not self.url:
            raise ConfigError(f"servers.{self.name}: http transport requires 'url'")
        if self.transport == "http" and self.headers:
            # fail at load time instead of runtime: header values belong in env-injected
            # plumbing, not policy files (SRS NFR-SEC-003); v0.1 does not wire them.
            raise ConfigError(
                f"servers.{self.name}: http headers are not supported in v0.1 "
                f"(planned for EX-6 secret egress)"
            )


@dataclass
class Config:
    default_decision: str = DENY
    state_dir: Path = Path(".agentgate")
    servers: dict[str, ServerConfig] = field(default_factory=dict)
    agents: dict[str, AgentPolicy] = field(default_factory=dict)
    # runtime behaviour for 'ask' when no human responds: "pending" (write approval
    # request and block) or "deny" (fail closed, for CI/unattended runs)
    on_ask: str = "pending"
    ask_timeout_seconds: int = 300

    def __post_init__(self) -> None:
        if self.default_decision not in DECISIONS:
            raise ConfigError(f"default_decision must be one of {DECISIONS}")
        if self.on_ask not in ("pending", "deny"):
            raise ConfigError("on_ask must be 'pending' or 'deny'")


def _parse_tool_rule(server: str, pattern: str, raw: object) -> ToolRule:
    if isinstance(raw, str):
        return ToolRule(pattern=pattern, decision=raw)
    if isinstance(raw, dict):
        decision = raw.get("decision")
        if not decision:
            raise ConfigError(f"agents.*.servers.{server}.tools.{pattern}: missing 'decision'")
        delegation = None
        if "delegation" in raw:
            d = raw["delegation"] or {}
            delegation = DelegationConfig(
                ttl_seconds=int(d.get("ttl_seconds", 3600)),
                bind=str(d.get("bind", "tool")),
            )
        args_match = raw.get("args_match") or None
        if args_match is not None and not isinstance(args_match, dict):
            raise ConfigError(f"args_match must be a mapping of arg-path -> glob, got {args_match!r}")
        return ToolRule(
            pattern=pattern,
            decision=str(decision),
            args_match=dict(args_match) if args_match else None,
            delegation=delegation,
        )
    raise ConfigError(f"agents.*.servers.{server}.tools.{pattern}: expected string or mapping, got {raw!r}")


def _parse_server_policy(server: str, raw: object) -> ServerPolicy:
    if not isinstance(raw, dict):
        raise ConfigError(f"agents.*.servers.{server}: expected mapping, got {raw!r}")
    rules = []
    tools = raw.get("tools") or {}
    if not isinstance(tools, dict):
        raise ConfigError(f"agents.*.servers.{server}.tools: expected mapping")
    for pattern, rule in tools.items():
        rules.append(_parse_tool_rule(server, str(pattern), rule))
    return ServerPolicy(default=str(raw.get("default", DENY)), rules=rules)


def _parse_server_config(name: str, raw: dict) -> ServerConfig:
    transport = str(raw.get("transport", "stdio"))
    return ServerConfig(
        name=name,
        transport=transport,
        command=raw.get("command"),
        args=[str(a) for a in raw.get("args", [])],
        env={str(k): str(v) for k, v in (raw.get("env") or {}).items()},
        url=raw.get("url"),
        headers={str(k): str(v) for k, v in (raw.get("headers") or {}).items()},
    )


def load_config(path: str | Path) -> Config:
    p = Path(path)
    if not p.exists():
        raise ConfigError(f"config file not found: {p}")
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise ConfigError(f"invalid YAML in {p}: {e}") from e
    if not isinstance(raw, dict):
        raise ConfigError(f"config root must be a mapping, got {type(raw).__name__}")

    version = raw.get("version", 1)
    if version != 1:
        raise ConfigError(f"unsupported policy version: {version!r} (expected 1)")

    cfg = Config(
        default_decision=str(raw.get("default_decision", DENY)),
        state_dir=Path(str(raw.get("state_dir", ".agentgate"))),
        on_ask=str(raw.get("on_ask", "pending")),
        ask_timeout_seconds=int(raw.get("ask_timeout_seconds", 300)),
    )
    for name, scfg in (raw.get("servers") or {}).items():
        if not isinstance(scfg, dict):
            raise ConfigError(f"servers.{name}: expected mapping")
        cfg.servers[str(name)] = _parse_server_config(str(name), scfg)
    for agent, apol in (raw.get("agents") or {}).items():
        if not isinstance(apol, dict):
            raise ConfigError(f"agents.{agent}: expected mapping")
        policy = AgentPolicy()
        for server, spol in (apol.get("servers") or {}).items():
            policy.servers[str(server)] = _parse_server_policy(str(server), spol)
        cfg.agents[str(agent)] = policy
    return cfg
