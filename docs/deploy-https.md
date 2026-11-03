# HTTPS 反向代理部署指南（agentgate HTTP 模式）

agentgate 自身不终止 TLS。暴露到网络时，**必须**前置一个做认证 + TLS 的反向代理。本指南给两个经Test的通用形态。

## 前置条件

```bash
agentgate run --config policy.yaml --agent all --http 127.0.0.1:8080 --trust-agent-header
agentgate ui --state-dir .agentgate --host 127.0.0.1 --port 8756
```

两者都只绑回环——公网入口完全交给反代。

## 形态 A：Caddy（自动 HTTPS + Basic Auth）

```caddy
# Caddyfile
gateway.example.com {
    basic_auth {
        operator <bcrypt-hash>
    }
    reverse_proxy 127.0.0.1:8080
}

console.example.com {
    basic_auth {
        operator <bcrypt-hash>
    }
    reverse_proxy 127.0.0.1:8756
}
```

要点：
- 仍设置 `AGENTGATE_UI_TOKEN`（控制台自己的第二道门）与 `AGENTGATE_APPROVAL_SECRET`；
- Basic Auth 在代理层挡人，agent 身份仍由 `X-Agentgate-Agent` 头决定（fail-closed）。

## 形态 B：nginx（TLS + allowlist + 头注入）

```nginx
server {
    listen 443 ssl;
    server_name gateway.example.com;
    ssl_certificate     /etc/ssl/certs/gateway.pem;
    ssl_certificate_key /etc/ssl/private/gateway.key;

    # 只有显式列出的身份头才能进来
    location /mcp {
        if ($http_x_agentgate_agent !~* ^(bot|alpha|beta)$) { return 403; }
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header X-Agentgate-Agent $http_x_agentgate_agent;
        proxy_http_version 1.1;
        proxy_buffering off;           # SSE/流式必需
        proxy_read_timeout 300s;
    }
    location / { return 404; }
}
```

## 安全清单（暴露前逐项确认）

- [ ] `AGENTGATE_HTTP_EXPOSE_OK` 未设（网关本身拒绝裸露），入口全在反代
- [ ] 反代强制认证（Basic Auth / OIDC / mTLS 任选其一）
- [ ] `X-Agentgate-Agent` 头由代理校验/覆写，不可由外网直接注入任意身份
- [ ] `AGENTGATE_APPROVAL_SECRET` 已设置（审批签名）
- [ ] 控制台 `AGENTGATE_UI_TOKEN` 已设置
- [ ] `/metrics`、`/status` 仅内网可达（反代 location 拦截或网络分段）
- [ ] state 目录与策略文件在反代主机上不可被外部写入
