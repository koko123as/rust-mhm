# Architecture

## 当前请求路径

```text
local SOCKS5 client
        |
        v
SOCKS5 handshake / CONNECT parser
        |
        v
structured target (IP or domain + port)
        |
        v
ordered routing rules (first match wins)
        |                         |
      DIRECT                    REJECT
        |                         |
        v                         v
DIRECT TCP dial with timeout   SOCKS5 REP 0x02
        |
        v
bounded Tokio bidirectional relay
```

## 模块边界

- `rust-mhm-core::config`：本项目严格的最小 YAML 配置；校验 loopback 地址、连接超时、并发上限及规则语法。
- `rust-mhm-core::routing`：纯决策层；处理 `DOMAIN`、`DOMAIN-SUFFIX`、`IP-CIDR`/`IP-CIDR6`、`DST-PORT`、`MATCH`，规则保持配置顺序。
- `rust-mhm-core::server`：SOCKS5 入站、路由动作执行、目标拨号、错误映射、连接并发限制和 TCP 转发。
- `rust-mhm`：命令行配置加载、日志初始化和服务启动；不承载协议/路由业务。

## 配置与路由边界

配置顶层只识别 `listen`、`connect_timeout_ms`、`max_connections`、`rules`。它不是完整 Mihomo YAML；例如 `mixed-port`、`proxies`、`proxy-groups` 和 `rule-providers` 等未知字段会失败。规则字符串仅接受本项目声明的规则类型与 `DIRECT`/`REJECT` 动作；缺少 `MATCH` 时追加本项目约定的 `MATCH,DIRECT` 默认项。

规则层不执行 DNS 查询。IP-CIDR 规则只匹配 SOCKS5 请求中给出的字面 IP；如果目标是域名，不会为了路由规则先解析它。域名直连时仍由 Tokio/系统名称解析路径处理。域名匹配限 ASCII DNS A-label（如 `xn--...`），采用小写比较并去掉一个末尾根点；这些均是本项目约定，不是完整上游行为承诺。

## 生命周期与资源

监听地址默认并限制为 loopback；每个活动连接占用一个有界 semaphore permit 和 Tokio task。服务退出时停止接受连接并取消现有连接任务。出站连接具有配置的超时；当前尚无热重载、持久化、UDP 关联、rule-provider 缓存或 TUN 文件描述符。
