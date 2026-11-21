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
        |                  |                         |
     DIRECT              REJECT                  named proxy
        |                  |                   HTTP CONNECT / SOCKS5
        v                  v                         |
DIRECT TCP dial      SOCKS5 REP 0x02 <--------------+
        |                                            |
        +--------------------+-----------------------+
                             v
              bounded Tokio bidirectional TCP relay
```

连接及完整代理握手均受统一的 `connect_timeout_ms` 超时约束；拒绝动作不会发起上游连接。

## 模块边界

- `rust-mhm-core::config`：严格的本项目 YAML 配置；校验 loopback 地址、连接超时、并发上限、入站用户、代理定义及规则引用。
- `rust-mhm-core::routing`：纯决策层；处理 `DOMAIN`、`DOMAIN-SUFFIX`、`IP-CIDR`/`IP-CIDR6`、`DST-PORT`、`MATCH`，规则保持配置顺序；动作是 `DIRECT`、`REJECT` 或具名代理。
- `rust-mhm-core::outbound`：HTTP CONNECT（可选 Basic 认证）和 SOCKS5 TCP CONNECT（可选 RFC 1929 用户名/密码认证）；只建立 TCP 隧道，不实现 UDP 或代理组。
- `rust-mhm-core::server`：SOCKS5 入站（可选 RFC 1929 认证）、规则动作执行、目标拨号、错误映射、连接并发限制和 TCP 转发。
- `rust-mhm`：命令行配置加载、日志初始化和服务启动；不承载协议/路由业务。

## 配置与路由边界

顶层只识别 `listen`、`connect_timeout_ms`、`max_connections`、`rules`、`proxies` 与 `authentication`。`authentication` 是 `username:password` 字符串列表；列表非空时服务强制 RFC 1929 子协商，不会回退到无认证。代理对象字段为 `name`、`type`（`http` 或 `socks5`）、`server`、`port` 和可选的成对 `username`/`password`。配置仍不是完整 Mihomo YAML；`skip-auth-prefixes`、`proxy-groups`、`rule-providers` 等未知字段会失败。规则第三列可用 `DIRECT`、`REJECT` 或配置中的代理名；未声明的动作/代理名失败。缺少 `MATCH` 时追加本项目约定的 `MATCH,DIRECT`。

SOCKS5 入站仅在配置非空 `authentication` 时要求 RFC 1929 用户名/密码，登录失败即关闭连接；该子协商本身没有加密。HTTP Basic 和 SOCKS5 用户密码在未加密代理链路上均可被观察，因此应限于可信主机/网络。HTTP 出站使用 HTTP/1.x `CONNECT` 并发送目标 authority；SOCKS5 出站将域名作为域名地址类型交给代理端解析；DIRECT 域名连接仍由 Tokio/系统解析。两种代理都仅支持 TCP `CONNECT`，没有 UDP associate、链式代理、健康检查、重试、TLS-to-proxy 或代理组。

规则层不执行 DNS 查询。IP-CIDR 规则只匹配 SOCKS5 请求中给出的字面 IP；域名目标不会为了路由先解析。域名规则接受 ASCII DNS A-label（如 `xn--...`），按小写比较并去掉一个末尾根点；这些均是本项目约定，不是完整上游行为承诺。HTTP CONNECT 的目标域名另作 ASCII DNS 名校验，以避免未经验证的控制字符进入 HTTP 请求头。

## 生命周期与资源

监听地址默认并限制为 loopback；每个活动连接占用一个有界 semaphore permit 和 Tokio task。服务退出时停止接受连接并取消现有连接任务。代理出站握手及连接均受配置超时；当前尚无热重载、持久化、UDP 关联、rule-provider 缓存、TUN 文件描述符或代理组运行时。
