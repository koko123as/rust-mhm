# Architecture

## 当前请求路径

```text
local SOCKS5 client
        |
        v
SOCKS5 handshake / CONNECT parser
        |
        v
structured target (IP or domain + port) + inbound peer IP
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
- `rust-mhm-core::routing`：纯决策层；处理 `DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`DOMAIN-WILDCARD`、有限的 `DOMAIN-REGEX`、`IP-CIDR`/`IP-CIDR6`、`SRC-IP-CIDR`、`SRC-PORT`、`DST-PORT`，并按原位置展开 inline classical `RULE-SET`；动作是 `DIRECT`、`REJECT` 或具名代理。
- `rust-mhm-core::outbound`：HTTP CONNECT（可选 Basic 认证）和 SOCKS5 TCP CONNECT（可选 RFC 1929 用户名/密码认证）；只建立 TCP 隧道，不实现 UDP 或代理组。
- `rust-mhm-core::server`：SOCKS5 入站（可选 RFC 1929 认证）、规则动作执行、目标拨号、错误映射、连接并发限制和 TCP 转发。
- `rust-mhm`：命令行配置加载、日志初始化和服务启动；不承载协议/路由业务。

## 配置与路由边界

顶层只识别 `listen`、`connect_timeout_ms`、`max_connections`、`rules`、`rule-providers`、`proxies`、`authentication` 与 `skip-auth-prefixes`。provider 当前支持 `type: inline`/`file`/`http` 与 `behavior: classical`/`domain`/`ipcidr` 子集；file 相对路径以配置文件目录为基准，HTTP 类型可使用 HTTP 或 HTTPS URL。二者都在启动时读取单份快照、限 4 MiB，并解析有限 YAML `payload` 或逐行文本；HTTP 响应须为成功状态，最多跟随 5 次重定向，完整请求受 `connect_timeout_ms` 超时约束。CLI 使用 `Config::load_async`；`Config::from_yaml_str` 不接受 file/HTTP，`Config::load` 不接受 HTTP。尚无持久缓存、定期刷新、请求头、自定义格式/MRS 或自动更新；上游 `interval` 等额外字段不支持。`authentication` 是 `username:password` 字符串列表；列表非空时通常强制 RFC 1929 子协商。来源 IP 命中 `skip-auth-prefixes` 的 IPv4/IPv6 CIDR 时改为无认证协商。代理对象字段为 `name`、`type`（`http` 或 `socks5`）、`server`、`port` 和可选的成对 `username`/`password`。配置仍不是完整 Mihomo YAML；`proxy-groups` 等未知字段会失败。规则第三列可用 `DIRECT`、`REJECT` 或配置中的代理名；未声明的动作/代理名失败。缺少 `MATCH` 时追加本项目约定的 `MATCH,DIRECT`。

SOCKS5 入站仅在配置非空 `authentication` 且 peer 不匹配豁免 CIDR 时要求 RFC 1929 用户名/密码，登录失败即关闭连接；该子协商本身没有加密。HTTP Basic 和 SOCKS5 用户密码在未加密代理链路上均可被观察，因此应限于可信主机/网络。HTTP 出站使用 HTTP/1.x `CONNECT` 并发送目标 authority；SOCKS5 出站将域名作为域名地址类型交给代理端解析；DIRECT 域名连接仍由 Tokio/系统解析。两种代理都仅支持 TCP `CONNECT`，没有 UDP associate、链式代理、健康检查、重试、TLS-to-proxy 或代理组。

规则层不执行 DNS 查询。`IP-CIDR` 只匹配 SOCKS5 请求中给出的字面目标 IP；`SRC-IP-CIDR` 与 `SRC-PORT` 分别匹配接受连接时取得的客户端 peer IP 与来源端口。域名目标不会为了路由先解析。域名规则接受 ASCII DNS A-label（如 `xn--...`），按小写规范化并去掉一个末尾根点；`DOMAIN-REGEX` 使用 Rust `regex` crate 语法，表达式在配置加载时编译。上述均是本项目约定，不是完整上游行为承诺。HTTP CONNECT 的目标域名另作 ASCII DNS 名校验，以避免未经验证的控制字符进入 HTTP 请求头。

## 生命周期与资源

监听地址默认并限制为 loopback；每个活动连接占用一个有界 semaphore permit 和 Tokio task。服务退出时停止接受连接并取消现有连接任务。代理出站握手及连接均受配置超时；rule-provider 下载只发生于启动配置加载阶段，下载完成后无后台更新任务。当前尚无热重载、持久缓存或自动更新、UDP 关联、TUN 文件描述符或代理组运行时。
