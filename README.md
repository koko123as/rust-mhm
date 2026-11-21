# rust-mhm

一个以 Rust 逐步实现代理内核能力的独立项目。仓库仍处于早期原型阶段，**不是 Mihomo 的完整替代品，也不声称兼容其完整配置或功能**。本项目使用自己的严格 YAML 子集，并按可测试的垂直切片推进。

## 当前实现

- SOCKS5 TCP `CONNECT` 入站，支持 IPv4、IPv6 与域名目标；默认无认证，可用 `authentication` 列表启用 RFC 1929 用户名/密码认证，并可用 `skip-auth-prefixes` CIDR 允许指定来源免认证。
- TCP 出站支持 `DIRECT`、HTTP `CONNECT`、SOCKS5；HTTP 与 SOCKS5 出站可选用户名/密码认证。
- 有序首匹配规则支持 `DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`DOMAIN-WILDCARD`、`IP-CIDR`/`IP-CIDR6`、`SRC-IP-CIDR`、`SRC-PORT`、`DST-PORT`、`MATCH`；动作可为 `DIRECT`、`REJECT` 或配置中声明的代理名称。
- `REJECT` 在拨号前返回 SOCKS5 connection-not-allowed；代理握手与连接共用配置的出站超时。
- 默认监听 `127.0.0.1:1080`，拒绝非 loopback 监听；连接并发有界。
- 未知 YAML 字段、代理类型、规则类型、动作、重复代理名和未配置的代理引用均显式报错。

配置示例（账号字段是明文配置；实际使用时应限制配置文件权限，不要提交真实凭据）：

```yaml
listen: "127.0.0.1:1080"
connect_timeout_ms: 10000
max_connections: 256
authentication: # 可省略；设置后每个 SOCKS5 客户端都必须认证
  - "local-user:change-me"
proxies:
  - name: upstream
    type: http # 也可以是 socks5
    server: proxy.example.net
    port: 8080
    username: your-user # 可省略；若配置则 username/password 必须同时存在
    password: your-password
rules:
  - DOMAIN,ads.example,REJECT
  - DOMAIN-SUFFIX,example.org,DIRECT
  - IP-CIDR,192.0.2.0/24,DIRECT,no-resolve
  - DST-PORT,443,upstream
  - MATCH,DIRECT
```

代理类型目前只支持 `http`（HTTP CONNECT 隧道，不是通用正向 HTTP 转发，也不支持 TLS-to-proxy）和 `socks5`（SOCKS5 TCP CONNECT）。规则的第三列用代理名选择出站，例如 `MATCH,upstream`。省略规则时按本项目约定使用 `MATCH,DIRECT`。

`skip-auth-prefixes` 命中时将协商无认证方法；该功能应谨慎配置，避免把不可信来源列入豁免范围。SOCKS5 入站认证和 SOCKS5 出站认证按 RFC 1929 传输明文凭据，因此仅应在可信本机网络使用；监听仍被限制为 loopback。**仍未实现：** UDP、HTTP 入站、HTTPS/其他代理出站、代理组、`RULE-SET`/rule providers、Mihomo DNS 策略、TUN、订阅、REST API、UI 与 Android 服务。IP-CIDR 不会为域名目标先行解析。该项目不接受完整 Mihomo YAML；见 [兼容性台账](COMPATIBILITY.md)。

## 快速开始

需要 Rust 1.85 或更高版本。

```sh
cargo test --workspace
cp config.example.yaml config.yaml
cargo run -p rust-mhm -- config.yaml
```

运行时可通过 `RUST_LOG=info` 设置日志级别。当前监听只允许 loopback IP；LAN/TUN 等网络暴露方式尚未实现。

## 架构与阶段

- [ARCHITECTURE.md](ARCHITECTURE.md)：当前数据路径与模块边界。
- [ROADMAP.md](ROADMAP.md)：分阶段目标、未实现能力与验收项。
- [COMPATIBILITY.md](COMPATIBILITY.md)：上游规则语义来源与本项目兼容性决策。
- [DEVELOPMENT.md](DEVELOPMENT.md)：依赖、工具链和本地开发说明。
- [TESTING.md](TESTING.md)：测试范围和未覆盖项。
- [PERFORMANCE.md](PERFORMANCE.md)：性能测量状态。
- [CHANGELOG.md](CHANGELOG.md)：阶段变更记录。

## 来源与许可证

SOCKS5 子集参考 [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928) 和 [RFC 1929](https://www.rfc-editor.org/rfc/rfc1929)；HTTP CONNECT 使用标准 HTTP 隧道请求。上游能力范围见 [MetaCubeX 官方 Meta 分支 README](https://raw.githubusercontent.com/MetaCubeX/mihomo/Meta/README.md) 与[官方配置文档](https://wiki.metacubex.one/en/config/)。本项目本阶段未复制或移植上游实现代码，能力名称的语法支持不代表完整语义兼容。

上游 README 标注 GPL-3.0，并注明与 MetaCubeX 无关的下游项目名称不能包含 “mihomo”。本仓库名称为 `rust-mhm`。**本项目自身的许可证尚未由项目所有者选择；仓库当前没有 `LICENSE` 文件，也不应据此假设已有再分发授权。**

## 验证状态

Linux x86_64 上验证：格式检查、workspace 全目标编译、workspace 测试、零警告 Clippy 与 CLI 帮助检查。当前测试覆盖代理认证与本地双向 TCP 隧道，不依赖外网。Windows、macOS、Android、真实代理服务、长时负载及 Android VPN 集成尚未验证。
