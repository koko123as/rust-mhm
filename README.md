# rust-mhm

一个以 Rust 逐步实现代理内核能力的独立项目。当前仓库处于早期原型阶段，**不是 Mihomo 的完整替代品，也不声称兼容其完整配置或功能**。

## 当前实现

- SOCKS5 无认证 TCP `CONNECT` 入站；支持 IPv4、IPv6 和域名目标。
- 仅有 `DIRECT` TCP 出站，使用 Tokio 双向转发。
- 有序路由规则子集：`DOMAIN`、`DOMAIN-SUFFIX`、`IP-CIDR`/`IP-CIDR6`、`DST-PORT`、`MATCH`；动作仅支持 `DIRECT` 和 `REJECT`，按配置顺序首个匹配优先。
- 默认监听 `127.0.0.1:1080`；配置校验拒绝非 loopback 监听，避免意外暴露开放代理。
- 严格的本项目 YAML 配置、有限并发连接数和出站连接超时；未知字段、规则类型或动作会报错，不会被静默忽略。
- 本地单元/集成测试覆盖配置校验、规则匹配与优先级、SOCKS5 握手、拒绝规则和本地 TCP 转发。

这只是受限规则切片：不支持 UDP、SOCKS5 认证、HTTP 入站、代理协议出站、代理组、`RULE-SET`/rule providers、TUN、订阅、REST API、UI 或 Android 服务。没有 Mihomo DNS 策略或基于 DNS 结果的 IP 规则匹配；域名 `DIRECT` 连接仍由系统/运行时解析。规则匹配约定及详细边界见 [COMPATIBILITY.md](COMPATIBILITY.md)。

## 快速开始

需要 Rust 1.85 或更高版本。

```sh
cargo test --workspace
cp config.example.yaml config.yaml
cargo run -p rust-mhm -- config.yaml
```

示例配置：

```yaml
listen: "127.0.0.1:1080"
connect_timeout_ms: 10000
max_connections: 256
rules:
  - DOMAIN,ads.example,REJECT
  - DOMAIN-SUFFIX,example.org,DIRECT
  - IP-CIDR,192.0.2.0/24,DIRECT,no-resolve
  - DST-PORT,443,DIRECT
  - MATCH,DIRECT
```

字段可省略；未配置规则时默认为 `MATCH,DIRECT`。运行时可通过 `RUST_LOG=info` 设置日志级别。当前监听只允许 loopback IP；LAN/TUN 等网络暴露方式尚未实现。项目使用自己的顶层配置结构，而不是完整 Mihomo YAML。

## 架构与阶段

- [ARCHITECTURE.md](ARCHITECTURE.md)：当前数据路径与边界。
- [ROADMAP.md](ROADMAP.md)：分阶段目标、未实现能力与验收项。
- [COMPATIBILITY.md](COMPATIBILITY.md)：上游规则语义来源与本项目兼容性决策。
- [DEVELOPMENT.md](DEVELOPMENT.md)：依赖、工具链和本地开发说明。
- [TESTING.md](TESTING.md)：测试范围与命令。
- [PERFORMANCE.md](PERFORMANCE.md)：性能测量状态。
- [CHANGELOG.md](CHANGELOG.md)：阶段变更记录。

## 来源与许可证

SOCKS5 子集按 [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928) 实现。上游内核的能力范围见 [MetaCubeX 官方 Meta 分支 README](https://raw.githubusercontent.com/MetaCubeX/mihomo/Meta/README.md) 与[官方配置文档](https://wiki.metacubex.one/en/config/)。本阶段未复制或移植上游实现代码；兼容性目标仅为后续逐项评估，不代表当前兼容。

上游 README 标注 GPL-3.0，并注明与 MetaCubeX 无关的下游项目名称不能包含 “mihomo”。本仓库名称为 `rust-mhm`。**本项目自身的许可证尚未由项目所有者选择；仓库当前没有 `LICENSE` 文件，也不应据此假设已有再分发授权。**

## 验证状态

本轮验证环境为 Linux x86_64：`cargo fmt --all -- --check`、`cargo check --workspace --all-targets`、`cargo test --workspace`（23 项通过）、`cargo clippy --workspace --all-targets -- -D warnings`（零警告）和 `cargo run -q -p rust-mhm -- --help` 均通过。

Windows、macOS、Android、Slint UI 和 Android VPN 集成尚未验证；本地通过不代表这些平台已构建或测试。
