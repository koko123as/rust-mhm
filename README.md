# rust-mhm

一个以 Rust 逐步实现代理内核能力的独立项目。当前仓库处于早期原型阶段，**不是 Mihomo 的完整替代品，也不声称兼容其完整配置或功能**。

## 当前实现

- SOCKS5 无认证 TCP `CONNECT` 入站；支持 IPv4、IPv6 和域名目标。
- 仅有 `DIRECT` TCP 出站，使用 Tokio 双向转发。
- 默认监听 `127.0.0.1:1080`；配置校验拒绝非 loopback 监听，避免意外暴露开放代理。
- YAML 使用本项目的严格最小配置格式；未知字段会报错，不会被静默忽略。
- 有界并发连接数和出站连接超时。
- 单元/集成测试覆盖配置校验、SOCKS5 握手、拒绝不支持命令和本地 TCP 转发。

不支持 UDP、SOCKS5 认证、HTTP 入站、代理协议出站、代理组、路由规则、DNS 配置、TUN、订阅、REST API、UI 或 Android 服务。后续按阶段实现，任何尚未完成的能力都会明确标记。

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
```

配置字段全部可选。运行时可通过 `RUST_LOG=info` 设置日志级别。当前监听只允许 loopback IP；LAN/TUN 等网络暴露方式尚未实现。

## 架构与阶段

- [ARCHITECTURE.md](ARCHITECTURE.md)：当前数据路径与边界。
- [ROADMAP.md](ROADMAP.md)：分阶段目标、未实现能力与验收项。
- [DEVELOPMENT.md](DEVELOPMENT.md)：依赖、工具链和本地开发说明。
- [TESTING.md](TESTING.md)：测试范围与命令。
- [PERFORMANCE.md](PERFORMANCE.md)：性能测量状态。
- [CHANGELOG.md](CHANGELOG.md)：阶段变更记录。

## 来源与兼容性说明

SOCKS5 子集按 [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928) 实现。上游内核的能力范围见 [MetaCubeX 官方 Meta 分支 README](https://raw.githubusercontent.com/MetaCubeX/mihomo/Meta/README.md) 与[官方配置文档](https://wiki.metacubex.one/en/config/)。本阶段未复制或移植上游实现代码；兼容性目标仅为后续逐项评估，不代表当前兼容。

上游 README 标注 GPL-3.0，并注明与 MetaCubeX 无关的下游项目名称不能包含 “mihomo”。本仓库名称为 `rust-mhm`。**本项目自身的许可证尚未由项目所有者选择；仓库当前没有 `LICENSE` 文件，也不应据此假设已有再分发授权。**

## 验证状态

当前开发环境为 Linux x86_64。本地 Rust 编译与测试将在本轮执行；Windows、macOS、Android、Slint UI 和 Android VPN 集成尚未验证。
