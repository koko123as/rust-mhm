# Testing

## 本地命令

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo test --workspace
```

## 当前自动化覆盖

- 配置默认值、loopback 安全校验、未知字段和范围校验。
- SOCKS5 无认证协商与 TCP CONNECT 端到端本地回环。
- 拒绝未实现的 SOCKS5 命令。

所有网络测试使用本地 loopback，不依赖外网服务。

## 未覆盖/未验证

- 当前尚未覆盖所有畸形/截断 SOCKS5 帧、长时间并发、连接取消、DNS 行为和跨平台差异。
- Linux x86_64 是当前实际构建目标；Windows、macOS、Android 与移动设备未验证。
- 没有基于 Mihomo 配置语料的兼容性测试；当前配置格式是独立的最小 YAML。
