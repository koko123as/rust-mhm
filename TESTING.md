# Testing

## 本地命令

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo run -q -p rust-mhm -- --help
```

## 当前自动化覆盖

- 配置默认值、loopback 安全校验、未知字段、资源范围及规则配置错误；仓库示例 YAML 会作为回归测试解析。
- `DOMAIN` 精确匹配与大小写归一化；`DOMAIN-SUFFIX` 标签边界、根域和子域。
- IPv4/IPv6 CIDR 前缀与地址族隔离；目的端口单值和闭区间匹配。
- 首匹配优先、隐式 `MATCH,DIRECT`、无效/不支持的规则拒绝。
- SOCKS5 无认证协商、IPv4/IPv6/域名目标解析、不支持命令/认证的拒绝、规则拒绝回复及本地 TCP 回环转发。

所有网络测试使用本地 loopback，不依赖外网服务。当前 Linux x86_64 `cargo test --workspace` 共 23 项测试通过；格式检查、全目标编译、零警告 Clippy 和 CLI 帮助检查也通过。

## 未覆盖/未验证

- 尚未覆盖全部畸形/截断 SOCKS5 帧、慢速客户端/完整超时行为、长时间并发压力、连接取消边界、DNS 策略或端到端真实网络故障。
- 没有基于 Mihomo 配置语料的兼容性测试；不支持 `RULE-SET`、代理组或其他未列明规则类型。
- Linux x86_64 是当前实际构建目标；Windows、macOS、Android 与移动设备未验证。
- 尚无性能基准、负载/长稳测试或外部网络验证。
