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

配置测试覆盖默认值、loopback 安全校验、未知字段、资源范围、全局认证与 IPv4/IPv6 `skip-auth-prefixes` 字段校验、代理类型/定义、inline classical rule provider、重复名称、规则配置错误，以及仓库示例 YAML。路由测试覆盖 `DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD` 子串匹配、`DOMAIN-WILDCARD` 的 `*`/`?`、`DOMAIN-REGEX`（域名规范化、逗号量词和无效表达式）、`RULE-SET` 的顺序展开和动作覆盖、IPv4/IPv6 目标和来源 CIDR、来源/目标端口单值与闭区间、首匹配优先、隐式 `MATCH,DIRECT` 与不支持规则拒绝。

协议测试覆盖 SOCKS5 入站协商、RFC 1929 入站认证成功/失败、CIDR 命中后的认证绕过、不支持命令/认证拒绝、IPv4/IPv6/域名目标解析、基于 loopback peer IP/端口的 `SRC-IP-CIDR` 与 `SRC-PORT` 拒绝回复和本地 TCP 转发。出站集成测试使用本地假 HTTP CONNECT 与 SOCKS5 服务，覆盖代理用户名/密码认证、域名请求和隧道双向 TCP 转发。所有网络测试只使用 loopback，不依赖外网服务。

## 未覆盖/未验证

尚未覆盖全部畸形/截断 SOCKS5 帧、慢速客户端/完整超时行为、长时间并发压力、连接取消边界、DNS 策略或真实网络故障。没有基于 Mihomo 配置语料的兼容性测试；`RULE-SET` 只支持 inline classical 子集，不支持文件/HTTP provider、自动更新或代理组。

当前 Linux x86_64 实际构建目标；Windows、macOS、Android 与移动设备未验证。尚无性能基准、负载/长稳测试或真实第三方代理互操作测试。
