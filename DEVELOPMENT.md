# Development

## 环境

- Rust 1.85+ / Cargo；本仓库采用 Rust 2024 edition。
- 本轮验证环境为 Linux x86_64。Windows、macOS、Android 尚未在此环境验证。

## 依赖

| Crate | 用途 | 当前版本 | 许可证/取舍 |
|---|---|---:|---|
| Tokio | TCP listener/stream、异步 I/O、运行时、信号与超时 | 1.54.1 | MIT；只启用本切片需要的 features，不启用 `full`。运行时带来基础调度开销，后续需测量。 |
| Serde | 配置反序列化和严格字段检查 | 1.0.229 | MIT OR Apache-2.0；只作配置模型，不进入数据面。 |
| yaml_serde | YAML 解码 | 0.10.7 | MIT OR Apache-2.0；采用 YAML 组织维护的实现，避免依赖已停止维护的 `serde_yaml`。 |
| thiserror | 结构化配置/服务错误 | 2.0.21 | MIT OR Apache-2.0；仅派生错误类型。 |
| regex | `DOMAIN-REGEX` 规则解析时编译及运行时匹配 | 1.13.2 | MIT OR Apache-2.0；只用于路由规则，不参与转发数据面。 |
| tracing | 结构化日志事件 | 0.1.44 | MIT；CLI 记录生命周期，不记录代理目标域名。 |
| tracing-subscriber | CLI 日志格式化与 `RUST_LOG` 过滤 | 0.3.23 | MIT；只在 CLI 层使用。 |

版本和许可证元数据在创建时通过 crates.io `cargo info` 核验，`Cargo.lock` 是构建解析后的实际版本记录。除上表外，当前没有数据库、Slint、Android、HTTP client 或 SOCKS 协议框架依赖。新增依赖前应说明必要性、运行时/体积影响、平台支持和许可证。

## 命令

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo test --workspace
```
