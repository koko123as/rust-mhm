# Development

## 环境

- Rust 1.85+ / Cargo；本仓库采用 Rust 2024 edition。
- 本地验证环境为 Linux x86_64；GitHub Actions 的 Linux、Windows、macOS 稳定版任务与 Rust 1.85 MSRV 测试均已通过。Android/移动设备尚未验证。

## 依赖

| Crate | 用途 | 当前版本 | 许可证/取舍 |
|---|---|---:|---|
| Tokio | TCP listener/stream、异步 I/O、运行时、信号与超时 | 1.54.1 | MIT；只启用本切片需要的 features，不启用 `full`。运行时带来基础调度开销，后续需测量。 |
| Serde | 配置反序列化和严格字段检查 | 1.0.229 | MIT OR Apache-2.0；只作配置模型，不进入数据面。 |
| yaml_serde | YAML 解码 | 0.10.7 | MIT OR Apache-2.0；采用 YAML 组织维护的实现，避免依赖已停止维护的 `serde_yaml`。 |
| thiserror | 结构化配置/服务错误 | 2.0.21 | MIT OR Apache-2.0；仅派生错误类型。 |
| regex | `DOMAIN-REGEX` 规则解析时编译及运行时匹配 | 1.13.2 | MIT OR Apache-2.0；只用于路由规则，不参与转发数据面。 |
| reqwest | 异步 HTTP/HTTPS rule-provider 启动下载 | 0.12.28（Cargo.lock） | MIT OR Apache-2.0；关闭默认特性，只启用 rustls TLS 与流式响应；仅配置加载阶段使用，响应限制 4 MiB。锁定依赖和 workspace 全套测试已在 Rust 1.85.0 下通过。 |
| tracing | 结构化日志事件 | 0.1.44 | MIT；CLI 记录生命周期，不记录代理目标域名。 |
| tracing-subscriber | CLI 日志格式化与 `RUST_LOG` 过滤 | 0.3.23 | MIT；只在 CLI 层使用。 |

版本和许可证元数据在创建时通过 crates.io `cargo info` 核验，`Cargo.lock` 是构建解析后的实际版本记录。锁文件将 URL/IDNA 依赖固定在 Rust 1.85 可编译的版本，并由 CI 的 Rust 1.85 `--locked` 测试任务防止无意抬高最低工具链。reqwest 增加了 TLS 与 HTTP 客户端依赖，且会扩大锁文件与构建图；新增依赖前应说明必要性、运行时/体积影响、平台支持和许可证。

## 命令

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo test --workspace
```
