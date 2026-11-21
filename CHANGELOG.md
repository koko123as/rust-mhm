# Changelog

## Unreleased

- Windows HTTP provider 缓存替换改用 `MoveFileExW` 的替换标志，确保刷新可覆盖已有快照；缓存冲突路径比较适配 Windows 大小写不敏感语义，并增加跨平台覆盖测试及 Windows 条件测试。
- 文档明确缓存持久化失败时仍采用已验证的新运行时规则，但重启离线时可能回退到旧快照。
- HTTP rule-provider 增加持久缓存（支持显式路径和安全的默认路径）、启动离线回退、自定义请求头和按秒刷新；新规则验证成功后原子切换共享路由表，刷新失败保留旧表，下一次间隔从上一轮完成后开始计算，关闭服务时取消后台任务。
- 带自定义请求头的 provider 禁止 HTTP 重定向，避免认证头泄露；缓存写入采用临时文件与 rename，拒绝缓存覆盖配置文件或与其他 HTTP provider 共用路径。
- 新增 HTTP provider 默认/显式缓存、离线回退、单值/多值请求头、带自定义头时拒绝重定向、缓存路径隔离、无效刷新保留旧快照及慢响应刷新周期的本地测试。
- 支持在启动时载入本地 `file` rule-provider：相对配置目录解析路径，4 MiB 上限，支持 YAML payload 或逐行文本，以及有限的 `classical`/`domain`/`ipcidr` 行为。
- 支持通过 `Config::load_async` 在启动时下载 HTTP/HTTPS rule-provider 快照；校验成功状态，最多跟随 5 次重定向，单响应 4 MiB 上限并受 `connect_timeout_ms` 超时约束；CLI 已切换异步配置加载。
- 增加 HTTP provider 重定向、超时、404、声明长度超限和 chunked 流式超限的本地回环测试。
- 修复拒绝非 `CONNECT` 请求时先读取完整地址/端口帧，避免 Windows 关闭含未读请求数据的 socket 时以 RST 丢弃 SOCKS5 错误回复。
- Linux、Windows、macOS 的 CI 全量任务和 Rust 1.85 锁文件测试已在提交 `37d11d4` 通过；Android 尚未纳入验证。
- 增加 SOCKS5 greeting/RFC 1929/CONNECT 畸形与截断帧矩阵、连接上限并发及已协商会话取消测试；长期并发负载仍未覆盖。
- 更新兼容性台账、路线图、测试、架构与开发依赖文档；MRS/自定义格式、完整上游 provider 生命周期和配置文件热重载仍未实现。
- 增加严格配置的具名 `http` 与 `socks5` TCP 代理出站；支持可选用户名/密码认证。
- 规则动作可选择配置中的代理名称；重复定义、缺失引用和保留动作名称会被拒绝。
- HTTP CONNECT 与 SOCKS5 出站握手纳入连接超时；添加基于本地假代理的认证、隧道及双向转发端到端测试。
- 更新架构、兼容性台账和路线图，明确这是受限出站切片，不是完整 Mihomo 配置或功能兼容。
- 增加全局 `authentication` 与 IPv4/IPv6 `skip-auth-prefixes` 支持；按 RFC 1929 认证并在失败时关闭连接，匹配豁免来源时允许无认证。
- 路由规则新增有限 `DOMAIN-KEYWORD` 支持：在规范化后的 ASCII 域名中执行大小写不敏感的子串匹配。
- 路由规则新增有限 `DOMAIN-WILDCARD` 支持：仅支持 `*` 和 `?` 两种通配符。
- 路由规则新增有限 `SRC-IP-CIDR` 与 `SRC-PORT` 支持：按入站 TCP peer 地址和来源端口匹配。
- 路由规则新增有限 `DOMAIN-REGEX` 支持：规则加载时编译 Rust `regex` 表达式，对规范化域名执行匹配，拒绝无效或超过 4096 字节的表达式。
- 增加有限 inline classical `RULE-SET` 支持：在引用位置展开 payload 并由引用动作统一覆盖；此后已加入有限 file 与 HTTP/HTTPS 启动快照加载。
- 完整 Mihomo rule-provider 生命周期/内容格式、代理组、UDP、DNS 策略、TUN 与平台集成仍未实现；当前 `RULE-SET` 仍只支持本项目有限内容格式与规则子集。

## 0.1.0 — 初始原型

- 建立 Rust workspace、核心库与 CLI。
- 实现受限 YAML 配置和 loopback SOCKS5 无认证 TCP CONNECT 到 DIRECT 的基本数据路径。
- 加入本地回环协议测试与阶段/限制文档。
- 尚不支持完整 Mihomo 配置、代理组、UDP、DNS 策略、TUN 或 UI。
