# Changelog

## Unreleased

- 增加严格配置的具名 `http` 与 `socks5` TCP 代理出站；支持可选用户名/密码认证。
- 规则动作可选择配置中的代理名称；重复定义、缺失引用和保留动作名称会被拒绝。
- HTTP CONNECT 与 SOCKS5 出站握手纳入连接超时；添加基于本地假代理的认证、隧道及双向转发端到端测试。
- 更新架构、兼容性台账和路线图，明确这是受限出站切片，不是完整 Mihomo 配置或功能兼容。
- 增加全局 `authentication` 与 IPv4/IPv6 `skip-auth-prefixes` 支持；按 RFC 1929 认证并在失败时关闭连接，匹配豁免来源时允许无认证。
- 路由规则新增有限 `DOMAIN-KEYWORD` 支持：在规范化后的 ASCII 域名中执行大小写不敏感的子串匹配。
- 路由规则新增有限 `DOMAIN-WILDCARD` 支持：仅支持 `*` 和 `?` 两种通配符。
- `RULE-SET`、代理组、UDP、DNS 策略、TUN 与平台集成仍未实现。

## 0.1.0 — 初始原型

- 建立 Rust workspace、核心库与 CLI。
- 实现受限 YAML 配置和 loopback SOCKS5 无认证 TCP CONNECT 到 DIRECT 的基本数据路径。
- 加入本地回环协议测试与阶段/限制文档。
- 尚不支持完整 Mihomo 配置、代理组、UDP、DNS 策略、TUN 或 UI。
