# Changelog

## Unreleased

- 新增按顺序首匹配的 `DOMAIN`、`DOMAIN-SUFFIX`、`IP-CIDR`/`IP-CIDR6`、`DST-PORT` 和 `MATCH` 规则子集。
- 支持 `DIRECT` 与 `REJECT` 动作；拒绝规则通过 SOCKS5 REP `0x02` 回复并在拨号前结束。
- 配置缺少 `MATCH` 时按本项目约定追加 `MATCH,DIRECT`；未知规则和动作显式报错。
- 新增兼容性决策说明，并将 Linux x86_64 自动化覆盖扩展到 23 项测试。
- `RULE-SET`/rule providers、DNS 规则解析、其他出站、UDP、TUN 与平台集成仍未实现。

## 0.1.0 — 初始原型

- 建立 Rust workspace、核心库与 CLI。
- 实现受限 YAML 配置和 loopback SOCKS5 无认证 TCP CONNECT 到 DIRECT 的基本数据路径。
- 加入本地回环协议测试与阶段/限制文档。
- 尚不支持完整 Mihomo 配置、代理组、UDP、DNS 策略、代理协议出站、TUN 或 UI。
