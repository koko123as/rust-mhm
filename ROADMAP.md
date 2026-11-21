# Roadmap

此路线按可测试的垂直切片推进，不把占位实现计为完成。当前仍未达到 Mihomo 功能等价；每个已勾选项仅表示所列切片在当前验证范围内完成。

## Phase 0 — 仓库与工程基线

- [x] 创建 Rust workspace 与核心库/CLI 边界。
- [x] 选择并记录最小依赖；未知 YAML 字段拒绝处理。
- [x] Linux x86_64：格式检查、全目标编译、workspace 测试与零警告 Clippy 通过。
- [x] Linux x86_64：CLI 帮助命令通过。
- [ ] 建立 Linux/Windows/macOS CI；在目标平台实际跑过前不标记为已验证。

## Phase 1 — SOCKS5 到 DIRECT 的 TCP 切片

- [x] SOCKS5 无认证协商、CONNECT、IPv4/IPv6/域名目标解析。
- [x] DIRECT TCP 出站、超时、错误回复和双向转发。
- [x] 默认 loopback 监听、并发连接上限。
- [ ] 补充畸形帧、慢速客户端/超时、并发压力和取消回归测试。

## Phase 2 — 受限配置与确定性路由

- [x] 严格加载本项目 YAML；未知字段、规则类型和无效动作显式报错。
- [x] 有序路由规则子集：`DOMAIN`、`DOMAIN-SUFFIX`、`IP-CIDR`/`IP-CIDR6`、`DST-PORT`、`MATCH`；首个命中优先。
- [x] 支持 `DIRECT`、`REJECT` 与已配置具名代理动作；拒绝动作在拨号前完成。
- [x] 覆盖域名边界、IPv4/IPv6 CIDR、端口区间、规则顺序和拒绝路径。
- [ ] 与更广泛 Mihomo 规则/配置语料逐项差异测试；当前规则子集不等于完整兼容。
- [ ] 设计 rule-provider 文件/HTTP 加载、内容格式、缓存及更新策略；`RULE-SET` 尚不支持。

## Phase 3 — TCP 出站与策略组

- [x] HTTP CONNECT 出站，支持可选 Basic 认证；本地假代理端到端验证隧道和转发。
- [x] SOCKS5 TCP CONNECT 出站，支持无认证或用户名/密码认证；本地假代理端到端验证。
- [ ] 扩展真实 Mihomo 代理类型及协议互操作测试；当前代理 schema 是严格子集。
- [ ] 评估手动选择、故障转移等策略组；对外暴露前必须有真实端到端测试。
- [ ] 重试、健康检查和多级代理尚未实现。

## Phase 4 — DNS、UDP 与控制接口

- [ ] 单独设计 DNS 解析策略、缓存和与 IP 规则的交互边界。
- [ ] UDP、DNS、连接监控和控制 API 各自拆阶段；未实现前明确显示不支持。

## Phase 5 — 平台数据面与产品集成

- [ ] 评估 TUN、透明代理与平台权限/资源生命周期。
- [ ] Windows、Linux、Android 逐个平台验证；Android UI/VpnService 需独立技术可行性阶段。
- [ ] 仅在真实设备、网络和长时测试通过后报告对应能力。
