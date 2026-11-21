# Roadmap

此路线按可测试的垂直切片推进，不把占位实现计为完成。当前是早期原型，尚未达到 Mihomo 功能等价；每个已勾选项仅表示所列切片在当前验证范围内完成。

## Phase 0 — 仓库与工程基线

- [x] 创建 Rust workspace 与核心库/CLI 边界。
- [x] 选择并记录最小依赖；未知 YAML 字段拒绝处理。
- [x] Linux x86_64：`cargo fmt --all -- --check` 通过。
- [x] Linux x86_64：`cargo check --workspace --all-targets` 通过。
- [x] Linux x86_64：`cargo test --workspace` 通过（本轮 23 项）。
- [x] Linux x86_64：`cargo clippy --workspace --all-targets -- -D warnings` 通过（零警告）。
- [x] Linux x86_64：`cargo run -q -p rust-mhm -- --help` 通过。
- [ ] 建立 Linux/Windows/macOS CI；在目标平台实际跑过前不标记为已验证。

## Phase 1 — SOCKS5 到 DIRECT 的 TCP 切片

- [x] SOCKS5 无认证协商、CONNECT、IPv4/IPv6/域名目标解析。
- [x] DIRECT TCP 出站、超时、错误回复和双向转发。
- [x] 默认 loopback 监听、并发连接上限。
- [ ] 补充畸形帧、慢速客户端/超时、并发压力和取消回归测试。

## Phase 2 — 受限配置与确定性路由（有限子集已验收，兼容性扩展未完成）

- [x] 严格加载项目自有最小 YAML；未知顶层字段、规则类型和动作均报错。
- [x] 有序纯规则引擎：`DOMAIN`、`DOMAIN-SUFFIX`、`IP-CIDR`/`IP-CIDR6`、`DST-PORT`、`MATCH`；首个命中优先。
- [x] 仅支持 `DIRECT` 与 `REJECT`；`REJECT` 返回 SOCKS5 connection-not-allowed 回复，不拨号。
- [x] 覆盖域名标签边界、IPv4/IPv6 CIDR、端口区间、规则顺序和拒绝路径。
- [ ] 与更广泛的 Mihomo 规则/配置语料逐项差异测试；当前规则子集不等于完整兼容。
- [ ] 设计 rule-provider 文件/HTTP 加载、内容格式、缓存及更新策略；`RULE-SET` 尚不支持。

## Phase 3 — 出站与策略组

- [ ] 先实现并测试 HTTP CONNECT、SOCKS 出站等有限协议。
- [ ] 再评估手动选择、故障转移等策略组；对外暴露能力前必须有真实端到端测试。

## Phase 4 — DNS、UDP 与控制接口

- [ ] 单独设计 DNS 解析策略、缓存和与 IP 规则的交互边界。
- [ ] UDP、DNS、连接监控和控制 API 各自拆阶段；未实现前明确显示不支持。

## Phase 5 — 平台数据面与产品集成

- [ ] 评估 TUN、透明代理与平台权限/资源生命周期。
- [ ] Windows、Linux、Android 逐个平台验证；Android UI/VpnService 需独立技术可行性阶段。
- [ ] 仅在真实设备、网络和长时测试通过后报告对应能力。
