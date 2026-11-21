# Roadmap

此路线按可测试的垂直切片推进，不把占位实现计为完成。当前仍未达到 Mihomo 功能等价；每个已勾选项仅表示所列切片在当前验证范围内完成。

## Phase 0 — 仓库与工程基线

- [x] 创建 Rust workspace 与核心库/CLI 边界。
- [x] 选择并记录最小依赖；未知 YAML 字段拒绝处理。
- [x] Linux x86_64：格式检查、全目标编译、workspace 测试与零警告 Clippy 通过；Rust 1.85.0 锁定依赖 workspace 测试通过。
- [x] Linux x86_64：CLI 帮助命令通过。
- [x] Linux/Windows/macOS GitHub Actions 与 Rust 1.85 锁文件测试门禁已通过（提交 `37d11d4`）；Android 与真实设备网络仍未验证。

## Phase 1 — SOCKS5 到 DIRECT 的 TCP 切片

- [x] SOCKS5 无认证协商或按配置强制 RFC 1929 用户名/密码协商；支持 `skip-auth-prefixes` CIDR 豁免、CONNECT 与 IPv4/IPv6/域名目标解析。
- [x] DIRECT TCP 出站、超时、错误回复和双向转发。
- [x] 默认 loopback 监听、并发连接上限。
- [x] 补充截断 CONNECT 帧断连与慢速握手超时回归测试。
- [x] 补充 SOCKS5 greeting/RFC 1929/CONNECT 畸形帧与 IPv4/IPv6/域名 CONNECT 全截断前缀矩阵、连接上限并发压力和已协商会话取消回归测试；长时压力测试仍未覆盖。

## Phase 2 — 受限配置与确定性路由

- [x] 严格加载本项目 YAML；未知字段、规则类型和无效动作显式报错。
- [x] 有序路由规则子集：`DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`DOMAIN-WILDCARD`、有限的 `DOMAIN-REGEX`、`IP-CIDR`/`IP-CIDR6`、`SRC-IP-CIDR`、`SRC-PORT`、`DST-PORT`、`MATCH`；首个命中优先。
- [x] 支持 `DIRECT`、`REJECT` 与已配置具名代理动作；拒绝动作在拨号前完成。
- [x] 覆盖域名边界与正则、IPv4/IPv6 目标及来源 CIDR、端口区间、规则顺序和拒绝路径。
- [x] 有限 inline classical `RULE-SET`：规则按引用位置展开，引用动作覆盖 payload 规则动作。
- [ ] 与更广泛 Mihomo 规则/配置语料逐项差异测试；当前规则子集不等于完整兼容。
- [x] 支持启动时载入 `file` rule-provider（classical/domain/ipcidr 有限行为），相对配置路径、4 MiB 上限和 YAML payload/逐行文本解析。
- [x] 支持启动时下载 HTTP/HTTPS rule-provider 快照：异步配置加载、最多 5 次重定向、`connect_timeout_ms` 超时、4 MiB 上限、成功状态检查与有限文本/YAML 解析；测试使用本地假 HTTP 服务。
- [x] HTTP provider 持久原文缓存、离线时回退到有效快照、请求头，以及 HTTP/file provider 按 `interval` 定时刷新；候选内容和整套路由校验成功后才原子替换运行中的路由表，刷新失败保留旧路由，服务退出时取消刷新任务。
- [ ] MRS/自定义格式、上游完整缓存校验器与 provider 生命周期兼容；当前只有受限 YAML payload/逐行文本解析，也没有整个配置文件热重载。

## Phase 3 — TCP 出站与策略组

- [x] HTTP CONNECT 出站，支持可选 Basic 认证；本地假代理端到端验证隧道和转发。
- [x] SOCKS5 TCP CONNECT 出站，支持无认证或用户名/密码认证；本地假代理端到端验证。
- [ ] 扩展真实 Mihomo 代理类型及协议互操作测试；当前代理 schema 是严格子集。
- [ ] 评估手动选择、故障转移等策略组；对外暴露前必须有真实端到端测试。
- [ ] 重试、健康检查和多级代理尚未实现。

## Phase 4 — DNS、UDP 与控制接口

- [ ] 单独设计 DNS 解析策略、缓存和与 IP 规则的交互边界。
- [x] SOCKS5 入站 `UDP ASSOCIATE` 的有限切片：控制 TCP 生命周期、loopback relay、IPv4/IPv6/域名目标、逐数据报规则判定与 DIRECT UDP 往返；只接收控制 peer 的来源 IP，固定客户端 UDP 端点；非 DIRECT、畸形与分片数据报均丢弃。
- [ ] SOCKS5/HTTP 代理 UDP 出站、UDP 分片、完整 Mihomo UDP 入站配置及与 DNS 策略的交互。
- [ ] DNS、连接监控和控制 API 各自拆阶段；未实现前明确显示不支持。

## Phase 5 — 平台数据面与产品集成

- [ ] 评估 TUN、透明代理与平台权限/资源生命周期。
- [ ] Windows、Linux、Android 逐个平台验证；Android UI/VpnService 需独立技术可行性阶段。
- [ ] 仅在真实设备、网络和长时测试通过后报告对应能力。
