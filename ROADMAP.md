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
- [x] 严格配置支持有限 `select` 组子集：代理/组前向及嵌套引用、`DIRECT`/`REJECT`、成员与名称校验、引用环路检测；`default-selected` 无效或缺省时回退首成员，组名可用于规则及 `RULE-SET` 动作。
- [x] 核心库的 `RuleSet` 保留可变进程内选择状态，并提供手动选择/读取成员方法；嵌套组及 `RULE-SET` 组动作按当前选择解析。克隆共享状态，独立构建的 `RuleSet` 隔离。
- [x] 可选 loopback 组控制 API：Bearer 密钥保护，支持列出组状态和选择成员；请求体、并发和 handler 时限有界。规则 provider 刷新时保留仍然有效的手动选择；若组/成员消失则使用新默认值。
- [x] 可选 `proxy-group-state-file` 本地状态文件：启动只恢复当前配置中仍存在的组及成员，缺失/损坏/过期状态安全回退；API 切换先原子写盘再更新运行状态，写入失败明确报错。
- [x] 有限 `fallback` 组：TCP CONNECT 建立失败后按序尝试候选、成功即停止、`REJECT` 终止、嵌套 fallback 展平；候选共享一个 `connect_timeout_ms` 总时限；UDP 数据报明确丢弃。端到端覆盖首候选失败/成功、候选全失败、REJECT、嵌套 select 状态变化与总时限。
- [x] 有限 `load-balance` round-robin：只接受缺省策略或 `strategy: round-robin`，每次路由决策轮换一个有序成员；线程安全游标在组类型及有序成员不变时跨 provider 刷新保留。TCP 当前请求失败不重试其他成员，UDP 每个数据报单独路由；控制 API 不把它当作可手动选择组。
- [ ] 主动健康探测及周期状态切换、`url-test`、一致性哈希/粘性 load-balance 策略、失败后重试与组过滤器；当前 fallback 只检查单次 TCP CONNECT 建连结果，不是完整 Mihomo 语义。控制 API 仍仅为有限手动 `select` 子集，不代表完整 Mihomo API。
- [ ] 扩展真实 Mihomo 代理类型及协议互操作测试；当前代理 schema 是严格子集。
- [ ] 重试与多级代理尚未实现。

## Phase 4 — DNS、UDP 与控制接口

- [x] TCP 域名 `IP-CIDR` 路由垂直切片：按有序规则需要时调用一次系统解析，限制 16 个去重答案并复用 DIRECT 地址；实现 `no-resolve`、失败关闭与 SOCKS 端到端覆盖。此项不含 DNS 策略、缓存或 hosts/fake-IP。
- [ ] 单独设计通用 DNS 解析策略、缓存和与其余 IP 规则/代理行为的交互边界。
- [x] SOCKS5 入站 `UDP ASSOCIATE` 的有限切片：控制 TCP 生命周期、loopback relay、IPv4/IPv6/域名目标、逐数据报规则判定与 DIRECT UDP 往返；只接收控制 peer 的来源 IP，固定客户端 UDP 端点；非 DIRECT、畸形与分片数据报均丢弃。
- [x] 有限 SOCKS5 UDP 代理出站：按数据报策略选择具名 SOCKS5 上游，持有 UDP ASSOCIATE TCP 控制连接，目标域名交给代理解析；队列有界，失败不回退 DIRECT。
- [ ] HTTP 代理 UDP、UDP 分片、完整 Mihomo UDP 入站配置及与 DNS 策略的交互。
- [ ] DNS 策略与连接监控接口另行拆阶段；当前的 loopback 组控制 API 不包含完整运行时监控或通用管理 API。

## Phase 5 — 平台数据面与产品集成

- [ ] 评估 TUN、透明代理与平台权限/资源生命周期。
- [ ] Windows、Linux、Android 逐个平台验证；Android UI/VpnService 需独立技术可行性阶段。
- [ ] 仅在真实设备、网络和长时测试通过后报告对应能力。
