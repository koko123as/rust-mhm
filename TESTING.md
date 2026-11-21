# Testing

## 本地命令

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo run -q -p rust-mhm -- --help
cargo +1.85.0 test --workspace --locked
```

## 当前自动化覆盖

配置测试覆盖默认值、loopback 安全校验、未知字段、资源范围、全局认证与 IPv4/IPv6 `skip-auth-prefixes` 字段校验、代理类型/定义、inline/file/HTTP provider、相对路径、YAML payload/纯文本载荷、domain/ipcidr 行为映射、缺失/超限本地文件、file/HTTP 刷新间隔边界、HTTP 404、超时、普通重定向和带自定义请求头时拒绝重定向、声明长度和 chunked 流式超限的具体拒绝原因、持久缓存、已有缓存文件原子替换、有效缓存离线回退、显式路径、多个 provider 共用缓存路径拒绝（Windows 额外检查大小写不同的别名）、官方单数 `header` 的单值和多值请求、旧复数键拒绝、刷新参数校验及异步加载要求。定时刷新端到端测试确认运行中的路由表和 HTTP 缓存快照均会更新；file provider 测试覆盖有效替换后切换路由，以及畸形规则、超限和暂时删除时保留上一份活动规则。无效 HTTP 刷新保留活动路由与旧缓存，慢响应不会因上一轮请求耗时而立即再次请求。路由测试覆盖 `DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD` 子串匹配、`DOMAIN-WILDCARD` 的 `*`/`?`、`DOMAIN-REGEX`（域名规范化、逗号量词和无效表达式）、`RULE-SET` 的顺序展开和动作覆盖、字面 IPv4/IPv6 与来源 CIDR、TCP 域名 CIDR 的解析触发顺序、`no-resolve`、多答案地址族命中、答案上限、首匹配优先、来源/目标端口单值与闭区间、隐式 `MATCH,DIRECT` 与不支持规则拒绝。

代理组测试覆盖严格 `select` 字段、组名/代理名冲突、保留名称、空组、未知与重复成员、未知类型、嵌套及前向引用、有效显式默认成员、缺省/无效 `default-selected` 回退首成员、`DIRECT`/`REJECT` 成员、规则动作、`RULE-SET` 动作，以及自环和多组环路拒绝。进程内手动选择测试覆盖默认状态、嵌套成员变化、直接/拒绝动作、未知组和非成员错误不改变原状态、克隆共享与独立 `RuleSet` 隔离、RULE-SET 动作实时读取当前选择。状态文件测试覆盖相对路径、默认关闭、合法状态重启恢复、损坏/过期组与成员/未知版本/超限快照回退、配置/provider 路径冲突拒绝、同一 `RuleSet` 并发更新后磁盘快照完整且与内存状态一致。provider 刷新回归还检查在刷新替换窗口内通过旧 `RuleSet` 句柄发起的选择仍影响新规则。所有组成员边均参与环路检查。控制 API 测试覆盖 Bearer 认证、组列表/详情/切换、未知组与非法成员、未知 JSON 字段及 4 KiB 请求体上限；端到端测试验证 API 切换立即改变路由、写盘失败不改变运行状态、无效/未授权请求不写入状态文件、重启恢复，以及 provider 刷新后选择仍有效并可再次恢复。

load-balance 配置测试覆盖缺省/显式 `round-robin`、严格拒绝一致性哈希、粘性会话、`url`/`interval`、`default-selected` 和非 load-balance 组上的策略字段。路由测试验证轮换顺序、克隆共享游标、独立 `RuleSet` 隔离、嵌套 select 当前状态解析，以及 8 个并发线程各 1000 次调用时两个成员各获 4000 次；provider 刷新只在组类型和有序成员未变时继承游标，成员顺序变化时重置。控制 API 确认 load-balance 不列出且不能手动切换。TCP 端到端测试用首节点 HTTP 502 验证当前请求不重试第二成员、下一次 CONNECT 才轮到第二成员；UDP 测试验证每个数据报轮换且 `REJECT` 槽位不会泄漏为直连。

URL-Test 测试覆盖严格配置（HTTP(S) URL、凭据/片段拒绝、必填秒级 interval 与边界、tolerance 缺省 0/最大 u16 毫秒值/超限拒绝、未实现字段及组成员拒绝）、独立于手动 select 的运行态与 provider 刷新继承（包含已成功探测标记）、首轮选最快、当前成员在 tolerance 边界内保留、超出边界或当前失败时切换最快成功成员、全员失败不改变上次选择、HTTP/SOCKS5 代理探测（含 SOCKS5 认证）及服务关闭时取消任务。探测集成测试使用 loopback 假服务，不依赖公网。

协议测试覆盖 SOCKS5 greeting 畸形输入、RFC 1929 入站认证成功/失败及子协商畸形/截断帧、CIDR 命中后的认证绕过、不支持命令/认证拒绝、IPv4/IPv6/域名 CONNECT 的所有截断前缀、非法请求字段、慢速 greeting 超时、已协商会话取消关闭、并发客户端下的连接上限、目标解析、基于 loopback peer IP/端口的 `SRC-IP-CIDR` 与 `SRC-PORT` 拒绝回复和本地 TCP 转发。TCP 域名 CIDR 另测试解析器按需单次调用、DNS 错误/空结果/答案超限/超时失败关闭，以及本地 `localhost` 的 DIRECT 地址复用、REJECT 不拨号和具名 HTTP 代理仍收到原始域名。新增 UDP 测试覆盖 `UDP ASSOCIATE` 请求及 IPv4/IPv6/域名 UDP 帧、非法 RSV/ATYP/FRAG 丢弃、loopback DIRECT UDP echo、客户端端口固定、TCP 控制关闭关联，以及 `REJECT`/HTTP 代理路由不误直连。SOCKS5 UDP 出站测试覆盖无认证与 RFC 1929 认证协商、上游 relay 地址解析、域名目标原样封装、经过本地假 relay 的请求/响应回送、控制关联保持至关闭，并验证 HTTP UDP 不回退 DIRECT。并发上限回归使用 20 个同时连接验证配置上限为 8 时只服务 8 个会话，不代表长时负载测试。TCP 出站集成测试使用本地假 HTTP CONNECT 与 SOCKS5 服务，覆盖代理用户名/密码认证、域名请求和隧道双向转发。所有网络测试只使用 loopback，不依赖外网服务。

## 未覆盖/未验证

fallback 配置测试覆盖 `default-selected` 拒绝、嵌套 fallback 展平、嵌套 select 解析及 fallback 不进入 select 快照；控制 API 测试确认 fallback 不可手动选择。TCP 假 HTTP CONNECT 代理覆盖首候选失败后次候选成功、首候选成功时不拨后续、全部失败、`REJECT` 终止、运行中的嵌套 select 变化影响后续请求，以及多个候选共享单个 `connect_timeout_ms` deadline。UDP fallback 测试确认组内即使包含 `DIRECT` 也会静默丢弃，不泄漏直连。load-balance 的相应测试证明行为仅为单成员轮换：失败不在同一 TCP 请求重试。URL-Test 只验证所列严格字段及有限 tolerance 子集；尚未做真实公网目标、真实 HTTPS 证书/TLS 失败场景或长时周期稳定性验证。fallback/load-balance 的主动健康探测、一致性哈希、粘性会话和真实 Mihomo 互操作也未覆盖。

尚未覆盖长时间并发压力、通用 DNS 策略/缓存或真实网络故障；TCP 域名 CIDR 仅使用受限系统解析器快照，未验证 DNS 策略、缓存、hosts、fake-IP 或完整 Mihomo 行为。HTTP provider 测试使用 loopback 假服务；file provider 使用临时本地文件；没有基于 Mihomo 配置语料的兼容性测试。file/HTTP provider 的缓存与刷新仅覆盖本项目受限 YAML/逐行文本格式，未验证 MRS、自定义格式、真实远端服务、完整 Mihomo 生命周期或整个配置文件热重载。控制 API 目前仅有 loopback 本地服务测试，未覆盖长时压力、真实 Mihomo 客户端互操作、TLS/WebSocket 或完整控制面；本地组状态文件不代表 Mihomo 持久化语义兼容。状态文件路径冲突测试覆盖配置文件、file provider 数据、HTTP provider 缓存和目录；尚未做断电/系统崩溃后的目录项耐久性测试。当前有限 fallback 仅覆盖本地 TCP CONNECT 建连失败后的顺序尝试，不包含主动探测、周期状态切换或完整 UDP 语义；load-balance 只实现 round-robin 的窄子集，未覆盖健康探测、哈希/粘性策略或失败重试。URL-Test 未覆盖的完整语义包括 `lazy`、`timeout`、状态暴露、失败阈值与其他 Mihomo 健康检查行为；实现 tolerance 也不代表完整 URL-Test 兼容。

本地实际构建环境为 Linux x86_64。提交 `d4bf016` 的 DIRECT-only UDP 阶段已通过格式、workspace 全目标检查、76 项测试、零警告 Clippy、CLI 帮助、Rust 1.85.0 锁定测试和 [Linux、Windows、macOS 与 Rust 1.85 CI](https://github.com/koko123as/rust-mhm/actions/runs/44947943108)。此前 SOCKS5 UDP 代理出站切片的 [Linux、Windows、macOS 与 Rust 1.85 CI](https://github.com/koko123as/rust-mhm/actions/runs/44948797643) 全项通过。上一阶段静态 `select` 组切片通过本地完整门禁（81 项 workspace 测试）与 [Linux、Windows、macOS、Rust 1.85 CI](https://github.com/koko123as/rust-mhm/actions/runs/44949696886)。本阶段进程内手动选择切片通过本地完整门禁（85 项 workspace 测试），并在[本阶段 CI](https://github.com/koko123as/rust-mhm/actions/runs/44950947867) 的 Ubuntu、Windows、macOS、Rust 1.85 四项任务中全部通过。Android 与移动设备未验证；尚无性能基准、负载/长稳测试或真实第三方代理互操作测试。

TCP 域名 CIDR 路由切片通过本地完整门禁（103 项测试；格式、workspace 全目标检查、零警告 Clippy、CLI 帮助与 Rust 1.85 锁定测试），并通过 [Linux、Windows、macOS 与 Rust 1.85 CI](https://github.com/koko123as/rust-mhm/actions/runs/44954299373)。

本地 `select` 状态持久化切片通过完整门禁（109 项 workspace 测试；格式、全目标检查、零警告 Clippy、CLI 帮助与 Rust 1.85 锁定测试），并通过 [Linux、Windows、macOS 与 Rust 1.85 CI](https://github.com/koko123as/rust-mhm/actions/runs/44956259709)。

有限 fallback 切片通过本地完整门禁（118 项 workspace 测试、格式、全目标检查、零警告 Clippy、CLI 帮助与 Rust 1.85 锁定测试）。全候选失败端到端用例使用两台 loopback HTTP 假代理明确返回 502，避免平台临时端口复用竞态；修复后 [Linux、Windows、macOS 与 Rust 1.85 CI](https://github.com/koko123as/rust-mhm/actions/runs/44958214245) 全项通过。

有限 load-balance round-robin 切片通过本地完整门禁（122 项 workspace 测试；格式、workspace 全目标检查、零警告 Clippy、CLI 帮助与 Rust 1.85 锁定测试）。最新工具链 CI 将 `AtomicUsize::fetch_update` 标为弃用后，游标改用 `compare_exchange_weak` 循环；提交 `628ece3` 对应的 [Linux、Windows、macOS 与 Rust 1.85 CI](https://github.com/koko123as/rust-mhm/actions/runs/44959469886) 四项任务全部通过。

有限 URL-Test 切片通过本地完整门禁（129 项 workspace 测试；格式、workspace 全目标检查、零警告 Clippy、CLI 帮助与 Rust 1.85.0 锁定测试），并通过 [Linux、Windows、macOS 与 Rust 1.85 CI](https://github.com/koko123as/rust-mhm/actions/runs/44960824081) 四项任务。CI 仅有现有 `actions/checkout@v4` 的 Node.js 20 弃用提示，不影响结果。
