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

协议测试覆盖 SOCKS5 greeting 畸形输入、RFC 1929 入站认证成功/失败及子协商畸形/截断帧、CIDR 命中后的认证绕过、不支持命令/认证拒绝、IPv4/IPv6/域名 CONNECT 的所有截断前缀、非法请求字段、慢速 greeting 超时、已协商会话取消关闭、并发客户端下的连接上限、目标解析、基于 loopback peer IP/端口的 `SRC-IP-CIDR` 与 `SRC-PORT` 拒绝回复和本地 TCP 转发。TCP 域名 CIDR 另测试解析器按需单次调用、DNS 错误/空结果/答案超限/超时失败关闭，以及本地 `localhost` 的 DIRECT 地址复用、REJECT 不拨号和具名 HTTP 代理仍收到原始域名。新增 UDP 测试覆盖 `UDP ASSOCIATE` 请求及 IPv4/IPv6/域名 UDP 帧、非法 RSV/ATYP/FRAG 丢弃、loopback DIRECT UDP echo、客户端端口固定、TCP 控制关闭关联，以及 `REJECT`/HTTP 代理路由不误直连。SOCKS5 UDP 出站测试覆盖无认证与 RFC 1929 认证协商、上游 relay 地址解析、域名目标原样封装、经过本地假 relay 的请求/响应回送、控制关联保持至关闭，并验证 HTTP UDP 不回退 DIRECT。并发上限回归使用 20 个同时连接验证配置上限为 8 时只服务 8 个会话，不代表长时负载测试。TCP 出站集成测试使用本地假 HTTP CONNECT 与 SOCKS5 服务，覆盖代理用户名/密码认证、域名请求和隧道双向转发。所有网络测试只使用 loopback，不依赖外网服务。

## 未覆盖/未验证

尚未覆盖长时间并发压力、通用 DNS 策略/缓存或真实网络故障；TCP 域名 CIDR 仅使用受限系统解析器快照，未验证 DNS 策略、缓存、hosts、fake-IP 或完整 Mihomo 行为。HTTP provider 测试使用 loopback 假服务；file provider 使用临时本地文件；没有基于 Mihomo 配置语料的兼容性测试。file/HTTP provider 的缓存与刷新仅覆盖本项目受限 YAML/逐行文本格式，未验证 MRS、自定义格式、真实远端服务、完整 Mihomo 生命周期或整个配置文件热重载。控制 API 目前仅有 loopback 本地服务测试，未覆盖长时压力、真实 Mihomo 客户端互操作、TLS/WebSocket 或完整控制面；本地组状态文件不代表 Mihomo 持久化语义兼容。状态文件路径冲突测试覆盖配置文件、file provider 数据、HTTP provider 缓存和目录；尚未做断电/系统崩溃后的目录项耐久性测试。URL-test、fallback、load-balance、健康检查与自动策略仍未实现。

本地实际构建环境为 Linux x86_64。提交 `d4bf016` 的 DIRECT-only UDP 阶段已通过格式、workspace 全目标检查、76 项测试、零警告 Clippy、CLI 帮助、Rust 1.85.0 锁定测试和 [Linux、Windows、macOS 与 Rust 1.85 CI](https://github.com/koko123as/rust-mhm/actions/runs/44947943108)。此前 SOCKS5 UDP 代理出站切片的 [Linux、Windows、macOS 与 Rust 1.85 CI](https://github.com/koko123as/rust-mhm/actions/runs/44948797643) 全项通过。上一阶段静态 `select` 组切片通过本地完整门禁（81 项 workspace 测试）与 [Linux、Windows、macOS、Rust 1.85 CI](https://github.com/koko123as/rust-mhm/actions/runs/44949696886)。本阶段进程内手动选择切片通过本地完整门禁（85 项 workspace 测试），并在[本阶段 CI](https://github.com/koko123as/rust-mhm/actions/runs/44950947867) 的 Ubuntu、Windows、macOS、Rust 1.85 四项任务中全部通过。Android 与移动设备未验证；尚无性能基准、负载/长稳测试或真实第三方代理互操作测试。

TCP 域名 CIDR 路由切片通过本地完整门禁（103 项测试；格式、workspace 全目标检查、零警告 Clippy、CLI 帮助与 Rust 1.85 锁定测试），并通过 [Linux、Windows、macOS 与 Rust 1.85 CI](https://github.com/koko123as/rust-mhm/actions/runs/44954299373)。

本地 `select` 状态持久化切片通过完整门禁（109 项 workspace 测试；格式、全目标检查、零警告 Clippy、CLI 帮助与 Rust 1.85 锁定测试），并通过 [Linux、Windows、macOS 与 Rust 1.85 CI](https://github.com/koko123as/rust-mhm/actions/runs/44956259709)。
