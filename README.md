# rust-mhm

一个以 Rust 逐步实现代理内核能力的独立项目。仓库仍处于早期原型阶段，**不是 Mihomo 的完整替代品，也不声称兼容其完整配置或功能**。本项目使用自己的严格 YAML 子集，并按可测试的垂直切片推进。

## 当前实现

- SOCKS5 TCP `CONNECT` 入站，支持 IPv4、IPv6 与域名目标；默认无认证，可用 `authentication` 列表启用 RFC 1929 用户名/密码认证，并可用 `skip-auth-prefixes` CIDR 允许指定来源免认证。
- TCP 出站支持 `DIRECT`、HTTP `CONNECT`、SOCKS5；HTTP 与 SOCKS5 出站可选用户名/密码认证。
- 有序首匹配规则支持 `DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`DOMAIN-WILDCARD`、有限的 `DOMAIN-REGEX`、`IP-CIDR`/`IP-CIDR6`、`SRC-IP-CIDR`、`SRC-PORT`、`DST-PORT`、有限的 `RULE-SET` 和 `MATCH`；动作可为 `DIRECT`、`REJECT`、配置中的代理名或代理组名，组动作在路由时按该 `RuleSet` 当前的进程内选择解析。
- TCP 域名请求只有在有序规则运行到普通 `IP-CIDR`/`IP-CIDR6` 时才查询一次系统解析器，最多接受 16 个去重答案；`no-resolve` 跳过 CIDR 路由查询（但 DIRECT 建立连接仍需解析域名），DIRECT 复用已执行的解析结果，代理动作保留原始域名交给上游。解析失败、无答案或答案超限均失败关闭。此能力不是通用 DNS 子系统，UDP 路径不改变。
- `REJECT` 在拨号前返回 SOCKS5 connection-not-allowed；代理握手与连接共用配置的出站超时。
- 默认监听 `127.0.0.1:1080`，拒绝非 loopback 监听；连接并发有界。
- 严格配置支持有限 `select`、`fallback` 与 `load-balance` 代理组：`select` 可嵌套引用代理组，`default-selected` 未填写或不是成员时取首成员；`fallback` 只在 TCP CONNECT 建立失败时按配置顺序尝试下一个候选，成功即停止，`REJECT` 候选会终止尝试，嵌套 fallback 会展平；有限 `load-balance` 只实现 round-robin，每次路由决策（包括每个 UDP 数据报）轮换一个成员，失败不会在该次请求内重试。fallback 与 load-balance 没有主动健康探测或完整 Mihomo 自动策略语义；UDP fallback 数据报明确丢弃。核心库和可选 loopback 控制 API 只允许手动选择 `select` 组；API 需 Bearer 密钥。可选 `proxy-group-state-file` 只持久化 `select` 选择；启动只恢复仍有效的成员，损坏或过期条目回退默认。
- 有限 `url-test` 组只接受已配置出站或 `DIRECT` 成员、HTTP(S) `url`、必填秒级 `interval` 和可选 `tolerance`（0–65535 毫秒，默认 0）；启动后按成员顺序串行探测，并在每轮完成后等待配置间隔，每个请求受项目连接超时限制。首次成功轮选择最低 2xx 响应头延迟成员；之后保留仍探测成功且延迟不超过最快成员加 tolerance 的当前成员，否则切换到最快成功成员；全员失败保留上次选择。探测运行态及是否已成功探测不进入 `select` 控制 API 或状态文件；`timeout`、`lazy`、`max-failed-times` 等上游字段及其他完整 Mihomo 组语义仍未实现。
- 未知 YAML 字段、代理类型、规则类型、动作、重复代理/组名和未配置的成员引用均显式报错。

配置示例（账号字段是明文配置；实际使用时应限制配置文件权限，不要提交真实凭据）：

```yaml
listen: "127.0.0.1:1080"
connect_timeout_ms: 10000
max_connections: 256
# 可选控制 API：只能绑定 loopback，且必须设置独立密钥
# external-controller: "127.0.0.1:9090"
# secret: "replace-with-a-private-token"
# 可选的本项目扩展：持久化手动 select 选择（相对路径以配置文件目录为基准）
# proxy-group-state-file: ".rust-mhm/proxy-groups.json"
authentication: # 可省略；设置后每个 SOCKS5 客户端都必须认证
  - "local-user:change-me"
proxies:
  - name: upstream
    type: http # 也可以是 socks5
    server: proxy.example.net
    port: 8080
    username: your-user # 可省略；若配置则 username/password 必须同时存在
    password: your-password
proxy-groups:
  - name: preferred
    type: select
    proxies: [upstream, DIRECT]
    default-selected: upstream
rules:
  - DOMAIN,ads.example,REJECT
  - DOMAIN-SUFFIX,example.org,DIRECT
  - IP-CIDR,192.0.2.0/24,DIRECT,no-resolve
  - DST-PORT,443,preferred
  - MATCH,DIRECT
```

核心库示例：

```rust,ignore
let rules = config.routing_rules()?;
rules.select_proxy_group_member("preferred", "backup")?;
let selected = rules.selected_proxy_group_member("preferred");
```

默认情况下，手动 `select` 切换只保存在进程内，重启后按配置默认值初始化。只有配置本项目的 `proxy-group-state-file` 才会持久化；API 先原子写入状态文件，写入失败会返回错误且保持当前选择不变。可选控制 API 提供 `GET /proxies`、`GET /proxies/{组名}` 与 `PUT /proxies/{组名}`（JSON `{"name":"成员名"}`），所有请求都必须带 `Authorization: Bearer <secret>`。API 仅绑定 loopback，配置时必须同时提供 `external-controller` 与 `secret`；请求体上限 4 KiB、最多 32 个并发请求、处理时限 10 秒。provider 刷新会保留仍然存在的 `select` 选择；组或成员已被移除时改用新配置默认值。fallback、load-balance 与 url-test 均不属于可手动选择或持久化的组。此 API 不提供 WebSocket、TLS、完整 Mihomo API 或通用代理列表。当前 load-balance 只有有限 round-robin；URL-Test 只实现上述探测子集，不代表完整自动策略兼容。本项目 fallback 仅为有限 TCP 连接失败顺序切换，不能视为完整 Mihomo fallback 语义。

规则 provider 支持 `inline`、本地 `file` 和 HTTP/HTTPS，当前行为限定为 `classical`、`domain`、`ipcidr`；本地文件路径相对配置文件所在目录。file provider 支持通过 `interval` 定时重新读取，示例：

```yaml
rule-providers:
  local-blocklist:
    type: file
    behavior: domain
    path: rules/blocklist.yaml
    interval: 3600 # 秒；可省略，默认 24 小时
rules:
  - RULE-SET,local-blocklist,REJECT
  - MATCH,DIRECT
```

`rules/blocklist.yaml` 可用 YAML `payload` 列表（域名行为每项一个域名，IP 段行为每项一个 CIDR；classical 行为每项一条当前已实现的规则），也可用逐行文本。启动时读取和之后每次刷新都限制为 4 MiB。HTTP/HTTPS provider 也能在启动时下载一次快照：

```yaml
rule-providers:
  remote-blocklist:
    type: http
    behavior: domain
    url: https://example.net/rules.yaml
    path: rules/remote-blocklist.yaml # 可选；相对配置文件目录，也可使用绝对路径
    interval: 86400 # 秒；默认 24 小时
    header:
      User-Agent:
        - rust-mhm/0.1
rules:
  - RULE-SET,remote-blocklist,REJECT
  - MATCH,DIRECT
```

HTTP 响应必须成功且不超过 4 MiB；完整请求及流式下载受 `connect_timeout_ms` 超时限制，最多跟随 5 次重定向。每个 HTTP provider 会将响应原文原子写入缓存：可用 `path` 指定位置（相对配置文件目录或绝对路径），省略时写入配置目录下 `.rust-mhm-cache/` 的 provider 专属文件。缓存路径不得直接覆盖配置文件，也不能被多个 provider 共用；由于自定义路径可能写入配置目录以外的位置，只应加载可信配置。启动时先尝试联网；若下载失败，则回退到已存在且通过校验的缓存，没有有效缓存时启动失败。`file` 与 `http` 的 `interval` 均以秒为单位，默认 86400，允许 1 到 31536000 秒；候选内容与整套路由规则都验证通过后，才会原子更新运行中的路由表。读取、下载或校验失败时继续使用旧规则，file provider 的缺失或超限文件也不会清空当前活动规则。缓存写入失败只记录警告，当前进程仍采用通过校验的新规则；若随后离线重启，缓存可能还是上一份快照。可用官方单数 `header` 字段设置一个或多个 HTTP 请求头值；为避免自定义凭据被转发给重定向站点，带自定义头的 provider 不跟随重定向。CLI 使用异步配置加载；库调用方可使用 `Config::load_async`，仅使用 file provider 的场景也可用 `Config::load`。MRS/自定义格式、完整 Mihomo provider 语义和整个配置文件热重载仍未实现。

代理类型目前只支持 `http`（HTTP CONNECT 隧道，不是通用正向 HTTP 转发，也不支持 TLS-to-proxy）和 `socks5`（TCP CONNECT，以及入站 UDP 数据报使用的有限 UDP ASSOCIATE）。HTTP 代理没有 UDP 转发能力。规则的第三列用代理名选择出站，例如 `MATCH,upstream`。省略规则时按本项目约定使用 `MATCH,DIRECT`。

SOCKS5 入站现支持有限的 RFC 1928 `UDP ASSOCIATE`：为每个已认证的 TCP 控制连接建立 loopback UDP relay，控制连接关闭时结束关联；仅允许来自控制连接客户端 IP 的数据报，并在首个合法数据报后固定客户端 UDP 端点。IPv4、IPv6 和域名目标按每个数据报应用路由规则：`DIRECT` 通过临时系统 UDP socket 发送，具名 SOCKS5 代理使用上游 `UDP ASSOCIATE`（域名交给代理端解析）；`REJECT` 与 HTTP 代理 UDP 动作会丢弃，绝不回退直连。上游 SOCKS5 控制连接随入站关联保持，队列有界。UDP 分片、HTTP 代理 UDP 出站、DNS 策略、Mihomo 的 `udp` 配置字段及完整入站语义均未实现；畸形和分片帧也会丢弃。relay 地址仍限制在 loopback。

`skip-auth-prefixes` 命中时将协商无认证方法；该功能应谨慎配置，避免把不可信来源列入豁免范围。SOCKS5 入站认证和 SOCKS5 出站认证按 RFC 1929 传输明文凭据，因此仅应在可信本机网络使用。**仍未实现：** HTTP 入站、HTTPS/其他代理出站、除有限 tolerance 子集外的完整 Mihomo URL-Test 字段与行为、fallback/load-balance 主动健康检查、一致性哈希/粘性会话、完整 Mihomo DNS 策略、TUN、订阅、完整 REST/WebSocket API、UI 与 Android 服务。fallback 只有上述有限 TCP 顺序切换；UDP 数据报会丢弃，不含 `url`/`interval` 探测与周期健康状态。load-balance 只提供每次路由决策一次轮换成员的 round-robin，不会在失败后于同一请求重试。当前只有受密钥保护的 loopback `select` 组状态/切换 API；可选的本地组状态文件是本项目扩展，不是完整 Mihomo 控制面或持久化兼容。域名 CIDR 规则仅有上述 TCP 有界系统解析切片，不提供 DNS 策略、缓存或 hosts/fake-IP。该项目不接受完整 Mihomo YAML；见 [兼容性台账](COMPATIBILITY.md)。

## 快速开始

需要 Rust 1.85 或更高版本。

```sh
cargo test --workspace
cp config.example.yaml config.yaml
cargo run -p rust-mhm -- config.yaml
```

运行时可通过 `RUST_LOG=info` 设置日志级别。当前监听只允许 loopback IP；LAN/TUN 等网络暴露方式尚未实现。

## 架构与阶段

- [ARCHITECTURE.md](ARCHITECTURE.md)：当前数据路径与模块边界。
- [ROADMAP.md](ROADMAP.md)：分阶段目标、未实现能力与验收项。
- [COMPATIBILITY.md](COMPATIBILITY.md)：上游规则语义来源与本项目兼容性决策。
- [DEVELOPMENT.md](DEVELOPMENT.md)：依赖、工具链和本地开发说明。
- [TESTING.md](TESTING.md)：测试范围和未覆盖项。
- [PERFORMANCE.md](PERFORMANCE.md)：性能测量状态。
- [CHANGELOG.md](CHANGELOG.md)：阶段变更记录。

## 来源与许可证

SOCKS5 子集参考 [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928) 和 [RFC 1929](https://www.rfc-editor.org/rfc/rfc1929)；HTTP CONNECT 使用标准 HTTP 隧道请求。上游能力范围见 [MetaCubeX 官方 Meta 分支 README](https://raw.githubusercontent.com/MetaCubeX/mihomo/Meta/README.md) 与[官方配置文档](https://wiki.metacubex.one/en/config/)。本项目本阶段未复制或移植上游实现代码，能力名称的语法支持不代表完整语义兼容。

上游 README 标注 GPL-3.0，并注明与 MetaCubeX 无关的下游项目名称不能包含 “mihomo”。本仓库名称为 `rust-mhm`。**本项目自身的许可证尚未由项目所有者选择；仓库当前没有 `LICENSE` 文件，也不应据此假设已有再分发授权。**

## 验证状态

Linux x86_64 上上一阶段的静态 `select` 组切片通过了 81 项 workspace 测试及其余本地门禁，且 [Linux、Windows、macOS 与 Rust 1.85 CI](https://github.com/koko123as/rust-mhm/actions/runs/44949696886) 全项通过。本阶段进程内手动选择切片通过了本地完整门禁（85 项 workspace 测试、格式、全目标检查、零警告 Clippy、CLI 帮助和 Rust 1.85 锁定依赖测试），并在[本阶段 CI](https://github.com/koko123as/rust-mhm/actions/runs/44950947867) 的 Ubuntu、Windows、macOS、Rust 1.85 四项任务中全部通过。此前 SOCKS5 UDP 出站的 [CI run](https://github.com/koko123as/rust-mhm/actions/runs/44948797643) 亦已通过。网络测试只使用本地假服务，不依赖外网；Android、真实第三方代理、长时负载及 Android VPN 集成尚未验证。

有限 TCP `fallback` 切片通过本地完整门禁（118 项测试、格式、全目标检查、零警告 Clippy、CLI 帮助与 Rust 1.85 锁定测试）；修复 Windows 临时端口竞态后的 [Linux、Windows、macOS 与 Rust 1.85 CI](https://github.com/koko123as/rust-mhm/actions/runs/44958214245) 全项通过。

有限 `load-balance` round-robin 切片通过本地完整门禁（122 项 workspace 测试、格式、全目标检查、零警告 Clippy、CLI 帮助与 Rust 1.85 锁定测试）；修复最新 Rust 弃用警告后的提交 `628ece3` 在 [Linux、Windows、macOS 与 Rust 1.85 CI](https://github.com/koko123as/rust-mhm/actions/runs/44959469886) 全项通过。

有限 `url-test` 垂直切片通过本地完整门禁（129 项 workspace 测试、格式、全目标检查、零警告 Clippy、CLI 帮助与 Rust 1.85 锁定测试），并通过 [Linux、Windows、macOS 与 Rust 1.85 CI](https://github.com/koko123as/rust-mhm/actions/runs/44960824081) 四项任务。CI 仅有现有 `actions/checkout@v4` 的 Node.js 20 弃用提示，不影响结果。
