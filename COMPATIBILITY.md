# Compatibility ledger

`rust-mhm` 当前只在本项目自己的严格 YAML 配置中实现部分 Mihomo 风格规则、有限 TCP 出站、有限 `select`/TCP `fallback`/round-robin `load-balance` 组行为、可选保存 `select` 状态的本地文件、受密钥保护的 loopback 组控制 API，以及 SOCKS5 UDP ASSOCIATE 的有限入站/代理出站切片。它不是完整 Mihomo 配置解析器，也没有完整规则、DNS、完整服务控制面或完整数据面；“支持”只表示所列有限行为在本仓库实现并有本地测试覆盖。

## 当前规则子集

| 规则 | 状态 | 当前含义 |
|---|---|---|
| `DOMAIN` | 支持 | 与规范化后的完整 ASCII 域名精确匹配。 |
| `DOMAIN-SUFFIX` | 支持 | 匹配域名本身及标签边界上的子域；`notexample.com` 不会命中 `example.com`。 |
| `DOMAIN-KEYWORD` | 有限支持 | 在规范化后的 ASCII 域名中做大小写不敏感的子串匹配；不匹配 IP 字面量，也不要求标签边界。 |
| `DOMAIN-WILDCARD` | 有限支持 | 在规范化 ASCII 域名上匹配完整模式；只支持 `*`（零个或多个字符）和 `?`（单个字符）。 |
| `DOMAIN-REGEX` | 有限支持 | 规则加载时用 Rust `regex` crate 编译表达式，对规范化后的 ASCII 域名执行搜索匹配；表达式语法和上游引擎不保证等价。 |
| `IP-CIDR` / `IP-CIDR6` | 有限支持 | 字面 IP 按同地址族匹配；TCP 域名请求只有在有序规则实际到达普通 CIDR 规则时才使用系统解析结果，任一有界答案命中即匹配。`no-resolve` 跳过域名查询；UDP 路径不为规则解析域名。 |
| `SRC-IP-CIDR` | 有限支持 | 对已接受 SOCKS5 TCP 连接的客户端 peer IP 做 CIDR 匹配；不匹配源端口或来源地理信息。 |
| `SRC-PORT` | 有限支持 | 匹配 TCP 客户端 peer 端口，接受单端口或闭区间格式。 |
| `DST-PORT` | 有限支持 | 匹配一个端口或一个闭区间，例如 `443` 或 `8000-8100`。 |
| `MATCH` | 支持 | 匹配所有剩余请求；显式出现时必须是唯一且最后一条规则。 |
| `RULE-SET` | 有限支持 | 支持 `type: inline`/`file`/`http`，`behavior: classical`/`domain`/`ipcidr`；HTTP/HTTPS provider 支持持久原文缓存、离线缓存回退、按秒刷新间隔和自定义请求头，file provider 可按秒重新读取本地文件。只有新内容与完整路由表都通过校验才切换活动路由；失败时保留旧表。引用处动作覆盖 provider 内容。classical 内容仅能使用本项目已实现的规则类型。缓存/刷新不是完整 Mihomo 生命周期兼容。 |

规则依配置顺序评估，首个匹配决定动作。动作可为 `DIRECT`（TCP 直连或入站 UDP 直连）、`REJECT`（TCP 在拨号前返回 SOCKS5 `REP=0x02`；UDP 数据报静默丢弃）、已声明的代理名，或组名。组名在规则中保留为符号化动作，并在每次路由时依该 `RuleSet` 当前进程内选择解析；嵌套选择同样按当前状态递归。UDP 具名 SOCKS5 代理动作通过上游 UDP ASSOCIATE 转发；HTTP 代理 UDP 动作会丢弃，不会回退直连。代理和组引用必须精确匹配已声明名称；重复名称及保留名称 `DIRECT`/`REJECT` 不接受。

## `select`、`fallback` 与 `load-balance` 代理组子集

| 能力 | 状态 | 当前行为与边界 |
|---|---|---|
| `type: select` | 有限支持 | 严格配置接受组名、`type`、非空 `proxies` 和可选 `default-selected`；不接受未实现的额外 Mihomo 字段。 |
| `type: fallback` | 有限支持 | 仅 TCP CONNECT 建立连接时按配置顺序尝试候选；失败才继续，连接成功即停止；`REJECT` 立即终止。嵌套 fallback 展平；没有主动探测、健康状态或运行时故障切换。 |
| `type: load-balance` | 有限支持 | 仅接受缺省策略或 `strategy: round-robin`；每次路由决策选择并轮换一个有序成员。TCP 失败不在该请求内重试，UDP 每个数据报单独路由；没有健康探测、`url`/`interval`、一致性哈希或粘性会话。同一 `RuleSet` 的克隆共享游标，独立构建实例隔离；provider 刷新仅在组类型和有序成员未变时继承游标，成员或顺序变化则重置。游标为进程内状态，不进入手动选择 API 或状态文件。 |
| 组成员 | 有限支持 | 可引用配置代理、其他组、`DIRECT` 或 `REJECT`；允许前向引用和嵌套引用，拒绝未知/重复成员、组名冲突及任何引用环路。 |
| 默认成员 | 有限支持 | 成员匹配 `default-selected` 时初始化为该项；缺省或不属于该组的值时取首成员。嵌套组会在每次路由时按当前选择递归解析。 |
| 手动选择状态 | 有限支持 | `RuleSet` 提供 `select_proxy_group_member` / `selected_proxy_group_member` 方法；校验成员后更新选择。同一 `RuleSet` 的克隆共享状态，独立调用 `Config::routing_rules()` 创建的实例隔离。默认只在进程内生效；显式配置本项目自有 `proxy-group-state-file` 后，可将有效组/成员映射保存为版本化本地 JSON，并在重启时恢复。损坏或过期状态忽略并回退默认；这不是 Mihomo 持久化语义兼容。 |
| 控制 API | 有限支持 | 仅在显式配置 `external-controller` 与 `secret` 时启用；仅允许 loopback 地址，使用 `Authorization: Bearer <secret>`。实现 `GET /proxies`、`GET /proxies/{name}` 与 `PUT /proxies/{name}`，只列出/切换 `select` 组；fallback 与 load-balance 不作为手动选择状态暴露。请求体最多 4 KiB、最多 32 个并发请求、处理时限 10 秒。 |
| 其他自动策略组 | 不支持 | `url-test`、健康检查及组过滤器不支持；load-balance 仅有上列 round-robin 子集，不含完整 Mihomo 策略和探测语义。 |

本项目的 fallback 只在处理 TCP CONNECT 时尝试建立上游连接；失败则按列表继续，直到成功或候选耗尽。一个 CONNECT 请求内的所有尝试共用配置的 `connect_timeout_ms` 总时限。`REJECT` 会停止后续尝试；UDP 数据报经 fallback 组会被明确丢弃，不会回退直连。该切片不执行周期健康检查，也不识别官方 `url` / `interval` 探测字段。Mihomo 官方文档描述当前节点超时后按顺序选择首个可用节点，并提供 `url`、`interval` 等健康检查相关字段，因此本项目行为范围显著更窄，不能视为等价。

控制 API 只提供受限 `select` 组状态和手动切换，不提供 WebSocket、TLS、通用 proxy 列表或运行时配置更新。默认不持久化；配置本项目的 `proxy-group-state-file` 时，切换先原子保存完整快照，写入失败不会更改运行状态。服务启动仅恢复当前配置中存在的 `select` 组和成员；provider 刷新会保留仍然属于组的当前成员，若组/成员移除则采用新默认值。该接口不是完整 Mihomo API，也不代表完整 Mihomo 组运行时语义兼容。

## 当前入站认证

本项目接受与 Mihomo 全局 `authentication` 相同形式的用户名/密码字符串列表，例如 `authentication: ["alice:secret"]`。列表为空或省略时使用 SOCKS5 无认证；列表非空时通常只协商 RFC 1929 用户名/密码方法，不向无认证客户端回退。用户名必须唯一，用户名和密码长度均为 1–255 个 UTF-8 字节；每个失败认证回复失败状态并关闭连接。可选 `skip-auth-prefixes` 接收 IPv4/IPv6 CIDR；peer IP 命中时允许无认证方法。

这只是本地 SOCKS5 监听的认证子集：不支持监听器级 `users` 覆盖或 HTTP 入站。UDP 支持 RFC 1928 `UDP ASSOCIATE` 的 loopback 有限子集：要求控制连接存续，只接收来自控制 peer IP 的数据报并固定首个合法 UDP 端点；路由可走 DIRECT 或具名 SOCKS5 UDP 出站。分片、HTTP 代理 UDP、完整 Mihomo `udp` 配置语义仍不支持。`skip-auth-prefixes` 是认证绕过开关，应只配置可信来源；当前监听器仍强制 loopback。RFC 1929 凭据是明文传输，不应把此功能视为安全的远程访问机制。

## 当前出站切片

| 配置 `type` | 支持范围 | 不包含 |
|---|---|---|
| `http` | HTTP/1.x `CONNECT` 隧道；可选 Basic 用户名/密码；只接受 2xx 成功响应。 | 明文 HTTP 代理连接、非 CONNECT 转发、TLS-to-proxy、代理链、重试与连接池。 |
| `socks5` | SOCKS5 TCP `CONNECT`；支持 IPv4、IPv6、域名目标；无认证或 RFC 1929 用户名/密码认证。另支持入站 UDP 路由使用 SOCKS5 `UDP ASSOCIATE` 转发，域名目标保留给代理解析。 | SOCKS5 UDP 分片、HTTP 代理 UDP、GSSAPI、SOCKS4、DNS 缓存或代理端点健康管理。 |

代理对象采用本项目自有 YAML 结构：`name`、`type`、`server`、`port`、可选的成对 `username`/`password`。凭据以明文保存在 YAML 里；使用者须自行限制文件访问并避免提交真实账号。出站连接与协议握手共用 `connect_timeout_ms`。收到 HTTP 或 SOCKS5 错误响应时，客户端收到失败回复；SOCKS5 返回的连接拒绝/不可达映射为对应的 SOCKS 回复。

## 项目约定与未实现语义

- `DOMAIN`/`DOMAIN-SUFFIX` 只接收 ASCII DNS A-label（国际化域名需预先转为 `xn--...`）；匹配时转小写，并接受/去掉一个末尾根点。`DOMAIN-KEYWORD` 同样只在该规范化后的 ASCII 域名中做任意位置子串匹配。`DOMAIN-WILDCARD` 只接受 ASCII 字母数字、点、连字符、`*` 与 `?`；模式在完整域名上匹配。`DOMAIN-REGEX` 也在规范化后的域名上做搜索匹配（目标域名大小写不影响匹配）；正则表达式本身默认区分大小写，需要时可用 `(?i)` 标志。它采用 Rust `regex` crate 语法，表达式长度上限为 4096 字节，不承诺与 Mihomo 的 regex 引擎完全兼容。这些正规化细节是本项目选择。
- HTTP CONNECT 的域名目标会做 ASCII DNS 格式校验后再写入 authority；这限制可表达的域名，但避免 HTTP 请求行/头注入。
- SOCKS5 代理会在连接请求中传递域名地址；代理端通常负责目标解析。DIRECT 域名目标仍使用 Tokio/系统解析路径。
- TCP 的 `IP-CIDR`/`IP-CIDR6` 域名判定仅在有序路由评估到达普通 CIDR 规则时触发一次 Tokio/系统解析；最多保留 16 个去重后的 IP 答案，并在配置的 `connect_timeout_ms` 总时限内完成路由和连接。任一 IPv4/IPv6 答案命中 CIDR 即命中；`no-resolve` 对域名目标跳过该规则且不触发 CIDR 路由查询，但若后续选择 DIRECT，建立连接仍需解析目标域名。DIRECT 会复用已执行的 CIDR 查询地址快照；代理动作仍把原始域名交给上游，不会以本地答案替换。解析失败、无答案或答案超过上限都会失败关闭，不回退为 DIRECT。字面 IP 不解析，UDP 路由仍不为 IP-CIDR 查询 DNS。这里没有 DNS 配置策略、缓存、hosts、fake-IP 或 Mihomo DNS 兼容承诺。
- `SRC-IP-CIDR` 与 `SRC-PORT` 检查 SOCKS5 TCP 控制连接提供的客户端 peer IP 和端口；UDP 数据报沿用该控制 peer 作为来源规则元数据。入站仍限制在 loopback，因此来源网段当前只代表 loopback 客户端地址。
- `DST-PORT` 目前只接受单值或单个 `-` 区间，不承诺上游语法中的所有端口集合/表达式形式。
- 没有规则时，或列表未写 `MATCH` 时，本项目会追加 `MATCH,DIRECT`。这是本项目的 fallback 约定，不代表完整 Mihomo 的默认值。
- 顶层只识别 `listen`、`connect_timeout_ms`、`max_connections`、`rules`、`rule-providers`、`proxies`、静态 `proxy-groups` 子集、`authentication`、`skip-auth-prefixes`、可选的 `external-controller` 与 `secret`，以及本项目自有的可选 `proxy-group-state-file`。状态文件相对路径以配置文件目录为基准，不能覆盖配置或 provider 数据；`Config::from_yaml_str` 因无文件路径而拒绝该选项。控制器两项必须同时设置；地址必须是 loopback IP socket，secret 为 1–256 字节可见 ASCII。`rule-providers` 是受限的 `inline`/`file`/`http` 子集；`mixed-port`、未实现的组类型/字段和完整 DNS 配置等仍会失败。
- `RULE-SET` 的 file provider 在启动时读取相对配置文件或绝对路径，并可按 `interval` 周期重新读取；file 与 HTTP 响应均限制为 4 MiB，并支持有限 YAML `payload` 或逐行 UTF-8 文本。HTTP provider 只允许无 URL 凭据的 HTTP/HTTPS URL，要求成功状态，完整下载受 `connect_timeout_ms` 限制；无自定义请求头时最多跟随 5 次重定向，配置官方单数 `header` 时禁用重定向以避免敏感头被转发。`header` 的每个头名可对应单个字符串或字符串列表。HTTP 数据会原子写入显式 `path`（相对配置目录或绝对路径）或默认 `.rust-mhm-cache/` 缓存；缓存不能直接覆盖配置文件，也不能被多个 provider 共用。显式路径可写至配置目录外，因此只应使用可信配置。联网失败时仅回退到经规则校验的已有缓存，否则启动失败。file/HTTP `interval` 均为 1–31536000 秒，默认一天；后台刷新仅在新 payload 和完整路由表均通过校验后切换活动路由，文件缺失、超限、下载失败或内容无效时保留旧规则。库调用方需使用 `Config::load_async`，CLI 已使用异步加载；仅含 file provider 的配置也可使用 `Config::load`。MRS/自定义格式、`size-limit`、完整 provider 语义和整个配置文件热重载未实现；`classical` 中未实现的规则类型会报错。`Config::from_yaml_str` 不接受 file 或 HTTP provider；`Config::load` 不接受 HTTP provider。
- 完整 Mihomo 控制 API、上游状态持久化语义、`url-test`、load-balance 的其他策略与主动健康检查、DNS 策略、HTTP 代理 UDP 出站、UDP 分片、完整 Mihomo UDP 配置、透明代理与 TUN 均未实现。当前有限 fallback 不包括健康检查，也不支持 UDP；round-robin 子集不包括失败重试或完整自动策略语义。

## 官方参考

- [Mihomo 官方 Routing Rules 文档](https://wiki.metacubex.one/en/config/rules/)：规则顺序和规则类型参考；官方将 `DOMAIN-REGEX` 定义为域名正则匹配，并将 `DOMAIN-KEYWORD` 定义为按域名关键词匹配、`SRC-IP-CIDR` 定义为匹配来源地址范围、`SRC-PORT` 定义为匹配来源端口，说明 `DOMAIN-WILDCARD` 只支持 `*` 与 `?`（分别匹配零或多个字符、恰好一个字符）。
- [Rust regex crate 语法参考](https://docs.rs/regex/latest/regex/#syntax)：本项目 `DOMAIN-REGEX` 表达式编译所使用的语法实现。
- [Rust regex crate 语法参考](https://docs.rs/regex/latest/regex/#syntax)：本项目 `DOMAIN-REGEX` 表达式编译所使用的语法实现。
- [Mihomo 官方 Proxy 配置文档](https://wiki.metacubex.one/en/config/proxies/) 与[配置语法手册](https://wiki.metacubex.one/en/handbook/syntax/)：上游出站配置参考；本项目使用不同 YAML 子集，不代表相同语义或完整支持。
- [Mihomo 官方 Proxy Groups 通用字段文档](https://wiki.metacubex.one/en/config/proxy-groups/)：组可引用代理或其他组；`default-selected` 缺省或找不到组内节点时使用首成员。本项目只采纳该默认成员规则的静态子集。
- [Mihomo 官方 Select 组文档](https://wiki.metacubex.one/en/config/proxy-groups/select/)：`select` 组语法参考；本项目只接受严格字段子集，不包含其余上游配置项。
- [Mihomo 官方 Fallback 组文档](https://wiki.metacubex.one/en/config/proxy-groups/fallback/) 与[代理组通用字段文档](https://wiki.metacubex.one/en/config/proxy-groups/)：官方描述当前节点超时后按顺序选择首个可用节点，并列出 `url` / `interval` 等健康检查字段。本项目只在单次 TCP CONNECT 期间按序尝试连接，不做主动探测或周期健康检查，UDP fallback 明确丢弃。
- [Mihomo 官方 Url-Test 组文档](https://wiki.metacubex.one/en/config/proxy-groups/url-test/)：列出 `url`、`interval` 与 `tolerance` 等字段；本项目当前不接受 `type: url-test`，此链接作为后续阶段语义参考。
- [Mihomo 官方 Load-Balance 组文档](https://wiki.metacubex.one/en/config/proxy-groups/load-balance/)：描述 `round-robin`、按目标地址的 `consistent-hashing` 与按来源/目标地址并带 10 分钟缓存的 `sticky-sessions`，并提及 `hash-key: in-user`。本项目只实现每次路由决策轮换一次成员的 round-robin 子集；不接受 `url` / `interval` 健康检查字段，不实现哈希、粘性会话或失败后重试。
- [Mihomo 官方 API 文档](https://wiki.metacubex.one/en/api/)：运行时可通过 `/proxies/{proxies_name}` 的 `PUT` 选择节点；本项目实现了同形的有限 `GET`/`PUT` 组路由，但仅支持 loopback、Bearer 密钥和 `select` 组，不声称完整 API 兼容。
- [Mihomo 官方全局配置](https://wiki.metacubex.one/en/config/general/)：`authentication` 与 `skip-auth-prefixes` 参考；本项目只支持全局认证列表及来源 CIDR 豁免的 SOCKS5 子集。
- [Mihomo 官方 SOCKS 入站文档](https://wiki.metacubex.one/en/config/inbound/listeners/socks/)：监听器级 `users` 覆盖语义参考，当前未实现。
- [Mihomo 官方 Rule Providers 文档](https://wiki.metacubex.one/en/config/rule-providers/) 与[内容格式说明](https://wiki.metacubex.one/en/config/rule-providers/content/)：官方文档说明 provider 生命周期、请求头和 classical/domain/ipcidr 内容格式；本项目只实现受限的缓存与刷新子集，不支持完整生命周期、MRS/自定义格式或全部上游语义。
- [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928)：SOCKS5 协议与回复码。
- [RFC 1929](https://www.rfc-editor.org/rfc/rfc1929)：SOCKS5 用户名/密码认证。
- [RFC 9110, Section 9.3.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6)：HTTP CONNECT 方法语义。
