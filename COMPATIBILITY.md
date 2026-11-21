# Compatibility ledger

`rust-mhm` 当前只在本项目自己的严格 YAML 配置中实现部分 Mihomo 风格规则和有限 TCP 出站。它不是完整 Mihomo 配置解析器，也没有完整规则、DNS、代理组或数据面；表中“支持”只表示该有限行为已在本仓库实现并有本地测试覆盖。

## 当前规则子集

| 规则 | 状态 | 当前含义 |
|---|---|---|
| `DOMAIN` | 支持 | 与规范化后的完整 ASCII 域名精确匹配。 |
| `DOMAIN-SUFFIX` | 支持 | 匹配域名本身及标签边界上的子域；`notexample.com` 不会命中 `example.com`。 |
| `DOMAIN-KEYWORD` | 有限支持 | 在规范化后的 ASCII 域名中做大小写不敏感的子串匹配；不匹配 IP 字面量，也不要求标签边界。 |
| `DOMAIN-WILDCARD` | 有限支持 | 在规范化 ASCII 域名上匹配完整模式；只支持 `*`（零个或多个字符）和 `?`（单个字符）。 |
| `DOMAIN-REGEX` | 有限支持 | 规则加载时用 Rust `regex` crate 编译表达式，对规范化后的 ASCII 域名执行搜索匹配；表达式语法和上游引擎不保证等价。 |
| `IP-CIDR` / `IP-CIDR6` | 支持 | 对 SOCKS5 请求给出的字面 IP 做同地址族 CIDR 前缀比较；不会为域名查询 DNS。 |
| `SRC-IP-CIDR` | 有限支持 | 对已接受 SOCKS5 TCP 连接的客户端 peer IP 做 CIDR 匹配；不匹配源端口或来源地理信息。 |
| `SRC-PORT` | 有限支持 | 匹配 TCP 客户端 peer 端口，接受单端口或闭区间格式。 |
| `DST-PORT` | 有限支持 | 匹配一个端口或一个闭区间，例如 `443` 或 `8000-8100`。 |
| `MATCH` | 支持 | 匹配所有剩余请求；显式出现时必须是唯一且最后一条规则。 |
| `RULE-SET` | 有限支持 | 支持 `type: inline`/`file`/`http`，`behavior: classical`/`domain`/`ipcidr`；HTTP/HTTPS provider 支持持久原文缓存、离线缓存回退、按秒刷新间隔和自定义请求头。有效刷新会替换运行中的规则表，失败时保留旧表；引用处动作覆盖 provider 内容。classical 内容仅能使用本项目已实现的规则类型。缓存/刷新不是完整 Mihomo 生命周期兼容。 |

规则依配置顺序评估，首个匹配决定动作。动作可为 `DIRECT`（TCP 直连）、`REJECT`（拨号前返回 SOCKS5 `REP=0x02`）或已声明的代理名。代理引用必须精确匹配 `proxies[].name`；未配置名称、重复名称和保留名称 `DIRECT`/`REJECT` 均不接受。

## 当前入站认证

本项目接受与 Mihomo 全局 `authentication` 相同形式的用户名/密码字符串列表，例如 `authentication: ["alice:secret"]`。列表为空或省略时使用 SOCKS5 无认证；列表非空时通常只协商 RFC 1929 用户名/密码方法，不向无认证客户端回退。用户名必须唯一，用户名和密码长度均为 1–255 个 UTF-8 字节；每个失败认证回复失败状态并关闭连接。可选 `skip-auth-prefixes` 接收 IPv4/IPv6 CIDR；peer IP 命中时允许无认证方法。

这只是本地 SOCKS5 TCP 监听的认证子集：不支持监听器级 `users` 覆盖、HTTP 入站或 UDP。`skip-auth-prefixes` 是认证绕过开关，应只配置可信来源；当前监听器仍强制 loopback。RFC 1929 凭据是明文传输，不应把此功能视为安全的远程访问机制。

## 当前出站切片

| 配置 `type` | 支持范围 | 不包含 |
|---|---|---|
| `http` | HTTP/1.x `CONNECT` 隧道；可选 Basic 用户名/密码；只接受 2xx 成功响应。 | 明文 HTTP 代理连接、非 CONNECT 转发、TLS-to-proxy、代理链、重试与连接池。 |
| `socks5` | SOCKS5 TCP `CONNECT`；支持 IPv4、IPv6、域名目标；无认证或 RFC 1929 用户名/密码认证。 | UDP ASSOCIATE、GSSAPI、SOCKS4、DNS 缓存或代理端点健康管理。 |

代理对象采用本项目自有 YAML 结构：`name`、`type`、`server`、`port`、可选的成对 `username`/`password`。凭据以明文保存在 YAML 里；使用者须自行限制文件访问并避免提交真实账号。出站连接与协议握手共用 `connect_timeout_ms`。收到 HTTP 或 SOCKS5 错误响应时，客户端收到失败回复；SOCKS5 返回的连接拒绝/不可达映射为对应的 SOCKS 回复。

## 项目约定与未实现语义

- `DOMAIN`/`DOMAIN-SUFFIX` 只接收 ASCII DNS A-label（国际化域名需预先转为 `xn--...`）；匹配时转小写，并接受/去掉一个末尾根点。`DOMAIN-KEYWORD` 同样只在该规范化后的 ASCII 域名中做任意位置子串匹配。`DOMAIN-WILDCARD` 只接受 ASCII 字母数字、点、连字符、`*` 与 `?`；模式在完整域名上匹配。`DOMAIN-REGEX` 也在规范化后的域名上做搜索匹配（目标域名大小写不影响匹配）；正则表达式本身默认区分大小写，需要时可用 `(?i)` 标志。它采用 Rust `regex` crate 语法，表达式长度上限为 4096 字节，不承诺与 Mihomo 的 regex 引擎完全兼容。这些正规化细节是本项目选择。
- HTTP CONNECT 的域名目标会做 ASCII DNS 格式校验后再写入 authority；这限制可表达的域名，但避免 HTTP 请求行/头注入。
- SOCKS5 代理会在连接请求中传递域名地址；代理端通常负责目标解析。DIRECT 域名目标仍使用 Tokio/系统解析路径。
- IP-CIDR 只检查请求中提供的字面地址。规则不执行 DNS；`no-resolve` 可作为 `IP-CIDR` 的可选参数接受，但本项目不会触发供其抑制的 DNS 路由查询。
- `SRC-IP-CIDR` 与 `SRC-PORT` 检查接入 socket 提供的客户端 peer IP 和端口。入站仍限制在 loopback，因此来源网段当前只代表 loopback 客户端地址；本项目也仅接受 TCP CONNECT。
- `DST-PORT` 目前只接受单值或单个 `-` 区间，不承诺上游语法中的所有端口集合/表达式形式。
- 没有规则时，或列表未写 `MATCH` 时，本项目会追加 `MATCH,DIRECT`。这是本项目的 fallback 约定，不代表完整 Mihomo 的默认值。
- 顶层只识别 `listen`、`connect_timeout_ms`、`max_connections`、`rules`、`rule-providers`、`proxies`、`authentication`、`skip-auth-prefixes`。`rule-providers` 是受限的 `inline`/`file`/`http` 子集；`mixed-port`、`proxy-groups`、完整 DNS 配置等仍会失败。
- `RULE-SET` 的 file provider 仅在进程启动时读取相对配置文件或绝对路径；file 与 HTTP 响应均限制为 4 MiB，并支持有限 YAML `payload` 或逐行 UTF-8 文本。HTTP provider 只允许无 URL 凭据的 HTTP/HTTPS URL，要求成功状态，完整下载受 `connect_timeout_ms` 限制；无自定义请求头时最多跟随 5 次重定向，配置官方单数 `header` 时禁用重定向以避免敏感头被转发。`header` 的每个头名可对应单个字符串或字符串列表。HTTP 数据会原子写入显式 `path`（相对配置目录或绝对路径）或默认 `.rust-mhm-cache/` 缓存；缓存不能直接覆盖配置文件，也不能被多个 provider 共用。显式路径可写至配置目录外，因此只应使用可信配置。联网失败时仅回退到经规则校验的已有缓存，否则启动失败。`interval` 是 1–31536000 秒，默认一天；后台刷新成功后切换活动路由，失败保留旧规则。库调用方需使用 `Config::load_async`，CLI 已使用异步加载。MRS/自定义格式、`size-limit`、完整 provider 语义和配置文件热重载未实现；`classical` 中未实现的规则类型会报错。`Config::from_yaml_str` 不接受 file 或 HTTP provider；`Config::load` 不接受 HTTP provider。
- 代理组（手动选择、故障转移、负载均衡）、DNS 策略、UDP、透明代理与 TUN 均未实现。

## 官方参考

- [Mihomo 官方 Routing Rules 文档](https://wiki.metacubex.one/en/config/rules/)：规则顺序和规则类型参考；官方将 `DOMAIN-REGEX` 定义为域名正则匹配，并将 `DOMAIN-KEYWORD` 定义为按域名关键词匹配、`SRC-IP-CIDR` 定义为匹配来源地址范围、`SRC-PORT` 定义为匹配来源端口，说明 `DOMAIN-WILDCARD` 只支持 `*` 与 `?`（分别匹配零或多个字符、恰好一个字符）。
- [Rust regex crate 语法参考](https://docs.rs/regex/latest/regex/#syntax)：本项目 `DOMAIN-REGEX` 表达式编译所使用的语法实现。
- [Mihomo 官方 Proxy 配置文档](https://wiki.metacubex.one/en/config/proxies/) 与[配置语法手册](https://wiki.metacubex.one/en/handbook/syntax/)：上游出站配置参考；本项目使用不同 YAML 子集，不代表相同语义或完整支持。
- [Mihomo 官方全局配置](https://wiki.metacubex.one/en/config/general/)：`authentication` 与 `skip-auth-prefixes` 参考；本项目只支持全局认证列表及来源 CIDR 豁免的 SOCKS5 子集。
- [Mihomo 官方 SOCKS 入站文档](https://wiki.metacubex.one/en/config/inbound/listeners/socks/)：监听器级 `users` 覆盖语义参考，当前未实现。
- [Mihomo 官方 Rule Providers 文档](https://wiki.metacubex.one/en/config/rule-providers/) 与[内容格式说明](https://wiki.metacubex.one/en/config/rule-providers/content/)：官方文档说明 provider 生命周期、请求头和 classical/domain/ipcidr 内容格式；本项目只实现受限的缓存与刷新子集，不支持完整生命周期、MRS/自定义格式或全部上游语义。
- [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928)：SOCKS5 协议与回复码。
- [RFC 1929](https://www.rfc-editor.org/rfc/rfc1929)：SOCKS5 用户名/密码认证。
- [RFC 9110, Section 9.3.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6)：HTTP CONNECT 方法语义。
