# Architecture

## 当前请求路径

```text
local SOCKS5 client
        |
        v
SOCKS5 handshake / CONNECT parser
        |
        v
structured target (IP or domain + port) + inbound peer IP
        |
        v
ordered routing rules (first match wins)
        |                  |                         |                      |
     DIRECT              REJECT                  named proxy            fallback
        |                  |                   HTTP CONNECT / SOCKS5   ordered TCP candidates
        v                  v                         |                      |
DIRECT TCP dial      SOCKS5 REP 0x02 <--------------+----------------------+
        |                                            |
        +--------------------+-----------------------+
                             v
              bounded Tokio bidirectional TCP relay
```

连接及完整代理握手均受统一的 `connect_timeout_ms` 超时约束；拒绝动作不会发起上游连接。

fallback 会在单次 TCP CONNECT 请求内按顺序尝试已展开的候选；某候选连接失败时继续，成功即停止，`REJECT` 候选立即拒绝。全部候选共享同一个连接总时限。该逻辑只处理建连，不做健康探测；UDP 路由遇到 fallback 动作时丢弃数据报。

`select` 组配置加载时会校验全部组成员引用与环路，并为每个组创建以 `default-selected`（无效或缺省时取首成员）初始化的选择状态。路由规则保留组名；每次请求按当前选择递归解析为 `DIRECT`、`REJECT` 或具名代理动作。`RuleSet::select_proxy_group_member` 与 `selected_proxy_group_member` 操作进程内状态：同一 `RuleSet` 的克隆共享状态，另一次 `Config::routing_rules()` 创建独立状态。可选配置 `proxy-group-state-file` 后，启动会读取版本化 JSON 快照，仅恢复当前仍存在的组/成员；缺文件使用默认值，损坏、过期或未知条目被忽略。手动切换先将完整快照写入同目录临时文件并原子替换，再发布内存状态；写入失败时选择保持不变。未配置此字段时行为仍为纯进程内状态。provider 刷新会在组和成员仍存在时继承当前选择，否则回到新配置默认值。

## 当前 UDP ASSOCIATE 路径

```text
SOCKS5 TCP control connection
        |
        +-- UDP ASSOCIATE -> loopback UDP relay (association ends with TCP)
                                  |
                                  +-- verify client peer IP / pin UDP endpoint
                                  +-- decode SOCKS UDP frame and route each target
                                  +-- DIRECT -> family-matched ephemeral UDP egress
                                  +-- SOCKS5 proxy -> held upstream TCP + UDP ASSOCIATE relay
                                  +-- REJECT / HTTP proxy -> drop; never fall back to DIRECT
                                  +-- return validated relay responses to pinned endpoint
```

UDP `REJECT` 与不支持 UDP 的 HTTP 代理动作都丢弃，不会回退直连；分片与畸形帧也丢弃。DIRECT 路径最多跟踪 1024 个远端地址。具名 SOCKS5 UDP session 按需建立，保留其上游 TCP 控制连接并受有界队列约束；目标域名封装后交给上游解析。只有 loopback 入站 relay 地址会返回给本地 SOCKS 客户端。关闭下游 TCP 控制连接或取消服务任务会释放上游关联资源。

## 模块边界

- `rust-mhm-core::config`：严格的本项目 YAML 配置；校验 loopback 地址、连接超时、并发上限、入站用户、代理定义、`select`/`fallback` 组成员/环路及规则引用；每次 `routing_rules()` 为 `select` 组生成独立状态，并可从可选状态文件恢复有效选择。
- `rust-mhm-core::routing`：纯决策层；处理 `DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`DOMAIN-WILDCARD`、有限的 `DOMAIN-REGEX`、`IP-CIDR`/`IP-CIDR6`、`SRC-IP-CIDR`、`SRC-PORT`、`DST-PORT`，并按原位置展开 inline classical `RULE-SET`；按原始顺序使用服务层提供的域名 IP 快照匹配 CIDR，不执行 I/O；组名作为符号化动作保留，路由时读取进程内选择状态。fallback 子树展平为有序 TCP 候选，只有 `select` 组能通过公开状态接口手动更改/读取选择。
- `rust-mhm-core::outbound`：HTTP CONNECT（可选 Basic 认证）、SOCKS5 TCP CONNECT 与 SOCKS5 UDP ASSOCIATE（可选 RFC 1929 用户名/密码认证）；不实现 HTTP UDP 或组健康探测。
- `rust-mhm-core::server`：SOCKS5 入站（可选 RFC 1929 认证）、TCP CONNECT 转发与共享总时限的顺序 fallback、有限 UDP ASSOCIATE 入站、DIRECT/SOCKS5 UDP 逐数据报路由、客户端端点固定、错误映射与连接并发限制；UDP fallback 明确丢弃。
- `rust-mhm-core::control`：可选的 loopback 控制 API；Bearer 密钥保护 `GET /proxies`、`GET /proxies/{name}` 和 `PUT /proxies/{name}`，只读/切换 `select` 组；有状态文件时，写入失败返回服务端错误且不改变运行选择；请求体、并发数和处理时限均有上限。
- `rust-mhm`：命令行配置加载、日志初始化和服务启动；不承载协议/路由业务。

## 配置与路由边界

顶层还可选接受 `external-controller` 与 `secret`，二者必须同时设置；控制器地址必须是 loopback IP socket，secret 为 1–256 字节可见 ASCII。`proxy-group-state-file` 是本项目自有可选扩展；相对路径以配置文件目录为基准，不能覆盖配置文件或 rule-provider 数据文件/缓存。文件仅保存 `select` 组名和成员名，不保存代理凭据。`proxy-groups` 仅接受严格的 `type: select` / `type: fallback` 子集和 `name`、`proxies`、可选 `default-selected` 字段；fallback 不接受 `default-selected`。成员须为已配置代理、组、`DIRECT` 或 `REJECT`，组引用可前向或嵌套，但不能重复、缺失或形成环路。组名不能与代理/其他组冲突。有效 `default-selected` 映射到 select 组成员；缺省或不属于成员的值按已查阅的 Mihomo 文档行为回退到首成员。`RuleSet` 保留可变的进程内 select 选择状态，并在每次路由时解析嵌套组；fallback 子树会展平为有序候选。克隆共享 select 状态，独立构建的 `RuleSet` 不共享。fallback 仅在 TCP CONNECT 失败后继续尝试候选，候选共用 `connect_timeout_ms` 总时限；不做主动探测、健康检查或周期故障切换，UDP 行为为丢弃。`url-test`、`load-balance`、健康检查与过滤器不在本子集内。其余配置严格拒绝未知字段。

provider 当前支持 `type: inline`/`file`/`http` 与 `behavior: classical`/`domain`/`ipcidr` 子集；file 相对路径以配置文件目录为基准，启动时读取并可按 `interval` 周期重读。HTTP 类型可使用 HTTP 或 HTTPS URL，并可选 `path`（相对配置目录或绝对缓存路径）、`interval`（秒，默认 86400，范围 1–31536000）及官方单数 `header`（HTTP 头名到单值或值列表的映射）；file/HTTP 的 interval 默认值和范围相同。file/HTTP 数据限 4 MiB，并解析有限 YAML `payload` 或逐行文本。HTTP 启动时先下载；下载失败时回退到有效缓存，无有效缓存则启动失败。成功响应写入原子替换的持久缓存；省略 `path` 时写到配置目录下 `.rust-mhm-cache/` 的 provider 专属文件。缓存路径不得直接覆盖配置文件，provider 之间也不得共用；显式路径可能写到配置目录外，因此配置必须可信。无自定义请求头时最多跟随 5 次重定向；配置了请求头时禁用重定向，避免凭据转发到不同站点。HTTP 请求受 `connect_timeout_ms` 超时约束。CLI 使用 `Config::load_async`；`Config::from_yaml_str` 不接受 file/HTTP，`Config::load` 不接受 HTTP。启动后由后台任务按间隔刷新，只有新 payload 和整套路由均通过校验才切换共享路由表；失败保留当前规则。这里仅有 provider 级刷新，并非整个配置文件热重载；MRS/自定义格式及完整上游 provider 生命周期尚未实现。`authentication` 是 `username:password` 字符串列表；列表非空时通常强制 RFC 1929 子协商。来源 IP 命中 `skip-auth-prefixes` 的 IPv4/IPv6 CIDR 时改为无认证协商。代理对象字段为 `name`、`type`（`http` 或 `socks5`）、`server`、`port` 和可选的成对 `username`/`password`。规则第三列可用 `DIRECT`、`REJECT`、配置中的代理名或组名；组名以符号化动作保留并按当前 `RuleSet` 进程内选择解析，未声明的动作/代理名/组名失败。缺少 `MATCH` 时追加本项目约定的 `MATCH,DIRECT`。

SOCKS5 入站仅在配置非空 `authentication` 且 peer 不匹配豁免 CIDR 时要求 RFC 1929 用户名/密码，登录失败即关闭连接；该子协商本身没有加密。HTTP Basic 和 SOCKS5 用户密码在未加密代理链路上均可被观察，因此应限于可信主机/网络。HTTP 出站使用 HTTP/1.x `CONNECT` 并发送目标 authority；SOCKS5 TCP 与 UDP 出站都将域名地址类型交给代理端解析；DIRECT 域名目标仍由 Tokio/系统解析。HTTP 代理仅有 TCP `CONNECT`；SOCKS5 另支持受限 UDP ASSOCIATE。服务级组控制 API 仅绑定 loopback、使用 Bearer 密钥，支持三个组端点但只公开 `select` 组，没有 TLS、WebSocket 或完整 Mihomo 控制面能力；选择状态只有显式配置本项目的 `proxy-group-state-file` 才落盘，此扩展不代表 Mihomo 持久化兼容。有限 TCP fallback 不提供官方 `url`/`interval` 健康检查语义；手动 `select` 状态也不是完整 Mihomo 配置或语义实现。

规则匹配器本身不执行 DNS 查询。TCP 域名请求只有在有序评估到普通 `IP-CIDR`/`IP-CIDR6` 时，服务层才调用一次 Tokio/系统解析器；最多允许 16 个去重地址，解析、规则判定与连接共用 `connect_timeout_ms` 时限。任一解析答案命中 CIDR 即触发该规则，`no-resolve` 则跳过域名 CIDR 查询（但 DIRECT 建立连接仍需解析目标）；DIRECT 复用已执行的 CIDR 查询地址快照，代理动作仍将原域名交给上游。解析失败、空答案或超限时失败关闭，不回退 DIRECT。字面 IP 无需解析；UDP 的规则评估不使用该 TCP 解析路径。此切片没有 DNS 策略配置、缓存、hosts 或 fake-IP，也不代表 Mihomo DNS 兼容。`SRC-IP-CIDR` 与 `SRC-PORT` 分别匹配接受连接时取得的客户端 peer IP 与来源端口。域名规则接受 ASCII DNS A-label（如 `xn--...`），按小写规范化并去掉一个末尾根点；`DOMAIN-REGEX` 使用 Rust `regex` crate 语法，表达式在配置加载时编译。HTTP CONNECT 的目标域名另作 ASCII DNS 名校验，以避免未经验证的控制字符进入 HTTP 请求头。

## 生命周期与资源

监听地址默认并限制为 loopback；每个活动连接或 UDP 关联占用一个有界 semaphore permit 和 Tokio task。服务退出时停止接受连接并取消现有连接任务、provider 刷新任务和控制 API 任务。代理出站握手及连接均受配置超时；provider 刷新失败会保留最后一份有效路由表。当前尚无完整配置文件热重载、MRS/自定义格式、HTTP UDP 出站、UDP 分片、TUN 文件描述符、`url-test`、`load-balance` 或健康检查；fallback 仅有有限 TCP 连接顺序尝试。
