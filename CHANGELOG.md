# Changelog

## Unreleased

- 新增本项目自有可选 `proxy-group-state-file`：以版本化 JSON 保存手动 `select` 选择；相对路径基于配置文件目录，拒绝覆盖配置或 provider 数据文件/缓存。
- 启动时只恢复当前配置仍存在的组和成员；缺失、损坏、超限或未知/过期状态安全回退默认值。未配置时仍保持进程内状态行为。
- API 手动切换通过同目录临时文件原子替换状态快照后再更新运行选择；写入失败返回 500 且不改变内存状态。provider 刷新继续继承有效选择。
- 修复 provider 刷新和并发 API 选择在规则表替换时可能丢失后续选择的竞态；新旧规则句柄在刷新过渡期共享组状态锁。
- 新增控制 API 重启恢复、过期/损坏状态、路径冲突、写盘失败和并发更新覆盖；端到端验证持久化状态经过 provider 刷新仍可在重启后恢复。
- TCP 域名目标的 `IP-CIDR`/`IP-CIDR6` 路由现在按规则顺序按需执行一次有界系统解析；支持 `no-resolve`，DIRECT 复用最多 16 个去重答案并以 250ms 间隔交错尝试，避免慢失败的 IPv6 地址阻塞后续地址，具名代理仍接收原始域名。超时、DNS 失败、无答案或超限不回退 DIRECT；UDP 路径未改变，也未新增通用 DNS 策略/缓存。
- 新增解析顺序与调用次数、IPv4/IPv6 多答案、空/失败/超限/超时，以及 SOCKS5 DIRECT、REJECT 无拨号和 HTTP 上游保留原域名的测试。
- 增加严格配置的有限 `select` 代理组子集：支持代理与嵌套组前向引用、`DIRECT`/`REJECT`、有效 `default-selected` 默认项；缺省或无效默认项回退首成员，并校验成员、名称及引用环路。
- `RuleSet` 增加进程内手动选择/读取组成员的方法；普通规则与 `RULE-SET` 组动作保留符号化组名并按当前选择递归解析。克隆共享选择状态，另一次 `Config::routing_rules()` 创建独立状态。
- 覆盖默认值、合法选择、嵌套组变化、`DIRECT`/`REJECT`、未知组/非成员拒绝且不改变状态、克隆共享、独立实例隔离，以及 `RULE-SET` 动作跟随当前选择。
- 增加可选 loopback 组控制 API：使用 Bearer secret 保护 `GET /proxies`、`GET /proxies/{name}` 和 `PUT /proxies/{name}`；只支持手动 `select` 组，不支持 TLS、WebSocket 或完整 Mihomo API。
- 控制 API 请求体限制为 4 KiB、并发请求限制为 32、处理时限为 10 秒；配置要求 `external-controller` 与 `secret` 同时设置，且仅允许 loopback IP socket。
- provider 刷新在新组仍含当前已选成员时继承进程内选择；组或成员被移除时采用新配置默认成员。
- 新增控制 API 认证、非法/超大请求、服务启动/关闭与真实 SOCKS 路由联动测试，以及手动选择跨 provider 刷新的端到端测试。
- `url-test`、`fallback`、`load-balance`、健康检查与过滤器仍未实现。
- 增加受限 SOCKS5 UDP 代理出站：按数据报路由到具名 SOCKS5 上游，保留目标域名供代理解析，并维持上游 TCP 控制连接直至入站关联结束；HTTP 代理 UDP 与分片仍不支持，也不回退直连。
- 增加 SOCKS5 UDP ASSOCIATE 认证与上游 relay 协商测试，以及经本地假 SOCKS5 UDP relay 的域名请求/响应端到端测试。
- 增加受限 SOCKS5 UDP ASSOCIATE 入站：关联随 TCP 控制连接结束，支持 loopback relay、客户端端点固定、IPv4/IPv6/域名目标和逐数据报规则判断；可选择 DIRECT 或具名 SOCKS5 UDP 出站，REJECT/HTTP 代理/畸形/分片数据报丢弃且不回退直连。
- 增加 UDP 帧解析、地址族、端点绑定、loopback 回环和控制连接生命周期测试，并验证 REJECT 与代理路由不泄漏为 DIRECT。
- 本地 file rule-provider 支持可选 `interval`（默认 24 小时，范围 1–31536000 秒）周期重读；只有文件读取、载荷及完整路由校验成功后才更新活动路由，畸形、超限或暂时缺失的文件会保留旧路由。
- Windows HTTP provider 缓存替换改用 `MoveFileExW` 的替换标志，确保刷新可覆盖已有快照；缓存冲突路径比较适配 Windows 大小写不敏感语义，并增加跨平台覆盖测试及 Windows 条件测试。
- 文档明确缓存持久化失败时仍采用已验证的新运行时规则，但重启离线时可能回退到旧快照。
- HTTP rule-provider 增加持久缓存（支持显式路径和安全的默认路径）、启动离线回退、自定义请求头和按秒刷新；新规则验证成功后原子切换共享路由表，刷新失败保留旧表，下一次间隔从上一轮完成后开始计算，关闭服务时取消后台任务。
- 带自定义请求头的 provider 禁止 HTTP 重定向，避免认证头泄露；缓存写入采用临时文件与 rename，拒绝缓存覆盖配置文件或与其他 HTTP provider 共用路径。
- 新增 HTTP provider 默认/显式缓存、离线回退、单值/多值请求头、带自定义头时拒绝重定向、缓存路径隔离、无效刷新保留旧快照及慢响应刷新周期的本地测试。
- 支持在启动时载入本地 `file` rule-provider：相对配置目录解析路径，4 MiB 上限，支持 YAML payload 或逐行文本，以及有限的 `classical`/`domain`/`ipcidr` 行为。
- 支持通过 `Config::load_async` 在启动时下载 HTTP/HTTPS rule-provider 快照；校验成功状态，最多跟随 5 次重定向，单响应 4 MiB 上限并受 `connect_timeout_ms` 超时约束；CLI 已切换异步配置加载。
- 增加 HTTP provider 重定向、超时、404、声明长度超限和 chunked 流式超限的本地回环测试。
- 修复拒绝非 `CONNECT` 请求时先读取完整地址/端口帧，避免 Windows 关闭含未读请求数据的 socket 时以 RST 丢弃 SOCKS5 错误回复。
- Linux、Windows、macOS 的 CI 全量任务和 Rust 1.85 锁文件测试已在提交 `37d11d4` 通过；Android 尚未纳入验证。
- 增加 SOCKS5 greeting/RFC 1929/CONNECT 畸形与截断帧矩阵、连接上限并发及已协商会话取消测试；长期并发负载仍未覆盖。
- 更新兼容性台账、路线图、测试、架构与开发依赖文档；MRS/自定义格式、完整上游 provider 生命周期和配置文件热重载仍未实现。
- 增加严格配置的具名 `http` 与 `socks5` TCP 代理出站；支持可选用户名/密码认证。
- 规则动作可选择配置中的代理名称；重复定义、缺失引用和保留动作名称会被拒绝。
- HTTP CONNECT 与 SOCKS5 出站握手纳入连接超时；添加基于本地假代理的认证、隧道及双向转发端到端测试。
- 更新架构、兼容性台账和路线图，明确这是受限出站切片，不是完整 Mihomo 配置或功能兼容。
- 增加全局 `authentication` 与 IPv4/IPv6 `skip-auth-prefixes` 支持；按 RFC 1929 认证并在失败时关闭连接，匹配豁免来源时允许无认证。
- 路由规则新增有限 `DOMAIN-KEYWORD` 支持：在规范化后的 ASCII 域名中执行大小写不敏感的子串匹配。
- 路由规则新增有限 `DOMAIN-WILDCARD` 支持：仅支持 `*` 和 `?` 两种通配符。
- 路由规则新增有限 `SRC-IP-CIDR` 与 `SRC-PORT` 支持：按入站 TCP peer 地址和来源端口匹配。
- 路由规则新增有限 `DOMAIN-REGEX` 支持：规则加载时编译 Rust `regex` 表达式，对规范化域名执行匹配，拒绝无效或超过 4096 字节的表达式。
- 增加有限 inline classical `RULE-SET` 支持：在引用位置展开 payload 并由引用动作统一覆盖；此后已加入有限 file 与 HTTP/HTTPS 启动快照加载。
- 完整 Mihomo rule-provider 生命周期/内容格式、代理组、UDP、DNS 策略、TUN 与平台集成仍未实现；当前 `RULE-SET` 仍只支持本项目有限内容格式与规则子集。

## 0.1.0 — 初始原型

- 建立 Rust workspace、核心库与 CLI。
- 实现受限 YAML 配置和 loopback SOCKS5 无认证 TCP CONNECT 到 DIRECT 的基本数据路径。
- 加入本地回环协议测试与阶段/限制文档。
- 尚不支持完整 Mihomo 配置、代理组、UDP、DNS 策略、TUN 或 UI。
