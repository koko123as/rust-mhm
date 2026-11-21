# Compatibility ledger

`rust-mhm` 当前只在本项目自己的严格 YAML 配置中采用部分 Mihomo 规则字符串语法。它不是完整 Mihomo 配置解析器，也没有完整规则、DNS 或出站系统；表格中的“支持”仅指本仓库已实现并有本地测试覆盖的有限行为。

## 当前规则子集

| 规则 | 状态 | 当前含义 |
|---|---|---|
| `DOMAIN` | 支持 | 与规范化后的完整 ASCII 域名精确匹配。 |
| `DOMAIN-SUFFIX` | 支持 | 匹配域名本身及标签边界上的子域；`notexample.com` 不会命中 `example.com`。 |
| `IP-CIDR` / `IP-CIDR6` | 支持 | 对 SOCKS5 请求给出的字面 IP 做同地址族 CIDR 前缀比较；两种类型名按同一解析器处理。 |
| `DST-PORT` | 有限支持 | 匹配一个端口或一个闭区间，例如 `443` 或 `8000-8100`。 |
| `MATCH` | 支持 | 匹配所有剩余请求；显式出现时必须是唯一且最后一条规则。 |
| `RULE-SET` | 未支持 | 上游语法要求相应 rule provider；本项目尚无 provider 读取、格式解析、缓存或更新生命周期。 |

规则依配置顺序从上到下评估，首个匹配决定动作。当前动作只有 `DIRECT` 与 `REJECT`：`DIRECT` 执行 TCP 直连；`REJECT` 在拨号前返回 SOCKS5 `REP=0x02`。代理名称、代理组及其他策略均会显式报错，不会假装成功。

## 项目约定与未实现语义

- `DOMAIN`/`DOMAIN-SUFFIX` 只接收 ASCII DNS A-label（国际化域名需预先转为 `xn--...`）；匹配时转小写，并接受/去掉一个末尾根点。官方规则页面说明匹配类型，但这些正规化细节是本项目选择，尚未承诺与上游完全一致。
- 目前不为规则执行 DNS 查询。域名目标不会为 `IP-CIDR` 规则先解析；因此 `no-resolve` 可作为 `IP-CIDR` 的可选参数接受，但本项目不会触发供其抑制的 DNS 路由查询。域名 `DIRECT` 出站仍使用 Tokio/系统解析路径，这不等于实现了 Mihomo DNS 子系统。
- `DST-PORT` 目前只接受单值或单个 `-` 区间，不承诺上游语法中的所有端口集合/表达式形式。
- 没有规则时，或列表未写 `MATCH` 时，本项目在末尾添加 `MATCH,DIRECT`。这是本项目的显式 fallback 约定；不要据此推断完整 Mihomo 配置默认值。
- 当前顶层只识别 `listen`、`connect_timeout_ms`、`max_connections` 和 `rules`。`mixed-port`、`proxies`、`proxy-groups`、`rule-providers` 等完整配置结构尚未支持。

## 官方参考

- [Mihomo 官方 Routing Rules 文档](https://wiki.metacubex.one/en/config/rules/)：规则从上到下匹配；说明 `DOMAIN`、`DOMAIN-SUFFIX` 的域名边界、`IP-CIDR`/`IP-CIDR6`、目的端口、`MATCH` 与 `no-resolve`。
- [Mihomo 官方 Rule Providers 文档](https://wiki.metacubex.one/en/config/rule-providers/) 与[内容格式说明](https://wiki.metacubex.one/en/config/rule-providers/content/)：provider 配置及规则内容格式，供后续单独阶段评估。
- [Mihomo 官方配置语法手册](https://wiki.metacubex.one/en/handbook/syntax/)：通用配置及端口范围语法参考。
- [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928)：SOCKS5 回复码定义；本项目 `REJECT` 使用 connection-not-allowed（`0x02`）。
