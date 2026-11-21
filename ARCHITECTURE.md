# Architecture

## 当前请求路径

```text
local SOCKS5 client
        |
        v
SOCKS5 handshake / CONNECT parser
        |
        v
structured target (IP or domain + port)
        |
        v
DIRECT TCP dial with timeout
        |
        v
bounded Tokio bidirectional relay
```

## 模块边界

- `rust-mhm-core::config`：本项目的最小 YAML 配置；解析后做 loopback 地址、连接超时和并发上限校验。
- `rust-mhm-core::server`：SOCKS5 入站、目标拨号、错误映射、连接并发限制和 TCP 转发。
- `rust-mhm`：命令行配置加载、日志初始化和服务启动；不承载协议/路由业务。

内核数据面不经 UI 或平台桥接；当前也没有 UI、Kotlin 层、代理组或规则系统。后续增加规则时应将其做成可独立测试的决策层，并由入站和出站适配器调用。

## 配置边界

当前 YAML 仅识别 `listen`、`connect_timeout_ms`、`max_connections`。它不是 Mihomo YAML 子集的承诺；比如 `mixed-port`、`proxies`、`proxy-groups`、`rules` 会因未知字段而失败。

## 生命周期与资源

监听地址默认并限制为 loopback；每个活动连接占用一个有界 semaphore permit 和 Tokio task。服务退出时停止接受连接并取消现有连接任务。出站连接具有配置的超时；当前尚无热重载、持久化、UDP 关联或 TUN 文件描述符。
