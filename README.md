# nanotun 自托管网关

`nanotun` 是一个自托管的「组网工具」服务端:运行在一台具备公网入口的机器上,客户端
通过用户名 + PSK(预共享密钥)登录后,可在 TUN 虚拟网卡上互通,组成 mesh 子网。

无需任何外部控制面 / 账号系统,所有用户、设备、ACL 规则都保存在本机 SQLite
(`[store].db_path`),由 `nanotun-admin` CLI 管理。

## 快速启动

### 1. 构建并初始化数据库

```bash
cd cmd/nanotund
go build -o nanotund .

# 首次启动会自动跑 schema migration,也可显式执行(本地非 root 试跑用 no_tun 样例):
./nanotund -config config_no_tun.toml &  # 启动后立即 Ctrl-C 也行,只为建库
```

首次启动会自动建库并迁移到最新 schema。注意 `config.toml`(完整 reference 样板)
里 `[store].db_path` 钉的是生产绝对路径 `/var/lib/nanotun/nanotun.db`,非 root
本地试跑请改成相对路径,或直接用 `config_no_tun.toml`(其 `db_path` 为
`data/nanotun.db`,且无需 root/TUN):

```bash
./nanotund -config config_no_tun.toml
```

### 2. 用 admin CLI 创建用户和设备

详细命令见 [`cmd/nanotun-admin/README.md`](cmd/nanotun-admin/README.md);最常用的工作流(0013
credentials 解耦后**双 QR**:profile 不含 PSK + credentials 独立下发):

```bash
cd cmd/nanotun-admin
go build -o nanotun-admin .

# 1) 创建用户:PSK 仅在这一次以明文回显,同时分配 credential_id (UUID v4)。
./nanotun-admin user create alice --admin --exit-allowed=true

# 2) 客户端 profile QR(只含服务器节点 / 路由,不含 PSK,可公开传阅)。
./nanotun-admin profile show alice --host vpn.example.com --output alice-profile.json

# 3) 客户端 credentials QR(用 PSK 明文 + UUID 生成,**仅这一次能拿到明文**)。
#    用户用 nanotun-cred://v1?d=... 二维码扫入 Apple 客户端 Keychain,Profile 列表
#    再走「绑定凭证」选这把 UUID。后续 reset-psk 重新出新 QR,客户端按 UUID 自动覆盖。
./nanotun-admin credentials show alice --psk '<刚才创建时回显的明文>' \
    --format qr-png --output alice-cred.png
```

### 3. 启动服务端

**完整模式(含 TUN):**

```bash
cd cmd/nanotund
sudo ./nanotund -config config.toml
```

**无 TUN 模式(测试 / 本地联调):**

```bash
cd cmd/nanotund
./nanotund -config config_no_tun.toml
```

默认 VPN 数据面监听 `[server].listen_addr`(如 `:8080`),走 WebSocket Binary +
自定义链路帧(见 `util/link_frame.go`)。同时可启用 Hysteria 2(`[hysteria]`)和
Xray REALITY(`[reality]`)入站,均会在握手后环回到 VPN 数据面端口。

## 协议与会话语义

- 客户端首帧发 `LinkTypeLoginReq`,字段见 `util/protocol.go`。`Token` 字段承载
  PSK 明文,服务端用 argon2id 校验。
- 登录成功后服务端下发 `LinkTypeLoginResp(code=0, session_id, takeover_secret)`
  + `LinkTypeConvSaltMsg`(含虚拟 IP / DNS)。
- 每条会话拥有唯一 `connIDStr`(16B 十六进制),用于「热切换接管」:客户端可在另
  一条传输上发 `Purpose=takeover` 的 LoginReq 接管原会话,服务端校验 PSK + secret
  通过后无缝过户 vIP / TunChan。
- `Code*` 错误码(`util/login_codes.go`)定义在 `util` 包,客户端按 `Code` +
  `clientLoginMessageForCode` 做 UI 提示。

## 安全相关默认

- PSK 用 `argon2id`(t=3 / m=64MB / p=2)散列;`auth.argon2Sema` 限制并发,防止
  DoS 撑爆内存。
- 并发会话数默认**不限制**;可配全局上限 `[server].max_sessions_per_user`(>0 生效),
  或按账号覆盖 `user set-max-sessions <username> <n>`(>0 覆盖全局、-1 该账号不限、
  0 跟随全局);超过则按 `createdAt` 踢最老,改动仅对未来登录生效。
- `[server].jump_host_firewall=true` 时按 `[server].jump_host_allowed_ips` 在
  Linux 上挂 ipset + iptables,只允许列表内的源 IPv4 接入(自动加入 127.0.0.1)。
- 所有登录失败 / kick / 配置 reload / ACL drop 都写入 `audit_logs`,30 天自动
  prune(见 `cmd/nanotund/audit_gc.go`)。
- 撤销维度有两层:`user disable <user>` 全设备封、`user reset-psk <user>`(也可
  走 `credentials show <user> --rotate-psk`)让旧 credential 失效;两者都会让在线
  会话在 ≤ `[server].user_invalidate_interval_sec`(默认 10s)内被 server 主动踢
  掉(close code = 905)。
  历史的 per-profile `pid` 黑名单(P2#14)在 0014(2026-05-25)随 credentials 解耦
  一并移除——profile QR 已不含 PSK,泄露也无法登录,per-QR 吊销冗余。

## Profile QR vs Credentials QR — 双 QR 设计(0013 起)

0013(2026-05-25)起 nanotun 把客户端导入二维码**拆成两份**,杜绝把 PSK 跟服务器
配置塞在同一个可分享的 URL 里:

| QR 类型 | URL prefix | 内容 | 安全级别 |
| --- | --- | --- | --- |
| profile QR | `nanotun://v1` | server host / transport(WS, Hysteria, REALITY)/ nodes 配置 | **可公开** — 不含 PSK,泄露无法登录 |
| credentials QR | `nanotun-cred://v1` | `credential_id`(UUID v4)+ `username` + `psk` + `created_at` | **机密** — 仅本地一对一传递,客户端落 Keychain |

工作流:
- **首次下发**:管理员同时导出两份 QR 给用户。客户端先扫 profile(选服务器),
  再扫 credentials(注入凭证)。profile 可云同步 / 团队群发,credentials 走线下。
- **多设备**:同一用户在新设备扫**同一份** credentials QR 即可登录;`credential_id`
  保持不变,`nanotun-admin device list` 会按 device_uuid 单独统计。
- **凭证轮换**:`nanotun-admin user reset-psk <user>` 或 `credentials show <user> --rotate-psk`
  生成新 PSK,**保持** `credential_id` 不变。客户端再扫一次新的 credentials QR,
  按 `credential_id` 索引自动覆盖本地旧 PSK,无需手动删旧条目;旧 PSK 上的会话
  在 ≤ 10s 内被 server 以 Close(905) 踢下。
- **运维清单**:`nanotun-admin credentials list [--json]` 打印所有「已发过凭证」
  的用户(含 disabled),`credential_id` + 上次 rotate 时间;`user show --json` 在
  user 视角同步暴露 `credential_id` / `credential_created_at`。

CLI 命令速查:
```bash
# Profile QR(server 配置,可公开)
nanotun-admin profile show <user> --format qr      # 终端二维码
nanotun-admin profile show <user> --format qr-png --output profile.png

# Credentials QR(机密凭证;rotate 路径与 user reset-psk 等价)
nanotun-admin credentials show <user> --psk PLAIN  --format qr
nanotun-admin credentials show <user> --rotate-psk --format qr
nanotun-admin credentials list [--json]
```

Web 后台同款:`/users` 列表展示 `credential_id` 前 8 位;新建用户 / 重置 PSK 都
走 PRG 重定向到 `/users/{id}/created` 或 `/users/{id}/reset-psk-result`,token
失效或刷新即视为已展示一次,避免误触发重复 rotate。

## 可选模块

- **Magic DNS**(P2#11)`[server.magic_dns].enabled=true` 时,server 在 TUN
  gateway IP 的 :53 上跑内置 stub DNS,把 `<device>.<user>.<suffix>` 解析为 vIP。
  `listen_port` 必须 = 53,否则 server 会跳过给客户端 prepend gateway DNS
  (避免把客户端 DNS 指到查不到的端口)。配置范例见 `cmd/nanotund/config.toml` 注释。
- **Subnet route advertise**(P2#12,**控制面 only**)客户端可声明本地子网,
  管理员通过 `nanotun-admin route approve <device_id> <cidr>` 审批。
  ⚠️ 数据面 forwarding 排在下一 milestone;approved CIDR 暂不会真正承载流量,
  详见 `docs/DESIGN_SUBNET_ROUTES.md`。

## 可观测性 / 监控

- **`/health`**(默认 `127.0.0.1:8081`)JSON 探活,k8s liveness/readiness 直接用。
- **`/metrics`**(同上端口)Prometheus 文本格式(OpenMetrics 0.0.4 兼容),
  暴露:活跃会话数、ACL 丢包(分 kind)、lease GC 次数、Magic DNS 出口分布、
  subnet route 接受/拒绝数、登录 rate-limit 触顶次数等。
  scrape 范例:
  ```yaml
  scrape_configs:
    - job_name: nanotun
      static_configs: [{targets: ['127.0.0.1:8081']}]
      metrics_path: /metrics
  ```

## systemd 集成

`cmd/nanotund/nanotun.service` 使用 `Type=notify` + `WatchdogSec=30s`:
- 启动:server 调 `sd_notify READY=1` 后 systemd 才标记 `active`,依赖 unit 能正确排序;
- 心跳:server 每 15s 发 `WATCHDOG=1`,卡死 30s 后 systemd 自动 SIGTERM 重启;
- shutdown:`sd_notify STOPPING=1` 让 `systemctl status` 显示 `deactivating`。

非 systemd 部署(直接 `./nanotund`):`NOTIFY_SOCKET` 为空 → 全部 no-op,
不影响 dev / 容器场景。

## 配置校验

```bash
# 默认 lenient:未知字段只 WARN,server 继续启动(向后兼容)。
./nanotund -config config.toml

# strict:任何未知字段直接 fatal 退出(适合 CI / 升级流程)。
NANOTUN_CONFIG_STRICT=1 ./nanotund -config config.toml

# 不启动 server,只校验:
nanotun-admin config lint config.toml
# 退出码: 0=OK / 3=未知字段 / 4=TOML 语法错 / 1=I/O 错
```

## 测试

```bash
# 单元 + 集成测试(完全本地,不依赖任何外部服务)
go test -count=1 ./...

# 仅 server 包,带详细输出
go test -v -count=1 -timeout 120s ./cmd/nanotund/

# Benchmarks
go test -bench="BenchmarkLoginFlow" -benchtime=10s -count=1 ./cmd/nanotund/
```

## 升级 / 部署脚本

生产部署一般用 `scripts/install-self-hosted.sh`,会自动安装 systemd 单元 /
开启 IP 转发 / 写 UFW 规则,详见脚本头部注释与 `docs/UPGRADE_M0.md`。

历史版本曾经依赖 一个集中式认证后端(`legacy_backend` 模式),
当前代码库已经彻底移除该路径,所有部署一律走自托管 PSK。如需查阅历史归因,
见 `docs/POSTMORTEM-20260521-db-path-migration.md`。

## 许可证

本项目以 [Apache License 2.0](LICENSE) 开源。
`third_party/xtls-reality` 为 vendored 第三方代码,保留其自带许可(见该目录内
`LICENSE` 与 `LICENSE-Go`)。
