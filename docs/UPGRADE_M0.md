# Upgrading to nanotun (self-hosted PSK)

> 历史背景:M0 阶段引入了 PSK 自托管模式并与原有 `legacy_backend`(连接
> 旧集中式后端)模式并存。在 2026-05 完成全量切换后,`legacy_backend`
> 路径已经从代码库彻底移除,本文件保留作为升级回顾 + 自托管部署上手指南。

`nanotun` 现在是一个完全独立运行的「组网工具」服务端:用户、设备、ACL、
audit_logs 都存在本机 SQLite([store].db_path),由 `nanotun-admin` CLI 管理。
没有任何外部控制面 / 账号系统。

## 升级清单

### 1. 二进制 / 依赖

```bash
cd nanotun
go mod tidy
go build -o nanotund ./cmd/nanotund
```

主要运行依赖:

- `modernc.org/sqlite`(纯 Go SQLite 驱动,无 CGO)
- `golang.org/x/crypto/argon2`(PSK 散列)
- `github.com/apernet/hysteria`(可选 Hy2 入站)
- `github.com/xtls/reality`(可选 REALITY 入站)

### 2. 配置文件

最小可运行 `config.toml`:

```toml
[server]
listen_addr = ":8080"
# WebSocket 路径必须与客户端 profile 一致;不写则用默认长路径
vpn_websocket_path = "/internal/vpn-port/data-plane/ws/v1/<your-random-token>"

[tun]
device_name = "tun0"
subnets = ["10.200.0.0/16"]

[store]
# 首次启动会自动 mkdir + 跑 schema 迁移
db_path = "data/nanotun.db"

[admin]
# Web UI 留待后续里程碑(M2),目前 nanotun-admin CLI 已足够
enabled = false
```

详细字段含义见 `cmd/nanotund/config.toml`(完整 reference 样板)与
`config/config.go` 注释。

### 3. 创建用户 / 设备 / profile

```bash
cd nanotun-admin
go build -o nanotun-admin .

# 默认数据库路径与 [store].db_path 一致,建议导出环境变量
export NANOTUN_DB=data/nanotun.db

# 首次创建管理员账号(向导式,PSK 自动生成且只在这一次能看到明文)
./nanotun-admin init

# 追加普通用户
./nanotun-admin user add alice

# 生成客户端 profile(JSON / nanotun:// URL / QR 码)
./nanotun-admin profile gen alice --output alice.json
```

子命令完整列表 + 字段语义见 [`nanotun-admin/README.md`](../nanotun-admin/README.md)。

### 4. 客户端登录约定

`LoginReq` JSON 字段(详见 `util/protocol.go`):

| 字段 | 含义 |
|------|------|
| `name` | nanotun 用户名(`store.users.username`) |
| `token` | PSK 明文 |
| `device_uuid` | 客户端首次启动时生成、随后持久化的稳定 UUID(RFC 4122 v4) |
| `device_name` | 用户给设备起的名字,可空 |

服务端按以下优先级给设备分配 vIP:

1. `devices.fixed_vip_v4 / fixed_vip_v6`(管理员钉死;0008 起从 users 表迁到 devices 表,每台设备独立钉);
2. 该 device_uuid 已有的 lease 记录(沿用上次的 vIP);
3. 自动分配(从 `[tun].subnets` 中取)。

`Password` 字段保留只为反序列化兼容,新版客户端可以不填。

### 5. 关闭客户端互访隔离(mesh 关键)

历史 deploy 流程会安装 `tun-isolate.sh` 并由 `tun-setup.sh` 自动调用,
往 iptables 里灌一条 DROP 规则禁止虚拟 IP 互通。M0 起默认关掉:

- `cmd/nanotund/tun-setup.sh` 只在 `NANOTUN_TUN_ISOLATE=1` 时才会执行
  `nanotun-tun-isolate.sh`;
- `cmd/nanotund/tun-isolate.service` 移除了 `[Install]` 段,stock `systemctl enable`
  不再把它挂上 multi-user.target;
- 老用户升级后应当主动取消旧服务:

```bash
sudo systemctl disable --now tun-isolate.service
sudo /usr/local/bin/nanotun-tun-isolate-teardown.sh   # 清掉残留的 iptables 规则
```

如果确实希望保留历史隔离行为:

```bash
sudo systemctl enable --now tun-isolate.service
# 或 export NANOTUN_TUN_ISOLATE=1; tun-setup.sh
```

未来 mesh 内的访问控制走 `store/acl.go` 的 ACL 表,不再依赖 iptables。

### 6. 数据库版本与备份

- schema 版本写在 `app_settings.schema_version`,M0 落定为 `1`;新增 schema
  时在 `store/migrations/000N_xxx.sql` 追加。
- 备份只需要拷贝 `db_path` 指向的 `.db` 文件以及 `.db-wal` / `.db-shm`
  (WAL 模式)。
- **务必避免 DB 路径漂移**:`scripts/install-self-hosted.sh` 已经内置「K1
  Old DB 自检」,在脚本检测到旧路径存在用户但新路径为空时会拒绝继续。
  完整事故复盘见 `docs/POSTMORTEM-20260521-db-path-migration.md`。

### 7. 2026-05-26 拆字段升级路径(advertised_host → server_dial_host)

**背景**:历史上 `app_settings.advertised_host` 兼任「客户端 PacketTunnel 实际
拨号 host」+「客户端 UI 展示 label」两个角色,踩坑后(用户配
`test-203.0.113.10` 当 label 但被作为 dial 塞进 NEVPN 触发
`Invalid tunnelRemoteAddress`,隧道挂掉)拆出两个独立 setting:

| key | 角色 | 校验 |
|-----|------|------|
| `server_dial_host` | **客户端实际拨号目标** | 严格:IPv4 / IPv6 / RFC1035 末段含字母的合法域名,拒末段纯数字伪 hostname |
| `advertised_host`  | **客户端 UI 展示 label**(纯展示,不参与连接) | 宽松:任意短语 |

**升级动作**:

```bash
# 1. 全量升级到 0016 schema(NOP 迁移,只 bump 版本号,**不做数据 backfill**)
go build -o nanotund ./cmd/nanotund
./nanotund --migrate-only

# 2. 老库里 advertised_host 已经配过(老值通常是真实 IP),server_dial_host 还是空 →
#    Web dashboard 顶部红 banner「server_dial_host 未配置 — 服务器 QR 暂不可生成」。
#    若老值确实是合法拨号目标,可一键拷贝(CLI 只做语法校验,不跑 probe):
./nanotun-admin setting set server_dial_host "$(./nanotun-admin setting get advertised_host)"

# 3. 强烈推荐去 Web `/settings` 页用「保存」按钮再走一次 —— 会跑 DNS + ICMP probe,
#    避免老值是 `test-xxx` 这种 dial 不通的伪 hostname。
```

**Linux ICMP unprivileged ping(pro-bing)**:`nanotun-web` 在保存
`server_dial_host` 时跑 ICMP ping 做可达性检测。在 Linux 上需要内核
`ping_group_range` 包含 nanotun 的运行 group,否则 ping socket 创建失败 →
归类为 `ICMPSoftFail`(与「服务器 ban ICMP」无法区分),admin 只能勾选
「跳过 ICMP 可达性检测」绕过。一行 sysctl 即可永久放开:

```bash
# 临时(立刻生效,重启失效):
sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"

# 永久(写入 sysctl.d):
echo 'net.ipv4.ping_group_range = 0 2147483647' | sudo tee /etc/sysctl.d/99-vpn-port-ping.conf
sudo sysctl --system
```

macOS / FreeBSD / Windows 默认即可跑 unprivileged ping,无需配置。

**skip_probe 语义**(2026-05-26 第十一轮校正):勾选「跳过 ICMP 可达性检测」
**只跳过 ICMP softfail**,DNS 解析仍然必查 —— DNS 失败是硬错,任何
skip_probe 都不可入库。

**CLI 视角的可达性验证**(2026-05-27 第十五轮 backlog#3):
`nanotun-admin setting set server_dial_host <host>` 只做语法校验,**不**调
`ProbeServerDialHost` —— 因为运维笔记本网络环境通常与 server 不同(笔记本能
ping ≠ server 能 ping)。如果你在 **server 机器上**直接跑 CLI(SSH 部署流程
常见),可以用新加的 opt-in 验证工具确认可达性:

```bash
# 与 web 表单 POST /settings/server-dial-host 完全等价的 DNS+ICMP probe
./nanotun-admin setting probe-dial-host vpn.example.com

# 服务器 ban ICMP(Vultr / AWS / Linode 安全组默认)时,跳过 ICMP 但仍做 DNS:
./nanotun-admin setting probe-dial-host vpn.example.com --skip-icmp

# 字面 IP 跳过 DNS+ICMP,纯语法校验(包含 rejectedSpecialIP 黑名单)
./nanotun-admin setting probe-dial-host 203.0.113.10 --skip-icmp
```

验证通过后再跑 `setting set server_dial_host <host>` 落库 —— 两步分离避免
「在笔记本上 set 完后再去 server 上发现不可达」的部署回滚成本。

## 历史 legacy_backend 路径

已在 2026-05 彻底移除,不再支持回滚。`config.toml` 中如果仍有 `[backend]` /
`[auth]` 字段会被 `pelletier/go-toml/v2` 静默忽略(无 unknown key 校验);
建议升级时一并清理。
