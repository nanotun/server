# nanotun-admin

`nanotun-admin` 是 nanotun 自托管模式（PSK）下的本地管理 CLI。它直接读写 nanotun 的 SQLite 文件，不经过网络，适合在服务器上 SSH 登录后用、写在 systemd `ExecStartPre` / Ansible playbook 里、或者临时排障。

> 本工具与 M2 计划落地的 admin Web UI 功能正交：能 SSH 上服务器的运维用 CLI；终端用户用 Web UI。

## 安装

```bash
cd /path/to/nanotun
go build -o nanotun-admin ./cmd/nanotun-admin
sudo install -m 0755 nanotun-admin /usr/local/bin/nanotun-admin
```

或在部署脚本里跟 `nanotund` 一并 build：参见 `scripts/build-release.sh`（交叉编译打包）。

## 全局 Flag

| Flag | 默认值 | 说明 |
|------|-------|------|
| `--db-path PATH` | `data/nanotun.db`（env `NANOTUN_DB`） | SQLite 路径 |
| `--json` | false | 以 JSON 输出（脚本化用） |
| `--yes`, `-y` | false | 危险操作（删除用户/设备）跳过二次确认 |

## 常用流程

### 首次部署：创建第一个管理员

```bash
sudo mkdir -p /var/lib/nanotun
export NANOTUN_DB=/var/lib/nanotun/nanotun.db

nanotun-admin init
# 管理员用户名 [admin]: wenhai
# 管理员 PSK（回车自动生成）:
# ✓ nanotun 管理员账号已创建
#   username: wenhai
#   PSK:      D7D7U-ZPVXX-ESALI-UKHWB-MLDGE-GGJZ5-OB
```

PSK 仅在本次输出里出现一次，请立刻把它录入客户端。

> 之后把 `cmd/nanotund/config.toml` 里 `[store].db_path` 改成 `/var/lib/nanotun/nanotun.db` 并重启 nanotun 即可(目前 PSK 是唯一认证模式,不需要额外开关)。

### 用户管理

```bash
# 创建用户（PSK 自动生成）
nanotun-admin user create alice --admin --exit-allowed=true

# 创建用户 — 注意 0008(2026-05-23)起 fixed_vip 按 **设备** 维度配置,
# 用户创建时不再有 --fixed-vip-* 标志。流程改为:用户登录一次自动注册 device,
# 然后再用 `nanotun-admin device set-fixed-vip <device_id> --v4 ...` 给该设备钉死。
nanotun-admin user create bob

# 列表(默认仅活跃账号)
nanotun-admin user list
nanotun-admin --json user list

# 列表(含已禁用)— P1#7,2026-05-26 新增
nanotun-admin user list --all

# 详情
nanotun-admin user show alice

# 重置 PSK
nanotun-admin user reset-psk alice               # 自动生成
nanotun-admin user reset-psk alice --psk hunter2  # 指定明文

# 临时禁用 / 恢复
nanotun-admin user disable alice
nanotun-admin user enable  alice

# 永久删除（级联清理 devices/leases/acl）
nanotun-admin -y user delete alice
```

### 设备 / vIP 租约

设备记录由 nanotun 在登录时按 `device_uuid` upsert，无需手动创建。

```bash
nanotun-admin device list
nanotun-admin device list --user alice
nanotun-admin -y device delete 7

nanotun-admin lease list
nanotun-admin lease release 7                          # 让该设备下次登录重新分配
nanotun-admin lease set 7 --v4 100.64.0.50 --manual    # 钉死，不被自动分配器改写
```

### ACL

> ✅ **数据面已接入（P0-1，2026-05-22）：`acl_pairs` 规则在 nanotun 进程内被强制执行。**
>
> 启动 / `SIGHUP` 时 `nanotun` 会一次性把 `acl_pairs` 拉成 in-memory snapshot
> （详见 `cmd/nanotund/acl_runtime.go`），TUN demux 路径上每个 IP 包根据 `srcUserID`（来自连接登录态）
> 和 `dstUserID`（按目的 vIP 反查 `vipOwner` 表）做 O(1) 裁决：命中 deny → drop（不入 TUN），
> 命中 allow / 同用户 / 无规则 → 放行。零 DB I/O 在 per-packet 热路径上。
>
> **改完规则要让运行中进程生效**，执行：
>
> ```bash
> kill -HUP $(pidof nanotund)     # 或 systemctl reload nanotun
> ```
>
> `journalctl -u nanotun` 会看到 `[reload] acl 规则集已刷新 rule_count=N`；
> 同时 `audit_logs` 写入一条 `config.reload applied=[acl_rules]` 便于追溯。

`acl_pairs` 表里没规则时 nanotun 默认全网放行；一旦添加规则即转为「白名单」语义：

- 同 userID 间永远放行（同账号多设备 mesh 互通）
- 显式 `allow` 规则放行（src=0 或 dst=0 表示通配）
- 显式 `deny` 规则拒绝（同优先级下 deny 胜 allow）
- 有任何规则但本对 src→dst 没命中 → 默认 deny（白名单语义）

```bash
nanotun-admin acl allow alice bob          # 允许 alice → bob
nanotun-admin acl deny  alice carol        # 拒绝 alice → carol（deny 优先于 allow）
nanotun-admin acl allow alice '*'          # 允许 alice 访问所有人（src 通配同理用 '*'）

nanotun-admin acl list
nanotun-admin acl del 3

# 改完别忘 reload，让运行中的 nanotun 把新规则装进 in-memory snapshot
kill -HUP $(pidof nanotund)
```

### 设置（app_settings）

```bash
nanotun-admin setting list
nanotun-admin setting get setup_completed
# 注:历史 default_cidr_v4 / default_cidr_v6 已在 schema v5 删除;网段唯一真源是
# config.toml 的 [tun].subnets / subnets_v6,改 setting 不会影响 vIP 分配。
```

### Profile 吊销(已移除,2026-05-25)

P2#14 历史上提供过 `profile revoke <pid>` 链路,把单张已发出的 profile QR 加入
黑名单。0013 credentials 解耦后 profile QR 不再含 PSK,被截屏泄露也无法登录;
0014 移除了 pid 字段、`profile revoke / unrevoke / revocations` 子命令以及配套
的 server 侧 `revoked_profiles` 表读写代码(SQLite 表本身保留作 dead table)。

需要让用户登不上,请改用:
- `nanotun-admin user disable <user>` —— 全设备封;
- `nanotun-admin user reset-psk <user>` —— 旧 credential 立刻失效;
  也可走 `nanotun-admin credentials show <user> --rotate-psk` 同步取新凭证 QR;
- 已在线会话由 `user_invalidate` 周期扫描在 ≤ 10s 内主动踢线。

### Credentials(0013 起)

profile / credentials 解耦后,credentials 子命令负责导出 `nanotun-cred://v1` 凭证:

```bash
# 用现有 PSK 重新导出凭证(校验明文与 hash 匹配,不变 PSK)
nanotun-admin credentials show alice --psk hunter2 --format qr

# 一次性 rotate:生成新 PSK + 写库 + 输出新凭证(等价 user reset-psk)
nanotun-admin credentials show alice --rotate-psk --format qr-png --output alice-cred.png

# 列表:已发过凭证(credential_id 非空)的所有用户,**含 disabled**(运维要看「禁用
# 但仍持有 UUID」)。table 默认包含 USERNAME / CREDENTIAL_ID / CREATED_AT / DISABLED。
nanotun-admin credentials list
nanotun-admin --json credentials list
```

JSON 输出示例(`credentials list --json`):
```json
[
  {
    "username": "alice",
    "credential_id": "0d4b1c4e-3a2f-4f7e-9c8d-12345678abcd",
    "credential_created_at": 1716530400
  },
  {
    "username": "bob",
    "credential_id": "8e2a59d1-fa11-4234-9d11-aaaaaa00bbbb",
    "credential_created_at": 1716000000,
    "disabled_at": 1716200000
  }
]
```

`user show --json` 在 user 视角同步暴露 `credential_id` / `credential_created_at`,
方便运维脚本一处取齐两端口径:
```bash
nanotun-admin --json user show alice
# {"id":3,"username":"alice", ..., "credential_id":"0d4b1c4e-...", "credential_created_at":1716530400}
```

老 user(0013 之前建,`credential_id` 为空)首次跑 `credentials show <user>` 会
**幂等 backfill**:写一行 UUID v4 + 当前时间到 users 表;后续多次调用 UUID 保持不变,
client 按 UUID 索引覆盖旧 PSK 的契约成立。

### Subnet route(P2#12)

> ⚠️ **任意 CIDR 的数据面尚未接入**:`route approve <任意网段>` 暂不会真正承载流量
> (server 启动横幅 + admin CLI 会显式提醒)。详见 `docs/DESIGN_SUBNET_ROUTES.md`。
>
> ✅ **例外:出口节点 `0.0.0.0/0` / `::/0` 数据面已落地**(exit-node)。`route approve <device> 0.0.0.0/0`
> 后,该 device 在线且会话 `exit_allowed` 时,选它当出口的用户公网流量会真正经它转发(由出口客户端本机
> NAT 出公网)。详见 `docs/DESIGN_EXIT_NODE.md`。

```bash
nanotun-admin route list
nanotun-admin route list --device 12
nanotun-admin route list --user alice
nanotun-admin route list --status pending

nanotun-admin route approve 12 192.168.1.0/24
nanotun-admin route reject  12 10.0.0.0/8  --reason "私网冲突"
nanotun-admin route delete  12 192.168.1.0/24

# 出口节点:批准某 device 为公网出口(数据面已生效)。
nanotun-admin route approve 12 0.0.0.0/0
```

### 运行时控制(经 unix socket)

下面这些命令通过 `--control-socket`(默认 `/run/nanotun/control.sock`,env `NANOTUN_CONTROL_SOCKET`)与 server 进程实时交互,不动 SQLite。

```bash
nanotun-admin reload [acl]                # 让 server 热重载 ACL snapshot,等价 SIGHUP
nanotun-admin kick session <conn_id>      # 踢一条会话
nanotun-admin kick user    <username>     # 踢该用户所有会话
nanotun-admin connection list             # 当前 connIDMap 快照(JSON 友好)
```

`/status` JSON 同时暴露 ACL 丢包、user invalidate 踢线、lease GC、`magic_dns`(P2#11)、`route_advertise`(P2#12)等计数,方便巡检脚本拉取。

### Magic DNS(P2#11)

server 内置 stub DNS,把 peer 主机名 `<device>.<user>.<suffix>` 解析为 vIP。配置见 `cmd/nanotund/config.toml` 中的 `[server.magic_dns]`:

```toml
[server.magic_dns]
enabled = true
domain_suffix = "lan"
listen_port = 53            # 必须 = 53,见下方关键约束
upstream_v4 = ["223.5.5.5"]
```

**关键约束**(三点 deployment 陷阱):

1. **`listen_port` 必须 = 53**。客户端拿到的 DNS server 列表只是 IP 字符串,OS stub resolver 永远打 :53。非标端口下 server 会跳过 prepend(`Warn` 一次),客户端 DNS 维持 `[tun].dns_servers_v4`。
2. **与系统 DNS 服务冲突**:
   - `systemd-resolved` 默认 listen `127.0.0.53:53`(具体 IP),与 server 的 `100.x.x.x:53` IP 不同,**不冲突**。
   - `dnsmasq` / Pi-hole listen `0.0.0.0:53`(全 IP)会和 server 冲突 → bind 失败 → magic_dns 模块不起(主进程继续跑)。修法:dnsmasq 改 `bind-interfaces` + `listen-address=127.0.0.1`,或换非标端口 + 自做 53→5353 转发。
3. **权限**:server 已 root 启动(TUN 需要),:53 没成本;rootless 容器需 `cap_net_bind_service`。

### 备份 / 恢复 / 压缩(P1#10)

```bash
nanotun-admin backup  /var/backup/nanotun-$(date +%F).db   # VACUUM INTO,一致性快照
nanotun-admin vacuum                                         # 在线 VACUUM,回收空闲页
nanotun-admin restore /var/backup/nanotun-2026-05-22.db    # ⚠️ 覆盖现 DB(会 prompt)
```

### 配置 lint(J4,2026-05-22)

```bash
nanotun-admin config lint /etc/nanotun/config.toml
# 退出码:
#   0  配置干净,可放心 systemctl restart
#   3  存在未知字段(可能拼错或已废弃);stderr 列出字段名
#   4  TOML 语法错;stderr 含原始解析报错
#   1  I/O 错(文件不存在 / 权限不足)
```

强烈建议在 CI / Ansible / 升级脚本里 `systemctl restart nanotun` 之前先跑一次,
避免因为拼错字段名(常见:`lease_gc_idle_day` 漏 s)被 server lenient 解析时
静默忽略,默认值偷偷生效。

server 本身默认 lenient(未知字段只 WARN,不阻塞启动),环境变量
`NANOTUN_CONFIG_STRICT=1` 可升级为 fatal:
```bash
NANOTUN_CONFIG_STRICT=1 ./nanotund -config config.toml
```

## 脚本化示例

在 CI 里批量预置用户：

```bash
for u in alice bob carol; do
  out=$(nanotun-admin --json user create "$u")
  psk=$(echo "$out" | jq -r .psk)
  echo "$u $psk" >> /tmp/psks.txt
done
```

## 安全说明

- `nanotun-admin` 直接对 SQLite 文件读写，**不会**通过网络。请确保数据库文件权限为 `600`，仅 nanotun 进程与运维账号可读。
- PSK 在创建 / 重置时通过 stdout 一次性返回；之后只保留 argon2id 哈希，无法反推。
- `user list --json` 已剔除 `psk_hash` 字段，可放心 `tee` 到日志。

## audit action 命名约定(2026-05 双轨制)

`audit_logs.action` 列**有意保留两种风格**,运维写报表 / 过滤前请按下表选对前缀:

| 风格 | 示例 | 适用场景 | 过滤方式 |
|------|------|----------|----------|
| `xx.yy.zz` (dot, hierarchy) | `login.success` / `login.fail.bad_psk` / `login.takeover.fail.<reason>` / `acl.drop.agg` | server 自身热路径,可能扇出多个子分类 | `audit list --action-prefix login.fail` 一次抓全部失败 |
| `xx_yy` (underscore, flat) | `user_create` / `user_reset_psk` / `device_set_fixed_vip` / `credentials_rotate_psk` / `webadmin_create` / `totp_setup_start` | admin CLI / Web Console / control-socket 触发的 CRUD,无子分类 | `audit list --action user_reset_psk` 精确匹配 |

不要为「统一」把 dot 改成 underscore — 会丢掉 `--action-prefix` 一键过滤的能力,
admin 排错时只能逐 verb 写一长串过滤,得不偿失。新增 runtime action 时维持 dot,
新增 CRUD action 时维持 underscore。`store/audit.go` 的注释也以这张表为准。

### `user_reset_psk` 家族(第六/七/八轮深扫引入)

PSK 重置是高频高风险动作(同时变更凭证 + 立即让历史会话失效),把四种结局拆成
独立 action 后,运维可以用 `--action-prefix user_reset_psk` 一次取齐再按后缀分桶:

| Action | 触发场景 | 修复建议 |
|--------|----------|----------|
| `user_reset_psk` | 成功完成 rotate + backfill | 无 |
| `user_reset_psk_raced` | CAS 失败 — 另一管理员已先一步重置;**caller 拒绝下发 QR** | 刷新 user 状态再操作 |
| `user_reset_psk_failed` | RotateUserPSKAndEnsureCredential 报通用错(DB / hash 故障) | 看 detail 的 `err=...` |
| `user_reset_psk_stash_failed` | PSK 已落库,**但 flash 暂存失败**,Web 没拿到展示 QR | 重置一次拿新 QR |

四种均为 underscore 双轨;同一管理员动作出现 `_raced` + `_stash_failed` 是异常组合,
应优先排查 DB 写入路径。Web 路径 actor 是 `web:<username>`;CLI 路径是 `admin-cli`。

### audit `detail` 字段约定(第九轮深扫引入)

audit_logs.detail 列是自由文本,但常用字段约定走 `key=value` 空格分隔,便于 grep:

| key | 含义 | 来源 |
|-----|------|------|
| `username` | 目标用户名(优先于历史 `user=`,与 Web `FormatDetail` 对齐) | 所有 user_* action |
| `reason` | 失败 / 拒绝原因(underscore short id,如 `concurrent_rotation_by_peer_admin`) | failed / raced 路径 |
| `via` | 入口标识(underscore,与 action 双轨一致),已枚举值:`web_reset_psk` / `user_reset_psk`(cmd_user) / `credentials_show`(cmd_credentials) | 多入口的 sibling action |
| `err` | 系统层错误 message(短一行,长 stack 走 log,不进 audit) | failed 路径 |
| `from` / `to` | 状态翻转的两端,如 `mesh_toggle` 的 `from=true to=false` | toggle 类 action |

新增 sibling action 时:detail 的关键字段应至少含 `username`(若涉及用户)+ `via`
(若多入口),让 `audit list --action X | grep "via=Y"` 能立即区分来源。**禁止**
在 detail 里写 PSK / token / cookie 等任何凭证 —— audit 日志长期持久化,把它当
密文存储区是严重事故。

## 退出码

| 退出码 | 含义 |
|-------|------|
| 0 | 成功 |
| 1 | 业务/数据库错误(具体错误打到 stderr) |
| 2 | 用法错误(unknown subcommand、缺少必填 flag) |
| 3 | `config lint`:未知字段(疑似拼写错误或废弃配置) |
| 4 | `config lint`:TOML 语法错 |
