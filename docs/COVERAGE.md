# 覆盖率怎么量

这套系统有两层测试，量的是完全不同的东西，任何单独一个数字都会误导人：

- **进程内单测**（`go test -cover`）：只统计单测进程里执行到的语句。
- **三机 e2e**（`scripts/e2e/`）：跑的是编译好的真二进制，跨进程、跨机器。它执行的
  代码在普通覆盖率剖面里**一个字节都不会记**，因为生产二进制没有插桩。

所以「`cmd/nanotund` 单测覆盖 59.3%」的正确读法是「40.7% 的语句没有被单测覆盖」，
而不是「40.7% 从来没人验证过」。出口选择、ACL 快照、子网路由这些被 e2e 反复压过的
路径全在那 40.7% 里。反过来，e2e 也扫不到报文畸形、非 INET class、上游反投毒这类
分支——真实流量里几乎不出现，却正是攻击面所在。

要看清全貌，得把两笔账合起来。

## 合并账怎么出

### 一、单测这一侧（要在 Linux 上跑）

macOS 上跑单测会漏掉所有 `*_linux.go`——那些文件在 darwin 上根本不参与编译，
既不进分子也不进分母，得出的百分比虚高。交叉编译出测试二进制丢到 Linux 机器上跑：

```bash
# 本机交叉编译
mkdir -p /tmp/lt
for p in $(go list ./...); do
  GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
    go test -c -cover -covermode=set -o /tmp/lt/$(basename $p).test $p
done

# 传到 Linux 机器,连同源码树(有测试读相对路径文件,CWD 必须是各自的包目录)
rsync -az --exclude=.git --exclude=dist ./ root@<linux>:/root/nttest/src/
rsync -az /tmp/lt/ root@<linux>:/root/nttest/bin/

# 逐包跑,CWD = 包目录
cd /root/nttest/src/cmd/nanotund && /root/nttest/bin/nanotund.test \
  -test.count=1 -test.timeout=40m -test.coverprofile=/root/nttest/cov/nanotund.cov
```

各包的 `.cov` 拼成一份（保留一行 `mode:` 头即可）。

### 二、e2e 这一侧（插桩二进制）

用 `go build -cover` 编出带插桩的三个二进制，部署上去跑完整 e2e，进程退出时会把
计数写进 `GOCOVERDIR`：

```bash
go build -cover -covermode=atomic -coverpkg=github.com/nanotun/server/... \
  -o /tmp/cov-bin/nanotund ./cmd/nanotund      # nanotun-web / nanotun-admin 同理
```

部署时三件事：

1. 两个 systemd unit 加 drop-in `Environment=GOCOVERDIR=<目录>`；
2. `nanotun-admin` 是 CLI，e2e 通过 ssh 直接调，用一层 wrapper 脚本注入 `GOCOVERDIR`
   （放 `/usr/local/bin/nanotun-admin`，真二进制改名放旁边）；
3. 跑完 `systemctl stop` 让进程正常退出刷盘，再把 `GOCOVERDIR` 收回来。

```bash
go tool covdata textfmt -i=<收回的目录> -o=e2e.cov
```

### 三、合并

```bash
scripts/coverage/merge-coverage.py unit-linux.cov e2e.cov coverage-gaps.txt
```

输出按包分「两边都覆盖 / 仅单测 / 仅 e2e / 都没有」四类。**只有「都没有」那一列
才是真正该补的空白**，`coverage-gaps.txt` 里是精确到语句块的完整清单。

## 四个坑（都踩过）

**`GOCOVERDIR` 不能放 `/root`。** `nanotun.service` 和 `nanotun-web.service` 都开着
`ProtectHome=yes`，`/root` 在它们的 mount namespace 里根本不存在，覆盖数据被静默拒写，
日志里只留一行 `coverage meta-data emit failed: ... no such file or directory`。
必须放在 unit 的 `ReadWritePaths` 覆盖的路径下，例如 `/var/lib/nanotun/cov`。
第一次采集就是这么白跑了两轮 e2e 才发现。

**阶段 70 的 `kill -9` 会吞掉计数器。** 插桩数据是进程正常退出时才落盘的，SIGKILL
直接丢。若 00–70 一口气跑完，`nanotund` 在阶段 0–6 攒的覆盖会连同那条命一起没掉。
得拆成两次服务生命周期：先跑 00–60 → `systemctl stop` 刷盘归档 → 重启 → 单跑 70 →
再 stop 刷盘。两批数据放同一目录，`covdata` 会自动合并。

**改了源码，旧剖面就作废。** 合并是按 `文件:起止行.列` 匹配语句块的。哪怕只是在
文件中间插入一个函数，其后所有行号位移，那个文件的 key 全部对不上，合并结果会把它
整片误算成「仅单侧覆盖」。改完代码要两边重新采集，别拿旧剖面凑。校验很简单：两份
`.cov` 的行数应当完全相同（当前是 11953）。

**拼剖面的输出别落在 `*.cov` 的通配范围里。** `{ for f in $COV/*.cov; do tail -n +2
$f; done; } > $COV/unit-linux.cov` 看着没问题，实际上输出文件自己也匹配那个通配，
`tail` 读自己写自己，几分钟就把 23G 根分区写满了。更阴的是 `rm` 掉之后 `df` 还是
100% —— 有个 `sftp-server` 还开着那个已删除的句柄，`du` 只算出 7G 而 `df` 报 23G，
得 `lsof | grep deleted` 找出来杀掉才回收。输出放到 `$COV` 外面就没这事。

## 当前基线（2026-07-28 晚，第 22 轮后重采）

全仓 18177 条语句，合并覆盖 **92.6%**，1346 条两边都没碰过。

| 包 | 总语句 | 两边 | 仅单测 | 仅 e2e | 都没有 | 合并覆盖 |
|---|---:|---:|---:|---:|---:|---:|
| `config` | 337 | 148 | 189 | 0 | 0 | 100.0% |
| `cmd/nanotun-web` | 4518 | 1226 | 3236 | 0 | 56 | 98.8% |
| `cmd/nanotun-admin` | 3002 | 830 | 2077 | 0 | 95 | 96.8% |
| `store` | 1879 | 666 | 1126 | 1 | 86 | 95.4% |
| `certs` | 84 | 0 | 77 | 0 | 7 | 91.7% |
| `util` | 675 | 233 | 378 | 0 | 64 | 90.5% |
| `cmd/nanotund` | 7545 | 3363 | 2227 | 945 | 1010 | 86.6% |
| `auth` | 137 | 83 | 26 | 0 | 28 | 79.6% |

采集时 e2e 两轮共 142 项断言全过（117 + 25，拆成两次服务生命周期是为了绕开阶段 70
的 `kill -9`，见下面第二个坑）。单测那一侧在 Linux 上跑，全仓 **87.4%**（不含子进程
插桩是 86.9%）；e2e 那一侧单独看是 41.2%。

**这一版的关键读数是「剩下的空白集中到了一个包」。** 1346 条里有 1010 条在
`cmd/nanotund`，其余七个包合起来只剩 336 条。也就是说数据面之外基本收口了，
下一轮该啃的地方没有悬念。

「仅 e2e」这一列从 1099 条掉到 946 条，且现在**全部**来自 `cmd/nanotund` ——
web / admin 的 `main()` 此前只有 e2e 摸得到，现在子进程冒烟测试（`go build -cover`
出插桩二进制、计数进 `GOCOVERDIR`）把它们挪进了「两边」，两个包的这一列都归零。

### 与前两版的差

| | 2026-07-27 | 2026-07-28 早 | 现在 |
|---|---:|---:|---:|
| 合并覆盖 | 77.5% | 84.8% | **92.6%** |
| 两边都没碰过 | 4078 | 2758 | **1346** |
| 单测（Linux，全仓） | — | 78.8% | **87.4%** |
| 空白集中度 | 分散在 8 个包 | 分散 | 75% 在 `cmd/nanotund` |

中间做的事记在下面「基线之后补掉的」表里。

### 剩下的 1346 条在哪

按文件排（完整清单在 `coverage-gaps.txt`，精确到语句块）：

| 条数 | 文件 | 性质 |
|---:|---|---|
| 205 | `cmd/nanotund/server.go` | 大半是 `main` 的启动编排与 IO 错误分支 |
| 126 | `cmd/nanotund/network_setup_linux.go` | 需要真 WAN 网卡 / 特定内核配置的分支 |
| 67 | `cmd/nanotund/magic_dns.go` | 上游超时、并发缓存竞争这类难构造的时序 |
| 46 | `cmd/nanotund/egress_select.go` | 出口裁决的罕见组合 |
| 35 | `cmd/nanotund/control_socket.go` | 控制面的 IO 错误分支 |
| 34 | `cmd/nanotund/acl_runtime.go` | ACL 快照重建的边角 |
| 34 | `cmd/nanotund/magic_dns_exit.go` | 出口侧 DNS 改写 |
| 28 | `auth/psk.go` | argon2 并发与失败路径 |

前 20 名里除了 `auth/psk.go`、`cmd/nanotun-web/sysmon_linux.go`（23 条）、
`util/protocol.go`（21 条），全是 `cmd/nanotund`。

几个单文件的数比上一版**大**（`server.go` 147 → 205），但 `cmd/nanotund` 的包级
「都没有」几乎没动（1007 → 1010）、「仅 e2e」也只从 955 掉到 945 —— 这一轮没碰过
这个包的源码，所以变化是**包内在文件之间挪位**，不是退步。具体挪了哪些说不准：
上一版的 `coverage-gaps.txt` 是生成物、没有留存，无法逐文件对账。两次 e2e 走到的
路径本来就不完全相同（`server.go` 的启动编排尤其吃这个）。下次重采前先把旧清单
归档一份，这笔账才能对得上。

## 补空白的顺序

按「都没有」的条数排，但别只看数字——`main` 那 96 条是进程启动编排，写单测的性价比
远低于同样条数的 ACL 判决。挑的时候看这三条：

1. **判错了会静默出错吗**（ACL、出口选择、地址校验这类，判错不崩溃，只是悄悄放行或
   悄悄黑洞）优先；
2. **是不是 e2e 结构上够不着的**（畸形输入、并发、平台分支）；
3. **要不要为了可测性动生产代码**——需要动的，照 `health.go` 的 `isLoopbackHost`、
   `network_rules.go` 的路数把判定抽成纯函数，`FatalExit` / IO 留在薄壳里。

补完必须做变异验证：把被测逻辑定点改坏，确认测试真的会红。只跑一遍看行数变亮不算数
——`listen_addr` 那个校验漏洞就是变异逃逸暴露出来的，测试照过，一查才发现那个分支
从来没被自己的用例走到过。

## 基线之后补掉的

按上面的排序逐块清理 `cmd/nanotund`。记在这里是为了下次不用翻 git log 反推进度。

| 轮次 | 目标 | 补掉 | 变异 |
|---|---|---:|---|
| 1 | `magic_dns.go` / `acl_runtime.go` 出口裁决 / `server.go` 地址助手 | 160 条 | 挖出 `listen_addr` 校验漏洞（已修） |
| 2 | `handleTakeoverLogin` 八条拒绝分支 + 两处竞态复验 | — | 21 个全抓住 |
| 3 | `handleVPNLink` 四道闸 + panic 隔离 + vIP 耗尽 | — | 16 抓 14，2 个是空转代码 |
| 4 | `runLinkTunnel` 帧分发与数据面执法链 | 71 条 | 24 抓 24 |
| 4 | `util.IPPacketTotalLen` / `TrimIPPacketToTotalLen` | 大门此前零测试 | 12 抓 9，3 个等价 |
| 5 | `jump_host_firewall.go` 白名单 + ipset/iptables 编排 | 91 条 | 34 抓 31，3 个等价 |
| 6 | `config` 全包（启动期配置闸、REALITY dest、smux、hysteria 凭证与调参） | 到 100% | 21 抓 19，2 个等价 |
| 7 | `store` 零覆盖函数（TOTP 重放、会话生命周期、PSK CAS 轮换、审计查询） | 零覆盖 33 → 0 | 26 抓 24 |
| 8 | `cmd/nanotund` 控制面 socket + 端口转发编排 + hysteria outbound + 后台循环 | 73.8% → 78.8% | — |
| 9 | `cmd/nanotun-admin` 写路径 / 控制面命令 / 列表视图 | 68.1% → 80.5%，零覆盖只剩 `main` | — |
| 10 | `util` ws 流适配 + 证书闸口 + wire 助手；`auth` 限流版 verify | util 70.1% → 90.5%，auth → 78.8% | — |
| 11 | `cmd/nanotun-web` 分发表 / 凭证 QR / 会话联表 / 私钥落盘 | 80.2% → 81.5% | — |
| 12 | `certs` 客户端证书签发闸口 | 71.4% → 91.7% | — |
| 13 | `store/web_admins*.go` 入参闸门 + DB 故障传播 | 97 条 → 12 条,store 79.8% → 84.3% | 33 抓 32,1 个等价 |
| 14 | `store` 大头:`acl` / `leases` / `devices` / `users(+helper)` | 各自 21→2 / 27→5 / 40→10 / 49→6,store → 90.4% | 与 15 轮合并跑 |
| 15 | `store` 尾巴:`migrations` / `canonicalize_vips` / `via6` / `subnet_routes` / `rate_settings` / `audit` / `port_forwards` / `server_id` / `sqlite` | store 90.4% → **95.4%**,未覆盖 86 条 | 61 抓 57 → 收紧断言后 5/5 全抓 |
| 16 | `cmd/nanotun-web` 登录入口:`handler_auth.go` 的拒绝面 | 94 条 → 19 条 | 20 抓 20 |
| 17 | `handler_me.go`(自助改密 / TOTP 绑定) | 77 条 → 11 条 | — |
| 18 | `handler_users.go` + `handler_admins.go` | 66→4 / 55→0 | 36 抓 36 |
| 19 | `handler_server_qr.go` / `handler_devices.go` / `handler_routes.go` | 65→2 / 56→0 / 59→4 | 65 抓 65 |
| 20 | web 零散块:`handler_misc` / `portforward` / `tls_cert` / `session` / `acl` / `control_client` / `config` / `render` / `captcha` / `pow` / `totp` / `ip_failures` | web 80.2% → 96.8% | — |
| 21 | `cmd/nanotun-web/main.go` 启动编排(含子进程冒烟) | 107 条 → 少数 | — |
| 22 | `cmd/nanotun-admin` 全面收口(见下节) | 80.5% → **96.7%**,未覆盖 98 条 | 35 抓 34,1 条无法确定性构造 |
| 23 | `cmd/nanotund` 数据面「静默出错」那一档:ACL 快照重建 / 出口裁决 / 出口列表 | `acl_runtime` 40→29、`egress_select` 53→38、`exits_list` 46→8,包 79.0% → 79.7%(macOS) | 21 抓 20,逃逸的那条见下 |

第 14/15 轮把 `store` 从 79.8% 推到 95.4%(未覆盖 86 / 1879 条)。剩下的基本进不去:驱动层的
`LastInsertId()` / `Commit()` / `RowsAffected()` 失败、`listMigrations` 对 embed FS 的防御分支
(文件名非法 / 版本号重复 —— 编译期就固定了)、以及 `ProbeServerDialHost` 需要真 DNS + ICMP 回包
的那几条。要再动就得引一个注入故障的 `database/sql/driver` 包装,性价比不如去啃 `cmd/*`。

这两轮里真正抓到东西的用例(不是补行数的):

- **事务半途失败必须整体回滚**。删设备 / 删用户时,清孤儿 `port_forwards` 那步失败却照样把行删掉,
  剩下的转发会被下一个注册同 UUID 的账号静默继承——外网入口换了主人,两边界面都看不出来。
  `SetDeviceFixedVIP` 同理:`--force` 释放对方 lease 失败却把地址钉上去,就是双占。
- **`RotateUserPSKAndEnsureCredential` 的原子性**。补 `credential_id` 失败时 `psk_hash` 必须跟着回滚,
  否则旧 PSK 已作废、新 QR 又生成不出来,用户被锁在门外而 admin 只看到一句报错。
- **迁移出错时版本号不许前进**,而且「版本号读不出来」绝不能当成 0 ——当成 0 会把非幂等的历史迁移
  (`ALTER TABLE ADD COLUMN`)重放一遍,比启动失败严重得多。构造手法是把 `schema_version` 往回拨一格
  再跑 `Migrate`。
- **存量 VIP 归一的跨表撞车**:`leases.vip_v6` 归一后撞上别的设备已钉的 `devices.fixed_vip_v6` 时要跳过 +
  把完成标记留在 `'0'`,下次启动重跑。落 `'1'` 就等于永久 no-op,残留的非规范写法再不会被处理。
- **`SettingsSet` 的纵深校验**。`mesh_enabled` 拼成 `flase` 时读路径兜底是 **true**(fail-open),
  「想关 mesh」会静默保持互通;限速键写歪则被静默当 0(= 不限)。这些校验不能只留在 CLI 那一层。
- **列表读到坏行要整体报错**,不能少一行。管理员看不到某个账号 / 某条已批准的网段,就以为它不存在,
  而它照样在生效。

新增的两个手法:

- `abortOnWhen(table, op, when)` —— 带 `WHEN` 的 `RAISE(ABORT)` 触发器。用来分辨「同一事务里第几步失败」,
  比如 `SetRateDefaults` 三个键各失败一次,验的都是同一个不变量:三个键同生同死,不留撕裂态。
- 往 INTEGER 列写 **REAL**(而不是 TEXT)。TEXT 在 SQLite 里排在所有数字之后,`WHERE at >= ? AND at < ?`
  会把坏行直接滤掉,`Scan` 根本走不到;写 `1000.5` 则留在数值域内,过得了 WHERE、卡在 `Scan` ——
  这才是 `QueryAudit` 那条扫描错误分支的构造方式。

变异逃逸这次同样是**用例没隔离干净**:拿不到迁移锁、坏 `device_id`、读不出版本号这三条,报的错
都来自另一道闸(SQLite 自己的写失败 / 外键 / 后续语句),把断言收紧到「报错原因必须是这一道」之后
全部抓住。剩一条 `SetRateDefaults` 第一个键失败时提前 commit 是等价变异——那时还没写任何东西;
换成第二、第三个键失败就立刻被抓。

第 13 轮引入了两个可复用的手段,后面几轮都在用:

- **`Options{ReadOnly:true}` / 已 Close 的 store** 两级故障注入。只读库让第一条写语句失败,
  已关库让 `BeginTx` 就失败 —— 两者覆盖的错误分支不同。要验的不变量很朴素:库挂了或只读时
  **没有任何一个 DAL 函数报成功**,也不能把存储故障归一成 `ErrNotFound`(那会让 handler 显示
  「账号不存在」而不是「存储不可写」,排查方向全错)。
- **`RAISE(ABORT)` 触发器**做精准故障注入(`abortOn` 助手)。前两种手段都只能让**第一条**语句
  失败,而最该验的是「事务里第二条失败要整体回滚」:改密的 UPDATE 成了但撤销旧会话的 DELETE
  失败,不回滚就是「密码已改、旧 cookie 仍有效」—— 改密根本没把攻击者踢下线。在 `web_sessions`
  / `web_admin_recovery_codes` 上装 BEFORE DELETE/INSERT 触发器就能精确制造这种失败。
  注意 BEFORE 触发器在**匹配 0 行时不触发**,构造时要确认目标行真的存在。

另外用「往 INTEGER 列写 TEXT」(SQLite 非 STRICT 表允许)模拟手工改库 / 迁移写坏。这类用例
的价值不在覆盖率:`failed_logins` 扫不出来若被静默当成 0,等于把已锁定的账号自动解锁。

第 13 轮的变异逃逸值得记一笔,四条里三条是**用例没隔离干净**——报的错来自另一道闸:
`CreateFirstWebAdmin` 的空用户名撞的是 `ErrSetupClosed`(库里已有 admin)、
`SetWebAdminRoleEnsuringAdmin` 的非法 role 撞的是 `ErrLastAdmin`(只有一个 admin)、
`EnableWebAdminTOTP` 的空恢复码撞的是 CAS 的 `ErrNotFound`(没设过 secret)。
三条都拆成独立用例、先把「别的闸不会响」布置好再断言。**光看行数变亮完全发现不了这类问题。**
唯一的等价变异是 `CreateWebSession` 的 `AdminID<=0`:外键 `REFERENCES web_admins(id)` 兜住了
同样的不变量,DAL 那道判断的价值只是给出一条清楚的错误。

剩下 12 条全是驱动层错误(`Commit()` / `PrepareContext()` / `LastInsertId()` / `RowsAffected()`
失败),用 SQLite 自身的手段构造不出来,要一个会注入故障的 `database/sql/driver` 包装。全包这类
包装只有 7 处,而 `if err := tx.Commit(); err != nil { return err }` 判错的风险极低 —— 性价比低
于去啃别的文件里的语义分支,暂时留着。

第 4 轮的等价变异记一下，省得下次重打一遍：`t < 20` 被 `ihl >= 20 && ihl <= t`
蕴含；`startWSSDataPlaneKeepalive` 自己也挡 `interval <= 0` 和 `missThreshold <= 0`，
调用侧那两处判断拆掉也没有可观察差异。`runLinkTunnel` 门口的 `ValidIPPacket` 与 ACL
对「解不出 tuple」的 fail-closed 互为兜底，拆掉任意一层畸形包都还是进不了 TUN——
门本身的边界钉在 `util` 那侧的用例里。

`runLinkTunnel` 还剩 4 条未覆盖，都是 `interceptExitDNSResponseIfPending` /
`forwardPacketToSubnetRoute` / `forwardPacketToExitNode` / `serverSelfEgressV6FastFail`
的 true 分支，这四个函数各有专门用例，从 readLoop 再走一遍是重复劳动。

### 第 22 轮:`cmd/nanotun-admin`(80.5% → 96.7%)

CLI 的坏法与 handler 不同:它没有 HTTP 状态码,只有**退出码 + 两条流**。所以这一轮的
断言几乎都围绕三件事:

- **退出码不许随环境漂移**。`kick user`(参数敲错)在 server 可达与不可达时都必须是 2。
  此前有几条命令先拨 control socket 再校验参数,于是「用法错」被报成「连不上」(exit 1),
  脚本没法判断。
- **落库 ≠ 生效**。ACL / 限速 / mesh 这些键都缓存在 server 内存快照里,不通知就只是改了行 DB。
  这一轮在 `acl add --json` 上抓到一个真缺陷:`--json` 分支直接 return,把通知 server、
  reload 提示、缺回程告警一并跳过 —— 脚本化加规则拿到一条「已创建」的 JSON,而数据面
  的 ACL 快照从没刷过,规则静默不生效;同一文件里的 `acl del` 反倒一直通知,两条路口径相反。
  修法是把通知/提示移出分叉(它们全走 stderr,不污染 `--json` 的机器可读 stdout)。
- **确定性的输出失败必须发生在落库之前**。`credentials --rotate-psk` 一旦落库,旧 PSK 立刻作废;
  之后才发现 `--output` 的目录不存在 = PSK 已换、明文从未交付,用户当场断连而运维手里也没有新密钥。
  `preflightCredentialsOutput` 的每一条判定都对着这个不变量。

故障注入这一侧新加了两个手法:

- **只挡一个 key 的写**(`abortSettingWrite`)。整表挡 `app_settings` 的 INSERT 会先把
  migration 挡掉 —— 命令在到达被测那行之前就 exit 1,用例照样"通过",但验的其实是
  migration 失败。这正是 `init` 的 `setup_completed` 那条变异逃逸的原因。
- **放宽 NOT NULL 后塞 NULL**(`relaxAppSettingsValue`)。`SettingsGet` 往 `string` 扫会报错,
  这是模拟「真·读故障」的唯一办法 —— 与「这个 key 没设过」(`ok=false`,不是 error)是两回事。
  `route approve` 读不出 mesh 网段时必须**拒**(交叠检查是 fail-closed)就是靠它验的。

为可测性动的生产代码只有一处接缝:`cmd_setting.go` 把 DNS 与 ICMP 探测收进
`probeLookupIPAddr` / `probeDialHost` 两个包级变量。`probe-dial-host` 的价值全在
**结果分类**(DNS 硬错 / 无记录 / 解到不可拨的特殊地址 / ICMP 软失败)上,而真去查网络
会让用例随宿主网络红绿漂移。

`main()` 本体(读 `os.Args`、`os.Exit`)照 `nanotun-web` 的路数用子进程冒烟测试覆盖:
设了 `NANOTUN_SUBPROC_COVERDIR` 就用 `go build -cover` 编,计数落进 `GOCOVERDIR` 并进合并账。

剩下的 98 条基本进不去,分三类:`crypto/rand` / `json.Marshal` 一个固定结构失败这类
「机器已经坏了」的分支;`copyFileAtomic` 的 `Chmod`/`Sync`/`Close` 失败(要一个写满的
文件系统);以及**代码里就走不到的空分支** —— `confirm()` 永远返回 `nil` error、
`openProfileOutput()` 的 error 恒为 `nil`,它们的 `if err != nil` 判断有六七处调用点,
真正该做的是把这两个函数的签名收掉,不是给它们编测试。

唯一一条抓不住的变异是 `writeFileTight` 里 `os.Link` 换成 `os.Rename`:两者只在
「Lstat 与落盘之间被抢建」这个 race 窗口里有区别,没有可移植的确定性测法。它靠注释与 review 守。

第 5 轮为了可测性动了生产代码：`jump_host_firewall.go` 里所有 `exec.Command` 与
`runtime.GOOS` 判断收进 `jumpFWExec` / `jumpFWOnLinux` 两个变量。这段编排只在生产的
Linux 上执行，开发机没有真 iptables、三机 e2e 也没开这个开关，所以「装出来的规则集
长什么样」此前从没被验证过——而它判错既不报错也看不出来。等价变异同样记一下：
`net.IP.String()` 自己就会把 v4-mapped 归一，所以 `To4().String()` 换成 `String()`
没有可观察差异；`teardownImpl` 的非 Linux 判断被 `installed` 标志盖住（非 Linux 上
`installed` 恒为 false）；`Teardown` 的 `sync.Once` 同理。

### 第 22 轮的修复在三机上复核过（2026-07-28）

`acl add/deny --json` 漏通知是单测抓到的，但它的**后果**只在跨进程这一层可见 —— 单测能证明
「通知函数被调了」，证不了「数据面真的开始拦」。所以在阶段 20 补了三条断言：`--json` 的
stdout 仍是可解析 JSON、规则同样即时生效、提示确实走 stderr（`2>` 重定向后 stdout 干净）。

部署前先在服务端拿旧二进制实测了一次,算是对缺陷判断的独立确认:`acl deny … --json` 的
stderr **空**,而紧接着的 `acl delete` 打了「ACL snapshot has been refreshed」—— 同一命令族
两条路口径相反,与代码读出来的结论一致。换上 `c8751d4` 的二进制后 stderr 有提示、stdout
不变。

随后跑了全量:132 项断言全过,退出码 0,6.5 分钟。这一轮改的产品代码除 `cmd_acl.go` 外都是
测试接缝(函数改包级变量、`rand.Read` 改 `randRead`,默认值不变)与一处等价重构
(`main.go` 的 PoW GC 内联 goroutine 收成 `runPoWGC` 方法),阶段 0/6/7 的全绿也顺带确认了
这些接缝没有改变启动编排与 Web 面的行为。

### 第 23 轮:`cmd/nanotund` 的「静默出错」那一档

按「补空白的顺序」第 1 条挑的:ACL 快照重建、出口裁决、出口列表。这三处判错都不报错、
不掉线,只表现成用户那头「网怪怪的」，所以优先级排在条数多得多的 `main` 启动编排前面。

真正值得记的是**断言该断在哪**:

- **「读不出设置」与「这个 key 没设过」必须分开。** `reloadACLSnapshotFromStore` 里两者
  的正确行为恰好相反 —— 前者要返回 err 且**原样保留旧快照**,后者落到内置默认 allow。
  只断 `err != nil` 是不够的:一个「先把快照换成空规则 + allow、再返回 err」的实现同样
  满足它,而那正是最坏的结果(default-deny 被一次 DB 抖动翻成全放行,且无告警)。用例断的
  是**快照指针不变** + 旧的 deny 规则仍在拦。
- **fail-closed 兜底只能由手抠 DB 触发。** `acl_default_action` 写路径自己就拒非法值,
  所以用例得直写 SQL 才进得去那条分支 —— 顺手把「写路径确实在拦」也钉成断言,这样两层
  防御各自的责任都写在测试里。
- **「查不动」不是「未批准」。** `resolveApprovedExitDeviceID` /
  `deviceHasApprovedExitRoute` 都返回 `(值, ok)`,ok=false 意味着无法判定。混为一谈的话,
  一次 DB 抖动就会撤销仍然有效的出口绑定,或把用户想避开的 server 自出口静默给他。
  三种入口(无 store、deviceID=0、DB 报错)分别钉。

两次变异逃逸都出在同一种写法上,值得当模板记住:**用例里让同一个对象同时满足正反两边,
去掉判定后结果不变**。第一次是「同一台设备既宣告了 LAN 段又宣告了出口」——去掉
`IsExitDefaultRoute` 过滤照样解析到同一个 device;改成「只批了 192.168 段的设备绝不能
被解析成出口」才抓得住。`buildExitsList` 第 ④ 步那条一模一样。

`isRunningExitConn` 是这一轮唯一动的产品代码:`buildExitsList` 的 ① 快照与 ③ 复核本来
手抄了两遍同一判据,而 ① 还多查一个 `deviceID != 0`,属于随时会漂移的重复。抽成一处之后
判据本身可以直测。

还剩一条变异逃逸,是结构性的:③ 复核守的是「② 查 DB 期间会话状态翻转」那个窗口,
单线程单测开不出来 —— 要么给生产代码加一个纯为开窗存在的钩子。判据抽出来后至少
「判据认不认这几种失效状态」钉住了,调用时序靠 e2e 里出口接管/重登那几条。

后半轮接着补 `route_advertise.go`(49 → 17)与 MagicDNS 一家四个文件
(`magic_dns.go` 93 → 42、`_exit.go` 36 → 19、`_cache.go` 30 → 12、`_intercept.go` 15 → 7),
包覆盖 80.3% → 81.6%。这半轮的教训集中在**「用例形状对不对」**上,变异测试基本全是替我
指出这一点:

- **重名裁决必须绕开去重那道口子才测得到。** `lookupMagicHost` 对同名设备取 device_id
  最小的那台,但 `UpsertDevice` 会给撞名的自动追 `-1`,走它根本造不出两台同名。得直写
  SQL —— 而这恰好也是这段代码真正服务的场景:唯一性强制生效**之前**登记的存量重名。
  断言还要跑多次,因为「取遍历顺序第一个」的实现会随两台机器 last_seen 的更新来回漂移。
- **「返回了 cleanup」证不了「没起 listener」。** `startMagicDNS` 的六条 no-op 路径,
  只断 cleanup 非 nil 的话,一个「非法 listen_addr 照样绑」的实现也能过 —— 而
  `addr.IP=nil` 会被 `ListenUDP` 当成 `0.0.0.0`,把本该只在 TUN 上听的内网 DNS 摆到
  所有网卡,包括公网口。改成调完立刻去 bind 那个端口:绑得上才说明真的没起。
  「未启用」那条还得把端口显式写成探测端口 —— 留空会走默认 53,而「绑 53 需要 root」
  会让「其实起了 listener」的实现**碰巧**也失败,用例就空过了。
- **验「取最小」的用例里,几个值必须不相等。** `parseExitDNSResult` /
  `parseRawDNSMeta` 都取答复区最小 TTL,原来的用例每条答复给同一个 TTL,于是取最大的
  实现结果一样。改成 300/45/90 三条、最小值刻意放中间,顺带排除「取最后一条」。
- **越界检查要在**足够长**的包上验。** `dnsQuestionEnd` 拒绝 question 段里的压缩指针;
  短包里去掉这道检查,`0xc0` 会被当成长度 192、一步跨过包尾,照样落到「越界」那条
  `return false` —— 两种实现结果相同。得给一个 220 字节的包、让指针跳到的位置恰好是
  0 字节,缺检查的实现才会返回一个在界内的**假**偏移。

两条判定为等价、不再追的:`tryResolvePublicViaExit` 里对 fail-closed 哨兵的显式判定
(去掉后 `lookupRunningExitConnByDevice(-1)` 也查不到,结果相同 —— 它是可读性分支,
不是唯一防线),以及拦截路径上关联端口的区间预筛(waiter 只可能登记在区间内,真正的
门是那次 map 查找)。

`route_advertise` 那半轮还暴露了一个**测试自身**的 data race:撤回出口会
fire-and-forget 一条 `broadcastExitsList`,它读 `gatewayInstance`,而子测试的
`t.Cleanup` 同时把值改回去。修法不是加 sleep,而是挂一条只收广播的 exit_allowed 会话、
等那一帧到达 —— 既建立了 happens-before,又顺带把「撤回后必须立刻重算并推送」钉成
断言(否则已撤回的出口要留在别人的下拉里直到它下线)。

## 单测这一侧的现状（2026-07-28 晚，Linux 实测）

零覆盖函数已经清空，只剩三个 `main` —— 那三个各有子进程冒烟测试（`nanotund` 靠 e2e）。

Linux 列是在客户端主机 A 上跑交叉编译的测试二进制实测的（`go test` 打印的那个数）：

| 包 | macOS | Linux 实测 | 计子进程插桩后 | 差额来自 |
|---|---:|---:|---:|---|
| `config` | 100.0% | 100.0% | 100.0% | — |
| `cmd/nanotun-web` | 97.4% | 97.0% | **98.8%** | `sysmon_linux.go`；子进程补 `main()` |
| `cmd/nanotun-admin` | 96.7% | 96.5% | **96.8%** | `db_holders_linux.go`；子进程补 `main()` |
| `store` | 95.4% | 95.3% | 95.4% | — |
| `certs` | 91.7% | 91.7% | 91.7% | — |
| `util` | 90.5% | 90.5% | 90.5% | — |
| `auth` | 78.8% | 79.6% | 79.6% | argon2 并发路径 |
| `cmd/nanotund` | 78.8% | **74.1%** | 74.1% | `network_setup_linux.go` 等 |

web / admin 两边只差 0.2–0.4 个点，说明第 16–22 轮补的确实全是平台无关代码。
`cmd/nanotund` 仍是唯一的洼地。

采集这一侧踩到两件事，都值得记：

- **`go build` 需要模块缓存，而目标机的出站可能绕着 VPN 走。** 主机 A 的默认路由在
  `nanotun0` 上（它拿 C 当出口），从它下载 Go 发行包只有 ~110 KB/s。临时
  `systemctl stop` 掉客户端会话、让流量走自己的 WAN，`go mod download` 从 20 分钟
  变成 37 秒。注意 e2e 的客户端是 `systemd-run` 建的**临时 unit**，停掉即消失，
  不能用 `systemctl start` 拉回来 —— 交给阶段 00 自己重建。
- **子进程冒烟测试的超时预算别把编译算进去。** `runWebBinary` / `runAdminBinary`
  原本先 `context.WithTimeout(60s)` 再调 `buildXxxBinary()`，于是那次**整轮只做一次**
  的编译占用了「跑一次二进制」的预算。开了 `-cover` 要插桩整个 module，在 1 核机器上
  编一次将近 3 分钟，第一条子测试就以 `context deadline exceeded` 假失败（本轮实际
  撞上了，`nanotun-admin` 因此 rc=1）。改成先编、再开始计时。

跑全量回归时注意 `-race` 下 `cmd/nanotun-web` 要 **12 分钟**（子进程编译 + 探测等待），
超过 `go test` 默认的 10 分钟 timeout。用 `go test ./... -race -timeout 25m`，
否则会看到一个纯粹由 timeout 造成的假失败。

只有 `cmd/nanotund` 两边差得明显：macOS 上 `*_linux.go` 根本不参与编译，那 700 多条
语句既不进分子也不进分母。**报数要报 Linux 的那一列**，macOS 的数偏乐观。

那些 Linux-only 的空白基本都被 e2e 接住了（合并后 `cmd/nanotund` 到 86.6%）：

| 文件 | 单测 | 说明 |
|---|---:|---|
| `network_setup_linux.go` | 大部分 0% | 启动期 iptables / sysctl 编排，e2e 每次起服务都走 |
| `iptables_sweep_linux.go` | 0% | 启动 sweep，阶段 70 专门验它 |
| `sdnotify_linux.go` | 0% | 只在 systemd 下有意义 |
| `exit_guard_linux.go` | 0% | 出口私网守卫，需要真 WAN 网卡 |

为可测性动过的生产代码（都是薄壳/接缝，不改行为）：`cmd/nanotund/port_forward.go`
的 `pfExec`（`ip route` / `iptables` 收进一个变量）、`cmd/nanotun-web/main.go` 的
`sessionGCInterval`（原本硬编码 10 分钟，测不到清理体）、`auth` 侧的 `ResetForTest`。

## 采集脚本

`scripts/coverage/` 下三个脚本把上面的流程固化了：

| 脚本 | 在哪跑 | 干什么 |
|---|---|---|
| `run-linux-unit.sh` | Linux 机 | 逐包跑交叉编译好的测试二进制，拼出 `unit-linux.cov`；顺带把子进程插桩计数转成 `subproc.cov`，两者合成 `unit-side.cov`（合并时要用的是它） |
| `deploy-instrumented.sh` | SRV | 换插桩二进制 + 接好 `GOCOVERDIR` + admin wrapper |
| `restore-plain.sh` | SRV | 上一条的逆操作，采集完务必执行 |
| `merge-coverage.py` | 本机 | 合并两侧，出四象限表和精确空白清单 |
