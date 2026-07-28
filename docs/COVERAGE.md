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

## 当前基线（2026-07-28）

全仓 18182 条语句，合并覆盖 **84.8%**，2758 条两边都没碰过。

| 包 | 总语句 | 两边 | 仅单测 | 仅 e2e | 都没有 | 合并覆盖 |
|---|---:|---:|---:|---:|---:|---:|
| `config` | 337 | 148 | 189 | 0 | 0 | 100.0% |
| `certs` | 84 | 0 | 77 | 0 | 7 | 91.7% |
| `util` | 675 | 233 | 378 | 0 | 64 | 90.5% |
| `cmd/nanotund` | 7545 | 3357 | 2226 | 955 | 1007 | 86.7% |
| `cmd/nanotun-web` | 4524 | 1145 | 2543 | 101 | 735 | 83.8% |
| `cmd/nanotun-admin` | 3001 | 791 | 1630 | 38 | 542 | 81.9% |
| `store` | 1879 | 667 | 832 | 5 | 375 | 80.0% |
| `auth` | 137 | 83 | 26 | 0 | 28 | 79.6% |

采集时 e2e 两轮共 138 项断言全过（113 + 25，拆成两次服务生命周期是为了绕开阶段 70
的 `kill -9`，见下面第二个坑）。单测那一侧在 Linux 上跑，全仓 78.8%。

「仅 e2e」合计 1099 条。它主要是 `cmd/nanotund` 的 955 条 —— 启动期的 iptables /
sysctl 编排、systemd 通知、出口守卫这些，单测结构上就摸不到。这一列比上一版
（2008 条）少了，不是 e2e 退步了，是那部分代码现在单测也覆盖到了，从「仅 e2e」
挪进了「两边」。

### 与上一版（2026-07-27，77.5%）的差

| | 上一版 | 现在 |
|---|---:|---:|
| 合并覆盖 | 77.5% | 84.8% |
| 两边都没碰过 | 4078 | 2758 |
| 全仓零覆盖函数 | 数十个 | 3 个（都是 `main`） |

中间做的事记在下面「基线之后补掉的」表里。

### 剩下的 2758 条在哪

按文件排（完整清单在 `coverage-gaps.txt`，精确到语句块）：

| 条数 | 文件 | 性质 |
|---:|---|---|
| 147 | `cmd/nanotund/server.go` | 大半是 `main` 的启动编排与 IO 错误分支 |
| 102 | `cmd/nanotund/network_setup_linux.go` | 需要真 WAN 网卡 / 特定内核配置的分支 |
| 68 | `store/web_admins.go` | 罕见的 DB 错误路径 |
| 57 | `cmd/nanotund/magic_dns.go` | 上游超时、并发缓存竞争这类难构造的时序 |
| 50 | `cmd/nanotun-admin/cmd_profile.go` | profile 导出的各种格式组合 |

再往下是长尾，单文件都在 45 条以内。这些的共同点是「构造成本高、判错了会立刻报错
而不是静默出错」—— 按下面「补空白的顺序」那三条筛，优先级都不高了。

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

第 5 轮为了可测性动了生产代码：`jump_host_firewall.go` 里所有 `exec.Command` 与
`runtime.GOOS` 判断收进 `jumpFWExec` / `jumpFWOnLinux` 两个变量。这段编排只在生产的
Linux 上执行，开发机没有真 iptables、三机 e2e 也没开这个开关，所以「装出来的规则集
长什么样」此前从没被验证过——而它判错既不报错也看不出来。等价变异同样记一下：
`net.IP.String()` 自己就会把 v4-mapped 归一，所以 `To4().String()` 换成 `String()`
没有可观察差异；`teardownImpl` 的非 Linux 判断被 `installed` 标志盖住（非 Linux 上
`installed` 恒为 false）；`Teardown` 的 `sync.Once` 同理。

## 单测这一侧的现状（2026-07-28，Linux）

零覆盖函数已经清空，只剩三个 `main` —— 那是进程启动编排，用 e2e 覆盖比写单测划算。

| 包 | Linux | macOS | 差额来自 |
|---|---:|---:|---|
| `config` | 100.0% | 100.0% | — |
| `certs` | 91.7% | 91.7% | — |
| `util` | 90.5% | 90.5% | — |
| `cmd/nanotun-web` | 81.5% | 81.5% | `sysmon_linux.go` 已被测到 |
| `cmd/nanotun-admin` | 80.7% | 80.5% | `db_holders_linux.go` |
| `store` | 95.4% | 95.4% | 第 13–15 轮补完,见上表 |
| `auth` | 79.6% | 78.8% | argon2 并发路径 |
| `cmd/nanotund` | **74.0%** | 78.8% | `network_setup_linux.go` 等 |

只有 `cmd/nanotund` 两边差得明显：macOS 上 `*_linux.go` 根本不参与编译，那 700 多条
语句既不进分子也不进分母。**报数要报 Linux 的那一列**，macOS 的数偏乐观。

那些 Linux-only 的空白基本都被 e2e 接住了（合并后 `cmd/nanotund` 到 86.7%）：

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
| `run-linux-unit.sh` | Linux 机 | 逐包跑交叉编译好的测试二进制，拼出 `unit-linux.cov` |
| `deploy-instrumented.sh` | SRV | 换插桩二进制 + 接好 `GOCOVERDIR` + admin wrapper |
| `restore-plain.sh` | SRV | 上一条的逆操作，采集完务必执行 |
| `merge-coverage.py` | 本机 | 合并两侧，出四象限表和精确空白清单 |
