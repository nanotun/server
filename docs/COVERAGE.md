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

## 三个坑（都踩过）

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
整片误算成「仅单侧覆盖」。改完代码要两边重新采集，别拿旧剖面凑。

## 基线（2026-07-27）

全仓 18163 条语句，合并覆盖 **77.5%**，4078 条两边都没碰过。

| 包 | 总语句 | 两边 | 仅单测 | 仅 e2e | 都没有 | 合并覆盖 |
|---|---:|---:|---:|---:|---:|---:|
| `cmd/nanotund` | 7526 | 2803 | 1662 | 1506 | 1555 | 79.3% |
| `cmd/nanotun-web` | 4524 | 1117 | 2360 | 111 | 936 | 79.3% |
| `cmd/nanotun-admin` | 3001 | 643 | 1408 | 186 | 764 | 74.5% |
| `store` | 1879 | 587 | 705 | 80 | 507 | 73.0% |
| `util` | 675 | 145 | 302 | 88 | 140 | 79.3% |
| `config` | 337 | 116 | 71 | 32 | 118 | 65.0% |
| `auth` | 137 | 78 | 20 | 5 | 34 | 75.2% |
| `certs` | 84 | 0 | 60 | 0 | 24 | 71.4% |

「仅 e2e」合计 2008 条，是三机 e2e 不可替代的贡献。`cmd/nanotund` 尤其明显：单测在
Linux 上只有 59.3%，加上 e2e 到 79.3%，其中 1506 条**只有**真实流量才触达得到。

采集这份基线时 e2e 三轮共 379 项断言全过（128 + 113 + 25 + 113，含重跑）。

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
