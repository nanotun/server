# 三机 e2e 回归

把此前靠人工敲命令跑的整轮回归固化成脚本。覆盖 341 项断言,一次完整运行约 27 分钟
(在与被测机同机房的调度机上;从远端开发机指挥要 47 分钟,原因见下面 `run-remote.sh` 那节)。

单测(`go test ./...`)覆盖的是函数级行为;这套 e2e 覆盖的是**跨进程、跨机器、
带真实网络的行为** —— 出口 fail-closed、ACL 快照是否真的即时生效、限速三层
min、子网撤销后是否立刻黑洞、LAN 回程会不会被源反欺骗守卫误杀。这些都是单测
结构上摸不到的地方,历史上找到的十几个缺陷绝大多数出在这一层。

## 拓扑

需要三台可 SSH 的机器:

| 角色 | 说明 |
| --- | --- |
| SRV | 跑 `nanotund` + `nanotun-web` |
| A | 普通客户端,选 C 作为出口。多数「使用方视角」的断言从这台发起 |
| C | 出口节点 + 子网宣告方,同时跑测试靶站 |

前置条件:

- 本机装有 `sshpass`(用口令认证时)、`python3`、`curl`;
- C 的防火墙放行 `E2E_TARGET_PORT`(默认 8088),否则测出来的「不通」是防火墙挡的;
- 两台客户端上 `nanotun` 已就绪,且 `E2E_*_CONNECT_ARGS` 是能无人值守直接连上的形式
  (脚本会反复停/起会话);
- 服务端 `nanotun-admin` 在 PATH 里;
- **带默认路由接管的客户端(不加 `--no-default-route`,A 就是这种)需要一条管理面回程规则**,
  见下。

### 带默认路由的客户端:先装管理面回程规则

客户端接管默认路由时,`default dev nanotun0` 的 metric 是 0,压过 DHCP 那条 WAN 默认路由。
于是公网入向连接(比如你的 SSH)的**回包**也被塞进隧道、从出口节点发出去 —— 那些包源地址是
本机公网 IP,机房出向过滤直接丢掉。表现是「机器活着、隧道正常、公网 SSH 超时」,而且只能从
隧道内部(`ssh root@<vIP>`,经 SRV 跳)才进得去。

规则只管回程,本机主动发起的流量源地址是 vIP,不匹配,照旧走隧道出口 —— 出口类断言不受影响:

```bash
# 在客户端上执行。gw/dev/src 三个值取 WAN 那条默认路由的。
ip route add default via <WAN_网关> dev <WAN_网卡> table 100
ip rule  add from <本机公网_IP> table 100 priority 100
```

`ip rule` 重启即失效,而失效之后你就进不去了。做成开机自启的 oneshot unit
(`After=network-online.target`,不要依赖 nanotun —— 这条规则的意义正是隧道出问题时还能进来)。

## 用法

```bash
cp e2e.env.example e2e.env   # 填写机器地址、凭据、身份
./run.sh                     # 跑全部阶段
./run.sh 30 50               # 只跑阶段 3 和阶段 5(阶段 0 总是先跑)
./run.sh --list              # 列出阶段
./run.sh --keep-target       # 跑完保留靶站,方便接着手工排查

./selftest.sh                # 断言库自测,不连机器,改过 lib/assert.sh 就跑一下
```

退出码:`0` 全通过 / `1` 有断言失败 / `2` 环境或配置问题(此时红绿都不可信)。

`e2e.env` 含明文口令,已在 `.gitignore` 里。

### 开跑前:先把 HEAD 装到 SRV

```bash
./deploy-srv.sh              # 构建 HEAD → 热替 SRV → 回读校验 → 改 E2E_EXPECT_VERSION
```

阶段 0 会断言 SRV 上的版本等于 `E2E_EXPECT_VERSION`。这条断言不是形式主义:没有它,
整套 e2e 会在**上一个版本**的服务端上安静地跑一遍全绿,然后那个绿被盖成发版戳 ——
而戳里只有一个 SHA,事后完全看不出来验的其实是旧代码。

但它要跑到 e2e 中途才报,前面十几分钟白跑(2026-08-05 就这么漏过一次)。`deploy-srv.sh`
把「装 HEAD」和「改版本钉子」两步合成一步,并在本地当场回读校验,不合就不让你开跑。

它只覆盖 `/usr/local/bin` 下的二进制与脚本,**不碰** `config.toml`、`certs/`、数据库 ——
那三样一动,机器的身份(REALITY 私钥、PSK、已发出去的 profile)就变了,实验室得重建。

### 别在自己机器上跑:`run-remote.sh`

`run.sh` 不参与被测,它只是个指挥 —— 每做一次检查就 SSH 到三台机器上执行一条命令、
把结果收回来判断。所以指挥站在哪儿不影响**测什么**,只影响每条命令来回一趟要多久,
而那是四位数级别的次数。

2026-08-05 实测,同一 commit、同样 341 项断言全过:

| 从哪儿指挥 | 总耗时 | 其中收敛等待 | 其余(网络往返) |
| --- | --- | --- | --- |
| 开发者的 Mac | 2838 秒 | 1188 秒 | 1650 秒 |
| 与 A/C 同机房的调度机 | 1615 秒 | 1041 秒 | 574 秒 |

省下的 20 分钟全在往返上:Mac 到三台机器 RTT 656~1052ms,即便开着 ControlMaster
复用,一条**什么都不干**的远程命令仍要 1.56 秒;调度机到 A/C 是 0.4ms、到 SRV 66ms。
收敛等待那一栏几乎纹丝不动 —— 那是被测系统自己的速度,其中 841 秒是 39 次「等客户端
重连」的退避,换谁来指挥都得等。

```bash
# e2e.env 里填好 E2E_RUNNER_* 之后:
./run-remote.sh              # 参数原样转交 run.sh
./run-remote.sh 10 50
```

它每次都会把调度机 `git reset --hard` 到**本地 HEAD**,并在核对不一致时中止。这条不是
洁癖:发版戳钉的是本地 HEAD 的 SHA,而 e2e 跑在另一台机器的另一份 checkout 里,两者
一旦漂开就会出现「戳盖在 A、e2e 其实验的是 B」—— 而戳里只有一个 SHA,事后完全查不出来。
同理,工作树不干净时它直接拒绝开跑:调度机跑的是已提交的那份,你手上的改动不在里面。

选调度机时**别选 A**:它接管默认路由,指挥机放上去等于自断 SSH(见上面那节回程规则)。
C 虽然带 `--no-default-route`,但它是出口节点兼靶站,额外负载会干扰吞吐类断言。

## 阶段

| 阶段 | 覆盖 |
| --- | --- |
| 00 基线 | 版本对齐、服务存活、会话在线、四条基线路径、`tun_write_drops` 为 0 |
| 10 出口与 MagicDNS | A/AAAA/NXDOMAIN/上游转发、系统解析器接管、UDP、2MB 下载、MTU 边界、撤销即 fail-closed、重新指定与离线回归的自动恢复 |
| 20 ACL 与限速 | 端口子集语义、通配源 + 端口区间、规则即时生效(含 `--json` 路径)、全局/设备/用户三层 min、放宽一层不复活旧快照 |
| 30 子网与 4via6 | IPv4/ULA/4via6 三种寻址、两道 4via6 守卫的计数器增量、`reject` 对已批准路由的保护、撤销即黑洞与重新批准恢复 |
| 40 租约与账号 | 网关/网段/网段外地址的钉住告警、冲突退出码、禁用的 905 终态关闭与连带 fail-closed、重新启用后恢复 |
| 50 运维面 | 热备份与完整性、还原的三道守卫、在线 VACUUM、坏配置 SIGHUP 不中断、踢线 902 与自动重连、审计 actor |
| 60 端口转发与 Web | 未登录/CSRF/方法白名单、节点与 LAN 目标从公网可达、非法输入拒绝、启停开关、viewer 的 RBAC 读写边界 |
| 70 硬崩溃恢复 | `kill -9` 后 systemd 自愈、启动 sweep 清掉上一条命的残留规则、粘性租约与 vIP 跨崩溃不变、无幽灵会话、数据面三条路径自动回来 |

## 三个设计选择

**用 `wait_until` 而不是 `sleep`。** 管理面动作几乎都是最终一致的:`exit designate`
之后要等下一次 `EgressSelectAck`,`acl deny` 之后要等快照重建,踢线之后要等客户端
自己重连。固定睡眠要么不够(假失败)要么太长(整轮拖慢),而且掩盖了「变慢」这个
信号。轮询到条件成立为止,顺带把耗时打出来 —— 上面那些 `（2s）` 就是实际收敛时间。

**跑完比对状态快照。** 开跑前记下 ACL、设置项、端口转发、Web 账号、路由、设备限速,
收尾时比对,有漂移直接算失败。人工回归最容易犯的错就是某一步忘了收尾,代价是
下一轮跑在被污染的环境上而结论看起来依然是绿的。

**「没测到」跟「测出问题」分开报。** 取值函数拿不到值(空串,或它自己声明的 `?`)时,
这条断言给不出任何结论。报成 `FAIL` 等于宣称被测系统不对,会把排查直接引向产品代码。
这类情况记为 `ENV`,不计入红绿,并让整轮退出码变成 `2`(优先于失败的 `1`)。

这条是有来历的:2026-07-27 那轮五条限速断言全红,看着像限速回归,实际是断言把登录名
当 `device_id` 传了进去,取值恒为空 —— 而且它从这套脚本落地起就是错的,那五条从来
没有真正验证过限速。取值函数(如 `conn_rate_down`)自己发现被误用时也应当调 `env_error`
说清楚,别退化成一句「限速没生效」。

注意 `wait_until` 执行谓词时会吞掉 stdout/stderr,所以 `env_error` 除了打印还会写一份
到临时文件 —— 否则在轮询里报的环境问题会连同输出一起消失。期望值本身就是空串的断言
(比如「NXDOMAIN 返回空结果」)不受影响。

## 已知边界

- **不在这里做真还原。** 阶段 5 只验证 `restore` 的守卫会拒绝,不执行覆盖实时库的还原 ——
  在共用环境上风险太高。完整的「备份 → 删库 → 还原 → 逐字对账」演练改在用完即弃的
  假 VPS 上跑:`scripts/testlab/lab.sh drill`,十几秒一轮。它同时把守卫真的踩一遍
  (服务没停、漏停 nanotun-web、坏备份源、没 TTY 又忘了 `--yes`),并断言库丢失后
  `/setup` 抢占入口的去向 —— 向导装的机器靠 `web.env` 顶住,CLI 建管理员的机器会
  如实重新敞开。
- **不测并发与规模。** 全程只有两个客户端会话,结构上摸不到并发问题。这块由
  进程内的 Go 压测补上,不在本套件里:

  ```bash
  go test ./cmd/nanotund/ -run 'Storm|Scale|RateWindow' -race -count=1
  NT_STORM_N=500 go test ./cmd/nanotund/ -run Storm -race -count=1     # 加压
  NT_SCALE_ACL=5000 go test ./cmd/nanotund/ -run ACLScale -count=1     # 加 ACL 规则数
  ```

  那几个测试用 `net.Pipe` 直接打 `handleVPNLink`,不需要真 TUN 和真监听端口,
  却完整跑「PoW → 认证 → supersede → vIP 分配 → lease 落库」整条链路,因而能配合
  `-race` 检出竞态。覆盖分三类:

  - *不崩不漏*:并发登录的 vIP 唯一性、同设备重登的 supersede 收敛、反复登录登出
    不泄漏、管理面操作与登录风暴并发。
  - *算得对*:每用户会话上限在并发登录下不被突破、vIP→归属会话 反查表(ACL 执法
    依据)在 churn 下与在线会话双向一致、限速刷新不会被登录/接管窗口吞掉、
    单来源 IP 的登录风暴确实被 per-IP 闸门挡下。这些破了都不会报错,只会静默算错。
  - *规模曲线*:登录耗时随租约数的增长、千条级 ACL 规则的快照重建与判定耗时。

  注意性能类断言(登录吞吐、重建耗时)在 `-race` 下会被插桩严重扭曲,相关测试
  检测到 race 开启时会自行跳过,量性能请用不带 `-race` 的那一遍。
- **不测 Web 后台的界面层。** 阶段 60 打的是 HTTP 接口(状态码、CSRF、RBAC),页面
  渲不渲得出来、表单填不填得进去、按钮点了有没有反应,它一概不知道。那一层由
  `scripts/testlab/lab.sh browse` 用真 Chrome 走一遍(开服 → 登录 → 建用户拿码 →
  服务器 QR 二次验密 → viewer 权限边界),在本地 Docker 假 VPS 上十几秒跑完。
  后台 2FA 那条更险的路(注册 TOTP → 启用拿恢复码 → 二次因子登录 → 错码被拒 →
  恢复码一次性 → 改密 step-up → 旧密码作废)由 `scripts/testlab/lab.sh browse-2fa`
  单独覆盖:它内置 RFC6238 算码,连「enable 输的码被重放到登录」这类时间步共享的坑
  都当场验。两者都不进发版门禁:要装浏览器,而门禁跑在三台不带图形栈的真机上。
- **恶意客户端视角:握手层走单测,分片绕 ACL 另有数据面 drill。** 畸形/超大预登录帧、
  PSK(PoW)重放、伪造 PoW、错 nonce、垃圾 LoginReq、预登录空闲超时,由
  `cmd/nanotund/login_adversarial_test.go` 用 `net.Pipe` 直打 `handleVPNLink` 覆盖
  (不需真监听端口)。「端口 deny 不能被分片绕过」除了解析器单测
  (`acl_eval_guards_test.go`),还有一条按需跑的三机数据面黑盒:
  `scripts/e2e/frag-acl-drill.sh` —— 从 A 用原始套接字造 IP 分片穿隧道,靠服务端
  `acl_drops` 增量断言「无端口的非首片也被 fail-closed(增量 6 而非 3)」。它不进
  发版门禁:要 root 开 `SOCK_RAW`,且共用环境上临时动 ACL 有风险。
- **传输隐蔽性:REALITY 端口被主动探测时回落到真站,不可区分。** REALITY 的命脉是
  探测者拿普通 TLS ClientHello 打接入端口(默认 8443)时,服务端把连接透明代理到
  `[reality].dest`(默认 `www.microsoft.com:443`),让探测者拿到一张**能过系统 CA 校验
  的真站证书**,认不出这是 VPN。本地假 VPS 上用同网段另一台带 `openssl` 的容器当探测者
  即可复现(需服务器容器能出网到 `dest`):

  ```bash
  # <SRV> = 服务器容器 IP。期望与直连真站逐字一致、Verify 0
  echo | openssl s_client -connect <SRV>:8443 -servername www.microsoft.com 2>/dev/null \
    | openssl x509 -noout -issuer -subject
  echo | openssl s_client -connect www.microsoft.com:443 -servername www.microsoft.com 2>/dev/null \
    | openssl x509 -noout -issuer -subject           # 对照:issuer/subject 应逐字相同
  ```

  返回自签证书、连接被 RST、或 `Verify return code` 非 0,就是回落坏了 —— 指纹已泄。
- **hy2/QUIC 数据面本地可验,但「出真公网」必须上真机。** 隧道建立、QUIC 收发、
  **隧道内 TCP**(客户端经隧道打**服务器自身**的 HTTP,拿 200 且大响应两端 `md5` 逐字
  一致)、ICMP 出公网,这些都能在本地 Docker 假 VPS 上验完 —— 用一枚 `nanotun` 客户端
  `connect ... --transport hy2` 连上 lab 服务器容器即可。但**客户端经隧道出公网的 TCP,
  在 Docker Desktop for Mac 上会假失败**:它的用户态出网栈把容器入向回程包的 TCP 校验和
  搞坏(抓包见朝 `tun0` 的 SYN-ACK `cksum (incorrect)`、`mss 65495` 的本地代答特征,且带
  `CHECKSUM_UNNECESSARY` 标志,连服务端 `iptables -t mangle -A POSTROUTING -o tun0 -j
  CHECKSUM --checksum-fill` 都救不回),nanotun 忠实转发进隧道,客户端真 TCP 栈校验失败
  静默丢弃 → SYN 无限重传。ICMP 是软件校验和不受影响,于是表现成「小包 `ping` 出网通、
  任何 TCP 出网超时」。判据:抓包见 SYN-ACK `cksum incorrect`,即环境伪影而非产品缺陷
  (服务端 `ip_forward` / SNAT / FORWARD 三样都对;真 Linux VPS 上 reality 的 HTTPS 出口
  早已实测通)。要验真出口,用真 VPS(reality/hy2 均可),别在 Docker Desktop for Mac 里
  测客户端出公网 TCP。
- **本套件的贡献在普通覆盖率里看不见。** 跑的是没插桩的生产二进制,`go test -cover`
  的剖面里一条都不记。想量它到底覆盖了多少代码,得编插桩二进制重跑一遍再与单测剖面
  合并,做法与坑见 [`docs/COVERAGE.md`](../../docs/COVERAGE.md)。2026-07-27 那次测下来,
  本套件覆盖了 2008 条**单测一行都走不到**的语句,`cmd/nanotund` 里就占 1506 条。
- **吞吐断言是数量级级别的。** 精确吞吐受公网抖动影响,做成硬断言必然 flaky;
  精确性由 `connection list` 里的有效限速值来保证。

## 加用例

在对应的 `phases/*.sh` 里加断言即可,可用的原语:

```bash
check      <描述> <期望> <实际>
check_match/check_contains
check_rc   <描述> <期望退出码> <runner> <命令...>
wait_until <描述> <超时秒> <谓词函数> [参数...]
wait_while <描述> <超时秒> <谓词函数> [参数...]   # 等到不再成立
env_error  <说明>                                 # 环境/脚手架故障,整轮退出码变 2
skip/note
```

谓词必须是**函数**。不能写成 `bash -c "..."` —— 那会开一个新 shell,`adm`、
`probe_*` 这些在里面都不存在,命令必然失败,`wait_until` 就一路等到超时再报一个
假失败。

远程执行用 `s`(服务端)、`a`(客户端 A)、`c`(客户端 C);服务端管理命令用
`adm`(自动带 `--db-path`),带确认提示的用 `adm_y`。
