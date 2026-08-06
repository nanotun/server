# nanotun 自托管网关

`nanotun` 是一个自托管的「组网工具」服务端:运行在一台具备公网入口的机器上,客户端
通过用户名 + PSK(预共享密钥)登录后,可在 TUN 虚拟网卡上互通,组成 mesh 子网。

无需任何外部控制面 / 账号系统,所有用户、设备、ACL 规则都保存在本机 SQLite
(`[store].db_path`),由 `nanotun-admin` CLI 管理。

## 快速启动

服务端只跑 **Linux**(要 TUN + iptables + systemd),支持 amd64 与 arm64,不需要装 Go 或编译。

### 一条命令

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/nanotun/server/main/scripts/install.sh)"
```

[`install.sh`](scripts/install.sh) 按顺序做四件事,任何一步没过都会停下来告诉你原因:

1. **检查环境** —— 这台机器能不能跑(见下);不过就不下载、不安装,不留半个装了一半的系统
2. **下载** —— 自动挑架构,校验 SHA256,解压到 `/opt/nanotun/`
3. **安装**([`install-self-hosted.sh`](scripts/install-self-hosted.sh))—— systemd 单元、
   IP 转发、REALITY / hy2 密钥与自签证书、放行 ufw、第一个 VPN 管理员
4. **开服向导**([`setup.sh`](scripts/setup.sh))—— 见下

跑完就能用:向导会问客户端拨号地址、定下 Web 后台的用户名和密码、建第一个 VPN 用户、出两个二维码。

> **别写成 `curl … | sudo bash`。** Ubuntu / Debian 的 sudo 默认开着 `use_pty`,会另开一个
> pty 跑命令;再叠加管道占着 sudo 的 stdin,向导一问话就被作业控制挂起 —— 提示符出来了、
> 回车却毫无反应(在全新 Ubuntu 26.04 上实测两次两挂)。写成 `bash -c "$(curl …)"`,
> bash 的 stdin 就是终端本身,不存在这个问题。真用了管道形态也不会挂:`install.sh`
> 认得出这个组合,会把系统装完、跳过向导,并提示你补一句 `sudo nanotun-setup`。

**无人值守**(CI / cloud-init):把向导要问的直接给它,一条命令做到底。这种场景不需要
问话,用管道形态最省事 ——

```bash
curl -fsSL https://raw.githubusercontent.com/nanotun/server/main/scripts/install.sh \
  | sudo NANOTUN_WEB_ADMIN_PASSWORD='换成你的密码' bash -s -- \
      --dial-host vpn.example.com --user alice --web-admin ops --yes
```

这一条装完之后 Web 后台就能用 `ops` 加那个密码直接登录 —— 不带 `--web-admin` 也能装,
只是后台账号留着没建,而 `/setup` 在建成之前对全网公开(谁先打开谁是管理员)。

`install.sh` 自己不认得的参数一律原样转交向导,所以 [`setup.sh`](scripts/setup.sh)
的选项都能这么带。

生产建议钉版本:`sudo NANOTUN_VERSION=v0.1.0 bash -c "$(curl -fsSL .../install.sh)"`。
想自己控制每一步就手动下 [Releases](https://github.com/nanotun/server/releases) 里对应架构的
tar,解压后跑 `sudo ./scripts/install-self-hosted.sh` —— 那是上面第 3 步,随发布包走,
不需要联网。`install.sh` 只是把「弄到这台机器上」这段也一并办了。

### 先看看这台机器行不行

买完 VPS 想先摸底、或者装完出问题要排查,单独跑环境检查。它是**只读**的,不装、不改任何东西:

```bash
curl -fsSL https://raw.githubusercontent.com/nanotun/server/main/scripts/preflight.sh | bash
```

一次把问题全列出来,最后给一条能直接粘的修复命令(按你的发行版给对包名),不用装一样重跑一次。
装过之后本地也有一份:`nanotun-preflight`。

查的是 systemd 有没有在跑、`/dev/net/tun` 在不在、`iptables`/`ip6tables`/`ip`/`openssl` 齐不齐、
`ip_forward` 能不能置 1,以及 8443/tcp、443/udp、7443/tcp 有没有被占。**最常见的两个坑**是
便宜 VPS 用 OpenVZ / LXC 虚拟化拿不到 TUN 设备(得换 KVM),和 Alpine 这类不用 systemd 的
发行版(得改走 Docker)。

### 支持哪些发行版、最低到什么版本

**不挑发行版,挑的是上面那几样东西。** 二进制是静态编译的(`CGO_ENABLED=0`),不链接
glibc 或 musl,所以发行版和版本对程序本身没有意义。

**硬门槛是 systemd ≥ 235。** 单元文件里用到 `RuntimeDirectoryPreserve=`,那是 systemd 235
(2017 年 10 月)才有的指令;更低的版本会把这行当没看见,于是两个服务共享的 `/run/nanotun`
会在各自重启时被对方清掉,控制 socket 跟着消失 —— 症状是 Web 后台一直说「运行时数据不可用」。
换算到发行版,就是下面这张表的下限。

每一行都在容器里从空系统装到开服向导跑完,不是照着版本号推的:

| 发行版 | 最低 | 实测过 | 备注 |
| --- | --- | --- | --- |
| Ubuntu | 18.04 | 18.04 / 20.04 / 26.04 | 18.04 的 systemd 是 237,刚好在门槛之上 |
| Debian | 10 | 11 / 13 | 10 的软件源已归档、装不动包,没能实测;它与 18.04 同代,组件版本一一对应 |
| RHEL 系 | 8 | Rocky 8 / 9 | 防火墙是 firewalld,脚本会自动放行 |
| Alpine | — | 明确挡下 | 用 OpenRC 而非 systemd,改走 Docker |

没列到的发行版不代表不行:Fedora、Alma、openSUSE、Arch 只要 systemd 在跑就是同一条路,
preflight 也认得它们的包管理器。拿不准就跑上面那条只读的检查命令 —— 它给的是这台机器的
答案,比任何兼容性列表都准。

**但仍然建议用还在收安全更新的版本。** Ubuntu 18.04 和 Debian 10 都已 EOL:nanotun 装得上
也跑得起来,可那台机器的内核和 OpenSSL 不再有人修,而它是要对公网开端口的。

老发行版上有三处与新版本不同,装机脚本都已经处理,列在这里只是为了排障时不必重新发现一遍:
OpenSSL 1.1.1(Ubuntu ≤ 20.04 / Debian 11 / RHEL 8)生成证书时会写出重复的扩展项而 Go 拒收;
mawk 1.3.3(Ubuntu 18.04 / Debian 10)不认 `[[:space:]]` 这类字符类;老版本默认的 legacy
iptables 需要写 `/run/xtables.lock`,而 systemd 沙盒把 `/run` 挂成了只读。

Alpine、Devuan 这类不用 systemd 的,以及连 init 都没有的容器环境,走
[Docker 部署](docs/DOCKER.md):那条路不要求宿主有 systemd,发行版就更无所谓了。

### 开服向导

**装完不等于客户端能连上** —— 还差三件只有你知道答案的事:客户端该往哪个地址拨、
Web 后台管理员密码、给用户的二维码。上面那条命令的最后一步就是它;单独跑:

```bash
sudo nanotun-setup
```

它会探测并写入拨号地址(`server_dial_host`)、**当场创建 Web 后台管理员**(用户名和密码
你现在定,密码两遍隐藏输入)、创建第一个 VPN 用户,并直接在终端打出两个二维码:

- **profile QR** —— 服务器地址与传输配置,不含密钥,可以公开传
- **credentials QR** —— 用户名 + PSK,机密,只能一对一给本人

后台账号这一步别跳过:在第一个管理员出现之前,`/setup` 页面对全网公开 —— **谁先打开谁就是
管理员**。向导把它建掉,这扇门就自动关了(之后访问 `/setup` 会跳到登录页)。

重复跑是安全的(不重置 PSK、不动配置、已有管理员就跳过),之后加用户、重出二维码都用它。
自动化部署一条命令做完:

```bash
sudo NANOTUN_WEB_ADMIN_PASSWORD='...' nanotun-setup \
     --dial-host vpn.example.com --user alice --web-admin ops --yes
```

密码只走环境变量,不做成命令行参数 —— argv 对同机所有用户可见(`ps`),还会落进 shell
history。`--yes` 下给了 `--web-admin` 却没给密码时,向导会随机生成一个并打在屏幕上(只此一次)。

VPN 账号和 Web 后台是**两套东西**,最容易混:前者是客户端登录用的用户名 + PSK(PSK 由服务器
生成,不能自选);后者是浏览器登录后台用的,密码你自己设。后台账号也可以随时用命令行加:

```bash
sudo nanotun-admin webadmin create <名字>     # 会提示输两遍密码,不回显
sudo nanotun-admin webadmin list              # 看后台都有谁
```

忘了后台密码,或者被连续输错锁在门外了,从服务器上救回来:

```bash
sudo nanotun-admin webadmin reset-password <名字>   # 改密码,顺带清掉失败锁定
sudo nanotun-admin webadmin unlock <名字>           # 只解锁,密码不动
```

客户端扫完两个码就能连。剩下的用户管理走 Web 后台或下面的命令行。

### 用 Docker 跑

已经熟悉容器的话也可以走这条:

```bash
curl -fsSLO https://raw.githubusercontent.com/nanotun/server/main/docker/docker-compose.yml
docker compose up -d && docker compose logs -f     # 首次启动的 PSK 会打在日志里
```

镜像是 `ghcr.io/nanotun/server`(amd64 + arm64 多架构)。它是个 VPN 网关,对
`/dev/net/tun`、`CAP_NET_ADMIN`、宿主 `sysctl` 和防火墙有硬性要求,宿主那几个内核参数
容器改不了得你自己设 —— **上面两行跑完不等于客户端就能连上**,逐条踩坑说明见
[`docs/DOCKER.md`](docs/DOCKER.md)。容器里没有 `nanotun-setup`,拨号地址和用户在
Web 后台里设,或 `docker compose exec nanotun nanotun-admin ...`。

### 从源码构建(开发用)

```bash
git clone https://github.com/nanotun/server.git && cd server
go build ./...

# 本地非 root 试跑:config.toml 里 [store].db_path 钉的是生产绝对路径
# /var/lib/nanotun/nanotun.db,用 config_no_tun.toml 那份(db_path 为
# data/nanotun.db,且不需要 root / TUN)。
cd cmd/nanotund && go build -o nanotund . && ./nanotund -config config_no_tun.toml

# 容器里验证自己改的代码:
cd docker && docker compose -f docker-compose.dev.yml up --build
```

## 用 admin CLI 创建用户和设备

`nanotun-setup` 做的就是下面这几步,想手工控制或写脚本时直接用 CLI。详细命令见
[`cmd/nanotun-admin/README.md`](cmd/nanotun-admin/README.md);最常用的工作流(0013
credentials 解耦后**双 QR**:profile 不含 PSK + credentials 独立下发):

```bash
# 注意 --db-path:它的默认值是**相对当前目录**的 data/nanotun.db。忘了传不会报错,
# 而是在 cwd 建一个空库,现象是「刚建的用户查不到」。设 NANOTUN_DB 环境变量也行。
export NANOTUN_DB=/var/lib/nanotun/nanotun.db

# 1) 创建用户:PSK 仅在这一次以明文回显,同时分配 credential_id (UUID v4)。
nanotun-admin user create alice --admin --exit-allowed=true

# 2) 客户端 profile QR(只含服务器节点 / 路由,不含 PSK,可公开传阅)。
#    --dial-host 必须显式给,CLI 不会去读库里的 server_dial_host 设置。
nanotun-admin profile show alice --dial-host vpn.example.com --format qr

# 3) 客户端 credentials QR(用 PSK 明文 + UUID 生成,**仅这一次能拿到明文**)。
#    用户用 nanotun-cred://v1?d=... 二维码扫入 Apple 客户端 Keychain,Profile 列表
#    再走「绑定凭证」选这把 UUID。后续 reset-psk 重新出新 QR,客户端按 UUID 自动覆盖。
nanotun-admin credentials show alice --psk '<刚才创建时回显的明文>' \
    --format qr-png --output alice-cred.png

# PSK 丢了不是死局,但轮换会把该用户在线的会话踢下去:
nanotun-admin --yes credentials show alice --rotate-psk --format qr
```

Docker 部署统一加前缀 `docker compose exec nanotun`(镜像里 `NANOTUN_DB` 已经钉好了)。

## 服务端进程与端口

装完后服务由 systemd 管(`systemctl status nanotun` / `nanotun-web`);Docker 部署则
是容器自身。想手工前台跑(排障):`sudo nanotund -config /etc/nanotun/config.toml`。

VPN 数据面监听 `[server].listen_addr`(默认 `127.0.0.1:8080`,仅回环),走 WebSocket
Binary + 自定义链路帧(见 `util/link_frame.go`)。生产客户端(iOS/Android)经 Hysteria 2
(`[hysteria]`,:443/udp)或 Xray REALITY(`[reality]`,:8443/tcp)入站,服务端在握手后
把它们环回桥接到数据面端口,客户端不直连 8080。仅当你要让客户端直接 wss:// 拨数据面时,
才把 `listen_addr` 改成 `:8080`(所有网卡)并放行防火墙。

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
- **Subnet route advertise**(P2#12,**数据面已落地 SR-M1**)客户端可声明本地子网,
  管理员通过 `nanotun-admin route approve <device_id> <cidr>` 审批。审批后,只要宣告方
  device 在线、且请求方→宣告方的 ACL 放行,发往该 CIDR 的流量就会由 server 真正投递到
  宣告方会话,再由宣告方本机转发 / NAT 进其 LAN(需宣告方客户端支持 SR-M2 的 LAN 转发)。
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

三机行为回归与**发版门禁**见 [`docs/RELEASE.md`](docs/RELEASE.md)。
合并绿只过 CI;发版必须走:

```bash
./scripts/e2e/run.sh 00 10 20 30 40 50 60 70
./scripts/release/stamp-e2e.sh
./scripts/release/cut.sh v0.1.0
git push origin v0.1.0     # 触发 CI 构建 Release tar + GHCR 镜像
```

三机 e2e 跑不进 GitHub Actions,所以门禁留在本地:`cut.sh` 把 e2e 戳写进 annotated
tag,workflow 只认这种 tag —— 手工 `git tag` 推上去发不出版本。

## 升级 / 部署

**Docker**:`docker compose pull && docker compose up -d`。配置不会被覆盖,
模板变更另存 `config.toml.dist` 供 diff。

**裸机**:重跑一遍 `install.sh`(或下新版本 tar 后跑 `install-self-hosted.sh`)。
脚本幂等,**不会动**已生效的 `config.toml` 和密钥 —— 重签密钥等于踢掉全部现有客户端。
详见脚本头部注释与 [`docs/UPGRADE_M0.md`](docs/UPGRADE_M0.md)。

**备份**:`nanotun-admin backup`(热一致,走 `VACUUM INTO`)拿 SQLite 库,
再连 `/etc/nanotun` 一起存 —— REALITY 私钥和 hy2 口令都在那儿,丢了客户端要重新接入。

**数据库丢了怎么办**:服务不会因为库不见了就停 —— 它会重建一个空库照常启动,
所以别指望「服务挂了」来提醒你。恢复就是把备份拷回去:

```bash
sudo systemctl stop nanotun nanotun-web
sudo cp /path/to/backup.db /var/lib/nanotun/nanotun.db
sudo chmod 600 /var/lib/nanotun/nanotun.db
sudo systemctl start nanotun nanotun-web
```

安装向导会往 `/etc/nanotun/web.env` 写一行 `NANOTUN_WEB_ALLOW_SETUP=0`,
把 /setup 的关闭状态放在数据库之外。否则库一没,/setup 会重新对全网敞开,
谁先打开谁就是这台机器的管理员。真要重新 bootstrap 一个后台账号,用 CLI:

```bash
sudo nanotun-admin webadmin create <名字>
```

容器部署同理,只是那行写在 compose 的 `environment:` 里(见 `docker/docker-compose.yml`)——
卷丢失是容器最常见的事故,而 compose 文件跟卷不在一起,那种时候它还活着。

**卸载**:[`scripts/uninstall.sh`](scripts/uninstall.sh)(随发布包走)。

```bash
sudo ./scripts/uninstall.sh              # 停服务、删程序,保留配置与数据库
sudo ./scripts/uninstall.sh --purge      # 连配置、证书、数据库一起删
sudo ./scripts/uninstall.sh --dry-run    # 先看看会动哪些文件
```

默认保留 `/etc/nanotun` 与数据库,重装一遍就能接着用;`--purge` 会要求你手输 `purge` 再确认,
因为用户、设备、PSK 和审批过的子网路由是一起没的,已发出去的客户端配置随之作废。

别手动 `rm -rf /etc/nanotun /var/lib/nanotun`:这两个目录**和客户端共用**,
客户端的设备身份 `/etc/nanotun/device_id` 就在里面。删掉它客户端会以新 UUID 重新注册,
而 UUID 是审批和出口选择的稳定键 —— 旧设备行还占着固定 vIP,新设备钉不上,
已经选了这个出口的客户端那边它直接消失。卸载脚本按文件清单删,不碰这些。

数据库 schema 在启动时自动迁移,没有单独的 migrate 命令。

历史版本曾经依赖 一个集中式认证后端(`legacy_backend` 模式),
当前代码库已经彻底移除该路径,所有部署一律走自托管 PSK。如需查阅历史归因,
见 `docs/POSTMORTEM-20260521-db-path-migration.md`。

## 许可证

本项目以 [Apache License 2.0](LICENSE) 开源。
`third_party/xtls-reality` 为 vendored 第三方代码,保留其自带许可(见该目录内
`LICENSE` 与 `LICENSE-Go`)。
