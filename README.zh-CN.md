# nanotun 自托管网关

[English](README.md) · **简体中文**

让一个小团队安全地访问你自己的机器 —— 并且在有人离开时真的收回权限。

网关跑在你自己的服务器上,团队成员拿到一个虚拟子网,可以访问你的 GPU 主机、测试机
和办公室内网,也可以经一个只属于你们的出口 IP 出网。权限按人下发,受 ACL 约束,
留审计日志,撤销就是真的撤销。

这件事现在多数团队是靠在群里发一个配置链接解决的。那个链接发出去就收不回来,人走了
还能连,而且谁用过什么完全查不到。

典型用户:

- 需要访问自托管推理、GPU 服务器,或必须留在特定辖区的数据的团队
- 共享商业 VPN 出口 IP 被上游 API 风控拉黑的团队
- 想要一个私有网络,但不愿意把控制面交给供应商的人

## 它是怎么工作的

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

0. **选语言** —— 英文或中文。默认英文;只在有终端时问一次,而且问在最前面(见下)
1. **检查环境** —— 这台机器能不能跑(见下);不过就不下载、不安装,不留半个装了一半的系统
2. **下载** —— 自动挑架构,校验 SHA256,解压到 `/opt/nanotun/`
3. **安装**([`install-self-hosted.sh`](scripts/install-self-hosted.sh))—— systemd 单元、
   IP 转发、REALITY / hy2 密钥与自签证书、放行 ufw、第一个 VPN 管理员
4. **开服向导**([`setup.sh`](scripts/setup.sh))—— 见下

跑完就能用:向导会问客户端拨号地址、定下 Web 后台的用户名和密码、建第一个 VPN 用户、出两个二维码。

> **先说清楚客户端。** 这个仓库发布的是**服务端**;那两个二维码要用 nanotun 客户端扫,
> 而客户端(macOS / Windows / Android / OpenWrt)目前**不公开分发**,代码也不在这里。
> 也就是说:服务端你现在就能装起来、能从 Web 后台和 CLI 管起来,但手上没有客户端的话,
> 二维码暂时没有东西可扫。要客户端请联系维护者。
>
> 把这句写在最前面,是因为它值得你在花时间装之前就知道 —— 而不是装完、拿到二维码那一刻
> 才发现。

> **别写成 `curl … | sudo bash`。** Ubuntu / Debian 的 sudo 默认开着 `use_pty`,会另开一个
> pty 跑命令;再叠加管道占着 sudo 的 stdin,向导一问话就被作业控制挂起 —— 提示符出来了、
> 回车却毫无反应(在全新 Ubuntu 26.04 上实测两次两挂)。写成 `bash -c "$(curl …)"`,
> bash 的 stdin 就是终端本身,不存在这个问题。真用了管道形态也不会挂:`install.sh`
> 认得出这个组合,会把系统装完、跳过向导,并提示你补一句 `sudo nanotun-setup`。

**无人值守**(CI / cloud-init):把向导要问的直接给它,一条命令做到底 ——

```bash
curl -fsSL https://raw.githubusercontent.com/nanotun/server/main/scripts/install.sh -o nanotun-install.sh \
  && sudo NANOTUN_WEB_ADMIN_PASSWORD='换成你的密码' bash nanotun-install.sh \
      --dial-host vpn.example.com --user alice --web-admin ops --yes
```

> **这里要先落盘,不能写成 `curl … | bash`。** 管道形态下,curl 失败时 bash 拿到的是一个
> 空脚本 —— 它老老实实跑完那零行内容,然后**以 0 退出**。`bash -c "$(curl …)"` 一样。
> 人在旁边看着无所谓(屏幕上什么都没发生),但 cloud-init / Ansible / CI 只认退出码:
> 它们会把「一个字节都没下下来」当成装好了,继续往下走,而那台机器上什么都没有。
> 先落盘再执行,curl 的失败就由 `&&` 如实挡住了。
>
> 落在当前目录而不是 `/tmp`:`/tmp` 人人可写,下载完到 sudo 执行之间那一瞬,同机器上
> 的其他用户能把文件换掉 —— 而下一步是 root 在跑它。

这一条装完之后 Web 后台就能用 `ops` 加那个密码直接登录 —— 不带 `--web-admin` 也能装,
只是后台账号留着没建,而 `/setup` 在建成之前对全网公开(谁先打开谁是管理员)。

`install.sh` 自己不认得的参数一律原样转交向导,所以 [`setup.sh`](scripts/setup.sh)
的选项都能这么带。

**端口。** 三个里有两个刻意**不**随机,一个刻意随机:

| | 端口 | 为什么 |
|---|---|---|
| REALITY | `443/tcp` | REALITY 的伪装是「这就是个普通 HTTPS 站」—— 探测者会拿到一张 `[reality].dest` 的、能过系统 CA 校验的真证书。这套说法只有在「本来就该是 HTTPS」的端口上才成立。 |
| hysteria2 | `443/udp` | 443 是能穿过酒店 / 企业 / 运营商网络的那个端口,而 443 上的 QUIC 与普通 HTTP/3 无从区分。TCP 与 UDP 的 443 互不冲突,两者合起来恰恰是任何支持 HTTP/3 的网站的指纹。 |
| Web 后台 | **随机** | 管理登录页没有「要像正常流量」的需求,却有充分的理由别被找到。所有部署都长在 7443 上,等于给扫描器一份现成的名单。取值 10000–31999(在 Linux 临时端口段以下,不会和对外连接的源端口撞)。 |

有终端时装机会显示随机挑中的后台端口,并让你可以改成别的;没终端就自己挑一个并打出来。
`--web-port 23456`(或 `NANOTUN_WEB_PORT=23456`)可以显式钉住 —— 自动化需要确定值时用它。**重跑不会挪动它**:
升级是重跑 `install.sh` 的头号理由,而把一台正在服务的机器的管理入口挪走,不是你要的。
端口以 `NANOTUN_WEB_LISTEN` 落在 `/etc/nanotun/web.env`,下游全部从那儿读(环境检查、防火墙规则、装完的「监听中」
自检、向导打的登录地址)。

> `443/tcp` 和已有 Web 服务器撞车的概率远高于原来的 `8443`。环境检查会在动任何东西之前
> 告诉你,并给出一步就能过去的办法:重跑时带 `--reality-port 8443`(或
> `NANOTUN_REALITY_PORT=8443`)。它**不会被静默挪走** —— 否则同一条安装命令在两台机器上
> 会装出不同端口,而差异不留任何痕迹。
>
> `--reality-port` **只对全新安装生效**。已经有 `config.toml` 的机器上安装器会拒绝并说明:
> REALITY 的端口印在每一份已经发出去的客户端配置里,挪走等于把所有现有客户端一次性踢下线,
> 而他们看到的只是「连不上」,没有任何线索指向服务端换了端口。要有意这么做:改
> `[reality].listen_addr`、重启、然后给每个客户端重发配置。

**语言。** 整条安装链打出来的东西 —— 环境检查、安装脚本、开服向导,以及它装下的那几个
`nanotun-*` 命令 —— 都有英文和中文两份,**默认英文**。有终端时会在一切动作之前问你一次;
没有终端(CI、cloud-init、`curl … | bash`)就不问、直接用英文,所以无人值守永远不会卡在
这一问上。

```bash
sudo bash -c "$(curl -fsSL …/install.sh)" --lang zh      # 或者 NANOTUN_LANG=zh
```

优先级是 `--lang` > `NANOTUN_LANG` > `/etc/nanotun/lang` 里记下的那次选择。装机时会把选择
写进那个文件,所以之后单独敲 `nanotun-setup`、`nanotun-uninstall`、`nanotun-set-suffix`
默认沿用同一种语言,不必再说一遍;要临时换,上面两个开关照样管用。`nanotun-admin` 和 Web
后台认的是同一个 `NANOTUN_LANG`(后台另有自己的语言切换器),所以决定一次就覆盖整条链。

**生产建议钉版本**,别跟着 latest 漂。把 URL 里的 `main` 和 `NANOTUN_VERSION` 都换成同一个
tag,拿到的就是完全钉死的一次安装 —— 脚本、环境检查、发布包三样都来自那个 tag:

```bash
sudo NANOTUN_VERSION=v1.0.0 bash -c "$(curl -fsSL \
  https://raw.githubusercontent.com/nanotun/server/v1.0.0/scripts/install.sh)"
```

只换 `NANOTUN_VERSION`、URL 仍走 `main` 也可以,发布包一样钉得住;差别在于**脚本本身**跟着
主干走。`main` 上的改动不经发布门禁,一次 push 就对所有新安装生效 —— 在意这件事就用上面那条。

> 三样全钉住要求 tag ≥ v0.1.25:「`NANOTUN_VERSION` 是 tag 时环境检查也从同一个 tag 取」这条
> 联动是 v0.1.25 加的。更早的 tag 上那份 `install.sh` 还没有它,环境检查仍从 `main` 取 ——
> 脚本和发布包钉住了,环境检查没有。要单独指定用 `NANOTUN_BRANCH`。

**github.com 连不上**(网络受限 / 出站受限)时不必放弃一键,把两个下载前缀指到镜像即可。给的是
完整前缀,所以路径型和 ghproxy 那种前缀型镜像都装得下:

```bash
sudo NANOTUN_GH_BASE=https://<你的镜像>/https://github.com/nanotun/server \
     NANOTUN_RAW_BASE=https://<你的镜像>/https://raw.githubusercontent.com/nanotun/server/main/scripts \
     bash -c "$(curl -fsSL https://<你的镜像>/https://raw.githubusercontent.com/nanotun/server/main/scripts/install.sh)"
```

`NANOTUN_GH_BASE` 管发布包,`NANOTUN_RAW_BASE` 管环境检查脚本。下载失败时报错会点名你填的那个
前缀,而不是笼统说「连不上 github.com」。

**这台机器上没有 `curl`**(Debian netinst 之类的最小镜像常常只带 `wget`)时不用先去装 curl,
用 wget 取脚本就行 —— 脚本内部的下载也会自动退到 wget:

```bash
sudo bash -c "$(wget -qO- https://raw.githubusercontent.com/nanotun/server/main/scripts/install.sh)"
```

两个都没有的话它会当场说清楚该装哪个,而不是在第一个网络动作上报一句「网络不通」。

想自己控制每一步就手动下 [Releases](https://github.com/nanotun/server/releases) 里对应架构的
tar,解压后跑 `sudo ./scripts/install-self-hosted.sh` —— 那是上面第 3 步,随发布包走,
不需要联网。`install.sh` 只是把「弄到这台机器上」这段也一并办了。

### 先看看这台机器行不行

买完 VPS 想先摸底、或者装完出问题要排查,单独跑环境检查。它什么都不装:

```bash
curl -fsSL https://raw.githubusercontent.com/nanotun/server/main/scripts/preflight.sh | bash
```

一次把问题全列出来,最后给一条能直接粘的修复命令(按你的发行版给对包名),不用装一样重跑一次。
装过之后本地也有一份:`nanotun-preflight`。

> 唯一会写的一处:它会试着把 `net.ipv4.ip_forward` 置 1 —— 因为要验的正是「这台机器
> 允不允许改它」,而只读的检查答不了这个问题(答错的代价是装完 nanotund 直接 exit 60)。
> 装机本来也要设这一条。真想一个字节都不动,加 `--dry-run`:
> `curl -fsSL .../preflight.sh | bash -s -- --dry-run`。`install.sh --check-only`
> 走的就是这条只读路径。

查的是 systemd 有没有在跑、`/dev/net/tun` 在不在、`iptables`/`ip6tables`/`ip`/`openssl` 齐不齐、
`ip_forward` 能不能置 1,以及 443/tcp、443/udp 和 Web 管理面那个端口有没有被占。**最常见的两个坑**是
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

- **profile QR** —— 服务器地址与传输配置,不含 PSK。但开着 hy2 mTLS(装机默认)时它内嵌一张客户端证书 —— 那不是登录凭证,却是进 QUIC 那道门的钥匙,所以发给本人、别公开贴
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
curl -fsSLO https://raw.githubusercontent.com/nanotun/server/main/docker/docker-compose.yml \
  && docker compose up -d && docker compose logs -f     # 首次启动的 PSK 会打在日志里
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
# 装过 nanotun 的机器上不带 --db-path 也行:找不到当前目录下的 data/nanotun.db 时,
# 会自动用 /var/lib/nanotun/nanotun.db 并说一声。想固定下来就设 NANOTUN_DB ——
# 写进文档、脚本、工单里的命令不该依赖「在哪个目录跑」。
export NANOTUN_DB=/var/lib/nanotun/nanotun.db

# 1) 创建用户:PSK 仅在这一次以明文回显,同时分配 credential_id (UUID v4)。
nanotun-admin user create alice --admin --exit-allowed=true

# 2) 客户端 profile QR(服务器节点 / 路由,不含 PSK;开着 hy2 mTLS 时内嵌一张客户端证书,
#    所以是「发给本人」而不是「随便贴」)。--dial-host 不给就用库里存的 server_dial_host。
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
(`[hysteria]`,:443/udp)或 Xray REALITY(`[reality]`,:443/tcp)入站,服务端在握手后
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
| profile QR | `nanotun://v1` | server host / transport(WS, Hysteria, REALITY)/ nodes 配置;hy2 mTLS 开着时还含一张客户端证书与私钥 | **发给本人** — 不含 PSK,拿到也登不进来;但那张证书是进 QUIC 那道门的钥匙,公开等于把挡扫描的一层拆了 |
| credentials QR | `nanotun-cred://v1` | `credential_id`(UUID v4)+ `username` + `psk` + `created_at` | **机密** — 仅本地一对一传递,客户端落 Keychain |

工作流:
- **首次下发**:管理员同时导出两份 QR 给用户。客户端先扫 profile(选服务器),
  再扫 credentials(注入凭证)。两份都只发给本人:profile 不含 PSK、可以走云同步给同一个人的
  多台设备,但它内嵌的客户端证书不适合公开张贴或群发;credentials 走线下。
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
# Profile QR(server 配置 + 客户端证书,发给本人)
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
  后缀 `<suffix>` 默认 `nanotun`,**装机时**可定制:`--magic-suffix lab`
  或环境变量 `NANOTUN_MAGIC_SUFFIX=lab`(一键装 `install.sh` / 离线
  `install-self-hosted.sh` / Docker 同名变量,只在首次写 `config.toml` 时生效)。
  改**已装好**机器的后缀用 `sudo nanotun-set-suffix <后缀>`(装机时随包装成命令;发布包里
  对应 `scripts/set-magic-suffix.sh`)——备份→改→重启→失败自动回滚;`nanotun-setup` 向导里
  也有一步可选改。运行期后缀只从 `config.toml` 读,`nanotun-admin setting set magic_suffix`
  不是入口(已硬拒并指路)。
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

**裸机**:重跑一遍 `install.sh`,升级时加 `--no-setup` —— 那一步是开服向导,已经开过服的
机器不需要再走一遍:

```bash
sudo NANOTUN_VERSION=v1.0.0 bash -c "$(curl -fsSL \
  https://raw.githubusercontent.com/nanotun/server/v1.0.0/scripts/install.sh)" --no-setup
```

也可以下新版本 tar 后直接跑 `install-self-hosted.sh`(那条本来就不进向导)。脚本幂等,
**不会动**已生效的 `config.toml` 和密钥 —— 重签密钥等于踢掉全部现有客户端。
详见脚本头部注释与 [`docs/UPGRADE_M0.md`](docs/UPGRADE_M0.md)。

不加 `--no-setup` 也不会弄坏什么:向导认得已经配好的机器,拨号地址拿现值作默认,
Web 管理员和 VPN 用户都已存在就跳过。只是白走一遍问答。

跨多个版本一次升上来也是这个办法,不用逐版本爬。实测从 v0.1.0 直接升到 v0.1.16:
`server_id`、REALITY 私钥、两张证书、用户与 ACL 全部原样保留,已经发出去的 profile
二维码继续有效(逐字段比对只有那张随取随签的客户端证书不同,其余 18 项一致,老证书
也能被升级后的 CA 验过)。

**但有一件事升级不会替你做**:profile 里内嵌的那张客户端证书,有效期在**签发那一刻**
就定死了。默认值一路从 90 天放到 10 年、再放到 100 年,每次改的都只是新签发的那批;
老版本发出去的二维码仍然按当初的日子到期,升级不会追溯延长。从早期版本升上来的话,
给现有用户重出一次 `profile show` 才能换到长效证书 —— 否则你以为「现在都是一百年」,
而客户端会在原定的日子集体掉线。

盘上那张**客户端 CA** 同理:装机脚本只在文件缺失时才签,所以改成一百年之前装的机器,
手里还是那张较短的老 CA —— 而签发端会把叶子夹到 CA 的 `NotAfter` 以内,新签的客户端
证书于是静默继承了老 CA 的到期日。剩余寿命进 180 天以内时 `profile show` 会说一句。

**备份**:`nanotun-admin backup <路径>`(热一致,走 `VACUUM INTO`;路径不给就按时间戳命名)拿 SQLite 库,
再连 `/etc/nanotun` 一起存 —— REALITY 私钥和 hy2 口令都在那儿,丢了客户端要重新接入。

**数据库丢了怎么办**:服务不会因为库不见了就停 —— 它会重建一个空库照常启动,
所以别指望「服务挂了」来提醒你。恢复就是把备份拷回去:

```bash
sudo systemctl stop nanotun nanotun-web
sudo nanotun-admin --db-path /var/lib/nanotun/nanotun.db restore /path/to/backup.db
sudo systemctl start nanotun nanotun-web
```

用 `restore` 而不是 `cp`:它会先验源文件是不是一个完整的 nanotun 库(半截下载的备份、
拿错的 tar.gz、0 字节的 cron 产物都挡在门外),覆盖前把现库留一份
`.pre-restore-<时间戳>`,并且**在服务还开着时直接拒绝**。

最后这条最要紧。`cp` 是原地覆盖、inode 不变,所以服务端那道「库文件被换掉就重开」的
兜底照不到它:漏停一个服务再 cp,那个进程会拿着一个从底下被换掉字节的库继续服务,
一声不吭,而另一个服务从此起不来,日志里只有一句 `database is locked`。
非交互场景(ssh、脚本)记得加 `--yes` —— 没有 TTY 时它问不到人,会什么都不做并以非 0 退出。

安装向导会往 `/etc/nanotun/web.env` 写一行 `NANOTUN_WEB_ALLOW_SETUP=0`,
把 /setup 的关闭状态放在数据库之外。否则库一没,/setup 会重新对全网敞开,
谁先打开谁就是这台机器的管理员。

**写这行的只有向导。** 跳过向导装机、后台账号用 `nanotun-admin webadmin create` 建的机器
没有这一行 —— 那台机器上「已有管理员所以 /setup 关着」这件事只记在库里,库一丢就跟着丢。
实测:删掉库重启,两个服务都是 active,`/setup` 回 200 并带着建管理员的表单。
不放心就自己补上那行再重启 `nanotun-web`(`nanotun-web` 每次启动也会就此警告一句)。

真要重新 bootstrap 一个后台账号,用 CLI:

```bash
sudo nanotun-admin webadmin create <名字>
```

容器部署同理,只是那行写在 compose 的 `environment:` 里(见 `docker/docker-compose.yml`)——
卷丢失是容器最常见的事故,而 compose 文件跟卷不在一起,那种时候它还活着。

**整台机器没了怎么办**:上面那几条针对的是「库丢了、机器还在」,那时 `/etc/nanotun`
原封不动,只补库就够。换一台机器要多一步 —— 把身份也搬过去,否则新机器会给自己生成
一套全新的 REALITY 私钥和证书,老客户端一个都连不上,而服务端日志一切正常。

```bash
# 1) 新机器上照常装(版本不必与旧机相同,新的即可)
curl -fsSL https://raw.githubusercontent.com/nanotun/server/main/scripts/install.sh -o nanotun-install.sh \
  && sudo bash nanotun-install.sh --yes --dial-host <新地址>

# 2) 停服务,把备份盖回去 —— 两样都要:/etc/nanotun 是身份,库是用户和设置
#    库用 restore 而不是 cp,理由见上一节(它会验源、留一份旧库、服务没停就拒绝)
sudo systemctl stop nanotun nanotun-web
sudo tar -xzf etc-nanotun.tar.gz -C /etc
sudo nanotun-admin --db-path /var/lib/nanotun/nanotun.db restore backup.db --yes
sudo systemctl start nanotun nanotun-web

# 3) 新机器 IP 变了的话,拨号地址是从备份里恢复的,还指着旧机器
sudo nanotun-admin --db-path /var/lib/nanotun/nanotun.db setting set server_dial_host <新地址>

# 4) 备份里没有 Web 后台管理员的话,现在建一个(理由见下)
sudo nanotun-admin --db-path /var/lib/nanotun/nanotun.db webadmin create <名字>
```

第 4 步容易漏:新机器装的时候向导写下了 `/etc/nanotun/web.env`(`ALLOW_SETUP=0`),而第 2 步
解 tar **不会**删掉归档里没有的文件,那一行就留了下来 —— 于是 /setup 关着、库里又没有管理员,
后台谁也进不去。服务是 active 的、日志干净、页面照常打开,没有一处症状指向原因,所以
`nanotun-web` 会在启动日志里直说这件事(`journalctl -u nanotun-web`)。

实测跨发行版也成立(源机 Ubuntu 26.04 → 新机 Ubuntu 20.04):恢复后证书指纹、REALITY
私钥、用户列表与源机逐字相同。

第 3 步换地址救不了已经发出去的客户端配置 —— 那里面写的是旧地址。**所以拨号地址从一开始
就该填域名而不是 IP**:换机器时改一条 DNS 记录,客户端什么都不用动。

**卸载**:装机时装成了命令,在哪个目录都能敲。

```bash
sudo nanotun-uninstall --dry-run    # 先看看会动哪些文件
sudo nanotun-uninstall              # 停服务、删程序,保留配置与数据库
sudo nanotun-uninstall --purge      # 连配置、证书、数据库一起删
```

对应发布包里的 [`scripts/uninstall.sh`](scripts/uninstall.sh);解压目录还在的话直接跑它也一样。

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
