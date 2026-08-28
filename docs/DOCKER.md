# 用 Docker 跑 nanotun

这套镜像把 `nanotund`、`nanotun-web`、`nanotun-admin` 装在**同一个容器**里。三者是绑在一起的：
Web 管理面通过 `/run/nanotun/control.sock` 跟守护进程通信，生成客户端配置二维码时还会 fork
`nanotun-admin`。拆成多个容器要共享 socket 目录和网络命名空间，麻烦远大于收益。

容器内没有 systemd，`entrypoint.sh` 顶替它做三件事：起飞前自检、首次初始化、进程守护。
代码里的 sdnotify 在 `NOTIFY_SOCKET` 为空时自动退化成空操作，不需要额外处理。

---

## 快速开始

```bash
# 宿主先设内核参数（host 网络模式下 Docker 不接受 --sysctl net.*，只能在宿主设）
cat >/etc/sysctl.d/99-nanotun.conf <<'EOF'
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv4.ping_group_range = 0 2147483647
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
EOF
sysctl --system

# 防火墙放行（systemd 那条路径由安装脚本自动做，容器这边没人替你做）
ufw allow 443/tcp && ufw allow 443/udp && ufw allow 7443/tcp

# 拿 compose 文件（不需要 clone 仓库，镜像从 GHCR 拉）
curl -fsSLO https://raw.githubusercontent.com/nanotun/server/main/docker/docker-compose.yml
docker compose up -d
docker compose logs -f
```

镜像是 `ghcr.io/nanotun/server`，amd64 / arm64 多架构，由发版流水线在过了三机 e2e
门禁的 tag 上构建（见 `docs/RELEASE.md`）。生产建议钉版本，别跟着 `latest` 漂：

```bash
NANOTUN_IMAGE_TAG=1.0.0 docker compose up -d
```

**镜像 tag 不带 `v`**。Release 页面上写的是 `v1.0.0`，镜像那边是 `1.0.0`（外加
`0.1` 和 `latest`）—— 这是容器生态的惯例，照抄 Release 的版本号会拿到一句
`not found`，而那句话看着像是没权限或者镜像是私有的，其实只是多了个字母。

想验证镜像确实来自本仓库的构建流水线：

```bash
gh attestation verify oci://ghcr.io/nanotun/server:1.0.0 --repo nanotun/server
```

首次启动会自动生成 REALITY 私钥、hy2 口令、自签证书，并初始化数据库。
**管理员 PSK 只在这一次打印**，同时落到 `/var/lib/nanotun/init.out.json`（权限 0600），请立即抄走。

管理面在 `https://<服务器IP>:7443`，首次访问走 `/setup` 创建 Web 管理员。

开发试用用另一份，它从本地源码构建（需要 clone 仓库），数据落在 `docker/data/` 下，
随时可删：

```bash
git clone https://github.com/nanotun/server.git && cd server/docker
docker compose -f docker-compose.dev.yml up --build
```

---

## 三个必须给的权限

| 需要什么 | 怎么给 | 不给会怎样 |
|---|---|---|
| `/dev/net/tun` | `devices: ["/dev/net/tun:/dev/net/tun"]` | 建不出 TUN，`nanotund` 以 exit 60 退出 |
| `CAP_NET_ADMIN` | `cap_add: [NET_ADMIN]` | 同上；iptables 和 conntrack 也全部失败 |
| `net.ipv4.ip_forward=1` | 在宿主设（host 模式下容器共用宿主的内核参数） | 同上，exit 60 |

不需要 `--privileged`。它会把 `/proc/sys` 整个变成可写，容器里一条命令就能改宿主任意内核参数，
为了一个 `ip_forward` 敞这么大的口不划算。

entrypoint 会在启动前逐条检查这三项，缺哪项就直接拒绝启动并说明怎么补，
而不是让你对着一个反复重启的容器猜原因。

关于 `ip_forward` 有个细节值得知道。Docker 是在**创建容器那一刻**按 `--sysctl` 把值设好，
之后 `/proc/sys` 就挂成只读了。所以容器里跑 `sysctl -w net.ipv4.ip_forward=1` 必然报
`permission denied`，哪怕值早就是 1。`nanotund` 遇到写失败会回读一次实际值，
已经是 1 就按已开启处理；只有回读确认不是 1 才判为致命。这条是 2026-08-02 做容器化时
实撞出来的 —— 在此之前它会以 exit 60 退出，唯一的出路是 `--privileged`。

---

## 另外三个 sysctl：容器设不进去，但不致命

`/proc/sys` 只读影响的不止 `ip_forward`。`nanotund` 启动时还会设三项，容器里同样写不进去。
它们失败只是 warning，容器照常起来 —— 而且是 **healthy**，因为数据面确实活着 —— 但功能是缺的，
缺得很安静，所以要在宿主预置。上面快速开始那段 sysctl 已经包含了，这里说明为什么：

**`rp_filter`（反向路径过滤）。** `nanotund` 会把 `conf.tun0.rp_filter` 设成 2（loose）。
发行版默认是 strict（1）时，出口节点的**回程包会被内核直接丢掉** —— 客户端表现为「连上了但什么都打不开」，
且 iptables 计数器上看不到任何丢弃。生效值取 `max(all, 接口)`，所以光设接口没用，
`all` 也得 ≤ 2；而 `tun0` 是启动时才创建的，只能靠 `default` 让它在创建那一刻继承。

**`send_redirects`。** mesh peer 互访时网关会向客户端发 ICMP Redirect，客户端路由缓存变脏、
`ping` 记成 error。生效值是 `all || 接口`，所以 `all` 和 `default` 两个都得设 0，少一个都不起作用。

**`net.ipv6.conf.all.forwarding`。** 这一项最容易被忽略，因为 IPv4 那半边看着一切正常。
宿主没预置时日志里是一句 `开启 IPv6 转发失败`，然后容器照常 healthy、IPv4 出口和 mesh 全通 ——
但**所有 IPv6 转发都不会发生**：客户端之间的 v6 mesh、经出口节点的 v6 上网全部黑洞，而客户端那边
只表现为「v6 的站点打不开」，最容易被归咎到对端或者运营商。裸机安装脚本会自己开这一项，容器这边
不行，只能靠宿主预置。

判断有没有踩到，看启动日志里这三项有没有 `失败` 字样的 warning。预置对了之后它们会降级成 info：

```
sysctl 写入被拒但该项已经是目标值(容器里 /proc/sys 常为只读,值由外部预置),按已设置处理
```

这句 info 是**正常**的 —— `nanotund` 写不进去会回读一次实际值，已经对了就按设置成功处理。
看到它说明预置生效了，不用管。

---

## 防火墙：容器不会替你开端口

`scripts/install-self-hosted.sh` 检测到 ufw active 时会自动放行 443/tcp、443/udp、以及 Web 管理面那个端口。
容器这条路径**没有对应动作** —— 容器不该去改宿主的防火墙，而 host 模式下端口就绑在宿主网卡上，
ufw 的 INPUT 策略照样拦。现象是容器 healthy、日志干净、本机 `curl 127.0.0.1:7443` 也正常，
唯独从外面连不上。

```bash
ufw allow 443/tcp   # REALITY
ufw allow 443/udp    # Hysteria2（用了端口跳跃的话，把整段范围一起放行）
ufw allow 7443/tcp   # Web 管理面（只想内网访问就别开，改用 SSH 端口转发）
```

自己改用 bridge 的话要反过来小心：Docker 的 DNAT 规则排在 `ufw-*` 链之前，**发布出去的端口
会绕过 ufw**。你以为 ufw 拦着，实际全世界都能连，管理面尤其危险。那边只能靠 `ports` 绑到
具体地址上收口（比如 `127.0.0.1:7443:7443`），ufw 帮不上忙。

---

## 为什么只有 host 模式

这里只提供 host 网络模式（`docker-compose.yml`）。不是省事，是这个 VPN 网关有两件事要在宿主的
网络栈里做，bridge 下做不成，而且**两件都不报错**：

**端口跳跃。** hy2 的端口跳跃靠 `nanotund` 启动时自己往 `nat PREROUTING` 写 REDIRECT，
把一段 UDP 端口重定向到主端口。bridge 下这条链在**容器自己的网络命名空间**里，而公网来的包
先落在宿主的命名空间，只有宿主 `ports` 发布过的端口才会被转进容器 —— 没发布的端口根本到不了
那条链，规则装得好好的却一个包也匹配不到，且不报错。

把整段端口发布出来也不成立：Docker 每个发布端口要一条 DNAT 规则加两个 `docker-proxy` 进程
（v4/v6 各一）。实测发布 100 个 UDP 端口是 100 条规则 + 200 个进程，发布 500 个时直接
fork 失败、容器起不来；而端口跳跃有意义的量级是几千个端口。

**公网 IPv6 出口。** Docker 的默认 bridge 网络只有 v4，容器压根没有 v6 出网能力。
`nanotund` 启动时探测得出 `has_ipv6_egress=false` 并明确警告，然后照常服务：客户端仍然分到
v6 vIP、**mesh 内部的 v6 照常互通**，只有去公网的 v6 会被数据面回 ICMPv6 unreachable 秒回落
v4。功能上不算崩，但你以为在跑双栈、实际是单栈。要 v6 就得自己给 docker 网络开 IPv6，
不是改一行 compose 的事。

出口 NAT 和出口网卡推断这两件，**实测比预想的好**：bridge 下变成双重 NAT（容器 SNAT 到
`172.x`，宿主再 SNAT 到公网），出口节点是通的，而且从公网看到的出口 IP 就是宿主的公网 IP、
和 host 模式一致；`ip route get` 在容器命名空间里推断出的 `eth0` 对那个命名空间来说也是对的，
NAT 规则挂得没错。排查时对不上号的是容器内那条 SNAT 规则写的是容器地址，仅此而已。

代价要说清楚：host 模式下容器和宿主共用网络栈，容器写的 iptables 规则**就是宿主的规则**，
`ip_forward` 也是宿主的。网络这一层的容器隔离基本不存在了。这正是这个应用需要的，
但你要知道自己在换什么 —— 拿容器换来的是交付和依赖的一致，不是网络隔离。

不用端口跳跃、也不要公网 v6 的话，bridge 是能跑的，自己写一份 compose 即可（要点：
`sysctls` 里预置 `ip_forward` / `rp_filter` / `send_redirects`，因为容器建好之后 `/proc/sys`
就只读了；`ports` 里逐个映射端口，容器内开的监听不会自动出现在宿主上，Web 里配的端口转发
尤其容易忘）。仓库不附带这份配置：漏掉的那两件事都属于**不报错的缺功能**，放在这儿容易被
当成平级选项随手拿去跑真网关。

一次实测留个底（Debian 11 + Docker 29.7.2，把官方 compose 的 `network_mode: host` 换成
`ports` 逐个发布）：容器 healthy，REALITY(TCP 443) 和 hy2(UDP 443) 都能从公网连进来，
出口流量正常、5MB 下载完整，Web 管理面可达。**客户端的真实公网 IP 也没丢** —— Docker 发布
端口走的是 iptables DNAT 而不是用户态代理，审计日志里记的是客户端的真实地址，不是网关地址。
另外 `exit-guard` 会自动把 docker 的网段（如 `172.18.0.0/16`）一起拦进私网黑名单，客户端
碰不到同宿主的其它容器。

---

## 在 Mac / Windows 上：能起来，但 host 的不是你那台机器

宿主不是 Linux 时，Docker 并不在你的系统上跑容器 —— Docker Desktop 底下开了一台 Linux
虚拟机，容器全在那台 VM 里。所以 `network_mode: host` 里的 host **永远是一台 Linux 主机**，
只是换成了那台 VM：它没有 WAN 网卡，它在宿主系统的 NAT 后面，宿主又在路由器的 NAT 后面。

于是上一节列的三件事全部落空，而且**不报错**：容器照样把 `ip_forward` 打开、照样把 iptables
规则写进去、`ip route get 1.1.1.1` 照样返回一个出口网卡 —— 全在 VM 里，一样都不作数。
这是这里最需要提防的地方，坏得完全没有声音。

还有个机械层面的坑：`network_mode: host` 在 Docker Desktop 上长期直接被忽略，4.34 之后才
作为一个要手动打开的功能存在（Settings → Resources → Network）。没开那个开关它就是不生效，
同样不会有任何提示。

仍然正常的部分比想象中多：`/dev/net/tun` 在 VM 里是有的，`NET_ADMIN` 也给得了，所以
`nanotund` 能起、Web 能开、`nanotun-admin` 和 SQLite 都正常。看看这套东西长什么样、点点后台、
改改配置，完全够用。跑不了的是真实客户端从公网连进来、端口跳跃、真实出口与 NAT ——
也就是 e2e 覆盖的那一整片，所以 **e2e 必须打 Linux 机器**，Mac 上跑不出结论。

**所以 Mac / Windows 不是受支持的部署环境**，只适合把这套东西起起来看看。真要跑服务就得是
Linux 机器。想在 Mac 上开管理界面看一眼的话，host 那个开关不好用时改成 bridge 加
`ports: ["7443:7443"]` 更省事 —— 发布出来的端口 Docker Desktop 会转到你机器的 localhost。
仓库不附带这份配置，理由见上一节。

最后一条与网络无关但同样会咬人：Apple Silicon 上 `docker build` 出来的是 **arm64** 镜像。
它**不能**直接搬到 x86 服务器，要在 Mac 上构建给服务器用的话加 `--platform linux/amd64`：

```bash
docker build --platform linux/amd64 -t nanotun:latest .
```

（用 GHCR 上的发布镜像就没这个问题：那是多架构 manifest，`docker pull` 会自动挑
宿主对应的架构。这一段只适用于自己从源码构建的情况。）

架构这件事镜像里有一道构建期断言兜着：二进制的 ELF `e_machine` 与基底 `dpkg` 架构不一致
就直接构建失败。它防的是一种很难自己发现的错配 —— 基底按本机平台拉、二进制却编成了另一个
架构，镜像能构建成功、能推、还自称是基底的架构，只在真机启动那一刻才 `exec format error`；
而在开发机上因为有 binfmt / Rosetta 兜底，连那一下都不会炸。

---

## iptables 后端：一个会安静坏掉的坑

镜像基底用的是 `debian:bookworm-slim` 而不是 alpine，多 60MB 左右，换的是**后端与宿主一致**。

Debian 的 `iptables` 包默认走 nft 后端，和现代 Ubuntu / Debian 宿主同款；alpine 的
`iptables` 是 legacy 后端。两者写的是内核里**不同的表**。后端不匹配时，`iptables -L`
看着干净、命令也返回成功，规则却没进宿主实际生效的那张表 —— NAT 不生效、出口静默黑洞，
而且完全没有报错。

启动日志里有一行 `[entrypoint] iptables: ...`，写明容器用的是哪个后端。宿主上跑
`iptables --version` 对一下，两边应该一致。

宿主确实是 legacy 后端时，在容器里切过去：

```dockerfile
RUN update-alternatives --set iptables  /usr/sbin/iptables-legacy \
 && update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy
```

---

## 数据持久化与备份

两个卷，都要备份：

| 路径 | 内容 | 丢了会怎样 |
|---|---|---|
| `/etc/nanotun` | `config.toml`、TLS 证书、mTLS CA、masquerade 页 | REALITY 私钥和 hy2 口令没了，所有客户端要重配 |
| `/var/lib/nanotun` | SQLite 库（用户 / 设备 / ACL / 租约） | 所有客户端要重新接入，固定 IP 和 ACL 全丢 |

`/run/nanotun` 是 tmpfs，只放控制面 socket，不用备份。

热备份（服务不用停，走 SQLite 的 `VACUUM INTO` 拍强一致快照）：

```bash
docker compose exec nanotun nanotun-admin backup --out /var/lib/nanotun/backup.db
docker compose cp nanotun:/var/lib/nanotun/backup.db ./nanotun-$(date +%F).db
```

配置那一侧直接拷卷就行：

```bash
docker run --rm -v nanotun-etc:/src -v "$PWD":/dst alpine \
  tar czf /dst/nanotun-etc-$(date +%F).tar.gz -C /src .
```

---

## 日常操作

`nanotun-admin` 在镜像里，直接进容器用：

```bash
docker compose exec nanotun nanotun-admin user list
docker compose exec nanotun nanotun-admin device list
docker compose exec nanotun nanotun-admin reload acl
```

改了 `config.toml` 之后，大部分 ACL 类改动能热更（`reload acl`），但约 30 个字段是
**启动时读一次**的（hy2 口令、PoW、`exit_mode`、TLS 路径、`lease_gc_*` 等），
必须重启容器才生效：

```bash
docker compose restart nanotun
```

哪些字段属于这一类，见 `docs/RELEASE.md` 里的延迟生效表。

---

## 升级

拉新镜像滚一次就行，数据在卷里：

```bash
docker compose pull
docker compose up -d
```

钉了 `NANOTUN_IMAGE_TAG` 的话，改成新版本号再 `up -d`。从本地源码构建的
（`docker-compose.dev.yml`）才需要 `docker compose build --pull`。

`entrypoint.sh` **不会**覆盖已有的 `config.toml`，只会把新模板刷到
`/etc/nanotun/config.toml.dist`。升级后想看新增了哪些字段：

```bash
docker compose exec nanotun diff /etc/nanotun/config.toml /etc/nanotun/config.toml.dist
```

确实想用模板推倒重来，设 `NANOTUN_FORCE_CONFIG=1`（原文件会自动备份成 `config.toml.bak.*`）。
注意这会重签 REALITY 私钥和 hy2 口令，等于把所有现有客户端一次性踢下线。

---

## 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `NANOTUN_WEB_ENABLED` | `1` | 设 `0` 只跑数据面，不起 Web 管理面 |
| `NANOTUN_WEB_LISTEN` | `0.0.0.0:7443` | 管理面监听地址 |
| `NANOTUN_WEB_EXTRA_SANS` | 空 | 自签证书额外 SAN，如 `vpn.example.com` |
| `NANOTUN_WEB_TRUSTED_PROXIES` | 空 | 可信反代 IP/CIDR。放在 nginx 后面时必须设，否则按 IP 的登录限流看到的全是反代地址 |
| `NANOTUN_FORCE_CONFIG` | `0` | 用镜像模板覆盖已有配置（会备份原文件） |
| `NANOTUN_MAGIC_SUFFIX` | 空（模板默认 `nanotun`） | MagicDNS 局域网后缀，客户端解析 `*.<后缀>` → mesh 虚拟 IP。**只在首次生成 `config.toml` 时生效**；卷里已有配置后再改这行不起作用（改法见下） |
| `NANOTUN_REALITY_PORT` | 空（模板默认 `443`） | REALITY 的 TCP 端口。宿主上 443 已被别的服务占着时用它换一个。**只在首次生成 `config.toml` 时生效**；卷里已有配置后再改不起作用（挪动它会让所有现有客户端连不上，因为端口印在已经发出去的配置里）。与裸机的 `--reality-port` 同义 |
| `NANOTUN_SKIP_INIT` | `0` | 跳过 `nanotun-admin init`。init 本身幂等，这个开关只为特殊排查保留 |
| `NANOTUN_LANG` | `en` | 日志与 CLI 的语言，`en` 或 `zh`。容器里不问、不猜，默认英文 |

> `NANOTUN_LANG` 是**整个项目共用**的那一个语言开关：`entrypoint.sh` 的日志、`nanotund` /
> `nanotun-web` / `nanotun-admin` 的输出都认它（Web 后台另有自己的语言切换器和 cookie，
> 与这里无关）。裸机安装那条路（`scripts/install.sh`）也是同一个变量、同一套优先级。
>
> 首次启动时它会被落盘到卷里的 `/etc/nanotun/lang`。这一步是为 `docker exec` 那条路准备的：
> `docker exec <容器> nanotun-admin user list` 是一个**新起的进程**，不继承 compose 里
> `environment:` 给主进程的变量 —— 不落盘的话，同一台机器上容器日志是中文、`docker exec`
> 敲出来的却是英文。显式给了 `NANOTUN_LANG` 时仍以给的为准。

> `NANOTUN_MAGIC_SUFFIX` 想换成别的（模板默认已是 `nanotun`），要在**首次 `up -d` 前**设好（`docker-compose.yml` 的 `environment:` 里有注释好的样例）。数据卷里已经有 `config.toml` 之后，这个变量会被 `entrypoint.sh` 忽略并给出告警 —— 此时改后缀有两条路：直接改卷里 `config.toml` 的 `[server.magic_dns].domain_suffix` 再重启容器，或设 `NANOTUN_FORCE_CONFIG=1` 用模板重来（后者会重签密钥、踢掉所有客户端）。注意运行期后缀**只**从 `config.toml` 读，`nanotun-admin setting set magic_suffix` 不是入口（会被硬拒并指路）。
>
> `NANOTUN_REALITY_PORT` 同理，而且后果更重：REALITY 的端口印在每一份已经发出去的客户端配置里，挪走等于把所有现有客户端一次性踢下线，而他们看到的只是「连不上」。另外镜像 `EXPOSE` 的是 `443/tcp`（构建期写死），桥接模式下换了端口要自己 `-p <口>:<口>`；`network_mode: host` 不受影响。

---

## 进程守护的行为

两个进程的重启策略**刻意不同**，与 systemd 下两个独立 unit 的行为对齐：

`nanotund` 挂了 → 整个容器退出，交给 Docker 的 restart 策略拉起。没有它什么都干不了。

`nanotun-web` 挂了 → 就地重启，不动数据面。为了一个管理界面把所有 VPN 客户端踢下线，
代价和收益完全不成比例。60 秒内连挂 5 次就不再拉起，只留日志 —— 配置写错时无限重启
只会把日志刷爆，反而盖住真正的错误行。

放弃拉起后容器会转成 **unhealthy**，尽管数据面还在正常转发。systemd 那边这种情况
`systemctl is-active nanotun-web` 会显示 failed，容器里没有第二个 unit 可看，只能靠健康
状态把「后台已经进不去了」这件事说出来。看见 unhealthy 又能连上 VPN，先查日志里
`nanotun-web` 的退出原因（host 模式下最常见的是 7443 被宿主上别的服务占了），修好后
`docker compose restart` 即可 —— 管理面不会自己回来。

`NANOTUN_WEB_ENABLED=0` 是有意只跑数据面，不算降级，健康状态照常。

有几个退出码重启也没用，entrypoint 会直接停下并说明：

| 退出码 | 含义 |
|---|---|
| 10 | 配置解析失败（TOML 语法错） |
| 11 | 配置语义错（字段值非法） |
| 20 | TLS 证书问题 |
| 60 | 网络配置失败（TUN / ip_forward / iptables） |

前三个对应 systemd unit 里的 `RestartPreventExitStatus=10 11 20`。Docker 的 restart 策略
没有「某些退出码不重启」这种表达，只能在 entrypoint 里判。

**容器的退出码就是 `nanotund` 的退出码**，上表这几个原样透出来：

```bash
docker inspect -f '{{.State.ExitCode}}' nanotun   # 11 = 配置语义错
```

别只看日志判死因 —— 编排系统、告警规则、运维脚本读的都是退出码。唯一被改写的是
`nanotund` 在没人要求关停的情况下以 `0` 退出：那不是正常收工，容器会以 `1` 退出，
免得 `docker ps` 显示成 `Exited (0)` 骗过巡检。

---

## 已知不适用的场景

**多副本 / 编排调度。** SQLite 是单写者，两个实例挂同一个卷会互相踩。这套东西的形态就是
单机网关，不要往 k8s Deployment 里放多副本。

**只读根文件系统。** `nanotund` 要写 `/run/nanotun`、`/etc/nanotun/certs`，
`read_only: true` 需要额外挂一堆 tmpfs，收益不大，暂时没做。

**非 root 运行。** 需要 `CAP_NET_ADMIN` 和写 `/etc/nanotun`，`User=root` 是 systemd 那边
就定下的形态，容器里保持一致。
