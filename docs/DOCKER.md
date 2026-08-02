# 用 Docker 跑 nanotun

这套镜像把 `nanotund`、`nanotun-web`、`nanotun-admin` 装在**同一个容器**里。三者是绑在一起的：
Web 管理面通过 `/run/nanotun/control.sock` 跟守护进程通信，生成客户端配置二维码时还会 fork
`nanotun-admin`。拆成多个容器要共享 socket 目录和网络命名空间，麻烦远大于收益。

容器内没有 systemd，`entrypoint.sh` 顶替它做三件事：起飞前自检、首次初始化、进程守护。
代码里的 sdnotify 在 `NOTIFY_SOCKET` 为空时自动退化成空操作，不需要额外处理。

---

## 快速开始

```bash
# 宿主先开转发（host 网络模式下 Docker 不接受 --sysctl net.*，只能在宿主设）
cat >/etc/sysctl.d/99-nanotun.conf <<'EOF'
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv4.ping_group_range = 0 2147483647
EOF
sysctl --system

cd docker
docker compose up -d
docker compose logs -f
```

首次启动会自动生成 REALITY 私钥、hy2 口令、自签证书，并初始化数据库。
**管理员 PSK 只在这一次打印**，同时落到 `/var/lib/nanotun/init.out.json`（权限 0600），请立即抄走。

管理面在 `https://<服务器IP>:7443`，首次访问走 `/setup` 创建 Web 管理员。

开发试用用另一份，数据落在 `docker/data/` 下，随时可删：

```bash
docker compose -f docker-compose.dev.yml up --build
```

---

## 三个必须给的权限

| 需要什么 | 怎么给 | 不给会怎样 |
|---|---|---|
| `/dev/net/tun` | `devices: ["/dev/net/tun:/dev/net/tun"]` | 建不出 TUN，`nanotund` 以 exit 60 退出 |
| `CAP_NET_ADMIN` | `cap_add: [NET_ADMIN]` | 同上；iptables 和 conntrack 也全部失败 |
| `net.ipv4.ip_forward=1` | host 模式在宿主设；bridge 模式用 compose 的 `sysctls` | 同上，exit 60 |

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

## host 还是 bridge

默认给的是 host（`docker-compose.yml`），因为这是个 VPN 网关，它要在宿主的网络栈里做三件
bridge 模式下做不成的事：

**端口跳跃。** hy2 的端口跳跃靠 iptables NAT REDIRECT 把一段 UDP 端口重定向到主端口。
bridge 下入站先过 Docker 自己的 DNAT 链，两套 NAT 顺序冲突，跳跃基本失效。

**出口 NAT。** 出口节点要对客户端流量做 MASQUERADE。bridge 下变成双重 NAT，能通，
但出口 IP 是容器地址，排查时和宿主对不上号。

**出口网卡推断。** 代码用 `ip route get 1.1.1.1` 推断出口网卡和出口 IP。bridge 下拿到的是
容器的 `eth0` 和 `172.17.x.x`，NAT 规则会挂到错误的接口上。

代价要说清楚：host 模式下容器和宿主共用网络栈，容器写的 iptables 规则**就是宿主的规则**，
`ip_forward` 也是宿主的。网络这一层的容器隔离基本不存在了。这正是这个应用需要的，
但你要知道自己在换什么。

只做 mesh 互联、不依赖端口跳跃、也不当出口节点的话，用 `docker-compose.bridge.yml`，
里面把限制和注意事项逐条写在注释里了。最容易忘的一条：**Web 里配的端口转发，
需要在 compose 的 `ports` 里逐个映射出来**，容器内开的监听不会自动出现在宿主上。

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

镜像重建后滚一次就行，数据在卷里：

```bash
cd docker
docker compose build --pull
docker compose up -d
```

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
| `NANOTUN_SKIP_INIT` | `0` | 跳过 `nanotun-admin init`。init 本身幂等，这个开关只为特殊排查保留 |

---

## 进程守护的行为

两个进程的重启策略**刻意不同**，与 systemd 下两个独立 unit 的行为对齐：

`nanotund` 挂了 → 整个容器退出，交给 Docker 的 restart 策略拉起。没有它什么都干不了。

`nanotun-web` 挂了 → 就地重启，不动数据面。为了一个管理界面把所有 VPN 客户端踢下线，
代价和收益完全不成比例。60 秒内连挂 5 次就不再拉起，只留日志 —— 配置写错时无限重启
只会把日志刷爆，反而盖住真正的错误行。

有几个退出码重启也没用，entrypoint 会直接停下并说明：

| 退出码 | 含义 |
|---|---|
| 10 | 配置解析失败（TOML 语法错） |
| 11 | 配置语义错（字段值非法） |
| 20 | TLS 证书问题 |
| 60 | 网络配置失败（TUN / ip_forward / iptables） |

前三个对应 systemd unit 里的 `RestartPreventExitStatus=10 11 20`。Docker 的 restart 策略
没有「某些退出码不重启」这种表达，只能在 entrypoint 里判。

---

## 已知不适用的场景

**多副本 / 编排调度。** SQLite 是单写者，两个实例挂同一个卷会互相踩。这套东西的形态就是
单机网关，不要往 k8s Deployment 里放多副本。

**只读根文件系统。** `nanotund` 要写 `/run/nanotun`、`/etc/nanotun/certs`，
`read_only: true` 需要额外挂一堆 tmpfs，收益不大，暂时没做。

**非 root 运行。** 需要 `CAP_NET_ADMIN` 和写 `/etc/nanotun`，`User=root` 是 systemd 那边
就定下的形态，容器里保持一致。
