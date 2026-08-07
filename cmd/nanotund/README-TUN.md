# 服务端 TUN 网卡

**只有一张。** nanotund 启动时自己建 `[tun].device_name`（默认 `tun0`，先删后建），
网段从 `[tun].subnets` 的候选里挑一个和本机不冲突的：

```toml
device_name = "tun0"
# 10.200~10.202/16，避开常见局域网 10.0.x
subnets = ["10.200.0.0/16", "10.201.0.0/16", "10.202.0.0/16"]
```

选中的那一段会粘住（`tun_subnet_sticky.go`），重启后客户端拿到的还是原来的虚拟 IP。
不需要谁替它预先建网卡。

## nanotun-tun-setup.service 是干什么的

名字是历史遗留，它现在跟"建网卡"没关系了，只做两件与 TUN 无关的杂事：

1. `touch /run/xtables.lock` —— 必须赶在 nanotun.service 建 mount namespace **之前**。
   老发行版上 iptables 是 legacy 后端，要在这个文件上加锁，而 nanotund 跑在
   `ProtectSystem=strict` 里、`/run` 是只读的，拿不到锁就 crash-loop。详见单元文件里的注释。
2. 清理老版本遗留的空网卡（见下）。

`nanotun.service` 用 `Requires=` 依赖它，所以这个单元必须能成功跑完。

## 旧版的 15 张网卡（v0.1.14 及之前）

老的 `tun-setup.sh` 会建 tun0–tun14，每张占一个私网段（10.0.0–4、192.168.100–104、
172.16–20），想法是"任一局域网顶多冲突一段"。但产品早就是单网卡了，那 14 张**从未被
使用**，而地址是真占的 —— 谁的网关落进哪张 tunN 的 /24，那台机器装完就出不了网：
/24 比网卡自己的 /16 更具体，路由抢得过，网关地址还成了 tunN 上的本机地址，
内核把发往网关的包直接收进 lo。症状是服务全 active、日志干净，然后 SSH 再也连不回来。

踩中的都不是冷门配置：`172.17.0.0/24` 是 Docker 默认的 docker0；`10.0.1.0/24` /
`10.0.2.0/24` 是 AWS 默认 VPC 向导建的子网；192.168.100–104 是常见家宽网段。

现在不再创建它们，并且升级或卸载时会主动清掉遗留的那 14 张。清理只认"名字是 tunN、
类型是 tun、地址正好是老脚本会分的那一个"三者全中的设备，不会碰用户自己建的同名网卡。

## 客户端间隔离（默认关闭）

M0 起默认不做隔离：自托管 mesh 场景下客户端互通是核心功能，访问控制由应用层 ACL
完成（`store/acl.go`）。仅当 `NANOTUN_TUN_ISOLATE=1` 时才会执行
`/usr/local/bin/nanotun-tun-isolate.sh`。

> 注意：`tun-isolate.sh` 里的网段仍是旧版那 15 段，与现在的单网卡设计对不上 ——
> 要用隔离得先按实际的 `[tun].subnets` 改它。

## 删除网卡

卸载脚本会调用；也可手动执行（需 root）：

```bash
/usr/local/bin/nanotun-tun-teardown.sh
```
