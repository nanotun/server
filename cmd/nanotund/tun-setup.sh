#!/bin/bash
# 开机时跑一次（systemd nanotun-tun-setup.service），在 nanotund 起来之前。
#
# 这里**不再创建任何 TUN 设备**。nanotund 自己会按 [tun].device_name 建它要的那一张
# （默认 tun0，先删后建），网段从 [tun].subnets 里挑一个和本机不冲突的，不需要谁替它
# 预先铺好。
#
# 原先这里会一口气建 15 张（tun0–tun14），每张占一个私网段：
#   tun0–4   10.0.0.1/24 … 10.0.4.1/24
#   tun5–9   192.168.100.1/24 … 192.168.104.1/24
#   tun10–14 172.16.0.1/24 … 172.20.0.1/24
# 想法是「任一局域网顶多冲突一段，其余两段仍可用」。但产品早就不是多网卡了，这 14 张
# 从建出来那一刻起就没人用过 —— 而它们占的地址是真占的。
#
# 于是这变成了一颗踩谁谁死的雷:哪张 tunN 的 /24 罩住了本机的网关，那台机器装完就出
# 不了网了。/24 比网卡自己的 /16 更具体，路由抢得过；更要命的是网关地址成了 tunN 上的
# **本机地址**，内核直接把发给网关的包收进 lo。表现是装完一切正常、服务全 active、
# 日志干净，然后 SSH 断了再也连不回来 —— 而原因在一张跟功能毫无关系的空网卡上。
#
# 中招的都不是冷门配置:
#   · 172.17.0.0/24 —— Docker 默认的 docker0，自托管的人十有八九装了 Docker
#   · 10.0.1.0/24、10.0.2.0/24 —— AWS 默认 VPC 向导建的就是这两个子网
#   · 192.168.100–104 —— 常见家宽 / 办公室网段，也有 VPS 内网用
# 反讽的是 nanotund 的候选网段特意选了 10.200–10.202/16「避免与常见局域网 10.0.x
# 冲突」,而这个脚本转头把 10.0.x 全占了。
#
# 现在只剩两件事:把老版本留下的那 14 张清掉(见下)，以及单元里那句 touch
# /run/xtables.lock（原因写在 tun-setup.service 里，跟 TUN 无关）。

set -e

# 清理老版本(v0.1.14 及之前)留下的 tun1–tun14。
#
# 它们是 persist on 的，进程退了也不会消失，光升级二进制不会让它们走 —— 不主动删就
# 一直留到下次重启，那台机器的网也就一直坏着。升级路径上顺手治好，比在文档里写一句
# 「请手动检查」有用得多。
#
# 只删「名字对得上、类型是 tun、地址正好是老脚本会分的那一个」的设备。少了这层核对，
# 一台自己建了 tun3 干别的事的机器，会在装 nanotun 时被无声地拆掉网卡。tun0 不在清理
# 范围里 —— 那是 nanotund 自己要用的，它启动时会先删后建。
for i in $(seq 1 14); do
  dev=tun$i
  ip link show "$dev" >/dev/null 2>&1 || continue

  if   (( i < 5 ));  then legacy_addr="10.0.$i.1/24"
  elif (( i < 10 )); then legacy_addr="192.168.$((100+i-5)).1/24"
  else                    legacy_addr="172.$((16+i-10)).0.1/24"
  fi

  # 类型必须是 tun:名字叫 tun3 的网桥 / 物理口不能碰。
  ip -d link show "$dev" 2>/dev/null | grep -q ' tun ' || continue
  ip -o -4 addr show dev "$dev" 2>/dev/null | grep -qF " $legacy_addr " || continue

  ip link set "$dev" down 2>/dev/null || true
  if ip tuntap del dev "$dev" mode tun 2>/dev/null; then
    echo "已清除旧版遗留的空网卡 ${dev}（${legacy_addr}，从未被使用，可能挡住本机路由）"
  fi
done

echo "TUN 预处理完成:不预建网卡,nanotund 会自己建 [tun].device_name 那一张"

# 清掉旧版「客户端隔离」shell 脚本(NANOTUN_TUN_ISOLATE=1)留下的规则。
#
# 那套东西已经删了,因为它三样全占:
#  · 不起作用 —— ipset 里锁的是上面那 15 个早已不存在的网段,真实客户端在
#    [tun].subnets(默认 10.201/16),一个都匹配不上;而且规则挂在 INPUT,客户端互访
#    走的是 FORWARD。开着它的人以为客户端之间互相隔离了,实际一点没隔。
#  · 会断服 —— 它依赖 ipset,而它是被本脚本在 set -e 下调用的。没装 ipset 的机器上
#    tun-setup 退 127,nanotun.service 因为 Requires= 直接起不来,日志里只有一句
#    status=127/n/a,连 ipset 三个字都不出现。
#  · 是重复的 —— 真正能用的隔离在 Go 里:config.toml 的 exit_mode = "isolate",
#    规则插在 FORWARD、用的是实际网段,还处理了与出口节点 / 子网路由的互斥。
#
# 只在确实有残留时才动手,并且不让失败影响本脚本 —— 这是打扫,不是本职工作,
# 没有任何理由因为打扫没做成而把 VPN 拖下水(那正是上面第二条的教训)。
if command -v ipset >/dev/null 2>&1 && ipset list vpn_client_ips >/dev/null 2>&1; then
  while iptables -C INPUT -i tun+ -m set --match-set vpn_client_ips src \
        -m set --match-set vpn_client_ips dst -j DROP 2>/dev/null; do
    iptables -D INPUT -i tun+ -m set --match-set vpn_client_ips src \
      -m set --match-set vpn_client_ips dst -j DROP 2>/dev/null || break
  done
  ipset destroy vpn_client_ips 2>/dev/null || true
  echo "已清除旧版客户端隔离残留（那套机制不起作用且会断服，已移除；要隔离请用 exit_mode = \"isolate\"）"
fi
