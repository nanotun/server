#!/bin/bash
# 在系统层面禁止「玩家虚拟 IP」之间互访：只允许玩家 ↔ 网关/公网
# 与 tun-setup.sh 的 15 个网段一致。需 root，依赖 ipset 和 iptables

set -e

IPSET_NAME="vpn_client_ips"
IPTABLES_CHAIN="INPUT"
# 标记用，避免重复插入
RULE_COMMENT="nanotun: drop client-to-client"

# 创建 ipset（存所有“玩家可用 IP”，即各网段去掉网关 .1）
if ! ipset list "$IPSET_NAME" &>/dev/null; then
  ipset create "$IPSET_NAME" hash:ip hashsize 4096 maxelem 65536
fi
ipset flush "$IPSET_NAME"

# 各网段：网关为 x.x.x.1，玩家 IP 为 x.x.x.2–254
add_range() { ipset add "$IPSET_NAME" "$1"; }
add_range "10.0.0.2-10.0.0.254"
add_range "10.0.1.2-10.0.1.254"
add_range "10.0.2.2-10.0.2.254"
add_range "10.0.3.2-10.0.3.254"
add_range "10.0.4.2-10.0.4.254"
add_range "192.168.100.2-192.168.100.254"
add_range "192.168.101.2-192.168.101.254"
add_range "192.168.102.2-192.168.102.254"
add_range "192.168.103.2-192.168.103.254"
add_range "192.168.104.2-192.168.104.254"
add_range "172.16.0.2-172.16.0.254"
add_range "172.17.0.2-172.17.0.254"
add_range "172.18.0.2-172.18.0.254"
add_range "172.19.0.2-172.19.0.254"
add_range "172.20.0.2-172.20.0.254"

# 若已存在规则则先删（按序号或匹配条件）
while iptables -C "$IPTABLES_CHAIN" -i tun+ -m set --match-set "$IPSET_NAME" src -m set --match-set "$IPSET_NAME" dst -j DROP 2>/dev/null; do
  iptables -D "$IPTABLES_CHAIN" -i tun+ -m set --match-set "$IPSET_NAME" src -m set --match-set "$IPSET_NAME" dst -j DROP
done
iptables -I "$IPTABLES_CHAIN" 1 -i tun+ -m set --match-set "$IPSET_NAME" src -m set --match-set "$IPSET_NAME" dst -j DROP

echo "TUN isolation applied: client-to-client traffic dropped (same or cross subnet)."
