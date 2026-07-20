#!/bin/bash
# 移除“玩家间隔离”规则，恢复各 TUN 网段可互通（需 root）

IPSET_NAME="vpn_client_ips"
IPTABLES_CHAIN="INPUT"

while iptables -C "$IPTABLES_CHAIN" -i tun+ -m set --match-set "$IPSET_NAME" src -m set --match-set "$IPSET_NAME" dst -j DROP 2>/dev/null; do
  iptables -D "$IPTABLES_CHAIN" -i tun+ -m set --match-set "$IPSET_NAME" src -m set --match-set "$IPSET_NAME" dst -j DROP
done
ipset destroy "$IPSET_NAME" 2>/dev/null || true
echo "TUN isolation removed."
