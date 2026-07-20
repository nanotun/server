#!/bin/bash
# 服务端 139 上执行：步骤 4～8 合一（TUN、转发、SNAT、UFW、可选隔离、持久化）
# 用法：在 139 上 root 执行
#   bash /root/nanotun/server/setup-network-and-persist.sh
#   bash /root/nanotun/server/setup-network-and-persist.sh --no-isolate   # 不启用客户端互访隔离
set -e

ENABLE_ISOLATE=true
[[ "${1:-}" == "--no-isolate" ]] && ENABLE_ISOLATE=false

echo "=== 4. 创建 TUN 虚拟网卡 ==="
bash /root/nanotun/server/tun-setup.sh
ip addr show tun0 | head -3

echo ""
echo "=== 5. 配置转发与 NAT ==="
sysctl -w net.ipv4.ip_forward=1
WAN_IF=$(ip route get 1.1.1.1 | awk '{print $5; exit}')
WAN_IP=$(ip -4 addr show dev "$WAN_IF" | awk '/inet /{print $2; exit}' | cut -d/ -f1)
echo "公网接口: $WAN_IF, 出口 IP: $WAN_IP"

iptables -I FORWARD 1 -i tun+ -o "$WAN_IF" -j ACCEPT
iptables -I FORWARD 1 -i "$WAN_IF" -o tun+ -m state --state ESTABLISHED,RELATED -j ACCEPT

# 每个虚拟 IP 最多 40 TCP、40 UDP 连接（connlimit，插到链首先于 ACCEPT 生效）
iptables -I FORWARD 1 -i tun+ -p udp -m connlimit --connlimit-above 40 --connlimit-saddr --connlimit-mask 32 -j DROP
iptables -I FORWARD 1 -i tun+ -p tcp -m connlimit --connlimit-above 40 --connlimit-saddr --connlimit-mask 32 -j DROP

for p in tcp udp; do
  iptables -t nat -A POSTROUTING -s 10.0.0.0/21 -o "$WAN_IF" -p $p -j SNAT --to-source "${WAN_IP}:10000-65535"
  iptables -t nat -A POSTROUTING -s 192.168.100.0/22 -o "$WAN_IF" -p $p -j SNAT --to-source "${WAN_IP}:10000-65535"
  iptables -t nat -A POSTROUTING -s 192.168.104.0/24 -o "$WAN_IF" -p $p -j SNAT --to-source "${WAN_IP}:10000-65535"
  iptables -t nat -A POSTROUTING -s 172.16.0.0/13 -o "$WAN_IF" -p $p -j SNAT --to-source "${WAN_IP}:10000-65535"
done
iptables -t nat -A POSTROUTING -s 10.0.0.0/21 -o "$WAN_IF" -j SNAT --to-source "$WAN_IP"
iptables -t nat -A POSTROUTING -s 192.168.100.0/22 -o "$WAN_IF" -j SNAT --to-source "$WAN_IP"
iptables -t nat -A POSTROUTING -s 192.168.104.0/24 -o "$WAN_IF" -j SNAT --to-source "$WAN_IP"
iptables -t nat -A POSTROUTING -s 172.16.0.0/13 -o "$WAN_IF" -j SNAT --to-source "$WAN_IP"
echo "FORWARD/SNAT 已配置"

echo ""
echo "=== 6. 配置 UFW ==="
ufw allow 22/tcp 2>/dev/null || true
ufw allow 8080/tcp
ufw allow 3300/udp
# TCP 数据面默认 :3401；与 config.toml [tcp].listen_addr 一致，改过端口则改此处
ufw allow 3401/tcp
ufw --force enable
ufw status | head -12

if "$ENABLE_ISOLATE"; then
  echo ""
  echo "=== 7. 客户端之间隔离（tun→tun 丢弃）==="
  iptables -I FORWARD 1 -i tun+ -o tun+ -j DROP
  echo "已启用客户端互访隔离"
else
  echo ""
  echo "=== 7. 跳过客户端隔离（如需启用请不加 --no-isolate 再跑）==="
fi

echo ""
echo "=== 8. 持久化 ==="
grep -q "^net.ipv4.ip_forward" /etc/sysctl.conf 2>/dev/null || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo ""
echo "--- TCP BBR（可选，失败不阻断后续）---"
bash "$SCRIPT_DIR/enable-bbr.sh" 2>/dev/null || echo "已跳过或未生效 BBR，见 QUICK-DEPLOY.md 1.5.1"
DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent 2>/dev/null || true
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
systemctl enable netfilter-persistent 2>/dev/null || true
echo "iptables 与 sysctl 持久化已配置"

echo ""
echo "=== 完成 ==="
