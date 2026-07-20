#!/bin/bash
# 开服可选：启用 Google TCP BBR + fq 队列（改善高带宽/较高延迟链路，如跨境）。
# 要求：内核 >= 4.9；Ubuntu 18.04+ / 常见云镜像均满足。
# 用法（root）：bash /root/nanotun/server/enable-bbr.sh
# 与 QUICK-DEPLOY.md「1.5.1」、DEPLOY.md「12.3」一致。
set -u

CONF="/etc/sysctl.d/99-bbr-vpn.conf"

if ! grep -qE '\bbbr\b' /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
  echo "enable-bbr: 当前内核未提供 bbr（查看: cat /proc/sys/net/ipv4/tcp_available_congestion_control），跳过。"
  exit 0
fi

modprobe tcp_bbr 2>/dev/null || true

cat >"$CONF" <<'EOF'
# nanotun 开服：TCP BBR + fq（勿与自定义 default_qdisc 冲突时可保留）
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF

if sysctl -p "$CONF" 2>/dev/null; then
  echo "enable-bbr: 已写入 $CONF 并生效；当前: $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)"
else
  echo "enable-bbr: sysctl -p 失败，请手动检查 $CONF"
  exit 1
fi
