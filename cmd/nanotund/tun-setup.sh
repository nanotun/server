#!/bin/bash
# 创建 15 个 TUN 设备：10.x 五个、192.168.x 五个、172.x 五个；任一局域网顶多冲突一段，其余两段仍可用
# 已存在的 TUN 不再创建。需 root 执行；由 systemd tun-setup.service 在开机时调用

set -e

# 仅当设备不存在时才创建并配置
# tun0–tun4: 10.0.0.0/24 ~ 10.0.4.0/24
# tun5–tun9: 192.168.100.0/24 ~ 192.168.104.0/24
# tun10–tun14: 172.16.0.0/24 ~ 172.20.0.0/24
for i in $(seq 0 14); do
  dev=tun$i
  if ! ip link show "$dev" &>/dev/null; then
    ip tuntap add dev "$dev" mode tun
    if (( i < 5 )); then
      ip addr add 10.0.$i.1/24 dev "$dev"
    elif (( i < 10 )); then
      ip addr add 192.168.$((100+i-5)).1/24 dev "$dev"
    else
      ip addr add 172.$((16+i-10)).0.1/24 dev "$dev"
    fi
  fi
  # 每次都给已有设备执行 up，避免重启后一直 DOWN
  ip link set "$dev" up 2>/dev/null || true
done

echo "TUN ready: tun0-4(10.0.x) tun5-9(192.168.100-104) tun10-14(172.16-20)"

# M0 起默认不再做客户端间隔离：自托管 mesh 场景下，客户端互通是核心功能，
# 同账号 / 同组的访问控制由 nanotun 在应用层 ACL 完成（store/acl.go）。
# 仅当显式设置 NANOTUN_TUN_ISOLATE=1 时才执行 iptables 隔离脚本。
if [ "${NANOTUN_TUN_ISOLATE:-0}" = "1" ] && [ -x /usr/local/bin/nanotun-tun-isolate.sh ]; then
  /usr/local/bin/nanotun-tun-isolate.sh
fi
