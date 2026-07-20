#!/bin/bash
# 删除 tun0–tun14 虚拟网卡（与 tun-setup.sh 对应）
# 需 root 执行

set -e

for i in $(seq 0 14); do
  dev=tun$i
  if ip link show "$dev" &>/dev/null; then
    ip link set "$dev" down
    ip tuntap del dev "$dev" mode tun
    echo "removed $dev"
  fi
done

echo "TUN teardown done (tun0–tun14)"
