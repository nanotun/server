#!/bin/bash
# 卸载时删掉 nanotun 用过的 TUN 网卡（scripts/uninstall.sh 调用）。需 root。

set -e

# ── 语言 ─────────────────────────────────────────────────────────────────────
# 与 tun-setup.sh 同一套:默认英文,NANOTUN_LANG > /etc/nanotun/lang > en。
# 本脚本由 systemd 在停机/卸载时跑,输出进 journal。
NT_LANG=en
case "$(printf '%s' "${NANOTUN_LANG:-}" | tr '[:upper:]' '[:lower:]')" in
  zh|zh[-_]*|chinese|cn) NT_LANG=zh ;;
  en|en[-_]*|english)    NT_LANG=en ;;
  *) case "$(head -1 /etc/nanotun/lang 2>/dev/null | tr '[:upper:]' '[:lower:]')" in
       zh|zh[-_]*) NT_LANG=zh ;;
     esac ;;
esac
tsel() { if [ "$NT_LANG" = zh ]; then printf '%s' "$2"; else printf '%s' "$1"; fi; }

removed=0

# nanotund 自己那张（[tun].device_name，默认 tun0）。
# 它是 persist off 的，进程退出时通常自己就没了；这里兜一手异常退出留下的。
if ip link show tun0 >/dev/null 2>&1; then
  ip link set tun0 down 2>/dev/null || true
  ip tuntap del dev tun0 mode tun 2>/dev/null && { echo "removed tun0"; removed=$((removed+1)); }
fi

# 老版本(v0.1.14 及之前)的 tun-setup.sh 会额外建 tun1–tun14 各占一个私网段，
# 那 14 张从来没被用过，卸载时得一并带走 —— 否则「卸干净了」的机器上还留着 14 张
# 空网卡压着 172.17/192.168.100 这类常用段，继续挡着本机路由。
#
# 与 tun-setup.sh 同一套核对口径:名字、类型、地址三者都对得上才删，免得拆掉用户
# 自己建的同名设备。
for i in $(seq 1 14); do
  dev=tun$i
  ip link show "$dev" >/dev/null 2>&1 || continue

  if   (( i < 5 ));  then legacy_addr="10.0.$i.1/24"
  elif (( i < 10 )); then legacy_addr="192.168.$((100+i-5)).1/24"
  else                    legacy_addr="172.$((16+i-10)).0.1/24"
  fi

  ip -d link show "$dev" 2>/dev/null | grep -q ' tun ' || continue
  ip -d link show "$dev" 2>/dev/null | grep -q 'persist on' || continue
  ip -o -4 addr show dev "$dev" 2>/dev/null | grep -qF " $legacy_addr " || continue

  ip link set "$dev" down 2>/dev/null || true
  ip tuntap del dev "$dev" mode tun 2>/dev/null && { echo "removed ${dev}$(tsel " (stale, from an older version)" "（旧版遗留）")"; removed=$((removed+1)); }
done

echo "TUN teardown done$(tsel " (${removed} removed)" "（清掉 ${removed} 张）")"
