#!/usr/bin/env bash
# scale-clean.sh <count> [prefix] —— 在 **SRV 本机** 删除压测身份。
#
# 删 <prefix>000..(count-1) 用户;user delete 会级联清掉其设备与租约,不留残行。
# scale-drill.sh 的收尾 trap 调它,确保共用库里不残留一堆 scaleuNNN。
set -u
DB="${NTE2E_DB:-/var/lib/nanotun/nanotun.db}"
count="$1"; prefix="${2:-scaleu}"
adm() { nanotun-admin --db-path "$DB" "$@"; }

del=0
for ((i=0; i<count; i++)); do
  id=$(printf '%03d' "$i"); u="$prefix$id"
  if adm user show "$u" >/dev/null 2>&1; then
    echo y | adm user delete "$u" >/dev/null 2>&1 && del=$((del+1))
  fi
done
rm -rf /tmp/nte2e-scalegen
echo "deleted=$del remaining=$(adm user list 2>/dev/null | grep -c "$prefix")"
