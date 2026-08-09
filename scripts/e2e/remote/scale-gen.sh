#!/usr/bin/env bash
# scale-gen.sh <count> <dial_host> [prefix] —— 在 **SRV 本机** 批量造压测身份。
#
# scale-drill.sh 把它推到服务端跑:建 <prefix>000..(count-1) 个 VPN 用户,各签一份
# 凭据,再用其中任一用户签一份 **server 级 profile**(reality 走的是服务端密钥,与
# 具体用户无关,一份够所有实例复用),打成 bundle.tgz 后以 base64 打到 stdout。
#
# 为什么要 N 个用户而不是 N 个隔离客户端目录:客户端的 device_uuid 是**按机器**派生的
# (同机隔离 HOME/XDG 出不来第二个设备身份),而服务端设备唯一键是 (user_id, uuid) ——
# 换 N 个用户即便共用同一台机器的同一个 uuid 也算 N 台不同设备,才凑得出 N 条会话。
set -u
DB="${NTE2E_DB:-/var/lib/nanotun/nanotun.db}"
count="$1"; dial="$2"; prefix="${3:-scaleu}"
adm() { nanotun-admin --db-path "$DB" "$@"; }

work=/tmp/nte2e-scalegen
rm -rf "$work"; mkdir -p "$work"; chmod 700 "$work"

first=""
for ((i=0; i<count; i++)); do
  id=$(printf '%03d' "$i"); u="$prefix$id"
  if adm user show "$u" >/dev/null 2>&1; then
    echo y | adm user delete "$u" >/dev/null 2>&1
  fi
  out="$(adm user create "$u")"
  psk="$(printf '%s\n' "$out" | grep -oE '[A-Z2-7]{5}(-[A-Z2-7]{2,5})+' | head -1)"
  if [ -z "$psk" ]; then echo "NO_PSK $u" >&2; continue; fi
  adm credentials show "$u" --psk "$psk" --format json \
    --output "$work/cred_$id.json" --force >/dev/null 2>/dev/null
  [ -z "$first" ] && first="$u"
done

if [ -z "$first" ]; then echo "MADE=0" ; echo "=== BUNDLE_B64 ===" ; echo ; exit 1; fi
adm profile show "$first" --dial-host "$dial" --format json \
  --output "$work/profile.json" --force >/dev/null

made=$(ls "$work"/cred_*.json 2>/dev/null | wc -l | tr -d '[:space:]')
(
  cd "$work" || exit 1
  cp profile.json profile.txt
  for f in cred_*.json; do cp "$f" "${f%.json}.txt"; done
  tar czf bundle.tgz profile.txt cred_*.txt
)
echo "MADE=$made"
echo "=== BUNDLE_B64 ==="
base64 -w0 "$work/bundle.tgz"; echo
