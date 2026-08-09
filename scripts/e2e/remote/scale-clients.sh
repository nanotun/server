#!/usr/bin/env bash
# scale-clients.sh <launch N|teardown|count> —— 在 **压力机** 上批量起/停隔离客户端。
#
# 每个实例:独立 systemd 瞬时 unit(ntscale-NNN)、独立 HOME/XDG(避免状态目录互踩)、
# 独立 --tun-name、--no-default-route(mesh-only,绝不抢压力机的默认路由/SSH)、
# --transport reality(服务端级密钥,与 profile 里按用户的 hy2 mTLS 无关)、--auto-reconnect
# (单 IP 被 PoW 出题限速摊开时自动补齐)。全部落在 BASE 下,靠路径特征跟真实 e2e 的
# nanotun-a(connect test ...)区分,teardown 的兜底 pkill 不会误伤它。
set -u
BASE=/tmp/nte2e-scale
BIN=/usr/local/bin/nanotun

case "${1:-}" in
  launch)
    count="${2:?launch 需要 count}"
    prof="$BASE/profile.txt"
    if [ ! -f "$prof" ]; then echo "missing $prof" >&2; exit 2; fi
    made=0
    for ((i=0; i<count; i++)); do
      id=$(printf '%03d' "$i")
      cred="$BASE/cred_$id.txt"
      if [ ! -f "$cred" ]; then echo "missing $cred" >&2; continue; fi
      H="$BASE/h$id"; rm -rf "$H"; mkdir -p "$H/.config" "$H/.state" "$H/.data" "$H/.cache"
      systemctl reset-failed "ntscale-$id" 2>/dev/null || true
      systemd-run --unit="ntscale-$id" --collect \
        --setenv=HOME="$H" \
        --setenv=XDG_CONFIG_HOME="$H/.config" \
        --setenv=XDG_STATE_HOME="$H/.state" \
        --setenv=XDG_DATA_HOME="$H/.data" \
        --setenv=XDG_CACHE_HOME="$H/.cache" \
        "$BIN" connect "$prof" --cred "$cred" \
          --transport reality --no-default-route --tun-name "nts$id" --auto-reconnect \
        >/dev/null 2>&1 && made=$((made+1))
      sleep 0.2
    done
    echo "launched=$made"
    ;;
  teardown)
    n=0
    for u in $(systemctl list-units 'ntscale-*' --all --no-legend 2>/dev/null | awk '{print $1}'); do
      systemctl stop "$u" 2>/dev/null
      systemctl reset-failed "$u" 2>/dev/null
      n=$((n+1))
    done
    # 兜底:只按 BASE 路径特征杀,绝不碰 nanotun-a(它是 connect test …)。
    pkill -f "nanotun connect $BASE/" 2>/dev/null || true
    sleep 1
    rm -rf "$BASE"
    echo "stopped=$n remaining=$(pgrep -f "nanotun connect $BASE/" 2>/dev/null | wc -l | tr -d '[:space:]')"
    ;;
  count)
    pgrep -f "nanotun connect $BASE/" 2>/dev/null | wc -l | tr -d '[:space:]'
    ;;
  *)
    echo "用法: $0 launch <N> | teardown | count" >&2; exit 2 ;;
esac
