#!/usr/bin/env bash
# 阶段 2:ACL 与三层限速。
#
# 两条主线:
#   ACL —— 规则必须**立即**生效。历史上 acl deny 只写库不通知运行中的 server,
#          表现为「命令说成功了但流量照过」,这是安全策略里最坏的一种失败模式。
#   限速 —— 全局/设备/用户三层取 min。历史上刷新其中一层会用另一层的**登录期
#          快照**去覆盖,把刚设的更严的值悄悄放宽(Bug 11)。所以这里不只验证
#          「设了生效」,更要验证「放宽一层不会复活旧快照」。

_acl_del_all() {
  local ids
  ids="$(adm "acl list --json" 2>/dev/null |
    python3 -c 'import json,sys
try: print(" ".join(str(r["id"]) for r in json.load(sys.stdin)))
except Exception: pass')"
  local id
  for id in $ids; do adm "acl delete $id" >/dev/null; done
}

phase_20_acl_rate() {
  phase_begin "阶段 2 · ACL 与限速"

  local url="http://$E2E_C_VIP4:$E2E_TARGET_PORT/"

  # ── 端口子集语义 ──────────────────────────────────────────────────────────
  # deny 指定端口时,只该掐掉那个端口,其余端口和 ICMP 必须不受影响。
  # 「一条端口规则把整台主机封死」是很常见的实现错误。
  adm "acl deny $E2E_A_USER $E2E_C_USER --port $E2E_TARGET_PORT --proto tcp" >/dev/null
  wait_until "单端口 deny 生效（无需手工 reload）" 20 probe_http_blocked a "$url"
  check "单端口 deny · 其它端口不受影响（22 仍可建连）" "0" \
    "$(probe_tcp a "$E2E_C_VIP4" 22 && echo 0 || echo 1)"
  check "单端口 deny · ICMP 不受影响" "0" \
    "$(probe_ping a "$E2E_C_VIP4" && echo 0 || echo 1)"
  _acl_del_all
  wait_until "删除规则后端口恢复" 20 probe_http_ok a "$url"

  # ── 通配源 + 端口区间 ─────────────────────────────────────────────────────
  adm "acl deny '*' $E2E_C_USER --port-range $((E2E_TARGET_PORT - 8))-$((E2E_TARGET_PORT + 2)) --proto tcp" >/dev/null
  wait_until "通配源 + 端口区间 deny 生效" 20 probe_http_blocked a "$url"
  check "端口区间 deny · 区间外端口不受影响" "0" \
    "$(probe_tcp a "$E2E_C_VIP4" 22 && echo 0 || echo 1)"
  _acl_del_all
  wait_until "删除区间规则后恢复" 20 probe_http_ok a "$url"

  # ── 三层限速的 min 语义 ───────────────────────────────────────────────────
  # 主要断言看 connection list 里的**有效**限速值而不是实测吞吐:实测受公网
  # 抖动影响,做成硬断言必然 flaky。吞吐另有一条宽松的数量级检查兜底。
  adm "setting rate --down-bps 1000000 --up-bps 1000000" >/dev/null
  wait_until "限速 · 全局默认 1000000 下发到在线会话" 20 rate_is "$E2E_A_USER" 1000000

  adm "device set-rate $E2E_A_DEVICE_ID --down-bps 300000" >/dev/null
  wait_until "限速 · 设备层更严时取设备值（min）" 20 rate_is "$E2E_A_USER" 300000

  adm "user set-bandwidth $E2E_A_USER --down-bps 150000" >/dev/null
  wait_until "限速 · 用户层最严时取用户值（min）" 20 rate_is "$E2E_A_USER" 150000

  # 回归 Bug 11:把设备层放宽到远大于用户层,有效值必须仍是用户层的 150000。
  # 若这里变回 300000 或 5000000,说明刷新时又用上了登录期的陈旧快照。
  # 这里用固定等待而非轮询 —— 要断言的是「一直没变」,轮询会把中途的错误值放过去。
  adm "device set-rate $E2E_A_DEVICE_ID --down-bps 5000000" >/dev/null
  sleep 5
  check "限速 · 放宽设备层不复活旧快照（Bug 11 回归）" "150000" "$(conn_rate_down "$E2E_A_USER")"

  adm "user set-bandwidth $E2E_A_USER --down-bps 0" >/dev/null
  wait_until "限速 · 清空用户层后回落到全局值" 20 rate_is "$E2E_A_USER" 1000000

  # 吞吐只做数量级校验:限到 1MB/s 时不应该跑出远超该值的速度。
  local speed
  speed="$(a "curl -s -o /dev/null -w '%{speed_download}' --max-time 40 'https://speed.cloudflare.com/__down?bytes=4000000'" |
    tr -d '[:space:]' | cut -d. -f1)"
  if [[ -n "$speed" ]] && (( speed > 0 && speed < 1600000 )); then
    _pass "限速 · 实测吞吐与限值同量级（${speed} B/s）"
  else
    _fail "限速 · 实测吞吐异常" "限值 1000000 B/s,实测 ${speed:-空} B/s"
  fi

  # 收尾:恢复不限速。
  adm "device set-rate $E2E_A_DEVICE_ID --down-bps 0" >/dev/null
  adm "setting rate --down-bps 0 --up-bps 0" >/dev/null
  sleep 2
}
