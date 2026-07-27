#!/usr/bin/env bash
# 阶段 3:子网路由、ULA 与 4via6。
#
# 除了「通不通」,更要盯两类静默失败:
#   - 撤销宣告后流量应当立刻黑洞,而不是继续按旧快照转发(权限已撤但还能访问);
#   - 4via6 的两道守卫(未批准的 v4、不存在的站点)必须拒绝**并且计到对应的
#     计数器上** —— 只看「ping 不通」区分不了「守卫生效」和「网络本来就断了」。

# 4via6 地址 = /64 前缀 + 2 字节保留 + 2 字节 siteID + 4 字节原始 IPv4。
via6_addr() {
  local site="$1" v4="$2"
  python3 -c '
import ipaddress,sys
site=int(sys.argv[1]); v4=ipaddress.IPv4Address(sys.argv[2])
b=bytearray(ipaddress.IPv6Address(sys.argv[3]).packed)
b[8]=b[9]=0
b[10]=site>>8; b[11]=site&0xFF
b[12:16]=v4.packed
print(ipaddress.IPv6Address(bytes(b)).compressed)
' "$site" "$v4" "${E2E_VIA6_PREFIX:-fdbc:4a60::}"
}

# C 的 siteID 由服务端分配,不能写死。
c_site_id() {
  s "sqlite3 '$E2E_DB_PATH' \"select site_id from via6_sites where device_id=$E2E_C_DEVICE_ID;\"" | tr -d '[:space:]'
}

subnet_counter() { srv_status_json | jq_field "subnet_route.$1"; }

# 谓词要写成函数交给 wait_until 调用。不能用 bash -c ——
# 那会开一个新 shell,adm / probe_* 这些函数在里面全都不存在,
# 命令必然失败,wait_until 就会一直等到超时再报一个假的失败。
_route_is_pending() {
  adm "route list --device $E2E_C_DEVICE_ID --status pending" | grep -q "$E2E_C_LAN4"
}

phase_30_subnet() {
  phase_begin "阶段 3 · 子网路由与 4via6"

  local site v6target
  site="$(c_site_id)"
  if [[ -z "$site" ]]; then
    _fail "取得 C 的 4via6 siteID" "via6_sites 表里没有 device_id=$E2E_C_DEVICE_ID 的记录"
    return 1
  fi
  v6target="$(via6_addr "$site" "$E2E_C_LAN4_HOST")"
  note "C 的 siteID=$site,4via6 目标=$v6target"

  # ── 三种寻址方式都要通 ────────────────────────────────────────────────────
  wait_until "IPv4 子网可达（$E2E_C_LAN4_HOST）"      20 probe_ping  a "$E2E_C_LAN4_HOST"
  wait_until "IPv4 子网 HTTP 200"                      20 probe_http_ok a "http://$E2E_C_LAN4_HOST:$E2E_TARGET_PORT/"
  wait_until "ULA 子网可达（$E2E_C_LAN6_HOST）"        20 probe_ping6 a "$E2E_C_LAN6_HOST"
  wait_until "4via6 可达（$v6target）"                 20 probe_ping6 a "$v6target"
  wait_until "4via6 HTTP 200"                          20 probe_http_ok a "http://[$v6target]:$E2E_TARGET_PORT/"

  # ── 4via6 两道守卫 ────────────────────────────────────────────────────────
  # 断言点是计数器增量,而不是「ping 失败」。
  local before_na after_na before_ns after_ns bad_v4 bad_site
  before_na="$(subnet_counter dropped_not_approved)"
  bad_v4="$(via6_addr "$site" "10.99.99.1")"
  probe_ping6 a "$bad_v4" && _fail "4via6 · 未批准的 v4 竟然可达" || true
  sleep 2
  after_na="$(subnet_counter dropped_not_approved)"
  if (( after_na > before_na )); then
    _pass "4via6 · 未批准的 v4 被拒并计入 dropped_not_approved（$before_na→$after_na）"
  else
    _fail "4via6 · 未批准的 v4 未计入 dropped_not_approved" "计数器停在 $after_na"
  fi

  before_ns="$(subnet_counter dropped_no_site)"
  bad_site="$(via6_addr 999 "$E2E_C_LAN4_HOST")"
  probe_ping6 a "$bad_site" && _fail "4via6 · 不存在的站点竟然可达" || true
  sleep 2
  after_ns="$(subnet_counter dropped_no_site)"
  if (( after_ns > before_ns )); then
    _pass "4via6 · 不存在的站点被拒并计入 dropped_no_site（$before_ns→$after_ns）"
  else
    _fail "4via6 · 不存在的站点未计入 dropped_no_site" "计数器停在 $after_ns"
  fi

  # ── reject 对已批准路由的保护 ─────────────────────────────────────────────
  # reject 只应作用于 pending。对已批准的记录要明确拒绝并指路 route delete,
  # 否则管理员会以为自己撤销了权限,实际什么也没发生。
  local out
  out="$(adm "route reject $E2E_C_DEVICE_ID $E2E_C_LAN4 --reason e2e" 2>&1)"
  check_contains "route reject 拒绝作用于已批准路由并给出替代命令" "route delete" "$out"
  check "reject 未生效，子网仍可达" "0" "$(probe_ping a "$E2E_C_LAN4_HOST" && echo 0 || echo 1)"

  # ── 撤销 → 黑洞 → 重新宣告 → 批准 → 恢复 ─────────────────────────────────
  adm_y "route delete $E2E_C_DEVICE_ID $E2E_C_LAN4" >/dev/null
  wait_while "撤销宣告后 IPv4 子网立刻黑洞" 25 probe_ping a "$E2E_C_LAN4_HOST"
  check "撤销宣告后 4via6 同步失效" "1" "$(probe_ping6 a "$v6target" && echo 0 || echo 1)"
  # 只撤了 IPv4 那条,ULA 必须不受牵连。
  check "撤销范围精确：ULA 宣告不受影响" "0" "$(probe_ping6 a "$E2E_C_LAN6_HOST" && echo 0 || echo 1)"

  client_c_start
  wait_until "客户端重连后重新宣告为 pending" 45 _route_is_pending

  adm "route approve $E2E_C_DEVICE_ID $E2E_C_LAN4" >/dev/null
  wait_until "批准后 IPv4 子网恢复" 30 probe_ping a "$E2E_C_LAN4_HOST"
  wait_until "批准后 4via6 恢复"     30 probe_ping6 a "$v6target"
  wait_until "批准后出口也恢复"      45 probe_egress_is "$E2E_C_HOST"
}
