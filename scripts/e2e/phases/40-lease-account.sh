#!/usr/bin/env bash
# 阶段 4:vIP 租约钉住 与 账号启用/禁用。
#
# 租约这块测的全是「CLI 说成功了,但登录路径根本用不了这个值」的静默失败:
# 管理员钉一个网关地址/网段地址/网段外地址,lease list 会一直显示这个钉住值,
# 设备下次登录却被静默改成自动分配 —— 两边看到的不是同一个事实。
# 正确行为是当场告警,所以这里断言的是**告警文案出现**,不是命令成功与否。

phase_40_lease_account() {
  phase_begin "阶段 4 · 租约钉住与账号状态"

  local dev="${E2E_SPARE_DEVICE_ID:-}"
  if [[ -z "$dev" ]]; then
    skip "租约钉住告警（未配置 E2E_SPARE_DEVICE_ID 备用离线设备）"
  else
    local out
    out="$(adm "lease set $dev --v4 ${E2E_MESH_GATEWAY:-10.201.0.1}" 2>&1)"
    check_contains "钉住网关地址时告警" "WARN" "$out"
    check_contains "告警指出这是网关地址" "gateway address" "$out"

    out="$(adm "lease set $dev --v4 ${E2E_MESH_NETWORK:-10.201.0.0}" 2>&1)"
    check_contains "钉住网段地址时告警" "network address" "$out"

    out="$(adm "lease set $dev --v4 192.168.5.5" 2>&1)"
    check_contains "钉住 mesh 网段外地址时告警" "outside the current mesh subnet" "$out"

    # 与在线设备的 vIP 冲突必须是硬失败(退出码 1),不能只打印一行然后返回 0。
    check_rc "钉住已被占用的 vIP 返回退出码 1" 1 adm "lease set $dev --v4 $E2E_C_VIP4"

    out="$(adm "lease set $dev --v4 ${E2E_SPARE_VIP:-10.201.0.201}" 2>&1)"
    check_contains "钉住合法主机地址成功且无告警" "assigned vIP" "$out"
    if [[ "$out" == *WARN* ]]; then
      _fail "合法地址不应告警" "$out"
    else
      _pass "合法地址不产生误报告警"
    fi
    adm_y "lease release $dev" >/dev/null
  fi

  # ── 账号禁用:终态关闭,客户端不得重连 ─────────────────────────────────────
  adm "user disable $E2E_C_USER" >/dev/null
  wait_while "禁用账号后会话被断开" 30 client_active c "$E2E_C_UNIT"

  local log
  log="$(client_log c "$E2E_C_UNIT" 90)"
  check_contains "关闭帧为 905（终态，区别于可重连的 902）" "905" "$log"
  check_contains "客户端明确记录不再重连" "no reconnect" "$log"

  # 连带效应:依赖 C 做出口的 A 必须 fail-closed,而不是回落到服务端出口。
  wait_until "出口方被禁用后 A 同步 fail-closed" 30 probe_egress_blocked

  # 禁用期间重新登录应当被直接拒绝,而不是进重试循环。
  client_c_start
  sleep 8
  check "禁用期间无法建立会话" "1" "$(client_active c "$E2E_C_UNIT" && echo 0 || echo 1)"

  adm "user enable $E2E_C_USER" >/dev/null
  client_c_start
  wait_until "重新启用后会话恢复"     45 client_active c "$E2E_C_UNIT"
  wait_until "重新启用后出口恢复"     60 probe_egress_is "$E2E_C_HOST"
  wait_until "重新启用后子网恢复"     30 probe_ping a "$E2E_C_LAN4_HOST"
}
