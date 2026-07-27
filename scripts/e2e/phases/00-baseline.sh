#!/usr/bin/env bash
# 阶段 0:三机对齐与基线连通性。
#
# 这一阶段的作用是「结论可信度的前置条件」:如果版本没对齐或者基线就不通,
# 后面所有阶段的红绿都没有意义,应当直接停在这里而不是继续跑完再来猜。

phase_00_baseline() {
  phase_begin "阶段 0 · 基线"

  local srv_ver
  srv_ver="$(srv_field server_version 2>/dev/null)"
  if [[ -z "$srv_ver" ]]; then
    _fail "服务端控制面可达" "connection list --json 无输出,后续阶段不可信"
    return 1
  fi
  _pass "服务端控制面可达（$srv_ver，uptime $(srv_field uptime)）"

  # 版本对齐:客户端与服务端不同版本时,协议层的差异会伪装成功能 bug。
  local want="${E2E_EXPECT_VERSION:-}"
  if [[ -n "$want" ]]; then
    check "服务端版本符合预期" "$want" "$srv_ver"
  else
    note "未设置 E2E_EXPECT_VERSION,跳过版本比对"
  fi

  check "nanotund 运行中"    "active" "$(s 'systemctl is-active nanotun'     | tr -d '[:space:]')"
  check "nanotun-web 运行中" "active" "$(s 'systemctl is-active nanotun-web' | tr -d '[:space:]')"

  # 两个客户端会话必须都在线。不在线就地拉起,拉不起来才算失败 ——
  # 上一轮跑完可能留下停掉的会话,这不该让整套 e2e 直接红。
  if ! both_clients_online; then
    note "在线会话数为 $(conn_count),尝试拉起客户端会话"
    client_a_start; client_c_start
  fi
  wait_until "两个客户端会话在线" 45 both_clients_online || return 1

  target_start || { _fail "C 上的 HTTP 靶站启动失败"; return 1; }
  _pass "C 上的 HTTP 靶站就绪（:$E2E_TARGET_PORT）"

  # 基线四条路径。任意一条不通,后面的「阻断/恢复」类断言都无法解读。
  wait_until "基线 · A 可达公网（经出口 C）" 30 probe_egress_is "$E2E_C_HOST"
  wait_until "基线 · A→C mesh 可达"          20 probe_ping a "$E2E_C_VIP4"
  wait_until "基线 · A→C 靶站 200"           20 probe_http_ok a "http://$E2E_C_VIP4:$E2E_TARGET_PORT/"

  # tun 写丢包是「数据面已经出问题了」的硬信号,基线阶段就该是 0。
  check "基线 · tun_write_drops 为 0" "0" "$(srv_field tun_write_drops)"
}
