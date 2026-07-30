#!/usr/bin/env bash
# 阶段 0:三机对齐与基线连通性。
#
# 这一阶段的作用是「结论可信度的前置条件」:如果版本没对齐或者基线就不通,
# 后面所有阶段的红绿都没有意义,应当直接停在这里而不是继续跑完再来猜。

# _check_c_subnet_routes_are_approved 验进入后续阶段前,C 的子网宣告确实是 approved。
#
# 加它的起因:2026-07-30 有一轮跑到基线时这两条 LAN 路由是 pending 的。基线原有四条断言
# (两会话在线 / A 经出口出网 / A→C 的 **vIP** 可达 / 靶站 200)全都与审批状态无关,于是一路
# 全绿,而阶段 3 第一条断言打的是 C 背后的 LAN,20 秒等满报「子网 HTTP 200 失败」——
# 那个红看起来像子网数据面坏了,真因是一条没批的路由,排查方向从一开始就被带偏。
#
# **这里只断言,不自动批准。** 曾有一版实现是「发现 pending 就就地批准」,那样每轮都能自愈,
# 代价是永久遮住「为什么会变成 pending」:
#   - 已查明的是,正常路径不会造成它 —— 重新宣告走 `ON CONFLICT DO UPDATE SET advertised_at`,
#     只动宣告时间;`DeleteAdvertisedRoutesForDevice` 只删 pending 行;没有任何调用点把状态设回
#     pending(SetRouteStatus 的调用方只写 approved / rejected)。2026-07-30 实测重启 nanotund
#     并等客户端重连,两条路由都稳稳留在 approved。
#   - 也就是说真因未明。这种时候自动修复正是最坏的选择:它让现象再也不会出现,于是也再也
#     查不出来。断言失败会停在基线并把 route list 原样打出来,那是能往下查的形状。
_check_c_subnet_routes_are_approved() {
  local missing=""
  local cidr
  for cidr in "$E2E_C_LAN4" "$E2E_C_LAN6"; do
    [[ -n "$cidr" ]] || continue
    adm "route list --device $E2E_C_DEVICE_ID --status approved" | grep -q "$cidr" || missing+="$cidr "
  done
  if [[ -z "$missing" ]]; then
    _pass "基线 · C 的子网宣告均为 approved"
    return 0
  fi
  _fail "基线 · C 的子网宣告应为 approved（缺:${missing}）" \
    "$(adm "route list --device $E2E_C_DEVICE_ID")
提示:先 nanotun-admin route approve $E2E_C_DEVICE_ID <cidr> 让状态回到已知,再重跑;
但请顺手记下它是**怎么**变成 pending 的 —— 已知正常路径不会造成这个状态。"
  return 1
}

# _check_c_is_an_approved_exit 断言 C 的默认路由(0.0.0.0/0 / ::/0)在库里已批准。
#
# 为什么单独立一条:这是后面一大批断言的**隐式前提**,而它缺失时的表现极具误导性。
# 2026-07-30 单独跑阶段 1 踩到:开跑时 device 31 的 0.0.0.0/0 整行不存在,于是阶段 1 开头
# 五条(MagicDNS 的 A/AAAA/上游转发、公网 UDP DNS、2MB 下载、DF 边界)集体红 —— 它们全都
# 要经 C 出网。跑到中段 `exit designate` 把该行建出来之后,后面的断言又全绿了,收尾还多报
# 一条「残留」。一次开跑状态问题,伪装成了六条互不相干的产品缺陷。
#
# 同样只断言不自动 designate:自动补会让「这行为什么会没了」永远查不出来。已知的正常路径
# (客户端重连、服务端重启)实测都不会删它,所以真出现就是值得查的。
_check_c_is_an_approved_exit() {
  local approved
  approved="$(adm "route list --device $E2E_C_DEVICE_ID --status approved")"
  if echo "$approved" | grep -q '0\.0\.0\.0/0'; then
    _pass "基线 · C 的默认路由已批准（后续出口类断言的前提）"
    return 0
  fi
  _fail "基线 · C 应是已批准的出口（缺 0.0.0.0/0 的 approved 记录）" \
    "$(adm "route list --device $E2E_C_DEVICE_ID")
提示:nanotun-admin exit designate $E2E_C_DEVICE_ID 可恢复,但请先记下它是怎么丢的 ——
缺这行时,阶段 1 开头所有经 C 出网的断言都会红,看起来像出口功能坏了,其实是开跑状态不对。"
  return 1
}

phase_00_baseline() {
  phase_begin "阶段 0 · 基线"

  local srv_ver
  srv_ver="$(srv_field server_version 2>/dev/null)"
  if [[ -z "$srv_ver" ]]; then
    _fail "服务端控制面可达" "connection list --json 无输出,后续阶段不可信"
    return 1
  fi
  _pass "服务端控制面可达（${srv_ver}，uptime $(srv_field uptime)）"

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
  _pass "C 上的 HTTP 靶站就绪（:${E2E_TARGET_PORT}）"

  # C 的子网宣告必须已批准 —— 阶段 3 与阶段 6 的 LAN 目标都建立在它之上,而基线原有的
  # 四条断言全都与审批状态无关(见函数注释里那次跑偏的排查)。
  _check_c_subnet_routes_are_approved || return 1
  _check_c_is_an_approved_exit || return 1

  # 基线四条路径。任意一条不通,后面的「阻断/恢复」类断言都无法解读。
  wait_until "基线 · A 可达公网（经出口 C）" 30 probe_egress_is "$E2E_C_HOST"
  wait_until "基线 · A→C mesh 可达"          20 probe_ping a "$E2E_C_VIP4"
  wait_until "基线 · A→C 靶站 200"           20 probe_http_ok a "http://$E2E_C_VIP4:$E2E_TARGET_PORT/"

  # tun 写丢包是「数据面已经出问题了」的硬信号,基线阶段就该是 0。
  check "基线 · tun_write_drops 为 0" "0" "$(srv_field tun_write_drops)"
}
