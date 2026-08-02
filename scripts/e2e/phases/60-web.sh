#!/usr/bin/env bash
# 阶段 6:端口转发 与 Web 管理面的安全边界。
#
# 端口转发这块的重点是 LAN 目标:服务端要替 LAN 目标拨出去,回程包的源地址是
# LAN 地址,曾经被源反欺骗守卫当成伪造流量掐掉 —— 而 Web 上状态仍显示
# 「监听中」,只有从公网实际访问才会发现是坏的。所以这里必须真的从外部发起请求。
#
# Web 这块只测**安全边界**(CSRF、方法白名单、RBAC、未登录),不测页面渲染:
# 渲染问题肉眼可见,而边界问题只有被攻击时才暴露。

WEBC=""   # 远端 webclient.py 路径,由 web_setup 填

web_setup() {
  local dir="${E2E_REMOTE_DIR:-/tmp/nte2e}"
  s "mkdir -p $dir" >/dev/null
  local f
  for f in webclient.py capsolve.py; do
    s "cat > $dir/$f" < "$E2E_ROOT/remote/$f"
  done
  WEBC="python3 $dir/webclient.py --base $E2E_WEB_BASE"
}

# wadmin 会话
wa() { s "$WEBC --jar ${E2E_REMOTE_DIR:-/tmp/nte2e}/jar_admin.txt $*"; }
# viewer 会话
wv() { s "$WEBC --jar ${E2E_REMOTE_DIR:-/tmp/nte2e}/jar_viewer.txt $*"; }
# 未登录(每次用一个空 jar)
wn() { s "rm -f ${E2E_REMOTE_DIR:-/tmp/nte2e}/jar_anon.txt; $WEBC --jar ${E2E_REMOTE_DIR:-/tmp/nte2e}/jar_anon.txt $*"; }

# 按用户名删掉 web 管理员账号,不存在就静默返回。
# 只认纯数字 id:sqlite3 缺失 / 查询报错时返回的是报错文本,拿它去拼 URL 会删不掉又不报错。
viewer_purge() {
  local vid
  vid="$(s "sqlite3 '$E2E_DB_PATH' \"select id from web_admins where username='$1';\"" | tr -d '[:space:]')"
  [[ "$vid" =~ ^[0-9]+$ ]] || return 0
  wa "post /admins/$vid/delete" >/dev/null
}

pf_count() { s "sqlite3 '$E2E_DB_PATH' 'select count(*) from port_forwards;'" | tr -d '[:space:]'; }
pf_id_of() { s "sqlite3 '$E2E_DB_PATH' \"select id from port_forwards where public_port=$1;\"" | tr -d '[:space:]'; }

# 从**外部**(跑 e2e 的这台机器)访问服务端的公网端口。
ext_http_code() {
  curl -s -o /dev/null -w '%{http_code}' --max-time "${2:-10}" "http://$E2E_SRV_HOST:$1/" 2>/dev/null
}
ext_ok()      { [[ "$(ext_http_code "$1")" == "200" ]]; }
ext_blocked() { [[ "$(ext_http_code "$1" 6)" == "000" ]]; }

phase_60_web() {
  phase_begin "阶段 6 · 端口转发与 Web 安全边界"
  # 三条「从公网可达」最终打的是 C 上那个靶站,理由同阶段 3。
  local E2E_SANITY_HOOK=target_alive

  web_setup

  if [[ -z "${E2E_WEB_USER:-}" || -z "${E2E_WEB_PASS:-}" ]]; then
    skip "Web 阶段（未配置 E2E_WEB_USER / E2E_WEB_PASS）"
    return 0
  fi

  local st
  st="$(wa "login --user $E2E_WEB_USER --password '$E2E_WEB_PASS' --totp-secret '${E2E_WEB_TOTP:-}'" | tail -1)"
  if [[ "$st" != "200" ]]; then
    _fail "管理员登录（口令 + 验证码 + TOTP）" "登录返回 $st"
    return 1
  fi
  _pass "管理员登录（口令 + 验证码 + TOTP 两步）"

  # ── 未登录与 CSRF ─────────────────────────────────────────────────────────
  check "未登录 GET 页面重定向到登录页" "302" "$(wn "get /" | tail -1)"
  check "未登录 POST 返回 401"           "401" "$(wn "post /port-forwards/new public_port=19999 --no-csrf" | tail -1)"
  check "缺少 CSRF token 的 POST 返回 403" "403" \
    "$(wa "post /port-forwards/new public_port=19999 --no-csrf" | tail -1)"
  check "伪造 CSRF token 的 POST 返回 403" "403" \
    "$(wa "post /port-forwards/new public_port=19999 --bad-csrf deadbeef" | tail -1)"

  # ── 方法白名单 ────────────────────────────────────────────────────────────
  # GET 绝不允许产生副作用。除了状态码,还要核对确实没写进库。
  local before after
  before="$(pf_count)"
  check "对仅接受 POST 的路由发 GET 返回 405" "405" "$(wa "get /port-forwards/new" | tail -1)"
  after="$(pf_count)"
  check "GET 未产生任何副作用（记录数不变）" "$before" "$after"

  # ── 端口转发:节点目标 与 LAN 目标 ────────────────────────────────────────
  local np="${E2E_PF_NODE_PORT:-19001}" lp="${E2E_PF_LAN_PORT:-19002}"
  check "创建端口转发 · 节点目标" "303" \
    "$(wa "post /port-forwards/new public_port=$np target_port=$E2E_TARGET_PORT target_ip=$E2E_C_VIP4 device_uuid=$E2E_C_UUID comment=e2e-node" | tail -1)"
  check "创建端口转发 · LAN 目标" "303" \
    "$(wa "post /port-forwards/new public_port=$lp target_port=$E2E_TARGET_PORT target_ip=$E2E_C_LAN4_HOST device_uuid=$E2E_C_UUID comment=e2e-lan" | tail -1)"

  wait_until "节点目标端口转发从公网可达" 30 ext_ok "$np"
  # 这条就是源反欺骗守卫误杀 LAN 回程的回归点。
  wait_until "LAN 目标端口转发从公网可达（LAN 回程未被误杀）" 30 ext_ok "$lp"

  # ── 非法输入 ──────────────────────────────────────────────────────────────
  check "重复公网端口返回 409" "409" \
    "$(wa "post /port-forwards/new public_port=$np target_port=$E2E_TARGET_PORT target_ip=$E2E_C_VIP4 device_uuid=$E2E_C_UUID" | tail -1)"
  check "占用 SSH 端口被拒" "400" \
    "$(wa "post /port-forwards/new public_port=22 target_port=$E2E_TARGET_PORT target_ip=$E2E_C_VIP4 device_uuid=$E2E_C_UUID" | tail -1)"
  check "端口越界被拒" "400" \
    "$(wa "post /port-forwards/new public_port=70000 target_port=$E2E_TARGET_PORT target_ip=$E2E_C_VIP4 device_uuid=$E2E_C_UUID" | tail -1)"
  check "公网 IP 作为转发目标被拒" "400" \
    "$(wa "post /port-forwards/new public_port=19003 target_port=80 target_ip=8.8.8.8 device_uuid=$E2E_C_UUID" | tail -1)"
  check "未知设备 UUID 被拒" "400" \
    "$(wa "post /port-forwards/new public_port=19004 target_port=$E2E_TARGET_PORT target_ip=$E2E_C_VIP4 device_uuid=00000000-0000-4000-8000-000000000000" | tail -1)"

  # ── 启停开关 ──────────────────────────────────────────────────────────────
  local nid; nid="$(pf_id_of "$np")"
  wa "post /port-forwards/$nid/disable" >/dev/null
  wait_until "禁用后公网不可达" 25 ext_blocked "$np"
  wa "post /port-forwards/$nid/enable" >/dev/null
  wait_until "重新启用后公网恢复可达" 30 ext_ok "$np"

  # ── RBAC ──────────────────────────────────────────────────────────────────
  local vuser="${E2E_VIEWER_USER:-nte2e_viewer}" vpass="${E2E_VIEWER_PASS:-Nt-E2E-Viewer-2026!x}"
  # 先清掉上一轮漏下的同名账号:重名会让创建退回 200(带错误的表单),整组 RBAC 直接 skip。
  # 而收尾的删除但凡失败过一次(2026-08-02:服务端没装 sqlite3,查 id 拿到的是报错文本),
  # 这组断言就从此**永久静默** —— 之后每轮都 skip,还都是绿的。所以创建前无条件清一次。
  viewer_purge "$vuser"
  st="$(wa "post /admins/new username=$vuser role=viewer password='$vpass' password_confirm='$vpass'" | tail -1)"
  if [[ "$st" != "303" ]]; then
    skip "RBAC（创建 viewer 账号失败,返回 ${st}）"
  else
    st="$(wv "login --user $vuser --password '$vpass'" | tail -1)"
    check "viewer 登录成功" "200" "$st"
    check "viewer 可读会话页" "200" "$(wv "get /sessions" | tail -1)"
    check "viewer 可读设备页" "200" "$(wv "get /devices" | tail -1)"
    check "viewer 不可读审计页（仅管理员）" "403" "$(wv "get /audit" | tail -1)"

    before="$(pf_count)"
    check "viewer 创建端口转发被拒" "403" \
      "$(wv "post /port-forwards/new public_port=19008 target_port=$E2E_TARGET_PORT target_ip=$E2E_C_VIP4 device_uuid=$E2E_C_UUID --csrf-from /sessions" | tail -1)"
    check "viewer 触发运行时 reload 被拒" "403" "$(wv "post /runtime/reload --csrf-from /sessions" | tail -1)"
    check "viewer 切换 mesh 开关被拒"    "403" "$(wv "post /runtime/mesh-toggle --csrf-from /sessions" | tail -1)"
    check "viewer 创建管理员被拒"        "403" \
      "$(wv "post /admins/new username=x role=admin password='$vpass' password_confirm='$vpass' --csrf-from /sessions" | tail -1)"
    check "viewer 的写尝试没有产生任何副作用" "$before" "$(pf_count)"

    viewer_purge "$vuser"
  fi

  # ── 收尾:删掉两条端口转发 ────────────────────────────────────────────────
  local id
  for id in "$(pf_id_of "$np")" "$(pf_id_of "$lp")"; do
    [[ -n "$id" ]] && wa "post /port-forwards/$id/delete" >/dev/null
  done
  s "rm -rf ${E2E_REMOTE_DIR:-/tmp/nte2e}" >/dev/null
}
