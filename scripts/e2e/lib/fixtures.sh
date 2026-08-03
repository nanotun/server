#!/usr/bin/env bash
# 探针、会话控制、靶站,以及「跑完之后环境有没有被改脏」的状态校验。

set -uo pipefail

# ── 网络探针 ────────────────────────────────────────────────────────────────
# 全部设计成「成功返回 0」,可以直接喂给 wait_until / wait_while。

# A 当前的公网出口 IP(走隧道)。不可达时输出空串。
egress_ip() {
  a "curl -4 -s --max-time ${1:-10} https://ifconfig.me" 2>/dev/null | tr -d '[:space:]'
}

probe_egress_is()      { [[ "$(egress_ip 8)" == "$1" ]]; }
probe_egress_blocked() { [[ -z "$(egress_ip 6)" ]]; }

# probe_ping <runner> <目标>  /  probe_ping6 同理
probe_ping()  { "$1" "ping  -c1 -W3 $2 >/dev/null 2>&1"; }
probe_ping6() { "$1" "ping6 -c1 -W3 $2 >/dev/null 2>&1"; }

# http_code <runner> <url> → 三位状态码;连不上时是 000
http_code() {
  "$1" "curl -s -o /dev/null -w '%{http_code}' --max-time ${3:-8} '$2'" 2>/dev/null | tr -d '[:space:]'
}

probe_http_ok()      { [[ "$(http_code "$1" "$2")" == "200" ]]; }
probe_http_blocked() { [[ "$(http_code "$1" "$2" 6)" == "000" ]]; }

# probe_tcp <runner> <host> <port>:只看能否建连,不发数据。
probe_tcp() { "$1" "timeout 5 bash -c '</dev/tcp/$2/$3' >/dev/null 2>&1"; }

# ── 靶站 ────────────────────────────────────────────────────────────────────
# C 上的 HTTP 靶站,同时充当「mesh 目标」「子网目标」「端口转发目标」。
# 端口必须在 C 的防火墙放行名单里,否则测出来的「不通」是 ufw 挡的,不是被测逻辑。
target_start() {
  c "systemctl stop nte2e-target 2>/dev/null
     systemd-run --unit=nte2e-target --collect --working-directory=/tmp \
       /usr/bin/python3 -m http.server $E2E_TARGET_PORT --bind 0.0.0.0 >/dev/null 2>&1"
  local i
  for i in $(seq 1 10); do
    c "curl -s -o /dev/null --max-time 2 http://127.0.0.1:$E2E_TARGET_PORT/" && return 0
    sleep 1
  done
  echo "靶站未能在 C 上起来(端口 $E2E_TARGET_PORT)" >&2
  return 1
}

target_stop() { c "systemctl stop nte2e-target 2>/dev/null; true" >/dev/null; }

# target_alive:靶站还在 C 本机上应答吗。**在 C 上打 127.0.0.1**,不经隧道 ——
# 这样它只回答「脚手架还在不在」,不掺进任何被测路径的成败。
# 给 wait_until 的自检钩子用:凡是打 :$E2E_TARGET_PORT 的可达性断言,超时时先问这一句,
# 靶站已经没了就该记 ENV(本轮不可信),而不是报成子网/端口转发的缺陷。
target_alive() {
  c "curl -s -o /dev/null --max-time 3 http://127.0.0.1:$E2E_TARGET_PORT/"
}

# ── 客户端会话 ──────────────────────────────────────────────────────────────
# 用 systemd-run 起瞬时 unit:比 nohup 可靠,能拿到 is-active 和 journal,
# 而且被 kick / disable 打断后的重连行为跟真实部署一致。
client_start() {
  local runner="$1" unit="$2" args="$3"
  "$runner" "systemctl stop $unit 2>/dev/null
             systemd-run --unit=$unit --collect /usr/local/bin/nanotun connect $args >/dev/null 2>&1"
}

client_stop() { "$1" "systemctl stop $2 2>/dev/null; true" >/dev/null; }

client_active() { [[ "$("$1" "systemctl is-active $2" | tr -d '[:space:]')" == "active" ]]; }

client_a_start() { client_start a "$E2E_A_UNIT" "$E2E_A_CONNECT_ARGS"; }
client_c_start() { client_start c "$E2E_C_UNIT" "$E2E_C_CONNECT_ARGS"; }

# client_a_start_no_exit 用「不指定出口」的参数重起 A,使它改从**服务器自身** NAT 出网。
#
# 默认拓扑里 A 固定拿 C 当出口,它的公网流量是 tun→tun 直投给 C 的,完全不碰服务器的
# `-i tun -o wan` 那条路径。凡是要验这条路径的用例(connlimit 的并发上限、exit_mode=off
# 的出网封堵),不先切过来的话,规则在不在、对不对,断言都会一样绿。
#
# 只摘掉 --exit,别的参数一律不动:顺手改别的会在「出口变了」之外多出无关变量。
# 返回非 0 表示参数里压根没有 --exit,调用方应报 env_error 而不是当成产品缺陷。
client_a_start_no_exit() {
  local args
  args="$(printf '%s' "$E2E_A_CONNECT_ARGS" | sed -E 's/ --exit [^ ]+//')"
  [[ "$args" == "$E2E_A_CONNECT_ARGS" ]] && return 1
  client_start a "$E2E_A_UNIT" "$args"
}
client_a_stop()  { client_stop a "$E2E_A_UNIT"; }
client_c_stop()  { client_stop c "$E2E_C_UNIT"; }

# 客户端最近的日志,用来核对服务端下发的 close code(902 瞬态 / 905 终态)。
client_log() { "$1" "journalctl -u $2 --since '-${3:-60}s' --no-pager 2>/dev/null"; }

# route_status_of <device_id> <cidr> → approved|pending|rejected;该行不存在则空串。
#
# 必须自己解析 STATUS 列。`route list --device N --status approved | grep <cidr>` 看着更省事,
# 但 0.1.0 的 nanotun-admin 里 --status 与 --device 同时出现时会被静默忽略(取数写成了 switch,
# --device 命中就不再看 --status;已在 cmd_route.go 修掉,这里仍自行解析,以便对着尚未升级的
# 服务端也判得准)。用那种写法时 grep 会匹配到 **pending** 的行,把「没批」读成「已批」。
#
# 2026-08-03 的代价:基线里那两条 approved 守卫正是用它写的,于是在 C 的两条 LAN 路由
# 都是 pending 时照常放行 —— 而它们恰恰是为拦这个而加的。结果阶段 1 里四条「子网恢复」
# 断言全红,同时所有「子网被掐断」的断言全绿(没通过的东西当然掐得掉),
# 从红绿分布上完全看不出真因是一条没批的路由。
route_status_of() {
  adm "route list --device $1" | awk -v d="$1" -v c="$2" '$2==d && $3==c {print $4; exit}'
}

# 在线会话数。很多阶段的前置条件就是「两台都在线」。
conn_count() { srv_field conn_count 2>/dev/null || echo 0; }

both_clients_online() { [[ "$(conn_count)" == "2" ]]; }

# conn_id_of_device <device_id> → 该设备当前在线会话的 conn_id;不在线就空串。
#
# 用来判「还是不是同一条会话」:被踢 / 被杀之后重连必然换号,而只看「在线」在那种情形下
# 每次取样都是在线,什么都判不出来。
#
# 按 device_id 取,不按 user_id:后者是 u2 这种展示形式,和管理命令用的登录名对不上
# (与 conn_rate_down 同一个坑)。
conn_id_of_device() {
  srv_status_json 2>/dev/null | python3 -c '
import json,sys
dev = int(sys.argv[1])
for s in json.load(sys.stdin).get("sessions", []):
    if s.get("device_id") == dev:
        print(s.get("conn_id", ""))
        break
else:
    print("")
' "$1"
}

# conn_rate_down <device_id> → 该设备在线会话的**有效**下行限速。
#
# 按 device_id 而不是用户名匹配:JSON 里的 user_id 是 "u2" 这种展示形式
# (u + 数据库用户 id),跟管理命令用的登录名(testcli)对不上,按名字匹配会
# 永远匹配不到、静默退化成 "?" —— 一个只会表现为「限速没生效」的假故障。
#
# 取 link_rate_down_bps 而不是 bw_down_bps:后者是登录期的用户静态配额,
# 看不出设备层/全局层参与 min 之后的结果(历史上 connection list 就是显示错了这个)。
conn_rate_down() {
  # 传成登录名时下面的匹配永远落空,表现为「限速没生效」——一个指向完全错误的
  # 假故障。判成环境问题而不是断言失败,别让调用方去追产品代码。
  if [[ ! "$1" =~ ^[0-9]+$ ]]; then
    env_error "conn_rate_down 需要 device_id(数字),收到 '$1' —— 限速相关断言全部无效"
    echo "?"
    return 1
  fi
  srv_status_json 2>/dev/null | python3 -c '
import json,sys
dev = int(sys.argv[1])
for s in json.load(sys.stdin).get("sessions", []):
    if s.get("device_id") == dev:
        # link_ready=false 表示限流器还没装好,此时的数值没有意义,
        # 报 "?" 让调用方继续等,而不是拿一个中间值去比对。
        print(s.get("link_rate_down_bps", "?") if s.get("link_ready") else "?")
        break
else:
    print("?")
' "$1"
}

# 等待有效限速收敛到期望值:限速下发要经过控制套接字,不是同步的。
rate_is() { [[ "$(conn_rate_down "$1")" == "$2" ]]; }

# session_vips <device_id> → 该设备当前会话的 vIP,多个按字典序逗号连接。
# 用于崩溃前后比对:vIP 变了就说明粘性租约没扛住重启,ACL 与用户侧固定地址会一起失效。
session_vips() {
  if [[ ! "$1" =~ ^[0-9]+$ ]]; then
    env_error "session_vips 需要 device_id(数字),收到 '$1'"
    echo "?"
    return 1
  fi
  srv_status_json 2>/dev/null | python3 -c '
import json,sys
dev = int(sys.argv[1])
for s in json.load(sys.stdin).get("sessions", []):
    if s.get("device_id") == dev:
        v = s.get("vips")
        print(",".join(sorted(v)) if isinstance(v, list) and v else "?")
        break
else:
    print("?")
' "$1"
}

# ipt_main_count <iptables|ip6tables> → 带 nanotun_main 注释的规则条数。
#
# nanotund 装的每条规则都带这个注释,启动时先按注释 sweep 掉上次的残留再重装
# (network_setup_linux.go 的「重启 = 干净安装」)。崩溃前后条数应当相等:
# 变成两倍就说明 sweep 没生效,残留在一轮轮累积。
ipt_main_count() {
  s "$1-save 2>/dev/null | grep -c nanotun_main" | tr -d '[:space:]'
}

srv_main_pid() { s "systemctl show nanotun -p MainPID --value" | tr -d '[:space:]'; }

srv_is_active()  { [[ "$(s 'systemctl is-active nanotun' | tr -d '[:space:]')" == "active" ]]; }
srv_control_ok() { [[ -n "$(srv_field conn_count 2>/dev/null)" ]]; }

# ── 状态快照 ────────────────────────────────────────────────────────────────
# 每个阶段都应当自己收尾,但「忘了收尾」恰恰是人工回归最容易出的错,
# 而且它的代价是下一轮跑在一个被污染的环境上、结论不可信。
# 这里在开跑前拍一张快照,收尾时比对,漂移直接算失败。
E2E_SNAP=""

state_snapshot() {
  E2E_SNAP="$(_state_dump)"
  # 快照本身取失败(SSH 抖动、sqlite 报错)时必须当场喊停:留着一个装着错误
  # 文本的「快照」,收尾时必然报一个跟被测系统无关的假红,还会盖住真正的残留。
  if [[ -z "$E2E_SNAP" || "$E2E_SNAP" == *"Permission denied"* || "$E2E_SNAP" == *"Error:"* ]]; then
    E2E_SNAP=""
    return 1
  fi
  return 0
}

_state_dump() {
  s "sqlite3 '$E2E_DB_PATH' \
      \"select 'acl:'||id||':'||action||':'||coalesce(src_user_id,'*')||':'||coalesce(dst_user_id,'*') from acl_pairs order by id;
        select 'setting:'||key||'='||value from app_settings where key in
          ('acl_default_action','mesh_enabled','exit_mode','rate_default_download_bps','rate_default_upload_bps') order by key;
        select 'pf:'||id||':'||public_port||':'||enabled from port_forwards order by id;
        select 'webadmin:'||username||':'||role from web_admins order by username;
        select 'route:'||device_id||':'||cidr||':'||status from subnet_routes order by device_id,cidr;
        select 'devrate:'||id||':'||rate_upload_bps||':'||rate_download_bps from devices order by id;\""
}

state_verify() {
  local now diff
  if [[ -z "$E2E_SNAP" ]]; then
    skip "收尾:开跑时未能取得状态快照,无法比对残留"
    return 0
  fi
  now="$(_state_dump)"
  if [[ "$now" == "$E2E_SNAP" ]]; then
    _pass "收尾:服务端状态与开跑前一致(无残留)"
    return 0
  fi
  diff="$(diff <(printf '%s\n' "$E2E_SNAP") <(printf '%s\n' "$now") | head -20)"
  _fail "收尾:服务端状态被改脏,存在未清理的残留" "$diff"
}
