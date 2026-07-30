#!/usr/bin/env bash
# 阶段 1:出口节点 + MagicDNS。
#
# 核心是 fail-closed:出口不可用时必须**阻断**,而不是悄悄改走服务端出口。
# 这条一旦回归,现象是「网还能上」,不会有任何报错 —— 属于最难靠肉眼发现、
# 后果又最严重的那类(用户以为流量走的是指定出口,实际暴露在服务端 IP 上)。

# _check_per_family_revoke_keeps_device_eligible 验「按族撤销并不会取消出口资格」。
#
# 出口资格是**按 device** 判定的:只撤 C 的 0.0.0.0/0、留着 ::/0,C 仍是合法出口,
# A 的 v4 流量照样经它出网。而 route 子命令把两族显示成两行、也允许单独删一行,
# 天然暗示了一个并不存在的粒度 —— 2026-07-25 三机实测坐实过这个坑。
#
# 当时补的是一条 CLI 告警(单测已钉),但告警**声称的那个数据面事实**一直没人钉。
# 撤掉 v4 之后有三种可能结局,只有一种是当前行为,而另外两种都不会让任何现有断言变红:
#   - 仍经 C 出网:当前行为,也正是告警文案告诉运维的那件事;
#   - 回落到服务端出口:用户以为流量走 C,实际暴露在服务端 IP 上 —— 就是本阶段
#     开头说的「网还能上、不会有任何报错」那类最难发现的静默泄露;
#   - 整个阻断:与告警文案矛盾,运维会照着一个错的心智模型去操作。
# 所以这里两边都钉:告警怎么说,数据面就得怎么做。
_check_per_family_revoke_keeps_device_eligible() {
  local delout ip1 ip2

  delout="$(adm_y "route delete $E2E_C_DEVICE_ID 0.0.0.0/0")"
  check_contains "按族撤 v4 时 CLI 警告该设备仍是出口" "exit revoke" "$delout"

  # 删出口路由会触发 notifyExitsChanged(把绑定它的会话踢回去重新评估)。等这一轮
  # 踢回/重绑走完再取样,别在过渡态上判。
  #
  # 这里刻意**不用** wait_until:它证明的是「某一刻等于 C」,而这条要钉的是「不得回落」。
  # 若行为退化成过一会儿才翻到服务端出口,轮询会在第一次取样就通过,漏个正着。
  # 故等待固定时长后隔开采两次,能抓住延迟发生的翻转。
  sleep 20
  ip1="$(egress_ip 10)"
  sleep 8
  ip2="$(egress_ip 10)"

  if [[ "$ip1" == "$E2E_SRV_HOST" || "$ip2" == "$E2E_SRV_HOST" ]]; then
    _fail "按族撤 v4 后 v4 流量仍经 C 出网" \
      "回落到了服务端出口($E2E_SRV_HOST)—— 用户以为走 C,实际暴露在服务端 IP 上"
  elif [[ "$ip1" == "$E2E_C_HOST" && "$ip2" == "$E2E_C_HOST" ]]; then
    _pass "按族撤 v4 后 v4 流量仍经 C 出网（与 CLI 告警所述一致）"
  else
    _fail "按族撤 v4 后 v4 流量仍经 C 出网" \
      "期望两次取样都是 $E2E_C_HOST,实测 [$ip1] / [$ip2]"
  fi

  # 复原:designate 一次把两族都批回来。后面的阶段都依赖 C 是可用出口,
  # 所以这里要断言复原确实成功,而不是默默往下走。
  adm_y "exit designate $E2E_C_DEVICE_ID" >/dev/null
  check_contains "复原:C 的 v4 默认路由回到 approved" "0.0.0.0/0" \
    "$(adm "route list --device $E2E_C_DEVICE_ID --status approved")"
  wait_until "复原:出口仍正常工作" 40 probe_egress_is "$E2E_C_HOST"
}

phase_10_exit() {
  phase_begin "阶段 1 · 出口节点与 MagicDNS"

  # ── MagicDNS ──────────────────────────────────────────────────────────────
  local c_name="${E2E_C_DEVNAME:-vultr}.$E2E_C_USER.$E2E_MAGIC_SUFFIX"
  local a_name="${E2E_A_DEVNAME:-vultr}.$E2E_A_USER.$E2E_MAGIC_SUFFIX"

  check "MagicDNS · A 记录解析到 C 的 vIP" "$E2E_C_VIP4" \
    "$(a "dig +short +time=4 +tries=1 @10.201.0.1 $c_name" | head -1 | tr -d '[:space:]')"
  check "MagicDNS · AAAA 记录" "$E2E_C_VIP6" \
    "$(a "dig +short -t AAAA +time=4 +tries=1 @10.201.0.1 $c_name" | head -1 | tr -d '[:space:]')"

  # 走系统解析器而不是直接问网关:这一条覆盖客户端的 DNS 接管逻辑
  # (systemd-resolved 在不在解析路径上、要不要直接改写 resolv.conf),
  # 历史上「网关能解析但应用解析不了」就是栽在这里。
  local via_resolver
  via_resolver="$(a "getent hosts $a_name" | head -1 | awk '{print $1}' | tr -d '[:space:]')"
  check_match "MagicDNS · 经系统解析器可解析（客户端 DNS 接管生效）" '^[0-9a-fA-F:.]+$' "$via_resolver"

  check "MagicDNS · 未知名字返回 NXDOMAIN（空结果）" "" \
    "$(a "dig +short +time=4 +tries=1 @10.201.0.1 nosuch.$E2E_C_USER.$E2E_MAGIC_SUFFIX" | tr -d '[:space:]')"
  check_match "MagicDNS · 非 magic 域名转发上游" '^[0-9]+\.[0-9]+\.' \
    "$(a "dig +short +time=5 @10.201.0.1 example.com" | head -1 | tr -d '[:space:]')"

  # ── 出口数据面 ────────────────────────────────────────────────────────────
  check_match "出口 · 公网 UDP DNS 可用" '^[0-9]+\.[0-9]+\.' \
    "$(a "dig +short +time=4 +tries=1 +notcp @8.8.8.8 example.com" | head -1 | tr -d '[:space:]')"

  local dl
  dl="$(a "curl -s -o /dev/null -w '%{size_download}' --max-time 60 'https://speed.cloudflare.com/__down?bytes=2000000'" | tr -d '[:space:]')"
  check "出口 · 2MB 下载完整" "2000000" "$dl"

  # MTU 边界:比隧道 MSS 大 1 字节的 DF 包必须被拒。这条能抓住「隧道 MTU 算错」
  # 导致的大包黑洞 —— 小包一切正常,只有大传输会卡死,极难定位。
  local mtu="${E2E_MTU_PROBE:-1252}"
  check_contains "出口 · DF 包 -s $mtu 通过" "1 received" \
    "$(a "ping -c1 -W4 -M do -s $mtu 8.8.8.8 2>&1")"
  check_contains "出口 · DF 包 -s $((mtu + 1)) 被拒（MTU 边界正确）" "Message too long" \
    "$(a "ping -c1 -W4 -M do -s $((mtu + 1)) 8.8.8.8 2>&1")"

  # ── revoke → fail-closed → designate → 自动恢复 ───────────────────────────
  adm_y "exit revoke $E2E_C_DEVICE_ID" >/dev/null
  wait_until "撤销出口资格后 A 公网流量被阻断（fail-closed，未回落服务端出口）" 25 probe_egress_blocked
  # 关键的反面条件:阻断的只该是公网流量,mesh 必须还通。
  check "撤销期间 mesh 仍可达（阻断范围精确）" "0" "$(probe_ping a "$E2E_C_VIP4" && echo 0 || echo 1)"

  adm_y "exit designate $E2E_C_DEVICE_ID" >/dev/null
  wait_until "重新指定出口后自动恢复（无需客户端重连）" 40 probe_egress_is "$E2E_C_HOST"

  _check_per_family_revoke_keeps_device_eligible

  # ── 出口离线 → 上线 ───────────────────────────────────────────────────────
  client_c_stop
  wait_until "出口节点离线后阻断" 30 probe_egress_blocked

  client_c_start
  wait_until "出口节点回归后自动恢复" 60 probe_egress_is "$E2E_C_HOST"
  # C 重连后子网宣告要重新生效,后面的阶段依赖它。
  wait_until "出口节点回归后子网重新可达" 30 probe_ping a "$E2E_C_LAN4_HOST"

  _check_exit_mode_isolate_drops_relay_but_keeps_the_server_reachable
}

# _check_exit_mode_isolate_drops_relay_but_keeps_the_server_reachable
# 验 [tun] exit_mode = "isolate" 的三件事:掐掉客户端互访、掐掉一切经 peer 的中转、
# 但**不**掐客户端与服务器本身。
#
# 为什么值得实机验:isolate 与「出口节点 / 子网路由」互斥,而这个互斥是**语义**上的,不是配置
# 校验能拦住的 —— 库里那些 approved 记录在 isolate 下依然显示为 approved,只是再也不承载流量。
# 2026-07-25 三机实测就踩过:A 经已批准的出口 C 出网 curl 全超时、子网也黑洞,而客户端只收到
# 一句「出口已离线」。现在 EgressSelect 会当场拒(reason=isolate)并在启动期打一条 WARN 说清
# 「这些审批在本模式下不会承载流量」—— 那条 WARN 是运维唯一的线索,必须钉住。
#
# 判别器是最后那条「A 与服务器自身仍通」。没有它,这组断言无法区分两种局面:
#   - isolate 按设计只掐客户端之间的转发(正确);
#   - 规则装错把整个数据面打死(缺陷)。
# 两者在前三条断言上表现完全一样。isolate 装的是 FORWARD 链 `-i tun -o tun DROP`,而客户端到
# 服务器自己的包走 INPUT 不走 FORWARD,所以这条必须仍通。
#
# exit_mode 不可热更(改 iptables 规则集 + 重建 NAT 表),所以两次切换都要重启 + 等重连。
_check_exit_mode_isolate_drops_relay_but_keeps_the_server_reachable() {
  local dir="${E2E_REMOTE_DIR:-/tmp/nte2e}"
  s "mkdir -p $dir" >/dev/null
  s "cat > $dir/tomlset.py" < "$E2E_ROOT/remote/tomlset.py"

  # 服务器自己的 mesh IPv4 运行时查:env 里没有这一项,而按 A 的 vIP 去猜网关(x.x.x.1)在
  # 换网段时会静默猜错 —— 猜错的表现是判别器恒为「不通」,于是它再也起不到判别作用。
  local srv_vip
  srv_vip="$(s "ip -4 -o addr show | awk '/${E2E_MESH_PREFIX:-10.201.}/{split(\$4,a,\"/\"); print a[1]; exit}'" | tr -d '[:space:]')"
  if [[ -z "$srv_vip" ]]; then
    env_error "查不到服务器自己的 mesh IPv4,isolate 这组缺判别器,不测"
    return
  fi
  # 判别器本身要先在 mesh 模式下自证:它现在必须是通的,否则切过去之后「仍通」这条毫无意义。
  if ! probe_ping a "$srv_vip"; then
    env_error "mesh 模式下 A 就 ping 不到服务器 mesh 地址($srv_vip),isolate 这组的判别器不成立,不测"
    return
  fi

  local since
  since="$(s 'date +%s' | tr -d '[:space:]')"
  if ! s "python3 $dir/tomlset.py /etc/nanotun/config.toml tun exit_mode '\"isolate\"' && systemctl restart nanotun" >/dev/null; then
    _restore_exit_mode_mesh
    env_error "切 exit_mode=isolate 失败,这组断言测不到"
    return
  fi
  wait_until "isolate · 切换后两个客户端重连" 90 both_clients_online

  wait_while "isolate · A→C mesh 被掐断（DROP i==o）"        25 probe_ping a "$E2E_C_VIP4"
  wait_while "isolate · A→C 背后的 LAN 也被掐断（子网也是客户端间中转）" 25 probe_ping a "$E2E_C_LAN4_HOST"
  wait_until "isolate · A 经出口 C 出网被拒（fail-closed，不是静默黑洞）" 30 probe_egress_blocked

  # 判别器:isolate 只掐客户端之间的转发,客户端与服务器自身必须仍通。
  check "isolate · A 与服务器自身仍可达（说明掐的是转发，不是整个数据面）" "0" \
    "$(probe_ping a "$srv_vip" && echo 0 || echo 1)"

  # 拒绝要在日志里说明是 isolate 造成的 —— 客户端侧只会显示「出口已离线」,运维查不到真因。
  local log
  log="$(s "journalctl -u nanotun --since @$since --no-pager")"
  if echo "$log" | grep -q "exit_mode=isolate 禁止客户端互通"; then
    _pass "isolate · 拒绝经 peer 出口时日志点明是 isolate（客户端侧只显示「出口已离线」）"
  else
    _fail "isolate · 应有「exit_mode=isolate 禁止客户端互通」的拒绝日志" "$log"
  fi

  # 启动期那条 WARN 是运维唯一的线索:库里的 approved 记录在 isolate 下是哑弹,列表上却照样显示已批准。
  if echo "$log" | grep -q "在本模式下不会承载流量"; then
    _pass "isolate · 启动期就警告「已批准的出口/子网在本模式下不承载流量」（否则审批看着有效实则失效）"
  else
    _fail "isolate · 启动期应警告库里已批准的中转类审批在本模式下失效" "$log"
  fi
  # 顺带钉住计数的去重:C 同时批了 0.0.0.0/0 与 ::/0,这是**一台**出口设备而不是两条。
  # 按条计会让运维以为自己有两台出口机 —— 一个只在双栈都批过时才暴露的差一错。
  # 不拿「WARN 存在」当前置条件:那样一旦 WARN 整条消失,这句会静默不执行 ——
  # 消失的断言比红的断言危险,它在汇总里看不见。
  check_contains "isolate · 提醒里出口设备按机器去重（C 的 v4+v6 两条 = 1 台）" "exit_devices=1" \
    "$(echo "$log" | grep "在本模式下不会承载流量" || echo "(日志里没有这条提醒)")"

  # 还原:写死 mesh 而不是拷快照 —— 快照式还原会把上一轮留下的脏状态一路传下去(见阶段 2 的教训)。
  _restore_exit_mode_mesh
  wait_until "isolate · 还原 mesh 后两个客户端重连" 90 both_clients_online
  wait_until "isolate · 还原后 A→C mesh 恢复"      30 probe_ping a "$E2E_C_VIP4"
  wait_until "isolate · 还原后经出口 C 出网恢复"    60 probe_egress_is "$E2E_C_HOST"
  wait_until "isolate · 还原后子网恢复"            30 probe_ping a "$E2E_C_LAN4_HOST"
}

# _restore_exit_mode_mesh 把 exit_mode 写回 mesh 并重启(不可热更)。
_restore_exit_mode_mesh() {
  local dir="${E2E_REMOTE_DIR:-/tmp/nte2e}"
  s "python3 $dir/tomlset.py /etc/nanotun/config.toml tun exit_mode '\"mesh\"' && systemctl restart nanotun" >/dev/null 2>&1 || true
}
