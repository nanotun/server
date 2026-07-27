#!/usr/bin/env bash
# 阶段 7:硬崩溃恢复。
#
# 优雅关停走的是 defer 链:teardownMainIptablesRules 会把本进程装的规则撤干净。
# SIGKILL 没有这个机会 —— 规则、TUN 状态、内存里的会话表全部原样留在内核里,
# 靠下一次启动时 network_setup_linux.go 的 sweep 自愈(「重启 = 干净安装」)。
#
# 这条自愈路径此前零覆盖,而 OOM、断电、运维手抖导致的硬杀在生产里一定会发生。
# 这里断言的不是「服务还能起来」,而是起来之后:
#   - 上一条命留下的残留规则确实被扫掉了;
#   - 粘性租约扛住了崩溃(vIP 不变,否则 ACL 与用户侧固定地址一起失效);
#   - 没有幽灵会话,数据面三条路径都自己回来了。
#
# 关于 sweep 怎么测:一开始只比对「崩溃前后规则条数相等」,变异验证(把启动 sweep
# 整个注释掉重新部署)照样全绿 —— 因为安装规则时先做带 comment 的 `-C` 检查,
# 残留 + 幂等安装还是同样那些规则,条数天然不变。sweep 真正兜的是**这次配置不会
# 再装的**旧规则(deviceName / WAN 网卡 / exit_mode 变过)。所以这里改成主动注入
# 一条服务端永远不会自己装、但带 nanotun_main 注释的假残留,崩溃重启后它必须消失。

# 假残留规则:203.0.113.0/24 是 RFC5737 文档专用地址,不会影响真实流量。
# 带 nanotun_main 注释 = 冒充「上一条命装的」,但服务端任何配置下都不会再装它。
CRASH_STALE_IP="203.0.113.99"
_stale_rule_args="-s ${CRASH_STALE_IP}/32 -j DROP -m comment --comment nanotun_main"

stale_rule_add()   { s "iptables -t filter -I FORWARD 1 ${_stale_rule_args}" >/dev/null 2>&1; }
stale_rule_count() { s "iptables-save -t filter 2>/dev/null | grep -c ${CRASH_STALE_IP}" | tr -d '[:space:]'; }
stale_rule_del()   { s "iptables -t filter -D FORWARD ${_stale_rule_args} 2>/dev/null; true" >/dev/null 2>&1; }
stale_rule_gone()  { [[ "$(stale_rule_count)" == "0" ]]; }

phase_70_crash() {
  phase_begin "阶段 7 · 硬崩溃恢复"

  if ! both_clients_online; then
    _fail "崩溃前两个会话未在线" "无法判定「恢复」,跳过本阶段"
    return 0
  fi

  # ── 崩溃前快照 ──────────────────────────────────────────────────────────────
  local vip_a_before vip_c_before v4_before v6_before pid_before
  vip_a_before="$(session_vips "$E2E_A_DEVICE_ID")"
  vip_c_before="$(session_vips "$E2E_C_DEVICE_ID")"
  v4_before="$(ipt_main_count iptables)"
  v6_before="$(ipt_main_count ip6tables)"
  pid_before="$(srv_main_pid)"

  if [[ -z "$pid_before" || "$pid_before" == "0" ]]; then
    env_error "取不到 nanotund 主进程 pid,无法制造崩溃"
    return 0
  fi
  # 规则数为 0 的话,后面「sweep 清掉了残留」就是一句空话,必须当场说清楚。
  if [[ "$v4_before" == "0" ]]; then
    env_error "崩溃前 iptables 里没有 nanotun_main 规则,残留累积断言无从判定"
    return 0
  fi
  note "崩溃前:pid=${pid_before},规则 v4=${v4_before} v6=${v6_before},A vIP=${vip_a_before}"

  # 注入假残留。注入不成功的话后面那条 sweep 断言就是空转,必须当场喊停。
  stale_rule_add
  if [[ "$(stale_rule_count)" == "0" ]]; then
    env_error "无法注入假残留规则(iptables 不可用?),sweep 断言无从判定"
    return 0
  fi

  # ── 制造硬崩溃 ──────────────────────────────────────────────────────────────
  # kill -9 与「立刻查残留」必须在同一条远程命令里完成:RestartSec=3,多一次 SSH
  # 往返就可能等到服务已经重启完,把「残留确实存在」测成一句空话。
  local residue
  residue="$(s "kill -9 ${pid_before}; sleep 0.5; iptables-save 2>/dev/null | grep -c nanotun_main" |
    tr -d '[:space:]')"

  # 本阶段的前提:证明 SIGKILL 确实**没有**走清理路径。不成立的话,后面所有
  # 「恢复了」都可能只是因为压根没留下什么要恢复的东西。
  if (( residue > v4_before )); then
    _pass "SIGKILL 未走清理路径,规则连同假残留原样留在内核里（${residue} 条）"
  else
    _fail "崩溃瞬间的残留少于预期" "崩溃前 ${v4_before} 条 + 假残留,实测 ${residue}"
  fi

  # ── 自愈 ────────────────────────────────────────────────────────────────────
  wait_until "systemd 自动拉起服务（无需人工干预）" 60 srv_is_active || {
    s "systemctl start nanotun" >/dev/null 2>&1
    _fail "服务未能自动恢复" "已尝试手工 start,请检查 RestartPreventExitStatus 与 journal"
    return 0
  }

  local pid_after
  pid_after="$(srv_main_pid)"
  if [[ -n "$pid_after" && "$pid_after" != "0" && "$pid_after" != "$pid_before" ]]; then
    _pass "确实是新进程而非假死（pid ${pid_before} → ${pid_after}）"
  else
    _fail "重启后的 pid 不合预期" "崩溃前 $pid_before,现在 ${pid_after:-空}"
  fi

  wait_until "控制面重新可用" 60 srv_control_ok

  # ── 内核里没有累积残留 ──────────────────────────────────────────────────────
  # 这条才是真正在测 sweep:假残留带着 nanotun_main 注释,但新配置不会再装它,
  # 只有启动时按注释扫一遍才能清掉。sweep 一失效它就会一直留在 FORWARD 链上。
  wait_until "启动 sweep 清掉了上一条命的残留规则" 30 stale_rule_gone
  stale_rule_del   # sweep 没清掉时兜底,别把垃圾规则留给下一轮

  check "iptables 规则数回到崩溃前" "$v4_before" "$(ipt_main_count iptables)"
  check "ip6tables 规则数回到崩溃前" "$v6_before" "$(ipt_main_count ip6tables)"

  # ── 会话与租约 ──────────────────────────────────────────────────────────────
  wait_until "两个客户端自动重连" 120 both_clients_online || return 0
  check "没有幽灵会话（在线数恰好 2）" "2" "$(conn_count)"
  check "A 的 vIP 跨崩溃保持不变（粘性租约存活）" "$vip_a_before" "$(session_vips "$E2E_A_DEVICE_ID")"
  check "C 的 vIP 跨崩溃保持不变"                 "$vip_c_before" "$(session_vips "$E2E_C_DEVICE_ID")"

  # ── 数据面自己回来 ──────────────────────────────────────────────────────────
  # 出口要等客户端重新走完 EgressSelect,给的窗口比 mesh 宽。
  wait_until "崩溃后出口自动恢复"   90 probe_egress_is "$E2E_C_HOST"
  wait_until "崩溃后 mesh 自动恢复" 30 probe_ping a "$E2E_C_VIP4"
  wait_until "崩溃后子网自动恢复"   30 probe_ping a "$E2E_C_LAN4_HOST"
  check "崩溃恢复后 tun_write_drops 仍为 0" "0" "$(srv_field tun_write_drops)"
}
