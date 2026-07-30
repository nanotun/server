#!/usr/bin/env bash
# 阶段 5:备份 / 还原守卫 / 配置热加载 / 踢线。
#
# 这里有一条刻意保留为「只测守卫、不做真还原」的边界:restore 会覆盖实时库,
# 在共用环境上跑真还原风险太高。真正的「停服→还原→启动→校验」演练请用
# --with-restore-drill 显式开启,并且只在可以随便重置的环境上跑。

# _check_deferred_fields_are_reported 验「改了不可热更的字段,SIGHUP 必须报 deferred」。
#
# 这一条测的是**信号**而不是数据面:这些字段本来就要重启才生效,e2e 没法在不重启的前提下
# 观察它们生效。真正会伤人的是「改了、SIGHUP、日志一切正常」——运维于是以为已经生效了。
# 第 48 轮补进 deferred 的五个字段就是这么漏了很久:它们和早已被覆盖的 exit_mode /
# exit_dns_redirect 在 server.go 里是同一次 SetupIptables 调用的相邻实参。
#
# 断言点取审计里那条 config_reload 的 detail(applied=[...] deferred=[...]),而不是日志 ——
# 审计是结构化的、可按 action 过滤,不受日志等级与轮转影响。
_check_deferred_fields_are_reported() {
  local dir="${E2E_REMOTE_DIR:-/tmp/nte2e}"
  s "mkdir -p $dir" >/dev/null
  s "cat > $dir/tomlset.py" < "$E2E_ROOT/remote/tomlset.py"

  s "cp /etc/nanotun/config.toml /tmp/nte2e-cfg.deferred-bak" >/dev/null

  # 三个字段各来自一个不同的段/机制,覆盖第 48 轮那三族。同一次 SIGHUP 一起改完再断言:
  # 「只报改动的那一项」由单测钉,这里要的是「真二进制读真配置文件后确实报得出来」。
  local setrc=0
  s "python3 $dir/tomlset.py /etc/nanotun/config.toml tun forward_block_bt true" >/dev/null || setrc=1
  s "python3 $dir/tomlset.py /etc/nanotun/config.toml server jump_host_protected_ports '[\"tcp/9099\"]'" >/dev/null || setrc=1
  s "python3 $dir/tomlset.py /etc/nanotun/config.toml hysteria udp_relay_enabled true" >/dev/null || setrc=1
  if (( setrc != 0 )); then
    env_error "改写 config.toml 失败(见 tomlset.py 输出),deferred 这组断言测不到"
    s "cp /tmp/nte2e-cfg.deferred-bak /etc/nanotun/config.toml && systemctl reload nanotun" >/dev/null
    return 0
  fi

  # 取服务端自己的时钟做起点:下面只看**这一次**reload 的日志。
  # 用 --since '-30s' 这种相对窗口会捞到上面那条坏配置用例留下的「保留旧配置」
  # (两次 SIGHUP 只隔二十几秒),于是自证钩子把一次正常的 reload 误判成坏配置。
  local since
  since="$(s 'date +%s' | tr -d '[:space:]')"
  s "systemctl reload nanotun" >/dev/null
  sleep 3

  # 改的是合法字段,配置必须解析成功 —— 否则 reload 走的是「保留旧配置」分支,
  # deferred 永远是空的,下面三条会红在一个完全无关的原因上。
  local rlog
  rlog="$(s "journalctl -u nanotun --since '@$since' --no-pager | grep -i reload")"
  if [[ "$rlog" == *保留旧配置* ]]; then
    env_error "SIGHUP 把这份配置判成坏配置(见 reload 日志),deferred 这组断言测不到"
    s "cp /tmp/nte2e-cfg.deferred-bak /etc/nanotun/config.toml && systemctl reload nanotun" >/dev/null
    return 0
  fi

  local detail
  detail="$(adm "audit list --limit 20" | grep config_reload | head -1)"
  check_contains "SIGHUP 报出 tun.forward_block_bt 需重启" "tun.forward_block_bt" "$detail"
  check_contains "SIGHUP 报出 server.jump_host_protected_ports 需重启" "server.jump_host_protected_ports" "$detail"
  check_contains "SIGHUP 报出 hysteria.udp_relay_enabled 需重启" "hysteria.udp_relay_enabled" "$detail"

  # 恢复,并确认恢复后的 SIGHUP 不再报这些字段(证明上面那三条是这次改动引起的,
  # 而不是审计里捞到了一条陈旧记录)。
  s "cp /tmp/nte2e-cfg.deferred-bak /etc/nanotun/config.toml && systemctl reload nanotun" >/dev/null
  sleep 3
  local after
  after="$(adm "audit list --limit 20" | grep config_reload | head -1)"
  if [[ "$after" == *forward_block_bt* ]]; then
    _fail "恢复配置后仍报 forward_block_bt" "$after"
  else
    _pass "恢复配置后不再报这些字段（说明断言捞的是本次 reload）"
  fi
  check "deferred 这组跑完服务仍然存活" "active" "$(s 'systemctl is-active nanotun' | tr -d '[:space:]')"
}

phase_50_ops() {
  phase_begin "阶段 5 · 运维面"

  local bk=/tmp/nte2e-backup.db

  # ── 热备份 ────────────────────────────────────────────────────────────────
  s "rm -f $bk" >/dev/null
  check_rc "热备份返回成功" 0 adm "backup --out $bk"
  check "备份文件通过 SQLite 完整性检查" "ok" \
    "$(s "sqlite3 $bk 'pragma integrity_check;'" | tr -d '[:space:]')"
  # 备份必须是有内容的快照,不是一个建好表的空库。
  local devcnt
  devcnt="$(s "sqlite3 $bk 'select count(*) from devices;'" | tr -d '[:space:]')"
  if [[ "$devcnt" =~ ^[0-9]+$ ]] && (( devcnt > 0 )); then
    _pass "备份包含实际数据（devices=${devcnt}）"
  else
    _fail "备份内容为空" "devices=$devcnt"
  fi
  check_rc "备份到不可写路径返回退出码 1" 1 adm "backup --out /proc/nope/x.db"

  # ── 还原守卫 ──────────────────────────────────────────────────────────────
  # 服务在跑时必须拒绝:带着旧 inode 的进程 + 换掉的库文件 = 状态分裂。
  local out
  out="$(adm_y "restore $bk" 2>&1)"
  check_contains "服务运行中拒绝还原" "running server" "$out"
  check_contains "并给出 --force-while-running 的显式逃生口" "force-while-running" "$out"

  s "head -c 200 /dev/urandom > /tmp/nte2e-junk.db" >/dev/null
  out="$(adm_y "restore /tmp/nte2e-junk.db --force-while-running" 2>&1)"
  check_contains "垃圾文件被识别为非 SQLite" "not a SQLite database" "$out"
  check_contains "并明确声明实时库未被改动" "left untouched" "$out"

  # ── 在线 VACUUM ───────────────────────────────────────────────────────────
  check_rc "在线 VACUUM 成功" 0 adm_y "vacuum"
  check "VACUUM 后服务仍在运行" "active" "$(s 'systemctl is-active nanotun' | tr -d '[:space:]')"

  # ── 坏配置 SIGHUP:保留旧配置且不中断流量 ─────────────────────────────────
  s "cp /etc/nanotun/config.toml /tmp/nte2e-cfg.good" >/dev/null
  s "printf '\nthis is not = valid toml [[\n' >> /etc/nanotun/config.toml" >/dev/null
  s "systemctl reload nanotun" >/dev/null
  sleep 3
  check "坏配置热加载后服务仍然存活" "active" "$(s 'systemctl is-active nanotun' | tr -d '[:space:]')"
  check_contains "日志明确记录保留旧配置" "保留旧配置" \
    "$(s "journalctl -u nanotun --since '-30s' --no-pager | grep -i reload")"
  check "坏配置期间数据面不中断" "0" "$(probe_egress_is "$E2E_C_HOST" && echo 0 || echo 1)"
  s "cp /tmp/nte2e-cfg.good /etc/nanotun/config.toml && systemctl reload nanotun" >/dev/null
  sleep 2
  check "恢复配置后服务正常" "active" "$(s 'systemctl is-active nanotun' | tr -d '[:space:]')"

  _check_deferred_fields_are_reported

  # ── 踢线:瞬态关闭 + 自动重连 ─────────────────────────────────────────────
  local cid
  cid="$(adm "connection list" | awk -v u="$E2E_C_USER" '$2==u{print $1; exit}')"
  if [[ -z "$cid" ]]; then
    skip "踢线（未找到 $E2E_C_USER 的在线会话）"
  else
    adm_y "kick session $cid" >/dev/null
    wait_until "踢线后客户端收到 902 瞬态关闭" 30 _kick_log_has_902
    wait_until "踢线后客户端自动重连、出口恢复" 60 probe_egress_is "$E2E_C_HOST"
    check_contains "审计记录 actor 为 admin-kick" "admin-kick" \
      "$(adm "audit list --limit 5")"
  fi

  s "rm -f $bk /tmp/nte2e-junk.db /tmp/nte2e-cfg.good" >/dev/null
}

_kick_log_has_902() { client_log c "$E2E_C_UNIT" 60 | grep -q "code=902"; }
