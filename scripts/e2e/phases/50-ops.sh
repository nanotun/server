#!/usr/bin/env bash
# 阶段 5:备份 / 还原守卫 / 配置热加载 / 踢线。
#
# 这里有一条刻意保留为「只测守卫、不做真还原」的边界:restore 会覆盖实时库,
# 在共用环境上跑真还原风险太高。真正的「停服→还原→启动→校验」演练请用
# --with-restore-drill 显式开启,并且只在可以随便重置的环境上跑。

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
    _pass "备份包含实际数据（devices=$devcnt）"
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
