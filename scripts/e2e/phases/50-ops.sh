#!/usr/bin/env bash
# 阶段 5:备份 / 还原守卫 / 配置热加载 / 踢线。
#
# 这里有一条刻意保留为「只测守卫、不做真还原」的边界:restore 会覆盖实时库,
# 在共用环境上跑真还原风险太高。真正的「停服→还原→启动→校验」演练请用
# --with-restore-drill 显式开启,并且只在可以随便重置的环境上跑。

# 停过服务端之后等数据面自己回来。不记断言 —— 它只是让后面那些「默认隧道是通的」
# 断言跑在稳定状态上。等不回来就直接返回,由后面的断言指名道姓地报。
#
# 这道等待原本没有:systemd 下停起够快,后续几条断言的耗时正好把重连窗口盖过去了;
# 容器下停起慢一截(整个容器 teardown + entrypoint 自检 + 等控制面 socket 才拉 web),
# 于是「坏配置期间数据面不中断」那条立即探测就扑空 —— 红在它身上,病根在这里。
_wait_egress_back() {
  local i
  for i in $(seq 1 45); do
    probe_egress_is "$E2E_C_HOST" && return 0
    sleep 2
  done
  return 1
}

# _check_restore_names_the_other_db_holder 验还原守卫的**第二道**闸:按 /proc 扫真实持有者。
#
# 为什么非得停掉 nanotund 才算测到:restore 前有两道闸,第一道探 control socket(只代表
# nanotund),第二道扫 /proc 找别的持有者(nanotun-web、手工开的 sqlite3)。nanotund 一直在跑,
# 第一道就先拦下了,第二道**永远走不到** —— 上面那两条"服务运行中拒绝还原"断言其实一条都没碰到
# 它。而当初真出事的恰恰是第二道要管的场景:按文档「stop nanotun → restore → start nanotun」
# 走完,web 没人停,继续持有那个已被 unlink 的旧 inode,此后后台建用户照样回 303、照样把一次性
# PSK 发出去,数据全进孤儿文件,零报错。
#
# 单测已经用「合成文件 + 假持有者」钉过这道闸,真机要补的是它在生产布局下**认不认得出**
# nanotun-web:/proc/<pid>/fd 的软链给的是解析过符号链接的真实路径,而命令侧是
# filepath.Abs(--db-path),不解析符号链接 —— 库目录哪天成了软链,这道闸就静默失效。
#
# 关键是最后那条反向断言:输出里**不能**出现第一道闸的 "control socket"。否则说明 stop 没生效、
# 短路在第一道,这组断言测的是别的东西却照样绿(母题:断言的观测点没落在要验的那道闸上)。
#
# 源刻意用**垃圾文件**而不是真备份:持有者这道闸排在源校验之前(cmd_backup.go 里 149 行 vs
# 168 行),所以闸在的时候赢的必须是持有者那条消息。这么选有两个好处 ——
#   - 哪天这道闸真被删了,本用例变红的同时不会顺手把实时库盖掉:失败的代价停在「红」上,
#     而不是把 e2e 环境连带毁掉(用真备份做源时,删掉闸就等于让测试自己执行一次真还原);
#   - 钉的力度反而更强:它同时钉住了**顺序**。顺序一旦被挪到源校验之后,删闸就会退化成静默覆盖。
_check_restore_names_the_other_db_holder() {
  local junk="$1"

  # 前提得自证:web 不在跑就没人持有库,这条会因为「确实没有持有者」而假绿。
  if [[ "$(s 'systemctl is-active nanotun-web' | tr -d '[:space:]')" != "active" ]]; then
    skip "还原守卫第二道 · /proc 扫持有者（nanotun-web 未运行，构造不出持有者）"
    return
  fi

  s "systemctl stop nanotun" >/dev/null
  # 停干净再敲,否则第一道闸先响。
  local i
  for i in 1 2 3 4 5 6 7 8 9 10; do
    [[ "$(s 'systemctl is-active nanotun' | tr -d '[:space:]')" != "active" ]] && break
    sleep 1
  done

  # 停完数据面再确认一次 web 还在。单容器部署里两个进程由同一个 entrypoint 守护,
  # 停数据面会把 web 一并带走 —— 于是没有任何持有者,这道闸无从触发,断言会红在
  # 「源校验先响了」上,看着像顺序被挪过,其实是构造不出前提。那种形态下本组本来就
  # 不适用:它防的「stop nanotun 之后 web 仍抱着旧 inode 写孤儿文件」结构上不会发生。
  if [[ "$(s 'systemctl is-active nanotun-web' | tr -d '[:space:]')" != "active" ]]; then
    s "systemctl start nanotun" >/dev/null
    _wait_egress_back
    skip "还原守卫第二道 · /proc 扫持有者（停掉数据面时 web 被一并停掉，构造不出持有者）"
    return
  fi

  local out
  out="$(adm_y "restore $junk" 2>&1)"

  # 先把服务拉回来,再做断言 —— 断言失败会 return,不能让服务停在那儿。
  s "systemctl start nanotun" >/dev/null
  _wait_egress_back

  check_contains "还原被第二道守卫拦下（/proc 扫到别的持有者）" "other processes still have this DB open" "$out"
  check_contains "并点名 nanotun-web 这个持有者" "nanotun-web" "$out"
  check_contains "并说明后果是静默写进旧文件" "silently" "$out"
  check_contains "并明确要求先停掉它们" "Stop them first" "$out"
  # 反证没有短路在第一道闸上。
  if [[ "$out" == *"control socket"* ]]; then
    _fail "第二道守卫其实没被触发（输出仍是 control socket 那道）" "$out"
  else
    _pass "拦下它的确实不是 control socket 那道闸"
  fi
  # 也不能是源校验那道:它排在持有者之后,赢了就说明顺序被挪过。
  if [[ "$out" == *"not a SQLite database"* ]]; then
    _fail "持有者检查被挪到源校验之后了（删掉它将退化为静默覆盖）" "$out"
  else
    _pass "持有者检查仍排在源校验之前"
  fi

  wait_until "nanotund 重启后客户端重连、出口恢复" 90 probe_egress_is "$E2E_C_HOST"
}

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
  # 每虚拟 IP 并发上限:与 forward_block_bt 是同一次 SetupIptables 的相邻实参,补那一族时漏了。
  # 收紧上限是应急动作,「reload 没提示」会让人以为已经摁住(见 reload.go 里那段注释)。
  s "python3 $dir/tomlset.py /etc/nanotun/config.toml tun tcp_connlimit_per_ip 5" >/dev/null || setrc=1
  # 「为安全而轮换」的一族:混淆口令 / 客户端 CA / 数据面 WS 路径。这一族漏报是双向的 ——
  # 旧口令与旧 CA 仍然有效(以为的加固没发生),而照配置文件新签出来的 profile 和客户端证书
  # 连不上(在跑的进程还用着旧值),报错还指向「认证失败/证书不受信」,指不到真因。
  #
  # CA 这一项刻意指向真 CA 的一份**副本**:万一它哪天真的生效了(比如本组中途挂掉、
  # 恢复没跑到,后面有别的用例重启了服务),hy2 入口仍然能验客户端证书,不会把整个
  # 数据面连带打死。换成一个不存在的路径就没有这层保险。
  # 配置里的 CA 路径是**相对** /etc/nanotun 的,所以要先 cd 过去再 cp;直接拿去 cp 会失败。
  # 这层保险必须确认真的建起来了 —— 建不起来就别改这个字段,否则「保险」只存在于注释里,
  # 而万一它哪天真生效,hy2 会因为 CA 文件不存在而起不来,比不做这条断言糟得多。
  local caok=0
  if s "cd /etc/nanotun && cp -f \"\$(awk '/^\[hysteria\]/{f=1;next} /^\[/{f=0} f && /^tls_client_ca_file *=/{print}' config.toml | cut -d'\"' -f2)\" certs/nte2e-ca-copy.pem && test -s certs/nte2e-ca-copy.pem && echo ok" | grep -q ok; then
    caok=1
    s "python3 $dir/tomlset.py /etc/nanotun/config.toml hysteria tls_client_ca_file '\"certs/nte2e-ca-copy.pem\"'" >/dev/null || setrc=1
  else
    env_error "备份客户端 CA 失败，tls_client_ca_file 那条 deferred 断言跳过（不冒「改了却没有可用 CA」的风险）"
  fi
  s "python3 $dir/tomlset.py /etc/nanotun/config.toml hysteria obfs_salamander_password '\"nte2e-rotated-obfs\"'" >/dev/null || setrc=1
  s "python3 $dir/tomlset.py /etc/nanotun/config.toml server vpn_websocket_path '\"/internal/nte2e/deferred-probe\"'" >/dev/null || setrc=1
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
  check_contains "SIGHUP 报出 tun.tcp_connlimit_per_ip 需重启" "tun.tcp_connlimit_per_ip" "$detail"
  check_contains "SIGHUP 报出 hysteria.obfs_salamander_password 需重启" "hysteria.obfs_salamander_password" "$detail"
  if (( caok )); then
    check_contains "SIGHUP 报出 hysteria.tls_client_ca_file 需重启" "hysteria.tls_client_ca_file" "$detail"
  fi
  check_contains "SIGHUP 报出 server.vpn_websocket_path 需重启" "server.vpn_websocket_path" "$detail"

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

  # 这一条是给**后面的阶段**兜底。本组为了触发上报,会把数据面 WS 路径改成一个假值;
  # 它不热更,所以在本组内部无害 —— 但只要留在配置里,下一次有人重启服务,进程就会去
  # 服务那条假路径,而所有客户端 profile 里写的还是真路径,于是全体连不上。这类污染
  # 上一次(login_rate_limit)就是靠快照机制一路传染到后续整轮的。
  s "rm -f /etc/nanotun/certs/nte2e-ca-copy.pem" >/dev/null 2>&1

  local wspath
  wspath="$(s "awk '/^\[server\]/{f=1;next} /^\[/{f=0} f && /^vpn_websocket_path *=/{print}' /etc/nanotun/config.toml" | cut -d'"' -f2)"
  if [[ "$wspath" == *nte2e* ]]; then
    _fail "deferred 这组收尾后 vpn_websocket_path 没还原（会让下次重启后所有客户端连不上）" "$wspath"
  else
    _pass "deferred 这组收尾后数据面 WS 路径已还原"
  fi
}

# _check_forward_port_drops_follow_their_own_knobs 验 tun 的三个端口封堵开关
# (forward_block_bt / forward_block_tracker_6969 / forward_block_smtp_25)各自只装自己那几条规则。
#
# 为什么这组测「内核规则」而不是测「BT 流量被挡」:规则是 FORWARD 链上 `-i tun0 --dport ...`,
# 唯一能碰到它的流量路径是「客户端 → 服务器自身 NAT 出网」(链里那条 `-i tun0 -o enp1s0 ACCEPT`)。
# 而本套件里 A 固定选 C 当出口,去程是用户态直投给 C 的会话、压根不碰 tun0;子网路由同理。
# 所以在当前三机拓扑下没有任何流量路径能打中这些规则 —— 硬造一条端到端断言只会得到一个
# 无论规则在不在都恒绿的假断言。能测且值得测的是「配置 → 内核规则」这一环。
#
# 这一环真有可错的地方:server.go 里 `SetupIptables(..., blockBT, blockTracker6969, blockSMTP25, ...)`
# 是三个相邻的同类型 bool 实参,串位编译器完全看不出来,而这段是 Linux-only 的无单测代码
# (纯函数 tunForwardPortDropRules 的单测测的是函数本身,测不到调用点)。
#
# 三个开关**必须各自单独打开**来测,这一点是这组的设计要害:两个开关同时为 true 时,无论实参
# 怎么对调,装出来的规则集一模一样 —— 于是串位在那种测法下完全不可见。所以每一档只开一个,
# 并断言另两个的端口**不出现**,这样三个方向上的串位都能抓住。
#
# 协议形状也各自钉住:BT 要 tcp+udp(代码注释自己点了「只挡 tcp 的话 uTP / DHT 走 udp 照样能把
# 出口跑满」),tracker 与 SMTP 只该有 tcp —— 多装一条 udp 会挡掉与这两个开关无关的服务。
#
# 三个都是 deferred 字段(只在启动期落链),所以每一档切换都要重启 + 等重连。
_check_forward_port_drops_follow_their_own_knobs() {
  local dir="${E2E_REMOTE_DIR:-/tmp/nte2e}"
  s "mkdir -p $dir" >/dev/null
  s "cat > $dir/tomlset.py" < "$E2E_ROOT/remote/tomlset.py"

  # 起始状态必须是「三个开关都关」:否则每一档的反面断言测的是别的东西,
  # 而串位缺陷恰好只能靠那些反面断言抓出来。
  local before
  before="$(s 'iptables -S FORWARD')"
  if printf '%s\n' "$before" | grep -qE -- '--dport (6881:6889|6969|25)( |$)'; then
    env_error "开跑时 FORWARD 链里已有端口封堵规则,这组的反面断言不成立,不测"
    return
  fi

  local stage field label want deny
  for stage in bt tracker smtp; do
    case "$stage" in
      bt)
        field=forward_block_bt; label="BT"
        want="tcp:6881:6889 udp:6881:6889"
        deny="tcp:6969 udp:6969 tcp:25 udp:25"
        ;;
      tracker)
        field=forward_block_tracker_6969; label="tracker"
        want="tcp:6969"
        deny="tcp:6881:6889 udp:6881:6889 udp:6969 tcp:25 udp:25"
        ;;
      smtp)
        field=forward_block_smtp_25; label="SMTP"
        want="tcp:25"
        deny="tcp:6881:6889 udp:6881:6889 tcp:6969 udp:6969 udp:25"
        ;;
    esac

    if ! _set_forward_blocks "$field"; then
      _set_forward_blocks ""
      env_error "只开 tun.$field 失败,端口封堵这组测不到"
      return
    fi
    wait_until "端口封堵 · $label · 只开这一个后两个客户端重连" 90 both_clients_online
    _assert_forward_drop_stage "$label" "$field" "$want" "$deny"
  done

  # 三个都关回去,确认规则随之消失:证明上面那些正面断言是开关驱动的,
  # 而不是某几条一直都在的规则。
  _set_forward_blocks ""
  wait_until "端口封堵 · 三个都关回去后两个客户端重连" 90 both_clients_online
  local after
  after="$(s 'iptables -S FORWARD')"
  if printf '%s\n' "$after" | grep -qE -- '--dport (6881:6889|6969|25)( |$)'; then
    _fail "端口封堵 · 三个都关掉后仍有端口 DROP 残留（那些正面断言就不是开关驱动的）" "$after"
  else
    _pass "端口封堵 · 三个都关掉后规则全部消失（确认由各自的开关驱动）"
  fi
}

# ── 数据面保活(server→client Ping/Pong)────────────────────────────────────────
#
# 这组是 [server].data_plane_ping_interval / _miss_threshold 的行为验证。参考部署里这两个键
# **一个都没配**,也就是说这套机制线上一直是关着的、从没在真机上跑过。所以第一件要钉的不是
# 「卡死能不能检出」,而是**打开它会不会把健康会话也一起杀掉** —— 客户端若压根不回 Pong,
# 这个开关就是个地雷:每 N×interval 把所有正常会话杀一遍,表现为全员周期性掉线。
#
# 三条都要:
#   1. 健康会话不被误杀(会话年龄必须远大于 miss 窗口 —— 只看「在线」抓不到「反复被杀又重连」);
#   2. 卡死会话被检出并关掉,且**只关那一个**(C 的会话不能受牵连);
#   3. 关掉开关后同样的卡死不再被检出(证明上面两条是这个开关驱动的,不是别的机制顺手做的)。
#
# 用 SIGSTOP 冻客户端来造「卡死」:进程停了但 TCP 连接还在,正是这套心跳存在的理由 ——
# 拔网线那种断法底层 read 会直接报错,根本走不到判活逻辑。
#
# 冻结按**进程名**(pgrep -x nanotun)而不是命令行模式匹配:2026-07-30 踩过 ——
# pkill -f 'nanotun connect' 会把远端执行这条命令的 bash 自己一起匹配上,把自己也冻死,
# SSH 就此挂住。
_check_data_plane_keepalive_reaps_only_the_wedged_session() {
  local dir="${E2E_REMOTE_DIR:-/tmp/nte2e}"
  s "mkdir -p $dir" >/dev/null
  s "cat > $dir/tomlset.py" < "$E2E_ROOT/remote/tomlset.py"

  # 上一轮若在 STOP 与 CONT 之间断了,A 的客户端会一直冻着,后面所有阶段都会红成一片。
  # 进门先无条件解冻一次,把「粘性污染」变成自愈。
  _thaw_a_client

  # ── 打开 5s / 2 次(判活窗口 10s)─────────────────────────────────────────
  if ! s "python3 $dir/tomlset.py /etc/nanotun/config.toml server data_plane_ping_interval '\"5s\"' && python3 $dir/tomlset.py /etc/nanotun/config.toml server data_plane_ping_miss_threshold 2 && systemctl restart nanotun" >/dev/null; then
    _restore_data_plane_keepalive_off
    env_error "打开数据面保活失败,这组测不到"
    return 0
  fi
  wait_until "数据面保活 · 打开后两个客户端重连" 90 both_clients_online

  local since_healthy cid_before up_before
  since_healthy="$(s "date +%s" | tr -d '[:space:]')"
  cid_before="$(conn_id_of_device "${E2E_A_DEVICE_ID:-1}")"
  up_before="$(srv_field uptime 2>/dev/null)"
  # 等 4 个判活窗口。误杀的话这段时间里会被杀 3~4 次。
  sleep 45
  local warns
  warns="$(s "journalctl -u nanotun --since @$since_healthy --no-pager | grep -c 僵尸连接" | tr -d '[:space:]')"
  [[ "$warns" =~ ^[0-9]+$ ]] || warns=0
  if [[ "$warns" == "0" ]] && both_clients_online; then
    _pass "数据面保活 · 健康会话不被误杀（4 个判活窗口内零告警、两个会话都在）"
  else
    _fail "数据面保活 · 健康会话被误杀了（客户端很可能压根不回 Pong，这个开关就是个地雷）" \
      "僵尸告警 ${warns} 次,在线会话 $(conn_count) 个
$(s "journalctl -u nanotun --since @$since_healthy --no-pager | grep 僵尸连接 | tail -3")"
  fi
  # 只看「在线」抓不到「被杀了又立刻重连」——那种退化下每次取样都是「在线」。
  # 判据用 conn_id 是否还是同一个:被杀过必然换号。
  #
  # 不用会话年龄:年龄要跟一个绝对阈值比,而阈值同时受本函数自己的重启节奏和 SSH 往返
  # 耗时影响,2026-07-30 实测出过「零告警但年龄偏小」的自相矛盾结果 —— 一条测不准
  # 自己声称的东西的断言,比没有更糟。
  local cid_after up_after grew
  cid_after="$(conn_id_of_device "${E2E_A_DEVICE_ID:-1}")"
  up_after="$(srv_field uptime 2>/dev/null)"
  # 同一个进程里 uptime 只会单调增长,且至少要涨够上面 sleep 的时长;涨得不够多
  # 就说明中途重启过(重启后 uptime 从零重新开始计)。
  #
  # 刻意**不**用「uptime 字符串是否相等」来判有没有重启:它是个时长,同一进程里每次读都不一样,
  # 那样写会让「conn_id 变了」永远被归成环境问题 —— 真缺陷被静默降级,比没有这条断言更糟。
  grew=$(( $(_dur_secs "$up_after") - $(_dur_secs "$up_before") ))
  if [[ "$cid_after" == "$cid_before" && -n "$cid_before" ]]; then
    _pass "数据面保活 · A 的会话全程是同一条（conn_id 没变，没被杀掉又重连）"
  elif (( grew >= 40 )); then
    # 服务端没重启过,那换号只能是会话被杀了 —— 真缺陷。
    _fail "数据面保活 · A 的会话在健康窗口内换了 conn_id（被杀掉又重连了）" \
      "窗口前 ${cid_before:-空} → 窗口后 ${cid_after:-空}
$(adm 'connection list')"
  else
    # 服务端在窗口中间自己重启了,换号是重启的必然结果,与保活无关。
    # 这是脚手架/环境层面的干扰,报成环境问题而不是产品缺陷。
    env_error "健康窗口里服务端重启过(uptime ${up_before} → ${up_after}),A 的会话连续性这条测不准"
  fi

  # ── 冻住 A:该被检出,且只该杀这一条 ─────────────────────────────────────
  local since_wedge
  since_wedge="$(s "date +%s" | tr -d '[:space:]')"
  if ! _freeze_a_client; then
    _restore_data_plane_keepalive_off
    env_error "冻结 A 的客户端失败,卡死检出这几条测不到"
    return 0
  fi

  if wait_until "数据面保活 · 卡死会话被判定为僵尸并关闭" 60 \
      _keepalive_reaped_a "$since_wedge"; then
    # 精确性:被杀的必须只有卡死那条。连坐会把一个客户端的故障放大成全员掉线。
    if [[ "$(conn_count)" == "1" ]]; then
      _pass "数据面保活 · 只关掉卡死那一条，C 的会话没被连坐"
    else
      _fail "数据面保活 · 期望只剩 C 的会话，实际在线 $(conn_count) 个" "$(adm 'connection list')"
    fi
  fi

  _thaw_a_client
  wait_until "数据面保活 · 解冻后 A 自行重连" 90 both_clients_online
  wait_until "数据面保活 · 解冻后出口恢复" 60 probe_egress_is "$E2E_C_HOST"

  # ── 关掉开关:同样的卡死不该再被检出 ────────────────────────────────────
  _restore_data_plane_keepalive_off
  wait_until "数据面保活 · 关掉后两个客户端重连" 90 both_clients_online

  local since_off
  since_off="$(s "date +%s" | tr -d '[:space:]')"
  if ! _freeze_a_client; then
    env_error "第二次冻结 A 失败,反面这条测不到"
    _thaw_a_client
    return 0
  fi
  # 只等 25s:比上面检出用的时间宽裕,又稳稳短于 smux 自己那套 30s 保活超时 ——
  # 等过 30s 的话会话可能被 smux 收走,那测的就是另一套机制了。
  sleep 25
  if _keepalive_warned_for_a "$since_off"; then
    _fail "数据面保活 · 关掉开关后仍在判僵尸（上面那几条就不是这个开关驱动的）" \
      "$(s "journalctl -u nanotun --since @$since_off --no-pager | grep 僵尸连接 | tail -3")"
  elif [[ "$(conn_count)" == "2" ]]; then
    _pass "数据面保活 · 关掉后同样的卡死不再被检出（确认由开关驱动）"
  else
    _fail "数据面保活 · 关掉后会话仍然掉了（是别的机制收走的，本条没能证明开关驱动）" \
      "$(adm 'connection list')"
  fi

  _thaw_a_client
  wait_until "数据面保活 · 收尾:A 重新在线" 90 both_clients_online
  wait_until "数据面保活 · 收尾:出口恢复" 60 probe_egress_is "$E2E_C_HOST"
}

# _keepalive_warned_for_a <起始 unix 秒> 判断 $1 之后有没有针对 A 的僵尸判定告警。
#
# 按 remote 里的 A 公网 IP 匹配,不按 user_id:后者是 u2 这种展示形式,和 E2E_A_USER
# (登录名)对不上,按名字匹配会永远落空、静默变成一条恒绿的假断言。
_keepalive_warned_for_a() {
  s "journalctl -u nanotun --since @$1 --no-pager | grep 僵尸连接 | grep -c '$E2E_A_HOST'" \
    | tr -d '[:space:]' | grep -qvE '^0?$'
}

# _keepalive_reaped_a 要求两件事都成立:告警打了,**而且**那条会话真的没了。
# 只查告警的话,「记了日志却忘了 Close」这种退化会从这条断言底下溜过去 —— 而它恰恰是
# 最难发现的一种:日志看起来一切正常,僵尸连接却一直挂着占着 vIP 和配额。
_keepalive_reaped_a() {
  _keepalive_warned_for_a "$1" || return 1
  ! adm "connection list" | awk -v v="$E2E_A_VIP4" '$4 ~ v {found=1} END {exit !found}'
}

# _dur_secs <时长串> 把 1h2m3s / 1m34s / 43s 这类 Go 风格时长折成秒。取不到就 0。
_dur_secs() {
  printf '%s' "${1:-}" | awk '
    { t=$0; s=0
      if (match(t, /[0-9]+h/)) { s += substr(t, RSTART, RLENGTH-1) * 3600 }
      if (match(t, /[0-9]+m/)) { s += substr(t, RSTART, RLENGTH-1) * 60 }
      if (match(t, /[0-9]+s/)) { s += substr(t, RSTART, RLENGTH-1) }
      print s+0 }
    END { if (NR == 0) print 0 }'
}

# conn_id_of_device 在 lib/fixtures.sh(阶段 2 的平台限速也要用它判「是不是同一条会话」)。

# _freeze_a_client 用 SIGSTOP 冻住 A 上的客户端,并确认它真的停住了(状态含 T)。
# 不确认的话,信号没生效会让后面几条断言变成「什么都没测」。
_freeze_a_client() {
  local pid stat
  pid="$(_a_client_pid)"
  [[ -n "$pid" ]] || return 1
  a "kill -STOP $pid" >/dev/null 2>&1 || return 1
  sleep 2
  stat="$(a "ps -o stat= -p $pid" | tr -d '[:space:]')"
  [[ "$stat" == *T* ]]
}

# _thaw_a_client 解冻 A 上所有停住的客户端进程。幂等,没冻也能安全调用。
_thaw_a_client() {
  local pid
  pid="$(_a_client_pid)"
  [[ -n "$pid" ]] && a "kill -CONT $pid" >/dev/null 2>&1
  return 0
}

# _a_client_pid 取 A 上客户端进程号。按进程名精确匹配,绝不按命令行 ——
# 按命令行会把远端执行这条命令的 shell 自己一起匹配上(见本节顶部注释)。
_a_client_pid() { a "pgrep -x nanotun | head -1" | tr -d '[:space:]'; }

# _restore_data_plane_keepalive_off 把保活写死为关闭并重启。
# interval = "0s"、miss_threshold = 0 都与「键不存在」等价,故还原不依赖任何快照。
#
# 阈值也要归零:留着 2 的话,将来谁把 interval 打开就会拿到 2 而不是代码里的默认 3 ——
# 一个由测试残留造成、且没人会想到去查配置文件的行为偏差。
_restore_data_plane_keepalive_off() {
  local dir="${E2E_REMOTE_DIR:-/tmp/nte2e}"
  s "python3 $dir/tomlset.py /etc/nanotun/config.toml server data_plane_ping_interval '\"0s\"' && python3 $dir/tomlset.py /etc/nanotun/config.toml server data_plane_ping_miss_threshold 0 && systemctl restart nanotun" >/dev/null 2>&1 || true
}

# _check_exit_guard_installs_both_chains 验 tun.exit_deny_private 在 FORWARD **和** INPUT 两条链上
# 都装了链路本地/私网目的地的 DROP,而且是这个开关驱动的。
#
# 重点在 INPUT 那一半。代码注释把它的作用写得很明确:目的地是服务器**自己**的地址时走 INPUT 而不是
# FORWARD,「不装这条的话内部管理面服务照样对 VPN 用户敞开」。也就是说 FORWARD 装上了、INPUT 漏了
# 这种退化,是一个真实的暴露面缺陷 —— 而它在任何流量断言里都看不见(见下)。
#
# 为什么这组同样测「内核规则」而不是测流量:2026-07-30 实测,客户端 A 访问云元数据地址
# 169.254.169.254 时,A 自己的路由表把它送出 A 的 WAN(`via <A 的网关> dev enp1s0`)——
# 压根不进隧道。加上 A 固定选 C 当出口(去程用户态直投、不碰服务器 tun0),当前拓扑下没有任何
# 流量路径能打中服务端这两条规则。硬造端到端断言只会得到一个无论规则在不在都恒绿的假断言。
#
# exit_deny_private 是 deferred 字段(只在启动期落链),所以两次切换都要重启 + 等重连。
_check_exit_guard_installs_both_chains() {
  local dir="${E2E_REMOTE_DIR:-/tmp/nte2e}"
  s "mkdir -p $dir" >/dev/null
  s "cat > $dir/tomlset.py" < "$E2E_ROOT/remote/tomlset.py"

  # 出网网卡名运行时取:写死 enp1s0 会在换机器后让 FORWARD 那半永远匹配不上,
  # 而匹配不上的表现是「规则没装」—— 一个指向错误方向的红。
  local wan
  wan="$(s "ip route show default | awk '{print \$5; exit}'" | tr -d '[:space:]')"
  if [[ -z "$wan" ]]; then
    env_error "取不到出网网卡名,出口守卫这组测不到"
    return 0
  fi

  # ── 默认档(auto):四条规则都该在 ────────────────────────────────────────
  _assert_exit_guard_present "$wan" "默认档(auto)"

  # 反面:mesh 网段绝不能进拦截列表。真进了的话整个 mesh 会被打死 —— 那种失败会以
  # 「所有 mesh 断言一起红」的形式出现,没人会想到根因在这个守卫上,所以这里点名钉住。
  local guard4 mesh4 bad=""
  guard4="$(s "iptables -S INPUT; iptables -S FORWARD" | grep -E -- "-i tun.*-j DROP" | grep -v -- "--dport")"
  mesh4="$(echo "${E2E_A_VIP4:-10.201.0.77}" | awk -F. '{print $1"."$2"."}')"
  if echo "$guard4" | grep -q -- "-d ${mesh4}"; then
    bad="yes"
  fi
  if [[ -z "$bad" ]]; then
    _pass "出口守卫 · mesh 网段没被拦（进了拦截列表会把整个 mesh 打死）"
  else
    _fail "出口守卫 · mesh 网段被拦进去了（会把整个 mesh 打死）" "$guard4"
  fi

  # 运维唯一能看到「到底拦了哪些网段」的地方就是这行日志,故一并钉住档位与前缀。
  local log
  log="$(s "journalctl -u nanotun --no-pager | grep 'exit-guard' | tail -4")"
  check_contains "出口守卫 · 启动日志点明生效档位" "mode=auto" "$log"
  check_contains "出口守卫 · 启动日志点明实际拦了哪些网段（v4）" "169.254.0.0/16" "$log"
  check_contains "出口守卫 · 启动日志点明实际拦了哪些网段（v6）" "fe80::/10" "$log"

  # ── 关掉:四条规则都该消失 ─────────────────────────────────────────────
  if ! s "python3 $dir/tomlset.py /etc/nanotun/config.toml tun exit_deny_private '\"off\"' && systemctl restart nanotun" >/dev/null; then
    _restore_exit_deny_private_auto
    env_error "把 exit_deny_private 设为 off 失败,这组测不到"
    return 0
  fi
  wait_until "出口守卫 · 关掉后两个客户端重连" 90 both_clients_online

  local fam bin chain prefix text still=""
  for fam in "iptables|169.254.0.0/16" "ip6tables|fe80::/10"; do
    bin="${fam%%|*}"
    prefix="${fam#*|}"
    for chain in FORWARD INPUT; do
      text="$(s "$bin -S $chain")"
      if printf '%s\n' "$text" | grep -qE -- "-d $prefix -i tun.*-j DROP"; then
        still+="$bin/$chain "
      fi
    done
  done
  if [[ -z "$still" ]]; then
    _pass "出口守卫 · off 档下四条规则全部消失（确认由开关驱动）"
  else
    _fail "出口守卫 · off 档下仍残留 ${still}（那上面四条就不是这个开关驱动的）" \
      "$(s 'iptables -S INPUT; iptables -S FORWARD')"
  fi

  # ── 还原 auto:四条规则该回来 ──────────────────────────────────────────
  _restore_exit_deny_private_auto
  wait_until "出口守卫 · 还原 auto 后两个客户端重连" 90 both_clients_online
  _assert_exit_guard_present "$wan" "还原 auto"
}

# _assert_exit_guard_present <出网网卡> <档位标签> 断言四条守卫规则都在。
#
# FORWARD 那半额外要求带 `-o <wan>`:少了它会连 tun→tun 一起拦,把已批准子网路由和 mesh
# 里指向链路本地的流量也打掉 —— 代码注释专门解释了为什么要限定出网方向。
_assert_exit_guard_present() {
  local wan="$1" tag="$2"
  local fam bin rest prefix label line
  # 用 | 而不是 : 分隔:v6 前缀自己就带冒号。
  for fam in "iptables|169.254.0.0/16|IPv4" "ip6tables|fe80::/10|IPv6"; do
    bin="${fam%%|*}"
    rest="${fam#*|}"
    prefix="${rest%%|*}"
    label="${rest#*|}"

    line="$(s "$bin -S FORWARD" | grep -E -- "-d $prefix -i tun.*-j DROP")"
    if [[ -n "$line" ]] && [[ "$line" == *" -o $wan"* ]]; then
      _pass "出口守卫 · $tag · $label FORWARD 拦 $prefix 且限定出网方向（-o ${wan}）"
    elif [[ -n "$line" ]]; then
      _fail "出口守卫 · $tag · $label FORWARD 那条没限定 -o ${wan}（会连 tun→tun 一起拦）" "$line"
    else
      _fail "出口守卫 · $tag · $label FORWARD 应拦 $prefix" "$(s "$bin -S FORWARD")"
    fi

    # INPUT 这条是关键:目的地是服务器自己的地址时走 INPUT 不走 FORWARD,漏了它
    # 内部管理面就对 VPN 用户敞开,而且任何流量断言都看不见。
    line="$(s "$bin -S INPUT" | grep -E -- "-d $prefix -i tun.*-j DROP")"
    if [[ -n "$line" ]]; then
      _pass "出口守卫 · $tag · $label INPUT 拦 ${prefix}（否则服务器自己的私网地址对 VPN 用户敞开）"
    else
      _fail "出口守卫 · $tag · $label INPUT 应拦 $prefix" "$(s "$bin -S INPUT")"
    fi
  done
}

# _restore_exit_deny_private_auto 写死 auto 并重启。auto 是安全默认,还原绝不能依赖快照。
_restore_exit_deny_private_auto() {
  local dir="${E2E_REMOTE_DIR:-/tmp/nte2e}"
  s "python3 $dir/tomlset.py /etc/nanotun/config.toml tun exit_deny_private '\"auto\"' && systemctl restart nanotun" >/dev/null 2>&1 || true
}

# _fwd_drop_exists <链文本> <tcp|udp> <dport> 判断链里有没有这么一条 tun 入向的 DROP。
# 限定 `-i tun` 是必要的:不限定的话会捞到与这三个开关无关的规则,反面断言就会假红。
_fwd_drop_exists() {
  printf '%s\n' "$1" | grep -qE -- "-i tun.*-p $2 .*--dport $3( |\$).*-j DROP"
}

# _assert_forward_drop_stage <标签> <字段名> <期望的 proto:port 列表> <禁止的 proto:port 列表>
_assert_forward_drop_stage() {
  local label="$1" field="$2" want="$3" deny="$4"
  local v4 v6 fam famlabel text item proto port bad=""
  v4="$(s 'iptables -S FORWARD')"
  v6="$(s 'ip6tables -S FORWARD')"

  # v4 与 v6 都要装上:这两族走的是 SetupIptables / SetupIp6tables 两次不同的调用,
  # 「只做了 v4」这种漏法在别的规则上出现过,而 BT / SMTP over IPv6 都是真实存在的。
  for fam in "IPv4:$v4" "IPv6:$v6"; do
    famlabel="${fam%%:*}"
    text="${fam#*:}"
    for item in $want; do
      proto="${item%%:*}"
      port="${item#*:}"
      if _fwd_drop_exists "$text" "$proto" "$port"; then
        _pass "端口封堵 · $label · $famlabel $proto $port 已 DROP 在 tun 入向"
      else
        _fail "端口封堵 · $label · $famlabel 应有 $proto $port 的 DROP 规则" "$text"
      fi
    done
  done

  # 反面:只开了这一个开关,别的端口一条都不许出现。相邻 bool 实参串位就在这里露出来。
  for item in $deny; do
    proto="${item%%:*}"
    port="${item#*:}"
    if _fwd_drop_exists "$v4" "$proto" "$port"; then
      bad+="$proto/$port "
    fi
  done
  if [[ -z "$bad" ]]; then
    _pass "端口封堵 · $label · 只装了自己那几条，没碰别的开关（三个相邻 bool 实参没串位）"
  else
    _fail "端口封堵 · $label · 只开 tun.$field 却多装了 ${bad}（三个相邻 bool 实参串位了）" "$v4"
  fi
}

# _set_forward_blocks [要开的字段] 把三个封堵开关显式写成「只开指定那个」并重启。
#
# 三个都显式写,而不是只改一个:只改一个就得假定另两个当前是关的,而那个假定一旦不成立
# (上一档没还原干净、上一轮留了脏状态),表现就是反面断言假红。留空表示三个全关。
_set_forward_blocks() {
  local on="${1:-}"
  local dir="${E2E_REMOTE_DIR:-/tmp/nte2e}"
  local f val cmd=""
  for f in forward_block_bt forward_block_tracker_6969 forward_block_smtp_25; do
    if [[ "$f" == "$on" ]]; then val=true; else val=false; fi
    cmd+="python3 $dir/tomlset.py /etc/nanotun/config.toml tun $f $val && "
  done
  s "${cmd}systemctl restart nanotun" >/dev/null
}

# _check_udp_relay_stays_disabled 验 hysteria.udp_relay_enabled 关着时,通过认证的 hy2 客户端
# 也拿不到 UDP 中转能力;开着时确实能把服务器当通用 UDP 代理用。
#
# 这个开关是纯安全开关:关着时服务端设 DisableUDP,hy2 只承担 nanotun 自己的隧道流量;开着时
# 任何**通过认证的** hy2 客户端都能借它发任意 UDP(DNS 放大、内网横移),代码里那条启动期 WARN
# 就是为这个打的。误开之后从外部看不出任何异样 —— 隧道照常工作,攻击面悄悄变大。
#
# 断言用 remote/hy2udpprobe(用仓库自己依赖的 hysteria 客户端库写的,不必在被测机上装第三方软件)。
# 它以合法客户端身份完成握手 —— mTLS(服务端是 RequireAndVerifyClientCert)+ salamander 混淆
# + hy2 口令,三样缺一样都连不上 —— 然后尝试向公网 DNS 发查询并等应答。
#
# 正面那半(开启后真的中转成功)是这组的判别器:只有反面那半的话,探针连不上、口令取错、混淆没配
# 这些脚手架问题全都表现为「udp_disabled」,于是断言恒绿而什么都没测到。
#
# udp_relay_enabled 是 deferred 字段(只在启动期构建 hy2 server),所以两次切换都要重启 + 等重连。
_check_udp_relay_stays_disabled() {
  local dir="${E2E_REMOTE_DIR:-/tmp/nte2e}"
  local probe="/tmp/hy2udpprobe"
  if ! _ensure_hy2_probe "$probe"; then
    return 0
  fi

  # 口令与混淆口令都从服务端真配置里取:写死在脚本里会在换环境后静默变成「连不上」,
  # 而连不上恰好长得像「UDP 被拦住」—— 那正是这组最怕的假绿。
  # 取值必须**段感知**:password / listen_addr 这些键名在 config.toml 里多个段都有
  # (server / hysteria / reality / web),按全文 grep 再 head -1 是碰运气 —— 实测
  # listen_addr 就有四条,拼起来变成一个非法端口,而那个错误长得像「探针连不上」。
  local pw ob port
  pw="$(_hy2_conf_value password)"
  ob="$(_hy2_conf_value obfs_salamander_password)"
  port="$(_hy2_conf_value listen_addr | grep -oE '[0-9]+$')"
  if [[ -z "$pw" || -z "$port" ]]; then
    env_error "取不到 hy2 口令/端口,UDP 中转这组测不到"
    return 0
  fi

  local cert_args=""
  if [[ "$(a "test -f /tmp/probe-cert.pem && echo yes" | tr -d '[:space:]')" == "yes" ]]; then
    cert_args="-cert /tmp/probe-cert.pem -key /tmp/probe-key.pem"
  fi
  local cmd="$probe -addr $E2E_SRV_HOST:$port -password '$pw' -obfs '$ob' $cert_args -sni localhost"


  # ── 关着(默认):握手成功,但拿不到 UDP 能力 ──────────────────────────────
  local out
  out="$(a "$cmd")"
  case "$out" in
    *handshake_failed*)
      env_error "hy2 探针握不上手($out),UDP 中转这组测不到 —— 连不上会伪装成「UDP 被拦住」"
      return 0
      ;;
    *udp_disabled*) _pass "hy2 UDP 中转 · 关着时通过认证的客户端也拿不到 UDP 能力" ;;
    *) _fail "hy2 UDP 中转 · 关着时不该给出 UDP 能力" "$out" ;;
  esac

  # ── 开着:确实能把服务器当通用 UDP 代理 ────────────────────────────────
  local since
  since="$(s 'date +%s' | tr -d '[:space:]')"
  if ! s "python3 $dir/tomlset.py /etc/nanotun/config.toml hysteria udp_relay_enabled true && systemctl restart nanotun" >/dev/null; then
    _restore_udp_relay_off
    env_error "开 udp_relay_enabled 失败,正面那半测不到"
    return 0
  fi
  wait_until "hy2 UDP 中转 · 开启后两个客户端重连" 90 both_clients_online

  out="$(a "$cmd")"
  if [[ "$out" == *udp_relayed* ]]; then
    _pass "hy2 UDP 中转 · 开启后真的中转成功（说明上面那条不是「探针连不上」造成的假绿）"
  else
    _fail "hy2 UDP 中转 · 开启后应能中转到公网 UDP" "$out"
  fi

  # 攻击面变大这件事必须在启动日志里说清楚,否则误开之后无人知晓。
  local log
  log="$(s "journalctl -u nanotun --since @$since --no-pager")"
  if echo "$log" | grep -q "作为通用 UDP 代理使用"; then
    _pass "hy2 UDP 中转 · 开启时启动期就警告攻击面变大"
  else
    _fail "hy2 UDP 中转 · 开启时应在启动期警告「作为通用 UDP 代理使用」" "$(echo "$log" | grep -i hy2 | tail -5)"
  fi

  _restore_udp_relay_off
  wait_until "hy2 UDP 中转 · 关闭后两个客户端重连" 90 both_clients_online
  out="$(a "$cmd")"
  if [[ "$out" == *udp_disabled* ]]; then
    _pass "hy2 UDP 中转 · 关回去之后能力随之收回"
  else
    _fail "hy2 UDP 中转 · 关回去之后不该还能中转" "$out"
  fi
}

# _check_rotating_hy2_obfs_revokes_the_old_password 验「轮换 salamander 混淆口令,旧口令必须立刻失效」。
#
# 为什么单独测这一项:混淆口令是**为安全而轮换**的东西 —— 运维会在怀疑入口被识别、
# 或口令可能已泄漏时换掉它。换完之后唯一重要的问题是「旧的还能不能用」。这件事在
# 上面那组 deferred 里只体现为一行日志,而日志说的是「需重启」,不是「重启后旧的真的没用了」。
# 两者之间隔着一整个 hy2 服务端的构建路径。
#
# 这组同时把那行 deferred 警告的**代价**摆出来:第三段刻意只发 SIGHUP 不重启,然后证明
# 上一把口令仍然握得上手 —— 也就是说,运维如果只 reload 就以为轮换完成了,旧口令实际
# 一直有效到下次重启。这正是 reload.go 里给这个字段加上报的理由。
#
# 判别器是必须的:混淆口令不对的表现就是 handshake_failed,而探针坏了、口令取错、证书
# 没签上,表现**一模一样**。所以每一段「旧口令失败」的断言旁边都配一条「当前口令成功」。
_check_rotating_hy2_obfs_revokes_the_old_password() {
  local dir="${E2E_REMOTE_DIR:-/tmp/nte2e}"
  local probe="/tmp/hy2udpprobe"
  if ! _ensure_hy2_probe "$probe"; then
    return 0
  fi
  s "mkdir -p $dir" >/dev/null
  s "cat > $dir/tomlset.py" < "$E2E_ROOT/remote/tomlset.py"

  local orig_ob
  orig_ob="$(_hy2_conf_value obfs_salamander_password)"
  if [[ -z "$orig_ob" ]]; then
    env_error "这台的 hy2 没配 obfs_salamander_password（salamander 没开），轮换这组测不到"
    return 0
  fi

  # ── 第一段:基线判别器 ──────────────────────────────────────────────────
  # 先证明「用当前口令能握上手」。少了这一步,后面每一条断言都可能是探针坏了造成的假绿。
  if [[ "$(_obfs_probe "$probe" "$orig_ob")" == "ok" ]]; then
    _pass "hy2 混淆口令 · 基线:用当前口令能完成握手（判别器）"
  else
    env_error "用当前口令都握不上手，轮换这组测不到 —— 否则后面的「旧口令失效」全是假绿"
    return 0
  fi

  local new_ob="nte2e-obfs-$(date +%s)"

  # ── 第二段:真轮换(改配置 + 重启)—— 旧口令必须失效,新口令必须可用 ──────
  if ! s "python3 $dir/tomlset.py /etc/nanotun/config.toml hysteria obfs_salamander_password '\"$new_ob\"' && systemctl restart nanotun" >/dev/null; then
    _restore_hy2_obfs "$dir" "$orig_ob"
    env_error "轮换 obfs 口令失败，这组测不到"
    return 0
  fi
  wait_until "hy2 混淆口令 · 轮换重启后两个客户端重连" 90 both_clients_online

  if [[ "$(_obfs_probe "$probe" "$orig_ob")" == "failed" ]]; then
    _pass "hy2 混淆口令 · 轮换重启后旧口令再也握不上手（旧口令真的被吊销）"
  else
    _fail "hy2 混淆口令 · 轮换重启后旧口令仍然可用" "$(_obfs_probe_raw "$probe" "$orig_ob")"
  fi
  if [[ "$(_obfs_probe "$probe" "$new_ob")" == "ok" ]]; then
    _pass "hy2 混淆口令 · 轮换重启后新口令可用（说明上一条不是「服务坏了」）"
  else
    _fail "hy2 混淆口令 · 轮换重启后新口令应可用" "$(_obfs_probe_raw "$probe" "$new_ob")"
  fi

  # ── 第三段:只 SIGHUP 不重启 —— 上报 deferred,且上一把口令仍然有效 ──────
  # 这一段是把 deferred 警告的代价变成可观测的事实。
  local third_ob="nte2e-obfs-sighup-$(date +%s)" since
  since="$(s 'date +%s' | tr -d '[:space:]')"
  if s "python3 $dir/tomlset.py /etc/nanotun/config.toml hysteria obfs_salamander_password '\"$third_ob\"' && systemctl reload nanotun" >/dev/null; then
    sleep 3
    local detail
    detail="$(adm "audit list --limit 20" | grep config_reload | head -1)"
    check_contains "hy2 混淆口令 · 只 reload 时上报需重启" "hysteria.obfs_salamander_password" "$detail"

    if [[ "$(_obfs_probe "$probe" "$third_ob")" == "failed" ]]; then
      _pass "hy2 混淆口令 · 只 reload 时新写的口令并没有生效"
    else
      _fail "hy2 混淆口令 · 只 reload 时新口令不该已经生效（那样 deferred 就报错了）" "$(_obfs_probe_raw "$probe" "$third_ob")"
    fi
    # 这条是这一段的重点:运维以为换掉了,而上一把口令一直有效到下次重启。
    if [[ "$(_obfs_probe "$probe" "$new_ob")" == "ok" ]]; then
      _pass "hy2 混淆口令 · 只 reload 时上一把口令仍然有效（这正是必须上报 deferred 的代价）"
    else
      _fail "hy2 混淆口令 · 只 reload 后上一把口令应仍然有效" "$(_obfs_probe_raw "$probe" "$new_ob")"
    fi
  else
    env_error "写第三把 obfs 口令 / reload 失败，SIGHUP 那半测不到"
  fi

  # ── 收尾:写回原口令并重启,确认基线口令重新可用 ─────────────────────────
  _restore_hy2_obfs "$dir" "$orig_ob"
  if [[ "$(_obfs_probe "$probe" "$orig_ob")" == "ok" ]]; then
    _pass "hy2 混淆口令 · 还原后原口令重新可用"
  else
    _fail "hy2 混淆口令 · 还原后原口令应重新可用" "$(_obfs_probe_raw "$probe" "$orig_ob")"
  fi
}

# _obfs_probe_raw <探针> <混淆口令> 用指定混淆口令跑一次探针,回原始输出。
# 口令/端口/证书都从服务端真配置取(理由同 udp_relay 那组:写死会在换环境后静默变成「连不上」)。
_obfs_probe_raw() {
  local probe="$1" ob="$2" pw port cert_args=""
  pw="$(_hy2_conf_value password)"
  port="$(_hy2_conf_value listen_addr | grep -oE '[0-9]+$')"
  if [[ "$(a "test -f /tmp/probe-cert.pem && echo yes" | tr -d '[:space:]')" == "yes" ]]; then
    cert_args="-cert /tmp/probe-cert.pem -key /tmp/probe-key.pem"
  fi
  # 超时压短些:这组要连着跑六七次探针,而「握不上手」这一侧每次都要等满超时。
  a "$probe -addr $E2E_SRV_HOST:$port -password '$pw' -obfs '$ob' $cert_args -sni localhost -timeout 5s"
}

# _obfs_probe <探针> <混淆口令> 回 ok / failed。
# 混淆口令不对时 salamander 收到的是一堆无法解包的字节,握手只能等到超时,故判 failed。
_obfs_probe() {
  case "$(_obfs_probe_raw "$1" "$2")" in
    *udp_disabled*|*udp_relayed*) echo ok ;;
    *) echo failed ;;
  esac
}

# _restore_hy2_obfs <远端目录> <原口令> 写回原混淆口令并重启(不可热更),等客户端回来。
_restore_hy2_obfs() {
  s "python3 $1/tomlset.py /etc/nanotun/config.toml hysteria obfs_salamander_password '\"$2\"' && systemctl restart nanotun" >/dev/null
  wait_until "hy2 混淆口令 · 还原后两个客户端重连" 90 both_clients_online
}

# _hy2_conf_value <键名> 取 [hysteria] 段里该键的值(去掉引号)。
_hy2_conf_value() {
  s "awk '/^\[hysteria\]/{f=1;next} /^\[/{f=0} f && /^$1 *=/{print; exit}' /etc/nanotun/config.toml" \
    | cut -d'"' -f2 | tr -d '[:space:]'
}

# _ensure_hy2_probe 保证客户端 A 上有可用的探针与客户端证书,缺就现做。
#
# 不做成「缺了就 skip」:skip 在汇总里是一行灰字,换个环境跑就会永远灰着,而这组测的是
# 一个安全开关 —— 静默不测比红更糟。所以缺二进制就本地交叉编译推上去,缺证书就用服务端
# 那把客户端 CA 现签一张(hy2 入口是 RequireAndVerifyClientCert,没证书连握手都过不去)。
_ensure_hy2_probe() {
  local probe="$1"
  if [[ "$(a "test -x $probe && echo yes" | tr -d '[:space:]')" != "yes" ]]; then
    local bin="/tmp/nte2e-hy2udpprobe.$$"
    if ! (cd "$E2E_ROOT/../.." && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o "$bin" ./scripts/e2e/remote/hy2udpprobe/) >/dev/null 2>&1; then
      env_error "编译 hy2udpprobe 失败(需要本机有 Go 工具链),hy2 UDP 中转这组测不到"
      return 1
    fi
    if ! push_file a "$bin" "$probe"; then
      rm -f "$bin"
      env_error "把 hy2udpprobe 推到客户端 A 失败,hy2 UDP 中转这组测不到"
      return 1
    fi
    rm -f "$bin"
    a "chmod +x $probe" >/dev/null
    note "已把 hy2udpprobe 编译并推到客户端 A"
  fi

  # 现签一张:CA 证书路径取自真配置,私钥按同名 -key 兄弟找(install 脚本就是这么摆的)。
  local ca
  ca="$(s "grep -oE '^tls_client_ca_file = \"[^\"]+\"' /etc/nanotun/config.toml | cut -d'\"' -f2" | tr -d '[:space:]')"
  if [[ -z "$ca" ]]; then
    note "hy2 入口未开 mTLS,探针不带客户端证书"
    return 0
  fi
  # 配置里这一项通常是相对路径(相对 /etc/nanotun),而远端命令的 cwd 是登录目录 ——
  # 直接拿去 test -f 会永远说「找不到」,于是这组静默退化成 ENV。先补成绝对路径。
  [[ "$ca" == /* ]] || ca="/etc/nanotun/$ca"

  # 每轮都重签,**不缓存**。省下的那两秒不值得换来这个故障模式:
  #
  # 原先是「/tmp/probe-cert.pem 在就复用」。2026-08-03 服务端重装换掉了客户端 CA,
  # A 上那张上一轮签的证书还在,于是被继续拿去握手,服务端以
  # `tls: unknown certificate authority` 拒掉 —— 报出来是「hy2 探针握不上手」,
  # 读起来像 UDP 中转坏了或者被防火墙拦了。
  #
  # 试过用「比对 CA 主体 hash 与证书签发者 hash」来判新旧,那是错的:
  # subject_hash 只对**名字**取哈希,与密钥无关。新旧 CA 的主体都是
  # `CN=nanotun-client-ca, O=nanotun-deploy`,两边算出来都是 becfdd85,
  # 换了密钥的 CA 照样判成「同一个」。要真判准就得验签,那还不如直接重签。
  a "rm -f /tmp/probe-cert.pem /tmp/probe-key.pem" >/dev/null

  local cadir cabase cakey
  cadir="$(dirname "$ca")"
  cabase="$(basename "$ca" .pem)"
  cakey="$cadir/${cabase}-key.pem"
  if [[ "$(s "test -f $cakey && echo yes" | tr -d '[:space:]')" != "yes" ]]; then
    env_error "找不到客户端 CA 私钥($cakey),签不出探针证书,hy2 UDP 中转这组测不到"
    return 1
  fi
  if ! s "cd $cadir && openssl req -newkey rsa:2048 -nodes -keyout /tmp/probe-key.pem -subj '/CN=e2e-hy2-udp-probe' -out /tmp/probe.csr 2>/dev/null && openssl x509 -req -in /tmp/probe.csr -CA $(basename "$ca") -CAkey $(basename "$cakey") -CAcreateserial -days 30 -out /tmp/probe-cert.pem" >/dev/null 2>&1; then
    env_error "用客户端 CA 签探针证书失败,hy2 UDP 中转这组测不到"
    return 1
  fi
  local f
  for f in probe-cert.pem probe-key.pem; do
    s "cat /tmp/$f" > "/tmp/nte2e-$f" 2>/dev/null
    if ! push_file a "/tmp/nte2e-$f" "/tmp/$f"; then
      env_error "把探针证书推到客户端 A 失败,hy2 UDP 中转这组测不到"
      return 1
    fi
    rm -f "/tmp/nte2e-$f"
  done
  note "已用服务端客户端 CA 现签探针证书并推到 A"
  return 0
}

# _restore_udp_relay_off 写死 false 并重启。这个开关关系到攻击面,还原绝不能依赖快照。
_restore_udp_relay_off() {
  local dir="${E2E_REMOTE_DIR:-/tmp/nte2e}"
  s "python3 $dir/tomlset.py /etc/nanotun/config.toml hysteria udp_relay_enabled false && systemctl restart nanotun" >/dev/null 2>&1 || true
}

# _check_jump_host_firewall_fails_closed_without_ipset 验 ipset 不可用时 jump_host_firewall
# **拒绝启动**,而不是起来了却把受保护端口对全网敞开。
#
# 钉的是第 23 轮深扫的那条 HIGH:在那之前 jumpFW.Replace 失败只打一行红字,启动照常继续,
# reload 还照样把它记成「已热更新」并回报成功。运维据配置认为入口已限制到跳板机名单,实际
# 对全网敞开 —— 而 `ipset 未装` 正是代码注释里列在第一位的触发条件。这条修复此前只有单测
# (用假 exec 注入失败),真机上从没验过。
#
# 为什么这台机器现成就能测:它**没装 ipset**(iptables 有,ipset 没有)。也就是说这里不需要
# 构造任何故障,生产条件本来就在。ipset 哪天被装上,这条就不再成立 —— 那时它必须**跳过并说
# 清楚**,而不是静默变成一条永远绿的空断言。
#
# 最要紧的是那条反向断言:名单必须填一个**合法非空**的 IPv4。留空的话会被更早的
# ValidateJumpHostFirewall 拦下(「留空等于全网开放」),Fatal 照样发生、断言照样绿,但测到的
# 是另一道闸 —— 第 51 轮刚在还原守卫上踩过同一个坑(一道闸被更早的同族闸永久遮住)。
_check_jump_host_firewall_fails_closed_without_ipset() {
  # 探测要落在 nanotund 自己看得到的文件系统里 —— 容器部署时宿主装没装 ipset 不作数。
  if srv_in_svc "command -v ipset >/dev/null 2>&1 || ls /sbin/ipset /usr/sbin/ipset >/dev/null 2>&1" >/dev/null 2>&1; then
    skip "跳板机防火墙 · 缺 ipset 时 fail-closed（本机装了 ipset，这条测不到：它要的正是「ipset 不可用」这个条件）"
    return 0
  fi

  local bak=/tmp/nte2e-cfg.jumpfw.bak
  s "cp /etc/nanotun/config.toml $bak" >/dev/null
  local dir="${E2E_REMOTE_DIR:-/tmp/nte2e}"
  s "mkdir -p $dir" >/dev/null
  s "cat > $dir/tomlset.py" < "$E2E_ROOT/remote/tomlset.py"

  # 名单填 A 的真实 IP:合法 IPv4、非空,足以走过所有 config 期校验,失败必须来自运行期应用。
  local setrc=0
  s "python3 $dir/tomlset.py /etc/nanotun/config.toml server jump_host_allowed_ips '[\"$E2E_A_HOST\"]'" >/dev/null || setrc=1
  s "python3 $dir/tomlset.py /etc/nanotun/config.toml server jump_host_firewall true" >/dev/null || setrc=1
  if (( setrc != 0 )); then
    s "cp $bak /etc/nanotun/config.toml" >/dev/null
    env_error "改写 config.toml 失败,跳板机防火墙这组断言测不到"
    return 0
  fi

  # 预期起不来。restart 因此会返回非零,不能让它中断本函数。
  local since status log
  since="$(s 'date +%s' | tr -d '[:space:]')"
  s "systemctl restart nanotun" >/dev/null 2>&1 || true
  sleep 4
  status="$(s 'systemctl is-active nanotun' | tr -d '[:space:]')"
  log="$(s "journalctl -u nanotun --since @$since --no-pager")"

  if [[ "$status" == "active" ]]; then
    _fail "跳板机防火墙 · ipset 不可用时必须拒绝启动" \
      "服务仍是 active —— 受保护端口此刻对全网敞开,而配置上写着已限制到名单内。这正是第 23 轮修掉的形态。
$log"
  else
    _pass "跳板机防火墙 · ipset 不可用时拒绝启动（fail-closed，不是带着敞开的端口跑起来）"
  fi

  # 退出码要是「配置语义错」(11) 而不是 panic / 通用 1:运维靠它区分「配置写错了」和「崩了」。
  local rc
  rc="$(s "systemctl show -p ExecMainStatus --value nanotun" | tr -d '[:space:]')"
  check "跳板机防火墙 · 退出码是配置语义错 ExitConfigSemantic(11)" "11" "$rc"

  if echo "$log" | grep -q "受保护端口当前"; then
    _pass "跳板机防火墙 · 日志明说「受保护端口当前未受限」（运维据此知道现在是没保护的）"
  else
    _fail "跳板机防火墙 · 日志应明说受保护端口未受限" "$log"
  fi

  # 反向断言:不能是被「名单留空」那道更早的闸拦下的 —— 那样测的是另一回事。
  if echo "$log" | grep -q "留空等于全网开放"; then
    _fail "跳板机防火墙 · 拦下它的是「名单留空」那道更早的闸，本条没测到运行期应用失败" "$log"
  else
    _pass "跳板机防火墙 · 拦下它的确实是运行期应用失败，不是名单校验"
  fi

  s "cp $bak /etc/nanotun/config.toml && rm -f $bak && systemctl restart nanotun" >/dev/null 2>&1 || true
  sleep 3
  check "跳板机防火墙 · 恢复配置后服务重新起来" "active" "$(s 'systemctl is-active nanotun' | tr -d '[:space:]')"
  wait_until "跳板机防火墙 · 客户端重连、出口恢复" 90 probe_egress_is "$E2E_C_HOST"
}

# _login_success_actor_since 取某用户在 $2 之后最新一条 login.success 的 actor;没有就空串。
_login_success_actor_since() {
  s "sqlite3 '$E2E_DB_PATH' \"select actor from audit_logs where action='login.success' and target='$1' and at>=$2 order by id desc limit 1;\"" \
    | tr -d '[:space:]'
}

_has_fresh_login() { [[ -n "$(_login_success_actor_since "$1" "$2")" ]]; }

# _check_login_attribution_uses_real_client_ip 验登录归因落在客户端**真实公网 IP** 上。
#
# 两个客户端都不是直连:C 走 hy2(QUIC),A 走 REALITY,两条都经本机环回 smux 承载再进
# handleVPNLink。承载那一跳会把真实客户端地址用 PROXY v2 头带过来 —— 这一步一旦坏掉,
# 服务端回退成环回地址,于是**所有**经该承载的会话在审计里都成了 127.0.0.1:
#   - 事后按 IP 追爆破/扫描直接失效(全是同一个地址);
#   - per-IP 登录限速退化成全局限速,一个客户端能把所有人锁死;
#   - PoW 难度按 IP 累进也跟着失效。
# 而这些症状都不会让任何现有断言变红:隧道照通、会话照在。
#
# hy2 那条尤其脆:客户端地址来自 QUIC,是 *net.UDPAddr,而 go-proxyproto 要求 src 与 dst
# 同类型,不归一就整个头静默退化成 LOCAL(无源)。2026-07-25 就这么坏过一次(当时审计
# actor 仍是 127.0.0.1),靠双机手工实测发现,一直没有自动回归 —— 这条补的就是它。
#
# 单测覆盖不到:归一化函数本身可以单测,但「QUIC 地址 → 归一 → PROXY v2 → 服务端解析 →
# 落进审计」跨了两条真实承载和一次真实登录,只有三机能走通。
_check_login_attribution_uses_real_client_ip() {
  # 按 vIP 认连接,不按用户名:审计的 target 是 userID("u<主键>"),跟用户名是两个命名空间,
  # 直接拿 E2E_*_USER 去查审计对不上。vIP 在 env 里是确定的,且 connection list 同一行的
  # USER_ID 列就是审计要的那个 userID。
  _attribution_case "$E2E_C_VIP4" "$E2E_C_HOST" "hy2"
  _attribution_case "$E2E_A_VIP4" "$E2E_A_HOST" "REALITY"
}

_attribution_case() {
  local vip="$1" host="$2" label="$3"
  local row cid user since actor ip

  row="$(adm "connection list" | awk -v v="$vip" '$4 ~ v {print $1, $3; exit}')"
  if [[ -z "$row" ]]; then
    skip "$label 登录归因（未找到 $vip 的在线会话）"
    return 0
  fi
  cid="${row%% *}"; user="${row##* }"

  # 用服务端时钟做起点,只认这次踢线之后的那条登录 —— 否则会读到上一轮跑留下的旧记录,
  # 归因坏掉了也照样绿。
  since="$(s 'date +%s' | tr -d '[:space:]')"
  adm_y "kick session $cid" >/dev/null
  if ! wait_until "$label 客户端踢线后重新登录" 90 _has_fresh_login "$user" "$since"; then
    return 0   # wait_until 已经记了红/ENV,再断言 actor 只会多一条同因的红
  fi

  actor="$(_login_success_actor_since "$user" "$since")"
  ip="${actor%:*}"
  check "$label 登录归因是客户端真实公网 IP（不是环回）" "$host" "$ip"
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

  _check_restore_names_the_other_db_holder /tmp/nte2e-junk.db

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
  # 紧跟在 deferred 后面:那条只验「SIGHUP 会报 forward_block_bt 需重启」,这条才验
  # 重启之后规则真的落进了内核。两条合起来才把这个开关的链路走完。
  _check_forward_port_drops_follow_their_own_knobs
  # 紧挨着上一条:同样是 FORWARD 链上的规则,而且两者装在同一次 SetupIptables 里。
  _check_connlimit_caps_concurrency_without_hurting_mesh
  _check_udp_relay_stays_disabled
  # 紧跟 udp_relay:同一套探针、同一个 hy2 入口。那组验「能力开关」,这组验「凭据轮换」。
  _check_rotating_hy2_obfs_revokes_the_old_password
  _check_exit_guard_installs_both_chains
  _check_data_plane_keepalive_reaps_only_the_wedged_session
  _check_lease_gc_reclaims_only_what_it_should

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

  # ── 登录归因落在真实客户端 IP 上 ─────────────────────────────────────────
  # 放在踢线之后:它自己也要踢一次来制造全新登录,顺序上挨着更省一次重连等待。
  _check_login_attribution_uses_real_client_ip

  # 放在踢线之后、jump_host 之前:它会把 A 挤下线再拉回来,自带一次完整的重连等待,
  # 挨着上面那条同样要重连的踢线断言,省掉一次冷启动。
  _check_max_sessions_evicts_the_oldest

  # 放在最后:它要重启 nanotund 并等两个客户端重连,后面不该再挂别的断言。
  _check_jump_host_firewall_fails_closed_without_ipset

  s "rm -f $bk /tmp/nte2e-junk.db /tmp/nte2e-cfg.good" >/dev/null
}

_kick_log_has_902() { client_log c "$E2E_C_UNIT" 60 | grep -q "code=902"; }

# ─────────────────────────────────────────────────────────────────────────────
# _check_lease_gc_reclaims_only_what_it_should 验 [server].lease_gc_idle_days。
#
# 这个开关此前 e2e 零命中。它的两个方向都会伤人,而且都是安静地伤:
#   - **不回收**:leases 表堆满「设备半年没上线」的 vIP 占位,新设备拿不到地址(IPv4 私网池尤其);
#   - **回收错**:把还在用的地址收走,设备重连换 IP —— 按 vIP 钉的 ACL / 端口转发就此指向空处。
#
# 判定条件是 `manual=0 AND device_id IN (select id from devices where last_seen_at < cutoff)`,
# 外加一道「lease 的 vip 正是该设备 fixed_vip 就永不回收」的兜底。所以要钉三件事:
# 过期的非手动租约会被收;**未过期的**非手动租约不许被收(cutoff 的算术);手动租约永不被收。
#
# 触发点选**启动那一次**:定时器周期以小时计(默认 24h),e2e 里等不到;而 lease_gc 启动时
# 会先跑一次(代码注释:「启动跑一次(防错过 tick)」),重启即触发。
#
# 观测量用 lease_gc_total 而不是 grep 日志:它是进程内计数器,重启归零,所以「这一次启动
# 回收了几条」能精确断言成 1 或 0。日志只在 n>0 时打 INFO(n==0 走 Debug,默认级别看不见),
# 只靠 grep 的话「没回收」和「日志没打出来」分辨不开。
#
# 靶子用 E2E_SPARE_DEVICE_ID(harness 指定的备用设备),租约由本用例自建自收,不动别人的。
# 阈值刻意取 90 天、把靶子回拨 200 天:库里另一台闲置设备(闲置数天、同样是非手动租约)
# 因此成为**天然对照** —— 它必须活下来,谁把 cutoff 的单位或方向写错,它就会跟着一起死。
_check_lease_gc_reclaims_only_what_it_should() {
  local dev="${E2E_SPARE_DEVICE_ID:-}"
  if [[ -z "$dev" ]]; then
    skip "lease_gc（未配置 E2E_SPARE_DEVICE_ID，没有可安全回收的靶子）"
    return 0
  fi

  # 现场取证用:开跑前把「除靶子之外的租约」记下来,回收后逐条比对。
  local others_before
  others_before="$(_lease_rows_except "$dev")"
  if [[ -z "$others_before" ]]; then
    env_error "库里除靶子外没有别的租约,lease_gc 的「不许连坐」这组测不到"
    return 0
  fi

  local seen_before
  seen_before="$(s "sqlite3 '$E2E_DB_PATH' 'select last_seen_at from devices where id=$dev;'" | tr -d '[:space:]')"
  if [[ ! "$seen_before" =~ ^[0-9]+$ ]]; then
    env_error "取不到设备 $dev 的 last_seen_at,lease_gc 这组测不到"
    return 0
  fi

  # 前四档只关心「收谁 / 不收谁」,把首轮宽限期压到 1s 免得每档白等两分钟。
  # 宽限期本身单独在最后一档验(它是这一轮修掉的那个缺陷的正面证明)。
  #
  # 必须先**关掉回收并重启**再装靶:阶段 5 前面的用例也会重启 nanotund,现场常留下一条
  # 「默认 startup_grace=2m、idle=30d」的进程。若直接把过期靶子写进库,那条进程的首轮 GC
  # 会在我们自己的 restart 之前把租约偷走 —— 新进程 lease_gc_total 恒为 0,而靶子已经没了
  # (2026-08-01 实撞:journal 里旧进程 reclaimed=1,紧接着新进程 grace=1s 却无可回收)。
  _lease_gc_set_days -1
  _lease_gc_set_grace 1
  _lease_gc_restart || { _lease_gc_restore "$dev" "$seen_before"; return 0; }

  # ── 第一档:过期的非手动租约应当被收,且只收它 ────────────────────────────
  _lease_gc_arm_target "$dev" false || { _lease_gc_restore "$dev" "$seen_before"; return 0; }
  if ! _lease_gc_set_days 90; then
    _lease_gc_restore "$dev" "$seen_before"
    env_error "写不进 lease_gc_idle_days,这组测不到"
    return 0
  fi
  _lease_gc_restart || { _lease_gc_restore "$dev" "$seen_before"; return 0; }

  # 宽限期 1s,而 _lease_gc_restart 要等客户端重连(~30s),通常回来时首轮早已跑完。
  # 仍 wait 一下:慢启动 / 控制面短暂不可达时,立刻读计数器会假红成 0。
  if ! wait_until "lease_gc · 启动宽限期后回收发生" 30 _lease_gc_total_at_least 1; then
    _lease_gc_restore "$dev" "$seen_before"
    return 0
  fi
  check "lease_gc · 启动那一次恰好回收 1 条（过期的非手动租约）" "1" "$(srv_field lease_gc_total)"
  check "lease_gc · 靶子的租约确实没了" "0" "$(_lease_count_of "$dev")"
  # 对照:另一台设备同样是非手动租约,但闲置天数没到阈值,必须一条不少地留着。
  # 这条是 cutoff 算术的判别器 —— 单位写成秒、或把 < 写成 >,它就会跟着被收走。
  check "lease_gc · 未过期的非手动租约一条没动（cutoff 的算术没写错）" "$others_before" \
    "$(_lease_rows_except "$dev")"

  # ── 第二档:未过期的非手动租约不许被收 ───────────────────────────────────
  # 这一档是 cutoff **方向与单位**的判别器,而且刻意用自己管的靶子设备来做,不靠库里
  # 恰好存在的某条别人的租约:后者一旦不在(比如被上一次反向验证吃掉了),剩下的全是手动
  # 租约 —— 它们因**另一个**原因免疫,于是「不许连坐」变成恒绿。2026-07-30 就是这么发现的。
  _lease_gc_arm_target "$dev" false fresh || { _lease_gc_restore "$dev" "$seen_before"; return 0; }
  _lease_gc_restart || { _lease_gc_restore "$dev" "$seen_before"; return 0; }
  check "lease_gc · 未过期的非手动租约不被回收（cutoff 的方向与单位没写错）" "0" "$(srv_field lease_gc_total)"
  check "lease_gc · 未过期的靶子租约仍在库里" "1" "$(_lease_count_of "$dev")"

  # ── 第三档:手动(管理员钉的固定地址)租约永不回收 ────────────────────────
  # 同样过期 200 天,唯一差别是 manual=1。收走它等于把管理员手钉的地址抢掉,
  # 设备再上线拿不回原地址,而按该地址写的 ACL / 端口转发全部落空。
  _lease_gc_arm_target "$dev" true || { _lease_gc_restore "$dev" "$seen_before"; return 0; }
  local since_manual
  since_manual="$(s "date +%s" | tr -d '[:space:]')"
  _lease_gc_restart || { _lease_gc_restore "$dev" "$seen_before"; return 0; }
  check "lease_gc · 手动租约过期同样不回收（管理员钉的地址不许被抢）" "0" "$(srv_field lease_gc_total)"
  check "lease_gc · 手动租约仍在库里" "1" "$(_lease_count_of "$dev")"
  # 正面对照:上面那个 0 也可能是「GC 压根没跑」得来的(配置没写进去、循环没起来都会这样)。
  # 启动日志证明这一轮回收确实执行了,那个 0 才是「跑了但没动手动租约」的意思。
  check_contains "lease_gc · 手动那一档里回收确实跑了（0 不是因为压根没跑）" "定时回收已启用" \
    "$(s "journalctl -u nanotun --since @$since_manual --no-pager | grep lease-gc")"

  # ── 第四档:负值才是关闭 ──────────────────────────────────────────────────
  _lease_gc_arm_target "$dev" false || { _lease_gc_restore "$dev" "$seen_before"; return 0; }
  if ! _lease_gc_set_days -1; then
    _lease_gc_restore "$dev" "$seen_before"
    env_error "写不进 lease_gc_idle_days=-1,关闭这一档测不到"
    return 0
  fi
  local since
  since="$(s "date +%s" | tr -d '[:space:]')"
  _lease_gc_restart || { _lease_gc_restore "$dev" "$seen_before"; return 0; }
  check "lease_gc · 负值关闭后一条都不回收（过期的非手动租约也留着）" "0" "$(srv_field lease_gc_total)"
  check "lease_gc · 负值关闭后靶子的租约仍在" "1" "$(_lease_count_of "$dev")"
  # 关闭这一档必须在日志里留痕,否则运维事后无从确认「到底是关了还是没跑」。
  check_contains "lease_gc · 关闭时日志留痕（运维事后能确认是关了而非没跑）" "显式关闭定时回收" \
    "$(s "journalctl -u nanotun --since @$since --no-pager | grep lease-gc")"

  # ── 第五档:写 0 是「用默认的 30 天」,不是关闭 ───────────────────────────
  # 这一档钉的是 2026-07-30 查出来的那处文档与代码矛盾:三处注释都写着「<=0 关闭」,
  # 而 server.go 里是 `== 0 → 30`。真语义(0 == 默认 30)必须被钉住,否则后来人照注释
  # 「修」成「0 = 关闭」时,所有**从没配过这个键**的部署会一起静默停掉回收 ——
  # int 的零值分不出「没配」与「显式 0」,而那正是这个功能要防的 vIP 池耗尽。
  # 靶子回拨了 200 天,远超默认的 30 天,所以「按默认跑」的表现就是它被收掉。
  _lease_gc_arm_target "$dev" false || { _lease_gc_restore "$dev" "$seen_before"; return 0; }
  if ! _lease_gc_set_days 0; then
    _lease_gc_restore "$dev" "$seen_before"
    env_error "写不进 lease_gc_idle_days=0,这一档测不到"
    return 0
  fi
  since="$(s "date +%s" | tr -d '[:space:]')"
  _lease_gc_restart || { _lease_gc_restore "$dev" "$seen_before"; return 0; }
  # 同第一档:宽限期 1s,立刻读计数器会假红成 0。
  if ! wait_until "lease_gc · 写 0 后启动宽限期回收发生" 30 _lease_gc_total_at_least 1; then
    _lease_gc_restore "$dev" "$seen_before"
    return 0
  fi
  check "lease_gc · 写 0 等于默认 30 天而非关闭（没配过的部署不会被静默停掉回收）" "1" \
    "$(srv_field lease_gc_total)"
  # 启用侧也必须留痕:在此之前只有「真删到东西」才打 INFO,于是「正按 30 天回收」这件事
  # 在日志里完全不可见 —— 照文档写 0 以为关掉了的人无从发现。
  check_contains "lease_gc · 启用时日志点明生效阈值（否则「按默认在跑」不可见）" "定时回收已启用" \
    "$(s "journalctl -u nanotun --since @$since --no-pager | grep lease-gc")"
  check_contains "lease_gc · 启用日志里的阈值是默认的 720h（30 天）" "idle=720h" \
    "$(s "journalctl -u nanotun --since @$since --no-pager | grep lease-gc")"

  _check_lease_gc_startup_grace_protects_online_devices "$dev" "$seen_before"

  _lease_gc_restore "$dev" "$seen_before"
}

# _check_lease_gc_startup_grace_protects_online_devices 验启动宽限期 —— 这一轮修掉的那个缺陷
# 的正面证明,而且只有三机能证:回收前那段「把在线会话的 last_seen_at 顶到 now」依赖当前会话
# 快照,而首轮回收跑在进程启动那一瞬间,那时一条会话都没重连上来,防御空转。后果是一台连续在线
# 超过 idle 天数、期间没重新登录的设备,每次重启都丢粘性租约 —— 重连换 IP,按 vIP 钉的
# ACL / 端口转发一起落空。
#
# 造这个现场需要一台**在线**且租约是**非手动**的设备。A 与 C 的租约都是 manual=1(管理员钉过
# 固定地址),天然免疫,打不中这个缺陷 —— 所以这里临时把 A 的租约改成非手动、清掉 fixed_vip,
# 测完原样钉回去。改的是租约的 manual 位与 fixed_vip,vIP 本身自始至终没变。
_check_lease_gc_startup_grace_protects_online_devices() {
  local spare="$1" spare_seen="$2"
  local adev="${E2E_A_DEVICE_ID:-1}" v4 v6 fv4 fv6

  read -r v4 v6 <<<"$(s "sqlite3 -separator ' ' '$E2E_DB_PATH' \"select coalesce(vip_v4,'-'),coalesce(vip_v6,'-') from leases where device_id=$adev;\"")"
  read -r fv4 fv6 <<<"$(s "sqlite3 -separator ' ' '$E2E_DB_PATH' \"select coalesce(fixed_vip_v4,'-'),coalesce(fixed_vip_v6,'-') from devices where id=$adev;\"")"
  if [[ "$v4" == "-" || -z "$v4" ]]; then
    env_error "取不到 A 的租约地址,启动宽限期这组测不到"
    return 0
  fi

  # 靶子设备留着当**探针**:它是可回收的,所以计数器从 0 变 1 的那一刻,就是首轮回收真的跑了
  # 的那一刻。没有它的话「首轮还没跑」和「跑了但什么都没收」在外面看是一模一样的 0。
  _lease_gc_arm_target "$spare" false || return 0

  # 把 A 变成「在线 + 非手动租约 + last_seen_at 很旧」—— 正是缺陷要打中的形状。
  s "sqlite3 '$E2E_DB_PATH' \"update devices set fixed_vip_v4=null,fixed_vip_v6=null where id=$adev;\"" >/dev/null
  if ! adm "lease set $adev --v4 $v4 $([[ "$v6" != "-" && -n "$v6" ]] && echo "--v6 $v6") --manual=false" >/dev/null 2>&1; then
    _lease_gc_repin_a "$adev" "$v4" "$v6" "$fv4" "$fv6"
    env_error "把 A 的租约临时改成非手动失败,启动宽限期这组测不到"
    return 0
  fi
  s "sqlite3 '$E2E_DB_PATH' \"update devices set last_seen_at=strftime('%s','now') - 200*86400 where id=$adev;\"" >/dev/null

  # 宽限期取 90s:两个客户端重连实测 ~30s 完成,断言「还没扫」要在那之后、宽限期之前落地,
  # 90s 留了约一分钟的余量。
  _lease_gc_set_grace 90
  _lease_gc_set_days 90
  local since
  since="$(s "date +%s" | tr -d '[:space:]')"
  if ! _lease_gc_restart; then
    _lease_gc_repin_a "$adev" "$v4" "$v6" "$fv4" "$fv6"
    return 0
  fi
  check_contains "lease_gc · 启用日志报出启动宽限期" "startup_grace=1m30s" \
    "$(s "journalctl -u nanotun --since @$since --no-pager | grep lease-gc")"

  # 客户端都重连上来了(约 30s),而宽限期是 90s —— 此刻探针必须还活着。
  # 这条就是「不是启动即扫」的正面证据:去掉宽限期的话,首轮在 t≈0 就把探针收走了。
  check "lease_gc · 客户端重连时首轮还没开扫（不是启动即扫）" "0" "$(srv_field lease_gc_total)"

  # 再等到有东西被收走,证明首轮确实跑了、只是晚了 —— 否则上面那个 0 也可能是「压根不回收」。
  # 这里只等「>=1」而不是恰好 1:首轮若连坐了在线设备,计数是 2,等「恰好 1」会一直等不到,
  # 于是整组以 env_error 中止 —— 真缺陷被降级成脚手架问题,下面那条最关键的断言根本跑不到。
  if ! wait_until "lease_gc · 宽限期过后首轮确实执行了（探针被回收）" 120 _lease_gc_total_at_least 1; then
    _lease_gc_repin_a "$adev" "$v4" "$v6" "$fv4" "$fv6"
    env_error "等不到首轮回收执行,启动宽限期这组测不到"
    return 0
  fi
  check "lease_gc · 首轮只收走了探针那一条（在线设备没被连坐）" "1" "$(srv_field lease_gc_total)"
  # 关键的一条是**地址**而不是条数:租约被收走之后设备重连会立刻拿到一条新的,条数照样是 1 ——
  # 变了的是地址。真实伤害正是这个:设备悄悄换了 IP,按 vIP 钉的 ACL / 端口转发一起落空。
  # 2026-07-30 反向验证时,「仍持有租约」是绿的而「地址没变」是红的,就是这么看出来的。
  check "lease_gc · 在线设备重启后仍持有租约" "1" "$(_lease_count_of "$adev")"
  check "lease_gc · 在线设备的粘性地址扛过了重启（首轮没把它当 idle 收走）" "$v4" \
    "$(s "sqlite3 '$E2E_DB_PATH' \"select coalesce(vip_v4,'') from leases where device_id=$adev;\"")"

  _lease_gc_repin_a "$adev" "$v4" "$v6" "$fv4" "$fv6"
  _lease_gc_set_grace 1
  # 还原靶子设备的 last_seen_at,后面 _lease_gc_restore 还要用它收尾。
  s "sqlite3 '$E2E_DB_PATH' \"update devices set last_seen_at=$spare_seen where id=$spare;\"" >/dev/null
}

# _lease_rows_except <设备> 除该设备之外的全部租约,一行一条,用于「不许连坐」的整体比对。
_lease_rows_except() {
  s "sqlite3 '$E2E_DB_PATH' \"select device_id||':'||coalesce(vip_v4,'')||':'||coalesce(vip_v6,'')||':'||manual from leases where device_id<>$1 order by device_id;\""
}

_lease_count_of() {
  s "sqlite3 '$E2E_DB_PATH' 'select count(*) from leases where device_id=$1;'" | tr -d '[:space:]'
}

# _lease_gc_arm_target <设备> <是否手动> [fresh] 给靶子装一条租约并设定 last_seen_at。
# 第三个参数给 fresh 表示「未过期」(设为当下),否则回拨 200 天(远超本组用的 90 天阈值)。
# 地址取池里明确空闲的一个;已有租约先收掉,保证 manual 位是这次想要的值。
_lease_gc_arm_target() {
  local dev="$1" manual="$2" fresh="${3:-}" vip="${E2E_LEASE_GC_PROBE_VIP:-10.201.9.9}" seen
  adm_y "lease release $dev" >/dev/null 2>&1
  if ! adm "lease set $dev --v4 $vip --manual=$manual" >/dev/null 2>&1; then
    env_error "给设备 $dev 装租约失败(manual=$manual),lease_gc 这组测不到"
    return 1
  fi
  # 时间戳在**库那一侧**算(strftime),不用本地 date:本地是开发机,与服务器有时钟差,
  # 而这一组的判定就是拿 last_seen_at 跟服务器的 now 比。
  if [[ "$fresh" == "fresh" ]]; then
    seen="strftime('%s','now')"
  else
    seen="strftime('%s','now') - 200*86400"
  fi
  s "sqlite3 '$E2E_DB_PATH' \"update devices set last_seen_at=$seen where id=$dev;\"" >/dev/null
  if [[ "$(_lease_count_of "$dev")" != "1" ]]; then
    env_error "设备 $dev 的租约没装上,lease_gc 这组测不到"
    return 1
  fi
  return 0
}

_lease_gc_set_days() {
  local dir="${E2E_REMOTE_DIR:-/tmp/nte2e}"
  s "mkdir -p $dir" >/dev/null
  s "cat > $dir/tomlset.py" < "$E2E_ROOT/remote/tomlset.py"
  s "python3 $dir/tomlset.py /etc/nanotun/config.toml server lease_gc_idle_days $1" >/dev/null
}

_lease_gc_set_grace() {
  local dir="${E2E_REMOTE_DIR:-/tmp/nte2e}"
  s "mkdir -p $dir" >/dev/null
  s "cat > $dir/tomlset.py" < "$E2E_ROOT/remote/tomlset.py"
  s "python3 $dir/tomlset.py /etc/nanotun/config.toml server lease_gc_startup_grace_sec $1" >/dev/null
}

# _lease_gc_total_at_least <n> 已回收总数是否达到 n。用「至少」而不是「恰好」:
# 恰好会在「多收了」的情形下永远等不到,把真缺陷变成超时中止。
_lease_gc_total_at_least() {
  local n
  n="$(srv_field lease_gc_total)"
  [[ "$n" =~ ^[0-9]+$ ]] && (( n >= $1 ))
}

# _lease_gc_repin_a 把 A 的固定地址原样钉回去(vIP 全程没变,只还原 manual 位与 fixed_vip)。
_lease_gc_repin_a() {
  local dev="$1" v4="$2" v6="$3" fv4="$4" fv6="$5" args=""
  [[ "$v4" != "-" && -n "$v4" ]] && args="--v4 $v4"
  [[ "$v6" != "-" && -n "$v6" ]] && args="$args --v6 $v6"
  adm_y "lease release $dev" >/dev/null 2>&1
  adm "lease set $dev $args --manual=true" >/dev/null 2>&1
  # fixed_vip 那两列是 lease set --manual 之外的东西,原来有就写回去,原来没有就保持空。
  if [[ "$fv4" != "-" && -n "$fv4" ]]; then
    s "sqlite3 '$E2E_DB_PATH' \"update devices set fixed_vip_v4='$fv4' where id=$dev;\"" >/dev/null
  fi
  if [[ "$fv6" != "-" && -n "$fv6" ]]; then
    s "sqlite3 '$E2E_DB_PATH' \"update devices set fixed_vip_v6='$fv6' where id=$dev;\"" >/dev/null
  fi
}

# _lease_gc_restart 重启并等两个客户端回来。lease_gc_idle_days 不可热更(reload 会报 deferred),
# 而启动那一次 GC 正是本组要观测的触发点,所以这里只能重启。
_lease_gc_restart() {
  s "systemctl restart nanotun" >/dev/null 2>&1
  if ! wait_until "lease_gc · 重启后两个客户端重连" 90 both_clients_online; then
    env_error "重启后客户端没能重连,lease_gc 余下的断言测不到"
    return 1
  fi
  return 0
}

# _lease_gc_restore 收掉靶子的租约、还原它的 last_seen_at、删掉本用例写进配置的那一行,再重启。
# 配置的还原用「删行」而不是「写回默认值 30」:后者虽与默认等价,却会在参考部署里留下一行
# 本来没有的配置,下次有人读配置时会以为这是刻意设的。
_lease_gc_restore() {
  local dev="$1" seen="$2" n
  adm_y "lease release $dev" >/dev/null 2>&1
  s "sqlite3 '$E2E_DB_PATH' 'update devices set last_seen_at=$seen where id=$dev;'" >/dev/null
  n="$(s "grep -cE '^lease_gc_(idle_days|startup_grace_sec) = ' /etc/nanotun/config.toml" | tr -d '[:space:]')"
  if [[ "$n" =~ ^[12]$ ]]; then
    s "grep -vE '^lease_gc_(idle_days|startup_grace_sec) = ' /etc/nanotun/config.toml > /tmp/nte2e-cfg.nogc && cat /tmp/nte2e-cfg.nogc > /etc/nanotun/config.toml" >/dev/null
  fi
  s "systemctl restart nanotun" >/dev/null 2>&1
  wait_until "lease_gc · 还原后两个客户端重连" 90 both_clients_online
}

# ─────────────────────────────────────────────────────────────────────────────
# _check_connlimit_caps_concurrency_without_hurting_mesh 验每虚拟 IP 并发连接上限。
#
# [tun] tcp_connlimit_per_ip / udp_connlimit_per_ip 此前 e2e 零覆盖,而这个开关**已经出过
# 两次事故**,两次都写在 network_setup_linux.go 的注释里,两次都极难现场定位:
#
#   - 规则漏了 `-o <wan>`:xt_connlimit 按 conntrack 原始方向的源地址归类,于是「某客户端
#     公网连接数超标」会把它的 mesh 互访、子网路由、出口回程**一起打死**。三机实测时的现象是
#     A↔C 的 TCP 握手永远收不到 SYN-ACK(ICMP 却通),conntrack 表里一条相关条目都没有,
#     规则计数器经 nft-compat 层还不自增 —— 几乎没有任何线索指向这条规则。
#   - 规则装在 `-i tun -o wan ACCEPT` **之后**:两者都用 `-I FORWARD 1`,后插入的更靠前,
#     于是 ACCEPT 盖在 connlimit 上方,出公网的包第一条就被放行 —— 限流**整条静默失效**,
#     而 `iptables -S` 里两条规则一应俱全,看不出任何异常。
#
# 所以这一组既钉规则的**形状**(有没有 -o wan / -s subnet),也钉它们的**次序**,还要用真流量
# 证明限流真的在拦 —— 三者缺一不可:形状对、次序对,也可能因为 mask 或模块问题根本不生效;
# 而只测行为的话,「限住了」不能区分是 connlimit 干的还是别的什么东西挡的。
#
# **拓扑上的前提**:connlimit 只管 `-i tun0 -o <wan>` 这一段,也就是「客户端经服务器自身
# NAT 出网」。而本套件里 A 固定用 C 当出口,它的公网流量是 tun→tun 直投给 C 的,压根碰不到
# 这条规则(FORWARD 里那条 tun→wan ACCEPT 的计数器长期为 0 就是证据)。所以本组会先把 A 的
# 客户端**去掉 --exit** 重启一次,让它改从服务器出网,测完再原样恢复。不做这一步的话,
# 无论规则在不在、次序对不对,并发都能全成 —— 又一个恒绿的假断言。
#
# 靶子选 C 的 22 端口:C 的 ufw 只放行了 22,而这条路径要求靶子从**服务器的公网侧**可达
# (服务器 SNAT 之后才连过去),所以 8088 那个靶站在这里用不了。sshd 连上后会保持到
# LoginGraceTime,足够把并发攥在手里;并发数压在 7 以内,不去碰 MaxStartups 的 10。
_check_connlimit_caps_concurrency_without_hurting_mesh() {
  local dir="${E2E_REMOTE_DIR:-/tmp/nte2e}" wan dev cidr subnet vip saved limit=3 attempts=7
  wan="$(s "ip route show default | awk '{print \$5; exit}'" | tr -d '[:space:]')"
  # 期望的网段与设备名取自**配置和内核接口**,不从被测规则里反推。
  # 反推是自我实现的断言:规则少了 -s 时,sed 匹配不上就把整行当成「期望网段」,
  # 于是断言比的是「这一行包含它自己」—— 既永远比不出问题,失败信息还是一坨乱码
  # (2026-07-31 反向验证时正是这个形状)。
  dev="$(s "grep -m1 '^device_name' /etc/nanotun/config.toml | sed 's/.*= *//; s/\"//g'" | tr -d '[:space:]')"
  [[ -z "$dev" ]] && dev="tun0"
  cidr="$(s "ip -4 -o addr show $dev 2>/dev/null | awk '{print \$4; exit}'" | tr -d '[:space:]')"
  if [[ -n "$cidr" ]]; then
    subnet="$(s "python3 -c \"import ipaddress;print(ipaddress.ip_interface('$cidr').network)\"" | tr -d '[:space:]')"
  fi
  vip="${E2E_A_VIP4:-}"
  saved="$(s "grep -m1 '^tcp_connlimit_per_ip' /etc/nanotun/config.toml | sed 's/.*= *//'" | tr -d '[:space:]')"
  if [[ -z "$wan" || -z "$subnet" || -z "$vip" || ! "$saved" =~ ^-?[0-9]+$ ]]; then
    env_error "取不到 WAN 网卡 / 客户端网段 / A 的 vIP / 原上限(wan=$wan subnet=$subnet vip=$vip saved=$saved),connlimit 这组测不到"
    return 0
  fi

  # ① 让 A 改从服务器出网(去掉 --exit),否则它的公网流量走 tun→tun,碰不到被测规则。
  if ! _cl_switch_a_to_server_egress; then
    _cl_restore "$saved"
    return 0
  fi

  # ② 收紧上限并重启(这两个键只在启动时落链,SIGHUP 不重建 —— 这一点由 deferred 那组钉着)。
  s "mkdir -p $dir" >/dev/null
  s "cat > $dir/tomlset.py" < "$E2E_ROOT/remote/tomlset.py"
  local out
  out="$(s "python3 $dir/tomlset.py /etc/nanotun/config.toml tun tcp_connlimit_per_ip $limit" 2>&1)"
  if [[ "$out" == *rror* || "$out" == *Traceback* ]]; then
    env_error "改 tcp_connlimit_per_ip 失败:$out"
    _cl_restore "$saved"
    return 0
  fi
  s "systemctl restart nanotun" >/dev/null 2>&1
  if ! wait_until "connlimit · 收紧上限重启后两个客户端重连" 90 both_clients_online; then
    env_error "重启后客户端没能重连,connlimit 这组测不到"
    _cl_restore "$saved"
    return 0
  fi

  # ③ 规则的形状与次序。
  _cl_assert_rule_shape "tcp" "$limit" "$wan" "$subnet"
  _cl_assert_rule_shape "udp" "" "$wan" "$subnet"
  _cl_assert_rule_order "$wan" "$dev"

  # ④ 真流量:并发到上限为止。
  # 先清掉 A 在 conntrack 里的残留 —— 上面那次「确认出口改到服务器」的 curl 会留下条目,
  # 它照样占 connlimit 的名额,不清的话这里会少成一条,而失败长得就像「上限算错了」。
  _cl_flush_conntrack "$vip"
  local got
  got="$(_cl_concurrent_ok "$attempts")"
  check "connlimit · 并发到上限为止(试 ${attempts} 条只成 ${limit} 条)" "$limit" "$got"
  # 计数器是「这条规则有没有被上面的 ACCEPT 盖住」的判据(注释里点名的那个):
  # 盖住时它长期为 0,而规则本身在 iptables -S 里一应俱全。
  local drops
  drops="$(_cl_rule_pkts tcp)"
  if [[ "$drops" =~ ^[0-9]+$ ]] && (( drops > 0 )); then
    _pass "connlimit · 超限的包真的落在这条规则上（计数器 ${drops}，没被上面的 ACCEPT 盖住）"
  else
    _fail "connlimit · 超限的包没有落在这条规则上（计数器 ${drops}）" \
      "规则装在 tun→wan ACCEPT 之后就会这样:限流静默失效,而 iptables -S 看起来一切正常"
  fi

  # ⑤ 超限期间不许误伤 —— 这一条对应第一次事故。
  # 必须**在超限的同时**测:不超限的话 connlimit 根本不参与判决,mesh 当然是通的。
  _cl_assert_no_collateral "$attempts"

  # ⑥ 放开上限后同样的并发全成 —— 证明上面那个 3 是被这个开关卡住的,不是别的什么东西坏了。
  out="$(s "python3 $dir/tomlset.py /etc/nanotun/config.toml tun tcp_connlimit_per_ip $saved" 2>&1)"
  s "systemctl restart nanotun" >/dev/null 2>&1
  if wait_until "connlimit · 放开上限重启后两个客户端重连" 90 both_clients_online; then
    _cl_flush_conntrack "$vip"
    got="$(_cl_concurrent_ok "$attempts")"
    check "connlimit · 上限放回 ${saved} 后同样的并发全部成功" "$attempts" "$got"
  fi

  _cl_restore "$saved"
}

# _cl_switch_a_to_server_egress 把 A 换成「不指定出口」重启,并确认出口真的落到服务器身上。
_cl_switch_a_to_server_egress() {
  if ! client_a_start_no_exit; then
    env_error "A 的连接参数里没有 --exit,无法构造「经服务器出网」的场景,connlimit 这组测不到"
    return 1
  fi
  # 这一条既是前置条件的证明,也是后面所有并发断言的地基:出口没换过来的话,
  # 并发流量走的是 tun→tun,规则在不在都全成 —— 断言会恒绿。
  if ! wait_until "connlimit · A 去掉 --exit 后改从服务器出网（被测路径已就位）" 90 \
       probe_egress_is "$E2E_SRV_HOST"; then
    env_error "A 没能切到服务器出口,connlimit 这组的并发断言全部无效"
    return 1
  fi
  return 0
}

# _cl_assert_rule_shape <proto> <期望上限|""> <wan> <subnet>
# 上限传空表示只看形状不看数值(udp 那条本组不改它的值)。
_cl_assert_rule_shape() {
  local proto="$1" want="$2" wan="$3" subnet="$4" line
  line="$(s "iptables -S FORWARD 2>/dev/null | grep -- '-m connlimit' | grep -- '-p $proto'")"
  if [[ -z "$line" ]]; then
    _fail "connlimit · ${proto} 的并发上限规则不存在" "FORWARD 链里没有 -p $proto 的 connlimit 规则"
    return 0
  fi
  # -o <wan>:第一次事故就是漏了它,后果是把 tun→tun 的 mesh / 子网 / 出口回程一起算进来。
  if [[ "$line" == *" -o $wan"* ]]; then
    _pass "connlimit · ${proto} 规则限定了出网方向（-o ${wan}）"
  else
    _fail "connlimit · ${proto} 规则没限定 -o ${wan}（会把 mesh 与子网一起算进并发）" "$line"
  fi
  # -s <subnet>:少了它,出口回程(源是公网 CDN 的 IP)会按 CDN 源计数,热门站点整站卡死。
  if [[ "$line" == *" -s $subnet"* ]]; then
    _pass "connlimit · ${proto} 规则只按客户端网段计数（-s ${subnet}）"
  else
    _fail "connlimit · ${proto} 规则没限定 -s ${subnet}（回程会按公网源 IP 计数）" "$line"
  fi
  # 按 /32 的源地址计数:换成别的掩码会把整个网段的客户端合并成一个配额,
  # 一个人跑满就把所有人一起卡死。
  if [[ "$line" == *"--connlimit-saddr"* && "$line" == *"--connlimit-mask 32"* ]]; then
    _pass "connlimit · ${proto} 规则按单个客户端 IP 计数（saddr /32）"
  else
    _fail "connlimit · ${proto} 规则不是按 saddr /32 计数（配额会被多个客户端共享）" "$line"
  fi
  if [[ -n "$want" ]]; then
    check_contains "connlimit · ${proto} 规则用的是配置里的上限 ${want}" "--connlimit-above $want" "$line"
  fi
}

# _cl_assert_rule_order 验 connlimit 排在 tun→wan 的 ACCEPT **之前**。
#
# 这是第二次事故的判据,也是本组最容易被改坏又最看不出来的一条:两条规则都用 -I FORWARD 1,
# 谁后插入谁靠前,所以调用顺序一挪,ACCEPT 就盖在 connlimit 上方 —— 限流整条静默失效,
# 而 iptables -S 里两条规则都在。
_cl_assert_rule_order() {
  local wan="$1" dev="$2" nlimit naccept
  nlimit="$(s "iptables -S FORWARD 2>/dev/null | grep -n -- '-m connlimit' | tail -1 | cut -d: -f1" | tr -d '[:space:]')"
  # 必须带 -j ACCEPT:出口私网守卫那条 `-d 169.254.0.0/16 -i <dev> -o <wan> ... -j DROP`
  # 长得几乎一样且排在更前面,不区分的话会拿它当参照,于是次序永远判成「装反了」。
  naccept="$(s "iptables -S FORWARD 2>/dev/null | grep -n -- '-i $dev -o $wan -m comment' | grep -- '-j ACCEPT' | head -1 | cut -d: -f1" | tr -d '[:space:]')"
  if [[ ! "$nlimit" =~ ^[0-9]+$ || ! "$naccept" =~ ^[0-9]+$ ]]; then
    env_error "取不到规则行号(connlimit=$nlimit accept=$naccept),「次序」这条测不到"
    return 0
  fi
  if (( nlimit < naccept )); then
    _pass "connlimit · 规则排在 tun→wan 的 ACCEPT 之前（第 ${nlimit} 条 vs 第 ${naccept} 条）"
  else
    _fail "connlimit · 规则排在 tun→wan 的 ACCEPT 之后（第 ${nlimit} 条 vs 第 ${naccept} 条）" \
      "出公网的包会被 ACCEPT 先放行,限流整条静默失效 —— 而 iptables -S 里两条规则一应俱全"
  fi
}

# _cl_concurrent_ok <条数> → 同时开这么多条 TCP 到 C 的 22 端口,返回握手成功的条数。
#
# 靶子必须从**服务器的公网侧**可达(服务器 SNAT 之后才连过去),C 的 ufw 只放行 22,
# 所以用它而不是 8088 那个靶站。SO_LINGER 0 让关闭时发 RST:conntrack 条目立刻消失,
# 不会给下一次测量留下占着名额的 TIME_WAIT。
_cl_concurrent_ok() {
  local k="$1"
  a "cat > /tmp/nt_conc.py <<'PYEOF'
import socket, struct, sys, time
host, port, k, hold = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4])
socks, ok = [], 0
for _ in range(k):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
    s.settimeout(6)
    try:
        s.connect((host, port)); socks.append(s); ok += 1
    except Exception:
        try: s.close()
        except Exception: pass
print('OK=%d' % ok)
sys.stdout.flush()
time.sleep(hold)
for s in socks:
    try: s.close()
    except Exception: pass
PYEOF
python3 /tmp/nt_conc.py $E2E_C_HOST 22 $k 0" 2>/dev/null | sed -n 's/^OK=//p' | tr -d '[:space:]'
}

# _cl_assert_no_collateral <条数> 在**超限的同时**验 mesh / 子网仍然可用。
# 探针放后台攥住连接,窗口里再打 mesh 与子网 —— 不并行的话 connlimit 根本没参与判决。
_cl_assert_no_collateral() {
  local k="$1" res
  res="$(a "nohup python3 /tmp/nt_conc.py $E2E_C_HOST 22 $k 20 >/tmp/nt_conc.out 2>&1 &
     sleep 6
     timeout 6 bash -c '</dev/tcp/$E2E_C_VIP4/22' >/dev/null 2>&1 && echo meshtcp=ok || echo meshtcp=bad
     ping -c1 -W3 $E2E_C_VIP4 >/dev/null 2>&1 && echo meshping=ok || echo meshping=bad
     ping -c1 -W3 $E2E_C_LAN4_HOST >/dev/null 2>&1 && echo subnet=ok || echo subnet=bad")"
  # 三条分开断言:第一次事故里 ICMP 是通的、只有 TCP 握手收不到 SYN-ACK,
  # 只测 ping 的话那次事故完全测不出来。
  check "connlimit · 超限期间 mesh 的 TCP 仍能握手（没被连坐）" "ok" \
    "$(printf '%s\n' "$res" | sed -n 's/^meshtcp=//p')"
  check "connlimit · 超限期间 mesh 的 ICMP 仍然可达" "ok" \
    "$(printf '%s\n' "$res" | sed -n 's/^meshping=//p')"
  check "connlimit · 超限期间已批准的子网路由仍然可达" "ok" \
    "$(printf '%s\n' "$res" | sed -n 's/^subnet=//p')"
  a "pkill -f nt_conc.py 2>/dev/null; true" >/dev/null
}

# _cl_rule_pkts <proto> → 该 connlimit 规则的丢包计数。
#
# 过滤词是 `#conn` 而不是 `connlimit`:`iptables -vnL` 的详细格式把这个 match 渲染成
# `#conn src/32 > 3`,整行里没有 "connlimit" 三个字(只有 `-S` 的形式里才有)。
# 按 connlimit 过滤会一条都匹配不到,于是计数恒为空 —— 而失败文案会指向「规则被盖住了」,
# 把人引向一个完全不存在的产品缺陷。
_cl_rule_pkts() {
  s "iptables -vnL FORWARD 2>/dev/null | awk '/#conn/ && /^ *[0-9]/ {print \$1, \$4}'" \
    | awk -v p="$1" '$2==p{print $1; exit}' | tr -d '[:space:]'
}

# _cl_flush_conntrack <vip> 清掉该客户端在 conntrack 里的全部条目。
# 已关闭但仍在 TIME_WAIT 的条目照样占 connlimit 的名额,不清的话「恰好等于上限」会随机少一条。
_cl_flush_conntrack() {
  s "conntrack -D -s $1 >/dev/null 2>&1; true" >/dev/null
}

# _cl_restore <原上限> 还原配置与 A 的客户端。
# 顺序:先把配置写回去并重启(A 会跟着重连),再用原始参数把 A 拉回带 --exit 的形态。
_cl_restore() {
  local saved="$1" dir="${E2E_REMOTE_DIR:-/tmp/nte2e}" now
  now="$(s "grep -m1 '^tcp_connlimit_per_ip' /etc/nanotun/config.toml | sed 's/.*= *//'" | tr -d '[:space:]')"
  if [[ "$now" != "$saved" ]]; then
    s "python3 $dir/tomlset.py /etc/nanotun/config.toml tun tcp_connlimit_per_ip $saved" >/dev/null 2>&1
    s "systemctl restart nanotun" >/dev/null 2>&1
  fi
  a "pkill -f nt_conc.py 2>/dev/null; rm -f /tmp/nt_conc.py /tmp/nt_conc.out; true" >/dev/null
  client_a_start
  wait_until "connlimit · 还原后两个客户端都在线" 120 both_clients_online
  # 出口必须回到 C:后面的阶段全都按「A 经 C 出网」写的,漏还原的话它们会一片红,
  # 而红的原因全在这里。
  wait_until "connlimit · 还原后 A 的出口回到 C" 90 probe_egress_is "$E2E_C_HOST"
}

# _check_max_sessions_evicts_the_oldest 验按账号的并发会话上限(两级叠加)。
#
# 这个开关此前 e2e 零命中,而它的三个语义每一个错了都很难被发现:
#   - **超限不拒登**:超了要挤掉老的、放新的进来。写反成「拒绝新登录」,用户换了台设备
#     就再也上不来,而老会话还挂在那儿 —— 报障时看到的是「账号能用但新手机连不上」;
#   - **踢最老**:按 createdAt 升序挑。挑错方向就变成「刚登录的立刻被自己挤掉」,
#     表现为新设备连上一秒又断,循环重连;
#   - **不回踢现役**:上限只在**登录那一刻**判。要是改成 reload 后按新上限回收,
#     运维把上限调小的瞬间会批量踢线 —— 一次配置改动打断所有人。
#
# 三台机只有两个账号(A=testcli、C 另一个),不造第二条同账号会话就完全测不到,
# 所以这里用 mount 命名空间在 A 上起额外的探针会话:复制一份 /etc/nanotun、换掉
# device_id,再在私有挂载命名空间里 bind 回原路径。探针因此有独立身份、独立 tun,
# 而 A 自己的客户端毫发无损。
#
# 淘汰的受害者必然是 A:它是全场最老的一条会话。这不是巧合而是这组的**设计** ——
# 受害者是真客户端,于是「被踢方收到 406 终态关闭」这条能用真实客户端的日志来钉,
# 比读探针日志强得多。代价是收尾要把 A 重新拉起来,这一步已经并入下面的还原。
_check_max_sessions_evicts_the_oldest() {
  local adev="${E2E_A_DEVICE_ID:-1}" u saved a_conn

  saved="$(s "sqlite3 '$E2E_DB_PATH' \"select coalesce(max_sessions,0) from users where username='$E2E_A_USER';\"" | tr -d '[:space:]')"
  if [[ ! "$saved" =~ ^-?[0-9]+$ ]]; then
    env_error "读不到 $E2E_A_USER 的账号级会话上限,max_sessions 这组测不到"
    return 0
  fi
  u="$(_ms_user_json_id "$adev")"
  a_conn="$(conn_id_of_device "$adev")"
  if [[ -z "$u" || -z "$a_conn" ]]; then
    env_error "A 当前不在线,取不到它的账号标识,max_sessions 这组测不到"
    return 0
  fi
  # 计数是这组唯一的观测量,开跑时多一条少一条,后面每一条断言的数字都跟着错位。
  if [[ "$(_ms_count "$u")" != "1" ]]; then
    env_error "开跑时 $E2E_A_USER 名下不是恰好 1 条会话(实际 $(_ms_count "$u")),max_sessions 这组的计数全部无效"
    return 0
  fi
  # 配置里本来就写着这个键的话,收尾时的「删掉这一行」会把参考部署改脏。
  if [[ "$(s "grep -c '^max_sessions_per_user = ' /etc/nanotun/config.toml" | tr -d '[:space:]')" != "0" ]]; then
    env_error "配置里已存在 max_sessions_per_user,本用例会改写它且收尾会删掉整行,先人工确认再跑"
    return 0
  fi

  # ── 一:账号级 -1(不限)下,同账号第二条会话能并存 ──────────────────────────
  # 探针 unit 是瞬时的,但它的 journal 会跨轮留存。下面查「幸存者收没收到 406」必须
  # 只看本次窗口,否则会数到上一轮(尤其是反向验证那轮,探针本就该被踢)的旧记录 ——
  # 2026-07-31 全套里就红在这儿,而产品侧一切正常。时钟取 A 自己的,日志在 A 上。
  local since_a
  since_a="$(a "date +%s" | tr -d '[:space:]')"
  adm "user set-max-sessions $E2E_A_USER -1" >/dev/null
  _ms_probe_start 1
  if ! wait_until "max_sessions · 账号级 -1 时同账号第二条会话登录成功" 90 _ms_count_is "$u" 2; then
    _ms_cleanup 1 "" "" "$saved"
    return 0
  fi
  check "max_sessions · 不限时新登录没有挤掉老会话" "$a_conn" "$(conn_id_of_device "$adev")"

  # ── 二:现役 2 条的情况下把全局上限热更成 1,现役一条都不许被回踢 ───────────
  # 顺序是刻意的:先把会话堆到超限,再改上限。反过来(先改上限再登录)走的是登录那条
  # 判定路径,根本碰不到「回踢」这个问题。
  if ! _ms_reload_global_to 1; then
    _ms_cleanup 1 "" "" "$saved"
    return 0
  fi
  check_contains "max_sessions · 热更日志讲明只对未来登录生效" "现役会话不会被回踢" \
    "$(s "journalctl -u nanotun --since '-60s' --no-pager | grep max_sessions_per_user")"
  sleep 12
  check "max_sessions · 现役会话数超过新上限也不会被回踢" "2" "$(_ms_count "$u")"
  check "max_sessions · 回踢没有发生在 A 身上（还是同一条会话）" "$a_conn" "$(conn_id_of_device "$adev")"

  # ── 三:账号级 -1 压过全局的 1 ────────────────────────────────────────────
  # 全局明写着「限 1」,而这个账号仍然能开到第三条 —— 两级叠加里「账号级优先」的正面证据。
  _ms_probe_start 2
  if ! wait_until "max_sessions · 账号级 -1 压过全局限 1（第三条会话仍能登录）" 90 _ms_count_is "$u" 3; then
    _ms_cleanup 1 2 "" "$saved"
    return 0
  fi

  # ── 四:改回跟随全局,超限时挤掉最老那条 ──────────────────────────────────
  # 全局设 3、现役 3 条,第四条登录时恰好只淘汰 1 条 —— 只淘汰一条才分得清「踢的是谁」。
  # 全局若设 1,四条里死三条,「踢最老」和「踢错人」看起来一模一样。
  adm "user set-max-sessions $E2E_A_USER 0" >/dev/null
  if ! _ms_reload_global_to 3; then
    _ms_cleanup 1 2 "" "$saved"
    return 0
  fi
  # 受害者按 conn_id 认(要钉的就是「这一条连接」没了),幸存者按 device_id 认。
  # 幸存者不能按 conn_id 认:A 被挤掉会带走隧道默认路由,探针的「换网」检测随即触发重连,
  # conn_id 就换了号 —— 按 conn_id 判会把这次重连误报成「幸存者也被连坐」(首轮如此)。
  # 设备这一层不受影响:被挤下线是 406 终态,客户端不会重连,设备也就不会再出现。
  local oldest survivor_a survivor_b
  oldest="$(_ms_sessions "$u" | awk 'NR==1{print $1}')"
  survivor_a="$(_ms_sessions "$u" | awk 'NR==2{print $3}')"
  survivor_b="$(_ms_sessions "$u" | awk 'NR==3{print $3}')"
  if [[ -z "$oldest" || -z "$survivor_b" ]]; then
    env_error "取不到三条会话的先后次序,「踢最老」这条测不到"
    _ms_cleanup 1 2 "" "$saved"
    return 0
  fi
  # 期望里 A 就是最老那条。真不是的话下面的断言仍然成立(它们只认 conn_id 不认身份),
  # 只是 406 那条日志要去别处找 —— 如实记一句,别让读日志的人以为断言写错了。
  [[ "$oldest" != "$a_conn" ]] && note "最老的一条不是 A（${oldest}），406 那条断言改为只看会话消失"

  local since_login
  since_login="$(s "date +%s" | tr -d '[:space:]')"
  _ms_probe_start 3
  # 等的是**新会话真的建立**,不是「总数等于 3」。淘汰在登录之后异步关老连接,而登录
  # 之前的总数本来就是 3 —— 跟淘汰完成后一模一样。拿总数当信号会在「什么都还没发生」
  # 的那一瞬就判定成立,后面每一条断言都跑在这张空快照上(2026-07-30 首跑就是这样:
  # 「被挤掉的正是最老那条」红,而几秒后 A 其实真被挤掉了)。
  # 这一条同时也是「超限不拒登」的证据:新登录被拒的话它永远等不到。
  if ! wait_until "max_sessions · 超限时第四条登录仍然成功（不是拒登）" 90 _ms_conn_since "$u" "$since_login"; then
    _ms_cleanup 1 2 3 "$saved"
    return 0
  fi
  if ! wait_until "max_sessions · 淘汰完成后账号会话数回落到上限 3" 60 _ms_count_is "$u" 3; then
    _ms_cleanup 1 2 3 "$saved"
    return 0
  fi
  # 静默等局面稳定(幸存者可能正因换网在重连),再逐条判定。这里刻意不用 wait_until:
  # 它超时会记一条笼统的红,盖住下面三条各自指名道姓的结论。
  _ms_wait_settle "$u" "$oldest" "$survivor_a" "$survivor_b"

  # 三条断言合起来才把「踢最老」钉死:少了幸存者那两条,「见谁踢谁」也会绿。
  check "max_sessions · 被挤掉的正是最老那条" "no" "$(_ms_has_conn "$u" "$oldest" && echo yes || echo no)"
  check "max_sessions · 次老的那台设备没有被连坐" "yes" "$(_ms_has_device "$u" "$survivor_a" && echo yes || echo no)"
  check "max_sessions · 最新的那台设备没有被连坐" "yes" "$(_ms_has_device "$u" "$survivor_b" && echo yes || echo no)"
  # 上面按设备判「还在线」,这条补上「不是被踢了又回来」:406 是终态、客户端不会重连,
  # 所以幸存者的日志里出现 406 就等于连坐了,哪怕它此刻看起来是在线的。
  check "max_sessions · 两个幸存者都没收到过 406（不是被踢了又重连）" "0" \
    "$(a "journalctl -u nt-p1 -u nt-p2 --since @$since_a --no-pager 2>/dev/null | grep -c 'code=406'" | tr -d '[:space:]')"

  if [[ "$oldest" == "$a_conn" ]]; then
    check_contains "max_sessions · 被挤掉的一方收到 406 终态关闭" "code=406" \
      "$(client_log a "$E2E_A_UNIT" 180)"
    check_contains "max_sessions · 关闭原因讲清是被较新的登录挤下线" "挤下线" \
      "$(client_log a "$E2E_A_UNIT" 180)"
  fi

  _ms_cleanup 1 2 3 "$saved"
}

# _ms_user_json_id <设备> → 控制面 JSON 里该设备所属账号的 user_id(u2 这种展示形式)。
# 按 device_id 反查而不是直接用登录名:JSON 里的 user_id 跟管理命令用的登录名对不上
# (与 conn_rate_down 同一个坑),按名字过滤会永远过滤不到、静默退化成 0 条。
_ms_user_json_id() {
  srv_status_json 2>/dev/null | python3 -c '
import json,sys
dev = int(sys.argv[1])
for s in json.load(sys.stdin).get("sessions", []):
    if s.get("device_id") == dev:
        print(s.get("user_id", ""))
        break
else:
    print("")
' "$1"
}

# _ms_sessions <user_id> → 该账号的在线会话,**按 createdAt 从老到新**,
# 每行「conn_id created_at device_id」。
# 次序由服务端的时间戳定,不靠脚本这边推测谁先谁后:探针带 --auto-reconnect,
# 中途抖一下重连过的话登录次序就跟启动次序不一样了。
_ms_sessions() {
  srv_status_json 2>/dev/null | python3 -c '
import json,sys
u = sys.argv[1]
rows = [s for s in json.load(sys.stdin).get("sessions", []) if s.get("user_id") == u]
rows.sort(key=lambda s: s.get("created_at", 0))
for s in rows:
    print(s.get("conn_id", ""), s.get("created_at", 0), s.get("device_id", 0))
' "$1"
}

_ms_count()      { _ms_sessions "$1" | grep -c .; }
_ms_count_is()   { [[ "$(_ms_count "$1")" == "$2" ]]; }
_ms_has_conn()   { _ms_sessions "$1" | awk '{print $1}' | grep -qx "$2"; }
_ms_has_device() { _ms_sessions "$1" | awk '{print $3}' | grep -qx "$2"; }
# _ms_conn_since <user_id> <时间戳> 该账号有没有一条在这之后建立的会话。
_ms_conn_since() { [[ -n "$(_ms_sessions "$1" | awk -v t="$2" '$2>=t{print $1; exit}')" ]]; }

# _ms_wait_settle <user_id> <受害者 conn> <幸存设备> <幸存设备> 等淘汰的余波过去。
# 不记任何断言:它只是让后面那几条判定跑在一张稳定的快照上。等不到就直接返回,
# 由后面的断言各自给出指名道姓的结论。
_ms_wait_settle() {
  local u="$1" victim="$2" da="$3" db="$4" i
  for i in $(seq 1 60); do
    if [[ "$(_ms_count "$u")" == "3" ]] && ! _ms_has_conn "$u" "$victim" \
       && _ms_has_device "$u" "$da" && _ms_has_device "$u" "$db"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

# _ms_probe_start <n> 在 A 上起一条**同账号**的额外会话。
#
# --no-default-route:不许它抢 A 的默认路由。抢走的话后面所有走隧道的出口断言都会跑偏,
# 而且表现成「出口坏了」这种指向完全错误的假故障。
# --auto-reconnect:探针要扛得住 A 侧路由变动带来的抖动。这不会掩盖「被挤下线」——
# 挤下线是 406 终态,客户端收到就不再重连(这一点本身也由上面的断言钉着)。
_ms_probe_start() {
  local n="$1" profile="${E2E_A_CONNECT_ARGS%% *}"
  a "rm -rf /tmp/nt-p$n && cp -a /etc/nanotun /tmp/nt-p$n \
     && cat /proc/sys/kernel/random/uuid > /tmp/nt-p$n/device_id" >/dev/null
  a "systemctl stop nt-p$n 2>/dev/null
     systemd-run --unit=nt-p$n --collect --setenv=HOME=/root \
       unshare -m --propagation private bash -c \
       'mount --bind /tmp/nt-p$n /etc/nanotun && exec nanotun connect $profile --auto-reconnect --no-default-route --tun-name ntp$n'" >/dev/null 2>&1
}

# _ms_probe_stop <n> 停掉探针并把它在库里建出来的设备行删掉。
# 设备行必须删:收尾快照比对包含 devices,留一行下来整轮会以「状态被改脏」收场。
# 顺序上先读 uuid 再删目录 —— 反过来就再也认不出该删哪一行了。
_ms_probe_stop() {
  local n="$1" uuid id
  uuid="$(a "cat /tmp/nt-p$n/device_id 2>/dev/null" | tr -d '[:space:]')"
  a "systemctl stop nt-p$n 2>/dev/null; rm -rf /tmp/nt-p$n; true" >/dev/null
  [[ -z "$uuid" ]] && return 0
  id="$(s "sqlite3 '$E2E_DB_PATH' \"select id from devices where device_uuid='$uuid';\"" | tr -d '[:space:]')"
  [[ "$id" =~ ^[0-9]+$ ]] && adm_y "device delete $id" >/dev/null 2>&1
  return 0
}

# _ms_reload_global_to <n> 改全局上限并热更,等日志确认新值已生效。
# 不用固定 sleep:reload 是异步的,睡得短了后面的断言测的还是旧值 —— 而且会绿。
_ms_reload_global_to() {
  local want="$1" dir="${E2E_REMOTE_DIR:-/tmp/nte2e}" since out
  since="$(s "date +%s" | tr -d '[:space:]')"
  s "mkdir -p $dir" >/dev/null
  s "cat > $dir/tomlset.py" < "$E2E_ROOT/remote/tomlset.py"
  # 不吞 tomlset 的输出:它静默失败过一次,结果是整组「测了个寂寞」却全绿。
  out="$(s "python3 $dir/tomlset.py /etc/nanotun/config.toml server max_sessions_per_user $want" 2>&1)"
  if [[ "$out" == *rror* || "$out" == *Traceback* ]]; then
    env_error "改 max_sessions_per_user 失败:$out"
    return 1
  fi
  s "systemctl reload nanotun" >/dev/null
  wait_until "max_sessions · 全局上限热更到 ${want}（日志确认已应用）" 30 _ms_reload_logged "$since" "$want"
}

_ms_reload_logged() {
  s "journalctl -u nanotun --since @$1 --no-pager | grep -F 'max_sessions_per_user 已热更'" \
    | grep -q "new=$2"
}

# _ms_cleanup <探针1|""> <探针2|""> <探针3|""> <账号级原值>
# 收尾:停探针 → 删本用例写进配置的那一行 → 还原账号级 → 把 A 拉回来。
# 顺序不能换:探针还在的时候 conn_count 不是 2,「两个客户端在线」永远等不到。
_ms_cleanup() {
  local p1="$1" p2="$2" p3="$3" saved="$4" n
  [[ -n "$p1" ]] && _ms_probe_stop "$p1"
  [[ -n "$p2" ]] && _ms_probe_stop "$p2"
  [[ -n "$p3" ]] && _ms_probe_stop "$p3"

  # 还原用「删行」而不是「写回 0」:两者行为等价,但后者会在参考部署里留下一行本来
  # 没有的配置,下次有人读配置会以为这是刻意设的(与 lease_gc 那组同一个考虑)。
  n="$(s "grep -c '^max_sessions_per_user = ' /etc/nanotun/config.toml" | tr -d '[:space:]')"
  if [[ "$n" == "1" ]]; then
    s "grep -v '^max_sessions_per_user = ' /etc/nanotun/config.toml > /tmp/nte2e-cfg.noms \
       && cat /tmp/nte2e-cfg.noms > /etc/nanotun/config.toml && rm -f /tmp/nte2e-cfg.noms" >/dev/null
    s "systemctl reload nanotun" >/dev/null
  fi
  adm "user set-max-sessions $E2E_A_USER $saved" >/dev/null 2>&1

  # A 多半已经被挤下线了(这正是本组要的),把它按 harness 的原始参数重新拉起来。
  if ! client_active a "$E2E_A_UNIT"; then
    client_a_start
  fi
  wait_until "max_sessions · 收尾后两个客户端都在线" 120 both_clients_online
  # 出口这条是给**后面的阶段**兜底的:A 刚重连,隧道路由要是没回来,后续每一条走隧道的
  # 断言都会红,而红的原因全在这里。宁可在这儿就报出来。
  wait_until "max_sessions · 收尾后 A 的隧道出口恢复" 90 probe_egress_is "$E2E_C_HOST"
}
