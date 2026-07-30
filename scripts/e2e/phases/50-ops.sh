#!/usr/bin/env bash
# 阶段 5:备份 / 还原守卫 / 配置热加载 / 踢线。
#
# 这里有一条刻意保留为「只测守卫、不做真还原」的边界:restore 会覆盖实时库,
# 在共用环境上跑真还原风险太高。真正的「停服→还原→启动→校验」演练请用
# --with-restore-drill 显式开启,并且只在可以随便重置的环境上跑。

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

  local out
  out="$(adm_y "restore $junk" 2>&1)"

  # 先把服务拉回来,再做断言 —— 断言失败会 return,不能让服务停在那儿。
  s "systemctl start nanotun" >/dev/null

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

  if [[ "$(a "test -f /tmp/probe-cert.pem && echo yes" | tr -d '[:space:]')" == "yes" ]]; then
    return 0
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
  if s "command -v ipset >/dev/null 2>&1 || ls /sbin/ipset /usr/sbin/ipset >/dev/null 2>&1" >/dev/null 2>&1; then
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
  # 按 vIP 认连接,不按用户名:审计的 target 是 userID(u2/u4),而 E2E_*_USER 有的是用户名,
  # 两者对不上。vIP 在 env 里是确定的,且和 connection list 同一行还能取到 userID。
  _attribution_case "$E2E_C_VIP4" "$E2E_C_HOST" "hy2"
  _attribution_case "$E2E_A_VIP4" "$E2E_A_HOST" "REALITY"
}

_attribution_case() {
  local vip="$1" host="$2" label="$3"
  local row cid user since actor ip

  row="$(adm "connection list" | awk -v v="$vip" '$3 ~ v {print $1, $2; exit}')"
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
  _check_udp_relay_stays_disabled

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

  # 放在最后:它要重启 nanotund 并等两个客户端重连,后面不该再挂别的断言。
  _check_jump_host_firewall_fails_closed_without_ipset

  s "rm -f $bk /tmp/nte2e-junk.db /tmp/nte2e-cfg.good" >/dev/null
}

_kick_log_has_902() { client_log c "$E2E_C_UNIT" 60 | grep -q "code=902"; }
