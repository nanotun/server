#!/usr/bin/env bash
# 阶段 2:ACL 与三层限速。
#
# 两条主线:
#   ACL —— 规则必须**立即**生效。历史上 acl deny 只写库不通知运行中的 server,
#          表现为「命令说成功了但流量照过」,这是安全策略里最坏的一种失败模式。
#   限速 —— 全局/设备/用户三层取 min。历史上刷新其中一层会用另一层的**登录期
#          快照**去覆盖,把刚设的更严的值悄悄放宽(Bug 11)。所以这里不只验证
#          「设了生效」,更要验证「放宽一层不会复活旧快照」。

_acl_del_all() {
  local ids
  ids="$(adm "acl list --json" 2>/dev/null |
    python3 -c 'import json,sys
try: print(" ".join(str(r["id"]) for r in json.load(sys.stdin)))
except Exception: pass')"
  local id
  for id in $ids; do adm "acl delete $id" >/dev/null; done
}

phase_20_acl_rate() {
  phase_begin "阶段 2 · ACL 与限速"

  local url="http://$E2E_C_VIP4:$E2E_TARGET_PORT/"

  # ── 端口子集语义 ──────────────────────────────────────────────────────────
  # deny 指定端口时,只该掐掉那个端口,其余端口和 ICMP 必须不受影响。
  # 「一条端口规则把整台主机封死」是很常见的实现错误。
  adm "acl deny $E2E_A_USER $E2E_C_USER --port $E2E_TARGET_PORT --proto tcp" >/dev/null
  wait_until "单端口 deny 生效（无需手工 reload）" 20 probe_http_blocked a "$url"
  check "单端口 deny · 其它端口不受影响（22 仍可建连）" "0" \
    "$(probe_tcp a "$E2E_C_VIP4" 22 && echo 0 || echo 1)"
  check "单端口 deny · ICMP 不受影响" "0" \
    "$(probe_ping a "$E2E_C_VIP4" && echo 0 || echo 1)"
  _acl_del_all
  wait_until "删除规则后端口恢复" 20 probe_http_ok a "$url"

  # ── 通配源 + 端口区间 ─────────────────────────────────────────────────────
  adm "acl deny '*' $E2E_C_USER --port-range $((E2E_TARGET_PORT - 8))-$((E2E_TARGET_PORT + 2)) --proto tcp" >/dev/null
  wait_until "通配源 + 端口区间 deny 生效" 20 probe_http_blocked a "$url"
  check "端口区间 deny · 区间外端口不受影响" "0" \
    "$(probe_tcp a "$E2E_C_VIP4" 22 && echo 0 || echo 1)"
  _acl_del_all
  wait_until "删除区间规则后恢复" 20 probe_http_ok a "$url"

  # ── --json 路径也必须通知运行中的 server ──────────────────────────────────
  # 2026-07-28 回归:`acl add/deny --json` 打完 JSON 就 return 了,把「通知 server 重建
  # ACL 快照」连同缺回程告警一起跳过。命令返回一条「已创建」的 JSON、库里也确实有这条
  # 规则,但数据面读的是内存快照,于是流量照过 —— 最坏的一种失败模式:调用方拿到的是成功。
  # 踩这条的只有脚本化配 ACL 的路径(CI / 编排工具),人手敲的不带 --json 一直是好的,
  # 所以上面那几条断言永远发现不了。加这条是因为它只在跨进程这一层可见。
  local jout
  jout="$(adm "acl deny $E2E_A_USER $E2E_C_USER --port $E2E_TARGET_PORT --proto tcp --json 2>/tmp/nte2e-acl.err")"
  # 顺带钉住「告警走 stderr、没污染 stdout」:JSON 解析得动,这半边才算成立。
  # 2026-07-30 统一了键名:add/deny 此前打的是裸 store.ACLPair(Go 风格 Action/DstPortLo),
  # 现在与 acl list --json 同一套 snake_case。这里连端口一起读 —— 端口是这条命令唯一只能
  # 从 JSON 拿到的信息(人类那行是拼好的字符串),键名错了调用方拿到的是 null。
  check "acl deny --json · stdout 是 snake_case 的可解析 JSON" "deny/tcp/$E2E_TARGET_PORT" \
    "$(printf '%s' "$jout" | python3 -c 'import json,sys
try:
    d = json.load(sys.stdin)
    print("%s/%s/%s" % (d.get("action","缺 action"), d.get("proto","缺 proto"), d.get("dst_port_lo","缺 dst_port_lo")))
except Exception as e: print("解析失败: %s" % e)')"
  wait_until "acl deny --json · 规则同样即时生效(无需 reload)" 20 probe_http_blocked a "$url"
  check "acl deny --json · reload 提示走的是 stderr" "0" \
    "$(s "test -s /tmp/nte2e-acl.err" && echo 0 || echo 1)"
  _acl_del_all
  wait_until "删除 --json 规则后端口恢复" 20 probe_http_ok a "$url"

  # ── 三层限速的 min 语义 ───────────────────────────────────────────────────
  # 主要断言看 connection list 里的**有效**限速值而不是实测吞吐:实测受公网
  # 抖动影响,做成硬断言必然 flaky。吞吐另有一条宽松的数量级检查兜底。
  adm "setting rate --down-bps 1000000 --up-bps 1000000" >/dev/null
  wait_until "限速 · 全局默认 1000000 下发到在线会话" 20 rate_is "$E2E_A_DEVICE_ID" 1000000

  adm "device set-rate $E2E_A_DEVICE_ID --down-bps 300000" >/dev/null
  wait_until "限速 · 设备层更严时取设备值（min）" 20 rate_is "$E2E_A_DEVICE_ID" 300000

  adm "user set-bandwidth $E2E_A_USER --down-bps 150000" >/dev/null
  wait_until "限速 · 用户层最严时取用户值（min）" 20 rate_is "$E2E_A_DEVICE_ID" 150000

  # 回归 Bug 11:把设备层放宽到远大于用户层,有效值必须仍是用户层的 150000。
  # 若这里变回 300000 或 5000000,说明刷新时又用上了登录期的陈旧快照。
  # 这里用固定等待而非轮询 —— 要断言的是「一直没变」,轮询会把中途的错误值放过去。
  adm "device set-rate $E2E_A_DEVICE_ID --down-bps 5000000" >/dev/null
  sleep 5
  check "限速 · 放宽设备层不复活旧快照（Bug 11 回归）" "150000" "$(conn_rate_down "$E2E_A_DEVICE_ID")"

  adm "user set-bandwidth $E2E_A_USER --down-bps 0" >/dev/null
  wait_until "限速 · 清空用户层后回落到全局值" 20 rate_is "$E2E_A_DEVICE_ID" 1000000

  # 吞吐只做数量级校验:限到 1MB/s 时不应该跑出远超该值的速度。
  local speed
  speed="$(a "curl -s -o /dev/null -w '%{speed_download}' --max-time 40 'https://speed.cloudflare.com/__down?bytes=4000000'" |
    tr -d '[:space:]' | cut -d. -f1)"
  if [[ -n "$speed" ]] && (( speed > 0 && speed < 1600000 )); then
    _pass "限速 · 实测吞吐与限值同量级（${speed} B/s）"
  else
    _fail "限速 · 实测吞吐异常" "限值 1000000 B/s,实测 ${speed:-空} B/s"
  fi

  # 收尾:恢复不限速。
  adm "device set-rate $E2E_A_DEVICE_ID --down-bps 0" >/dev/null
  adm "setting rate --down-bps 0 --up-bps 0" >/dev/null
  sleep 2

  _check_login_rate_limit_refuses_after_burst
  _check_platform_rate_limit_only_hits_its_own_platform
}

# _check_platform_rate_limit_only_hits_its_own_platform 验 [server].rate_limit_by_platform ——
# 四层限速里的**第 3 层**,上面那组只覆盖了设备 / 全局 / 用户三层。
#
# 这一层与那三层有两处不同,都值得单独钉:
#
#  1. **它在登录期读**(linkRatesForPlatform 只在建限流器时调一次),所以热更后现役会话不受影响。
#     reload 日志明写「仅对未来登录生效」—— 这句声称此前没人验过。若哪天实现改成也回改现役会话,
#     运维照着这句话做的容量规划就全错了(以为改了要等重连,实际立刻生效)。
#  2. **它按 platform 键匹配**。写错成「有任何一个条目就套到所有会话」的话,给 android 配的限速
#     会把 linux 客户端一起限住 —— 表现是「莫名其妙变慢」,而配置文件里明明没写 linux。
#     所以先只给 A **不是**的那个平台配一档,断言 A 不受影响,这是这组的判别器。
#
# 平台名取自客户端登录时上报的 platform 字段(A 的 REALITY 会话报 linux,启动日志里能看到)。
_check_platform_rate_limit_only_hits_its_own_platform() {
  # 进门先清掉可能残留的追加段(上一轮若中途断了会留着)。
  _platform_block_reset

  local baseline
  baseline="$(conn_rate_down "$E2E_A_DEVICE_ID")"
  if [[ ! "$baseline" =~ ^[0-9]+$ ]] || (( baseline <= 300000 )); then
    # 基线必须是个「比待测限值宽松」的数,否则 min 之后看不出平台层有没有生效,
    # 断言会恒绿。取不到或已经很严都属于前置状态不对。
    env_error "取不到 A 的基线限速(或基线已严于待测值):${baseline:-空},平台层限速这组测不到"
    return 0
  fi

  # ── 只给 android 配:linux 的 A 不该有任何变化 ────────────────────────────
  # 刻意**只写 android 一个表**,不给 linux 留一个零值条目 —— 那才是真实部署的形状
  # (运维只写要限的那个平台)。留着零值 linux 条目会让 m[p] 永远命中,于是
  # 「键匹配写错」这一类故障压根走不到,断言看着绿实际上覆盖不到。
  _platform_write_block android 200000
  _sighup_and_wait_platform_reload
  # 正面对照:确认服务端**真的**载入了一个平台条目。少了这条,「追加没成功」
  # 会让下面那条断言恒绿通过 —— 没配限速当然不影响别的平台,什么都没测到。
  if _platform_count_is 1; then
    _pass "平台限速 · 服务端确认载入了 android 这一条（下面那条不是因为没配上才绿的）"
  else
    env_error "服务端载入了 $(_platform_count_now) 个平台条目,期望 1,平台层限速这组测不到"
    _platform_block_reset
    return 0
  fi
  _relogin_a || { _restore_platform_rates; return 0; }
  if [[ "$(conn_rate_down "$E2E_A_DEVICE_ID")" == "$baseline" ]]; then
    _pass "平台限速 · 只给 android 配时不影响 linux 客户端（按平台匹配，不是有条目就套所有人）"
  else
    _fail "平台限速 · 给 android 配的限速套到了 linux 客户端身上" \
      "基线 ${baseline} → 现在 $(conn_rate_down "$E2E_A_DEVICE_ID")"
  fi

  # ── 换成只给 linux 配:先钉「现役会话不受影响」,再钉「下次登录生效」──────
  # 这一档同样只写 linux。若两个都写,android 的 200000 比 linux 的 150000 宽,
  # min 之后仍是 150000 —— 「串平台」的故障会被 min 掩盖掉,断言就分辨不出来了。
  _platform_write_block linux 150000
  _sighup_and_wait_platform_reload
  # 刻意用固定等待而非轮询:要断言的是「一直没变」,轮询会在第一次取样就通过,
  # 把「过几秒才回改现役会话」的实现漏个正着。
  sleep 6
  if [[ "$(conn_rate_down "$E2E_A_DEVICE_ID")" == "$baseline" ]]; then
    _pass "平台限速 · 热更不回改现役会话（与 reload 日志所述「仅对未来登录生效」一致）"
  else
    _fail "平台限速 · 热更把现役会话也改了，与 reload 日志所述矛盾" \
      "基线 ${baseline} → 现在 $(conn_rate_down "$E2E_A_DEVICE_ID")"
  fi

  _relogin_a || { _restore_platform_rates; return 0; }
  wait_until "平台限速 · 重新登录后取到平台层的 150000（参与四层 min）" 25 \
    rate_is "$E2E_A_DEVICE_ID" 150000

  # 吞吐只做**单边**校验:限值以下多慢都算过(公网抖动只会让它更慢),
  # 只有跑出远超限值的速度才说明限流器压根没装上。
  local speed
  speed="$(a "curl -s -o /dev/null -w '%{speed_download}' --max-time 30 'https://speed.cloudflare.com/__down?bytes=1500000'" |
    tr -d '[:space:]' | cut -d. -f1)"
  if [[ "$speed" =~ ^[0-9]+$ ]] && (( speed > 0 && speed < 300000 )); then
    _pass "平台限速 · 实测吞吐不超过限值量级（${speed} B/s，限 150000）"
  elif [[ "$speed" =~ ^[0-9]+$ ]] && (( speed == 0 )); then
    env_error "测速取到 0 B/s(公网不通?),平台层的吞吐校验这条测不到"
  else
    _fail "平台限速 · 实测吞吐远超限值，限流器很可能没装上" "限 150000 B/s,实测 ${speed:-空} B/s"
  fi

  # ── 归零:回到基线 ──────────────────────────────────────────────────────
  _restore_platform_rates
  _relogin_a || return 0
  wait_until "平台限速 · 归零后回到基线 ${baseline}" 25 rate_is "$E2E_A_DEVICE_ID" "$baseline"
}

# 平台限速的配置段用「哨兵行 + 追加到文件末尾」来管:
#
#   - 追加在**末尾**:段头会终止上一个表,末尾是唯一不会改变已有键归属的位置。插在中间会把
#     [server] 后面的键全切进子表里 —— 一个「TOML 仍然合法但语义全变」的改动,自证也拦不住。
#   - 用**哨兵行**界定本用例写的那一段,还原就是「删掉哨兵行到文件末尾」。这样每一档都能精确
#     控制「哪些平台表存在」(真实部署就是只写要限的那个),而还原不依赖任何内容快照 ——
#     快照式还原会把污染一路传给后续跑动(见第 53 轮那次事故)。
#
# 不用 tomlset 改段内 key:那需要段先存在,而「让段一直存在(值置零)」正是上面说的、
# 会让键匹配类故障走不到的那个设计错误。
_platform_block_sentinel='# nte2e-platform-rate-block'

# _platform_block_reset 删掉哨兵行及其后所有内容。幂等,没写过也能安全调用。
# 用 cat 回写而不是 mv:保住原 inode 与权限。
_platform_block_reset() {
  s "awk '/^${_platform_block_sentinel}\$/{exit} {print}' /etc/nanotun/config.toml > /tmp/nte2e-cfg.noblock && cat /tmp/nte2e-cfg.noblock > /etc/nanotun/config.toml" >/dev/null
}

# _platform_write_block <平台> <下行字节/秒> 重写追加段,使其中**只有**这一个平台表。
_platform_write_block() {
  _platform_block_reset
  s "printf '%s\n[server.rate_limit_by_platform.%s]\ndownload_rate = %s\n' '${_platform_block_sentinel}' '$1' '$2' >> /etc/nanotun/config.toml" >/dev/null
}

# _sighup_and_wait_platform_reload 发 SIGHUP 并等到日志确认这一项已热更。
# 不用固定 sleep:reload 是异步的,睡太短会在旧值上判,睡太长白等。
_sighup_and_wait_platform_reload() {
  # 记进全局:platform_count 必须只在**这一次** reload 的日志里找,否则会读到上一档的数,
  # 于是「这次改动没进到进程里」被上一次的成功记录掩盖过去。
  _PLATFORM_RELOAD_SINCE="$(s "date +%s" | tr -d '[:space:]')"
  s "systemctl reload nanotun" >/dev/null 2>&1
  wait_until "平台限速 · SIGHUP 后日志确认 rate_limit_by_platform 已热更" 30 \
    _platform_reload_logged "$_PLATFORM_RELOAD_SINCE"
}

_platform_reload_logged() {
  s "journalctl -u nanotun --since @$1 --no-pager | grep -c 'rate_limit_by_platform 已热更'" \
    | tr -d '[:space:]' | grep -qvE '^0?$'
}

# _platform_count_now 取本次热更日志里的 platform_count(服务端实际载入的平台条目数)。
# 这是唯一能从外面看出「配置到底有没有进到进程里」的数。
_platform_count_now() {
  s "journalctl -u nanotun --since @${_PLATFORM_RELOAD_SINCE:-0} --no-pager | grep 'rate_limit_by_platform 已热更' | tail -1" \
    | sed -nE 's/.*platform_count=([0-9]+).*/\1/p'
}

_platform_count_is() { [[ "$(_platform_count_now)" == "$1" ]]; }

# _relogin_a 踢掉 A 的会话逼它重新登录 —— 平台层只在登录期读,不重连就看不到新值。
# 返回非 0 表示没能造出重新登录(此时调用方该还原配置并放弃这组,而不是在旧会话上判)。
_relogin_a() {
  local cid
  cid="$(_conn_id_of_device_a)"
  if [[ -z "$cid" ]]; then
    env_error "取不到 A 的会话 conn_id,平台层限速这组测不到"
    return 1
  fi
  adm_y "kick session $cid" >/dev/null 2>&1
  if ! wait_until "平台限速 · 踢线后 A 重新登录" 90 _a_relogged "$cid"; then
    env_error "A 踢线后没能重新登录,平台层限速这组测不到"
    return 1
  fi
  return 0
}

# _a_relogged <老 conn_id> A 在线且 conn_id 已经换成新的。
# 只判「在线」会在老会话还没断时就通过,于是后面在老限流器上取值。
_a_relogged() {
  local now
  now="$(_conn_id_of_device_a)"
  [[ -n "$now" && "$now" != "$1" ]]
}

_conn_id_of_device_a() { conn_id_of_device "${E2E_A_DEVICE_ID:-1}"; }

# _restore_platform_rates 删掉追加段并热更,回到「压根没配平台限速」的出厂形状。
_restore_platform_rates() {
  _platform_block_reset
  _sighup_and_wait_platform_reload
}

# _check_login_rate_limit_refuses_after_burst 验 [server].login_rate_limit_per_min 真的拦人。
#
# 这个开关默认是 0(不限制),启用后每 IP 每分钟 N 次、突发固定 3。它此前完全没有实机断言,
# 而它是「被人拿 PSK 暴破」时运维会去敲的第一个开关 —— 敲完没生效跟没有这个开关一样危险。
#
# 难点在于**怎么造出登录尝试**:限速这道闸排在 PoW **之后**(server.go 里 PoW 校验通过才
# 走 AllowLogin),所以尝试必须先解完 PoW 才会被计数,拿 curl / nc 打是打不进去的。办法是用
# 客户端自己发:导出一份不含凭据的节点链接(profile show --format url),再配一份**用户名不
# 存在**的假凭据。这样每次尝试都会正常解 PoW、消耗一个令牌,然后倒在鉴权上。
#
# 几处刻意的选择:
#   - 不复用 A 上保存的那份凭据。传错的 --cred 去连已保存的连接有把它覆盖掉的风险,而 A 的
#     凭据一坏,整个 e2e 环境就再也起不来 —— 代价远超这条用例的价值。假凭据完全不碰它。
#   - --no-default-route + 独立 tun-name。登录失败本来走不到建 TUN 那步,但万一走到了,默认
#     行为是**接管默认路由** —— 那会当场打断 SSH 与 A 的真实隧道。
#   - 串行而不是并发。客户端即使连接失败也会存/恢复 resolv.conf(输出里那行「已恢复原始 DNS」),
#     并发跑会互相踩,而 A 的 DNS 是后续阶段的前提。串行代价是每次 ~7 秒,但令牌消耗速率
#     (~8/min)远高于回填速率(1/min),照样能很快打空。
#
# 断言的形状比「出现 429」更要紧:
#   - 前三次必须是 401 —— 突发额度就是 3。若实现把 burst 当成 0,测试同样能看到 429,但那是
#     另一种缺陷(正常用户重按一次登录就被拒),不该被当成这条通过;
#   - 关掉限速后同样的尝试必须**立刻**回到 401。此时桶还是空的,所以这条是真正的判别器:
#     429 若来自别的原因(比如某处把所有登录都拒了),改配置不会让它消失。
_check_login_rate_limit_refuses_after_burst() {
  local node cred out
  node="$(adm "profile show $E2E_A_USER --dial-host $E2E_SRV_HOST --config /etc/nanotun/config.toml --format url" 2>/dev/null | tail -1 | tr -d '[:space:]')"
  # profile show 是产品表面,给不出链接算缺陷;造假凭据是本地脚手架(要 python3),归 ENV。
  if [[ "$node" != nanotun://* ]]; then
    _fail "登录限速 · profile show 应给出 nanotun:// 节点链接" "$node"
    return
  fi
  cred="$(_bogus_cred_link)"
  if [[ "$cred" != nanotun-cred://* ]]; then
    env_error "造不出假凭据(本机 python3?),登录限速这组断言测不到:$cred"
    return
  fi

  local dir="${E2E_REMOTE_DIR:-/tmp/nte2e}"
  s "mkdir -p $dir" >/dev/null
  s "cat > $dir/tomlset.py" < "$E2E_ROOT/remote/tomlset.py"

  # 进来时必须是关闭状态。这条不是形式主义:2026-07-30 我在这个函数的**失败分支**里让一个裸
  # 变量引用紧跟了一个全角右括号(首字节被 bash 并进变量名),set -u 下当场中断,还原因此没跑,
  # 限速被留在开启状态。
  # 而当时的还原写法是「进函数时把 config 备份、出函数时拷回去」—— 于是污染变成粘性的:
  # 之后每一轮都把这份脏状态备份下来、又忠实地还原回去,连着三轮的红都指着错方向。
  #
  # 所以这里改成两条规矩:
  #   - 还原回**已知的安全默认值**(0),不回「进来时的样子」;
  #   - 进来时若不是 0,说成 ENV 并停下 —— 那说明上一轮留了脏状态,继续跑只会得到不可信的红。
  local cur
  cur="$(s "grep -E '^[[:space:]]*login_rate_limit_per_min' /etc/nanotun/config.toml | tail -1 | tr -d ' '" | tr -d '[:space:]')"
  if [[ -n "$cur" && "$cur" != "login_rate_limit_per_min=0" ]]; then
    env_error "开跑前 login_rate_limit_per_min 不是 0($cur)—— 上一轮留下了脏状态,先手工归零再跑,否则这组断言不可信"
    return
  fi

  _apply_login_rate_limit 1 || { _restore_login_rl; return; }

  out="$(_login_attempts 6 "$node" "$cred")"
  local n1 n2 n3 later
  n1="$(_attempt_code "$out" 1)"; n2="$(_attempt_code "$out" 2)"; n3="$(_attempt_code "$out" 3)"
  later="$(echo "$out" | sed -n '4,6p')"

  if [[ "$n1" == 401 && "$n2" == 401 && "$n3" == 401 ]]; then
    _pass "登录限速 · 突发额度内的三次仍走到鉴权（401，不是一刀切全拒）"
  else
    _fail "登录限速 · 突发额度内的三次应为 401" "实测 $n1/$n2/$n3;全部输出:$out"
  fi

  if echo "$later" | grep -q "429"; then
    _pass "登录限速 · 突发用尽后被拒（429）"
  else
    _fail "登录限速 · 突发用尽后应返回 429" "$out"
  fi

  # 审计必须记下来,否则运维事后没法按 IP 关联到暴破行为(429 只回给了攻击者)。
  local audit
  audit="$(adm "audit list --limit 10")"
  if echo "$audit" | grep "login.fail.ratelimit" | grep -q "$E2E_A_HOST"; then
    _pass "登录限速 · 审计记下 login.fail.ratelimit 且 actor 是尝试方真实 IP"
  else
    _fail "登录限速 · 审计缺 login.fail.ratelimit（或 actor 不是 ${E2E_A_HOST}）" "$audit"
  fi

  # 关掉限速:桶仍是空的,所以「立刻回到 401」证明 429 来自这个配置项本身。
  _apply_login_rate_limit 0 || { _restore_login_rl; return; }
  out="$(_login_attempts 2 "$node" "$cred")"
  if [[ "$(_attempt_code "$out" 1)" == 401 && "$(_attempt_code "$out" 2)" == 401 ]]; then
    _pass "登录限速 · 关掉后立刻回到 401（桶未回填，说明 429 确由该配置产生）"
  else
    _fail "登录限速 · 关掉后应立刻回到 401" "$out"
  fi

  # 真实会话全程不该被这些尝试影响 —— 限速是 per-IP 的,而 A 的真实会话与尝试同源 IP。
  check "登录限速 · 期间 A 的真实会话未掉线" "0" \
    "$(probe_egress_is "$E2E_C_HOST" && echo 0 || echo 1)"

  _restore_login_rl
}

# _apply_login_rate_limit 把 login_rate_limit_per_min 改成 $1 并**等到它真的生效**。
#
# 不用 sleep 猜:reload 里 SetRatePerMin 调用完才打那行「已热更」日志,所以看见日志就说明新
# 速率已经在 AllowLogin 的观测范围内了。2026-07-30 全套里红过一次正是因为原先写的 `sleep 2`
# ——单跑阶段 2 够用,全套里第一发仍撞在旧速率上,于是「关掉后回到 401」拿到 429 变红,
# 而红的方向指着产品,真因是脚手架在猜时间。
_apply_login_rate_limit() {
  local want="$1" since
  local dir="${E2E_REMOTE_DIR:-/tmp/nte2e}"
  since="$(s 'date +%s' | tr -d '[:space:]')"
  if ! s "python3 $dir/tomlset.py /etc/nanotun/config.toml server login_rate_limit_per_min $want && systemctl reload nanotun" >/dev/null; then
    env_error "改写/热加载 login_rate_limit_per_min=$want 失败,这组断言测不到"
    return 1
  fi
  wait_until "登录限速 · SIGHUP 已生效（login_rate_limit_per_min=${want}）" 20 \
    _login_rl_log_shows "$since" "$want"
}

# _login_rl_log_shows 判「本次 SIGHUP 之后确实打出了切到 $2 的那行热更日志」。
_login_rl_log_shows() {
  s "journalctl -u nanotun --since @$1 --no-pager" \
    | grep "server.login_rate_limit_per_min 已热更" | grep -q "new=$2"
}

# _restore_login_rl 把限速归零。
#
# 刻意**不**从快照拷回,而是显式写 0:快照式还原会把上一轮留下的脏状态一路传下去(见上面
# 那段注释里的实例)。写死安全默认值则无论进来时是什么样,出去时都是关闭的。
#
# 无条件 reload 而不是「值已经是 0 就省掉」:中途任何一步失败都会走到这里,那时运行中的值
# 可能还是 1 —— 限速留在开启状态会把后续阶段客户端的重连一并拦下,把一条本地失败放大成
# 后面十几条方向错误的红。
_restore_login_rl() {
  local dir="${E2E_REMOTE_DIR:-/tmp/nte2e}"
  s "python3 $dir/tomlset.py /etc/nanotun/config.toml server login_rate_limit_per_min 0 && systemctl reload nanotun" >/dev/null 2>&1 || true
}

# _bogus_cred_link 造一份「用户名不存在」的 nanotun-cred:// 链接。
# schema 见 util/credentials_url.go(base64url 去 padding,字段顺序不敏感)。
_bogus_cred_link() {
  python3 - <<'PY'
import base64, json, time, uuid
c = {
    "version": 1,
    "id": str(uuid.uuid4()),
    "username": "nte2e-nobody-ratelimit",
    "psk": "0" * 32,
    "created_at": int(time.time()),
    "host": "",
    "server_id": "",
}
print("nanotun-cred://v1?d=" + base64.urlsafe_b64encode(json.dumps(c).encode()).decode().rstrip("="))
PY
}

# _login_attempts 在 A 上串行发 N 次一次性登录尝试,每行输出 "<序号> <code=...>"。
_login_attempts() {
  local n="$1" node="$2" cred="$3"
  a "for i in \$(seq 1 $n); do
       code=\$(timeout 40 nanotun connect '$node' --cred '$cred' --transport reality \
                 --no-default-route --tun-name nte2erl0 2>&1 | grep -oE 'code=[0-9]+' | tail -1)
       echo \"\$i \${code:-code=none}\"
     done"
}

# _attempt_code 取第 n 次尝试的数字码。
_attempt_code() {
  echo "$1" | awk -v n="$2" '$1==n{sub(/^code=/,"",$2); print $2; exit}'
}
