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

  # 同一件事必须在 **C** 上再钉一遍。A 是全隧道、C 带 --no-default-route 走组网(mesh-only),
  # 两者的客户端 DNS 接管是**两段不同的代码**:全隧道会改写全局 DNS,组网只给 systemd-resolved
  # 下 per-link split-DNS —— 后者仅当 resolved 真在解析链上才对应用生效。而 Vultr/Ubuntu-cloud
  # 这类镜像 resolved 在跑却没接进链(nsswitch=files dns、resolv.conf 直写公网 DNS),于是网关
  # 答得好好的、应用却解析不到,正是本节开头那句「网关能解析但应用解析不了」。
  #
  # 2026-08-10 在 C 上实测就是这个状态(getent 空、dig @10.201.0.1 同名字正常返回),而当时整轮
  # 门禁全绿 —— 因为这条断言只在 A 上做过,组网那条分支从来没人验。故这里补 C 侧同款。
  # 用 ahostsv4 而不是 hosts:强制走 v4 得到确定值,可以直接对 A 的 vIP4,不必像 A 侧那样
  # 因 v4/v6 返回顺序不定而只能松散地断言「像个 IP」。
  local via_resolver_c
  via_resolver_c="$(c "getent ahostsv4 $a_name" | head -1 | awk '{print $1}' | tr -d '[:space:]')"
  if [ "$via_resolver_c" = "$E2E_A_VIP4" ]; then
    _pass "MagicDNS · 组网(mesh-only)下经系统解析器可解析"
  elif [ -z "$via_resolver_c" ]; then
    _fail "MagicDNS · 组网(mesh-only)下经系统解析器可解析" \
      "C 上 getent 解析不到 $a_name(但 dig @10.201.0.1 正常)—— 组网分支的 DNS 接管没对应用生效;常见成因是该主机 systemd-resolved 不在解析链上、而客户端版本尚无 resolv.conf 兜底(blackhorse-windows 的 11425ea)"
  else
    _fail "MagicDNS · 组网(mesh-only)下经系统解析器可解析" \
      "期望 A 的 vIP4 $E2E_A_VIP4,实测 [$via_resolver_c]"
  fi

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
  _check_exit_mode_off_shuts_the_door_to_wan_only
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
  if echo "$log" | grep -qF "[egress] exit_mode=isolate"; then
    _pass "isolate · 拒绝经 peer 出口时日志点明是 isolate（客户端侧只显示「出口已离线」）"
  else
    _fail "isolate · 应有「exit_mode=isolate 禁止客户端互通」的拒绝日志" "$log"
  fi

  # 启动期那条 WARN 是运维唯一的线索:库里的 approved 记录在 isolate 下是哑弹,列表上却照样显示已批准。
  if echo "$log" | grep -qF "[isolate] exit_mode=isolate"; then
    _pass "isolate · 启动期就警告「已批准的出口/子网在本模式下不承载流量」（否则审批看着有效实则失效）"
  else
    _fail "isolate · 启动期应警告库里已批准的中转类审批在本模式下失效" "$log"
  fi
  # 顺带钉住计数的去重:C 同时批了 0.0.0.0/0 与 ::/0,这是**一台**出口设备而不是两条。
  # 按条计会让运维以为自己有两台出口机 —— 一个只在双栈都批过时才暴露的差一错。
  # 不拿「WARN 存在」当前置条件:那样一旦 WARN 整条消失,这句会静默不执行 ——
  # 消失的断言比红的断言危险,它在汇总里看不见。
  check_contains "isolate · 提醒里出口设备按机器去重（C 的 v4+v6 两条 = 1 台）" "exit_devices=1" \
    "$(echo "$log" | grep -F "[isolate] exit_mode=isolate" || echo "(日志里没有这条提醒)")"

  # 还原:写死 mesh 而不是拷快照 —— 快照式还原会把上一轮留下的脏状态一路传下去(见阶段 2 的教训)。
  _restore_exit_mode_mesh
  wait_until "isolate · 还原 mesh 后两个客户端重连" 90 both_clients_online
  wait_until "isolate · 还原后 A→C mesh 恢复"      30 probe_ping a "$E2E_C_VIP4"
  wait_until "isolate · 还原后经出口 C 出网恢复"    60 probe_egress_is "$E2E_C_HOST"
  wait_until "isolate · 还原后子网恢复"            30 probe_ping a "$E2E_C_LAN4_HOST"
}

# _check_exit_mode_off_shuts_the_door_to_wan_only 验 [tun] exit_mode = "off" ——
# 三档里最后一档,此前从没测过(isolate 与 mesh 都有用例)。
#
# off 是个**容纳性保证**:纯组网部署(合规、计费、防滥用)靠它承诺「没有流量经本机出公网」。
# 这类保证坏掉的样子和别的缺陷不一样 —— 不报错、不断连,流量照样出得去,一切看起来都正常,
# 直到某天有人去查账单或出口日志。所以这一组的重心是「真的出不去」,而不是「规则装上了」。
#
# **拓扑上先要造出被测路径**:off 掐的是服务器自身的 `-i tun -o wan`,而默认 A 拿 C 当出口,
# 公网流量是 tun→tun 直投给 C 的,压根不碰那条规则。不先把 A 切成「不指定出口」的话,
# 无论 off 有没有生效,A 都照样从 C 出网 —— 断言恒绿(与 connlimit 那组同一个坑)。
#
# **判别器是 mesh 与子网仍通**。off 的定义就是「只掐出网、不掐互访」,没有这两条就无法区分:
#   - off 按设计只掐 tun→wan(正确);
#   - 规则装错把整个数据面打死(缺陷)。
# 两者在「出不去了」这一条上表现完全一样。
#
# 还钉一条**容易被误读的语义**:off 只关「经本机 WAN 出网」,不关「经 peer 中转出网」。
# A 带 --exit 时仍能从 C 出去,因为那条路是 tun→tun 转发 + C 自己的 WAN。选 off 的运维
# 若以为「没人能上网了」会判断失误 —— 这条断言把真实语义固定下来。
#
# 最后钉**切换路径上的残留**:上一轮 mesh 装的 tun→wan ACCEPT 与 SNAT 必须消失。
#
# 这一段刻意用 `SIGKILL + systemd 拉起` 而不是 `systemctl restart` 来切档,理由是第一次
# 写这组时踩的坑:优雅退出会在 defer 里 teardown 掉全部 nanotun_main 规则,于是新进程启动时
# **压根不存在残留** —— 两条「残留已清掉」的断言恒绿,而绿的原因跟清理逻辑毫无关系
# (禁掉启动期 sweep 做变异,14 条一条都没红,就是这么发现的)。硬杀才留得下残留,而
# 「在 mesh 档崩了、运维改成 off 再拉起来」本身就是个真实场景。
#
# 残留的危害是**可审计性**而不是直接泄漏:新装的 DROP 用 `-I FORWARD 1` 排在链首,残留的
# ACCEPT 在它后面,包先命中 DROP。但链上同时挂着一条 ACCEPT 和一条相反的 DROP,排查的人
# 极易据此判断「出网是开着的」;而一旦将来插入位置变了,它就会从误导变成真泄漏。
_check_exit_mode_off_shuts_the_door_to_wan_only() {
  local dir="${E2E_REMOTE_DIR:-/tmp/nte2e}" wan since log
  s "mkdir -p $dir" >/dev/null
  s "cat > $dir/tomlset.py" < "$E2E_ROOT/remote/tomlset.py"
  wan="$(s "ip route show default | awk '{print \$5; exit}'" | tr -d '[:space:]')"
  if [[ -z "$wan" ]]; then
    env_error "查不到服务器的出网网卡,off 这组测不到"
    return
  fi

  # 先把 A 切成「不指定出口」,并确认它此刻**确实**从服务器出网。
  # 这一条同时是前置条件的证明:mesh 档下都出不去的话,off 档「出不去」就什么也证明不了。
  if ! client_a_start_no_exit; then
    env_error "A 的连接参数里没有 --exit,构造不出「经服务器出网」的场景,off 这组测不到"
    return
  fi
  if ! wait_until "off · 前置:mesh 档下 A 经服务器出网是通的（判别器成立）" 90 \
       probe_egress_is "$E2E_SRV_HOST"; then
    env_error "mesh 档下 A 就没能从服务器出网,off 这组的「出不去」证明不了任何事"
    client_a_start
    return
  fi

  # 切档:先写配置,再 SIGKILL 让 systemd 拉起 —— 硬杀不走 defer 里的 teardown,
  # 于是 mesh 那套规则原样留在内核里,下面「残留已清掉」两条才有东西可测。
  # 顺带确认残留**确实**产生了,否则那两条又会退化成恒绿的装饰品。
  local since residue
  since="$(s 'date +%s' | tr -d '[:space:]')"
  if ! s "python3 $dir/tomlset.py /etc/nanotun/config.toml tun exit_mode '\"off\"'" >/dev/null; then
    _restore_exit_mode_mesh
    client_a_start
    env_error "切 exit_mode=off 失败,这组断言测不到"
    return
  fi
  residue="$(s "pkill -KILL -x nanotund; sleep 0.5; iptables-save 2>/dev/null | grep -c 'nanotun_main.*ACCEPT'" | tr -d '[:space:]')"
  if [[ ! "$residue" =~ ^[0-9]+$ ]] || (( residue == 0 )); then
    env_error "硬杀之后内核里没留下 mesh 的 ACCEPT 残留(residue=$residue),「残留已清掉」两条测不到"
  fi
  wait_until "off · 硬杀切档后 systemd 拉起、两个客户端重连" 120 both_clients_online

  # ① 真流量:经服务器出网被封死。这一条是这一档的全部意义。
  wait_until "off · A 经服务器出网被封死（容纳性保证成立）" 40 probe_egress_blocked

  # ② 判别器:掐的只是出网,不是整个数据面。
  wait_until "off · mesh 互访仍然可用（off 的定义就是只掐出网）" 30 probe_ping a "$E2E_C_VIP4"
  wait_until "off · 已批准的子网路由仍然可达"                    30 probe_ping a "$E2E_C_LAN4_HOST"

  # ③ 规则形状:显式 DROP 必须在(很多发行版 -P FORWARD ACCEPT,不显式 DROP 就直接漏出去)。
  local fwd
  fwd="$(s "iptables -S FORWARD 2>/dev/null")"
  # 整行锚定,不用子串:出口私网守卫那条是 `-d 169.254.0.0/16 -i tun0 -o <wan> ... -j DROP`,
  # 子串 `-i tun0 -o <wan> ... -j DROP` 在它身上照样成立 —— 于是 off 档一条 DROP 都没装时
  # 这句仍然是绿的(2026-07-31 用「off 退化成 mesh」的变异抓到的假绿)。off 装的那条不带
  # 任何 -s/-d 限定,所以锚在 `-A FORWARD ` 之后就能把守卫类规则排除干净。
  if printf '%s' "$fwd" | grep -qx -- "-A FORWARD -i tun0 -o $wan -m comment --comment nanotun_main -j DROP"; then
    _pass "off · FORWARD 上有显式的 tun→wan DROP（默认 ACCEPT 的发行版也不会漏出去）"
  else
    _fail "off · FORWARD 上没有无限定的 tun→wan DROP" "$fwd"
  fi
  # ④ 残留:mesh 留下的 ACCEPT 与 SNAT 必须已经消失。
  # 这两条针对的是**切换路径**而不是冷启动 —— 前一轮是 mesh,链上本来就挂着它们。
  if printf '%s' "$fwd" | grep -q -- "-i tun0 -o $wan -m comment.*-j ACCEPT"; then
    _fail "off · 链上还留着上一条命 mesh 装的 tun→wan ACCEPT" \
      "一条 ACCEPT 和一条相反的 DROP 同时挂着,排查的人会据此判断「出网是开着的」"
  else
    _pass "off · 硬杀留下的 mesh tun→wan ACCEPT 已被清掉"
  fi
  local snat
  snat="$(s "iptables -t nat -S POSTROUTING 2>/dev/null | grep -- '-j SNAT' | grep 'nanotun_main' || true")"
  if [[ -z "$snat" ]]; then
    _pass "off · 硬杀留下的客户端网段 SNAT 已被清掉"
  else
    # off 分支自己只删 ACCEPT、不删 SNAT,这一条全靠启动期 sweep 兜底 ——
    # sweep 哪天改成只扫 filter 表,这里就是唯一的哨兵。
    _fail "off · 客户端网段的 SNAT 仍挂在 nat 表上（off 分支不删它，只有启动期 sweep 会清）" "$snat"
  fi

  # ⑤ 启动日志要说清现在是 off,否则运维只能靠猜。
  # 匹配的是 off 分支**独有**的那句话,不是 `exit_mode=off` 这个字段。
  # 后者是结构化日志里原样回显的配置值,策略生没生效它都会打 —— 拿它当判据的话,
  # 「配置写了 off 但根本没按 off 装规则」会一路绿灯(同上,变异抓到的假绿)。
  log="$(s "journalctl -u nanotun --since @$since --no-pager")"
  check_contains "off · 启动日志点明已 DROP tun→WAN（运维据此确认档位真的生效）" \
    "已 DROP FORWARD device->WAN" \
    "$(printf '%s' "$log" | grep 'DROP FORWARD device->WAN' | head -1 || echo '(日志里没有这一句)')"

  # ⑥ 语义:off 只关「经本机 WAN 出网」,经 peer 中转仍然可用。
  # 这条容易被误读成「off = 没人能上网」,写死在断言里免得日后按错误的理解去改。
  client_a_start
  wait_until "off · 经 peer 出口中转仍然可用（off 只关本机 WAN，不关中转）" 90 \
    probe_egress_is "$E2E_C_HOST"

  # ⑦ 还原并确认闸门是可逆的:回 mesh 之后经服务器出网必须重新通。
  # 只还原不验的话,「off 把某样东西永久改坏了」会留到后面的阶段才炸,且指向完全错误。
  _restore_exit_mode_mesh
  wait_until "off · 还原 mesh 后两个客户端重连" 90 both_clients_online
  if client_a_start_no_exit; then
    wait_until "off · 还原后经服务器出网恢复（闸门可逆）" 90 probe_egress_is "$E2E_SRV_HOST"
  fi
  client_a_start
  wait_until "off · 收尾:A 的出口回到 C" 90 probe_egress_is "$E2E_C_HOST"
  wait_until "off · 收尾:子网仍然可达"    30 probe_ping a "$E2E_C_LAN4_HOST"
}

# _restore_exit_mode_mesh 把 exit_mode 写回 mesh 并重启(不可热更)。
_restore_exit_mode_mesh() {
  local dir="${E2E_REMOTE_DIR:-/tmp/nte2e}"
  s "python3 $dir/tomlset.py /etc/nanotun/config.toml tun exit_mode '\"mesh\"' && systemctl restart nanotun" >/dev/null 2>&1 || true
}
