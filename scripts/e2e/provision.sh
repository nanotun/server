#!/usr/bin/env bash
# 三机 e2e 实验室重建 —— 把三台空机器（或被搞坏的机器）恢复成 run.sh 能跑的状态。
#
#   ./scripts/e2e/provision.sh              重建并把新身份回填进 e2e.env
#   ./scripts/e2e/provision.sh --dry-run    只报告差距,不改任何东西
#   ./scripts/e2e/provision.sh --no-backfill  改机器但不动 e2e.env
#
# 为什么需要这个脚本
# ------------------
# run.sh 假定环境是**预置好**的:它只连不建。而预置过程此前只存在于人的记忆里,
# e2e.env 里那些写死的 device_id / UUID / vIP 是当初手工搭完之后抄下来的结果。
#
# 2026-08-03 踩到代价:在 SRV 上跑了一遍全新安装,服务端身份(server_id + REALITY
# 密钥对)和数据库被一起换掉。两台客户端于是全部报
# `REALITY: leaf certificate verification failed` —— 它们 profile 里钉的是旧公钥。
# 基线阶段第一条就红,而红的样子（"两个客户端会话在线 45s 内未成立"）跟真因
# （服务端换了身份）之间没有任何提示关系。恢复时才发现:没有任何脚本知道这套环境
# 是怎么搭起来的。
#
# 所以这个脚本的职责不是「跑测试」,而是**让实验室不再是手搭的孤本**。
#
# 幂等:每一步先探再改,重复跑安全。已经对的不动,不重置已有用户的 PSK ——
# 除非 --rotate-psk（客户端连不上、怀疑凭据不同步时用）。
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/env.sh
source "$HERE/lib/env.sh"

DRY=0; BACKFILL=1; ROTATE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run)     DRY=1; shift ;;
    --no-backfill) BACKFILL=0; shift ;;
    --rotate-psk)  ROTATE=1; shift ;;
    -h|--help)     sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "未知参数: $1" >&2; exit 2 ;;
  esac
done

if [ -t 1 ]; then
  _B=$'\033[1;36m'; _G=$'\033[1;32m'; _Y=$'\033[1;33m'; _R=$'\033[1;31m'; _D=$'\033[2m'; _N=$'\033[0m'
else
  _B=''; _G=''; _Y=''; _R=''; _D=''; _N=''
fi

step() { printf '\n%s══ %s%s\n' "$_B" "$*" "$_N"; }
ok()   { printf '   %s✓%s %s\n' "$_G" "$_N" "$*"; }
chg()  { printf '   %s+%s %s\n' "$_Y" "$_N" "$*"; }
warn() { printf '   %s!%s %s\n' "$_Y" "$_N" "$*"; }
die()  { printf '\n%sFATAL: %s%s\n' "$_R" "$*" "$_N" >&2; exit 1; }
note() { printf '     %s%s%s\n' "$_D" "$*" "$_N"; }

# would <描述> —— dry-run 下只报告不执行。返回 0 表示「该执行」。
would() {
  if [ "$DRY" = 1 ]; then chg "[dry-run] $1"; return 1; fi
  chg "$1"; return 0
}

e2e_load_env || exit 2
e2e_ssh_init
trap 'e2e_ssh_cleanup' EXIT INT TERM

TMP="$(mktemp -d)"
trap 'e2e_ssh_cleanup; rm -rf "$TMP"' EXIT INT TERM

# ── 0. 三台机器可达 ─────────────────────────────────────────────────────────
step "0. 连通性与前置工具"
e2e_ssh_warmup || die "三台机器没有全部就绪,先解决 SSH 再重建。"
ok "SRV / A / C 均可达"

# Web 后台端口和 MagicDNS 后缀都取自服务端配置,别猜 —— 连上了就直接问。
#
# 这两句 run.sh 里也有,但**本脚本必须自己调一遍**:它是独立入口,而且是「刚重建完实验室」
# 时先跑的那个 —— 正是端口随机、后缀已从 lan 变成 nanotun、默认值必错的时刻。第 7 步用
# E2E_WEB_BASE 去建 Web 管理员,猜错就直接失败,而失败长得像「Web 后台没起来」。
e2e_resolve_web_base
e2e_resolve_magic_suffix

s "command -v nanotun-admin" >/dev/null 2>&1 || die "SRV 上没有 nanotun-admin,先装服务端。"
for who in a c; do
  "$who" "test -x /usr/local/bin/nanotun" >/dev/null 2>&1 \
    || die "客户端 $who 上没有 /usr/local/bin/nanotun。这个二进制来自客户端工程,不在本仓库,得先装。"
done
ok "服务端 admin CLI 与两台客户端二进制就位"

# 关掉三台机器的 apt 日常升级。
#
# 2026-08-03 实测:apt-daily-upgrade 在 e2e 跑到一半时启动,升级顺带重启了
# systemd-networkd / ssh / rsyslog,A 因此短暂失联 —— 一条断言红、一条 ENV 误报,
# 而两者跟被测系统都没关系。这类噪声最难办的地方在于它不可复现:下一轮又好了,
# 于是那条红会被当成偶发 flake 记在产品头上。
#
# 实验室机器不需要自动升级(要升就手动升,升完重跑一轮基线)。
for who in s a c; do
  if "$who" "systemctl is-enabled apt-daily-upgrade.timer" >/dev/null 2>&1; then
    if would "关掉 $who 的 apt 日常升级定时器(避免升级中途重启网络)"; then
      "$who" "systemctl disable --now apt-daily-upgrade.timer apt-daily.timer" >/dev/null 2>&1
      ok "$who 的 apt 定时器已关"
    fi
  fi
done

# sqlite3:阶段 6 的 pf_count / viewer_purge 直接用它查库。缺了不会报「缺 sqlite3」,
# 而是把报错文本当成计数值,断言以看不懂的方式红。
if ! s "command -v sqlite3" >/dev/null 2>&1; then
  if would "SRV 装 sqlite3(阶段 6 查库要用)"; then
    s "apt-get -qq update >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get -qq install -y sqlite3 >/dev/null 2>&1" >/dev/null
    s "command -v sqlite3" >/dev/null 2>&1 && ok "sqlite3 已装" || warn "sqlite3 装失败,阶段 6 会有异常红"
  fi
else
  ok "sqlite3 已在"
fi

# ufw 的**转发**策略必须是 ACCEPT。
#
# 2026-08-26 换机重建时踩到:Vultr 的 Ubuntu 26.04 镜像出厂就开着 ufw,而
# /etc/default/ufw 里 DEFAULT_FORWARD_POLICY="DROP"。nanotun 自己那套规则(出口
# masquerade、子网转发)一条不少,但 ufw 在 forward 钩子上另挂一条 policy drop ——
# nftables 里两张表各自裁决、取交集,于是 C 作为出口节点一个包也转不出去。
#
# 真正难办的不是那几条红(「基线 · A 可达公网」「出口 · 2MB 下载完整」「DF 包通过」),
# 而是它同时制造**假绿**:「撤销出口资格后 A 公网流量被阻断(fail-closed)」照样 PASS ——
# 流量本来就出不去,撤不撤销都一样,那条断言什么也没验到。一层与被测系统无关的防火墙
# 会把所有「应该被挡」的断言变成恒真,而恒真的断言不会有人来查。
#
# 为什么是放开 routed 而不是干脆 ufw disable:phases/50-ops.sh 有两处刻意拿 C 的 22 端口
# 当靶子,写明理由是「C 的 ufw 只放行了 22」—— 那层 input 语义是被断言依赖的,拆了它
# 那两条会从「验到了」退化成「碰巧通」。所以这里只动**过路**流量的默认动作,
# input 放行名单一个字不碰。
for who in s a c; do
  "$who" "command -v ufw" >/dev/null 2>&1 || continue
  ufw_pol="$("$who" "grep '^DEFAULT_FORWARD_POLICY=' /etc/default/ufw | cut -d= -f2 | tr -d '\"'" 2>/dev/null | tr -d '[:space:]')"
  if [ "$ufw_pol" = "ACCEPT" ]; then
    ok "$who 的 ufw 转发策略已是 ACCEPT"
  elif would "$who 的 ufw 转发策略 ${ufw_pol:-未知} → ACCEPT(否则出口/子网转发被 ufw 静默挡掉)"; then
    "$who" "ufw default allow routed >/dev/null 2>&1; ufw reload >/dev/null 2>&1" >/dev/null 2>&1
    ufw_pol="$("$who" "grep '^DEFAULT_FORWARD_POLICY=' /etc/default/ufw | cut -d= -f2 | tr -d '\"'" 2>/dev/null | tr -d '[:space:]')"
    [ "$ufw_pol" = "ACCEPT" ] \
      && ok "$who 的 ufw 转发策略已改为 ACCEPT" \
      || warn "$who 的 ufw 转发策略仍是 ${ufw_pol:-未知},出口类断言会红(且 fail-closed 那几条会假绿)"
  fi
done

# 靶站端口必须在 C 的 ufw 放行名单里。README 和 lib/fixtures.sh 都记着这条前置,
# 但此前没有任何脚本落实它 —— 老 C 上那条放行规则是手工加的,机器一换就跟着没了,
# 而缺了它「A→C 靶站 200」的红看起来像 mesh 坏了。
if c "command -v ufw" >/dev/null 2>&1; then
  if c "ufw status 2>/dev/null | grep -q '^${E2E_TARGET_PORT}/tcp'" >/dev/null 2>&1; then
    ok "C 已放行靶站端口 ${E2E_TARGET_PORT}/tcp"
  elif would "C 放行靶站端口 ${E2E_TARGET_PORT}/tcp"; then
    c "ufw allow ${E2E_TARGET_PORT}/tcp >/dev/null 2>&1" >/dev/null 2>&1
    c "ufw status 2>/dev/null | grep -q '^${E2E_TARGET_PORT}/tcp'" >/dev/null 2>&1 \
      && ok "C 的 ${E2E_TARGET_PORT}/tcp 已放行" \
      || warn "C 的 ${E2E_TARGET_PORT}/tcp 放行失败,靶站类断言会红"
  fi
fi

# ── 1. A:防失联回程规则 ─────────────────────────────────────────────────────
# 必须在 A 建立隧道**之前**就位。A 不带 --no-default-route,连上之后
# `default dev nanotun0` 的 metric 是 0,压过 WAN 默认路由,公网 SSH 的**回包**
# 会被塞进隧道从出口节点发出去,源地址对不上,机房直接丢。
# 现象是「机器活着、隧道正常、SSH 超时」,而且只能从隧道内部绕进去救。
step "1. A:管理面回程规则(防 SSH 失联)"
A_WAN_IF="$(a "ip -o -4 route show default | awk '{print \$5; exit}'" | tr -d '[:space:]')"
A_WAN_GW="$(a "ip -o -4 route show default | awk '{print \$3; exit}'" | tr -d '[:space:]')"
[ -n "$A_WAN_IF" ] && [ -n "$A_WAN_GW" ] || die "取不到 A 的 WAN 网卡/网关,不敢往下走 —— 装错这条规则会把自己关在门外。"
note "A 的 WAN: $A_WAN_IF via $A_WAN_GW,本机 $E2E_A_HOST"

if a "systemctl is-enabled nanotun-mgmt-return.timer" >/dev/null 2>&1; then
  ok "nanotun-mgmt-return.timer 已启用(每 30s 自愈一次)"
else
  if would "在 A 上安装 nanotun-mgmt-return 的 service + timer(周期性自愈)"; then
    # 不设 RemainAfterExit、也不设 ExecStop,改由 timer 每 30s 重新断言一次。
    #
    # 起因(2026-08-03):跑到阶段 5 时 A 突然 SSH 超时,一条断言红、一条 ENV 误报
    # 「连接参数里没有 --exit」(其实是 ssh 失败的返回码被当成了参数问题)。
    # 查下来是 Ubuntu 的 apt-daily-upgrade 在测试中途启动,升级过程重启了
    # systemd-networkd —— networkd 重启会清掉**不归它管**的策略路由规则,
    # 我们这条正是。此前的 unit 是 oneshot + RemainAfterExit,systemd 仍认为
    # 服务是 active,于是规则没了也没人补,A 就那么裸奔着。
    #
    # ExecStart 两条都是幂等的,重复执行零副作用,所以周期重放是安全的。
    cat > "$TMP/mgmt-return.service" <<EOF
[Unit]
Description=nanotun e2e: management-plane return route (keeps public SSH alive when the tunnel takes the default route)
After=network-online.target
Wants=network-online.target
# 刻意不依赖 nanotun:这条规则存在的意义正是隧道出问题时还能进得来。

[Service]
Type=oneshot
ExecStart=/bin/sh -c "ip route replace default via $A_WAN_GW dev $A_WAN_IF table 100"
ExecStart=/bin/sh -c "ip rule list | grep -q \\"from $E2E_A_HOST lookup 100\\" || ip rule add from $E2E_A_HOST table 100 priority 100"

[Install]
WantedBy=multi-user.target
EOF
    cat > "$TMP/mgmt-return.timer" <<'EOF'
[Unit]
Description=nanotun e2e: re-assert the management-plane return route (networkd restarts flush foreign ip rules)

[Timer]
OnBootSec=15s
OnUnitInactiveSec=30s
AccuracySec=5s

[Install]
WantedBy=timers.target
EOF
    push_file a "$TMP/mgmt-return.service" /etc/systemd/system/nanotun-mgmt-return.service \
      || die "推送 mgmt-return unit 失败"
    push_file a "$TMP/mgmt-return.timer" /etc/systemd/system/nanotun-mgmt-return.timer \
      || die "推送 mgmt-return timer 失败"
    # daemon-reload 之后必须先 stop 再 start。老版 unit 带 RemainAfterExit=yes,
    # 服务会一直停在 active,`enable --now` 于是成了空操作 —— 服务没按新定义重跑,
    # 而 OnUnitInactiveSec 要等服务变 inactive 才排下一次,结果 timer 显示 active
    # 却永远不触发(list-timers 里 NEXT 是空的),看着装好了其实一点用没有。
    # stop 在 reload 之后执行,此时加载的是新定义(没有 ExecStop),不会误删规则。
    a "systemctl daemon-reload \
       && systemctl enable nanotun-mgmt-return.service nanotun-mgmt-return.timer \
       && systemctl stop nanotun-mgmt-return.service 2>/dev/null; \
       systemctl start nanotun-mgmt-return.service nanotun-mgmt-return.timer" >/dev/null \
      || die "启用 mgmt-return 失败"
    ok "已安装 service + timer 并启用(每 30s 重新断言)"
  fi
fi
a "ip rule list | grep -q 'from $E2E_A_HOST lookup 100'" >/dev/null 2>&1 \
  && ok "回程规则生效中" \
  || { [ "$DRY" = 1 ] || die "回程规则没生效,拒绝继续 —— 再往下 A 一连隧道就 SSH 不进去了。"; }

# ── 2. C:假 LAN ─────────────────────────────────────────────────────────────
# 阶段 3(子网路由)与阶段 6(LAN 目标端口转发)全建立在它之上。
# 原先是手工 ip 命令建的 dummy 网卡,没做持久化 —— 重启一次就没,而丢了之后
# 阶段 3 的红看起来像子网功能坏了。这里做成 systemd unit 一并解决。
step "2. C:假 LAN($E2E_C_LAN4 / $E2E_C_LAN6)"
# 这里刻意不写成「已 enable 就跳过」。enabled 只说明开机会拉,不说明**此刻**在跑:
# 2026-08-03 在 C 上做全新安装验证前手动 stop 了它,重建时这段看见 enabled 就报了句
# 「已启用」什么也没做,底下的地址检查发现 lan0 不在却只 warn 一声就过 —— 于是实验室
# 带着缺失的 lan0 被判为「重建完成」。而这个 unit 存在的理由,正是上面注释说的
# 「丢了之后阶段 3 的红看起来像子网功能坏了」。收敛型脚本不能只报告不动手。
if would "在 C 上安装并拉起 nanotun-e2e-lan.service(lan0 持久化)"; then
  lan4_len="${E2E_C_LAN4##*/}"; lan6_len="${E2E_C_LAN6##*/}"
  cat > "$TMP/e2e-lan.service" <<EOF
[Unit]
Description=nanotun e2e: dummy LAN behind C (subnet-route + port-forward fixtures)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c "ip link show lan0 >/dev/null 2>&1 || ip link add lan0 type dummy"
ExecStart=/bin/sh -c "ip link set lan0 up"
ExecStart=/bin/sh -c "ip -4 addr replace $E2E_C_LAN4_HOST/$lan4_len dev lan0"
ExecStart=/bin/sh -c "ip -6 addr replace $E2E_C_LAN6_HOST/$lan6_len dev lan0"
ExecStop=/bin/sh -c "ip link del lan0 2>/dev/null || true"

[Install]
WantedBy=multi-user.target
EOF
  push_file c "$TMP/e2e-lan.service" /etc/systemd/system/nanotun-e2e-lan.service \
    || die "推送 e2e-lan unit 失败"
  # restart 而不是 start:unit 是 RemainAfterExit=yes 的 oneshot,已经 active 时
  # start 是空操作,改了 unit 文件也不会重新执行那几条 ip 命令。
  c "systemctl daemon-reload && systemctl enable nanotun-e2e-lan.service && systemctl restart nanotun-e2e-lan.service" >/dev/null \
    || die "拉起 e2e-lan 失败"
  ok "nanotun-e2e-lan.service 已就位并拉起"
fi
if [ "$DRY" = 0 ]; then
  # 这两条要 die 不要 warn。lan0 缺了不是「小瑕疵」:阶段 3 的子网路由与阶段 6 的
  # LAN 端口转发全建在它上面,少了它那些断言会红成「子网功能坏了」的样子。
  # 重建脚本报了「完成」就该意味着可以直接开跑,而不是让人自己去核对告警。
  c "ip -4 addr show lan0 | grep -q '$E2E_C_LAN4_HOST'" >/dev/null 2>&1 \
    && ok "$E2E_C_LAN4_HOST 在 lan0 上" \
    || die "lan0 上没有 $E2E_C_LAN4_HOST —— 阶段 3/6 会全红,先查 nanotun-e2e-lan.service。"
  c "ip -6 addr show lan0 | grep -qi '$E2E_C_LAN6_HOST'" >/dev/null 2>&1 \
    && ok "$E2E_C_LAN6_HOST 在 lan0 上" \
    || die "lan0 上没有 $E2E_C_LAN6_HOST —— 同上。"
fi

# C 要替 LAN 转发,转发开关必须开。
if [ "$DRY" = 0 ]; then
  c "sysctl -w net.ipv4.ip_forward=1 -w net.ipv6.conf.all.forwarding=1" >/dev/null 2>&1
  ok "C 的 v4/v6 转发已开"
fi

# ── 3. SRV:拨号地址与用户 ───────────────────────────────────────────────────
step "3. SRV:拨号地址与 VPN 用户"
cur_dial="$(adm "setting get server_dial_host" 2>/dev/null | tr -d '[:space:]')"
if [ "$cur_dial" = "$E2E_SRV_HOST" ]; then
  ok "server_dial_host = $cur_dial"
elif would "把 server_dial_host 设为 $E2E_SRV_HOST(当前:${cur_dial:-未设置})"; then
  adm "setting set server_dial_host $E2E_SRV_HOST" >/dev/null || die "设置 server_dial_host 失败"
  ok "已设置"
fi

# ensure_user <用户名> → 把 PSK 写进 $TMP/<用户名>.psk
#
# 用户已存在时默认**不动**它的 PSK:PSK 一旦重置,所有已签发的凭据当场失效,
# 而这个脚本会被反复跑。只有 --rotate-psk 才轮换 —— 那是「客户端连不上、
# 怀疑两边凭据不同步」时的手段。
ensure_user() {
  local u="$1" out psk
  if adm "user show $u" >/dev/null 2>&1; then
    if [ "$ROTATE" = 1 ]; then
      would "轮换 $u 的 PSK" || { : > "$TMP/$u.willpsk"; return 0; }
      # reset-psk 带确认提示,必须喂 y,否则命令返回 "canceled" 而退出码是 0。
      out="$(adm_y "user reset-psk $u")" || die "重置 $u 的 PSK 失败: $out"
    else
      ok "用户 $u 已存在(不动 PSK;要重签凭据加 --rotate-psk)"
      return 0
    fi
  else
    would "创建用户 $u" || { : > "$TMP/$u.willpsk"; return 0; }
    out="$(adm "user create $u")" || die "创建 $u 失败: $out"
  fi
  # PSK 只在创建/轮换时打印这一次,必须当场抓住。
  # 优先认 "PSK:" 标签后面那一串;裸正则兜底时要留意**最后一组可能不足 5 个字符**
  # (形如 …-OBPMG-LA)。按 {5} 死磕会把结尾那组吃掉,得到一个短两位的 PSK,
  # 后面签发凭据时报「--psk 与当前 PSK 不符」—— 看起来像轮换没生效,其实是这里截断了。
  psk="$(printf '%s\n' "$out" | sed -nE 's/.*PSK:[[:space:]]*([A-Z2-7]{5}(-[A-Z2-7]{2,5})+).*/\1/p' | head -1)"
  [ -n "$psk" ] || psk="$(printf '%s\n' "$out" | grep -oE '[A-Z2-7]{5}(-[A-Z2-7]{2,5})+' | head -1)"
  [ -n "$psk" ] || die "没能从输出里解析出 $u 的 PSK,原样如下:
$out"
  printf '%s' "$psk" > "$TMP/$u.psk"
  ok "$u 的 PSK 已取得"
}
ensure_user "$E2E_A_USER"
ensure_user "$E2E_C_USER"

# ── 4. 签发身份并推给客户端 ─────────────────────────────────────────────────
# 只有拿到 PSK 的用户才需要重推。已存在且没轮换的用户,客户端手上那份仍然有效。
step "4. 签发 profile + 凭据并下发"

issue_and_push() {
  local who="$1" user="$2"
  if [ -f "$TMP/$user.willpsk" ]; then
    chg "[dry-run] 为 $user 签发 profile + 凭据并推到 $who"
    return 0
  fi
  if [ ! -f "$TMP/$user.psk" ]; then
    ok "$user 未轮换 PSK,沿用客户端现有凭据"
    return 0
  fi
  local psk; psk="$(cat "$TMP/$user.psk")"

  would "为 $user 签发 profile + 凭据并推到 $who" || return 0

  # 一律走 CLI 的 --output 落到服务端文件,再 cat 回来 —— 不要直接重定向 adm 的输出。
  # env.sh 的 _e2e_run 把远端 stderr 并进了 stdout(它需要那些告警),而
  # `credentials show --psk` 必定打一行「--psk 会经 /proc/<pid>/cmdline 泄露」的告警。
  # 直接重定向的话这行会成为 JSON 文件的第一行,客户端解析失败,
  # 而报错发生在客户端、离这里很远。
  local rd=/tmp/nte2e-prov
  s "mkdir -p $rd && chmod 700 $rd" >/dev/null
  local o
  o="$(adm "profile show $user --dial-host $E2E_SRV_HOST --format json --output $rd/$user.profile.json --force")" \
    || die "签发 $user 的 profile 失败: $o"
  o="$(adm "credentials show $user --psk $psk --format json --output $rd/$user.cred.json --force")" \
    || die "签发 $user 的凭据失败: $o"

  s "cat $rd/$user.profile.json" > "$TMP/$user.profile.json"
  s "cat $rd/$user.cred.json"    > "$TMP/$user.cred.json"
  # 凭据里是明文 PSK,别留在服务端 /tmp 里。
  s "shred -u $rd/$user.profile.json $rd/$user.cred.json 2>/dev/null || rm -f $rd/$user.profile.json $rd/$user.cred.json" >/dev/null

  python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if "server_id" in d else 1)' \
    "$TMP/$user.profile.json" 2>/dev/null \
    || die "$user 的 profile 不是合法 JSON,前三行:
$(head -3 "$TMP/$user.profile.json")"
  python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if d.get("psk") else 1)' \
    "$TMP/$user.cred.json" 2>/dev/null \
    || die "$user 的凭据不是合法 JSON 或缺 psk 字段,前三行:
$(head -3 "$TMP/$user.cred.json")"

  push_file "$who" "$TMP/$user.profile.json" "/tmp/${user}_profile.txt" || die "推 profile 到 $who 失败"
  push_file "$who" "$TMP/$user.cred.json"    "/tmp/${user}_cred.txt"    || die "推凭据到 $who 失败"
  "$who" "chmod 600 /tmp/${user}_profile.txt /tmp/${user}_cred.txt" >/dev/null
  ok "$user 的身份已推到 $who"
}
issue_and_push a "$E2E_A_USER"
issue_and_push c "$E2E_C_USER"

# A 走的是**具名连接**(connect test),凭据在保存时加密落盘;C 走的是临时文件。
# 两条路径都要覆盖 —— 具名连接是桌面端的主用法。
A_CONN_NAME="$(printf '%s' "$E2E_A_CONNECT_ARGS" | awk '{print $1}')"
if [ -f "$TMP/$E2E_A_USER.psk" ] && [ "$DRY" = 0 ]; then
  # 必须先 remove 再 add,--force 不够。
  # 客户端有个人节点配额(免费档 1 个),而「同一台服务器重扫新配置算 upsert、不占额」
  # 这条豁免是按 server_id 认的。服务端重装之后 server_id 变了,旧连接虽然指向同一个
  # IP 却被判成**另一个**节点,于是 add 撞配额报「个人节点已达上限(1/1)」——
  # 那句报错读起来像套餐问题,跟「服务端换了身份」看不出关系。
  a "/usr/local/bin/nanotun remove '$A_CONN_NAME'" >/dev/null 2>&1
  a "/usr/local/bin/nanotun add '$A_CONN_NAME' /tmp/${E2E_A_USER}_profile.txt --cred /tmp/${E2E_A_USER}_cred.txt --force" >/dev/null \
    && ok "A 的具名连接 '$A_CONN_NAME' 已重建" \
    || die "在 A 上重建具名连接失败:
$(a "/usr/local/bin/nanotun add '$A_CONN_NAME' /tmp/${E2E_A_USER}_profile.txt --cred /tmp/${E2E_A_USER}_cred.txt --force" 2>&1)"
fi

# ── 5. 拉起会话 ─────────────────────────────────────────────────────────────
step "5. 拉起两个客户端会话"
if [ "$DRY" = 0 ]; then
  # shellcheck source=lib/fixtures.sh
  source "$HERE/lib/fixtures.sh"
  client_a_start; client_c_start
  for i in $(seq 1 30); do
    [ "$(conn_count)" = "2" ] && break
    sleep 2
  done
  n="$(conn_count)"
  if [ "$n" = "2" ]; then
    ok "两个会话在线"
  else
    printf '\n'
    warn "只有 $n 个会话在线,下面是客户端日志:"
    printf '%s── A ──%s\n' "$_D" "$_N"; client_log a "$E2E_A_UNIT" 60 | tail -6
    printf '%s── C ──%s\n' "$_D" "$_N"; client_log c "$E2E_C_UNIT" 60 | tail -6
    die "会话没起来,后面的设备 ID / vIP 都取不到。"
  fi
fi

# ── 6. 钉 vIP、指定出口、批准子网 ───────────────────────────────────────────
step "6. 固定 vIP / 出口 / 子网路由"
if [ "$DRY" = 0 ]; then
  dev_of() { # dev_of <username> → device_id
    adm "device list --user $1" | awk 'NR>1 && $1 ~ /^[0-9]+$/ {print $1; exit}'
  }
  A_DEV="$(dev_of "$E2E_A_USER")"
  C_DEV="$(dev_of "$E2E_C_USER")"
  [ -n "$A_DEV" ] && [ -n "$C_DEV" ] || die "取不到设备 ID(A=$A_DEV C=$C_DEV)"
  ok "设备 ID: A=$A_DEV  C=$C_DEV"

  C_UUID_NEW="$(adm "device list --user $E2E_C_USER" | awk 'NR>1 && $1 ~ /^[0-9]+$/ {print $3; exit}')"
  [ -n "$C_UUID_NEW" ] && ok "C 的设备 UUID: $C_UUID_NEW"

  # 钉 vIP:阶段脚本大量按 vIP 断言(A→C 可达、靶站、端口转发目标),
  # 不钉住的话每次重连都可能换地址,e2e.env 就得跟着改。
  adm "device set-fixed-vip $A_DEV --v4 $E2E_A_VIP4 --force" >/dev/null 2>&1 \
    && ok "A 的 vIP 钉为 $E2E_A_VIP4" || warn "钉 A 的 vIP 失败"

  # 先清掉占着这两个 vIP 的**旧** C 设备。客户端状态目录一没(重装、清盘、或者像
  # 2026-08-03 那样把服务端和客户端共用的 /var/lib/nanotun 一起删了),C 会以新 UUID
  # 重新注册,而老设备行还攥着 fixed_vip 不放,新设备去钉就撞唯一约束。
  #
  # 那次的报错是 `store: unique constraint violation`,没说是谁占着 —— 而且 exit designate
  # 不是原子的:出口标记已经写进去了(默认路由都成 approved 了),只有钉 vIP 那步失败,
  # 命令却整体返回 1。于是从退出码看是「指定出口失败」,从库里看出口明明是好的,
  # 两边对不上,真因(有个同名旧设备)完全没露面。
  stale="$(adm "device list" | awk -v keep="$C_DEV" -v v4="$E2E_C_VIP4" -v v6="$E2E_C_VIP6" \
    '$1 ~ /^[0-9]+$/ && $1 != keep && ($7 == v4 || $8 == v6) {print $1}')"
  for d in $stale; do
    adm_y "device delete $d" >/dev/null 2>&1 \
      && ok "清掉占着固定 vIP 的旧设备 #$d" || warn "旧设备 #$d 删不掉,下一步钉 vIP 大概率会失败"
  done

  # exit designate 一并把 C 的 0/0 + ::/0 建成 approved 并钉住 vIP。
  out="$(adm "exit designate $C_DEV --v4 $E2E_C_VIP4 --v6 $E2E_C_VIP6 --force" 2>&1)" \
    && ok "C 已指定为出口,vIP 钉为 $E2E_C_VIP4 / $E2E_C_VIP6" \
    || die "指定 C 为出口失败,后面所有出口类断言都会红:
$out"

  # 客户端要重连才会拿到钉住的 vIP。
  client_a_start; client_c_start
  for i in $(seq 1 30); do [ "$(conn_count)" = "2" ] && break; sleep 2; done
  ok "两端已按固定 vIP 重连($(conn_count) 个会话在线)"

  # 子网路由要客户端先宣告(--advertise-routes)才有行可批。
  #
  # 自己解析 STATUS 列,不要用 `--status approved | grep <cidr>` 那种写法:
  # 0.1.0 的 nanotun-admin 里 --status 给了 --device 就会被静默忽略(已修,但这个
  # 脚本要能对着线上的旧二进制跑),于是 pending 的行也会被 grep 到,判成「已批准」。
  # 那个误判正是 2026-08-03 那次「子网四条断言全红、真因却毫无提示」的来源。
  route_status() { # route_status <device_id> <cidr> → approved|pending|rejected|空
    adm "route list --device $1" | awk -v d="$1" -v c="$2" '$2==d && $3==c {print $4; exit}'
  }
  for cidr in "$E2E_C_LAN4" "$E2E_C_LAN6"; do
    [ -n "$cidr" ] || continue
    st_r="$(route_status "$C_DEV" "$cidr")"
    case "$st_r" in
      approved) ok "$cidr 已是 approved" ;;
      "")       warn "$cidr 尚无宣告记录(C 还没宣告出来?),稍后重跑本脚本" ;;
      *)
        adm "route approve $C_DEV $cidr" >/dev/null 2>&1
        st_r="$(route_status "$C_DEV" "$cidr")"
        [ "$st_r" = approved ] \
          && ok "$cidr 已批准(原为 pending)" \
          || warn "批准 $cidr 失败,当前状态:${st_r:-未知}"
        ;;
    esac
  done

  # 备用离线设备:阶段 4 的租约钉住告警和阶段 5 的 lease_gc 都需要一台**存在但永不上线**
  # 的靶子 —— 那些用例要往设备上钉网关地址 / 网段地址这类非法值,拿 A 或 C 去试会打断
  # 正在跑的会话。设备 ID 是自增的,重建后必然与旧值不同,所以这里连同 ID 一起回填;
  # 指不到设备时那几条会报 `device not found: #N`,看起来像 CLI 坏了。
  SPARE_UUID=00000000-0000-4000-8000-00000000e2e5
  spare_dev_id() { adm "device list" | awk -v u="$SPARE_UUID" '$3==u {print $1; exit}'; }
  SPARE_DEV="$(spare_dev_id)"
  if [ -n "$SPARE_DEV" ]; then
    ok "备用离线设备已存在(ID=$SPARE_DEV)"
  else
    adm "device create $E2E_A_USER --uuid $SPARE_UUID --name e2e-spare --platform linux" >/dev/null 2>&1
    SPARE_DEV="$(spare_dev_id)"
    [ -n "$SPARE_DEV" ] && ok "已建备用离线设备(ID=$SPARE_DEV)" || warn "建备用设备失败,阶段 4 会红"
  fi

  # MagicDNS 后缀:阶段 1(10-exit.sh)按 $E2E_MAGIC_SUFFIX 拼 *.<后缀> 域名做解析断言。
  # 运行期后缀**只**取服务端 config.toml 的 [server.magic_dns].domain_suffix(缺省 lan)——
  # app_settings 里从来没有 magic_suffix 这一项,早先这里的 `setting set magic_suffix` 是空操作
  # (写进库无人读),现已在 CLI 侧硬拒(cmd_setting.go 的 systemManagedSettingKeys)。故不再徒劳写 DB:
  # e2e 默认后缀就是 lan、与模板 config.toml 一致,阶段 1 开箱即绿。要验**非默认后缀**端到端,
  # 用 scripts/e2e/magic-suffix-drill.sh(改 config.toml→重启→验证客户端解析→还原,不污染门禁基线)。
  note "MagicDNS 后缀取 config.toml 的 domain_suffix(默认 lan);非默认后缀验证见 magic-suffix-drill.sh"
fi

# ── 7. web 管理员 ───────────────────────────────────────────────────────────
step "7. Web 管理员 ${E2E_WEB_USER:-(未配置)}"
if [ -z "${E2E_WEB_USER:-}" ] || [ -z "${E2E_WEB_PASS:-}" ]; then
  warn "e2e.env 没配 E2E_WEB_USER / E2E_WEB_PASS,阶段 6 会整段跳过"
elif [ "$DRY" = 0 ]; then
  RD="${E2E_REMOTE_DIR:-/tmp/nte2e}"
  s "mkdir -p $RD" >/dev/null
  for f in webclient.py capsolve.py; do
    s "cat > $RD/$f" < "$HERE/remote/$f" || die "下发 $f 失败"
  done
  st="$(s "python3 $RD/webclient.py --base $E2E_WEB_BASE --jar $RD/jar_admin.txt setup --user $E2E_WEB_USER --password '$E2E_WEB_PASS'" | tail -1)"
  case "$st" in
    200)    ok "已创建 web 管理员 $E2E_WEB_USER" ;;
    exists) ok "web 管理员已存在(/setup 已关闭)" ;;
    *)      warn "创建 web 管理员失败(返回 $st),阶段 6 会红" ;;
  esac
fi

# ── 8. 回填 e2e.env ─────────────────────────────────────────────────────────
# 设备 ID 是自增的、UUID 由客户端生成,重建之后必然与旧值不同。
# 不回填的话,阶段脚本会拿着旧 ID 去查,查不到 —— 而那种红完全看不出是配置过期。
step "8. 回填 e2e.env"
if [ "$DRY" = 1 ]; then
  warn "dry-run,不写 e2e.env"
elif [ "$BACKFILL" = 0 ]; then
  warn "--no-backfill,跳过。请手动核对下列值:"
  printf '     E2E_A_DEVICE_ID=%s\n     E2E_C_DEVICE_ID=%s\n     E2E_C_UUID=%s\n' \
    "${A_DEV:-?}" "${C_DEV:-?}" "${C_UUID_NEW:-?}"
else
  ENVF="${E2E_ENV:-$HERE/e2e.env}"
  cp "$ENVF" "$ENVF.bak.$(date +%Y%m%d-%H%M%S)"
  setkv() { # setkv <key> <value> —— 有则改,无则追加
    local k="$1" v="$2"
    if grep -qE "^${k}=" "$ENVF"; then
      python3 - "$ENVF" "$k" "$v" <<'PY'
import re,sys
p,k,v = sys.argv[1],sys.argv[2],sys.argv[3]
src = open(p).read()
open(p,'w').write(re.sub(r'(?m)^%s=.*$' % re.escape(k), '%s=%s' % (k,v), src))
PY
    else
      printf '%s=%s\n' "$k" "$v" >> "$ENVF"
    fi
  }
  setkv E2E_A_DEVICE_ID "$A_DEV"
  setkv E2E_C_DEVICE_ID "$C_DEV"
  [ -n "${C_UUID_NEW:-}" ] && setkv E2E_C_UUID "$C_UUID_NEW"
  [ -n "${SPARE_DEV:-}" ] && setkv E2E_SPARE_DEVICE_ID "$SPARE_DEV"
  # A 的连接参数里写着 `--exit <C 的 UUID>`,UUID 变了这里必须同步,
  # 否则 A 会拿着一个不存在的出口去连,阶段 1 全红。
  if [ -n "${C_UUID_NEW:-}" ]; then
    NEWARGS="$(printf '%s' "$E2E_A_CONNECT_ARGS" | sed -E "s#(--exit )[0-9a-fA-F-]{36}#\\1$C_UUID_NEW#")"
    setkv E2E_A_CONNECT_ARGS "\"$NEWARGS\""
  fi
  ok "已回填(原文件备份为 $(basename "$ENVF").bak.*)"
  printf '     E2E_A_DEVICE_ID=%s\n     E2E_C_DEVICE_ID=%s\n     E2E_C_UUID=%s\n     E2E_SPARE_DEVICE_ID=%s\n' \
    "$A_DEV" "$C_DEV" "${C_UUID_NEW:-未变}" "${SPARE_DEV:-未建}"
fi

step "完成"
if [ "$DRY" = 1 ]; then
  echo "   以上是 dry-run。去掉 --dry-run 实际执行。"
else
  echo "   接着跑:./scripts/e2e/run.sh 00 10 20 30 40 50 60 70"
fi
echo
