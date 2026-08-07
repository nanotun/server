#!/usr/bin/env bash
# nanotun 服务端卸载 —— 把 install-self-hosted.sh 装的东西原路撤掉。
#
#   sudo ./scripts/uninstall.sh            # 停服务、删程序,**保留**配置与数据库
#   sudo ./scripts/uninstall.sh --purge    # 连配置、证书、数据库一起删(要再确认一次)
#   sudo ./scripts/uninstall.sh --dry-run  # 只列要做什么,不动手
#
# 选项:
#   --purge     连 config.toml / 证书 / 数据库 / QR / 发布包解压目录一起删
#   --yes       跳过 --purge 那道确认(只有 --purge 会问 —— 它删的东西没有撤销;
#               不带 --purge 的卸载留着配置与数据库,重装即可恢复,所以不拦)
#   --dry-run   只打印计划
#
# 为什么删的是**一份文件清单**而不是 `rm -rf /etc/nanotun /var/lib/nanotun`:
#
#   这三个目录是服务端与**客户端**共用的,而客户端的身份就放在里面:
#     /etc/nanotun/device_id          客户端的设备 UUID
#     /var/lib/nanotun/tun_name       客户端的 TUN 网卡名
#     /run/nanotun/dataplane.lock     客户端数据面锁
#
#   2026-08-03 在一台既跑客户端又临时装了服务端的机器上,卸载时按目录整个删掉,
#   客户端的 device_id 跟着没了 —— 它以新 UUID 重新注册,而 UUID 是审批与出口选择的
#   稳定键(见 docs/DESIGN_EXIT_NODE.md):旧设备行还攥着固定 vIP,新设备钉不上;
#   已经选了这个出口的客户端那边它直接「失踪」。整个过程一声不响。
#
#   所以这里逐个文件删,最后用 rmdir 收尾 —— 目录非空就留着,这正是我们要的行为。
set -euo pipefail

PURGE=0; ASSUME_YES=0; DRY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --purge)   PURGE=1; shift ;;
    --yes|-y)  ASSUME_YES=1; shift ;;
    --dry-run) DRY=1; shift ;;
    -h|--help)
      awk 'NR>1 && /^#/ {sub(/^#[ \t]?/,""); print; next} NR>1 {exit}' "$0"
      exit 0 ;;
    *) printf 'uninstall.sh: 未知参数 %s(--help 看用法)\n' "$1" >&2; exit 2 ;;
  esac
done

step() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[1;32m✓\033[0m %s\n' "$*"; }
warn() { printf '    \033[1;33m!\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mFATAL: %s\033[0m\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "需要 root(要停 systemd 单元、删 /usr/local/bin 与 /etc)。请用 sudo。"

ETC_DIR=/etc/nanotun
LIB_DIR=/var/lib/nanotun
RUN_DIR=/run/nanotun

# 服务端装的 systemd 单元。tun-isolate 那套已经删了,这里仍然留着名字 —— 卸载要能
# 收拾**老版本**装下的东西,而老机器上它确实在。
UNITS=(nanotun.service nanotun-web.service nanotun-tun-setup.service nanotun-tun-isolate.service)

# 服务端装进 /usr/local/bin 的东西。
# **不含 `nanotun`** —— 那是客户端二进制,跟服务端毫无关系,删了等于顺手把人家的 VPN 也卸了。
BINS=(nanotund nanotun-admin nanotun-web nanotun-setup nanotun-preflight
      nanotun-ensure-assets.sh
      nanotun-tun-setup.sh nanotun-tun-teardown.sh
      nanotun-tun-isolate.sh nanotun-tun-isolate-teardown.sh)

# --purge 才删。全部是服务端独有的,客户端不碰。
#
# web.env 漏掉的代价比一般残留大:它写着 NANOTUN_WEB_ALLOW_SETUP=0。purge 之后重装,
# 新机器的库里一个管理员都没有,却带着一份「已关门」的残留 —— /setup 打不开、也没有
# 账号可登,Web 后台直接进不去,而向导还照着旧逻辑说「/setup 仍然敞着」。
PURGE_FILES=("$ETC_DIR/config.toml" "$ETC_DIR/config.toml.dist" "$ETC_DIR/web.env")
# 数据库连同它的一族随从一起走:-wal / -shm(SQLite)、.migrate.lock(store.Migrate
# 建的)、.preimport.*(旧库导入前的备份,里面是整个用户表)。
#
# 这里用通配而不是逐个点名,是因为漏掉一个的代价不对称:下面收尾用 rmdir,目录里
# 只要还剩一个文件就整个留着,而留下的理由会被打印成「还有别人的文件」——
# nanotun.db.migrate.lock 就这样被报成别人的,人看了会以为那是客户端的东西不敢动。
# --purge 说了「数据库一起没」,就不该留个目录在那儿。
# /var/lib/nanotun 里客户端只有 tun_name,不会撞上 nanotun.db* 这个前缀。
PURGE_GLOBS=("$ETC_DIR/config.toml.bak.*" "$LIB_DIR/nanotun.db*")
PURGE_DIRS=("$ETC_DIR/certs" "$ETC_DIR/masquerade" "$LIB_DIR/qr" /opt/nanotun)

run() { # run <描述> <命令...>
  local what="$1"; shift
  if [ "$DRY" = 1 ]; then printf '    + [dry-run] %s\n' "$what"; return 0; fi
  "$@" >/dev/null 2>&1 && ok "$what" || warn "$what —— 没做成(可能本来就不在)"
}

# ── 0. 先看清楚这台机器上还有谁 ──────────────────────────────────────────────
step "0. 现状"

CLIENT_PRESENT=0
for f in /usr/local/bin/nanotun "$ETC_DIR/device_id" "$LIB_DIR/tun_name"; do
  [ -e "$f" ] && CLIENT_PRESENT=1
done
if [ "$CLIENT_PRESENT" = 1 ]; then
  warn "这台机器上还装着 nanotun **客户端**。它与服务端共用 $ETC_DIR / $LIB_DIR,"
  warn "本脚本只删服务端自己的文件,客户端的 device_id / tun_name 一概不动。"
fi

if [ -x /usr/local/bin/nanotund ] || [ -f /etc/systemd/system/nanotun.service ]; then
  # --version 第一行已经是 "nanotund <版本>",别再自己拼一遍程序名(会变成 nanotund nanotund vX)。
  #
  # 取空是正常情况,不是故障:--version 是后加的,v0.1.0-rc2 及更早的 nanotund 不认这个
  # flag(它会打 "flag provided but not defined" 到 stderr,stdout 一个字没有)。而卸载
  # 恰恰最常发生在老版本上。取空时整个括号一起省掉,别留一对空括号让人以为读版本失败了。
  NANOTUND_VER=""
  [ -x /usr/local/bin/nanotund ] && NANOTUND_VER="$(/usr/local/bin/nanotund --version 2>/dev/null | head -1)"
  FOUND_SERVER=1
  ok "找到已安装的服务端${NANOTUND_VER:+($NANOTUND_VER)}"
else
  FOUND_SERVER=0
  warn "没找到已安装的服务端(nanotund 与 nanotun.service 都不在)。"
  warn "继续跑也无妨 —— 下面每一步都是幂等的,不在就跳过。"
fi

if [ "$PURGE" = 1 ]; then
  users="?"
  if [ -x /usr/local/bin/nanotun-admin ] && [ -f "$LIB_DIR/nanotun.db" ]; then
    users="$(/usr/local/bin/nanotun-admin --db-path "$LIB_DIR/nanotun.db" user list 2>/dev/null | tail -n +2 | grep -c . || echo '?')"
  fi
  printf '\n\033[1;31m--purge:配置、证书、数据库都会被删掉。\033[0m\n'
  printf '  数据库 %s(约 %s 个 VPN 用户)—— 用户、设备、PSK、审批过的子网路由全部一起没,\n' "$LIB_DIR/nanotun.db" "$users"
  printf '  已经发出去的客户端配置也就此作废。这一步没有撤销。\n'
  if [ "$ASSUME_YES" != 1 ] && [ "$DRY" != 1 ]; then
    printf '\n  确认请输入 purge:'
    read -r reply
    [ "$reply" = "purge" ] || die "已取消(没有输入 purge)。"
  fi
fi

# ── 1. 停服务 ────────────────────────────────────────────────────────────────
step "1. 停止并禁用 systemd 单元"
for u in "${UNITS[@]}"; do
  if systemctl list-unit-files "$u" >/dev/null 2>&1 && [ -f "/etc/systemd/system/$u" ]; then
    run "停止并禁用 $u" systemctl disable --now "$u"
  fi
done

# ── 2. 撤内核里的东西 ────────────────────────────────────────────────────────
# 顺序要紧:teardown 脚本本身就在 /usr/local/bin 里,得赶在第 3 步删它们之前跑。
# 不跑的话 TUN 网卡与 iptables 规则会留到下次重启 —— 而卸载完还占着 tun0 和一堆
# FORWARD/NAT 规则,是最容易被当成「别的软件坏了」的那种残留。
step "2. 拆掉 TUN 网卡与 iptables 规则"
# 旧版那套 shell 客户端隔离(ipset + INPUT DROP)的残留自己就地清,不再调它的
# teardown 脚本 —— 那个脚本已经随功能一起删了,新装的机器上根本没有,而残留是**老**
# 机器上的东西:靠一个新版不再分发的文件去清老版本的垃圾,恰好在唯一需要它的场合缺席。
if command -v ipset >/dev/null 2>&1 && ipset list vpn_client_ips >/dev/null 2>&1; then
  while iptables -C INPUT -i tun+ -m set --match-set vpn_client_ips src \
        -m set --match-set vpn_client_ips dst -j DROP 2>/dev/null; do
    iptables -D INPUT -i tun+ -m set --match-set vpn_client_ips src \
      -m set --match-set vpn_client_ips dst -j DROP 2>/dev/null || break
  done
  ipset destroy vpn_client_ips 2>/dev/null || true
  ok "清除旧版客户端隔离残留"
fi
[ -x /usr/local/bin/nanotun-tun-teardown.sh ] \
  && run "删除 TUN 网卡" /usr/local/bin/nanotun-tun-teardown.sh

# ── 3. 删程序与单元 ──────────────────────────────────────────────────────────
step "3. 删除程序与 systemd 单元"
for b in "${BINS[@]}"; do
  [ -e "/usr/local/bin/$b" ] && run "删 /usr/local/bin/$b" rm -f "/usr/local/bin/$b"
done
for u in "${UNITS[@]}"; do
  [ -f "/etc/systemd/system/$u" ] && run "删 /etc/systemd/system/$u" rm -f "/etc/systemd/system/$u"
done
run "systemctl daemon-reload" systemctl daemon-reload
[ -S "$RUN_DIR/control.sock" ] && run "删 $RUN_DIR/control.sock" rm -f "$RUN_DIR/control.sock"

# ── 4. sysctl 与防火墙 ───────────────────────────────────────────────────────
step "4. 撤销 sysctl 与防火墙放行"
if [ -f /etc/sysctl.d/99-nanotun.conf ]; then
  # 这个 drop-in 名义上是服务端装的,但 ip_forward 并不只有服务端在用:客户端做
  # **子网路由 / 出口节点**时同样靠它转发。所以机器上还有客户端时一律留着 ——
  # 多留一个开着转发的 drop-in 只是洁癖问题,删错了却会让正在经这台机器出网的客户端断流。
  if [ "$CLIENT_PRESENT" = 1 ]; then
    warn "保留 /etc/sysctl.d/99-nanotun.conf —— 客户端做子网路由 / 出口节点时也需要 ip_forward=1。"
    warn "确认这台机器不再需要转发,再自行删除该文件并 sysctl --system。"
  else
    run "删 /etc/sysctl.d/99-nanotun.conf" rm -f /etc/sysctl.d/99-nanotun.conf
    run "sysctl --system(重新载入其余 sysctl 配置)" sysctl --system
    # sysctl 只写「配置文件里出现过的」键。drop-in 一删,就没有任何文件再提 ip_forward,
    # 于是它**不会**被改回去:运行值原样留在 1,要到下次重启才回到内核默认 0。
    # 这行原来印的是「转发设置回到系统默认」—— 实测 --purge 跑完 sysctl -n
    # net.ipv4.ip_forward 仍是 1。一句让人以为已经关了、其实还开着的话,比不说更糟,
    # 尤其这台机器可能就是因为不想再转发才卸的。
    #
    # 也不替人关:docker、别的 VPN、k8s 节点都可能正靠着它,这里一 sysctl -w 就断在别处。
    # 只把事实和那一条命令给出来。
    fwd_on=""; fwd_cmd=""
    for k in net.ipv4.ip_forward net.ipv6.conf.all.forwarding; do
      if [ "$(sysctl -n "$k" 2>/dev/null)" = 1 ]; then
        fwd_on="$fwd_on $k"; fwd_cmd="$fwd_cmd; sysctl -w $k=0"
      fi
    done
    if [ -n "$fwd_on" ]; then
      warn "转发仍开着:${fwd_on# } —— sysctl 只回滚配置文件,不改已生效的运行值,重启后才回到内核默认 0。"
      warn "想立刻关掉(先确认没有 docker / 其它 VPN 靠着它):${fwd_cmd#; }"
    fi
  fi
fi
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
  for rule in 8443/tcp 443/udp 7443/tcp; do
    run "ufw 收回 $rule" ufw delete allow "$rule"
  done
fi
# 安装那边对 firewalld 也自动放行(RHEL 系默认防火墙),这里就得对称收回 ——
# 否则卸干净之后机器上还留着三个对公网敞着的端口,而已经没有东西在听了。
if command -v firewall-cmd >/dev/null 2>&1 && [ "$(firewall-cmd --state 2>/dev/null)" = running ]; then
  for rule in 8443/tcp 443/udp 7443/tcp; do
    firewall-cmd --permanent --remove-port="$rule" >/dev/null 2>&1 \
      && ok "firewalld 收回 $rule" || true
  done
  firewall-cmd --reload >/dev/null 2>&1 || true
fi

# ── 5. 配置与数据 ────────────────────────────────────────────────────────────
if [ "$PURGE" = 1 ]; then
  step "5. 删除配置、证书与数据库(--purge)"
  for f in "${PURGE_FILES[@]}"; do
    [ -e "$f" ] && run "删 $f" rm -f "$f"
  done
  for g in "${PURGE_GLOBS[@]}"; do
    for f in $g; do [ -e "$f" ] && run "删 $f" rm -f "$f"; done
  done
  for d in "${PURGE_DIRS[@]}"; do
    [ -d "$d" ] && run "删 $d/" rm -rf "$d"
  done
  # rmdir 而不是 rm -rf:客户端的 device_id / tun_name 还在的话目录就该留着,
  # 而 rmdir 在非空时会失败 —— 这里要的正是这个「删不掉就别删」。
  for d in "$ETC_DIR" "$LIB_DIR" "$RUN_DIR"; do
    if [ -d "$d" ]; then
      if [ "$DRY" = 1 ]; then
        printf '    + [dry-run] 若 %s 已空则删除该目录\n' "$d"
      elif rmdir "$d" 2>/dev/null; then
        ok "删 $d/(已空)"
      else
        ok "保留 $d/(还有别人的文件:$(ls -A "$d" 2>/dev/null | tr '\n' ' '))"
      fi
    fi
  done
else
  step "5. 配置与数据:保留"
  for p in "$ETC_DIR/config.toml" "$ETC_DIR/certs" "$LIB_DIR/nanotun.db"; do
    [ -e "$p" ] && ok "保留 $p"
  done
  printf '    连这些一起删:%s --purge\n' "$0"
fi

step "完成"
# 第 0 步已经如实说过「没找到已安装的服务端」,但那是十几行之前;人照着做的是这一句。
# 原来它无条件宣布「服务端已卸载」—— 在一台本来就没装过的机器上跑(手滑、或者已经卸过
# 一遍了),屏幕上就是一句凭空的战果。--purge 那句更容易吓人:说「配置与数据也已删除」,
# 而其实什么都没有,人会当真去找自己的库哪去了。
if [ "$DRY" = 1 ]; then
  printf '    这是 dry-run,什么都没动。\n'
elif [ "$FOUND_SERVER" = 0 ]; then
  printf '    这台机器上本来就没有服务端。该清的残留(如果有)已经清了。\n'
elif [ "$PURGE" = 1 ]; then
  printf '    服务端已卸载,配置与数据也已删除。\n'
else
  printf '    服务端已卸载。配置与数据库还在,重新装一遍就能接着用。\n'
fi
[ "$CLIENT_PRESENT" = 1 ] && printf '    客户端未受影响。\n'
exit 0
