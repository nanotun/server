#!/usr/bin/env bash
# nanotun 服务端卸载 —— 把 install-self-hosted.sh 装的东西原路撤掉。
#
#   sudo ./scripts/uninstall.sh            # 停服务、删程序,**保留**配置与数据库
#   sudo ./scripts/uninstall.sh --purge    # 连配置、证书、数据库一起删(要再确认一次)
#   sudo ./scripts/uninstall.sh --dry-run  # 只列要做什么,不动手
#
# 选项:
#   --purge     连 config.toml / 证书 / 数据库 / QR / 发布包解压目录一起删
#   --yes       不问,直接执行(配合 --purge 时尤其小心:用户和 PSK 一起没)
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
      awk 'NR>1 && /^#/ {sub(/^#[[:space:]]?/,""); print; next} NR>1 {exit}' "$0"
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

# 服务端装的 systemd 单元。tun-isolate 装了但默认不 enable,照样要清。
UNITS=(nanotun.service nanotun-web.service nanotun-tun-setup.service nanotun-tun-isolate.service)

# 服务端装进 /usr/local/bin 的东西。
# **不含 `nanotun`** —— 那是客户端二进制,跟服务端毫无关系,删了等于顺手把人家的 VPN 也卸了。
BINS=(nanotund nanotun-admin nanotun-web nanotun-setup nanotun-preflight
      nanotun-ensure-assets.sh
      nanotun-tun-setup.sh nanotun-tun-teardown.sh
      nanotun-tun-isolate.sh nanotun-tun-isolate-teardown.sh)

# --purge 才删。全部是服务端独有的,客户端不碰。
PURGE_FILES=("$ETC_DIR/config.toml" "$ETC_DIR/config.toml.dist"
             "$LIB_DIR/nanotun.db" "$LIB_DIR/nanotun.db-wal" "$LIB_DIR/nanotun.db-shm")
PURGE_GLOBS=("$ETC_DIR/config.toml.bak.*" "$LIB_DIR/nanotun.db.preimport.*")
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
  ok "找到已安装的服务端$([ -x /usr/local/bin/nanotund ] && printf '(nanotund %s)' "$(/usr/local/bin/nanotund --version 2>/dev/null | head -1)")"
else
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
[ -x /usr/local/bin/nanotun-tun-isolate-teardown.sh ] \
  && run "撤销客户端隔离规则" /usr/local/bin/nanotun-tun-isolate-teardown.sh
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
step "4. 撤销 sysctl 与 ufw 放行"
if [ -f /etc/sysctl.d/99-nanotun.conf ]; then
  # 这个 drop-in 名义上是服务端装的,但 ip_forward 并不只有服务端在用:客户端做
  # **子网路由 / 出口节点**时同样靠它转发。所以机器上还有客户端时一律留着。
  #
  # 不留的代价是立刻见效的,不是下次重启才出事:删完跑 sysctl --system,ip_forward 当场
  # 回落到别处配置的值(全新 Debian/Ubuntu 上就是 0),正在经这台机器出网的客户端瞬间断流。
  # 反过来,在一台已经没有服务端的机器上多留一个开着转发的 drop-in,只是洁癖问题,
  # 而且下面会把话说清楚 —— 两害相权,留着。
  if [ "$CLIENT_PRESENT" = 1 ]; then
    warn "保留 /etc/sysctl.d/99-nanotun.conf —— 客户端做子网路由 / 出口节点时也需要 ip_forward=1。"
    warn "确认这台机器不再需要转发,再自行删除该文件并 sysctl --system。"
  else
    run "删 /etc/sysctl.d/99-nanotun.conf" rm -f /etc/sysctl.d/99-nanotun.conf
    run "sysctl --system(转发设置回到系统默认)" sysctl --system
  fi
fi
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
  for rule in 8443/tcp 443/udp 7443/tcp; do
    run "ufw 收回 $rule" ufw delete allow "$rule"
  done
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
if [ "$DRY" = 1 ]; then
  printf '    这是 dry-run,什么都没动。\n'
elif [ "$PURGE" = 1 ]; then
  printf '    服务端已卸载,配置与数据也已删除。\n'
else
  printf '    服务端已卸载。配置与数据库还在,重新装一遍就能接着用。\n'
fi
[ "$CLIENT_PRESENT" = 1 ] && printf '    客户端未受影响。\n'
exit 0
