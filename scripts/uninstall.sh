#!/usr/bin/env bash
# nanotun 服务端卸载 —— 把 install-self-hosted.sh 装的东西原路撤掉。
#
#   sudo ./scripts/uninstall.sh            # 停服务、删程序,**保留**配置与数据库
#   sudo ./scripts/uninstall.sh --purge    # 连配置、证书、数据库一起删(要再确认一次)
#   sudo ./scripts/uninstall.sh --dry-run  # 只列要做什么,不动手
#
# 选项:
#   --lang en|zh 界面语言,默认英文。也认 NANOTUN_LANG 与 /etc/nanotun/lang(装机时选的
#               那份)—— 本命令是装好之后单独敲的,读落盘那份才跟装机时一致
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

# ── 语言 ─────────────────────────────────────────────────────────────────────
# 默认英文。优先级:--lang > NANOTUN_LANG > /etc/nanotun/lang(装机时落下的)> en。
# 这里不问语言:本脚本是装好之后由人单独敲的,读落盘的那份就跟这台机器装机时选的一致。
#
# 文案的组织方式:两种语言**并排写在调用处**(tsel / *_t),不抽成 key → 文案的目录。
# 理由见 scripts/install.sh 里同名那节 —— 这些提示几乎每句都在插值,搬进目录得把每处
# 插值改写成 %s 参数,错了还不会有任何东西红;而每句提示上面那段「为什么这么措辞」的
# 注释也会和它解释的文案隔开好几百行。
NT_LANG=en

nt_lang_normalize() {
  case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')" in
    en|en[-_]*|english)      printf 'en' ;;
    zh|zh[-_]*|chinese|cn)   printf 'zh' ;;
    *)                       printf '' ;;
  esac
}

_nt_l=""
for _nt_a in "$@"; do
  case "$_nt_a" in
    --lang=*) _nt_l="$(nt_lang_normalize "${_nt_a#--lang=}")" ;;
    --lang)   _nt_l=__next__ ;;
    *)        [ "$_nt_l" = __next__ ] && _nt_l="$(nt_lang_normalize "$_nt_a")" ;;
  esac
done
[ "$_nt_l" = __next__ ] && _nt_l=""
if [ -n "$_nt_l" ]; then
  NT_LANG="$_nt_l"
elif [ -n "$(nt_lang_normalize "${NANOTUN_LANG:-}")" ]; then
  NT_LANG="$(nt_lang_normalize "$NANOTUN_LANG")"
elif [ -r /etc/nanotun/lang ] && \
     [ -n "$(nt_lang_normalize "$(head -1 /etc/nanotun/lang 2>/dev/null)")" ]; then
  NT_LANG="$(nt_lang_normalize "$(head -1 /etc/nanotun/lang 2>/dev/null)")"
fi
unset _nt_l _nt_a
export NANOTUN_LANG="$NT_LANG"

# tsel <英文> <中文> —— 按当前语言选一份。
tsel() { if [ "$NT_LANG" = zh ]; then printf '%s' "$2"; else printf '%s' "$1"; fi; }

PURGE=0; ASSUME_YES=0; DRY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --purge)   PURGE=1; shift ;;
    --yes|-y)  ASSUME_YES=1; shift ;;
    --dry-run) DRY=1; shift ;;
    # 语言在文件上方已经扫过一遍(必须早于任何一句提示),这里只负责把它从 argv 里吃掉、
    # 顺带校验值。值不合法要当场说,别默默回落到英文:那样 `--lang fr` 看着像生效了。
    --lang)
      if [ -z "$(nt_lang_normalize "${2:-}")" ]; then
        printf '%s\n' "$(tsel \
          "$(basename "$0"): --lang takes en or zh (got '${2:-}')" \
          "$(basename "$0"): --lang 只认 en 或 zh(收到 '${2:-}')")" >&2
        exit 2
      fi
      shift 2 ;;
    --lang=*)
      if [ -z "$(nt_lang_normalize "${1#--lang=}")" ]; then
        printf '%s\n' "$(tsel \
          "$(basename "$0"): --lang takes en or zh (got '${1#--lang=}')" \
          "$(basename "$0"): --lang 只认 en 或 zh(收到 '${1#--lang=}')")" >&2
        exit 2
      fi
      shift ;;
    # 用法里的命令名按**实际被调用的名字**写。
    #
    # 安装脚本会把本文件装成 /usr/local/bin/nanotun-uninstall,而把它装成命令的理由恰恰是
    # 「一键安装的人当前目录里没有 scripts/」—— 那时帮助里还写 ./scripts/uninstall.sh,
    # 等于在人想卸载的那一刻指给他一条不存在的路径。setup.sh 早就这么做了,这里跟上。
    -h|--help)
      me="$(basename "$0")"; case "$me" in uninstall.sh) me="./scripts/uninstall.sh" ;; esac
      # 英文那份只能是这里手写的:文件头那段注释是给维护者看的,一直是中文。
      # 两份都得把命令名写成 $me —— 这一条是有守卫测试盯着的,漏在哪种语言里都算漏。
      if [ "$NT_LANG" != zh ]; then
        cat <<EOF
nanotun server uninstall — undo what install-self-hosted.sh put in place, item by item.

  sudo ${me}            # stop services, remove programs, **keep** config + database
  sudo ${me} --purge    # also delete config, certificates, database (asks once more)
  sudo ${me} --dry-run  # only list what would happen, touch nothing

Options:
  --lang en|zh interface language (default: en). Also read from NANOTUN_LANG and
              from /etc/nanotun/lang (what was picked at install time) — this
              command is run on its own later, so reading that file is what keeps
              it in step with the rest of this machine
  --purge     also delete config.toml / certificates / database / QR codes / the
              directory the release tarball was extracted into
  --yes       skip the --purge confirmation (only --purge asks — what it deletes
              cannot be undone; an uninstall without --purge leaves config and
              database in place, so a reinstall picks up where you left off)
  --dry-run   print the plan only

Why this deletes **a fixed list of files** instead of \`rm -rf /etc/nanotun /var/lib/nanotun\`:

  Those directories are shared with the **client**, and the client's identity
  lives in them:
    /etc/nanotun/device_id          the client's device UUID
    /var/lib/nanotun/tun_name       the client's TUN interface name
    /run/nanotun/dataplane.lock     the client's data-plane lock

  On 2026-08-03, on a machine that ran the client and had the server installed
  alongside it, uninstalling removed those directories wholesale and took the
  client's device_id with them — the client re-registered under a new UUID, and
  that UUID is the stable key for approvals and exit selection (see
  docs/DESIGN_EXIT_NODE.md): the old device row still held the fixed vIP, so the
  new one could not be pinned to it, and to clients that had already chosen this
  exit node it simply "went missing". None of it said a word.

  So this removes one file at a time and finishes with rmdir — a directory that
  is not empty stays, which is exactly the behaviour we want.
EOF
        exit 0
      fi
      awk 'NR>1 && /^#/ {sub(/^#[ \t]?/,""); print; next} NR>1 {exit}' "$0" \
        | sed "s#\./scripts/uninstall\.sh#${me}#g"
      exit 0 ;;
    *) printf '%s\n' "$(tsel \
         "$(basename "$0"): unknown argument $1 (see --help)" \
         "$(basename "$0"): 未知参数 $1(--help 看用法)")" >&2
       exit 2 ;;
  esac
done

step() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[1;32m✓\033[0m %s\n' "$*"; }
warn() { printf '    \033[1;33m!\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mFATAL: %s\033[0m\n' "$*" >&2; exit 1; }

# 双语版本:英文在前、中文在后,与 tsel 同序。
step_t() { step "$(tsel "$1" "$2")"; }
ok_t()   { ok   "$(tsel "$1" "$2")"; }
warn_t() { warn "$(tsel "$1" "$2")"; }
die_t()  { die  "$(tsel "$1" "$2")"; }

[ "$(id -u)" = 0 ] || die_t \
  "This needs root (it stops systemd units and removes files under /usr/local/bin and /etc). Use sudo." \
  "需要 root(要停 systemd 单元、删 /usr/local/bin 与 /etc)。请用 sudo。"

ETC_DIR=/etc/nanotun
LIB_DIR=/var/lib/nanotun
RUN_DIR=/run/nanotun

# 服务端装的 systemd 单元。tun-isolate 那套已经删了,这里仍然留着名字 —— 卸载要能
# 收拾**老版本**装下的东西,而老机器上它确实在。
UNITS=(nanotun.service nanotun-web.service nanotun-tun-setup.service nanotun-tun-isolate.service)

# 服务端装进 /usr/local/bin 的东西。
# **不含 `nanotun`** —— 那是客户端二进制,跟服务端毫无关系,删了等于顺手把人家的客户端也卸了。
#
# nanotun-uninstall 是本脚本自己(install-self-hosted.sh 把它装成了命令)。删掉正在跑的
# 脚本文件是安全的:bash 一直握着那个 fd,unlink 只摘掉目录项,inode 要等 fd 关闭才回收,
# 剩下的行照读不误。留着它反而更糟 —— 卸载完还杵着一个 nanotun-uninstall,下次有人敲
# 它只会看到「没找到已安装的服务端」。
BINS=(nanotund nanotun-admin nanotun-web nanotun-setup nanotun-preflight
      nanotun-set-suffix nanotun-uninstall
      nanotun-ensure-assets.sh nanotun-ports.sh
      nanotun-tun-setup.sh nanotun-tun-teardown.sh
      nanotun-tun-isolate.sh nanotun-tun-isolate-teardown.sh)

# --purge 才删。全部是服务端独有的,客户端不碰。
#
# web.env 漏掉的代价比一般残留大:它写着 NANOTUN_WEB_ALLOW_SETUP=0。purge 之后重装,
# 新机器的库里一个管理员都没有,却带着一份「已关门」的残留 —— /setup 打不开、也没有
# 账号可登,Web 后台直接进不去,而向导还照着旧逻辑说「/setup 仍然敞着」。
#
# lang 是装机时落下的界面语言(一行 en 或 zh,install-self-hosted.sh 写的),之后所有
# nanotun-* 命令 —— 包括本脚本 —— 都默认沿用它。它和 config.toml 同档:属于**配置**,
# 所以不带 --purge 的卸载留着(重装能接着用上次选的语言),--purge 才删。
# 漏掉它的后果不止是多一个残留文件:下面收尾用 rmdir,$ETC_DIR 里剩着 lang 就整个目录
# 留着,而留下的理由会被打印成「还有别人的文件:lang」—— 一个我们自己写的文件被报成
# 客户端的,人看了不敢动,以为 purge 没干净。
PURGE_FILES=("$ETC_DIR/config.toml" "$ETC_DIR/config.toml.dist" "$ETC_DIR/web.env"
             "$ETC_DIR/lang")
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
  "$@" >/dev/null 2>&1 && ok "$what" \
    || warn "$what$(tsel " — did not go through (it may simply not have been there)" \
                         " —— 没做成(可能本来就不在)")"
}
# run_t <英文描述> <中文描述> <命令...> —— 每一步的动作名都是给人看的,所以也要双语。
run_t() { local e="$1" z="$2"; shift 2; run "$(tsel "$e" "$z")" "$@"; }

# ── 0. 先看清楚这台机器上还有谁 ──────────────────────────────────────────────
step_t "0. What is on this machine" "0. 现状"

CLIENT_PRESENT=0
for f in /usr/local/bin/nanotun "$ETC_DIR/device_id" "$LIB_DIR/tun_name"; do
  [ -e "$f" ] && CLIENT_PRESENT=1
done
if [ "$CLIENT_PRESENT" = 1 ]; then
  warn_t "The nanotun **client** is also installed here. It shares $ETC_DIR / $LIB_DIR with the server," \
         "这台机器上还装着 nanotun **客户端**。它与服务端共用 $ETC_DIR / $LIB_DIR,"
  warn_t "and this script only removes the server's own files — the client's device_id / tun_name are left alone." \
         "本脚本只删服务端自己的文件,客户端的 device_id / tun_name 一概不动。"
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
  ok_t "Found an installed server${NANOTUND_VER:+ ($NANOTUND_VER)}" \
       "找到已安装的服务端${NANOTUND_VER:+($NANOTUND_VER)}"
else
  FOUND_SERVER=0
  warn_t "No installed server found (neither nanotund nor nanotun.service is here)." \
         "没找到已安装的服务端(nanotund 与 nanotun.service 都不在)。"
  warn_t "Running on is harmless — every step below is idempotent and skips what is not there." \
         "继续跑也无妨 —— 下面每一步都是幂等的,不在就跳过。"
fi

if [ "$PURGE" = 1 ]; then
  users="?"
  if [ -x /usr/local/bin/nanotun-admin ] && [ -f "$LIB_DIR/nanotun.db" ]; then
    users="$(/usr/local/bin/nanotun-admin --db-path "$LIB_DIR/nanotun.db" user list 2>/dev/null | tail -n +2 | grep -c . || echo '?')"
  fi
  # 这几句说的是「什么会被删掉」,含糊或译歪会让人以为还能找回来,所以两份各写全,
  # 不靠一句话套两种语序。
  if [ "$NT_LANG" = zh ]; then
    printf '\n\033[1;31m--purge:配置、证书、数据库都会被删掉。\033[0m\n'
    printf '  数据库 %s(约 %s 个用户)—— 用户、设备、PSK、审批过的子网路由全部一起没,\n' "$LIB_DIR/nanotun.db" "$users"
    printf '  已经发出去的客户端配置也就此作废。这一步没有撤销。\n'
  else
    printf '\n\033[1;31m--purge: config, certificates and the database will all be deleted.\033[0m\n'
    printf '  The database %s (about %s users) — users, devices, PSKs and approved\n' "$LIB_DIR/nanotun.db" "$users"
    printf '  subnet routes all go with it, and client configs already handed out stop working.\n'
    printf '  There is no undo for this step.\n'
  fi
  if [ "$ASSUME_YES" != 1 ] && [ "$DRY" != 1 ]; then
    # 要敲的那个词是 purge 本身,两种语言都一样 —— 它是判据,不是文案。
    printf '\n  %s' "$(tsel 'Type purge to confirm: ' '确认请输入 purge:')"
    read -r reply
    [ "$reply" = "purge" ] || die_t "Cancelled (purge was not typed)." "已取消(没有输入 purge)。"
  fi
fi

# ── 1. 停服务 ────────────────────────────────────────────────────────────────
step_t "1. Stop and disable the systemd units" "1. 停止并禁用 systemd 单元"
for u in "${UNITS[@]}"; do
  if systemctl list-unit-files "$u" >/dev/null 2>&1 && [ -f "/etc/systemd/system/$u" ]; then
    run_t "stop and disable $u" "停止并禁用 $u" systemctl disable --now "$u"
  fi
done

# ── 2. 撤内核里的东西 ────────────────────────────────────────────────────────
# 顺序要紧:teardown 脚本本身就在 /usr/local/bin 里,得赶在第 3 步删它们之前跑。
# 不跑的话 TUN 网卡与 iptables 规则会留到下次重启 —— 而卸载完还占着 tun0 和一堆
# FORWARD/NAT 规则,是最容易被当成「别的软件坏了」的那种残留。
step_t "2. Tear down the TUN interface and the iptables rules" "2. 拆掉 TUN 网卡与 iptables 规则"
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
  ok_t "Cleared leftovers of the old client-isolation rules" "清除旧版客户端隔离残留"
fi
[ -x /usr/local/bin/nanotun-tun-teardown.sh ] \
  && run_t "remove the TUN interface" "删除 TUN 网卡" /usr/local/bin/nanotun-tun-teardown.sh

# ── 3. 删程序与单元 ──────────────────────────────────────────────────────────
# 端口要在这儿读,不能等到第 4 步用的时候再读:解析器自己就装在 /usr/local/bin,
# 下面这一步就把它删了。读晚一步就只剩默认值,而那正是要修的 bug。
#
# 收回的必须是**当初真的放行了的**那几条,取决于这台机器的实际端口。写死 8443/443/7443 时,
# 改过端口的机器上收回的是三条不存在的规则,真正开着的那个自定义端口被永久留在防火墙里 ——
# 卸载报告一路绿灯,机器上却留下一个对公网敞着、后面什么都没有的洞。
#
# 配置这会儿还在(第 5 步才删),所以读得到;解析器读不到就回落默认值,那正是没改过端口的情形。
NT_DEFAULT_REALITY=443; NT_DEFAULT_HY2=443; NT_DEFAULT_WEB=7443
# 老默认端口:REALITY 曾默认 8443(2026-08-28 改成 443),Web 曾默认 7443 且不写进 web.env。
# 卸载要收回的是**当初真的放行了的**那几条,而那取决于机器是什么时候装的 —— 所以老值
# 也得进回收清单。多收一条不存在的规则无害(命令失败即忽略);漏收一条,就是在公网上
# 留一个对着空气敞开的洞,而卸载报告还是一路绿灯。
NT_LEGACY_TCP="8443 7443"

NT_PORT_REALITY=$NT_DEFAULT_REALITY; NT_PORT_HY2=$NT_DEFAULT_HY2; NT_PORT_WEB=$NT_DEFAULT_WEB
NT_HY2_SPECS=$NT_DEFAULT_HY2
if [ -r /usr/local/bin/nanotun-ports.sh ]; then
  # shellcheck source=scripts/nanotun-ports.sh
  . /usr/local/bin/nanotun-ports.sh
  nanotun_load_ports "$ETC_DIR/config.toml" "$ETC_DIR/web.env"
fi

step_t "3. Remove the programs and the systemd units" "3. 删除程序与 systemd 单元"
for b in "${BINS[@]}"; do
  # 不 purge 时把 nanotun-uninstall 自己留下。
  #
  # 不留的话最后那句「连配置和数据库一起删:<本命令> --purge」指向的是一个刚被自己删掉的
  # 命令 —— 而那正是这条路径上最可能的下一步:先卸载看看,确认不要了,再回来清数据。
  # 留一个几 KB 的脚本,比让人去 /opt/nanotun/<版本>-<架构>/scripts/ 里翻要好。
  #
  # --purge 时照删:数据都没了,它也没有下一步可指了。
  if [ "$b" = nanotun-uninstall ] && [ "$PURGE" != 1 ]; then
    continue
  fi
  [ -e "/usr/local/bin/$b" ] \
    && run_t "delete /usr/local/bin/$b" "删 /usr/local/bin/$b" rm -f "/usr/local/bin/$b"
done
for u in "${UNITS[@]}"; do
  [ -f "/etc/systemd/system/$u" ] \
    && run_t "delete /etc/systemd/system/$u" "删 /etc/systemd/system/$u" rm -f "/etc/systemd/system/$u"
done
run "systemctl daemon-reload" systemctl daemon-reload
[ -S "$RUN_DIR/control.sock" ] \
  && run_t "delete $RUN_DIR/control.sock" "删 $RUN_DIR/control.sock" rm -f "$RUN_DIR/control.sock"

# ── 4. sysctl 与防火墙 ───────────────────────────────────────────────────────
step_t "4. Undo the sysctl drop-in and the firewall openings" "4. 撤销 sysctl 与防火墙放行"
if [ -f /etc/sysctl.d/99-nanotun.conf ]; then
  # 这个 drop-in 名义上是服务端装的,但 ip_forward 并不只有服务端在用:客户端做
  # **子网路由 / 出口节点**时同样靠它转发。所以机器上还有客户端时一律留着 ——
  # 多留一个开着转发的 drop-in 只是洁癖问题,删错了却会让正在经这台机器出网的客户端断流。
  if [ "$CLIENT_PRESENT" = 1 ]; then
    warn_t "Keeping /etc/sysctl.d/99-nanotun.conf — a client acting as a subnet router / exit node needs ip_forward=1 too." \
           "保留 /etc/sysctl.d/99-nanotun.conf —— 客户端做子网路由 / 出口节点时也需要 ip_forward=1。"
    warn_t "Once you are sure this machine no longer has to forward, remove that file yourself and run sysctl --system." \
           "确认这台机器不再需要转发,再自行删除该文件并 sysctl --system。"
  else
    run_t "delete /etc/sysctl.d/99-nanotun.conf" "删 /etc/sysctl.d/99-nanotun.conf" \
      rm -f /etc/sysctl.d/99-nanotun.conf
    run_t "sysctl --system (reload the remaining sysctl config)" "sysctl --system(重新载入其余 sysctl 配置)" \
      sysctl --system
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
      warn_t "Forwarding is still on: ${fwd_on# } — sysctl only rolls back config files, not values already in effect; the kernel default of 0 comes back at the next reboot." \
             "转发仍开着:${fwd_on# } —— sysctl 只回滚配置文件,不改已生效的运行值,重启后才回到内核默认 0。"
      warn_t "To turn it off right now (first make sure no docker / other VPN relies on it): ${fwd_cmd#; }" \
             "想立刻关掉(先确认没有 docker / 其它 VPN 靠着它):${fwd_cmd#; }"
    fi
  fi
fi
# 默认端口一并收:老版本(或改端口之前的那次安装)放行的就是它们,不收就是残留。
# ufw delete 对不存在的规则只是报一句没这条,不影响卸载。
#
# 去重:没改过端口的机器上实际值和默认值本来就相等,不去重的话同一条会被收两遍,
# 屏幕上「✓ ufw 收回 7443/tcp」连着出现两次 —— 功能上无害,但看的人会以为哪里不对。
_nt_uniq() { printf '%s\n' "$@" | awk 'NF && !seen[$0]++' | tr '\n' ' '; }
UNINSTALL_TCP="$(_nt_uniq "$NT_PORT_REALITY" "$NT_PORT_WEB" "$NT_DEFAULT_REALITY" "$NT_DEFAULT_WEB" $NT_LEGACY_TCP)"
UNINSTALL_UDP="$(_nt_uniq $NT_HY2_SPECS "$NT_DEFAULT_HY2")"
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
  for rule in $UNINSTALL_TCP; do
    run_t "ufw: withdraw $rule/tcp" "ufw 收回 $rule/tcp" ufw delete allow "$rule/tcp"
  done
  for rule in $UNINSTALL_UDP; do
    run_t "ufw: withdraw $rule/udp" "ufw 收回 $rule/udp" ufw delete allow "${rule/-/:}/udp"
  done
fi
# 安装那边对 firewalld 也自动放行(RHEL 系默认防火墙),这里就得对称收回 ——
# 否则卸干净之后机器上还留着三个对公网敞着的端口,而已经没有东西在听了。
if command -v firewall-cmd >/dev/null 2>&1 && [ "$(firewall-cmd --state 2>/dev/null)" = running ]; then
  for rule in $UNINSTALL_TCP; do
    firewall-cmd --permanent --remove-port="$rule/tcp" >/dev/null 2>&1 \
      && ok_t "firewalld: withdrew $rule/tcp" "firewalld 收回 $rule/tcp" || true
  done
  for rule in $UNINSTALL_UDP; do
    firewall-cmd --permanent --remove-port="$rule/udp" >/dev/null 2>&1 \
      && ok_t "firewalld: withdrew $rule/udp" "firewalld 收回 $rule/udp" || true
  done
  firewall-cmd --reload >/dev/null 2>&1 || true
fi

# ── 5. 配置与数据 ────────────────────────────────────────────────────────────
if [ "$PURGE" = 1 ]; then
  step_t "5. Delete config, certificates and the database (--purge)" "5. 删除配置、证书与数据库(--purge)"
  for f in "${PURGE_FILES[@]}"; do
    [ -e "$f" ] && run_t "delete $f" "删 $f" rm -f "$f"
  done
  for g in "${PURGE_GLOBS[@]}"; do
    for f in $g; do [ -e "$f" ] && run_t "delete $f" "删 $f" rm -f "$f"; done
  done
  for d in "${PURGE_DIRS[@]}"; do
    [ -d "$d" ] && run_t "delete $d/" "删 $d/" rm -rf "$d"
  done
  # rmdir 而不是 rm -rf:客户端的 device_id / tun_name 还在的话目录就该留着,
  # 而 rmdir 在非空时会失败 —— 这里要的正是这个「删不掉就别删」。
  for d in "$ETC_DIR" "$LIB_DIR" "$RUN_DIR"; do
    if [ -d "$d" ]; then
      if [ "$DRY" = 1 ]; then
        printf '    + [dry-run] %s\n' \
          "$(tsel "remove $d itself if it ends up empty" "若 $d 已空则删除该目录")"
      elif rmdir "$d" 2>/dev/null; then
        ok_t "deleted $d/ (it was empty)" "删 $d/(已空)"
      else
        # 「别人的文件」= 不是服务端放的。上面那份清单漏一个文件,漏掉的那个就会在这里
        # 被报成别人的 —— 所以这句话的可信度直接取决于清单是不是全的。
        left="$(ls -A "$d" 2>/dev/null | tr '\n' ' ')"
        ok_t "kept $d/ (it still holds files that are not ours: $left)" \
             "保留 $d/(还有别人的文件:$left)"
      fi
    fi
  done
else
  step_t "5. Config and data: kept" "5. 配置与数据:保留"
  for p in "$ETC_DIR/config.toml" "$ETC_DIR/certs" "$LIB_DIR/nanotun.db"; do
    [ -e "$p" ] && ok_t "kept $p" "保留 $p"
  done
  printf '    %s\n' "$(tsel "To delete these as well: $0 --purge" "连这些一起删:$0 --purge")"
fi

step_t "Done" "完成"
# 第 0 步已经如实说过「没找到已安装的服务端」,但那是十几行之前;人照着做的是这一句。
# 原来它无条件宣布「服务端已卸载」—— 在一台本来就没装过的机器上跑(手滑、或者已经卸过
# 一遍了),屏幕上就是一句凭空的战果。--purge 那句更容易吓人:说「配置与数据也已删除」,
# 而其实什么都没有,人会当真去找自己的库哪去了。
if [ "$DRY" = 1 ]; then
  printf '    %s\n' "$(tsel \
    "This was a dry-run — nothing was touched." \
    "这是 dry-run,什么都没动。")"
elif [ "$FOUND_SERVER" = 0 ]; then
  printf '    %s\n' "$(tsel \
    "There was no server on this machine to begin with. Any leftovers that did need clearing have been cleared." \
    "这台机器上本来就没有服务端。该清的残留(如果有)已经清了。")"
elif [ "$PURGE" = 1 ]; then
  printf '    %s\n' "$(tsel \
    "The server is uninstalled, and config and data are deleted as well." \
    "服务端已卸载,配置与数据也已删除。")"
else
  printf '    %s\n' "$(tsel \
    "The server is uninstalled. Config and database are still here — install again and you pick up where you left off." \
    "服务端已卸载。配置与数据库还在,重新装一遍就能接着用。")"
fi
[ "$CLIENT_PRESENT" = 1 ] && printf '    %s\n' "$(tsel \
  "The client was not affected." "客户端未受影响。")"
exit 0
