#!/usr/bin/env bash
# nanotun 开服向导 —— 在 install-self-hosted.sh 之后跑,把「服务起来了」变成「客户端能连」。
#
#   sudo ./scripts/setup.sh
#
# 安装脚本负责的是机器这一侧:二进制、systemd、密钥、防火墙、第一个 VPN 管理员。
# 它跑完之后服务确实在跑,但客户端还连不上,因为还差三件只有你知道答案的事:
#
#   1. 客户端该往哪个地址拨(server_dial_host)—— 安装脚本猜不到你的域名;
#   2. Web 后台的第一个管理员 —— 只能在浏览器上创建,而且跟 VPN 的 PSK 是两套账号;
#   3. 给用户的两个二维码 —— profile(服务器配置,可公开)+ credentials(凭证,机密)。
#
# 这三件事以前全靠读文档,这个脚本把它们串起来。
#
# 幂等:重复跑安全。已设过的值会显示出来让你选择保留,不会重置 PSK、不会动 config.toml、
# 不会重跑 init。想只加一个用户,重跑一遍在前两步回车跳过即可。
#
# 可脚本化(自动化部署用):
#   sudo ./scripts/setup.sh --dial-host vpn.example.com --user alice --yes
#   sudo ./scripts/setup.sh --dial-host 203.0.113.10 --no-user --yes
set -euo pipefail

ETC_DIR=/etc/nanotun
LIB_DIR=/var/lib/nanotun
DB="$LIB_DIR/nanotun.db"
ADMIN=/usr/local/bin/nanotun-admin
WEB_BIN=/usr/local/bin/nanotun-web
CONTROL_SOCK=/run/nanotun/control.sock
WEB_PORT=7443
QR_DIR="$LIB_DIR/qr"

OPT_DIAL_HOST=""
OPT_USER=""
OPT_NO_USER=0
ASSUME_YES=0

# ── 输出 ─────────────────────────────────────────────────────────────────────
if [ -t 1 ]; then
  C_STEP=$'\033[1;36m'; C_OK=$'\033[1;32m'; C_WARN=$'\033[1;33m'
  C_ERR=$'\033[1;31m'; C_DIM=$'\033[2m'; C_OFF=$'\033[0m'
else
  C_STEP=''; C_OK=''; C_WARN=''; C_ERR=''; C_DIM=''; C_OFF=''
fi

step() { printf '\n%s==> %s%s\n' "$C_STEP" "$*" "$C_OFF"; }
ok()   { printf '    %s✓%s %s\n' "$C_OK" "$C_OFF" "$*"; }
warn() { printf '    %s!%s %s\n' "$C_WARN" "$C_OFF" "$*"; }
note() { printf '    %s%s%s\n' "$C_DIM" "$*" "$C_OFF"; }
die()  { printf '%sFATAL: %s%s\n' "$C_ERR" "$*" "$C_OFF" >&2; exit 1; }

usage() {
  # 按实际被调用的名字来写。安装脚本会把本文件装成 /usr/local/bin/nanotun-setup,
  # 而把它装成命令的理由恰恰是「解压出来的发布包目录用完就删了」—— 那时候再让
  # 帮助里写 ./scripts/setup.sh,等于指着一个已经不存在的路径。
  local me; me="$(basename "$0")"
  case "$me" in
    setup.sh) me="./scripts/setup.sh" ;;
  esac
  cat <<EOF
用法: sudo ${me} [选项]

nanotun 开服向导:设置客户端拨号地址、引导创建 Web 管理员、创建首个用户并出二维码。
在 install-self-hosted.sh 之后跑。重复跑是安全的。

选项:
  --dial-host HOST   客户端拨号地址(域名或 IP,不带端口/协议),跳过交互询问
  --user NAME        创建这个 VPN 用户并出二维码
  --no-user          跳过创建用户那一步
  -y, --yes          不再交互,全部走默认值(必须配合 --dial-host)
  -h, --help         显示本帮助

例:
  sudo ${me}
  sudo ${me} --dial-host vpn.example.com --user alice --yes
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --dial-host) OPT_DIAL_HOST="${2:-}"; shift 2 ;;
    --user)      OPT_USER="${2:-}"; shift 2 ;;
    --no-user)   OPT_NO_USER=1; shift ;;
    -y|--yes)    ASSUME_YES=1; shift ;;
    -h|--help)   usage; exit 0 ;;
    *) printf 'FATAL: 未知参数: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

# ── 交互助手 ─────────────────────────────────────────────────────────────────
# 提示写 stderr:调用方用 $(ask ...) 取值时,stdout 上只能有答案本身。
ask() { # ask <提示> [默认值]
  local prompt="$1" default="${2:-}" reply
  if [ "$ASSUME_YES" = 1 ]; then printf '%s' "$default"; return; fi
  if [ -n "$default" ]; then
    printf '    %s [%s]: ' "$prompt" "$default" >&2
  else
    printf '    %s: ' "$prompt" >&2
  fi
  # read 失败 = stdin 到了 EOF。必须当场退出:调用方大多在 while 里重问,
  # 而 EOF 之后每次 read 都立刻失败,吞掉错误就变成刷屏的死循环。
  IFS= read -r reply || die "输入意外结束(stdin EOF),向导中止。"
  printf '%s' "${reply:-$default}"
}

confirm() { # confirm <提示> [y|n 默认]
  local prompt="$1" def="${2:-y}" reply hint
  if [ "$def" = y ]; then hint="Y/n"; else hint="y/N"; fi
  if [ "$ASSUME_YES" = 1 ]; then [ "$def" = y ]; return; fi
  while true; do
    printf '    %s [%s]: ' "$prompt" "$hint" >&2
    IFS= read -r reply || die "输入意外结束(stdin EOF),向导中止。"
    reply="$(printf '%s' "${reply:-$def}" | tr '[:upper:]' '[:lower:]')"
    case "$reply" in y|yes) return 0 ;; n|no) return 1 ;; esac
  done
}

# JSON 取值。有 jq 用 jq,没有就退回 sed —— 服务器上装 jq 不是本项目该强加的依赖。
# sed 那条走的是「缩进 JSON 每个字段独占一行」的前提,printJSON 正是这么输出的。
json_field() { # json_field <字段名>,JSON 从 stdin 读
  local key="$1" input
  input="$(cat)"
  if command -v jq >/dev/null 2>&1; then
    printf '%s' "$input" | jq -r --arg k "$key" '.[$k] // empty' 2>/dev/null
  else
    printf '%s' "$input" | sed -n 's/.*"'"$key"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1
  fi
}

# nanotun-admin 默认输出英文(main.go 的 langDefault),而这个向导从头到尾是中文。
# 不对齐的话,最需要看懂的那一刻反而蹦出英文 —— 比如把 127.0.0.1 填进拨号地址时:
#   ✗ syntax validation failed: loopback "127.0.0.1" ... clients cannot dial this address externally
# 夹在中文提示中间。自己显式设过 NANOTUN_LANG 的按你的来。
#
# 切语言不会影响脚本对输出的解析:这里读的要么是 --json(键名与语言无关),要么是
# setting get 的原始值;user list 那张表两种语言下逐字一致(表格不本地化)。
export NANOTUN_LANG="${NANOTUN_LANG:-zh}"

# nanotun-admin 包装:--db-path 一定要显式传。
# 它的默认值是**相对 cwd** 的 data/nanotun.db —— 忘了传不会报错,而是在当前目录
# 建一个空库然后在里面查不到任何用户,现象是「刚建的用户不见了」。
admin() { "$ADMIN" --db-path "$DB" "$@"; }

# 放得下才打二维码。
#
# qrterminal 一个模块画成「两个空格 + ANSI 背景色」,所以终端列宽 = 模块数 × 2。
# 它没用 ▀▄ 半块字符(那样只要一列),是因为半块的前景色会随终端主题反转,深色
# 终端下扫不出来 —— 这个取舍在 cmd_profile_qr.go 里有说明,改不动。
#
# 于是 profile 二维码是真的画不下:payload 含 hy2 mTLS 证书+私钥,逼近 QR v40,
# 175 个模块 = 350 列。2026-08-03 在 Vultr 实测确认。往 80 列的 SSH 窗口里打,
# 每行折成四五段,拼出来是一团噪点 —— 不但扫不了,还会把前面的输出全顶出屏幕。
# 所以先渲染到变量里量出真实宽度,放得下才打,放不下就走 PNG。
qr_if_fits() { # qr_if_fits <admin 参数...>;放下并打印返回 0,太宽返回 2,生成失败返回 1
  local out cols term
  out="$(admin "$@" 2>/dev/null)" || return 1
  [ -n "$out" ] || return 1
  # 去掉 ANSI 转义后,每个模块正好剩两个空格,所以最长行的字符数就是显示列宽
  cols="$(printf '%s\n' "$out" | sed $'s/\033\\[[0-9;]*m//g' \
          | awk '{ if (length($0) > m) m = length($0) } END { print m+0 }')"
  term="${COLUMNS:-$(tput cols 2>/dev/null || echo 80)}"
  if [ "$cols" -gt 0 ] && [ "$cols" -le "$term" ]; then
    printf '%s\n' "$out"
    return 0
  fi
  warn "二维码要 ${cols} 列才画得下,当前终端 ${term} 列 —— 硬打会折行成噪点,跳过。"
  return 2
}

# ── 0. 前置检查 ──────────────────────────────────────────────────────────────
step "0. 检查安装状态"

[ "$(id -u)" = 0 ] || die "需要 root(要读 $DB 和控制面 socket)。请用 sudo 跑。"

[ -x "$ADMIN" ] || die "找不到 $ADMIN —— 先跑 scripts/install-self-hosted.sh 完成安装。"
[ -f "$DB" ]    || die "找不到数据库 $DB —— 先跑 scripts/install-self-hosted.sh 完成安装。"
ok "已安装:$(admin version 2>/dev/null | head -1 || echo 'nanotun-admin(版本未知)')"

if [ "$ASSUME_YES" = 0 ] && [ ! -t 0 ]; then
  die "stdin 不是终端,无法交互。脚本化请加 --yes 并显式给出 --dial-host。"
fi
if [ "$ASSUME_YES" = 1 ] && [ -z "$OPT_DIAL_HOST" ]; then
  die "--yes 必须配合 --dial-host(拨号地址没有安全的默认值可猜)。"
fi

# 等守护进程真的就绪再动用户数据。nanotun.service 是 Type=notify,active 基本等于
# 已经 READY=1;控制面 socket 存在是更硬的证据,两个都试。
daemon_ready=0
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet nanotun.service 2>/dev/null; then
  daemon_ready=1
elif [ -S "$CONTROL_SOCK" ]; then
  daemon_ready=1
fi

if [ "$daemon_ready" = 1 ]; then
  ok "nanotund 正在运行"
else
  warn "nanotund 似乎没在运行(systemctl is-active nanotun.service 不是 active)"
  note "向导本身只读写数据库,不需要它在跑;但客户端连不上。稍后排查:"
  note "  systemctl status nanotun --no-pager && journalctl -u nanotun -n 50"
fi

WEB_AVAILABLE=0
if [ -x "$WEB_BIN" ]; then
  WEB_AVAILABLE=1
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet nanotun-web.service 2>/dev/null; then
    ok "nanotun-web 正在运行(:$WEB_PORT)"
  else
    warn "装了 nanotun-web 但服务未运行,Web 后台暂时打不开"
  fi
else
  note "未安装 nanotun-web,跳过 Web 后台相关步骤(命令行一样能完成全部操作)"
fi

# ── 1. 客户端拨号地址 ────────────────────────────────────────────────────────
step "1. 客户端拨号地址(server_dial_host)"

note "客户端往哪个地址拨。填公网域名或公网 IP,**不要**带 http:// 和端口号。"
note "有域名就用域名 —— 换服务器时只改 DNS,已发出去的二维码不用重发。"

current_dial="$(admin setting get server_dial_host 2>/dev/null || true)"
if [ -n "$current_dial" ]; then
  ok "当前已设置为: $current_dial"
fi

# 猜一个默认值方便回车。公网 IP 得问外部服务 —— NAT 后面的机器上 `ip route get`
# 拿到的是内网地址,填进去客户端根本连不上,所以宁可不猜也不能猜错。
guess=""
if [ -z "$current_dial" ] && [ -z "$OPT_DIAL_HOST" ] && [ "$ASSUME_YES" = 0 ]; then
  for svc in https://api.ipify.org https://ifconfig.me/ip; do
    guess="$(curl -fsS --max-time 5 "$svc" 2>/dev/null | tr -d '[:space:]' || true)"
    case "$guess" in
      *[!0-9.]*|"") guess="" ;;   # 只接受点分十进制,拿到 HTML 之类一律丢弃
      *) break ;;
    esac
  done
  [ -n "$guess" ] && note "探测到本机公网 IP: $guess(仅作默认值,有域名请填域名)"
fi

dial_host="$OPT_DIAL_HOST"
while :; do
  if [ -z "$dial_host" ]; then
    dial_host="$(ask "拨号地址" "${current_dial:-$guess}")"
  fi

  if [ -z "$dial_host" ]; then
    warn "不能为空 —— 没有它客户端不知道往哪连,Web 后台也拒绝生成服务器二维码。"
    continue
  fi

  if [ "$dial_host" = "$current_dial" ]; then
    ok "保持不变: $dial_host"
    break
  fi

  # probe 只做语法 + DNS + ICMP,不写库。ICMP 不通很常见(云厂商默认封 ping),
  # 所以失败不当致命,让人自己判断。
  #
  # 三类失败的退出码是同一个,靠**判词前缀**区分 —— 这是 cmd_setting.go 明写的约定
  # (「不细分自定义 exit code,避免与全局 main 退出码语义打架」):
  #     ✗ = 硬错(语法 / DNS / 探测异常)   ⚠ = ICMP 软失败,且只有这一种
  # 两个语言目录里前缀一致,所以这里认符号不认中文。
  #
  # stdout 与 stderr 分开收:判词走 stdout,而 main 会把同一个 error 再往 stderr 打
  # 一遍,合在一起就是同一句话说两遍 —— 偏偏是在最需要看清楚的时刻。
  printf '\n'
  probe_rc=0
  probe_err_file="$(mktemp)" \
    || die "创建临时文件失败 —— ${TMPDIR:-/tmp} 写不进去(权限 / 只读 / 空间不足)。"
  probe_out="$(admin setting probe-dial-host "$dial_host" --timeout 10s 2>"$probe_err_file")" \
    || probe_rc=$?
  probe_err="$(cat "$probe_err_file")"; rm -f "$probe_err_file"
  if [ -n "$probe_out" ]; then
    printf '%s\n' "$probe_out"
  elif [ -n "$probe_err" ]; then
    # 判词一个字都没打出来(用法错、二进制炸了之类),这时 stderr 是唯一线索,不能吞。
    printf '%s\n' "$probe_err"
  fi

  if [ "$probe_rc" = 0 ]; then
    printf '\n'
    if admin setting set server_dial_host "$dial_host" >/dev/null; then
      ok "已写入 server_dial_host = $dial_host"
      current_dial="$dial_host"
      break
    fi
    die "写入失败,见上面的报错。"
  fi

  printf '\n'
  # 默认值必须跟建议一致。原来不分失败类型一律默认 N:向导前脚说「ICMP 不通通常
  # 没关系」,后脚问「仍然使用? [y/N]」—— 在云上填了**正确**公网 IP 的人顺手回车,
  # 就被打回去重填,再填还是同一个结果。而 ICMP 被安全组封恰恰是最常见的情况。
  if printf '%s' "$probe_out" | grep -q '⚠'; then
    use_default=y
    warn "只有 ICMP 没通 —— 云厂商默认封 ping(Vultr / AWS / 阿里云安全组都这样),"
    warn "这不代表 VPN 端口不通。地址没填错的话直接继续即可。"
  else
    use_default=n
    warn "探测没过,而且不是 ICMP 那种软失败:语法错必须改;"
    warn "DNS 不通说明域名还没解析到这台机器。"
  fi

  # 非交互模式下不能退回去重问(没人回答,只会死循环)。既然地址是命令行显式给的,
  # 就当操作者已经确认过:探测失败降级为告警,直接尝试写入。
  # 真正非法的值会被 setting set 自己的校验拦下并致命退出,所以这里不会把垃圾值
  # 悄悄写进库 —— DNS/ICMP 放过,语法不放过。
  if [ "$ASSUME_YES" = 1 ]; then
    warn "--yes:按命令行给定的值继续。"
    if admin setting set server_dial_host "$dial_host" >/dev/null; then
      ok "已写入 server_dial_host = $dial_host"
      current_dial="$dial_host"
      break
    fi
    die "写入失败 —— 原因见上面那行校验报错。"
  fi

  if confirm "仍然使用 $dial_host ?" "$use_default"; then
    if admin setting set server_dial_host "$dial_host" >/dev/null; then
      ok "已写入 server_dial_host = $dial_host"
      current_dial="$dial_host"
      break
    fi
    # 别在这里替校验下结论。setting set 拒绝的理由不止一种(回环 / 私网地址、
    # 带端口、带 http:// 前缀、域名本身不合法……),而它已经把真实原因打在上一行了。
    # 原来这句写死「不能带端口 / 协议头」,填 127.0.0.1 时屏幕上就是自相矛盾的两行:
    # 上一行说是回环地址,紧接着的红字说是端口/协议头 —— 而红字最后出现、最显眼。
    die "写入失败 —— 原因见上面那行校验报错,换一个再试。"
  fi
  dial_host=""
  OPT_DIAL_HOST=""
done

# ── 2. Web 后台管理员 ────────────────────────────────────────────────────────
step "2. Web 后台管理员"

if [ "$WEB_AVAILABLE" = 1 ]; then
  note "注意这跟 VPN 账号是**两套东西**,最容易搞混的一步:"
  note "  · VPN 用户 + PSK  —— 客户端登录用,安装时已建了一个 admin"
  note "  · Web 后台管理员  —— 浏览器登录用,密码你现在设,只能在网页上创建"
  printf '\n'
  printf '    打开: %shttps://%s:%s/setup%s\n' "$C_OK" "$current_dial" "$WEB_PORT" "$C_OFF"
  printf '\n'
  note "证书是自签的,浏览器会警告,确认地址无误后继续访问即可。"
  warn "尽快去建 —— 在第一个管理员出现之前,谁先打开 /setup 谁就是管理员。"
  note "机器暴露在公网且你暂时不想建的话,先把 $WEB_PORT 端口关掉:ufw deny $WEB_PORT/tcp"
  [ "$ASSUME_YES" = 0 ] && confirm "已经建好了(或稍后再说),继续?" y >/dev/null || true
else
  note "未安装 Web 后台。用户管理全部走命令行:nanotun-admin --db-path $DB ..."
fi

# ── 3. 首个 VPN 用户 + 二维码 ────────────────────────────────────────────────
step "3. 创建 VPN 用户并生成二维码"

if [ "$OPT_NO_USER" = 1 ]; then
  note "--no-user,跳过。"
else
  note "客户端需要扫**两个**二维码,这是刻意拆开的:"
  note "  · profile     服务器地址与传输配置,不含密钥,可以公开传"
  note "  · credentials 用户名 + PSK,机密,只能一对一给本人"
  printf '\n'

  username="$OPT_USER"
  if [ -z "$username" ]; then
    if confirm "现在创建一个 VPN 用户?" y; then
      username="$(ask "用户名" "alice")"
    fi
  fi

  if [ -n "$username" ]; then
    create_out=""
    if create_out="$(admin --json user create "$username" 2>&1)"; then
      psk="$(printf '%s' "$create_out" | json_field psk)"
      [ -n "$psk" ] || die "用户建好了但没能从输出里取出 PSK,原始输出:
$create_out"
      ok "已创建用户 $username"

      mkdir -p "$QR_DIR"; chmod 0700 "$QR_DIR"

      # profile QR:不含 PSK,公开也无所谓。
      # --dial-host 必须显式传 —— CLI 不会去读刚写进库的那个 setting。
      #
      # 先用 --format json 探一次:profile 要从 config.toml 读 REALITY 私钥、hy2 口令、
      # mTLS CA,任何一项不对都生成不出来。直接跑 qr 的话报错会混在二维码输出里,
      # 而失败原因(比如私钥还是 REPLACE_WITH_* 占位)恰恰是唯一有用的信息。
      printf '\n%s── profile 二维码(服务器配置,可公开)──%s\n\n' "$C_STEP" "$C_OFF"
      if prof_err="$(admin profile show "$username" --dial-host "$current_dial" --format json 2>&1 >/dev/null)"; then
        prof_png="$QR_DIR/${username}-profile.png"
        # PNG 先出:profile 的终端二维码基本上一定超宽,PNG 才是真正能用的那份
        if admin profile show "$username" --dial-host "$current_dial" \
             --format qr-png --output "$prof_png" --force >/dev/null 2>&1; then
          ok "PNG: $prof_png"
        else
          prof_png=""
          warn "PNG 生成失败"
        fi
        # set -e 下不能裸调:返回 2(太宽)会直接终止脚本
        prof_qr_rc=0
        qr_if_fits profile show "$username" --dial-host "$current_dial" --format qr || prof_qr_rc=$?
        if [ "$prof_qr_rc" -eq 2 ]; then
          note "profile 里带着 hy2 的 mTLS 证书,数据量顶到 QR 上限,终端画不下是常态。"
          if [ -n "$prof_png" ]; then
            note "把 PNG 取到本地扫(在你自己的电脑上跑):"
            note "  scp root@${current_dial}:${prof_png} ."
            note "装了 Web 后台的话,登录后也能直接在页面上看这个二维码。"
          fi
        fi
      else
        warn "profile 生成失败,这个二维码出不来:"
        printf '%s\n' "$prof_err" | sed 's/^/        /'
        note "多半是 $ETC_DIR/config.toml 里还留着 REPLACE_WITH_* 占位 ——"
        note "正常安装时 install-self-hosted.sh 会替换掉它们。补救:"
        note "  grep -n REPLACE_WITH $ETC_DIR/config.toml"
        note "credentials 二维码不依赖 config.toml,下面照常生成。"
      fi

      # credentials QR:含 PSK 明文。默认只打在终端,不落盘。
      #
      # 下面这条会让 CLI 打一句「--psk 在命令行上会经 /proc/<pid>/cmdline 泄露」的警告。
      # 是真的,但这里绕不开:要同时给出二维码**和**可手抄的明文,只有 --psk 这一条路
      # (--rotate-psk 不用把密钥放进 argv,可它只吐二维码,不单独回显明文)。
      # 暴露窗口是这一次 exec 的百来毫秒,且脚本里的变量不进 shell history。
      printf '\n%s── credentials 二维码(含 PSK,机密)──%s\n\n' "$C_STEP" "$C_OFF"
      note "(下面那句 --psk 泄露警告是预期内的,原因见本脚本此处注释)"
      # 这个 payload 小得多(URL ~330 字节 → 71 模块 = 142 列),宽终端里打得下;
      # 打不下也不要紧,下面照样回显 PSK 明文,可以手动输入。
      cred_qr_rc=0
      qr_if_fits credentials show "$username" --psk "$psk" --format qr || cred_qr_rc=$?
      [ "$cred_qr_rc" -eq 1 ] && warn "终端二维码生成失败,可用下面的 PSK 手动重出"
      [ "$cred_qr_rc" -eq 2 ] && note "把窗口拉宽到上面那个列数再重跑就能直接显示;或者存成 PNG(下面会问)。"
      true   # 上面两个 [ ] 都不成立时整体为假,set -e 会误杀

      printf '\n'
      printf '    PSK: %s%s%s\n' "$C_WARN" "$psk" "$C_OFF"
      if [ "$cred_qr_rc" -eq 0 ]; then
        warn "这是 PSK 明文**唯一**一次出现。抄走它,或者现在就把上面的二维码给用户扫。"
      else
        warn "这是 PSK 明文**唯一**一次出现,而且上面的二维码没能显示 —— 现在就抄走。"
      fi
      note "丢了也不是死局,但要轮换(会把该用户已在线的会话踢下去):"
      note "  nanotun-admin --db-path $DB --yes credentials show $username --rotate-psk --format qr"

      if [ "$ASSUME_YES" = 0 ] && confirm "把 credentials 也存成 PNG 文件?(含密钥,用完请删)" n; then
        if admin credentials show "$username" --psk "$psk" \
             --format qr-png --output "$QR_DIR/${username}-cred.png" --force >/dev/null 2>&1; then
          chmod 0600 "$QR_DIR/${username}-cred.png"
          ok "PNG: $QR_DIR/${username}-cred.png (0600)"
          warn "这个文件里就是密钥本身。传给用户之后立刻 rm 掉,别留在服务器上。"
        else
          warn "PNG 生成失败"
        fi
      fi
    else
      case "$create_out" in
        *nique*|*uplicate*|*已存在*)
          warn "用户 $username 已存在,没有重复创建。"
          note "要给已存在的用户重出凭证二维码(会轮换 PSK 并踢掉其在线会话):"
          note "  nanotun-admin --db-path $DB --yes credentials show $username --rotate-psk --format qr"
          ;;
        *) die "创建用户失败:
$create_out" ;;
      esac
    fi
  else
    note "跳过。之后手动创建:nanotun-admin --db-path $DB user create <名字>"
  fi
fi

# ── 收尾 ─────────────────────────────────────────────────────────────────────
step "完成"

printf '    拨号地址   %s\n' "${current_dial:-未设置}"
if [ "$WEB_AVAILABLE" = 1 ]; then
  printf '    Web 后台   https://%s:%s\n' "$current_dial" "$WEB_PORT"
fi
printf '    数据库     %s\n' "$DB"
printf '    配置       %s/config.toml\n' "$ETC_DIR"
printf '\n'
note "常用命令(都要带 --db-path,否则会去读 cwd 下的空库):"
note "  nanotun-admin --db-path $DB user list"
note "  nanotun-admin --db-path $DB connection list"
note "  journalctl -u nanotun -f"
printf '\n'
note "客户端连不上时先确认防火墙:REALITY 8443/tcp、hysteria2 443/udp 要能从公网进来。"
note "云服务器还要在厂商的安全组里放行 —— ufw 放了不等于安全组放了。"
