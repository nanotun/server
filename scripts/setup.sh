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
#   3. 给用户的两个二维码 —— profile(服务器配置 + 客户端证书)+ credentials(凭证,机密)。
#
# 这三件事以前全靠读文档,这个脚本把它们串起来。
#
# 幂等:重复跑安全。已设过的值会显示出来让你选择保留,不会重置 PSK、不会重跑 init。
# 默认也**不动 config.toml** —— 唯一例外是你在「MagicDNS 后缀」那步显式改了后缀(或带
# --magic-suffix):那会备份→段感知改写→重启 nanotund(失败自动回滚)。回车保留则纹丝不动。
# 想只加一个用户,重跑一遍在前几步回车跳过即可。
#
# 可脚本化(自动化部署用):
#   sudo ./scripts/setup.sh --dial-host vpn.example.com --user alice --yes
#   sudo ./scripts/setup.sh --dial-host 203.0.113.10 --no-user --yes
#   sudo ./scripts/setup.sh --magic-suffix nanotun --yes      # 只改 MagicDNS 后缀并重启
set -euo pipefail

# 装成 /usr/local/bin/nanotun-setup 时,同目录就有 nanotun-set-suffix;从发布包/仓库直接
# 跑时,同目录有 set-magic-suffix.sh。「MagicDNS 后缀」那步据此定位改后缀的工具(见 resolve_suffix_tool)。
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 向导也会落文件(web.env、二维码 PNG),同样不看调用者的 umask —— 它装成
# /usr/local/bin/nanotun-setup,谁都可能在自己的环境里直接敲。
umask 022

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
OPT_WEB_ADMIN=""
OPT_MAGIC_SUFFIX=""
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

nanotun 开服向导:设置客户端拨号地址、创建 Web 后台管理员、创建首个用户并出二维码。
在 install-self-hosted.sh 之后跑。重复跑是安全的。

选项:
  --dial-host HOST   客户端拨号地址(域名或 IP,不带端口/协议),跳过交互询问
  --user NAME        创建这个 VPN 用户并出二维码
  --no-user          跳过创建用户那一步
  --web-admin NAME   Web 后台管理员用户名(密码见下面的环境变量)
  --magic-suffix SFX MagicDNS 局域网后缀(客户端解析 *.<后缀> → mesh 虚拟 IP),默认 lan。
                     只在与现值不同时才改:备份→段感知改写 config.toml→重启 nanotund
                     (失败自动回滚)。不给这个参数时,交互模式会显示现值让你选择保留。
  -y, --yes          不再交互,全部走默认值(全新机器必须配合 --dial-host;
                     已配过的机器不给就沿用现有值)
  -h, --help         显示本帮助

环境变量:
  NANOTUN_WEB_ADMIN_PASSWORD   Web 后台密码。故意不做成命令行参数 —— argv 对同机
                               所有用户可见(ps),还会落进 shell history。
                               --yes 下不给它就随机生成一个并打出来。

例:
  sudo ${me}
  sudo ${me} --dial-host vpn.example.com --user alice --yes
  sudo NANOTUN_WEB_ADMIN_PASSWORD='...' ${me} --dial-host vpn.example.com \\
       --user alice --web-admin ops --yes
EOF
}

# need_val <参数名> <值> —— 取值,没给就当场说清楚。
#
# 原来这几个带值的参数一律 `OPT_X="${2:-}"; shift 2`。少打一个值(`--user` 结尾、
# 或者 `--web-admin` 后面忘了名字)时,shift 2 在只剩一个参数时返回非零,撞上 set -e
# 就地退出 —— 退出码 1,**屏幕上一个字都没有**。人看到的是「什么都没发生」,
# 而真正的原因是自己少打了一个词。
need_val() {
  case "${2:-}" in
    ''|-*) die "$1 后面要跟一个值。例:$1 <值>" ;;
  esac
  printf '%s' "$2"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --dial-host) OPT_DIAL_HOST="$(need_val "$1" "${2:-}")"; shift 2 ;;
    --user)      OPT_USER="$(need_val "$1" "${2:-}")"; shift 2 ;;
    --no-user)   OPT_NO_USER=1; shift ;;
    # 密码只从环境变量 NANOTUN_WEB_ADMIN_PASSWORD 读,故意**不做** --web-admin-password:
    # 命令行参数会进 argv,同机任何用户 ps 一眼就看见,还会落进 shell history 和 journal。
    --web-admin) OPT_WEB_ADMIN="$(need_val "$1" "${2:-}")"; shift 2 ;;
    --magic-suffix) OPT_MAGIC_SUFFIX="$(need_val "$1" "${2:-}")"; shift 2 ;;
    -y|--yes)    ASSUME_YES=1; shift ;;
    -h|--help)   usage; exit 0 ;;
    # 点名是谁在说话:install.sh 会把自己不认得的参数原样转交本向导,所以这行
    # 也可能是在一条 `curl … | sudo bash -s -- …` 里冒出来的。只说「未知参数」的话,
    # 读的人不知道该去查 install.sh 的 flag 还是向导的。
    *) printf 'FATAL: %s: 未知参数: %s\n\n' "$(basename -- "${0:-nanotun-setup}")" "$1" >&2; usage >&2; exit 2 ;;
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
    # 先去空白再判空:答 "y " 或从别处粘进来带 \r 的都该算数,而只敲了个空格
    # 应当与直接回车同义(人的本意就是「用默认的」)。
    reply="$(printf '%s' "$reply" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')"
    [ -n "$reply" ] || reply="$def"
    case "$reply" in y|yes) return 0 ;; n|no) return 1 ;; esac
    # 不认识的答案原样重问,屏幕上就只是同一句话又出现一遍 —— 没人知道是自己答错了
    # 还是终端卡住了(实测连问七遍的样子和死循环没有区别)。说破再问。
    printf '    %s! 不认识「%s」,只能答 y 或 n(直接回车 = %s)%s\n' "$C_WARN" "$reply" "$def" "$C_OFF" >&2
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

# 告诉 nanotun-admin「你是被向导调起来的」。
#
# 只影响一处:建首位管理员时它会讲一段「/setup 的关闭只记在库里,库丢了就重新敞开,
# 要自己往 web.env 钉一行」。那话对着裸敲 CLI 的人是对的,对着这里就不是 —— 下面的
# close_setup_gate 紧接着就把那行钉上并报「已永久关闭」。不区分的话,主路径上会先
# 警告一遍再自己否掉,读的人不知道该信哪句。
export NANOTUN_SETUP_WIZARD=1

# nanotun-admin 包装:--db-path 一定要显式传。
#
# 不传时它也能自己找到装好的库,但那个回退有个前提 —— 当前目录下没有 data/nanotun.db,
# 有就用那个。向导是 sudo 起来的,cwd 是谁的当前目录不好说,不该把开服这一步押在上面。
admin() { "$ADMIN" --db-path "$DB" "$@"; }

# 定位改 MagicDNS 后缀的工具。装成命令时它就在 /usr/local/bin/nanotun-set-suffix(install
# -self-hosted.sh 装的);从发布包/仓库直接跑时是同目录的 set-magic-suffix.sh。找不到就返回非零。
# 它内部做:校验后缀→读现值(相同则 no-op)→备份→段感知改写 config.toml→重启→轮询,
# 失败自动回滚。故这里只负责选路,真正的安全保证在那份脚本里(单一真源)。
resolve_suffix_tool() {
  local c
  for c in /usr/local/bin/nanotun-set-suffix "$HERE/set-magic-suffix.sh"; do
    [ -x "$c" ] && { printf '%s' "$c"; return 0; }
  done
  return 1
}

# 读 config.toml 里现有的 MagicDNS 后缀。空白类用 [ \t] 而非 [[:space:]]:mawk 1.3.3
# (老 Ubuntu/Debian 默认 awk)不认 POSIX 字符类,会永不匹配(与 set-magic-suffix.sh 同口径)。
# 配置里没写该行 → 运行期兜底为 lan(resolveMagicDNSConfig 的默认),这里也回落 lan。
current_magic_suffix() {
  local v
  v="$(awk -F'"' '/^[ \t]*domain_suffix[ \t]*=/{print $2; exit}' "$ETC_DIR/config.toml" 2>/dev/null || true)"
  printf '%s' "${v:-lan}"
}

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
  # 全新机器上确实没得猜。但这台机器要是已经配过,那个值就是最安全的默认值 ——
  # 交互模式在这种情况下的行为正是「回车即保留」,--yes 没有理由更严。
  # 之前一律致命,于是「重跑一行命令升级」这条路在 --yes 下必然以 exit 1 收场:
  # 装其实成功了,自动化却读成失败,人还得回去翻当初填的是什么再原样敲一遍。
  if [ -z "$(admin setting get server_dial_host 2>/dev/null || true)" ]; then
    die "--yes 必须配合 --dial-host(这台机器还没配过拨号地址,没有安全的默认值可猜)。"
  fi
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
# --yes 且没显式给值:沿用库里已有的那个(前置检查已确保它非空)。不这么接一手的话,
# 下面 ask 在非交互下拿到的是空串,直接撞进「为空即致命」那条。
if [ -z "$dial_host" ] && [ "$ASSUME_YES" = 1 ]; then
  dial_host="$current_dial"
fi
while :; do
  if [ -z "$dial_host" ]; then
    dial_host="$(ask "拨号地址" "${current_dial:-$guess}")"
  fi

  if [ -z "$dial_host" ]; then
    # 这里是本循环唯一的「回到起点」汇合点,所以兜底放这儿:非交互下再问一遍必然
    # 还是空值,continue 就是死循环。任何以后新增的 dial_host="" + continue 分支
    # 都会撞上这一条,而不是把机器跑满。
    [ "$ASSUME_YES" = 0 ] || die "拨号地址为空,--yes 下无法追问 —— 用 --dial-host 显式给一个。"
    warn "不能为空 —— 没有它客户端不知道往哪连,Web 后台也拒绝生成服务器二维码。"
    continue
  fi

  if [ "$dial_host" = "$current_dial" ]; then
    # 值没变也要核一下 DNS,不能直接打勾。
    #
    # 重跑向导是常事(加用户、换后缀),而原来这条路一个字都不查,直接「✓ 保持不变」——
    # 于是第一次填错(或 DNS 还没指过来)的地址,从第二次起就被一个绿勾背书了,
    # 而它恰恰是「客户端为什么连不上」的答案。打勾就得是真查过。
    #
    # 只查 DNS 不 ping:ICMP 在云上本来就常年不通(安全组默认封),拿它当判据只会天天
    # 误报;而 -skip-icmp 那条路只解析域名,通常几十毫秒,慢也就 3 秒(DNS 超时)。
    if admin setting probe-dial-host -skip-icmp "$dial_host" >/dev/null 2>&1; then
      ok "保持不变: $dial_host"
    else
      warn "保持不变: $dial_host —— 但它现在解析不到 IP。"
      warn "  域名还没指过来,或者当初就填错了。客户端在 DNS 生效前连不上。"
      DIAL_PROBE_FAILED=1
      DIAL_PROBE_KIND=hard
    fi
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
  # 语法就没过的值,不该再问「仍然使用?」—— 那是个死胡同问题:探测前脚刚说「语法错
  # 必须改」,后脚却提议照用,而答了 y 之后 setting set 必然拒绝,原来还会当场 die,
  # 整个向导退出、得重跑一遍。实测填 https://vpn.example.com 就是这个下场。
  #
  # 判据取探测输出的**第一行**:语法这一关的结论固定打在那里,过了是「✓ 语法校验通过」,
  # 没过是「✗ 语法校验失败」,后面的 DNS / ICMP 结论都在下面几行。认符号不认中文 ——
  # 两个语言目录里前缀一致(与本文件其它地方同一口径)。
  #
  # 分界画在「语法」而不是「✗ / ⚠」上,是因为要回答的问题其实是「写得进去吗」:
  # 域名 DNS 还没解析过来是很正常的(先开服、后改 DNS),那种值 setting set 是收的,
  # 所以那一问有意义,该留着。
  if ! printf '%s' "$probe_out" | head -1 | grep -q '✓'; then
    # 非交互下**不能**退回去重问,理由与下面那段 --yes 分支完全一样:ask() 在 --yes
    # 下立刻返回默认值,而全新机器上 current_dial 和 guess 都是空的,于是循环体判空、
    # 打一句「不能为空」、continue,再问再空 —— 满 CPU 的死循环,不会自己停。
    # (实测 40 秒刷了 230 万行 warn。原来只防了 ICMP 那条软失败的路,漏了这条。)
    [ "$ASSUME_YES" = 0 ] \
      || die "--dial-host 给的值语法不合格(判词见上),写进去也会被拒 —— 换个地址重跑。"
    warn "这个值语法就不合格,写进去也会被拒 —— 换一个再试。"
    dial_host=""
    OPT_DIAL_HOST=""
    continue
  fi

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
    # 记下这次是「带着探测失败继续的」,收尾要再说一遍。
    #
    # 这句警告出现在第 1 步,后面还有三四十行绿字,最后一屏是「完成」加一份摘要 ——
    # 摘要里那行 `Web 后台 https://<地址>:7443` 看上去与一切正常时一模一样。于是域名
    # 敲错(或 DNS 还没指过来)的人,拿到的是一台装得漂漂亮亮、而所有客户端配置和
    # 二维码都指向一个解析不到的名字的机器,要等到客户端连不上才回头找原因。
    # 探测本身是对的,继续也是对的(DNS 常常装完才配),漏的只是把这件事带到最后。
    DIAL_PROBE_FAILED=1
    DIAL_PROBE_KIND="$(printf '%s' "$probe_out" | grep -q '⚠' && printf 'icmp' || printf 'hard')"
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
    #
    # 也不 die:这句话本身就是「换一个再试」,而 die 之后整个向导退出,人根本没得试,
    # 得重新 sudo nanotun-setup 一遍。上面已经把语法不合格的挡在前面了,能走到这里
    # 说明是没预料到的拒绝理由 —— 那更该把原因摆出来让人当场改,而不是收摊。
    warn "写入失败 —— 原因见上面那行校验报错,换一个再试。"
  fi
  dial_host=""
  OPT_DIAL_HOST=""
done

# ── MagicDNS 局域网后缀(可选)────────────────────────────────────────────────
# 进阶设置:绝大多数人用默认 lan 就好。放在这里(而非核心编号步骤)是因为它是唯一会**动
# config.toml + 重启 nanotund** 的一步 —— 只有你显式改了后缀(或带 --magic-suffix)才发生,
# 回车保留则纹丝不动。运行期后缀只从 config.toml 读,故必须改文件+重启,setting set 不是入口。
step "MagicDNS 局域网后缀(可选 —— 改它会重启服务)"

if [ ! -f "$ETC_DIR/config.toml" ]; then
  note "没找到 $ETC_DIR/config.toml,跳过(这台机器可能只跑了 Web 后台)。"
else
  cur_suffix="$(current_magic_suffix)"
  if [ -z "$OPT_MAGIC_SUFFIX" ] && [ "$ASSUME_YES" = 1 ]; then
    # 无人值守且没显式点名:不擅改(改后缀要重启数据面)。一行交代现值和改法即可。
    note "MagicDNS 后缀 = $cur_suffix(--yes 不改;要改:--magic-suffix <后缀> 或 sudo nanotun-set-suffix <后缀>)"
  else
    note "客户端解析 *.<后缀> → mesh 虚拟 IP。默认 lan;想避开与家用路由器/保留域冲突可换一个。"
    ok "当前后缀: $cur_suffix"

    # 目标后缀:命令行显式给了(--magic-suffix)就用它;否则交互询问,默认=现值(回车即保留)。
    want_suffix="${OPT_MAGIC_SUFFIX:-$(ask "MagicDNS 后缀" "$cur_suffix")}"

    if [ "$want_suffix" = "$cur_suffix" ]; then
      ok "保持不变: $cur_suffix"
    else
      suffix_tool="$(resolve_suffix_tool || true)"
      if [ -z "$suffix_tool" ]; then
        # 这里**不能**建议去跑 scripts/set-magic-suffix.sh —— 走到这一支恰恰是因为
        # resolve_suffix_tool 两个候选都没找到,其中一个就是它。指着一条刚刚被证明不存在的
        # 路径,人只会以为是自己 cd 错了目录,在发布包里翻上一圈。
        #
        # 会落到这里的基本是同一批机器:v0.1.24 才把 set-magic-suffix.sh 打进发布包,更早的
        # 包里压根没有这个文件,于是装出来的机器也就没有 nanotun-set-suffix 这个命令。
        warn "想把后缀改成 '$want_suffix',但这台机器上没有改后缀的工具:既没有 nanotun-set-suffix"
        warn "  命令,发布包目录里也没有 set-magic-suffix.sh(v0.1.24 才开始打包它,更早的包没有)。"
        note "两条路,任选一条 ——"
        note "  ① 重跑一次安装脚本升到新版,它会把 nanotun-set-suffix 装成命令,再 sudo nanotun-set-suffix $want_suffix"
        note "  ② 手动改 $ETC_DIR/config.toml 里 [server.magic_dns] 的 domain_suffix,再 systemctl restart nanotun"
        note "     (domain_suffix 不在 SIGHUP 热更白名单里,不重启不生效;手动这条没有工具自带的"
        note "      「起不来就自动回滚」,改完记得确认 systemctl is-active nanotun)"
      else
        do_change=1
        # 改后缀要重启 nanotund(SIGTERM graceful drain,客户端会短暂重连)。交互下确认一句;
        # 带了 --magic-suffix 是命令行显式点名,不再追问(那个问题已经被回答过)。
        if [ "$ASSUME_YES" = 0 ] && [ -z "$OPT_MAGIC_SUFFIX" ]; then
          confirm "把后缀从 '$cur_suffix' 改成 '$want_suffix'?这会重启 nanotund(客户端短暂重连)" y \
            || do_change=0
        fi
        if [ "$do_change" = 1 ]; then
          # 工具自带后缀校验(非法直接退)与「重启后没回 active 就自动回滚」。它非零退出不该
          # 拖垮整个向导 —— 前面配好的拨号地址/管理员/用户都还在,单独重来即可,故用 if 兜住。
          if SERVICE=nanotun CONFIG="$ETC_DIR/config.toml" "$suffix_tool" "$want_suffix"; then
            ok "MagicDNS 后缀已改为 '$want_suffix'。各客户端重连一次即用新后缀。"
          else
            warn "改后缀没成功(原因见上;工具会自动回滚到旧后缀 '$cur_suffix')。可稍后单独重试:"
            note "  sudo nanotun-set-suffix <后缀>"
          fi
        else
          ok "保持不变: $cur_suffix"
        fi
      fi
    fi
  fi
fi

# ── 2. Web 后台管理员 ────────────────────────────────────────────────────────
step "2. Web 后台管理员"

# wa_create <用户名> <密码> —— 建后台管理员,把 CLI 的输出补上向导的缩进再打。
#
# 捕获再打而不是让 CLI 直接写屏:它的输出顶格,夹在向导四格缩进的正文里会像是另一个
# 程序插了句嘴。内容照原样,只补缩进 —— 失败时那几行(太短 / 字符类不够 / 重名)正是
# 人要照着改的依据,不能吞。
#
# 密码经管道进 CLI,不进 argv:同机任何用户 ps 都看得见 argv。
wa_create() {
  local out
  if out="$(printf '%s' "$2" | admin webadmin create "$1" --password-stdin 2>&1)"; then
    printf '%s\n' "$out" | sed 's/^/    /'
    return 0
  fi
  printf '%s\n' "$out" | sed 's/^/    /'
  return 1
}

# 把 /setup 的关闭状态落到数据库之外。
#
# /setup 只在 web_admins 表为空时开放,建好管理员就自然关上了 —— 但那个「关上」是库里的
# 一行。库一旦没了(Docker 卷没挂上、路径写错、误删、磁盘故障),服务照常启动、静默重建
# 空库,/setup 就重新对全网敞开,谁先打开谁就是这台机器的管理员;正牌管理员访问 /login
# 还会被 302 进这个向导。实测过:删掉库再起服务,GET /setup 回 200。
#
# 只在**确认已有管理员**时调用。一个都没有的机器绝不能关 —— 那等于把人彻底挡在后台外面。
#
# 已经写过就不再动,免得每次重跑向导都去踢一次服务;显式写了 =1 的也不覆盖(那是人自己
# 要把向导打开,比如正准备重新 bootstrap)。
# 门是不是已经关了。
#
# 「一个管理员都没有」曾经等价于「/setup 对全网敞着」,close_setup_gate 之后不再是 ——
# 库丢了(门照样关着,这正是它的用意)、或者 purge 没清干净 web.env 就重装,都会落到
# 「零管理员 + 门已关」。这时候还照着旧逻辑喊「/setup 敞着,谁先打开谁是管理员」就是
# 把话说反了,而且给的建议(封端口)也是错的 —— 人该做的是用 CLI 补一个账号。
setup_gate_closed() {
  local env_file="$ETC_DIR/web.env"
  [ -f "$env_file" ] || return 1
  grep -qE '^NANOTUN_WEB_ALLOW_SETUP=(0|false|no)[[:space:]]*$' "$env_file" 2>/dev/null
}

close_setup_gate() {
  local env_file="$ETC_DIR/web.env"

  if [ -f "$env_file" ] && grep -qE '^NANOTUN_WEB_ALLOW_SETUP=' "$env_file" 2>/dev/null; then
    return 0
  fi

  [ -d "$ETC_DIR" ] || return 0
  {
    printf '# 由 nanotun-setup 写入:已有 Web 管理员,永久关闭 /setup 抢占入口。\n'
    printf '# 需要重新 bootstrap 时改成 1 并重启 nanotun-web;日常补管理员用:\n'
    printf '#   nanotun-admin webadmin create <名字>\n'
    printf 'NANOTUN_WEB_ALLOW_SETUP=0\n'
  } >> "$env_file" 2>/dev/null || return 0
  chmod 600 "$env_file" 2>/dev/null || true

  if command -v systemctl >/dev/null 2>&1; then
    systemctl restart nanotun-web >/dev/null 2>&1 || true
  fi
  ok "已永久关闭 /setup(库若丢失也不会重新敞开)。"
}

if [ "$WEB_AVAILABLE" = 1 ]; then
  note "注意这跟 VPN 账号是**两套东西**,最容易搞混的一步:"
  note "  · VPN 用户 + PSK  —— 客户端登录用,安装时已建了一个 admin"
  note "  · Web 后台管理员  —— 浏览器登录用,用户名和密码现在就定下来"
  printf '\n'

  # 重跑向导是常事(加用户、改拨号地址),已经有管理员时不该每次都来问一遍。但「跳过」
  # 只在**没人点名**时才对:给了 --web-admin bob 却因为库里已经有个 ops 就整段跳过,
  # 等于把一个明确的指令悄悄吞掉 —— 而屏幕上还打着绿勾说「跳过」,重跑安装命令换了个
  # 后台名字的人会以为 bob 建好了,直到登录时才发现根本没这个账号。
  #
  # 所以分三种情况:点名的那个已经在了 → 跳过(幂等,cloud-init 重试会走到这);
  # 点名了但还没有 → 建(这正是被要求的事);没点名且已有人 → 跳过。
  WEB_ADMIN_LIST="$(admin webadmin list 2>/dev/null || true)"
  WEB_ADMIN_COUNT="$(printf '%s\n' "$WEB_ADMIN_LIST" | awk 'NR>1 && NF' | wc -l | tr -d '[:space:]')"
  WEB_ADMIN_NAMED_EXISTS=0
  if [ -n "$OPT_WEB_ADMIN" ] && printf '%s\n' "$WEB_ADMIN_LIST" | awk 'NR>1 && NF {print $2}' \
       | grep -qix -- "$OPT_WEB_ADMIN"; then
    WEB_ADMIN_NAMED_EXISTS=1     # 大小写不敏感 —— 与库里的去重口径一致
  fi

  if [ "$WEB_ADMIN_NAMED_EXISTS" = 1 ]; then
    ok "Web 后台管理员 $OPT_WEB_ADMIN 已存在,跳过。"
    note "  登录: https://$current_dial:$WEB_PORT/"
  elif [ "${WEB_ADMIN_COUNT:-0}" -gt 0 ] && [ -z "$OPT_WEB_ADMIN" ]; then
    ok "已有 $WEB_ADMIN_COUNT 个 Web 后台管理员,跳过。"
    note "  登录: https://$current_dial:$WEB_PORT/"
    note "  看都有谁: nanotun-admin --db-path $DB webadmin list"
  else
    # 这里是整个向导里唯一一处「不做就有安全后果」的步骤,所以话要说在前面:
    # /setup 在第一个管理员出现之前对全网公开,谁先打开谁就是管理员。装完到人想起来
    # 开浏览器之间的这段时间,这台机器的后台控制权是先到先得的(captcha + 自适应 PoW
    # 只是减速带)。当场把它建掉,窗口就是零。
    #
    # 只在真的一个管理员都没有时说这句。库里已经有人时 /setup 早就关了,再喊一遍
    # 「敞着」是假警报 —— 而这段代码的全部意义就是让人认真对待这一句。
    #
    # 同理,无人值守且已经点名了 --web-admin 时也不说:下面几行就把人建出来,窗口是零,
    # 「现在不建的话…」是在提醒一件马上就不会发生的事。而一次全程成功的安装里冒出一句
    # 带感叹号的警告,只会让人回头翻日志找哪里错了。交互式那边要留着 —— 那里用户真能
    # 答 n,这句话正是拿来劝住他的。
    if [ "${WEB_ADMIN_COUNT:-0}" = 0 ] && ! { [ "$ASSUME_YES" = 1 ] && [ -n "$OPT_WEB_ADMIN" ]; }; then
      if setup_gate_closed; then
        # 零管理员 + 门已关:多半是库丢了(门就是为这一刻留的),或者这台机器之前 purge
        # 过。网页那条路现在走不通,只能从这里或 CLI 建。
        warn "这台机器的 /setup 已经关闭,现在一个管理员都没有 —— Web 后台登不进去。"
      else
        warn "现在不建的话,/setup 会一直敞着 —— 谁先打开谁就是管理员。"
      fi
      printf '\n'
    fi

    web_admin_user="$OPT_WEB_ADMIN"
    web_admin_pass="${NANOTUN_WEB_ADMIN_PASSWORD:-}"

    if [ "$ASSUME_YES" = 1 ]; then
      # 无人值守。给了名字才建 —— 没给就当调用方另有安排(比如它自己会调
      # `webadmin create`),不替人凭空造账号。
      if [ -z "$web_admin_user" ]; then
        if setup_gate_closed; then
          warn "--yes 且没给 --web-admin:跳过。这台机器的 /setup 已关闭且没有管理员,后台进不去:"
        else
          warn "--yes 且没给 --web-admin:跳过。这台机器的 /setup 仍然敞着,记得尽快:"
        fi
        note "  nanotun-admin --db-path $DB webadmin create <名字>"
      else
        if [ -z "$web_admin_pass" ]; then
          # 无人值守下没给密码,就地生成一个强的并打出来 —— 总好过留一个敞开的
          # /setup。与 PSK 同一口径:只出现这一次,自己抄走。
          #
          # 两处讲究:
          #  ① 管道里不能有 `head -c N` 这种拿够就退的消费者 —— 它会给上游 tr 一个
          #     SIGPIPE,而本脚本开着 pipefail,整条赋值就以 141 失败,向导当场死在
          #     这一行(实测就是这么炸的:屏幕停在「现在不建的话…」那句警告上,
          #     后面什么都没有,而 /setup 还敞着 —— 恰恰是这段代码要防的局面)。
          #     改成 cut:它读完全部输入才结束,上游不会被打断。
          #  ② 组成写死:末尾接一段数字和一个连字符。纯随机 alnum 有约 0.7% 的概率
          #     一个数字都不含,那样会被「至少两类字符」的校验挡下 —— 一百多次里
          #     总要撞上一次,而撞上的人只会看到一句莫名其妙的「建失败」。
          web_admin_pass="$(head -c 4096 /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9' | cut -c1-24)-$(head -c 256 /dev/urandom | LC_ALL=C tr -dc '0-9' | cut -c1-4)"
          WEB_ADMIN_PASS_GENERATED=1
        fi
        if wa_create "$web_admin_user" "$web_admin_pass"; then
          if [ "${WEB_ADMIN_PASS_GENERATED:-0}" = 1 ]; then
            printf '\n'
            printf '    %sWeb 后台密码:%s%s\n' "$C_WARN" "$web_admin_pass" "$C_OFF"
            warn "这是它**唯一**一次出现(没给 NANOTUN_WEB_ADMIN_PASSWORD,所以是随机生成的)。"
          fi
        else
          # 无人值守下这里必须**当场失败**,不能只警告一句就往下走。
          #
          # 调用方明确点了 --web-admin,却没建成(密码太弱、名字不合法……)。原来是
          # warn 完继续,整条命令以 0 收场 —— 而 cloud-init / CI / Ansible 只看退出码:
          # 它们看到「成功」就往下走人了,可这台机器一个管理员都没有,/setup 对任何
          # 找到它的人敞着,谁先打开谁就是管理员。这正是 --web-admin 存在的理由,
          # 却在最需要它的无人值守场景里被一句警告吞掉了。
          # 实测:NANOTUN_WEB_ADMIN_PASSWORD='123' + --web-admin ops + --yes
          # → 屏幕上一句「密码至少 12 位」,webadmin 列表为空,退出码 0。
          #
          # 交互模式不走这条(人就在屏幕前,看得见那句警告,下面还会让他重输)。
          # 重名也不走这条:同名账号在上面就被「已存在,跳过」接住了,幂等重跑不受影响。
          if [ "${WEB_ADMIN_COUNT:-0}" = 0 ]; then
            # 同一件事有两种后果,取决于门开着没有:开着是被人抢占,关着是自己也进不去。
            if setup_gate_closed; then
              gate_state="而 /setup 已关闭 —— 谁也进不去这个后台,包括你。"
            else
              gate_state="/setup 谁先打开谁就是管理员。"
            fi
            die "建 Web 管理员失败(原因见上一行)。--yes 是无人值守,这里不能装作没事:
   现在这台机器一个管理员都没有,$gate_state
   改好 NANOTUN_WEB_ADMIN_PASSWORD(12 位起、至少两类字符)重跑本命令,或者手工补:
     nanotun-admin --db-path $DB webadmin create <名字>"
          else
            die "建 Web 管理员失败(原因见上一行)。--yes 是无人值守,这里不能装作没事:
   原有的管理员不受影响,但你要的这个账号没建成。改好密码重跑,或手工补:
     nanotun-admin --db-path $DB webadmin create <名字>"
          fi
        fi
      fi
    else
      # 名字是命令行点名给的,就别再问「要不要建」—— 那个问题已经被回答过了。
      # (原来无条件问,于是 `--web-admin ops` 不带 --yes 时还会被问一遍,答 n 就把
      #  明确的指令否掉了。)
      if [ -n "$web_admin_user" ] || confirm "现在就把 Web 后台管理员定下来?" y; then
        # 提示里点明「新账号」:这一步开场白刚说完「VPN 账号和后台是两套东西」,而安装时
        # 建的那个 VPN 用户恰好也叫 admin —— 默认值一撞名,人很容易以为这是在给同一个
        # 账号补个密码,刚讲清楚的区分当场又糊掉了。默认值仍留 admin(后台就该叫这个,
        # 换成 webadmin 之类只是把别扭挪个地方),用一句话把它钉住。
        [ -n "$web_admin_user" ] || web_admin_user="$(ask "后台用户名(新账号,跟 VPN 那个 admin 无关)" "admin")"

        if [ -n "$web_admin_pass" ] && wa_create "$web_admin_user" "$web_admin_pass"; then
          # 名字和密码都已经给全了(环境变量),即便没带 --yes 也不必再问一遍 ——
          # 交互只该问那些还没有答案的问题。
          :
        else
          # 环境变量里那个密码没通过校验。原来到此为止,只留一句「改好再跑一次」——
          # 可人就坐在屏幕前,而下面正好有一个现成的交互输入。让他当场重输一个就行,
          # 没道理为了一个打错的环境变量把整个向导作废、还把 /setup 继续敞着。
          [ -z "$web_admin_pass" ] || \
            warn "NANOTUN_WEB_ADMIN_PASSWORD 没通过校验(原因见上一行),改成现在手输。"
          # 密码不走 ask():它会回显。这里两遍隐藏输入,交给 CLI 自己校验强度
          # (与网页 /setup 同一套判据,12 位起、至少两类字符)。
          while true; do
            printf '    后台密码(至少 12 位,不回显): ' >&2
            IFS= read -rs web_admin_pass || die "输入意外结束(stdin EOF),向导中止。"
            printf '\n' >&2
            printf '    再输一遍: ' >&2
            IFS= read -rs web_admin_pass2 || die "输入意外结束(stdin EOF),向导中止。"
            printf '\n' >&2
            if [ "$web_admin_pass" != "$web_admin_pass2" ]; then
              warn "两次输入不一致,重来。"
              continue
            fi
            wa_create "$web_admin_user" "$web_admin_pass" && break
            # 失败的理由 CLI 已经说了(太短 / 字符类不够 / 重名)。回去重来,不退出向导:
            # 这一步退出等于把 /setup 继续敞着,而人多半不会再跑一遍。
            warn "换一个再试。"
          done
        fi
        unset web_admin_pass web_admin_pass2
        note "登录: https://$current_dial:$WEB_PORT/(自签证书,浏览器会警告,确认地址无误后继续)"
      elif setup_gate_closed; then
        warn "跳过了。这台机器的 /setup 已关闭,而一个管理员都没有 —— Web 后台进不去。补一个:"
        note "  nanotun-admin --db-path $DB webadmin create <名字>"
      else
        warn "跳过了。/setup 仍然敞着 —— 谁先打开谁是管理员。想现在关掉这扇门:"
        note "  ufw deny $WEB_PORT/tcp        # 或者"
        note "  nanotun-admin --db-path $DB webadmin create <名字>"
      fi
    fi
  fi

  # 重新数一遍再决定关不关:上面几条分支有的建了、有的因为已经有人而跳过、有的被用户
  # 否掉,只有「此刻确实有人」才是关门的依据。放在三条分支之外,重跑安装(管理员早就
  # 存在、走的是「跳过」那条)也能补上这道门 —— 那正是升级上来的机器。
  if [ "$(admin webadmin list 2>/dev/null | awk 'NR>1 && NF' | wc -l | tr -d '[:space:]')" -gt 0 ]; then
    close_setup_gate
  fi
else
  note "未安装 Web 后台。用户管理全部走命令行:nanotun-admin --db-path $DB ..."
  # 给了 --web-admin 却没装后台:那个参数这一趟什么都没做。不说的话,人会以为账号建好了
  # (上面那句只解释「没有后台」,没说「你要的账号没建」——两件事,读的人不会自己接上)。
  [ -n "$OPT_WEB_ADMIN" ] && warn "--web-admin $OPT_WEB_ADMIN 这次没生效:这台机器上没有 Web 后台,建了也没处登。"
fi

# ── 3. 首个 VPN 用户 + 二维码 ────────────────────────────────────────────────
step "3. 创建 VPN 用户并生成二维码"

if [ "$OPT_NO_USER" = 1 ]; then
  note "--no-user,跳过。"
else
  # 已经有真实用户时,这一步不该再默认建一个。
  #
  # 这里的默认是「建」(confirm 默认 y、用户名默认 alice),而 --yes 下 confirm 直接返回默认值,
  # 连问都不问。于是 README 写的裸机升级办法(「重跑一遍 install.sh」,而它结尾就会进本向导)
  # 会在一台已经开好服的机器上凭空多出一个 alice —— 带 PSK、EXIT 允许、enabled,二维码还照打
  # 一遍。2026-08-27 在容器里实测复现过:机器上原本只有 bob,重跑一次向导之后 user list 里
  # 就多了 alice。多出来的账号没人认领,却是一条能走出口的活账号。
  #
  # 上面 Web 管理员那段早就是这么处理的,理由(重跑向导是常事、cloud-init 会重试)一字不差地
  # 适用于这里,只是当时没一并改。三种情况沿用同一套:点名的那个已经在了 → 跳过(幂等);
  # 点名了但还没有 → 建(那正是被要求的事);没点名且已有真实用户 → 跳过。
  #
  # 计数只数**非管理员**($3=="no"),与 install-self-hosted.sh 的 count_real_users 同一个口径。
  # 装机脚本自己会建一个管理员账号,把它一起算进来的话,全新机器上这里会直接跳过 —— 首装就
  # 拿不到任何 VPN 用户和二维码,那比重复建一个严重得多。
  USER_LIST="$(admin user list 2>/dev/null || true)"
  REAL_USERS="$(printf '%s\n' "$USER_LIST" | awk 'NR>1 && $3=="no" {n++} END {print n+0}')"
  USER_NAMED_EXISTS=0
  if [ -n "$OPT_USER" ] && printf '%s\n' "$USER_LIST" | awk 'NR>1 && NF {print $2}' \
       | grep -qix -- "$OPT_USER"; then
    USER_NAMED_EXISTS=1     # 大小写不敏感 —— 与库里的去重口径一致
  fi

  username=""
  USER_SKIPPED=0
  if [ "$USER_NAMED_EXISTS" = 1 ]; then
    ok "VPN 用户 $OPT_USER 已存在,跳过创建。"
    note "要给它重出凭证二维码(会轮换 PSK 并踢掉其在线会话):"
    note "  nanotun-admin --db-path $DB --yes credentials show $OPT_USER --rotate-psk --format qr"
    USER_SKIPPED=1
  elif [ -n "$OPT_USER" ]; then
    username="$OPT_USER"
  elif [ "$REAL_USERS" -gt 0 ]; then
    ok "这台机器已有 $REAL_USERS 个 VPN 用户,跳过创建(升级 / 重跑向导时不该再来一遍)。"
    note "要加用户:nanotun-admin --db-path $DB user create <名字>"
    USER_SKIPPED=1
  elif confirm "现在创建一个 VPN 用户?" y; then
    username="$(ask "用户名" "alice")"
  fi

  if [ -n "$username" ]; then
    # profile 曾被写成「不含密钥,可以公开传」—— 不确切。开了 hy2 mTLS(装机默认就是)时,
    # 它内嵌一张客户端证书和对应私钥。那不是登录凭证(登录仍要用户名 + PSK),但它是进
    # QUIC 那道门的钥匙 —— 贴进群里,等于把挡扫描的那层拆了。两个码都发给本人就行。
    #
    # 放在这里而不是本节开头:跳过创建时(升级重跑)屏幕上不该再讲一遍「扫两个码」——
    # 那一趟根本不会有码出来。
    note "客户端需要扫**两个**二维码,这是刻意拆开的:"
    note "  · profile     服务器地址与传输配置,不含 PSK;但内嵌一张客户端证书 —— 发给本人,别公开贴"
    note "  · credentials 用户名 + PSK,机密,只能一对一给本人"
    # 先说清楚它们多半**不会**出现在这块屏幕上,免得下面连着两句「画不下,跳过」读起来
    # 像是出了故障。profile 那张要 350 列(payload 顶到 QR 上限),没有哪个 SSH 窗口有那么宽,
    # 所以它实际上永远走 PNG;credentials 那张 142 列,窗口够宽才画得出来。
    # 这两个数字是量出来的,不是估的 —— 见 qr_if_fits 的注释。
    note "  这块屏幕多半打不下它们:profile 要 350 列(必然超),credentials 要 142 列(看窗口)。"
    note "  打不下会自动转成 PNG 或回显 PSK 明文,都能用,下面每一步都会说清楚怎么取。"
    printf '\n'

    create_out=""
    if create_out="$(admin --json user create "$username" 2>&1)"; then
      psk="$(printf '%s' "$create_out" | json_field psk)"
      [ -n "$psk" ] || die "用户建好了但没能从输出里取出 PSK,原始输出:
$create_out"
      ok "已创建用户 $username"

      mkdir -p "$QR_DIR"; chmod 0700 "$QR_DIR"

      # profile QR:不含 PSK,但内嵌客户端证书和私钥(见上面那段注释),照样只发给本人。
      # --dial-host 必须显式传 —— CLI 不会去读刚写进库的那个 setting。
      #
      # 先用 --format json 探一次:profile 要从 config.toml 读 REALITY 私钥、hy2 口令、
      # mTLS CA,任何一项不对都生成不出来。直接跑 qr 的话报错会混在二维码输出里,
      # 而失败原因(比如私钥还是 REPLACE_WITH_* 占位)恰恰是唯一有用的信息。
      printf '\n%s── profile 二维码(服务器配置 + 客户端证书,发给本人)──%s\n\n' "$C_STEP" "$C_OFF"
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
      if [ "$cred_qr_rc" -eq 2 ]; then
        if [ "$ASSUME_YES" = 0 ]; then
          note "把窗口拉宽到上面那个列数再重跑就能直接显示;或者存成 PNG(下面会问)。"
        else
          # --yes 下面那个「存成 PNG?」的问句根本不会出现(见下面的 ASSUME_YES 判断)。
          # 指着一个不会到来的提示,等于让人对着屏幕干等,然后自己去猜是不是哪里出错了。
          note "把窗口拉宽到上面那个列数再重跑就能直接显示;PSK 明文在下面,手抄同样能用。"
        fi
      fi
      true   # 上面的 [ ] 不成立时整体为假,set -e 会误杀

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
  elif [ "$USER_SKIPPED" = 0 ]; then
    # 只有「问过、人答了不建」才走到这。上面那两条跳过分支各自把话说完了,再补这一句
    # 等于同一件事讲两遍,而两遍的措辞还不一样。
    note "跳过。之后手动创建:nanotun-admin --db-path $DB user create <名字>"
  fi
fi

# ── 收尾 ─────────────────────────────────────────────────────────────────────
step "完成"

printf '    拨号地址   %s%s\n' "${current_dial:-未设置}" \
  "$([ "${DIAL_PROBE_FAILED:-0}" = 1 ] && [ "${DIAL_PROBE_KIND:-}" = hard ] && printf '   ← 现在还解析不到这台机器')"
if [ "$WEB_AVAILABLE" = 1 ]; then
  printf '    Web 后台   https://%s:%s\n' "$current_dial" "$WEB_PORT"
fi
printf '    数据库     %s\n' "$DB"
printf '    配置       %s/config.toml\n' "$ETC_DIR"
[ -f "$ETC_DIR/config.toml" ] && printf '    MagicDNS   *.%s → mesh 虚拟 IP\n' "$(current_magic_suffix)"
printf '\n'
# --db-path 已经不是必须的了:不带它时 nanotun-admin 会自己找到这台机器装好的库
# (只有当前目录下正好有 data/nanotun.db 时才用那个)。但这里照旧写全 —— 贴进
# 文档、脚本、工单里的命令,不该依赖「在哪个目录跑」。
# 第 1 步探测没过就带着继续的,这里必须再说一遍 —— 那句警告早被后面几十行刷走了,
# 而它决定的是「客户端现在能不能连上」。只对硬失败(DNS / 语法)说:ICMP 不通是云上的
# 常态,再提一遍只会稀释真正要紧的那条。
if [ "${DIAL_PROBE_FAILED:-0}" = 1 ] && [ "${DIAL_PROBE_KIND:-}" = hard ]; then
  warn "拨号地址 $current_dial 在第 1 步没通过探测(域名解析不到这台机器)。"
  warn "上面生成的客户端配置和二维码全都指向它 —— DNS 生效之前,客户端连不上。"
  warn "  把域名解析到这台机器的公网 IP,生效后不用重发二维码,客户端会自己解析到新地址。"
  warn "  地址填错了的话现在改还来得及,改完要把已发出去的配置重新发一遍:"
  warn "    nanotun-setup --dial-host <正确的地址>"
  printf '\n'
fi
note "常用命令(在这台机器上不带 --db-path 也行,会自动用下面这个库):"
note "  nanotun-admin --db-path $DB user list"
note "  nanotun-admin --db-path $DB connection list"
note "  journalctl -u nanotun -f"
printf '\n'

# 守护进程的状态在开头(第 0 步)查过一次,但那是 70 多行之前的事了 —— 而人照着做的
# 是这最后一屏:抄二维码、把 profile 发给用户。服务没在跑的话,发出去的二维码连不上
# 任何东西,而下面那两句偏偏把人指向防火墙和安全组,那时候真正的原因就在手边却没人说。
# 所以在这里重新查一次(期间它可能崩了,也可能被人修好了),没起来就先说这个。
if command -v systemctl >/dev/null 2>&1 && ! systemctl is-active --quiet nanotun.service 2>/dev/null \
   && [ ! -S "$CONTROL_SOCK" ]; then
  warn "注意:nanotund 现在没在跑 —— 上面这些配置都写进库了,但客户端**连不上**。"
  note "  systemctl start nanotun    # 起来看看"
  note "  journalctl -u nanotun -n 50 --no-pager    # 起不来的话看这里"
  printf '\n'
fi

note "客户端连不上时先确认防火墙:REALITY 8443/tcp、hysteria2 443/udp 要能从公网进来。"
note "云服务器还要在厂商的安全组里放行 —— ufw 放了不等于安全组放了。"
