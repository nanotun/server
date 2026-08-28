#!/usr/bin/env bash
# nanotun 环境自检 —— 这台机器能不能跑 nanotun 服务端。
#
# 买完 VPS 先摸一下:
#   curl -fsSL https://raw.githubusercontent.com/nanotun/server/main/scripts/preflight.sh | bash
#
# 装过之后本地也有一份,叫 nanotun-preflight。install.sh 在下载发布包之前会先跑它。
#
# 它是**只读**的:不装任何东西、不改任何配置、不写任何文件。唯一的例外是探测
# ip_forward 可写性时会真写一次 sysctl(值本来就该是 1,安装时也要设),用
# --dry-run 可以连这一次也免掉。
#
# 与「跑到哪炸到哪」的区别:这里把所有问题**一次列全**,最后给一份修复清单。
# 缺三样东西的机器不用来回装三趟。
#
# 用法:
#   preflight.sh [--lang en|zh] [--offline] [--dry-run] [--quiet] [--for-install]
#     --lang en|zh   界面语言,默认英文。不给时按 NANOTUN_LANG,再按装机时落在
#                    /etc/nanotun/lang 的那份 —— 单独跑时跟这台机器装机时选的一致。
#     --offline      不检查 curl/tar(已经有发布包、不需要联网下载时)
#     --dry-run      不尝试写 ip_forward,只读当前值
#     --quiet        只输出结论,不逐项列
#     --for-install  这次跑完**紧接着就要装**:不是 root 直接判死。
#                    由 install.sh / install-self-hosted.sh 传,人手跑不用带。
#
# 退出码:0 = 可以装;1 = 有必须修复的项;2 = 用法错误。
# 「提醒」不影响退出码 —— 它们不阻塞安装,只是装完可能有惊喜。
#
# 这份文件是环境判据的**唯一真源**:install.sh 和 install-self-hosted.sh
# 都调它,不各写一份。两处判据分头演化最后必然对不上。
set -uo pipefail    # 刻意不要 -e:要跑完全部检查再汇总,不能第一个失败就退

# ── 语言 ─────────────────────────────────────────────────────────────────────
# 默认英文。优先级:--lang > NANOTUN_LANG > /etc/nanotun/lang(装机时落下的)> en。
# 只有 install.sh 会交互询问语言;这里不问 —— 走到这一步语言早已定下,并经环境变量传进来。
# 单独跑 nanotun-preflight 时则读落盘的那份,跟这台机器装机时选的保持一致。
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

# nt_plural <个数> <单数> <复数> —— 英文的单复数,只给英文那一份用(中文没有这回事)。
# 值得为它单开一个函数:唯一用到它的地方是结论行,而结论行是整份输出里被读得最仔细的
# 一句 —— 「1 items must be fixed first」这种货色摆在那儿,人会怀疑数字本身也是错的。
#
# 名字和签名与 scripts/setup.sh 里那份一致。这两个文件是分头改成双语的,一度各造了一个
# (这边是「补个 s」,那边是「在两个词里挑」)—— 一个概念两种拼法,下一个脚本就会造出第三种。
nt_plural() { if [ "${1:-0}" = 1 ]; then printf '%s' "$2"; else printf '%s' "$3"; fi; }

OFFLINE=0; DRY_RUN=0; QUIET=0; FOR_INSTALL=0
while [ $# -gt 0 ]; do
  case "$1" in
    --offline)     OFFLINE=1; shift ;;
    --dry-run)     DRY_RUN=1; shift ;;
    --quiet)       QUIET=1; shift ;;
    --for-install) FOR_INSTALL=1; shift ;;
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
    # 打开头那段注释,按行内容判起止,**不写死行号**。
    #
    # 原来是 sed -n '2,30p':注释早就长过 30 行,于是帮助从中间截断,末尾还把
    # `set -uo pipefail` 那行源码一并打了出来 —— 看着像脚本自己出了错。行号写死就是这个
    #下场:改文档的人不会想到有个地方按行号取它。同仓的 install.sh / uninstall.sh 用的
    # 就是下面这个 awk,顺带把行首的 `#` 去掉(sed 那版原样留着,像没写完)。
    #
    # 本脚本最常见的用法恰恰是 `curl … | bash`,那时 $0 是 "bash"、读不到文件,所以退回的
    # 那份必须自己够用 —— 只回一句「用法:...」等于让人再去开一次浏览器。
    -h|--help)
      # 英文那份只能是这里手写的:文件头那段注释是给维护者看的,一直是中文。
      if [ "$NT_LANG" != zh ]; then
        cat <<'EOF'
nanotun preflight — can this machine run the nanotun server?

It is **read-only**: it installs nothing and changes no configuration. The one
exception is the ip_forward writability probe, which does write the sysctl once
(the value has to be 1 anyway, the install sets it too); --dry-run skips even that.

Every problem is listed **in one go**, with a fix list at the end — a machine that
is missing three things does not need three install attempts to find that out.

Usage: nanotun-preflight [--lang en|zh] [--offline] [--dry-run] [--quiet] [--for-install]
  --lang en|zh   interface language (default: en). Without it, NANOTUN_LANG is used,
                 then whatever the install left in /etc/nanotun/lang
  --offline      skip the downloader / tar checks (release tarball already at hand)
  --dry-run      do not try to write ip_forward, only read the current value
  --quiet        print the verdict only, not every item
  --for-install  an install follows right away: not being root is fatal (passed by
                 install.sh, no need to type it by hand)

Exit codes: 0 = good to install; 1 = something must be fixed first; 2 = usage error.
Reminders do not affect the exit code — they do not block the install, they only
mean the installed machine may hold a surprise or two.
EOF
        exit 0
      fi
      awk 'NR>1 && /^#/ {sub(/^#[ \t]?/,""); print; next} NR>1 {exit}' "$0" 2>/dev/null || cat <<'EOF'
nanotun 环境自检 —— 这台机器能不能跑 nanotun 服务端。

它是**只读**的:不装任何东西、不改任何配置。唯一的例外是探测 ip_forward 可写性时会真写
一次 sysctl(值本来就该是 1,安装时也要设),用 --dry-run 可以连这一次也免掉。

所有问题**一次列全**,最后给一份修复清单 —— 缺三样东西的机器不用来回装三趟。

用法: nanotun-preflight [--lang en|zh] [--offline] [--dry-run] [--quiet] [--for-install]
  --lang en|zh   界面语言,默认英文。不给时按 NANOTUN_LANG,再按装机时落在
                 /etc/nanotun/lang 的那份
  --offline      不检查下载器 / tar(已经有发布包、不需要联网下载时)
  --dry-run      不尝试写 ip_forward,只读当前值
  --quiet        只输出结论,不逐项列
  --for-install  这次跑完紧接着就要装:不是 root 直接判死(由 install.sh 传,人手跑不用带)

退出码:0 = 可以装;1 = 有必须修复的项;2 = 用法错误。
「提醒」不影响退出码 —— 它们不阻塞安装,只是装完可能有惊喜。
EOF
      exit 0 ;;
    # 名字取自 $0(装成命令后是 nanotun-preflight),并指向 --help —— 只说「未知参数」
    # 等于让人自己猜有哪些参数,而这条消息出现的时刻恰恰是他已经猜错过一次了。
    *) printf '%s\n' "$(tsel \
         "$(basename "$0"): unknown argument $1 (--help shows the usage)" \
         "$(basename "$0"): 未知参数 $1（--help 看用法）")" >&2
       exit 2 ;;
  esac
done

if [ -t 1 ]; then
  C_H=$'\033[1;36m'; C_OK=$'\033[1;32m'; C_WARN=$'\033[1;33m'
  C_ERR=$'\033[1;31m'; C_DIM=$'\033[2m'; C_OFF=$'\033[0m'
else
  C_H=''; C_OK=''; C_WARN=''; C_ERR=''; C_DIM=''; C_OFF=''
fi

HARD_MSGS=(); HARD_FIXES=(); SOFT_MSGS=()

section() { [ "$QUIET" = 1 ] || printf '\n  %s%s%s\n' "$C_H" "$*" "$C_OFF"; }
pass()    { [ "$QUIET" = 1 ] || printf '    %s✓%s %s\n' "$C_OK" "$C_OFF" "$*"; }
info()    { [ "$QUIET" = 1 ] || printf '    %s·%s %s\n' "$C_DIM" "$C_OFF" "$*"; }
# fail <一行说明> <修复命令或办法>
fail() {
  [ "$QUIET" = 1 ] || printf '    %s✗%s %s\n' "$C_ERR" "$C_OFF" "$1"
  HARD_MSGS+=("$1"); HARD_FIXES+=("$2")
}
soft() {
  [ "$QUIET" = 1 ] || printf '    %s!%s %s\n' "$C_WARN" "$C_OFF" "$1"
  SOFT_MSGS+=("${2:-$1}")
}

# 双语版本:英文在前、中文在后,与 tsel 同序。并排放着的理由见文件上方「语言」那节。
#
# fail_t / soft_t 收两对参数:先是说明的英中一对,再是修复办法的英中一对 —— 每一对紧挨着,
# 而不是「两句英文 + 两句中文」。四个都是长句,挨着放才能一眼看出哪句对着哪句。
section_t() { section "$(tsel "$1" "$2")"; }
pass_t()    { pass    "$(tsel "$1" "$2")"; }
info_t()    { info    "$(tsel "$1" "$2")"; }
fail_t()    { fail    "$(tsel "$1" "$2")" "$(tsel "$3" "$4")"; }
# 后一对省掉时跟 soft 一样:进汇总清单的就是那句说明本身。
soft_t()    { soft    "$(tsel "$1" "$2")" "$(tsel "${3:-$1}" "${4:-$2}")"; }

have() { command -v "$1" >/dev/null 2>&1; }

# 按发行版给出能直接粘的安装命令。猜不出来就退回一句泛泛的话,
# 总比给一条在 RHEL 上跑不通的 apt 命令强。
# 发行版族决定包名(iproute2 还是 iproute、procps 还是 procps-ng),包管理器命令
# 决定怎么装。这两件事得分开判:
#   - minimal 镜像里包管理器可能根本不在 PATH 上(rockylinux:9-minimal 只有
#     microdnf,没有 dnf/yum),光探二进制会判成「不认识」;
#   - 而「不认识」如果退回 Debian 包名,给 RHEL 用户的就是一条必定失败的命令。
#     猜错包名比不猜更糟 —— 用户会以为是自己敲错了。
# 所以先信 /etc/os-release 的 ID/ID_LIKE 定族,再探二进制定命令。
FAM="unknown"; PKG_MGR=""
if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  _id="$(. /etc/os-release 2>/dev/null && printf '%s %s' "${ID:-}" "${ID_LIKE:-}")"
  case " $_id " in
    *debian*|*ubuntu*)              FAM=deb ;;
    *rhel*|*fedora*|*centos*)       FAM=rhel ;;
    *alpine*)                       FAM=alpine ;;
    *suse*)                         FAM=suse ;;
    *arch*)                         FAM=arch ;;
  esac
fi
for m in apt-get dnf microdnf yum apk pacman zypper; do
  have "$m" && { PKG_MGR="$m"; break; }
done
# 二进制能定族时以它为准(os-release 可能被魔改过,包管理器不会撒谎)
case "$PKG_MGR" in
  apt-get) FAM=deb ;;
  dnf|microdnf|yum) [ "$FAM" = unknown ] && FAM=rhel ;;
  apk) FAM=alpine ;;
  pacman) FAM=arch ;;
  zypper) FAM=suse ;;
esac

pkg_for() { # pkg_for <debian 包名> <rhel 包名> <alpine 包名> —— 取本机该用的那个
  case "$FAM" in
    rhel)   printf '%s' "$2" ;;
    alpine) printf '%s' "$3" ;;
    *)      printf '%s' "$1" ;;   # deb / suse / arch 的包名基本跟 Debian 一致
  esac
}
install_cmd() { # install_cmd <包名...> —— 一条能直接粘的命令
  case "$PKG_MGR" in
    apt-get)  printf 'apt update && apt install -y %s' "$*" ;;
    dnf)      printf 'dnf install -y %s' "$*" ;;
    microdnf) printf 'microdnf install -y %s' "$*" ;;
    yum)      printf 'yum install -y %s' "$*" ;;
    apk)      printf 'apk add %s' "$*" ;;
    pacman)   printf 'pacman -Sy --noconfirm %s' "$*" ;;
    zypper)   printf 'zypper install -y %s' "$*" ;;
    # 连包管理器都找不到:只报要什么,不编一条大概率跑不通的命令
    *)        tsel "install these with this machine's package manager: $*" \
                   "用本机的包管理器装上:$*" ;;
  esac
}

[ "$QUIET" = 1 ] || printf '\n%s==> %s%s\n' "$C_H" \
  "$(tsel "nanotun preflight" "nanotun 环境自检")" "$C_OFF"

# ── 系统 ─────────────────────────────────────────────────────────────────────
section_t "System" "系统"

OS="$(uname -s)"
# 系统不对就到此为止。继续跑下去只会级联出「没有 iptables」「/proc 读不到」这类
# 噪音,把唯一有用的那条结论淹掉 —— 在 macOS 上装 iptables 并不能让它能跑。
if [ "$OS" != "Linux" ]; then
  printf '    %s✗%s %s\n' "$C_ERR" "$C_OFF" \
    "$(tsel "the operating system is $OS" "操作系统是 $OS")"
  printf '\n%s==> %s%s\n\n' "$C_H" "$(tsel "Verdict" "结论")" "$C_OFF"
  printf '  %s✗ %s%s\n\n' "$C_ERR" \
    "$(tsel "the nanotun server only runs on Linux" "nanotun 服务端只跑 Linux")" "$C_OFF"
  printf '    %s\n' "$(tsel \
    "It needs a TUN device, iptables and systemd — macOS / WSL1 / *BSD provide none of those." \
    "它要 TUN 设备、iptables 和 systemd,macOS / WSL1 / *BSD 都提供不了。")"
  printf '    %s\n\n' "$(tsel \
    "For development on this machine use the container: docker compose -f docker/docker-compose.dev.yml up --build" \
    "本机开发调试用容器:docker compose -f docker/docker-compose.dev.yml up --build")"
  exit 1
fi

PRETTY=""
[ -r /etc/os-release ] && PRETTY="$(. /etc/os-release 2>/dev/null && printf '%s' "${PRETTY_NAME:-}")"
pass_t "${PRETTY:-Linux} · kernel $(uname -r)" "${PRETTY:-Linux} · 内核 $(uname -r)"

case "$(uname -m)" in
  x86_64|amd64)  pass_t "architecture $(uname -m) → uses the linux-amd64 release" \
                        "架构 $(uname -m) → 用 linux-amd64 发布包" ;;
  aarch64|arm64) pass_t "architecture $(uname -m) → uses the linux-arm64 release" \
                        "架构 $(uname -m) → 用 linux-arm64 发布包" ;;
  *) fail_t "no prebuilt release for architecture $(uname -m)" \
            "架构 $(uname -m) 没有预编译发布包" \
            "Only linux-amd64 / linux-arm64 are published. On this machine you have to go build it yourself — see the build-from-source section of the README" \
            "官方只出 linux-amd64 / linux-arm64。这台机器只能自己 go build,见 README 源码构建一节" ;;
esac

# root 不是**这台机器**的属性,是这次怎么跑的属性。而本脚本回答的问题是
# 「这台机器能不能跑 nanotun」—— 所以只在「跑完紧接着就要装」时才判死。
#
# 单独跑(curl | bash)和 install.sh --check-only 都是明确不需要 root 的路子,
# 文档里也是这么写的。在那两条路上把非 root 记成「必须修复」,结论就成了
# 「✗ 这台机器有 1 项必须先修复」并退 1 —— 只想问问机器行不行的人,会以为
# 自己的机器不合格,而要改的其实是命令前面加个 sudo。
#
# 端口那节已经按同一口径处理过(非 root 看不到 socket 属主就直说看不见),
# 这里不能还是另一套。
if [ "$(id -u)" = 0 ]; then
  pass "root"
elif [ "$FOR_INSTALL" = 1 ]; then
  fail_t "not root (currently $(id -un))" \
         "不是 root(当前 $(id -un))" \
         "Installing writes /usr/local/bin and /etc/systemd/system and changes a sysctl. Re-run it with sudo" \
         "安装要写 /usr/local/bin、/etc/systemd/system 并改 sysctl。用 sudo 重跑"
else
  soft_t "not root (currently $(id -un)) — fine if you are only checking" \
         "不是 root(当前 $(id -un))—— 只是检查的话没关系" \
         "This check ran as $(id -un): the machine itself is fine, but an actual install needs sudo. As non-root you also cannot see which process holds a port." \
         "这次是以 $(id -un) 身份检查的:机器本身没问题,但真要安装得用 sudo。非 root 也看不到端口被谁占着。"
fi

# ── init ─────────────────────────────────────────────────────────────────────
section_t "init system" "init 系统"

# 判据用 /run/systemd/system 是否存在(sd_booted(3) 的官方做法),不是 PATH 上有没有
# systemctl —— 不少容器镜像里有 systemctl 这个文件却没有在跑的 systemd,那时
# daemon-reload 报的是 "Failed to connect to bus",跟真正的原因看不出关系。
if [ -d /run/systemd/system ]; then
  pass_t "systemd is running" "systemd 正在运行"
elif [ "$OS" = "Linux" ]; then
  fail_t "no systemd running" \
         "没有正在运行的 systemd" \
         "nanotun installs a systemd unit. Alpine (OpenRC) / Devuan (sysvinit) / init-less containers cannot use the bare-metal install — take the Docker route instead: https://github.com/nanotun/server/blob/main/docs/DOCKER.md" \
         "nanotun 装的是 systemd unit。Alpine(OpenRC)/ Devuan(sysvinit)/ 无 init 的容器都用不了裸机安装,请改走 Docker:https://github.com/nanotun/server/blob/main/docs/DOCKER.md"
fi

# ── 必备命令 ─────────────────────────────────────────────────────────────────
section_t "Required commands" "必备命令"

# nanotund 是直接 exec 这些命令的,没有内置 netlink / nft 后端。
#
# 缺的命令不逐条进修复清单,先攒起来最后合成**一条** apt/dnf 命令。
# 一台 minimal 镜像能一口气缺六样,列成六行就是让人手工敲六遍 —— 而它们
# 本来一条命令就能装完。
MISSING_CMDS=(); MISSING_PKGS=()
# 「用途」是打给用户看的,所以英中各占一个参数(第 5、6 个),其余参数不变。
chk_cmd() { # chk_cmd <命令> <debian 包> <rhel 包> <alpine 包> <用途:英> <用途:中>
  local use; use="$(tsel "$5" "$6")"
  if have "$1"; then
    pass "$1 $C_DIM($use)$C_OFF"
  else
    [ "$QUIET" = 1 ] || printf '    %s✗%s %s %s(%s)%s\n' "$C_ERR" "$C_OFF" "$1" "$C_DIM" "$use" "$C_OFF"
    MISSING_CMDS+=("$1")
    MISSING_PKGS+=("$(pkg_for "$2" "$3" "$4")")
  fi
}
chk_cmd iptables  iptables iptables iptables "NAT / forwarding rules" "NAT / 转发规则"
chk_cmd ip6tables iptables iptables ip6tables "IPv6 rules" "IPv6 规则"
chk_cmd ip        iproute2 iproute  iproute2 "create the TUN device, detect the egress interface" \
                                             "建 TUN 网卡、探测出口网卡"
chk_cmd openssl   openssl  openssl  openssl  "generate the REALITY keys and the self-signed certificate" \
                                             "生成 REALITY 密钥与自签证书"
chk_cmd sysctl    procps   procps-ng procps  "turn on IP forwarding" "开 IP 转发"

if [ "$OFFLINE" = 0 ]; then
  # 下载器 curl 或 wget 有一个就行 —— install.sh 有 curl 用 curl,没有就退到 wget。
  #
  # 硬点名 curl 会把「只带 wget」的最小镜像(Debian netinst 是典型)判死在一个它其实
  # 装得上的地方:修复清单让人去装 curl,而这台机器本来就下得动东西。
  # 缺哪个都提示装 curl:两个都没有时装 curl 是主路径,走的是分辨力更好的那条。
  if have curl; then
    pass "curl $C_DIM($(tsel "download the release" "下载发布包"))$C_OFF"
  elif have wget; then
    pass "wget $C_DIM($(tsel \
      "download the release; with no curl around, install.sh falls back to wget" \
      "下载发布包;没有 curl,install.sh 会退到 wget"))$C_OFF"
  else
    [ "$QUIET" = 1 ] || printf '    %s✗%s curl/wget %s(%s)%s\n' \
      "$C_ERR" "$C_OFF" "$C_DIM" "$(tsel \
        "download the release, either one will do" \
        "下载发布包,两个有一个即可")" "$C_OFF"
    MISSING_CMDS+=("curl")
    MISSING_PKGS+=("$(pkg_for curl curl curl)")
  fi
  chk_cmd tar  tar  tar  tar  "unpack it" "解包"
fi

if [ "${#MISSING_CMDS[@]}" -gt 0 ]; then
  # 去重:iptables 和 ip6tables 在 Debian 系是同一个包,别让命令里出现两遍
  uniq_pkgs="$(printf '%s\n' "${MISSING_PKGS[@]}" | awk '!seen[$0]++' | tr '\n' ' ')"
  HARD_MSGS+=("$(tsel "missing commands: ${MISSING_CMDS[*]}" "缺少命令:${MISSING_CMDS[*]}")")
  HARD_FIXES+=("$(install_cmd "${uniq_pkgs% }")")
fi

# iptables 后端只做记录:legacy 与 nft 混用时规则会写进内核里另一张表,
# 现象是「命令成功、规则却不生效」。这里留一行,排查时能第一眼看到。
if have iptables; then
  # 取一次存下来:两份文案都要用它,而 iptables --version 没必要跑两遍。
  ipt_ver="$(iptables --version 2>/dev/null | head -1)"
  info_t "iptables backend: ${ipt_ver:-unknown}" "iptables 后端: ${ipt_ver:-未知}"
fi

# ── 内核与设备 ───────────────────────────────────────────────────────────────
section_t "Kernel and devices" "内核与设备"

if [ -c /dev/net/tun ]; then
  pass "/dev/net/tun"
elif [ "$OS" = "Linux" ]; then
  fail_t "/dev/net/tun does not exist" \
         "/dev/net/tun 不存在" \
         "Try modprobe tun first. If the host simply does not provide it (OpenVZ and some LXC VPS do not), this machine cannot run a VPN gateway — you need a KVM-virtualised one" \
         "先试 modprobe tun。要是宿主根本不提供(OpenVZ 和部分 LXC VPS 就没有),这台机器跑不了 VPN 网关,得换 KVM 虚拟化的"
fi

# ip_forward 必须能置 1:nanotund 装 iptables 规则前会自己 sysctl -w,
# 写不进去且当前又不是 1 就 FatalExit(60)。只读 /proc/sys 的容器会卡在这。
FWD="$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "")"
if [ "$FWD" = "1" ]; then
  pass_t "net.ipv4.ip_forward is already 1" "net.ipv4.ip_forward 已是 1"
elif [ -z "$FWD" ]; then
  soft_t "cannot read net.ipv4.ip_forward (/proc not mounted?)" \
         "读不到 net.ipv4.ip_forward(/proc 没挂?)" \
         "make sure /proc is mounted" "确认 /proc 已挂载"
elif [ "$DRY_RUN" = 1 ]; then
  soft_t "net.ipv4.ip_forward=$FWD, writability not verified (--dry-run)" \
         "net.ipv4.ip_forward=$FWD,未验证可写(--dry-run)" \
         "the install will set it to 1" "安装时会设成 1"
elif sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1; then
  pass_t "net.ipv4.ip_forward is writable (set to 1)" "net.ipv4.ip_forward 可写(已置 1)"
else
  fail_t "net.ipv4.ip_forward=$FWD and it cannot be written" \
         "net.ipv4.ip_forward=$FWD 且写不进去" \
         "nanotund will exit 60 on startup. Containers / VPS with a read-only /proc/sys need this one opened up on the host" \
         "nanotund 起来会 exit 60。/proc/sys 只读的容器 / VPS 需要在宿主上放开这一项"
fi

# 严格 rp_filter 会让出口流量的回程被静默丢掉 —— 症状是「连上了但上不了网」,
# 极难查。nanotund 会给 tun0 设 loose,但 all/default 是它管不到的。
RPF="$(cat /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null || echo "")"
[ "$RPF" = "1" ] && soft_t "net.ipv4.conf.all.rp_filter=1 (strict)" \
  "net.ipv4.conf.all.rp_filter=1(严格)" \
  "Strict reverse path filtering silently drops the return packets of egress traffic, which shows up as \"connected, but no internet\". Suggested: sysctl -w net.ipv4.conf.all.rp_filter=2" \
  "严格反向路由校验会静默丢掉出口回程包,表现为「连上了但上不了网」。建议 sysctl -w net.ipv4.conf.all.rp_filter=2"

# 纯 IPv6 主机(没有 IPv4 默认路由)现在是一等公民:nanotund 探不到 v4 出口时会跳过 v4 NAT、
# 只装 v6 数据面(不再崩溃循环)。但有个固有属性必须先讲清 —— 客户端经这台机器只能拿到 IPv6
# 出网,v4-only 的站点在没有 NAT64 时够不着。只在确实缺 v4 默认路由时提示;有 v4 出口的机器
# 这里什么都不打印。另外这类机器多半上不了 GitHub(github.com 仅 IPv4),一键 install.sh 下不了
# 发布包,得在能上网的机器上下好再拷进来跑 install-self-hosted.sh。
if have ip && [ "$OS" = "Linux" ]; then
  if [ -z "$(ip -4 route show default 2>/dev/null)" ]; then
    if [ -n "$(ip -6 route show default 2>/dev/null)" ]; then
      info_t "IPv6-only host (no IPv4 default route): v4 NAT will be skipped and only v6 set up, so clients get IPv6 egress only (v4-only sites need NAT64)" \
             "纯 IPv6 主机(无 IPv4 默认路由):将跳过 v4 NAT 只走 v6,客户端只有 IPv6 出网(v4-only 站点需 NAT64)"
      info_t "GitHub is IPv4-only, so this machine most likely cannot download the release — fetch the tarball on a machine that can reach it, copy it over and run install-self-hosted.sh" \
             "GitHub 仅 IPv4,这台多半下不了发布包 —— 在能上网的机器下好 tar 拷进来跑 install-self-hosted.sh"
    else
      soft_t "no IPv4 and no IPv6 default route" \
             "既无 IPv4 也无 IPv6 默认路由" \
             "this machine has no default route, so even once installed it cannot give clients a way out — check the network / routing configuration first" \
             "这台机器没有默认出口,装完也没法给客户端做出网 —— 先确认网络/路由配置"
    fi
  fi
fi

# ── 端口 ─────────────────────────────────────────────────────────────────────
section_t "Ports" "端口"

if have ss || have netstat; then
  port_user() { # port_user <tcp|udp> <端口>
    if have ss; then
      ss -lnp"${1:0:1}" 2>/dev/null | awk -v p=":$2" '$4 ~ p"$" {print; exit}'
    else
      netstat -lnp --"$1" 2>/dev/null | awk -v p=":$2" '$4 ~ p"$" {print; exit}'
    fi
  }
  # 「换个端口」得说清楚是**哪一个**旋钮 —— 三个端口分别落在三个不同的地方,而这话原来
  # 三条一律写成「改 /etc/nanotun/config.toml 的端口」。
  #
  # 对 7443 那句是错的:config.toml 里根本没有它的键,web 后台的监听地址由 nanotun-web 读
  # NANOTUN_WEB_LISTEN 决定,web.env 是唯一的入口。照着去 config.toml 里找,翻遍三百多行也
  # 找不到 —— 而这话恰恰出现在他端口被占、正着急的时候。
  #
  # 对另外两个也不够用:listen_addr 在这份配置里出现在四个段([server]、[server.magic_dns]、
  # [hysteria]、[reality]),不点名段就等于让人挨个试,而试错的代价是服务起不来。
  # 比的是解析出来的实际端口,不是字面量 —— 机器上把 REALITY 挪到 9443 之后,拿 8443 去比
  # 会一路落到兜底分支,给出「改 config.toml」这种没有指名段和键的话,等于白说。
  # (这两个函数在端口解析之后才被调用,所以引用那几个变量是安全的。)
  port_knob() { # port_knob <端口> -> 这个端口在哪儿改
    case "$1" in
      "$NT_PORT_REALITY") tsel "listen_addr under [reality] in /etc/nanotun/config.toml" \
                               "/etc/nanotun/config.toml 里 [reality] 的 listen_addr" ;;
      "$NT_PORT_HY2")     tsel "listen_addr under [hysteria] in /etc/nanotun/config.toml" \
                               "/etc/nanotun/config.toml 里 [hysteria] 的 listen_addr" ;;
      "$NT_PORT_WEB")     tsel "NANOTUN_WEB_LISTEN in /etc/nanotun/web.env (config.toml has no such key)" \
                               "/etc/nanotun/web.env 里的 NANOTUN_WEB_LISTEN（config.toml 里没有这一项）" ;;
      *)                  echo "/etc/nanotun/config.toml" ;;
    esac
  }
  port_svc() { # port_svc <端口> -> 改完要重启哪个服务
    case "$1" in
      "$NT_PORT_WEB") echo "nanotun-web" ;;
      *)              echo "nanotun" ;;
    esac
  }
  # 「说明」是打给用户看的(REALITY / hysteria2 两个是专名,Web 后台不是),所以英中各占
  # 一个参数(第 3、4 个)。
  chk_port() { # chk_port <tcp|udp> <端口> <说明:英> <说明:中>
    local hit lbl; hit="$(port_user "$1" "$2")"; lbl="$(tsel "$3" "$4")"
    if [ -z "$hit" ]; then
      pass "$(tsel "$2/$1 free" "$2/$1 空闲") $C_DIM($lbl)$C_OFF"
    else
      # 已经装过 nanotun 的机器重跑检查时会命中自己,那不是问题
      case "$hit" in
        *nanotun*) info_t "$2/$1 is held by nanotun itself ($lbl) — this is a reinstall / upgrade" \
                          "$2/$1 已被 nanotun 自己占用($lbl)—— 这是重装 / 升级" ;;
        *)
          # 内核只对特权进程暴露 socket 的属主,所以非 root 跑时 ss 那一列是空的,
          # 上面那个 *nanotun* 分支永远匹配不上 —— 本机 nanotun 自己占的端口会被
          # 一口咬定成「别的进程占着」。而 --check-only 是明确不需要 root 的那条路,
          # 在它上面给出错误结论,比不给结论更糟。看不见就说看不见。
          if [ "$(id -u)" != 0 ] && [ -x /usr/local/bin/nanotund ]; then
            info_t "$2/$1 is in use ($lbl) — as non-root you cannot see by which process; nanotun is already installed on this machine, so most likely by itself" \
                   "$2/$1 已被占用($lbl)—— 非 root 看不到是哪个进程;这台机器上已装了 nanotun,多半是它自己"
          elif [ "$FOR_INSTALL" = 1 ]; then
            # 跑完紧接着就要装,而这一项装下去是**必败**的:nanotund bind 同一个端口
            # 拿到 EADDRINUSE,服务 crash-loop。原来这里只给 soft,于是检查放行 →
            # 安装把二进制、systemd 单元、证书、数据库全写下去 → 第 6 步启动失败。
            # 实测在一台 443/udp 被别人占着的机器上就是这个下场:装了一半的系统,
            # 加几十行 journal,还得自己去 ss 里翻是谁占的 —— 而这些信息此刻就在手上。
            # 检查这一步的意义正是在动系统之前把必败的情形挡下来。
            # 「换个端口」这条出路得看配置文件在不在。全新机器上它还不存在(装完才有),
            # 照着去找只会扑空 —— 又是一条把人支到空地方的建议。所以分开说。
            local port_fix
            if [ -f /etc/nanotun/config.toml ]; then
              port_fix="$(tsel \
                "Stop whatever is holding it, or move nanotun off it by changing $(port_knob "$2"), then systemctl restart $(port_svc "$2")" \
                "停掉占用它的进程,或改 $(port_knob "$2") 换个端口,再 systemctl restart $(port_svc "$2")")"
            else
              port_fix="$(tsel \
                "Stop whatever is holding it and run the install again.
       To move nanotun onto another port instead: that file does not exist yet (it appears after the install),
       so install with --skip-check first, then change $(port_knob "$2") and systemctl restart $(port_svc "$2")" \
                "停掉占用它的进程再重跑安装。
       要让 nanotun 改用别的端口的话:那个文件这会儿还不存在(装完才有),
       先 --skip-check 装上,再改 $(port_knob "$2") 并 systemctl restart $(port_svc "$2")")"
            fi
            fail "$(tsel "$2/$1 is held by another process ($lbl)" \
                         "$2/$1 被别的进程占着($lbl)")" \
                 "$(printf '%s' "$hit" | tr -s ' ' | cut -c1-100)
       $port_fix"
          else
            # 只是检查、不马上装:说清楚就够了,不替人下「这台机器不行」的结论 ——
            # 占用者可能一会儿就停了,或者这次本来就只是问问。
            #
            # 但得点明这一条在**真装的时候会被判死**(上面那支 FOR_INSTALL 就是)。
            # 不说的话,结论行那句「另有 N 条提醒(不阻塞安装)」就把话说满了 —— 它对
            # 「没装 ipset」那类提醒是对的,对这一条不是:照着「可以装」去装,迎面撞上
            # 一条 FATAL。人会觉得两个工具在互相矛盾,而其实是同一个工具的两句话。
            #
            # 服务名按端口取:7443 被占时起不来的是 nanotun-web,数据面照常跑 ——
            # 笼统说「nanotun 起不来」会让人以为整台机器废了。
            soft_t "$2/$1 is in use ($lbl)" \
                   "$2/$1 已被占用($lbl)" \
                   "$2/$1 is held by another process, so $(port_svc "$2") will not start: $(printf '%s' "$hit" | tr -s ' ' | cut -c1-100)
       A real install rules this one \"must be fixed first\" (this run is only a check, so it does not stop you).
       To change the port: $(port_knob "$2")" \
                   "$2/$1 被别的进程占着,$(port_svc "$2") 起不来:$(printf '%s' "$hit" | tr -s ' ' | cut -c1-100)
       这条在真正安装时会被判为「必须先修复」(现在只是检查,所以不拦你)。
       改端口的话:$(port_knob "$2")"
          fi ;;
      esac
    fi
  }
  # 端口取这台机器**实际**配置的那几个,而不是默认值。
  #
  # 差别只在已经装过的机器上出现,但那正是升级前跑自检的场景:REALITY 挪到 9443 之后,
  # 去看 8443 等于既漏检了真正要用的端口(被别人占了也发现不了),又可能对一个早已跟
  # nanotun 无关的 8443 大惊小怪。
  #
  # 解析器装在 /usr/local/bin(装机脚本放的)。全新机器上没有它,也没有 config.toml,
  # 那时默认值就是对的 —— 所以读不到不是问题,不必因此报错。
  NT_PORT_REALITY=443; NT_PORT_HY2=443; NT_PORT_WEB=7443
  if [ -r /usr/local/bin/nanotun-ports.sh ]; then
    # shellcheck source=scripts/nanotun-ports.sh
    . /usr/local/bin/nanotun-ports.sh
    nanotun_load_ports
  fi
  chk_port tcp "$NT_PORT_REALITY" "REALITY" "REALITY"
  chk_port udp "$NT_PORT_HY2"  "hysteria2" "hysteria2"
  chk_port tcp "$NT_PORT_WEB" "web admin" "Web 后台"
else
  info_t "no ss / netstat, skipping the port-in-use check" \
         "没有 ss / netstat,跳过端口占用检查"
fi

# ── 可选项 ───────────────────────────────────────────────────────────────────
section_t "Optional" "可选项"

if have ufw && ufw status 2>/dev/null | grep -q '^Status: active'; then
  info_t "ufw is active — the install will open ${NT_PORT_REALITY:-443}/tcp, ${NT_PORT_HY2:-443}/udp and ${NT_PORT_WEB:-7443}/tcp for you" \
         "ufw 处于 active —— 安装时会自动放行 ${NT_PORT_REALITY:-443}/tcp、${NT_PORT_HY2:-443}/udp、${NT_PORT_WEB:-7443}/tcp"
elif have firewall-cmd && [ "$(firewall-cmd --state 2>/dev/null)" = running ]; then
  # RHEL 系默认是 firewalld 而不是 ufw。这句原来一律说成「没装 ufw,记得自己放行」,
  # 在 Rocky/Alma/CentOS 上既没说中用的是哪个防火墙,也没提安装脚本其实会替它放行。
  info_t "firewalld is running — the install will open ${NT_PORT_REALITY:-443}/tcp, ${NT_PORT_HY2:-443}/udp and ${NT_PORT_WEB:-7443}/tcp for you" \
         "firewalld 正在运行 —— 安装时会自动放行 ${NT_PORT_REALITY:-443}/tcp、${NT_PORT_HY2:-443}/udp、${NT_PORT_WEB:-7443}/tcp"
elif have ufw; then
  info_t "ufw is installed but not enabled — opening ports is up to you" \
         "装了 ufw 但未启用 —— 放行规则由你自己管"
else
  info_t "no ufw / firewalld — if you use another firewall or a cloud security group, remember to open ${NT_PORT_REALITY:-443}/tcp and ${NT_PORT_HY2:-443}/udp" \
         "没装 ufw / firewalld —— 用别的防火墙 / 云安全组的话,记得放行 ${NT_PORT_REALITY:-443}/tcp 与 ${NT_PORT_HY2:-443}/udp"
fi

have ipset || info_t "ipset is not installed — only needed with jump_host_firewall turned on" \
                     "没装 ipset —— 只有开启 jump_host_firewall 才需要"

# REALITY 的 dest 这台机器够不够得着。
#
# 这条不是锦上添花:REALITY 的每一条入站连接,进门第一件事就是 dial dest(见
# third_party/xtls-reality/tls.go 的 Server()),dial 不通就直接关连接 —— 在任何客户端
# 认证之前。也就是说 dest 不可达时,**所有**客户端都连不上,合法的也一样。
#
# 而现场看不出任何异常:端口在听(状态自检照样打「✓ 监听中:8443/tcp(REALITY)」)、
# 进程健康、配置没错;那条 "failed to dial dest" 是每连接错误,不进日志 —— 实测阻断出站
# 之后,journalctl 里一个字都没有。更糊的是 hy2(443/udp)不依赖 dest,照常能用,于是
# 症状变成「有的客户端能连、有的连不上」,取决于它挑了哪条传输。
#
# 触发场景都很实在:出站只放行了少数目的地的机器、被上游 IP 段封的机房、dest 站点抽风。
# 「取自哪里」那一段是打给用户看的,所以英中各占一个参数(第 2、3 个)。
dest_check() { # dest_check <dest> <来源:英> <来源:中>
  local dest="$1" src host port
  src="$(tsel "$2" "$3")"
  host="${dest%:*}"; port="${dest##*:}"
  [ -n "$host" ] && [ -n "$port" ] || return 0
  # 只做 TCP 连通性:能连上就够了(REALITY 要的正是这一步)。整个 TLS 握手交给它自己。
  if have timeout && have bash && timeout 8 bash -c "exec 3<>/dev/tcp/${host}/${port}" 2>/dev/null; then
    # 通了就一行带过 —— 这台机器一切正常时,没必要为它多占一行醒目位置。
    info_t "REALITY dest reachable: $dest ($src)" \
           "REALITY dest 可达:$dest($src)"
  else
    soft_t "cannot reach the REALITY dest: $dest ($src)" \
      "REALITY dest 连不上:$dest($src)" \
      "REALITY dials it as the very first thing on every inbound connection and closes the connection right there if the dial fails — before any client authenticates, so every client fails to connect while the port keeps listening and the log stays completely silent. First make sure this machine's egress can reach ${host}:${port}; if it cannot, point dest and server_names under [reality] at a site this machine can reach and that speaks TLS1.3" \
      "REALITY 每条连接进门先 dial 它,连不上就在认证之前关掉 —— 所有客户端都会连不上,而端口照样在听、日志里一个字都没有。先确认这台机器的出站能到 ${host}:${port};到不了就把 [reality] 的 dest 和 server_names 换成一个本机够得着、且支持 TLS1.3 的站点"
  fi
}
if [ -f /etc/nanotun/config.toml ]; then
  # 段感知地取 [reality] 的 dest —— 顶层和别的段里也可能有同名键。
  rd="$(awk '/^[ \t]*\[/ { sec = $0; sub(/^[ \t]*/, "", sec); sub(/[ \t]*$/, "", sec) }
             sec == "[reality]" && /^[ \t]*dest[ \t]*=/ {
               if (match($0, /"[^"]*"/)) { print substr($0, RSTART+1, RLENGTH-2); exit }
             }' /etc/nanotun/config.toml 2>/dev/null)"
  [ -n "$rd" ] && dest_check "$rd" "from config.toml" "取自 config.toml"
else
  # 还没装:按模板将要写入的默认值先探一次。装完才发现连不上,已经晚了一步。
  dest_check "www.microsoft.com:443" "the install template's default" "装机模板的默认值"
fi

if [ -x /usr/local/bin/nanotund ]; then
  # 取一次存下来:两份文案都要用它,而没必要为此把 nanotund 跑两遍。
  nt_ver="$(/usr/local/bin/nanotund --version 2>/dev/null | head -1)"
  info_t "found an existing nanotun install (${nt_ver:-version unknown}) — installing again is an upgrade, it will not touch the existing config or keys" \
         "检测到已安装的 nanotun(${nt_ver:-版本未知})—— 再装一次是升级,不会动现有配置和密钥"

  # 出口 SNAT 的源地址还在不在本机上。
  #
  # 数据面用的是 SNAT 而不是 MASQUERADE:源地址是**启动那一刻**探到的,之后钉死在规则里。
  # 机器的 WAN 地址后来变了(DHCP 续约拿到新地址、云上重新分配、双网卡切换),规则就会把
  # 客户端流量改写成一个本机已经没有的地址 —— 包发不出去,而控制面照常:客户端连得上、
  # 握手成功、就是上不了网。实测过:把 eth0 的地址换掉,规则仍指着旧的那个。
  #
  # 这种故障几乎没法从症状反推,而它在这里只是一次字符串比对。查出来的话,重启 nanotun
  # 就重新探测了 —— 难的从来是想到这一层。
  if have iptables; then
    snat_src="$(iptables -t nat -S POSTROUTING 2>/dev/null \
      | awk '/nanotun/ && /--to-source/ { for (i = 1; i < NF; i++) if ($i == "--to-source") { print $(i+1); exit } }')"
    # --to-source 可能带端口范围(a.b.c.d:1024-65535),只取地址那一段。
    snat_src="${snat_src%%:*}"
    if [ -n "$snat_src" ] && ! ip -4 -o addr show 2>/dev/null | grep -q " ${snat_src}/"; then
      soft_t "the source address $snat_src pinned in the egress SNAT rule is no longer on any interface of this machine" \
        "出口 SNAT 规则的源地址 $snat_src 已经不在本机任何网卡上" \
        "The data plane pinned it into the rule when it started, and this machine's address has changed since. Clients connect but get no internet — restart the data plane so it probes again: systemctl restart nanotun" \
        "数据面启动时把它钉进了规则,之后这台机器的地址变过。客户端能连上、但出不了网 —— 重启数据面重新探测:systemctl restart nanotun"
    fi

    # 出口 DNS 接管指着的解析器,还是不是这台机器现在用的那个。
    #
    # 与上面的 SNAT 同一个模子:exit_dns_redirect=auto(默认)是启动那一刻读一次
    # /etc/resolv.conf,之后钉死在 DNAT 规则里。解析器地址比主机 IP 更容易变(DHCP 续约
    # 换了 DNS 选项、systemd-resolved 重配、机器换了网络),变过之后客户端的查询被转给
    # 一个旧地址 —— 连得上、能拿到 IP、域名却全解析不了。
    #
    # 只在 auto / 没写 这两种模式下比:显式配了具体 IP 的人本来就是要钉住某个解析器,
    # 跟 resolv.conf 不一致是他自己的意图,拿这个报警等于对着正确配置喊。
    dns_mode="$(awk -F= '/^[ \t]*exit_dns_redirect[ \t]*=/ {gsub(/[" \t]/, "", $2); print tolower($2); exit}' \
      /etc/nanotun/config.toml 2>/dev/null)"
    if [ -z "$dns_mode" ] || [ "$dns_mode" = auto ]; then
      dns_pinned="$(iptables -t nat -S PREROUTING 2>/dev/null \
        | awk '/nanotun/ && /--to-destination/ { for (i = 1; i < NF; i++) if ($i == "--to-destination") { print $(i+1); exit } }')"
      dns_pinned="${dns_pinned%%:*}"
      # 现在的系统解析器:跟 detectSystemDNSv4 一个口径 —— 两个文件依次找,跳过环回
      # (systemd-resolved 的 127.0.0.53 stub 对转发流量没意义,Go 那边也跳)。
      dns_now="$(awk '/^[ \t]*nameserver/ && $2 !~ /^127\./ && $2 ~ /^[0-9.]+$/ {print $2; exit}' \
        /etc/resolv.conf /run/systemd/resolve/resolv.conf 2>/dev/null)"
      if [ -n "$dns_pinned" ] && [ -n "$dns_now" ] && [ "$dns_pinned" != "$dns_now" ]; then
        soft_t "the egress DNS takeover points at $dns_pinned, while this machine's system resolver is now $dns_now" \
          "出口 DNS 接管指向 $dns_pinned,而这台机器现在的系统解析器是 $dns_now" \
          "Under auto the data plane probed $dns_pinned when it started and pinned it into the rule; the resolver has changed since. Clients connect and get an IP, but no name resolves — restart the data plane so it probes again: systemctl restart nanotun" \
          "数据面启动时按 auto 探到 $dns_pinned 并钉进了规则,之后解析器换过。客户端能连上、能拿到 IP,域名却解析不了 —— 重启数据面重新探测:systemctl restart nanotun"
      fi
    fi
  fi
fi

# 这台机器上是不是还跑着 nanotun **客户端**。
#
# 两者共用 /etc/nanotun、/var/lib/nanotun、/run/nanotun,而客户端的身份就在里面
# (/etc/nanotun/device_id)。共存本身是支持的、装下去不会有事,但有两个坑值得先说:
#
#   1. 手动 `rm -rf /etc/nanotun` 会连客户端身份一起抹掉 —— 它随即以新 UUID 重新注册,
#      而 UUID 是审批与出口选择的稳定键:旧设备行还占着固定 vIP,新设备钉不上,已经选了
#      这个出口的客户端那边它直接消失。2026-08-03 我们自己的测试机上就这么中过一次。
#      scripts/uninstall.sh 按文件清单删,不会犯这个错。
#   2. 服务端启动时会 `ip link delete <[tun].device_name>` 再重建。默认 tun0 与客户端的
#      网卡不撞;但要是把 device_name 配成客户端那个名字,服务端每次启动都会把客户端的
#      网卡删掉。所以这里把客户端网卡名读出来直接摆在眼前。
CLI_TUN=""
[ -r /var/lib/nanotun/tun_name ] && CLI_TUN="$(cat /var/lib/nanotun/tun_name 2>/dev/null | tr -d '[:space:]')"
if [ -x /usr/local/bin/nanotun ] || [ -e /etc/nanotun/device_id ] || [ -n "$CLI_TUN" ]; then
  soft_t "the nanotun client is also installed on this machine, and it shares /etc/nanotun and /var/lib/nanotun with the server" \
       "这台机器上还装着 nanotun 客户端,它与服务端共用 /etc/nanotun 与 /var/lib/nanotun" \
       "The client and the server share /etc/nanotun, /var/lib/nanotun and /run/nanotun.
      · Uninstall with sudo nanotun-uninstall; rm -rf on those directories by hand wipes the
        client identity /etc/nanotun/device_id, after which it re-registers under a new UUID
        (while the old device row still holds the pinned vIP).${CLI_TUN:+
      · Do not set [tun].device_name to \"${CLI_TUN}\" (the interface the client is using) — on
        startup the server deletes the interface of that name and recreates it, so every start
        cuts the client off. The default tun0 does not clash.}" \
       "客户端与服务端共用 /etc/nanotun、/var/lib/nanotun、/run/nanotun。
      · 卸载请用 sudo nanotun-uninstall;手动 rm -rf 这些目录会抹掉客户端身份
        /etc/nanotun/device_id,它会以新 UUID 重新注册(旧设备还占着固定 vIP)。${CLI_TUN:+
      · [tun].device_name 别配成 \"${CLI_TUN}\"(客户端正在用的网卡)—— 服务端启动时会先
        删掉同名网卡再重建,等于每次启动都打断客户端。默认的 tun0 不冲突。}"
fi

AVAIL_KB="$(df -Pk /usr/local 2>/dev/null | awk 'NR==2{print $4}')"
if [ -n "${AVAIL_KB:-}" ] && [ "$AVAIL_KB" -lt 524288 ] 2>/dev/null; then
  soft_t "less than 512MB free on /usr/local (currently $((AVAIL_KB/1024))MB)" \
         "/usr/local 可用空间不足 512MB(当前 $((AVAIL_KB/1024))MB)" \
         "the release unpacks to about 150MB, and the database and logs come on top — leave 1GB or more" \
         "发布包解开约 150MB,再加数据库和日志,建议留 1GB 以上"
fi

# ── 结论 ─────────────────────────────────────────────────────────────────────
printf '\n%s==> %s%s\n\n' "$C_H" "$(tsel "Verdict" "结论")" "$C_OFF"

nh="${#HARD_MSGS[@]}"; ns="${#SOFT_MSGS[@]}"

if [ "$nh" -eq 0 ] && [ "$ns" -eq 0 ]; then
  printf '  %s✓ %s%s\n\n' "$C_OK" \
    "$(tsel "nanotun can be installed on this machine" "这台机器可以装 nanotun")" "$C_OFF"
  exit 0
fi

# 颜色只包住结论本身(「可以装」/「有 N 项必须先修复」),后面那半句是平文 ——
# 提醒的条数不该跟着结论一起染成绿色。
if [ "$nh" -eq 0 ]; then
  printf '  %s✓ %s%s%s\n\n' "$C_OK" "$(tsel "good to install" "可以装")" "$C_OFF" \
    "$(tsel ", plus $ns $(nt_plural "$ns" reminder reminders) (they do not block the install):" \
            ",另有 $ns 条提醒(不阻塞安装):")"
else
  printf '  %s✗ %s%s' "$C_ERR" \
    "$(tsel "$nh $(nt_plural "$nh" item items) must be fixed first" "有 $nh 项必须先修复")" "$C_OFF"
  [ "$ns" -gt 0 ] && printf '%s' "$(tsel ", plus $ns $(nt_plural "$ns" reminder reminders)" ",另有 $ns 条提醒")"
  printf ':\n\n'
fi

if [ "$nh" -gt 0 ]; then
  printf '  %s%s%s\n' "$C_ERR" "$(tsel "Must fix" "必须修复")" "$C_OFF"
  i=0
  while [ "$i" -lt "$nh" ]; do
    printf '    %d. %s\n' "$((i+1))" "${HARD_MSGS[$i]}"
    printf '       %s%s%s\n' "$C_DIM" "${HARD_FIXES[$i]}" "$C_OFF"
    i=$((i+1))
  done
  printf '\n'
fi

if [ "$ns" -gt 0 ]; then
  printf '  %s%s%s\n' "$C_WARN" "$(tsel "Reminders" "提醒")" "$C_OFF"
  for m in "${SOFT_MSGS[@]}"; do printf '    · %s\n' "$m"; done
  printf '\n'
fi

[ "$nh" -eq 0 ] || exit 1
exit 0
