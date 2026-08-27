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
#   preflight.sh [--offline] [--dry-run] [--quiet] [--for-install]
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

OFFLINE=0; DRY_RUN=0; QUIET=0; FOR_INSTALL=0
while [ $# -gt 0 ]; do
  case "$1" in
    --offline)     OFFLINE=1; shift ;;
    --dry-run)     DRY_RUN=1; shift ;;
    --quiet)       QUIET=1; shift ;;
    --for-install) FOR_INSTALL=1; shift ;;
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
      awk 'NR>1 && /^#/ {sub(/^#[ \t]?/,""); print; next} NR>1 {exit}' "$0" 2>/dev/null || cat <<'EOF'
nanotun 环境自检 —— 这台机器能不能跑 nanotun 服务端。

它是**只读**的:不装任何东西、不改任何配置。唯一的例外是探测 ip_forward 可写性时会真写
一次 sysctl(值本来就该是 1,安装时也要设),用 --dry-run 可以连这一次也免掉。

所有问题**一次列全**,最后给一份修复清单 —— 缺三样东西的机器不用来回装三趟。

用法: nanotun-preflight [--offline] [--dry-run] [--quiet] [--for-install]
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
    *) printf '%s: 未知参数 %s（--help 看用法）\n' "$(basename "$0")" "$1" >&2; exit 2 ;;
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
    *)        printf '用本机的包管理器装上:%s' "$*" ;;
  esac
}

[ "$QUIET" = 1 ] || printf '\n%s==> nanotun 环境自检%s\n' "$C_H" "$C_OFF"

# ── 系统 ─────────────────────────────────────────────────────────────────────
section "系统"

OS="$(uname -s)"
# 系统不对就到此为止。继续跑下去只会级联出「没有 iptables」「/proc 读不到」这类
# 噪音,把唯一有用的那条结论淹掉 —— 在 macOS 上装 iptables 并不能让它能跑。
if [ "$OS" != "Linux" ]; then
  printf '    %s✗%s 操作系统是 %s\n' "$C_ERR" "$C_OFF" "$OS"
  printf '\n%s==> 结论%s\n\n' "$C_H" "$C_OFF"
  printf '  %s✗ nanotun 服务端只跑 Linux%s\n\n' "$C_ERR" "$C_OFF"
  printf '    它要 TUN 设备、iptables 和 systemd,macOS / WSL1 / *BSD 都提供不了。\n'
  printf '    本机开发调试用容器:docker compose -f docker/docker-compose.dev.yml up --build\n\n'
  exit 1
fi

PRETTY=""
[ -r /etc/os-release ] && PRETTY="$(. /etc/os-release 2>/dev/null && printf '%s' "${PRETTY_NAME:-}")"
pass "${PRETTY:-Linux} · 内核 $(uname -r)"

case "$(uname -m)" in
  x86_64|amd64)  pass "架构 $(uname -m) → 用 linux-amd64 发布包" ;;
  aarch64|arm64) pass "架构 $(uname -m) → 用 linux-arm64 发布包" ;;
  *) fail "架构 $(uname -m) 没有预编译发布包" \
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
  fail "不是 root(当前 $(id -un))" "安装要写 /usr/local/bin、/etc/systemd/system 并改 sysctl。用 sudo 重跑"
else
  soft "不是 root(当前 $(id -un))—— 只是检查的话没关系" \
       "这次是以 $(id -un) 身份检查的:机器本身没问题,但真要安装得用 sudo。非 root 也看不到端口被谁占着。"
fi

# ── init ─────────────────────────────────────────────────────────────────────
section "init 系统"

# 判据用 /run/systemd/system 是否存在(sd_booted(3) 的官方做法),不是 PATH 上有没有
# systemctl —— 不少容器镜像里有 systemctl 这个文件却没有在跑的 systemd,那时
# daemon-reload 报的是 "Failed to connect to bus",跟真正的原因看不出关系。
if [ -d /run/systemd/system ]; then
  pass "systemd 正在运行"
elif [ "$OS" = "Linux" ]; then
  fail "没有正在运行的 systemd" \
       "nanotun 装的是 systemd unit。Alpine(OpenRC)/ Devuan(sysvinit)/ 无 init 的容器都用不了裸机安装,请改走 Docker:https://github.com/nanotun/server/blob/main/docs/DOCKER.md"
fi

# ── 必备命令 ─────────────────────────────────────────────────────────────────
section "必备命令"

# nanotund 是直接 exec 这些命令的,没有内置 netlink / nft 后端。
#
# 缺的命令不逐条进修复清单,先攒起来最后合成**一条** apt/dnf 命令。
# 一台 minimal 镜像能一口气缺六样,列成六行就是让人手工敲六遍 —— 而它们
# 本来一条命令就能装完。
MISSING_CMDS=(); MISSING_PKGS=()
chk_cmd() { # chk_cmd <命令> <debian 包> <rhel 包> <alpine 包> <用途>
  if have "$1"; then
    pass "$1 $C_DIM($5)$C_OFF"
  else
    [ "$QUIET" = 1 ] || printf '    %s✗%s %s %s(%s)%s\n' "$C_ERR" "$C_OFF" "$1" "$C_DIM" "$5" "$C_OFF"
    MISSING_CMDS+=("$1")
    MISSING_PKGS+=("$(pkg_for "$2" "$3" "$4")")
  fi
}
chk_cmd iptables  iptables iptables iptables "NAT / 转发规则"
chk_cmd ip6tables iptables iptables ip6tables "IPv6 规则"
chk_cmd ip        iproute2 iproute  iproute2 "建 TUN 网卡、探测出口网卡"
chk_cmd openssl   openssl  openssl  openssl  "生成 REALITY 密钥与自签证书"
chk_cmd sysctl    procps   procps-ng procps  "开 IP 转发"

if [ "$OFFLINE" = 0 ]; then
  # 下载器 curl 或 wget 有一个就行 —— install.sh 有 curl 用 curl,没有就退到 wget。
  #
  # 硬点名 curl 会把「只带 wget」的最小镜像(Debian netinst 是典型)判死在一个它其实
  # 装得上的地方:修复清单让人去装 curl,而这台机器本来就下得动东西。
  # 缺哪个都提示装 curl:两个都没有时装 curl 是主路径,走的是分辨力更好的那条。
  if have curl; then
    pass "curl $C_DIM(下载发布包)$C_OFF"
  elif have wget; then
    pass "wget $C_DIM(下载发布包;没有 curl,install.sh 会退到 wget)$C_OFF"
  else
    [ "$QUIET" = 1 ] || printf '    %s✗%s curl/wget %s(下载发布包,两个有一个即可)%s\n' \
      "$C_ERR" "$C_OFF" "$C_DIM" "$C_OFF"
    MISSING_CMDS+=("curl")
    MISSING_PKGS+=("$(pkg_for curl curl curl)")
  fi
  chk_cmd tar  tar  tar  tar  "解包"
fi

if [ "${#MISSING_CMDS[@]}" -gt 0 ]; then
  # 去重:iptables 和 ip6tables 在 Debian 系是同一个包,别让命令里出现两遍
  uniq_pkgs="$(printf '%s\n' "${MISSING_PKGS[@]}" | awk '!seen[$0]++' | tr '\n' ' ')"
  HARD_MSGS+=("缺少命令:${MISSING_CMDS[*]}")
  HARD_FIXES+=("$(install_cmd "${uniq_pkgs% }")")
fi

# iptables 后端只做记录:legacy 与 nft 混用时规则会写进内核里另一张表,
# 现象是「命令成功、规则却不生效」。这里留一行,排查时能第一眼看到。
if have iptables; then
  info "iptables 后端: $(iptables --version 2>/dev/null | head -1 || echo 未知)"
fi

# ── 内核与设备 ───────────────────────────────────────────────────────────────
section "内核与设备"

if [ -c /dev/net/tun ]; then
  pass "/dev/net/tun"
elif [ "$OS" = "Linux" ]; then
  fail "/dev/net/tun 不存在" \
       "先试 modprobe tun。要是宿主根本不提供(OpenVZ 和部分 LXC VPS 就没有),这台机器跑不了 VPN 网关,得换 KVM 虚拟化的"
fi

# ip_forward 必须能置 1:nanotund 装 iptables 规则前会自己 sysctl -w,
# 写不进去且当前又不是 1 就 FatalExit(60)。只读 /proc/sys 的容器会卡在这。
FWD="$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "")"
if [ "$FWD" = "1" ]; then
  pass "net.ipv4.ip_forward 已是 1"
elif [ -z "$FWD" ]; then
  soft "读不到 net.ipv4.ip_forward(/proc 没挂?)" "确认 /proc 已挂载"
elif [ "$DRY_RUN" = 1 ]; then
  soft "net.ipv4.ip_forward=$FWD,未验证可写(--dry-run)" "安装时会设成 1"
elif sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1; then
  pass "net.ipv4.ip_forward 可写(已置 1)"
else
  fail "net.ipv4.ip_forward=$FWD 且写不进去" \
       "nanotund 起来会 exit 60。/proc/sys 只读的容器 / VPS 需要在宿主上放开这一项"
fi

# 严格 rp_filter 会让出口流量的回程被静默丢掉 —— 症状是「连上了但上不了网」,
# 极难查。nanotund 会给 tun0 设 loose,但 all/default 是它管不到的。
RPF="$(cat /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null || echo "")"
[ "$RPF" = "1" ] && soft "net.ipv4.conf.all.rp_filter=1(严格)" \
  "严格反向路由校验会静默丢掉出口回程包,表现为「连上了但上不了网」。建议 sysctl -w net.ipv4.conf.all.rp_filter=2"

# 纯 IPv6 主机(没有 IPv4 默认路由)现在是一等公民:nanotund 探不到 v4 出口时会跳过 v4 NAT、
# 只装 v6 数据面(不再崩溃循环)。但有个固有属性必须先讲清 —— 客户端经这台机器只能拿到 IPv6
# 出网,v4-only 的站点在没有 NAT64 时够不着。只在确实缺 v4 默认路由时提示;有 v4 出口的机器
# 这里什么都不打印。另外这类机器多半上不了 GitHub(github.com 仅 IPv4),一键 install.sh 下不了
# 发布包,得在能上网的机器上下好再拷进来跑 install-self-hosted.sh。
if have ip && [ "$OS" = "Linux" ]; then
  if [ -z "$(ip -4 route show default 2>/dev/null)" ]; then
    if [ -n "$(ip -6 route show default 2>/dev/null)" ]; then
      info "纯 IPv6 主机(无 IPv4 默认路由):将跳过 v4 NAT 只走 v6,客户端只有 IPv6 出网(v4-only 站点需 NAT64)"
      info "GitHub 仅 IPv4,这台多半下不了发布包 —— 在能上网的机器下好 tar 拷进来跑 install-self-hosted.sh"
    else
      soft "既无 IPv4 也无 IPv6 默认路由" "这台机器没有默认出口,装完也没法给客户端做出网 —— 先确认网络/路由配置"
    fi
  fi
fi

# ── 端口 ─────────────────────────────────────────────────────────────────────
section "端口"

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
      "$NT_PORT_REALITY") echo "/etc/nanotun/config.toml 里 [reality] 的 listen_addr" ;;
      "$NT_PORT_HY2")     echo "/etc/nanotun/config.toml 里 [hysteria] 的 listen_addr" ;;
      "$NT_PORT_WEB")     echo "/etc/nanotun/web.env 里的 NANOTUN_WEB_LISTEN（config.toml 里没有这一项）" ;;
      *)                  echo "/etc/nanotun/config.toml" ;;
    esac
  }
  port_svc() { # port_svc <端口> -> 改完要重启哪个服务
    case "$1" in
      "$NT_PORT_WEB") echo "nanotun-web" ;;
      *)              echo "nanotun" ;;
    esac
  }
  chk_port() { # chk_port <tcp|udp> <端口> <说明>
    local hit; hit="$(port_user "$1" "$2")"
    if [ -z "$hit" ]; then
      pass "$2/$1 空闲 $C_DIM($3)$C_OFF"
    else
      # 已经装过 nanotun 的机器重跑检查时会命中自己,那不是问题
      case "$hit" in
        *nanotun*) info "$2/$1 已被 nanotun 自己占用($3)—— 这是重装 / 升级" ;;
        *)
          # 内核只对特权进程暴露 socket 的属主,所以非 root 跑时 ss 那一列是空的,
          # 上面那个 *nanotun* 分支永远匹配不上 —— 本机 nanotun 自己占的端口会被
          # 一口咬定成「别的进程占着」。而 --check-only 是明确不需要 root 的那条路,
          # 在它上面给出错误结论,比不给结论更糟。看不见就说看不见。
          if [ "$(id -u)" != 0 ] && [ -x /usr/local/bin/nanotund ]; then
            info "$2/$1 已被占用($3)—— 非 root 看不到是哪个进程;这台机器上已装了 nanotun,多半是它自己"
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
              port_fix="停掉占用它的进程,或改 $(port_knob "$2") 换个端口,再 systemctl restart $(port_svc "$2")"
            else
              port_fix="停掉占用它的进程再重跑安装。
       要让 nanotun 改用别的端口的话:那个文件这会儿还不存在(装完才有),
       先 --skip-check 装上,再改 $(port_knob "$2") 并 systemctl restart $(port_svc "$2")"
            fi
            fail "$2/$1 被别的进程占着($3)" \
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
            soft "$2/$1 已被占用($3)" "$2/$1 被别的进程占着,$(port_svc "$2") 起不来:$(printf '%s' "$hit" | tr -s ' ' | cut -c1-100)
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
  NT_PORT_REALITY=8443; NT_PORT_HY2=443; NT_PORT_WEB=7443
  if [ -r /usr/local/bin/nanotun-ports.sh ]; then
    # shellcheck source=scripts/nanotun-ports.sh
    . /usr/local/bin/nanotun-ports.sh
    nanotun_load_ports
  fi
  chk_port tcp "$NT_PORT_REALITY" "REALITY"
  chk_port udp "$NT_PORT_HY2"  "hysteria2"
  chk_port tcp "$NT_PORT_WEB" "Web 后台"
else
  info "没有 ss / netstat,跳过端口占用检查"
fi

# ── 可选项 ───────────────────────────────────────────────────────────────────
section "可选项"

if have ufw && ufw status 2>/dev/null | grep -q '^Status: active'; then
  info "ufw 处于 active —— 安装时会自动放行 ${NT_PORT_REALITY:-8443}/tcp、${NT_PORT_HY2:-443}/udp、${NT_PORT_WEB:-7443}/tcp"
elif have firewall-cmd && [ "$(firewall-cmd --state 2>/dev/null)" = running ]; then
  # RHEL 系默认是 firewalld 而不是 ufw。这句原来一律说成「没装 ufw,记得自己放行」,
  # 在 Rocky/Alma/CentOS 上既没说中用的是哪个防火墙,也没提安装脚本其实会替它放行。
  info "firewalld 正在运行 —— 安装时会自动放行 ${NT_PORT_REALITY:-8443}/tcp、${NT_PORT_HY2:-443}/udp、${NT_PORT_WEB:-7443}/tcp"
elif have ufw; then
  info "装了 ufw 但未启用 —— 放行规则由你自己管"
else
  info "没装 ufw / firewalld —— 用别的防火墙 / 云安全组的话,记得放行 ${NT_PORT_REALITY:-8443}/tcp 与 ${NT_PORT_HY2:-443}/udp"
fi

have ipset || info "没装 ipset —— 只有开启 jump_host_firewall 才需要"

if [ -x /usr/local/bin/nanotund ]; then
  info "检测到已安装的 nanotun($(/usr/local/bin/nanotund --version 2>/dev/null | head -1 || echo 版本未知))—— 再装一次是升级,不会动现有配置和密钥"

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
      soft "出口 SNAT 规则的源地址 $snat_src 已经不在本机任何网卡上" \
        "数据面启动时把它钉进了规则,之后这台机器的地址变过。客户端能连上、但出不了网 —— 重启数据面重新探测:systemctl restart nanotun"
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
  soft "这台机器上还装着 nanotun 客户端,它与服务端共用 /etc/nanotun 与 /var/lib/nanotun" \
       "客户端与服务端共用 /etc/nanotun、/var/lib/nanotun、/run/nanotun。
      · 卸载请用 sudo nanotun-uninstall;手动 rm -rf 这些目录会抹掉客户端身份
        /etc/nanotun/device_id,它会以新 UUID 重新注册(旧设备还占着固定 vIP)。${CLI_TUN:+
      · [tun].device_name 别配成 \"${CLI_TUN}\"(客户端正在用的网卡)—— 服务端启动时会先
        删掉同名网卡再重建,等于每次启动都打断客户端。默认的 tun0 不冲突。}"
fi

AVAIL_KB="$(df -Pk /usr/local 2>/dev/null | awk 'NR==2{print $4}')"
if [ -n "${AVAIL_KB:-}" ] && [ "$AVAIL_KB" -lt 524288 ] 2>/dev/null; then
  soft "/usr/local 可用空间不足 512MB(当前 $((AVAIL_KB/1024))MB)" "发布包解开约 150MB,再加数据库和日志,建议留 1GB 以上"
fi

# ── 结论 ─────────────────────────────────────────────────────────────────────
printf '\n%s==> 结论%s\n\n' "$C_H" "$C_OFF"

nh="${#HARD_MSGS[@]}"; ns="${#SOFT_MSGS[@]}"

if [ "$nh" -eq 0 ] && [ "$ns" -eq 0 ]; then
  printf '  %s✓ 这台机器可以装 nanotun%s\n\n' "$C_OK" "$C_OFF"
  exit 0
fi

if [ "$nh" -eq 0 ]; then
  printf '  %s✓ 可以装%s,另有 %d 条提醒(不阻塞安装):\n\n' "$C_OK" "$C_OFF" "$ns"
else
  printf '  %s✗ 有 %d 项必须先修复%s' "$C_ERR" "$nh" "$C_OFF"
  [ "$ns" -gt 0 ] && printf ',另有 %d 条提醒' "$ns"
  printf ':\n\n'
fi

if [ "$nh" -gt 0 ]; then
  printf '  %s必须修复%s\n' "$C_ERR" "$C_OFF"
  i=0
  while [ "$i" -lt "$nh" ]; do
    printf '    %d. %s\n' "$((i+1))" "${HARD_MSGS[$i]}"
    printf '       %s%s%s\n' "$C_DIM" "${HARD_FIXES[$i]}" "$C_OFF"
    i=$((i+1))
  done
  printf '\n'
fi

if [ "$ns" -gt 0 ]; then
  printf '  %s提醒%s\n' "$C_WARN" "$C_OFF"
  for m in "${SOFT_MSGS[@]}"; do printf '    · %s\n' "$m"; done
  printf '\n'
fi

[ "$nh" -eq 0 ] || exit 1
exit 0
