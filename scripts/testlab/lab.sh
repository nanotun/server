#!/usr/bin/env bash
# 本地假 VPS —— 在 Docker 里起一台带 systemd 的干净 Linux,把裸机安装脚本从头跑一遍。
#
#   scripts/testlab/lab.sh up          起一台(已存在就复用)
#   scripts/testlab/lab.sh install     跑完整安装:curl 真实发布包 → install.sh
#   scripts/testlab/lab.sh setup       跑开服向导(不带参数即交互式)
#   scripts/testlab/lab.sh browse      真 Chrome 把 Web 后台点一遍(要 pip3 install playwright)
#   scripts/testlab/lab.sh browse-2fa  真 Chrome 把后台 2FA 全生命周期走一遍(注册/登录/恢复码/改密)
#   scripts/testlab/lab.sh drill       灾难恢复演练:备份 → 删库 → 还原 → 逐字对账
#   scripts/testlab/lab.sh i18n        漏译演练:按英文装一遍,输出里出现中文即失败
#   scripts/testlab/lab.sh reset       推倒重来,回到刚开机的干净状态
#
# 全部命令:
#   up / status / install / setup / browse / browse-2fa / drill / i18n / preflight / uninstall / sh / logs / down / reset
#
# 选项(跟在命令后面):
#   --distro ubuntu|debian|rocky|opensuse|alpine   默认 ubuntu(与线上 SRV 的 Ubuntu 26.04 对齐)
#                                         可带版本验最低支持线:ubuntu:20.04 / debian:11 / rocky:8
#   --local                               装本地 HEAD 构建的包,而不是从 GitHub 下发布包
#   --version vX.Y.Z                      指定要装的版本;不给就自动取最新(含预发布)
#   --lang en|zh                          界面语言,透传成容器里的 NANOTUN_LANG(不给就是脚本自己的默认:英文)
#   其余参数原样透传给里面的脚本,例如:lab.sh install --skip-check
#
# 环境变量:
#   LAB_WEB_PORT   宿主上映射 Web 管理端口的号,默认 7443(被占了就换一个)
#
# ── 它能测什么 ────────────────────────────────────────────────────────────
# 只有全新机器才走得到的那些分支:空的 /etc/nanotun 从零落地、第一次 init 出管理员
# 凭据、config 模板占位填充、开服向导、卸载后重装;以及 preflight 在不同发行版上
# 给的包名提示,和各种「坏机器」(没有 TUN / 没有 iptables / /proc 只读 / 没有 systemd)。
# 装坏了 `lab.sh reset` 十几秒回到干净状态,不必再去真机上开备份窗口。
#
# `browse` 再往上盖一层:Web 后台的**界面**。e2e 那边的 60-web.sh 打的是 HTTP 接口,
# 页面渲不渲得出来、按钮点了有没有反应,它一概不知道 —— 那一层归这里。
# `browse-2fa` 是它的姊妹:把后台 TOTP 的**全生命周期**(注册 → 启用拿恢复码 → 二次因子
# 登录 → 错码被拒 → 恢复码一次性 → 改密 step-up)在真浏览器里用内置算码走一遍。密码泄露
# 能不能一键关 2FA、enable 输的码会不会被重放到登录 —— 这类洞 e2e 的 HTTP 断言看不出来。
#
# `drill` 补的是另一个洞:真还原。e2e 只敢验 restore 的守卫会拒绝,不敢在共用的真机上
# 把生产库覆盖掉;这里的机器用完即弃,可以把「停服 → 删库 → 还原 → 对账」整条走完。
#
# ── 它测不了什么(重要)──────────────────────────────────────────────────
# 数据面。客户端真的拨上来跑流量、出口节点、子网路由、MagicDNS —— 内核、网络拓扑
# 和多机关系都不是一个容器能模拟的。那些仍然只认 scripts/e2e/ 那三台真机,发版门禁
# 也不变。这里是**安装脚本的测试台**,替代的是「在 SRV 上开备份窗口」,不是替代 e2e。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="$ROOT/scripts/testlab"

if [ -t 1 ]; then
  C_OK=$'\033[1;32m'; C_WARN=$'\033[1;33m'; C_ERR=$'\033[1;31m'; C_STEP=$'\033[1;36m'; C_OFF=$'\033[0m'
else
  C_OK=''; C_WARN=''; C_ERR=''; C_STEP=''; C_OFF=''
fi
ok()   { printf '    %s✓%s %s\n' "$C_OK"   "$C_OFF" "$*"; }
warn() { printf '    %s!%s %s\n' "$C_WARN" "$C_OFF" "$*"; }
step() { printf '\n%s==> %s%s\n' "$C_STEP" "$*" "$C_OFF"; }
die()  { printf '%sFATAL: %s%s\n' "$C_ERR" "$*" "$C_OFF" >&2; exit 1; }

usage() { sed -n '2,34p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

# ── 参数 ────────────────────────────────────────────────────────────────
DISTRO=ubuntu
LOCAL=0
VERSION=""
# 界面语言。空 = 不设 NANOTUN_LANG,让脚本走自己的默认(英文)—— 那正是绝大多数用户
# 拿到的那一屏,所以默认就该测它。要验中文那份就 --lang zh。
LAB_LANG=""
NO_TUN=0
CMD=""
PASS=()
while (( $# )); do
  case "$1" in
    --distro)  DISTRO="${2:?--distro 后面要跟发行版}"; shift 2 ;;
    --local)   LOCAL=1; shift ;;
    --version) VERSION="${2:?--version 后面要跟版本号}"; shift 2 ;;
    # 不在这儿校验 en|zh:判据在被测脚本里(它们会把不认识的值当场顶回来),
    # 而那正是要验的行为之一 —— 在测试台上再抄一份判据,只会和它分头演化。
    --lang)    LAB_LANG="${2:?--lang 后面要跟 en 或 zh}"; shift 2 ;;
    # 便宜的 OpenVZ / 部分 LXC VPS 就是没有 /dev/net/tun,而这类机器恰恰是自托管
    # 用户最常买的。用它验 preflight 能不能在装之前就把话说清楚。
    --no-tun)  NO_TUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    -*)        PASS+=("$1"); shift ;;
    *)         if [ -z "$CMD" ]; then CMD="$1"; else PASS+=("$1"); fi; shift ;;
  esac
done
[ -n "$CMD" ] || { usage; exit 2; }

# --distro 可以带版本:`ubuntu:20.04`、`debian:11`、`rocky:8`。不带就是下面的默认值。
#
# 加这个是为了能验「最低支持版本」那句话。README 里写 Ubuntu 18.04 起、Debian 10 起,
# 依据是 systemd ≥ 235(RuntimeDirectoryPreserve 那条指令)—— 但推算出来的版本号和
# 实际装得上是两回事,而这种话一旦写进文档就是承诺。有了这个开关,声明的每一个下限
# 都能当场跑一遍。
DISTRO_NAME="${DISTRO%%:*}"
DISTRO_VER=""
[ "$DISTRO" != "$DISTRO_NAME" ] && DISTRO_VER="${DISTRO#*:}"

case "$DISTRO_NAME" in
  ubuntu) BASE="ubuntu:${DISTRO_VER:-26.04}" ;;
  debian) BASE="debian:${DISTRO_VER:-13}" ;;
  # Docker Hub 上的 rockylinux 仓库已归档,官方现在发在 quay.io。
  # 但 8 只在旧的 docker.io/rockylinux 下面有,quay 那边最早是 9。
  rocky)
    if [ "${DISTRO_VER:-9}" = 8 ]; then BASE="rockylinux:8"
    else BASE="quay.io/rockylinux/rockylinux:${DISTRO_VER:-9}"; fi ;;
  # openSUSE Leap:官方镜像在 docker.io/opensuse/leap。Tumbleweed(滚动版)是另一个仓库,
  # 这里只覆盖 Leap —— 自托管用户装的绝大多数是 Leap 这种带固定版本号的。
  opensuse) BASE="opensuse/leap:${DISTRO_VER:-15.6}" ;;
  alpine) BASE="alpine:${DISTRO_VER:-3}" ;;
  *) die "不认识的发行版 ${DISTRO_NAME}(可选:ubuntu / debian / rocky / opensuse / alpine,可带版本如 ubuntu:20.04)" ;;
esac

TAG="$DISTRO_NAME"
[ -n "$DISTRO_VER" ] && TAG="${DISTRO_NAME}-${DISTRO_VER//./-}"
IMAGE="nanotun-lab:${TAG}"
NAME="nanotun-lab-${TAG}"
# 每个发行版一个默认端口。四台可以同时开着(比如一边在 ubuntu 上装,一边在 rocky 上
# 看 preflight),共用 7443 的话第二台起不来,而报错是 docker 的「port is already
# allocated」—— 跟 nanotun 毫无关系,查起来先入为主地往错的方向想。
case "$DISTRO_NAME" in
  ubuntu)   DEF_PORT=7443 ;; debian) DEF_PORT=7444 ;;
  rocky)    DEF_PORT=7445 ;; alpine) DEF_PORT=7446 ;;
  opensuse) DEF_PORT=7447 ;;
esac
# 钉了版本的另占一段端口:同一个发行版的两个版本经常要同时开着比对(比如 20.04 上
# 复现的问题,要立刻在 26.04 上确认是不是版本相关),共用默认端口的话第二台起不来。
# 用版本串的 cksum 散进 7500-7899,同名同版本每次都落在同一个号上,可复现。
if [ -n "$DISTRO_VER" ]; then
  DEF_PORT=$(( 7500 + $(printf '%s' "$DISTRO" | cksum | cut -d' ' -f1) % 400 ))
fi
WEB_PORT="${LAB_WEB_PORT:-$DEF_PORT}"
# 缺 TUN 的那台是独立一台,不能跟正常那台共用容器名/端口 —— 否则 up 会直接复用
# 已存在的那个(带着 /dev/net/tun),测出来的是假绿。
if [ "$NO_TUN" = 1 ]; then
  NAME="${NAME}-notun"
  [ -n "${LAB_WEB_PORT:-}" ] || WEB_PORT=$((DEF_PORT + 10))
fi

command -v docker >/dev/null 2>&1 || die "没有 docker"
docker info >/dev/null 2>&1 || die "docker 没在跑(macOS 上先打开 Docker Desktop)"

# ── 基础动作 ────────────────────────────────────────────────────────────
exists()  { docker inspect "$NAME" >/dev/null 2>&1; }
running() { [ "$(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null || echo false)" = true ]; }

# 有 TTY 就带 -t:开服向导要交互,二维码也要靠它才排得开。
dex() {
  local flags=(-i)
  [ -t 0 ] && flags=(-it)
  # 语言一并带进去:docker exec 不继承宿主环境,不显式传的话容器里永远是默认语言,
  # 于是 --lang zh 看着生效了(测试台自己打的字是中文的),而被测脚本压根没收到。
  [ -n "$LAB_LANG" ] && flags+=(-e "NANOTUN_LANG=$LAB_LANG")
  docker exec "${flags[@]}" "$@"
}

# 透传参数拼成一段可以塞进 `bash -c` 的字符串。
# 不能直接写 printf '%q ' "${PASS[@]}":printf 在**没有参数**时仍会把格式串走一遍,
# 吐出一个 '' —— 于是空数组变成了一个空串参数,被 install.sh 当成未知参数顶回来。
passq() { (( ${#PASS[@]} )) && printf '%q ' "${PASS[@]}" || true; }

ensure_image() {
  if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    step "构建镜像 ${IMAGE}(基于 ${BASE})"
    docker build --build-arg "BASE=${BASE}" -t "$IMAGE" -f "$HERE/Dockerfile" "$HERE"
  fi
}

up() {
  if running; then ok "${NAME} 已在运行"; return 0; fi
  if exists; then docker start "$NAME" >/dev/null; ok "${NAME} 已启动"; wait_boot; return 0; fi
  ensure_image
  step "起一台 ${DISTRO} 假 VPS"

  local run=(docker run -d --name "$NAME" --hostname nanotun-lab
    # systemd 要能写 cgroup、要真的 /run;--privileged 一并解决 CAP_NET_ADMIN、
    # sysctl 可写、iptables 能加规则 —— 一台真 VPS 上 root 本来就有这些。
    --privileged --cgroupns=host
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw
    --tmpfs /run --tmpfs /run/lock
    -p "127.0.0.1:${WEB_PORT}:7443")
  # 光是不加 --device 不够:--privileged 会把宿主整个 /dev 暴露进来,/dev/net/tun
  # 照样在。拿一层空 tmpfs 盖住 /dev/net,才是「这台机器没有 TUN」的样子。
  if [ "$NO_TUN" = 1 ]; then
    run+=(--tmpfs /dev/net)
  else
    run+=(--device /dev/net/tun)
  fi

  # Alpine 没有 systemd,/sbin/init 是 busybox 的,拿它当 PID 1 会立刻退出。
  # 这台只用来跑 preflight —— 看它是否老老实实报「没有 systemd」。
  if [ "$DISTRO_NAME" = alpine ]; then
    run+=("$IMAGE" sleep infinity)
  else
    run+=("$IMAGE")
  fi

  if ! "${run[@]}" >/dev/null 2>/tmp/lab.run.err; then
    if grep -qi 'port is already allocated\|address already in use' /tmp/lab.run.err; then
      rm -f /tmp/lab.run.err
      die "宿主 ${WEB_PORT} 端口被占了。换一个:LAB_WEB_PORT=8443 $0 up"
    fi
    cat /tmp/lab.run.err >&2; rm -f /tmp/lab.run.err
    die "容器起不来"
  fi
  rm -f /tmp/lab.run.err
  ok "${NAME} 已创建"
  wait_boot
  if [ "$NO_TUN" = 1 ]; then
    # 只能等开机之后再拿掉。systemd 启动时会照 kmod 的 static-nodes 规则重建
    # /dev/net/tun(见 /usr/lib/tmpfiles.d/static-nodes-permissions.conf),
    # 所以 --tmpfs /dev/net 盖不住它,--privileged 又把宿主 /dev 整个带了进来。
    docker exec "$NAME" rm -f /dev/net/tun
    ok "已移除 /dev/net/tun —— 这台假装是没有 TUN 的 OpenVZ/LXC VPS"
  fi
}

wait_boot() {
  [ "$DISTRO_NAME" = alpine ] && return 0
  local st
  for _ in $(seq 1 60); do
    st="$(docker exec "$NAME" systemctl is-system-running 2>/dev/null || true)"
    # degraded 在容器里是常态:总有几个单元(时间同步、日志转发之类)没法在容器内起来,
    # 那不影响我们要测的东西。等到 running 才走,多数情况下永远等不到。
    case "$st" in
      running)  ok "systemd 就绪"; return 0 ;;
      degraded) ok "systemd 就绪(degraded —— 容器里正常,有单元起不来不影响安装)"; return 0 ;;
    esac
    sleep 1
  done
  warn "等了 60s systemd 还没就绪(${st:-无输出});先看看 $0 logs"
}

need_up() { running || die "${NAME} 没在跑,先 $0 up"; }

# ── 版本 ────────────────────────────────────────────────────────────────
# 不给 --version 时自己找最新的。注意不能用 /releases/latest:它**不含预发布**,
# 而现在仓库里只有 rc,那条路会 404 到一个叫 "releases" 的假版本号上。
latest_version() {
  curl -fsSL "https://github.com/nanotun/server/releases.atom" 2>/dev/null \
    | sed -n 's#.*<link[^>]*releases/tag/\([^"]*\)".*#\1#p' | head -1
}

# ── 命令 ────────────────────────────────────────────────────────────────
# 带了 --yes 就说明调用方要的是「一条命令装完」那条路 —— 向导不需要人守着,该让它真跑一遍。
#
# 原来 install 一律硬加 --no-setup,理由是「向导要交互」。可用户实际打的那条命令
# (curl … | sudo bash -s -- --dial-host X --web-admin ops --yes)恰恰是向导也一起跑的,
# 于是这个测试台从来没覆盖过它 —— 装完那半段测得很熟,开服那半段一次都没走过。
wants_wizard() {
  local a
  for a in ${PASS[@]+"${PASS[@]}"}; do
    case "$a" in -y|--yes) return 0 ;; --no-setup) return 1 ;; esac
  done
  return 1
}

cmd_install() {
  need_up
  local WIZARD=0
  wants_wizard && WIZARD=1
  if [ "$LOCAL" = 1 ]; then
    local arch ver pkg
    arch="$(docker exec "$NAME" uname -m)"
    case "$arch" in aarch64|arm64) arch=arm64 ;; x86_64|amd64) arch=amd64 ;; *) die "不支持的架构 ${arch}" ;; esac
    ver="dev-$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo local)"
    step "构建本地包 ${ver} (${arch})"
    ( cd "$ROOT" && NANOTUN_RELEASE_I_KNOW=1 NANOTUN_ARCHES="$arch" NANOTUN_VERSION="$ver" ./scripts/build-release.sh >&2 )
    pkg="$ROOT/dist/nanotun-${ver}-linux-${arch}.tar.gz"
    [ -f "$pkg" ] || die "没找到刚构建的包:${pkg}"

    step "送进容器并安装"
    # 落点不能选 /tmp:新版 systemd 默认启用 tmp.mount,开机后 /tmp 上盖着一层 tmpfs。
    # docker cp 写的是镜像层里的 /tmp,正好被压在挂载点下面 —— 复制「成功」,容器里
    # 却看不见这个文件,报出来的是 tar: Cannot open。/var/tmp 不是挂载点。
    docker cp "$pkg" "$NAME:/var/tmp/nanotun-pkg.tar.gz"
    # 走 install-self-hosted.sh 而不是 install.sh:后者的职责是「把包从网上弄下来」,
    # 包已经在本地了就没它的事。真正动系统的逻辑全在前者,测的也正是它。
    #
    # 透传的参数**一个都不给安装脚本** —— 它不接受任何参数(向导的活儿它不干)。
    # 原来这里在非向导模式下传了 $(passq),而当时那个脚本对多余参数是默默忽略的:
    # `lab.sh install --local --dial-host X` 装完全绿,--dial-host 一个字没生效。
    # 测试台谎报成功比装不上更糟,而这条恰好骗过的是「参数到底有没有生效」这类验证。
    # 现在安装脚本会把未知参数顶回来(exit 2),这里也就没有再传的道理。
    dex "$NAME" bash -c "set -e
      mkdir -p /opt/nanotun && tar -xzf /var/tmp/nanotun-pkg.tar.gz -C /opt/nanotun && rm -f /var/tmp/nanotun-pkg.tar.gz
      cd /opt/nanotun/nanotun-${ver}-linux-${arch}
      ./scripts/install-self-hosted.sh"
    if [ "$WIZARD" = 1 ]; then
      echo
      step "接着跑开服向导(用户那条一行命令的后半段)"
      cmd_setup
    else
      # 与远端路径(下面那句 ok)同口径:装完不等于能连,得把下一步说出来。
      ok "接着跑开服向导:$0 setup       (非交互:$0 setup -y --dial-host 198.51.100.7)"
    fi
  else
    local ver="$VERSION"
    if [ -z "$ver" ]; then
      ver="$(latest_version)" || true
      [ -n "$ver" ] || die "取不到最新版本号,用 --version vX.Y.Z 显式指定"
      ok "未指定版本,取到最新的 ${ver}(含预发布)"
    fi
    step "在容器里跑 install.sh(和用户看到的是同一条命令)"
    # 带了 --yes 就连向导一起跑,一步不拆 —— 那才是用户真打的那条命令。没带的话仍加
    # --no-setup:交互式向导要人守着,docker exec 这边没有终端。
    local no_setup="--no-setup"
    local envs=(-e "NANOTUN_VERSION=${ver}")
    [ -n "$LAB_LANG" ] && envs+=(-e "NANOTUN_LANG=$LAB_LANG")
    if [ "$WIZARD" = 1 ]; then
      no_setup=""
      # 向导那边的密码只走环境变量(setup.sh 故意不收命令行参数,理由见那边注释),
      # 而 docker exec 不继承宿主环境 —— 不显式带进去,--web-admin 这条路就测不到。
      [ -n "${NANOTUN_WEB_ADMIN_PASSWORD:-}" ] && envs+=(-e "NANOTUN_WEB_ADMIN_PASSWORD=${NANOTUN_WEB_ADMIN_PASSWORD}")
    fi
    # 先落盘再执行,别用 `curl … | bash`:curl 失败时 bash 拿到的是个空脚本,跑完零行
    # 内容以 0 退出 —— 测试台会报「安装成功」,而容器里一个字节都没下下来。实测被这个
    # 骗过一次:容器 DNS 挂了,退出码 0,机器上还是旧版本,差点当成升级路径的 bug 去查。
    # 测试台谎报成功比装不上更糟。
    dex "${envs[@]}" "$NAME" bash -c \
      "curl -fsSL https://raw.githubusercontent.com/nanotun/server/main/scripts/install.sh -o /root/nanotun-install.sh \
         && bash /root/nanotun-install.sh ${no_setup} $(passq)"
    echo
    # 例子里的地址不能写 127.0.0.1 —— 向导会按语法把回环判掉("客户端拨到自己机器"),
    # 照抄这行提示的人拿到的是一句 FATAL。用 RFC 5737 的文档保留段:语法过得去,又不会
    # 有人误以为那是个真能拨的地址。
    [ "$WIZARD" = 1 ] || ok "接着跑开服向导:$0 setup       (非交互:$0 setup -y --dial-host 198.51.100.7)"
  fi
}

cmd_setup() {
  need_up
  step "开服向导"
  # Web 后台密码只走环境变量(向导故意不收命令行参数,理由见 setup.sh),而 docker exec
  # 不继承宿主的环境 —— 不显式带进去的话,`--web-admin` 那条无人值守路径在这里根本测不到。
  local envs=()
  [ -n "${NANOTUN_WEB_ADMIN_PASSWORD:-}" ] && envs=(-e "NANOTUN_WEB_ADMIN_PASSWORD=${NANOTUN_WEB_ADMIN_PASSWORD}")
  dex ${envs[@]+"${envs[@]}"} "$NAME" nanotun-setup ${PASS[@]+"${PASS[@]}"}
}

# preflight 用工作区里的这一份,不走网络 —— 测的是 HEAD,不是 main 上已发布的那份。
cmd_preflight() {
  need_up
  step "环境检查(工作区的 scripts/preflight.sh)"
  local envs=()
  [ -n "$LAB_LANG" ] && envs=(-e "NANOTUN_LANG=$LAB_LANG")
  docker exec -i ${envs[@]+"${envs[@]}"} "$NAME" bash -s -- ${PASS[@]+"${PASS[@]}"} \
    < "$ROOT/scripts/preflight.sh"
}

cmd_uninstall() {
  need_up
  step "卸载"
  # bash -c '脚本' 之后的第一个参数是内层的 $0,不是 $1 —— 少垫一个占位的话,
  # --purge 会被当成 $0 吞掉,卸载看着跑了,数据却一点没删。
  dex "$NAME" bash -c 'u="$(ls /opt/nanotun/*/scripts/uninstall.sh 2>/dev/null | head -1)"
    [ -n "$u" ] || { echo "容器里没有解压好的发布包,找不到 uninstall.sh" >&2; exit 1; }
    bash "$u" "$@"' _ ${PASS[@]+"${PASS[@]}"}
}

cmd_status() {
  if ! exists; then echo "${NAME}: 不存在"; return 0; fi
  printf '%s: %s\n' "$NAME" "$(docker inspect -f '{{.State.Status}}' "$NAME")"
  running || return 0
  docker exec "$NAME" sh -c '
    printf "  发行版   %s\n" "$(. /etc/os-release; echo "$PRETTY_NAME")"
    printf "  架构     %s\n" "$(uname -m)"
    if [ -x /usr/local/bin/nanotund ]; then
      v="$(/usr/local/bin/nanotund --version 2>/dev/null | head -1)"
      # rc2 及更早的 nanotund 没有 --version,取空 —— 装的是真实发布包时会碰到。
      printf "  nanotund %s\n" "${v:-已装(这个版本不认 --version)}"
      printf "  服务     %s\n" "$(systemctl is-active nanotun nanotun-web 2>/dev/null | tr "\n" " ")"
    else
      printf "  nanotund 未安装\n"
    fi' || true
  # 别只是把网址印出来完事 —— 宿主能不能真的连上取决于 Docker Desktop 的端口转发,
  # 而它在 macOS 上并不总是好使(见过 TCP 连得上、流量却根本没进容器的情况:容器里
  # ss 看不到任何连接,服务端日志也是空的)。印一个打不开的链接,会让人以为是
  # nanotun-web 挂了,转头去查一个根本不存在的问题。所以这里当场探一下再说。
  local code
  code="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 3 "https://127.0.0.1:${WEB_PORT}/" 2>/dev/null || true)"
  if [ -n "$code" ] && [ "$code" != 000 ]; then
    printf '  Web      https://127.0.0.1:%s/  (HTTP %s)\n' "$WEB_PORT" "$code"
  else
    printf '  Web      https://127.0.0.1:%s/  宿主连不上 —— Docker Desktop 端口转发的毛病,不是服务端\n' "$WEB_PORT"
    printf '           容器里验:docker exec %s curl -sk -o /dev/null -w "%%{http_code}\\n" https://127.0.0.1:7443/\n' "$NAME"
  fi
}

# browse / browse-2fa 跑之前该具备的条件,一次讲清楚 —— 这几条任何一条不满足,Playwright
# 报出来的都是让人查错方向的错(ERR_CONNECTION_REFUSED / 找不到 password_confirm 之类)。
# 两个测试都从抢首位管理员起步,所以 /setup 必须还开着。
browse_precheck() {
  need_up
  command -v python3 >/dev/null 2>&1 || die "没有 python3"
  python3 -c 'import playwright' 2>/dev/null || die "缺 playwright:pip3 install playwright"

  # 浏览器跑在宿主上,必须真的能连进容器。macOS 上 Docker Desktop 的端口转发时好时坏
  # (见 cmd_status 里那段),不先探一下的话,Playwright 报的是 ERR_CONNECTION_REFUSED,
  # 看着像 nanotun-web 没起来 —— 方向就带偏了。
  local code
  code="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 "https://127.0.0.1:${WEB_PORT}/" 2>/dev/null || true)"
  [ -n "$code" ] && [ "$code" != 000 ] \
    || die "宿主连不上 https://127.0.0.1:${WEB_PORT}/ —— 先 $0 status 看是端口转发还是服务没起"

  # 已经有管理员的话「抢首位」那条断言必挂,而挂出来的样子是「找不到 password_confirm
  # 输入框」,跟真实原因隔着好几层 —— 在这里先说清楚。
  code="$(docker exec "$NAME" curl -sk -o /dev/null -w '%{http_code}' --max-time 5 \
            https://127.0.0.1:7443/setup 2>/dev/null || true)"
  [ "$code" = 200 ] \
    || die "这台已经有 Web 管理员了(/setup 回 ${code},已自动关闭)。这个测试要自己抢首位管理员:
       $0 reset && $0 install --local        # 装的时候别带 --web-admin"
}

# 真浏览器走一遍 Web 后台。断言都在 browse.py 里。
cmd_browse() {
  browse_precheck
  step "浏览器实操(真 Chrome 把后台点一遍)"
  python3 "$HERE/browse.py" --base "https://127.0.0.1:${WEB_PORT}" ${PASS[@]+"${PASS[@]}"}
}

# 真浏览器走一遍后台 2FA 全生命周期。断言都在 browse_2fa.py 里。
# 它内置 RFC6238 算码,跑起来会因「等新的 TOTP 时间步」有几段 30s 的停顿 —— 属正常,不是卡住。
cmd_browse_2fa() {
  browse_precheck
  step "浏览器实操(真 Chrome 把后台 2FA 全生命周期走一遍)"
  python3 "$HERE/browse_2fa.py" --base "https://127.0.0.1:${WEB_PORT}" ${PASS[@]+"${PASS[@]}"}
}

# 漏译演练:装一台**英文**的机器,然后在整屏输出里找中文。
#
# 为什么需要它:安装链的文案是双语的,而漏译**只在运行时才看得见**。
# Go 那侧的守卫(cmd/nanotun-admin/scripts_i18n_guard_test.go)能钉住「默认必须英文」
# 「不许把默认按回 zh」「--help 两种语言都得有」,但它读的是源码和 --help 那一屏 ——
# 一句漏在装机第 6 步、或者收尾那段「常用运维 / 卸载」里的中文,它一个字也看不到。
#
# 2026-08-28 实测就是这样:install-self-hosted.sh 收尾那两块当时还是裸中文,而
# `bash -n`、全量 go test、`--help` 双语检查全绿 —— 唯一发现它的办法是真装一遍,
# 然后盯着屏幕。这条演练把「盯着屏幕」变成一个退出码。
#
# 它必然重置容器:要看的正是**全新机器**那条路(首次生成配置、第一次 init 出 PSK、
# 收尾提示),沿用一台装过的机器会绕开一半文案。
cmd_i18n() {
  step "漏译演练:全新机器上按英文装一遍,再在输出里找中文"
  exists && docker rm -f "$NAME" >/dev/null 2>&1 || true
  up

  local log; log="$(mktemp)"
  # 语言留空 = 不设 NANOTUN_LANG,走脚本自己的默认(英文)。那正是绝大多数人拿到的那一屏。
  #
  # 这几个是**普通赋值**,不是 `VAR=值 函数` 那种前缀 —— 数组做命令前缀在 bash 里不成立:
  # `PASS=(-y --x) cmd` 会把字面量 "(-y --x)" 当成一个标量赋给 PASS,于是向导收到一个
  # 叫 `(-y` 的参数、打出帮助就退了(2026-08-28 写这条演练时当场踩到,而症状是整条演练
  # 一声不响地结束,连结论都没打)。
  # 把测试台自己的旁白静音。这条演练要看的是**被测脚本**打了什么,而 lab.sh 自己的
  # step/ok/warn 一直是中文(它是给维护者看的工具,也应该一直是中文)。
  #
  # 靠一份「排除这些中文串」的清单来区分行不通:清单会跟着 lab.sh 的文案漂,漏一条就是
  # 一次假红 —— 写这条演练时就当场漏了「送进容器并安装」。静音是按**来源**分的,不按内容。
  local _saved_step _saved_ok _saved_warn
  _saved_step="$(declare -f step)"; _saved_ok="$(declare -f ok)"; _saved_warn="$(declare -f warn)"
  step() { :; }; ok() { :; }; warn() { :; }

  LAB_LANG=""
  LOCAL=1
  PASS=()
  cmd_install                                                       >>"$log" 2>&1
  PASS=(-y --dial-host 198.51.100.7)
  cmd_setup                                                         >>"$log" 2>&1
  PASS=()
  # 装完之后由人单独敲的那两个,同样要看:它们的语言来自落盘的 /etc/nanotun/lang。
  dex "$NAME" nanotun-uninstall --dry-run                           >>"$log" 2>&1
  dex "$NAME" nanotun-set-suffix --help                             >>"$log" 2>&1

  eval "$_saved_step"; eval "$_saved_ok"; eval "$_saved_warn"

  # 剩下要排除的只有 build-release.sh:打包是维护者动作,不是装机的一部分,而 cmd_install
  # 在 --local 模式下会把它的输出一并带进来。它那几行是固定的编号步骤。
  local hits count
  hits="$(grep -n '[一-鿿]' "$log" \
    | grep -vE '(警告:绕过发版门|交叉编译|复制 config|打包 nanotun-|清理临时目录|生成 SHA256SUMS|完成。发布包)' \
    || true)"

  if [ -n "$hits" ]; then
    count="$(printf '%s\n' "$hits" | grep -c . || true)"
    printf '%s\n' "$hits" >&2
    echo >&2
    die "英文安装里有 ${count} 行中文输出(上面每行都带行号,完整日志:$log)——
     这些是漏译。文案要成对:die_t / ok_t / warn_t / tsel,或 if [ \"\$NT_LANG\" = zh ] 的两个分支。"
  fi
  rm -f "$log"
  ok "英文安装全程没有中文残留(装机 + 向导 + 卸载预演 + 改后缀帮助)"
}

# 灾难恢复演练。断言都在 restore-drill.sh 里。
#
# 它会把这台机器的库删掉再还原 —— 这正是要测的东西,所以只让它在 lab 容器上跑。
cmd_drill() {
  need_up
  step "灾难恢复演练(备份 → 删库 → 还原 → 对账)"
  docker exec "$NAME" test -x /usr/local/bin/nanotun-admin \
    || die "这台还没装 nanotun,先 $0 install"
  bash "$HERE/restore-drill.sh" --container "$NAME" --base "https://127.0.0.1:${WEB_PORT}"
}

case "$CMD" in
  up)        up ;;
  status)    cmd_status ;;
  install)   cmd_install ;;
  setup)     cmd_setup ;;
  browse)    cmd_browse ;;
  browse-2fa) cmd_browse_2fa ;;
  drill)     cmd_drill ;;
  i18n)      cmd_i18n ;;
  preflight) cmd_preflight ;;
  uninstall) cmd_uninstall ;;
  sh)        need_up; dex "$NAME" bash ;;
  logs)      need_up; docker exec "$NAME" journalctl -n "${PASS[0]:-120}" --no-pager ;;
  down)      exists && docker rm -f "$NAME" >/dev/null && ok "${NAME} 已销毁" || ok "${NAME} 本来就不在" ;;
  reset)     exists && docker rm -f "$NAME" >/dev/null 2>&1 || true; up ;;
  *)         die "不认识的命令 ${CMD}(看 $0 --help)" ;;
esac
