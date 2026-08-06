#!/usr/bin/env bash
# 本地假 VPS —— 在 Docker 里起一台带 systemd 的干净 Linux,把裸机安装脚本从头跑一遍。
#
#   scripts/testlab/lab.sh up          起一台(已存在就复用)
#   scripts/testlab/lab.sh install     跑完整安装:curl 真实发布包 → install.sh
#   scripts/testlab/lab.sh setup       跑开服向导(不带参数即交互式)
#   scripts/testlab/lab.sh reset       推倒重来,回到刚开机的干净状态
#
# 全部命令:
#   up / status / install / setup / preflight / uninstall / sh / logs / down / reset
#
# 选项(跟在命令后面):
#   --distro ubuntu|debian|rocky|alpine   默认 ubuntu(与线上 SRV 的 Ubuntu 26.04 对齐)
#   --local                               装本地 HEAD 构建的包,而不是从 GitHub 下发布包
#   --version vX.Y.Z                      指定要装的版本;不给就自动取最新(含预发布)
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

usage() { sed -n '2,32p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

# ── 参数 ────────────────────────────────────────────────────────────────
DISTRO=ubuntu
LOCAL=0
VERSION=""
NO_TUN=0
CMD=""
PASS=()
while (( $# )); do
  case "$1" in
    --distro)  DISTRO="${2:?--distro 后面要跟发行版}"; shift 2 ;;
    --local)   LOCAL=1; shift ;;
    --version) VERSION="${2:?--version 后面要跟版本号}"; shift 2 ;;
    # 便宜的 OpenVZ / 部分 LXC VPS 就是没有 /dev/net/tun,而这类机器恰恰是自托管
    # 用户最常买的。用它验 preflight 能不能在装之前就把话说清楚。
    --no-tun)  NO_TUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    -*)        PASS+=("$1"); shift ;;
    *)         if [ -z "$CMD" ]; then CMD="$1"; else PASS+=("$1"); fi; shift ;;
  esac
done
[ -n "$CMD" ] || { usage; exit 2; }

case "$DISTRO" in
  ubuntu) BASE=ubuntu:26.04 ;;
  debian) BASE=debian:13 ;;
  # Docker Hub 上的 rockylinux 仓库已归档,官方现在发在 quay.io。
  rocky)  BASE=quay.io/rockylinux/rockylinux:9 ;;
  alpine) BASE=alpine:3 ;;
  *) die "不认识的发行版 ${DISTRO}(可选:ubuntu / debian / rocky / alpine)" ;;
esac
IMAGE="nanotun-lab:${DISTRO}"
NAME="nanotun-lab-${DISTRO}"
# 每个发行版一个默认端口。四台可以同时开着(比如一边在 ubuntu 上装,一边在 rocky 上
# 看 preflight),共用 7443 的话第二台起不来,而报错是 docker 的「port is already
# allocated」—— 跟 nanotun 毫无关系,查起来先入为主地往错的方向想。
case "$DISTRO" in
  ubuntu) DEF_PORT=7443 ;; debian) DEF_PORT=7444 ;;
  rocky)  DEF_PORT=7445 ;; alpine) DEF_PORT=7446 ;;
esac
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
  if [ "$DISTRO" = alpine ]; then
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
  [ "$DISTRO" = alpine ] && return 0
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
    # 要跑向导时,透传的参数一个都不给安装脚本 —— 这与 install.sh 的分工一致:
    # 它自己只认 --check-only / --skip-check / --no-setup,其余原样交给向导。
    local inst_args=""
    [ "$WIZARD" = 1 ] || inst_args="$(passq)"
    dex "$NAME" bash -c "set -e
      mkdir -p /opt/nanotun && tar -xzf /var/tmp/nanotun-pkg.tar.gz -C /opt/nanotun && rm -f /var/tmp/nanotun-pkg.tar.gz
      cd /opt/nanotun/nanotun-${ver}-linux-${arch}
      ./scripts/install-self-hosted.sh ${inst_args}"
    if [ "$WIZARD" = 1 ]; then
      echo
      step "接着跑开服向导(用户那条一行命令的后半段)"
      cmd_setup
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
    if [ "$WIZARD" = 1 ]; then
      no_setup=""
      # 向导那边的密码只走环境变量(setup.sh 故意不收命令行参数,理由见那边注释),
      # 而 docker exec 不继承宿主环境 —— 不显式带进去,--web-admin 这条路就测不到。
      [ -n "${NANOTUN_WEB_ADMIN_PASSWORD:-}" ] && envs+=(-e "NANOTUN_WEB_ADMIN_PASSWORD=${NANOTUN_WEB_ADMIN_PASSWORD}")
    fi
    dex "${envs[@]}" "$NAME" bash -c \
      "curl -fsSL https://raw.githubusercontent.com/nanotun/server/main/scripts/install.sh | bash -s -- ${no_setup} $(passq)"
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
  docker exec -i "$NAME" bash -s -- ${PASS[@]+"${PASS[@]}"} < "$ROOT/scripts/preflight.sh"
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

case "$CMD" in
  up)        up ;;
  status)    cmd_status ;;
  install)   cmd_install ;;
  setup)     cmd_setup ;;
  preflight) cmd_preflight ;;
  uninstall) cmd_uninstall ;;
  sh)        need_up; dex "$NAME" bash ;;
  logs)      need_up; docker exec "$NAME" journalctl -n "${PASS[0]:-120}" --no-pager ;;
  down)      exists && docker rm -f "$NAME" >/dev/null && ok "${NAME} 已销毁" || ok "${NAME} 本来就不在" ;;
  reset)     exists && docker rm -f "$NAME" >/dev/null 2>&1 || true; up ;;
  *)         die "不认识的命令 ${CMD}(看 $0 --help)" ;;
esac
