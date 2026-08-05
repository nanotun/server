#!/usr/bin/env bash
# nanotun 一条命令开服 —— 检查环境 → 下载发布包 → 安装 → 开服向导。
#
#   sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/nanotun/server/main/scripts/install.sh)"
#
# 跑完就能用:向导会问拨号地址、建第一个 VPN 用户、出两个二维码。
#
# 为什么不是更眼熟的 `curl … | sudo bash`:Ubuntu / Debian 的 sudo 默认 use_pty,会
# 另开一个 pty 跑命令,叠加管道占着 sudo 的 stdin,向导一问话就被挂起(全新 Ubuntu
# 26.04 上实测两次两挂)。把脚本当参数传给 bash 则 bash 的 stdin 就是终端,
# 不存在这个问题。管道形态仍然能装,只是本脚本会认出这个组合、装完跳过向导让人手动跑。
#
# 无人值守(CI / cloud-init)不需要问话,管道形态最省事,不认得的参数一律转交向导 ——
#   curl -fsSL .../install.sh | sudo bash -s -- --dial-host vpn.example.com --user alice --yes
#
# 只想先看看这台机器行不行(不下载、不安装、不改任何东西):
#   curl -fsSL .../install.sh | bash -s -- --check-only
#   环境检查也可以单独跑:curl -fsSL .../preflight.sh | bash
#
# 装指定版本(生产建议钉版本,别跟着 latest 漂):
#   sudo NANOTUN_VERSION=v0.1.0 bash -c "$(curl -fsSL .../install.sh)"
#
# 只下载不安装(想先看看包里是什么):
#   curl -fsSL .../install.sh | NANOTUN_NO_INSTALL=1 bash
#
# 注意跟 install-self-hosted.sh 的分工:本脚本是**网络入口**,负责把发布包弄到这台
# 机器上;真正动系统的那些活(systemd / 防火墙 / 密钥)都在 install-self-hosted.sh
# 里,它随发布包走,也可以从解压好的目录单独跑。
#
# 选项:
#   --check-only   只做环境检查,一次列全问题后退出(不需要 root)
#   --skip-check   跳过环境检查直接装(不建议;装到一半失败比现在就知道难收拾)
#   --no-setup     装完不自动进开服向导
#   其余参数        原样转交开服向导,例如 --dial-host / --user / --web-admin / --yes
#
# 环境变量:
#   NANOTUN_WEB_ADMIN_PASSWORD  Web 后台管理员密码,配合 --web-admin <名字> 使用。
#                       走环境变量而不是命令行参数:argv 对同机所有用户可见(ps),
#                       还会落进 shell history。注意 sudo 默认不传环境变量,得写成
#                       `sudo NANOTUN_WEB_ADMIN_PASSWORD=... bash -c "$(curl ...)"`。
#   NANOTUN_VERSION     要装的版本,默认取最新 Release
#   NANOTUN_INSTALL_DIR 解压落点,默认 /opt/nanotun
#   NANOTUN_NO_INSTALL  =1 时只下载解压,不执行 install-self-hosted.sh
#   NANOTUN_REPO        换仓库(fork 自用)
#   NANOTUN_BRANCH      从哪个分支取 preflight.sh,默认 main
#   NANOTUN_VERBOSE     =1 时安装过程连 systemd 状态和日志一起打出来(默认只给结论)
#
# 安装要 root(写 /usr/local/bin、/etc/systemd/system、sysctl)。
# --check-only 和 NANOTUN_NO_INSTALL=1 不需要 root。
set -euo pipefail

REPO="${NANOTUN_REPO:-nanotun/server}"
BRANCH="${NANOTUN_BRANCH:-main}"
INSTALL_DIR="${NANOTUN_INSTALL_DIR:-/opt/nanotun}"
RAW_BASE="https://raw.githubusercontent.com/${REPO}/${BRANCH}/scripts"

# curl 的停滞防护。--retry 只在**失败**时重试,而最难受的一种失败根本不算失败:
# 连接建好了、数据一个字节都不来。curl 会一直等下去,屏幕停在「下载 …」那一行 ——
# 没有超时、没有进度、也没法判断该不该继续等。实测容器里就这么卡了 8 分钟,
# 目标文件始终 0 字节;下面那个 `28) 下载失败:超时` 分支从来没有机会被走到。
#
# 大文件不能用 --max-time:真慢的小机器(几百 K 带宽拉十几 M)会被无辜掐断,而它
# 本来是能装完的。--speed-limit/--speed-time 只掐「停住不动」的那种 —— 慢但在动的
# 照样让它下完,这才是要区分的两件事。
CURL_BASE=(--fail --silent --show-error --location --retry 3 --connect-timeout 20)
# 几十 KB 的脚本与清单:整体封顶即可(最坏 4 次尝试 × 30 秒)。
CURL_SMALL=("${CURL_BASE[@]}" --max-time 30)
# 十几 M 的发布包:30 秒内传不满 1KB/s 就判死,重试 3 次,最坏约 2 分钟收敛。
CURL_BIG=("${CURL_BASE[@]}" --speed-limit 1024 --speed-time 30)

CHECK_ONLY=0; SKIP_CHECK=0; NO_SETUP=0; SETUP_ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --check-only) CHECK_ONLY=1; shift ;;
    --skip-check) SKIP_CHECK=1; shift ;;
    --no-setup)   NO_SETUP=1; shift ;;
    # 打开头那段注释。不写死行号 —— 改文档时忘了同步行号,--help 就会截半句话。
    # 被 curl | bash 时 $0 不是文件,读不到就退回一个链接。
    -h|--help)
      # 退回的那份必须自己够用。--help 最常见的用法恰恰是 curl | bash -s -- --help,
      # 而那时 $0 是 "bash"、读不到文件 —— 只回一个链接等于让人再去开一次浏览器。
      awk 'NR>1 && /^#/ {sub(/^#[[:space:]]?/,""); print; next} NR>1 {exit}' "$0" 2>/dev/null || cat <<EOF
nanotun 一条命令开服 —— 检查环境 → 下载发布包 → 安装 → 开服向导。

  sudo bash -c "\$(curl -fsSL ${RAW_BASE}/install.sh)"

  别用 curl … | sudo bash:Ubuntu/Debian 的 sudo 默认 use_pty,向导会被挂死。
  无人值守(不需要问话)用管道没问题:
  curl -fsSL ${RAW_BASE}/install.sh | sudo bash -s -- --dial-host <域名> --user <名> --yes

  连 Web 后台账号一起定(不然 /setup 谁先打开谁是管理员):
  curl -fsSL ${RAW_BASE}/install.sh | sudo NANOTUN_WEB_ADMIN_PASSWORD='<密码>' bash -s -- \\
    --dial-host <域名> --user <名> --web-admin <后台用户名> --yes

选项:
  --check-only   只做环境检查,一次列全问题后退出(不需要 root)
  --skip-check   跳过环境检查直接装(不建议)
  --no-setup     装完不自动进开服向导

环境变量:
  NANOTUN_VERSION     要装的版本,默认取最新 Release(不含预发布)
  NANOTUN_INSTALL_DIR 解压落点,默认 /opt/nanotun
  NANOTUN_NO_INSTALL  =1 时只下载解压,不安装(不需要 root)
  NANOTUN_REPO        换仓库(fork 自用)
  NANOTUN_VERBOSE     =1 时连 systemd 状态和日志一起打出来(默认只给结论)

完整说明: https://github.com/${REPO}
EOF
      exit 0 ;;
    # 自己不认得的一律转交开服向导。这条是「一条命令装完就能用」的关键:
    #
    #   curl -fsSL .../install.sh | sudo bash -s -- --dial-host vpn.example.com --user alice --yes
    #
    # 没有它,无人值守就只能拆成两条命令(装完再 sudo nanotun-setup ...),而中间那步
    # 恰恰是最容易被忘掉的 —— 忘了它,服务是起着的,客户端却因为没有 server_dial_host
    # 而连不上,现象离原因很远。
    #
    # 不认得的参数不在这里判死,是因为判据在向导那边(它才知道自己收哪些 flag),
    # 在这里再抄一份必然跟它分头演化。写错的 flag 仍然会被向导当场拒掉并点名。
    *) SETUP_ARGS+=("$1"); shift ;;
  esac
done

# 但如果向导压根不会跑,这些参数就没人接了 —— 而且此刻大概率是把 install.sh 的
# flag 敲错了(比如 --skip-chek)。这种要在动系统之前就拦下,不能装完一整套再说。
if [ ${#SETUP_ARGS[@]} -gt 0 ] && { [ "$CHECK_ONLY" = 1 ] || [ "$NO_SETUP" = 1 ]; }; then
  if [ "$CHECK_ONLY" = 1 ]; then why="--check-only 只检查不安装"; else why="--no-setup 明说了不跑向导"; fi
  printf 'install.sh: 这些参数本该转交开服向导,但这次向导不会跑(%s):%s\n' "$why" "${SETUP_ARGS[*]}" >&2
  printf '   install.sh 自己只认 --check-only / --skip-check / --no-setup,其余一律转交向导(--help 看用法)。\n' >&2
  exit 2
fi

info() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
ok()   { printf '    \033[1;32m✓\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mFATAL: %s\033[0m\n' "$*" >&2; exit 1; }

# 这两个一起给是矛盾的,而按原来的写法后果是**静默装上**:--skip-check 会让下面那段
# `if [ "$SKIP_CHECK" = 0 ]` 整个跳过,而「只检查就退出」正好写在那段里面 ——
# 于是一条本意是「只看看」的命令,以 root 把整个服务端装了。宁可让它报错。
if [ "$CHECK_ONLY" = 1 ] && [ "$SKIP_CHECK" = 1 ]; then
  die "--check-only 和 --skip-check 是矛盾的:一个是只检查不安装,另一个是不检查直接装。
   只想看看这台机器行不行:--check-only
   明知有问题也要硬装:--skip-check"
fi

# ── 1. 环境自检 ──────────────────────────────────────────────────────────────
#
# 判据全在 preflight.sh 里,这里只负责把它弄到手再跑。不在本文件里重写一份 ——
# 同一套「这台机器行不行」的规则散在三个脚本里,迟早对不上。
#
# 被 curl | bash 时本地没有 scripts/ 目录,得先把 preflight.sh 也下下来;
# 从解压好的发布包里跑时它就在隔壁,直接用本地那份(还能离线)。
run_preflight() {
  local self local_pf pf args=()

  if [ "$CHECK_ONLY" = 1 ]; then
    args+=(--dry-run)          # 只是看看,连 sysctl 都别写
  elif [ "${NANOTUN_NO_INSTALL:-0}" = "1" ]; then
    # 只下载解压,同样不动系统。本脚本头部和 --help 都明写它「不需要 root」,
    # 上面那道 root 硬检查也确实为它放了行 —— 漏的是这里:环境检查照样收到
    # --for-install,于是非 root 被判死在「不是 root」上,一个字节都没下就退了。
    # 文档说不用 root、代码却拦下,这种自相矛盾比单纯的限制更难自查。
    args+=(--dry-run)
  else
    # 跑完就要装,所以非 root 在这条路上是硬伤,得当场判死。
    # --check-only 那条路相反:它明确不需要 root,preflight 只会提醒一句。
    args+=(--for-install)
  fi

  # 只有在「本脚本确实是磁盘上的一个文件」时才找隔壁的 preflight.sh。
  # 这个 -f 判断不能省:被 curl | sudo bash 时 BASH_SOURCE[0] 是字符串 "bash",
  # dirname 出来是 ".",于是「隔壁」就成了用户当前所在目录 —— 那意味着谁在自己
  # 目录里放一个 preflight.sh,我们就以 root 跑了它。走网络那条路反而是安全的。
  self="${BASH_SOURCE[0]:-}"
  if [ -n "$self" ] && [ -f "$self" ]; then
    local_pf="$(cd "$(dirname "$self")" 2>/dev/null && pwd)/preflight.sh"
    if [ -f "$local_pf" ]; then
      bash "$local_pf" "${args[@]+"${args[@]}"}"
      return $?
    fi
  fi

  command -v curl >/dev/null 2>&1 || die "缺少 curl,没法取环境检查脚本(apt install curl / yum install curl)"

  # mktemp 失败必须当场拦下,不能让一个空变量顺着往下走。
  #
  # 本函数是在 `if ! run_preflight` 里调用的,而 bash 在条件上下文中会关掉**整个函数体**
  # 的 errexit —— 所以 mktemp 挂了脚本不会停,$pf 只是留空,接着 curl -o "" 报
  # 「blank argument」,最终打出来的是「下载 preflight.sh 失败 / 网络不通的话可以
  # --skip-check」。真实原因是临时目录写不进去:既指错了方向,又建议跳过环境检查。
  # 一台 /tmp 是 0700 root 的机器上,非 root 跑 --check-only 就是这个下场。
  pf="$(mktemp)" || pf=""
  [ -n "$pf" ] || die "创建临时文件失败 —— ${TMPDIR:-/tmp} 写不进去(权限 / 只读 / 配额 / 空间不足)。
   换个位置重试,例如:TMPDIR=/var/tmp <刚才那条命令>"
  curl "${CURL_SMALL[@]}" -o "$pf" "$RAW_BASE/preflight.sh" \
    || { rm -f "$pf"; die "下载 preflight.sh 失败: $RAW_BASE/preflight.sh
   网络不通的话可以 --skip-check 跳过检查直接装(风险自负)。"; }
  bash "$pf" "${args[@]+"${args[@]}"}"
  local rc=$?
  rm -f "$pf"
  return $rc
}

if [ "$SKIP_CHECK" = 0 ]; then
  if ! run_preflight; then
    if [ "$CHECK_ONLY" = 1 ]; then exit 1; fi
    die "环境检查没过(见上面的修复清单)。修完重跑本命令;
   确认要带着问题硬装可以加 --skip-check。"
  fi
  [ "$CHECK_ONLY" = 1 ] && exit 0
else
  printf '    \033[1;33m!\033[0m --skip-check:跳过环境检查\n'
fi

case "$(uname -m)" in
  x86_64|amd64)  ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "不支持的架构 $(uname -m)。发布包只有 linux-amd64 与 linux-arm64;
   其它架构请自行 go build(见仓库 README 的源码构建一节)。" ;;
esac

# --skip-check 绕过了 preflight,这两条最基本的还是要拦,否则后面直接报错更难懂
command -v curl >/dev/null 2>&1 || die "缺少 curl(apt install curl / yum install curl)"
command -v tar  >/dev/null 2>&1 || die "缺少 tar(apt install tar)"
if [ "${NANOTUN_NO_INSTALL:-0}" != "1" ] && [ "$(id -u)" != "0" ]; then
  die "安装需要 root。请用 sudo 跑,或设 NANOTUN_NO_INSTALL=1 只下载。"
fi

# ── 2. 定版本 ────────────────────────────────────────────────────────────────
VERSION="${NANOTUN_VERSION:-}"
if [ -z "$VERSION" ]; then
  info "查询最新 Release ..."
  # 不解析 JSON(机器上不一定有 jq),跟着 /releases/latest 的 302 读 Location 里的 tag。
  # 比 grep API 返回体稳:API 有速率限制,未认证时一小时 60 次,CI 或反复重试很容易撞到。
  latest_url="$(curl "${CURL_SMALL[@]}" -I -o /dev/null -w '%{url_effective}' \
    "https://github.com/${REPO}/releases/latest" 2>/dev/null)" \
    || die "查询最新版本失败,检查网络或用 NANOTUN_VERSION 指定版本。"
  VERSION="${latest_url##*/}"
  case "$VERSION" in
    v[0-9]*) ;;
    # 走到这儿有两种可能,而它们的下一步动作完全不同,所以别只说「还没发过 Release」:
    # /releases/latest **不含预发布**,只发过 rc 时它会退回 /releases 这个列表页,
    # 于是这里拿到的是字面的 "releases"。仓库明明有能装的版本,却被告知「还没发过」——
    # 用户只会以为没得装,而不是去挑一个 rc。这正是 v0.1.0-rc1 发出去当天的实况。
    releases)
      # 顺手把最新那个报出来,别让人自己去翻网页。
      # releases.atom 是公开 RSS:含预发布、按时间倒序、不像 API 有 60 次/小时的限速,
      # 也不需要 jq。写死一个示例版本号是会烂的 —— 这里原本举的例子是 rc1,
      # 而 rc2 第二天就把它顶掉了,照着抄只会装到一个过时的版本。
      newest="$(curl "${CURL_SMALL[@]}" "https://github.com/${REPO}/releases.atom" 2>/dev/null \
        | sed -n 's#.*<link[^>]*releases/tag/\([^"]*\)".*#\1#p' | head -1)"
      case "$newest" in
        # URL 要写全。这条命令是给人**原样粘走**的 —— 原来这里是 `.../install.sh`,
        # 省略号粘过去就是一个不存在的地址,等于还得自己回去翻文档拼一遍。
        v[0-9]*) die "${REPO} 目前只有预发布版本(rc),而 /releases/latest 不含预发布。
   最新的是 ${newest},照抄这条:
     sudo NANOTUN_VERSION=${newest} bash -c \"\$(curl -fsSL ${RAW_BASE}/install.sh)\"" ;;
        *) die "${REPO} 目前只有预发布版本(rc),而 /releases/latest 不含预发布。
   到 https://github.com/${REPO}/releases 挑一个,再用 NANOTUN_VERSION=vX.Y.Z 指定。" ;;
      esac ;;
    *) die "没能从 $latest_url 解析出版本号。可能该仓库还没发过 Release;
   用 NANOTUN_VERSION=vX.Y.Z 显式指定。" ;;
  esac
fi
ok "版本: $VERSION"

TARBALL="nanotun-${VERSION}-linux-${ARCH}.tar.gz"
BASE="https://github.com/${REPO}/releases/download/${VERSION}"

# ── 3. 下载 + 校验 ───────────────────────────────────────────────────────────
TMP="$(mktemp -d)" || TMP=""
[ -n "$TMP" ] || die "创建临时目录失败 —— ${TMPDIR:-/tmp} 写不进去(权限 / 只读 / 配额 / 空间不足)。
   换个位置重试,例如:TMPDIR=/var/tmp <刚才那条命令>"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

info "下载 $TARBALL ..."
# curl 的退出码要分开看。原来无论怎么失败都归结成「确认该版本存在且有 linux-xxx 产物」,
# 于是磁盘写满时(curl 23,它自己已经打了 "Failure writing output to destination")
# 屏幕上让人去 GitHub Releases 查有没有这个产物 —— 方向完全错了,而真正要做的是腾地方
# 或换 TMPDIR。实测在一个只剩 1M 的 TMPDIR 上就是这个下场。
CURL_RC=0
curl "${CURL_BIG[@]}" -o "$TMP/$TARBALL" "$BASE/$TARBALL" || CURL_RC=$?
if [ "$CURL_RC" != 0 ]; then
  case "$CURL_RC" in
    23) die "下载失败:写不进 ${TMPDIR:-/tmp}(curl 23:写目标文件失败)。
   多半是空间不足或只读。腾出空间,或换个位置重试:TMPDIR=/var/tmp <刚才那条命令>
   当前可用:$(df -h "$TMP" 2>/dev/null | awk 'NR==2{print $4}')" ;;
    6|7)  die "下载失败:连不上 github.com(curl $CURL_RC:DNS 解析不了 / 连接被拒)。
   检查网络、DNS、出站防火墙或代理。" ;;
    28)   die "下载失败:连上了但数据不来(curl 28:30 秒内速度不到 1KB/s,已重试 3 次)。
   不是「你的网慢」—— 慢但在动的下载不会走到这里,这是彻底停住了。多半是到
   github.com 的链路被中断或被墙,换个时间 / 换条线路重试,或者自己把包下好再装:
     curl -fsSL ${RAW_BASE}/install.sh | NANOTUN_NO_INSTALL=1 bash" ;;
    22)   die "下载失败:服务器返回 404 之类的错(curl 22): $BASE/$TARBALL
   确认该版本存在且有 linux-$ARCH 产物:https://github.com/${REPO}/releases" ;;
    *)    die "下载失败(curl $CURL_RC): $BASE/$TARBALL
   确认该版本存在且有 linux-$ARCH 产物:https://github.com/${REPO}/releases" ;;
  esac
fi

info "校验 SHA256 ..."
if curl "${CURL_SMALL[@]}" -o "$TMP/SHA256SUMS" "$BASE/SHA256SUMS" 2>/dev/null; then
  if command -v sha256sum >/dev/null 2>&1; then
    SHA_CHECK=(sha256sum -c --ignore-missing -)
  elif command -v shasum >/dev/null 2>&1; then
    SHA_CHECK=(shasum -a 256 -c --ignore-missing -)
  else
    SHA_CHECK=()
  fi

  if [ "${#SHA_CHECK[@]}" -gt 0 ]; then
    # --ignore-missing:清单里同时有 amd64 和 arm64 两条,我们只下了一个。
    # 在 tar 所在目录执行,清单里是裸文件名。
    ( cd "$TMP" && "${SHA_CHECK[@]}" < SHA256SUMS >/dev/null ) \
      || die "SHA256 校验失败 —— 下载的包与官方清单不符,已中止。
   可能是传输损坏,也可能是被中间人替换过。别装,重下一次;还不行就去
   https://github.com/${REPO}/releases 手动核对。"
    ok "校验通过"
  else
    printf '    \033[1;33m!\033[0m 本机既无 sha256sum 也无 shasum,跳过校验\n'
  fi
else
  printf '    \033[1;33m!\033[0m 该版本没有 SHA256SUMS,跳过校验\n'
fi

# ── 4. 解压 ──────────────────────────────────────────────────────────────────
DEST="${INSTALL_DIR}/${VERSION}-${ARCH}"
info "解压到 $DEST ..."
mkdir -p "$DEST"
# --strip-components=1:tar 内是 nanotun-<ver>-linux-<arch>/ 一层目录,
# 剥掉它,免得路径变成 /opt/nanotun/v0.1.0-amd64/nanotun-v0.1.0-linux-amd64/。
tar -xzf "$TMP/$TARBALL" -C "$DEST" --strip-components=1
ok "已解压"

if [ "${NANOTUN_NO_INSTALL:-0}" = "1" ]; then
  echo
  info "NANOTUN_NO_INSTALL=1,到此为止。手动安装:"
  echo "    sudo $DEST/scripts/install-self-hosted.sh    # 装二进制 / systemd / 防火墙"
  echo "    sudo $DEST/scripts/setup.sh                  # 开服向导:拨号地址 / 用户 / 二维码"
  exit 0
fi

# /proc/<pid>/stat 取字段。comm 那一项裹在括号里、且允许含空格甚至右括号,所以从
# **最后**一个 ") " 之后才开始数。编号以 state 为第 1 项:2=ppid,5=tty_nr。
proc_stat_field() { # <pid> <字段号>
  local s
  s="$(cat "/proc/$1/stat" 2>/dev/null)" || return 1
  s="${s##*) }"
  printf '%s\n' "$s" | awk -v n="$2" '{print $n}'
}

# 认出「sudo 另开了 pty」这个组合 —— `curl … | sudo bash` 会在交棒给向导时挂死,
# 而原因不在 nanotun:
#
# Ubuntu / Debian 的 /etc/sudoers 默认带 `Defaults use_pty`,sudo 会另建一个 pty
# 会话把命令跑在里面,而不是直接用你正在敲字的那个终端。于是进程眼里的 /dev/tty 是
# sudo 造出来的内层 pty;再叠加 sudo 的 stdin 是 curl 那根管道(而且已读到底),
# 向导一去读它就被作业控制的停止信号挂起(ps 里是 T 状态、wchan=do_signal_stop),
# 父进程正等着它的输出 —— 死锁。用户看到的是提示符出来了、回车毫无反应。
#
# 实测(Ubuntu 26.04 全新 VPS):`curl … | sudo bash` 两次两挂;换成把脚本当参数传
# (`sudo bash -c "$(curl …)"`)则 71 秒装完 —— 那种形态下 bash 的 stdin 本身就是终端,
# 压根不用绕 /dev/tty。
#
# 所以认出来就不碰 /dev/tty:装照样装完,向导留给人手动跑,并把能一次到底的命令原样
# 打出来。宁可多敲一条,也不能挂在那儿让人以为装崩了。
#
# 判据是「祖先里存在一个 sudo,它的控制终端跟本进程不是同一个」—— 那就说明中间隔着
# 一层 sudo 新造的 pty,我们的 /dev/tty 不是用户正在敲字的那个终端。
#
# 必须把整条链走完,不能撞见第一个 sudo 就下结论:开了 pty 时链上会**同时有两个 sudo**,
# 内层那个(监督进程)跟命令一起待在新 pty 里、tty 与我们相同,只有外层那个还留在用户的
# 真终端上。只看最近的那个,永远得出「没开 pty」的结论 —— 第一版就是这么漏掉的。
#
# 没开 pty 的发行版上,链上唯一的 sudo 与我们同 tty,判定为假,照走原来的 /dev/tty 路径。
under_sudo_pty() {
  [ -r /proc/self/stat ] || return 1   # 没有 /proc 就不猜,交给原路径
  local mytty pid ttynr
  mytty="$(proc_stat_field $$ 5)"; [ -n "$mytty" ] || return 1
  pid="$(proc_stat_field $$ 2)"
  while [ -n "$pid" ] && [ "$pid" -gt 1 ] 2>/dev/null; do
    if [ "$(cat "/proc/$pid/comm" 2>/dev/null)" = sudo ]; then
      ttynr="$(proc_stat_field "$pid" 5)"
      if [ -n "$ttynr" ] && [ "$ttynr" != "$mytty" ]; then return 0; fi
    fi
    pid="$(proc_stat_field "$pid" 2)"
  done
  return 1
}

# 向导要问话,所以先弄清楚这次到底有没有人能回答。置 SETUP_STDIN(空 = 没人能答)
# 与 SKIP_WHY(跳过的原因,给收尾提示用)。
#
# 被 `curl … | bash` 跑时 stdin 是 curl 那根管道(而且已经读到底了),`-t 0` 永远为假 ——
# 哪怕人就坐在终端前面。但管道占的只是 stdin,控制终端还在,/dev/tty 就是它,把向导的
# stdin 重新指过去就能照常问话(rustup 之流的老做法)。
#
# 判据是「能不能真的打开 /dev/tty」,不是「文件在不在」:CI、cron、systemd 里
# /dev/tty 这个节点通常也在,但进程没有控制终端,一 open 就 ENXIO。所以这里真去开一次。
SETUP_STDIN=""; SKIP_WHY=""
setup_stdin_probe() {
  if [ -t 0 ]; then
    SETUP_STDIN=/dev/stdin
  elif { : </dev/tty; } 2>/dev/null; then
    if under_sudo_pty; then SKIP_WHY=sudo_pty; else SETUP_STDIN=/dev/tty; fi
  fi
}

# ── 5. 安装 ──────────────────────────────────────────────────────────────────
#
# 「等下会不会自动进向导」这件事必须**在安装之前**就定下来,虽然向导要装完才跑。
# 因为 install-self-hosted.sh 的收尾语要照它分岔:向导紧接着就来的话,它只说一句
# 「马上开始」;没人接的话才该郑重催「还差最后一步:sudo nanotun-setup」。之前不分
# 情形一律催,于是催完向导自己启动了 —— 照着做的人会在向导跑完后又原样敲一遍。
#
# 判据只跟终端和参数有关,跟装没装成无关,所以提前算没有副作用。
setup_stdin_probe
WIZARD_FOLLOWS=0
if [ "$NO_SETUP" = 0 ] && { [ -n "$SETUP_STDIN" ] || [ ${#SETUP_ARGS[@]} -gt 0 ]; }; then
  WIZARD_FOLLOWS=1
fi

info "执行安装脚本 ..."
echo
# 安装脚本按自身位置推导发布包根目录,不必再传 DEPLOY_DIR。
# 环境已经在第 1 步验过了,不必再验一遍。
NANOTUN_PREFLIGHT_DONE=1 NANOTUN_WIZARD_FOLLOWS="$WIZARD_FOLLOWS" \
  "$DEST/scripts/install-self-hosted.sh"

# ── 6. 开服向导 ──────────────────────────────────────────────────────────────
#
# 装完不等于能用:还差拨号地址、Web 管理员、用户的二维码。以前这里就结束了,
# 把这三件事留给用户自己从输出里读出来 —— 既然是「一条命令开服」,就一路走到底。
if [ "$NO_SETUP" = 1 ]; then
  echo
  info "--no-setup:跳过开服向导。想连上客户端还差最后一步:"
  echo "    sudo nanotun-setup"
  exit 0
fi

if [ ! -x /usr/local/bin/nanotun-setup ]; then
  echo
  info "这个版本的发布包里没有开服向导,手动完成剩下的配置:"
  echo "    见 https://github.com/${REPO}#快速启动"
  exit 0
fi

# 给了参数就未必需要人回答了 —— 带 --yes 的那套本来就是无人值守用的,
# 这种情况下没有终端也照跑,不然 CI / cloud-init 里永远进不了向导。
if [ -z "$SETUP_STDIN" ] && [ ${#SETUP_ARGS[@]} -eq 0 ]; then
  echo
  if [ "$SKIP_WHY" = sudo_pty ]; then
    info "安装完成。开服向导这次不自动进 —— sudo 另开了一个 pty(Ubuntu/Debian 的"
    echo "  Defaults use_pty),向导在里面问话会被挂死,所以主动跳过。接着跑:"
    echo
    echo "    sudo nanotun-setup"
    echo
    echo "  下次换成这条就能一次装完,不用再补这一步:"
    echo "    sudo bash -c \"\$(curl -fsSL ${RAW_BASE}/install.sh)\""
  else
    info "安装完成。这次既没有终端可问话、也没给向导参数,开服向导跳过。手动跑:"
    echo "    sudo nanotun-setup"
  fi
    echo
    echo "  无人值守(CI / cloud-init)可以一条命令做完:"
    echo "    curl -fsSL ${RAW_BASE}/install.sh | sudo bash -s -- --dial-host <域名或IP> --user <用户名> --yes"
    echo
    echo "  想连 Web 后台账号一起定下来(否则 /setup 谁先打开谁是管理员):"
    echo "    curl -fsSL ${RAW_BASE}/install.sh | sudo NANOTUN_WEB_ADMIN_PASSWORD='<密码>' bash -s -- \\"
    echo "      --dial-host <域名或IP> --user <用户名> --web-admin <后台用户名> --yes"
  exit 0
fi

echo
info "进入开服向导 ..."
echo
# exec 会拿新进程映像顶掉自己,EXIT trap **不会**执行 —— $TMP 里那个十几 MB 的
# tar 就此长住 /tmp。交棒前自己收干净,并撤掉 trap 免得留个悬空的处理器。
cleanup
trap - EXIT
if [ "$SETUP_STDIN" = /dev/tty ]; then
  exec /usr/local/bin/nanotun-setup ${SETUP_ARGS[@]+"${SETUP_ARGS[@]}"} </dev/tty
else
  exec /usr/local/bin/nanotun-setup ${SETUP_ARGS[@]+"${SETUP_ARGS[@]}"}
fi
