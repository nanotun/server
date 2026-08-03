#!/usr/bin/env bash
# nanotun 一条命令开服 —— 检查环境 → 下载发布包 → 安装 → 开服向导。
#
#   curl -fsSL https://raw.githubusercontent.com/nanotun/server/main/scripts/install.sh | sudo bash
#
# 只想先看看这台机器行不行(不下载、不安装、不改任何东西):
#   curl -fsSL .../install.sh | bash -s -- --check-only
#   环境检查也可以单独跑:curl -fsSL .../preflight.sh | bash
#
# 装指定版本(生产建议钉版本,别跟着 latest 漂):
#   curl -fsSL .../install.sh | sudo NANOTUN_VERSION=v0.1.0 bash
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
#
# 环境变量:
#   NANOTUN_VERSION     要装的版本,默认取最新 Release
#   NANOTUN_INSTALL_DIR 解压落点,默认 /opt/nanotun
#   NANOTUN_NO_INSTALL  =1 时只下载解压,不执行 install-self-hosted.sh
#   NANOTUN_REPO        换仓库(fork 自用)
#   NANOTUN_BRANCH      从哪个分支取 preflight.sh,默认 main
#
# 安装要 root(写 /usr/local/bin、/etc/systemd/system、sysctl)。
# --check-only 和 NANOTUN_NO_INSTALL=1 不需要 root。
set -euo pipefail

REPO="${NANOTUN_REPO:-nanotun/server}"
BRANCH="${NANOTUN_BRANCH:-main}"
INSTALL_DIR="${NANOTUN_INSTALL_DIR:-/opt/nanotun}"
RAW_BASE="https://raw.githubusercontent.com/${REPO}/${BRANCH}/scripts"

CHECK_ONLY=0; SKIP_CHECK=0; NO_SETUP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --check-only) CHECK_ONLY=1; shift ;;
    --skip-check) SKIP_CHECK=1; shift ;;
    --no-setup)   NO_SETUP=1; shift ;;
    # 打开头那段注释。不写死行号 —— 改文档时忘了同步行号,--help 就会截半句话。
    # 被 curl | bash 时 $0 不是文件,读不到就退回一个链接。
    -h|--help)
      awk 'NR>1 && /^#/ {sub(/^#[[:space:]]?/,""); print; next} NR>1 {exit}' "$0" 2>/dev/null \
        || echo "见 https://github.com/${REPO}"
      exit 0 ;;
    *) printf 'install.sh: 未知参数 %s(--help 看用法)\n' "$1" >&2; exit 2 ;;
  esac
done

info() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
ok()   { printf '    \033[1;32m✓\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mFATAL: %s\033[0m\n' "$*" >&2; exit 1; }

# ── 1. 环境自检 ──────────────────────────────────────────────────────────────
#
# 判据全在 preflight.sh 里,这里只负责把它弄到手再跑。不在本文件里重写一份 ——
# 同一套「这台机器行不行」的规则散在三个脚本里,迟早对不上。
#
# 被 curl | bash 时本地没有 scripts/ 目录,得先把 preflight.sh 也下下来;
# 从解压好的发布包里跑时它就在隔壁,直接用本地那份(还能离线)。
run_preflight() {
  local self local_pf pf args=()

  [ "$CHECK_ONLY" = 1 ] && args+=(--dry-run)   # 只是看看,连 sysctl 都别写

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
  pf="$(mktemp)"
  curl -fsSL --retry 3 -o "$pf" "$RAW_BASE/preflight.sh" \
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
  latest_url="$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
    "https://github.com/${REPO}/releases/latest" 2>/dev/null)" \
    || die "查询最新版本失败,检查网络或用 NANOTUN_VERSION 指定版本。"
  VERSION="${latest_url##*/}"
  case "$VERSION" in
    v[0-9]*) ;;
    *) die "没能从 $latest_url 解析出版本号。可能该仓库还没发过 Release;
   用 NANOTUN_VERSION=vX.Y.Z 显式指定。" ;;
  esac
fi
ok "版本: $VERSION"

TARBALL="nanotun-${VERSION}-linux-${ARCH}.tar.gz"
BASE="https://github.com/${REPO}/releases/download/${VERSION}"

# ── 3. 下载 + 校验 ───────────────────────────────────────────────────────────
TMP="$(mktemp -d)"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

info "下载 $TARBALL ..."
curl -fsSL --retry 3 -o "$TMP/$TARBALL" "$BASE/$TARBALL" \
  || die "下载失败: $BASE/$TARBALL
   确认该版本存在且有 linux-$ARCH 产物:https://github.com/${REPO}/releases"

info "校验 SHA256 ..."
if curl -fsSL --retry 3 -o "$TMP/SHA256SUMS" "$BASE/SHA256SUMS" 2>/dev/null; then
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

# ── 5. 安装 ──────────────────────────────────────────────────────────────────
info "执行安装脚本 ..."
echo
# 安装脚本按自身位置推导发布包根目录,不必再传 DEPLOY_DIR。
# 环境已经在第 1 步验过了,不必再验一遍。
NANOTUN_PREFLIGHT_DONE=1 "$DEST/scripts/install-self-hosted.sh"

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

# 非交互环境(CI、curl | bash 且 stdin 不是终端)下向导问不了话,别让它报错收场。
if [ ! -t 0 ]; then
  echo
  info "安装完成。stdin 不是终端,开服向导需要交互,请手动跑:"
  echo "    sudo nanotun-setup"
  echo
  echo "  想全自动的话给它参数:"
  echo "    sudo nanotun-setup --dial-host <你的域名或IP> --user <用户名> --yes"
  exit 0
fi

echo
info "进入开服向导 ..."
echo
exec /usr/local/bin/nanotun-setup
