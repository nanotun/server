#!/usr/bin/env bash
# 把**对外发布**的 Linux CLI 装到 A/C,并把 e2e 的客户端版本钉子改成同一个值。
#
#   ./deploy-cli.sh            # 装 dl.nanotun.com 上当前发布的版本(问 /api/v1/client/latest)
#   ./deploy-cli.sh 1.0.5      # 钉指定版本
#   ./deploy-cli.sh --check    # 只报告:线上是哪版、A/C 现在是哪版、钉子是多少,不改任何东西
#
# ── 为什么是「对外发布的版本」而不是从客户端工程现编 ────────────────────────
# 此前 A/C 上的 /usr/local/bin/nanotun 是手工从 blackhorse-windows 某个 commit 现编的
# musl 静态二进制。两个问题:
#   · 它验的是一个从未发布的中间构建,而门禁的意义是「这版服务端 + 外面在用的客户端」;
#   · 那时 `nanotun --version` 恒为 0.1.0,看不出构建,于是 e2e 可以在几周前的旧客户端上
#     安静跑绿(2026-08-10 实测撞过:v0.1.20 全绿,A/C 却不含 08-09 的 MagicDNS 修复)。
# 下载页上给用户的 `nanotun-<版本>-<arch>-musl-static` 是同一条 `cargo zigbuild … musl`
# 命令的产物(见客户端工程 linux/package-cli.sh),只是带了真实版本号 —— 换成它之后,
# 阶段 00 能像钉服务端那样钉客户端(E2E_EXPECT_CLIENT_VERSION),这个洞才算补上。
#
# ── 做什么、不做什么 ────────────────────────────────────────────────────────
# 在 A/C 上各自从 dl.nanotun.com 下载(它们能出网,比经本机中转快),按发布记录里的
# sha256 核对,再原子替换 /usr/local/bin/nanotun(旧文件留成 nanotun.bak-<时刻>)。
# **不碰**客户端状态(/etc/nanotun、具名连接、凭据),所以已建好的实验室不用重跑 provision。
# 装完会重起正在跑的两个会话(nanotun-a / nanotun-c):Linux 上替换二进制不影响已运行的
# 进程,不重起的话它们跑的仍是旧代码,而钉子已经改成新值 —— 恰恰是本脚本要消灭的错位。
#
# 退出码:0 成功 / 2 环境或配置问题。
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/env.sh
source "$HERE/lib/env.sh"

_R=$'\033[31m'; _G=$'\033[32m'; _Y=$'\033[33m'; _B=$'\033[1m'; _N=$'\033[0m'
[[ -t 1 ]] || { _R=""; _G=""; _Y=""; _B=""; _N=""; }
die()  { printf '%s致命:%s %s\n' "$_R" "$_N" "$*" >&2; exit 2; }
step() { printf '\n%s==> %s%s\n' "$_B" "$*" "$_N"; }
ok()   { printf '    %s✓%s %s\n' "$_G" "$_N" "$*"; }
warn() { printf '    %s!%s %s\n' "$_Y" "$_N" "$*"; }

# 发布记录与安装包都挂在这两个地址下。下载页(blackhorse-server web/site/assets/download.js)
# 也是按同样的规则拼链接,这里改了那边也得改。
API_LATEST="${NT_CLIENT_API:-https://www.nanotun.com/api/v1/client/latest?platform=linux-cli}"
DL_BASE="${NT_DL_BASE:-https://dl.nanotun.com}"

CHECK_ONLY=0; WANT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --check) CHECK_ONLY=1; shift ;;
    -h|--help) sed -n '2,7p' "$0"; exit 0 ;;
    -*) die "未知参数: $1" ;;
    *) WANT="$1"; shift ;;
  esac
done

e2e_load_env || exit 2
e2e_ssh_init
trap 'e2e_ssh_cleanup' EXIT INT TERM
ENVF="${E2E_ENV:-$HERE/e2e.env}"

# ── 1. 线上发布的是哪一版 ───────────────────────────────────────────────────
step "1. 发布记录 ($API_LATEST)"
command -v python3 >/dev/null || die "本机没有 python3(解析发布记录要用)"
RAW="$(curl -fsSL --max-time 30 "$API_LATEST" 2>/dev/null)" || die "取不到发布记录:$API_LATEST"
# 接口把全部平台一起返回,自己按 platform 挑;资产名 → sha256 逐条列出来给下面核对用。
REL="$(printf '%s' "$RAW" | python3 -c '
import json, sys
d = json.load(sys.stdin)
rel = [r for r in d.get("data", {}).get("releases", []) if r.get("platform") == "linux-cli"]
if not rel:
    sys.exit(1)
r = rel[0]
print(r["version"])
for a in r.get("assets", []):
    print(a["name"], a["sha256"])
')" || die "发布记录里没有 linux-cli 这个平台"
LATEST="$(printf '%s\n' "$REL" | head -1)"
VER="${WANT:-$LATEST}"
if [[ "$VER" != "$LATEST" ]]; then
  # 钉旧版时发布记录里只有当前版的 sha256,只能按下载到的文件算 —— 说清楚,别装成校验过。
  warn "指定的 $VER 不是当前发布的 $LATEST:没有官方 sha256 可核对,只能记下载到的值"
fi
ok "线上当前 linux-cli:$LATEST;本次安装:$VER"

sha_for() { # sha_for <资产名> → 发布记录里的 sha256,没有则空
  printf '%s\n' "$REL" | awk -v n="$1" 'NR>1 && $1==n {print $2; exit}'
}

# ── 2. A/C 现状 ─────────────────────────────────────────────────────────────
step "2. 客户端现状"
# 只碰 A/C,不预热 SRV:本脚本不读服务端的任何值(端口 / 后缀),也就不该假装需要它。
declare -A CUR ARCH
for who in a c; do
  "$who" true >/dev/null 2>&1 || die "连不上 $who(${who^^})"
  CUR[$who]="$("$who" '/usr/local/bin/nanotun --version 2>/dev/null' | awk 'NR==1{print $NF}' | tr -d '[:space:]\r')"
  case "$("$who" 'uname -m' | tr -d '[:space:]\r')" in
    x86_64)  ARCH[$who]=x86_64 ;;
    aarch64) ARCH[$who]=aarch64 ;;
    *)       die "$who 的架构不认识:$("$who" 'uname -m')" ;;
  esac
  host="$E2E_A_HOST"; [[ "$who" == c ]] && host="$E2E_C_HOST"
  ok "${who^^} $host: 现有 ${CUR[$who]:-无} (${ARCH[$who]})"
done
PIN="$(sed -n 's/^E2E_EXPECT_CLIENT_VERSION=//p' "$ENVF" 2>/dev/null | head -1)"
ok "e2e.env 钉子 E2E_EXPECT_CLIENT_VERSION=${PIN:-<空>}"
if [[ "$CHECK_ONLY" = 1 ]]; then
  echo; echo "   --check:到此为止,没有改任何东西。"; exit 0
fi

# ── 3. 逐台安装 ─────────────────────────────────────────────────────────────
step "3. 安装 $VER 到 A/C"
for who in a c; do
  asset="nanotun-${VER}-${ARCH[$who]}-musl-static"
  url="$DL_BASE/linux-cli/$asset"
  want_sha="$(sha_for "$asset")"
  if [[ "${CUR[$who]}" == "$VER" ]]; then
    # 版本号一样也要核对内容:同一个版本号被重新上传过的话,光看 --version 分不出来。
    got_sha="$("$who" 'sha256sum /usr/local/bin/nanotun 2>/dev/null' | awk '{print $1}')"
    if [[ -n "$want_sha" && "$got_sha" == "$want_sha" ]]; then
      ok "${who^^} 已是 $VER 且 sha256 与发布记录一致,跳过"
      continue
    fi
    warn "${who^^} 版本号已是 $VER 但 sha256 不符(现有 ${got_sha:0:12}…,发布 ${want_sha:0:12}…),重装"
  fi
  # 下载、核对、替换都在目标机上一条命令做完;任何一步失败都不会动到现有的二进制。
  out="$("$who" "set -e
    tmp=\$(mktemp /tmp/nanotun-cli.XXXXXX)
    trap 'rm -f \"\$tmp\"' EXIT
    curl -fsSL --retry 3 --max-time 300 -o \"\$tmp\" '$url'
    got=\$(sha256sum \"\$tmp\" | awk '{print \$1}')
    if [ -n '$want_sha' ] && [ \"\$got\" != '$want_sha' ]; then
      echo \"sha256 不符: 下载到 \$got, 发布记录 $want_sha\"; exit 3
    fi
    chmod 0755 \"\$tmp\"
    v=\$(\"\$tmp\" --version 2>/dev/null | awk 'NR==1{print \$NF}')
    if [ \"\$v\" != '$VER' ]; then echo \"下载到的二进制自报版本 [\$v],不是 $VER\"; exit 4; fi
    if [ -x /usr/local/bin/nanotun ]; then
      cp -a /usr/local/bin/nanotun /usr/local/bin/nanotun.bak-\$(date +%Y%m%d%H%M%S)
      ls -t /usr/local/bin/nanotun.bak-* 2>/dev/null | tail -n +3 | xargs -r rm -f
    fi
    install -m 0755 \"\$tmp\" /usr/local/bin/nanotun
    echo \"installed sha256=\$got\"" 2>&1)" || die "${who^^} 安装失败:
$out"
  ok "${who^^} 已装 $VER($(printf '%s' "$out" | tail -1))"
done

# ── 4. 回读 + 重起会话 ──────────────────────────────────────────────────────
step "4. 回读校验并重起会话"
for who in a c; do
  got="$("$who" '/usr/local/bin/nanotun --version 2>/dev/null' | awk 'NR==1{print $NF}' | tr -d '[:space:]\r')"
  [[ "$got" == "$VER" ]] || die "${who^^} 回读到的版本是 [${got:-空}],不是 $VER —— 别开跑,先查"
  ok "${who^^} nanotun --version → $got"
done
# shellcheck source=lib/fixtures.sh
source "$HERE/lib/fixtures.sh"
restarted=0
if client_active a "$E2E_A_UNIT"; then client_a_start; restarted=$((restarted+1)); fi
if client_active c "$E2E_C_UNIT"; then client_c_start; restarted=$((restarted+1)); fi
if (( restarted > 0 )); then
  for i in $(seq 1 30); do both_clients_online 2>/dev/null && break; sleep 2; done
  if both_clients_online 2>/dev/null; then
    ok "已重起 $restarted 个会话,两端在线"
  else
    warn "重起后只有 $(conn_count) 个会话在线 —— 开跑前先看 client_log"
  fi
else
  ok "没有在跑的会话(实验室未 provision 或已停),不用重起"
fi

# ── 5. 钉子 ─────────────────────────────────────────────────────────────────
step "5. 更新 e2e.env 的客户端版本钉子"
if [[ "$PIN" == "$VER" ]]; then
  ok "E2E_EXPECT_CLIENT_VERSION 已经是 $VER"
else
  [[ -f "$ENVF" ]] || die "找不到 $ENVF"
  cp "$ENVF" "${ENVF}.bak.$(date +%Y%m%d-%H%M%S)" || die "备份 e2e.env 失败"
  if grep -q '^E2E_EXPECT_CLIENT_VERSION=' "$ENVF"; then
    # 不用 sed -i:GNU 与 BSD 的语义不同,而这个脚本要在开发者的 Mac 上跑。
    tmp="$(mktemp)" || die "创建临时文件失败"
    sed "s|^E2E_EXPECT_CLIENT_VERSION=.*|E2E_EXPECT_CLIENT_VERSION=${VER}|" "$ENVF" >"$tmp" \
      && cat "$tmp" >"$ENVF" && rm -f "$tmp"
  else
    printf 'E2E_EXPECT_CLIENT_VERSION=%s\n' "$VER" >>"$ENVF"
  fi
  ok "E2E_EXPECT_CLIENT_VERSION: ${PIN:-<空>} → $VER"
fi

printf '\n%s接着:%s 首次建实验室先 ./scripts/e2e/provision.sh;之后 ./scripts/e2e/run.sh 00 验基线。\n' "$_B" "$_N"
