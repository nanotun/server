#!/usr/bin/env bash
# 把本地 HEAD 构建出来的服务端二进制热替到 SRV,并把 e2e 的版本钉子改成同一个值。
#
# ── 为什么需要这个脚本 ──────────────────────────────────────────────────────
# 阶段 0 有一条断言:SRV 上跑的版本必须等于 E2E_EXPECT_VERSION。它存在的理由很实在
# —— 没有它,e2e 会安安静静地在**上一个版本**的服务端上跑一遍全绿,然后那个绿被盖成
# 发版戳,戳里只有一个 SHA,事后谁也看不出来验的其实是旧代码。
#
# 但「装 HEAD 到 SRV」和「改 E2E_EXPECT_VERSION」这两步以前既没进发版清单也没有脚本,
# 只能靠记性。2026-08-05 就漏了一次:e2e 跑到一半才在阶段 0 报版本不符,前面十几分钟
# 全白跑。这个脚本把两步合成一步,顺带做了「装完真的变了吗」的回读校验。
#
# ── 换什么、不换什么 ────────────────────────────────────────────────────────
# 只覆盖 /usr/local/bin 下的二进制与脚本,然后 restart。**不碰** config.toml、certs/、
# 数据库 —— 那三样一动,机器的身份(REALITY 私钥、PSK、已发出去的 profile)就变了,
# 客户端全部要重新配,实验室得重建。
#
# 用法:
#   ./deploy-srv.sh          # 构建 HEAD → 热替 → 回读校验 → 更新 e2e.env
#
# 之后照常:
#   ./run-remote.sh 00 10 20 30 40 50 60 70
#
# 退出码:0 成功 / 2 环境或配置问题。

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
ENVF="$HERE/e2e.env"

_R=$'\033[31m'; _G=$'\033[32m'; _Y=$'\033[33m'; _B=$'\033[1m'; _N=$'\033[0m'
[[ -t 1 ]] || { _R=""; _G=""; _Y=""; _B=""; _N=""; }

die()  { printf '%s致命:%s %s\n' "$_R" "$_N" "$*" >&2; exit 2; }
step() { printf '\n%s==> %s%s\n' "$_B" "$*" "$_N"; }
ok()   { printf '    %s✓%s %s\n' "$_G" "$_N" "$*"; }
warn() { printf '    %s!%s %s\n' "$_Y" "$_N" "$*"; }

[[ -f "$ENVF" ]] || die "找不到 $ENVF(照 e2e.env.example 建一份)"
set -a
# shellcheck source=/dev/null
. "$ENVF"
set +a

SRV_HOST="${E2E_SRV_HOST:-}"
SRV_PASS="${E2E_SRV_PASS:-}"
SRV_USER="${E2E_SSH_USER:-root}"
[[ -n "$SRV_HOST" ]] || die "e2e.env 里没有 E2E_SRV_HOST"

SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o LogLevel=ERROR -o ConnectTimeout=20 -o ServerAliveInterval=30)

rsh() {
  if [[ -n "$SRV_PASS" ]]; then
    sshpass -p "$SRV_PASS" ssh "${SSH_OPTS[@]}" "$SRV_USER@$SRV_HOST" "$@"
  else
    ssh "${SSH_OPTS[@]}" "$SRV_USER@$SRV_HOST" "$@"
  fi
}
rcp() {
  if [[ -n "$SRV_PASS" ]]; then
    sshpass -p "$SRV_PASS" scp "${SSH_OPTS[@]}" "$1" "$SRV_USER@$SRV_HOST:$2"
  else
    scp "${SSH_OPTS[@]}" "$1" "$SRV_USER@$SRV_HOST:$2"
  fi
}

# ── 1. 本地是哪个 commit ────────────────────────────────────────────────────
step "1. 核对 commit"
cd "$ROOT" || die "进不去仓库根目录 $ROOT"
# 与 run-remote.sh 同一口径:脏树意味着装上去的东西没有一个可复现的名字,
# 而版本号是从 commit 派生的 —— dev-<sha> 会指向一份并不等于它的二进制。
if [[ -n "$(git status --porcelain)" ]]; then
  printf '%s' "$_R" >&2
  {
    echo "工作树不干净。版本号是从 commit 派生的,装上去的二进制却含着未提交的改动 ——"
    echo "dev-<sha> 这个名字会对不上它实际的内容。先提交或 stash:"
  } >&2
  printf '%s' "$_N" >&2
  git status --porcelain | head -10 >&2
  exit 2
fi
SHORT="$(git rev-parse --short HEAD)"
VER="dev-${SHORT}"
ok "本地 HEAD ${SHORT} $(git log -1 --pretty=%s | cut -c1-40)"

# ── 2. SRV 是什么架构 ───────────────────────────────────────────────────────
step "2. SRV $SRV_HOST"
RAW_ARCH="$(rsh 'uname -m' 2>/dev/null | tr -d '\r')" \
  || die "连不上 SRV($SRV_USER@$SRV_HOST)"
case "$RAW_ARCH" in
  x86_64|amd64)  ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "不认识的架构 ${RAW_ARCH} —— 发布包只出 amd64 / arm64" ;;
esac
OLD_VER="$(rsh 'nanotund --version 2>/dev/null | head -1' | tr -d '\r')"
ok "架构 ${RAW_ARCH} → ${ARCH};当前 ${OLD_VER:-未知}"

# ── 3. 构建 ─────────────────────────────────────────────────────────────────
step "3. 构建 ${VER} (${ARCH})"
PKG="$ROOT/dist/nanotun-${VER}-linux-${ARCH}.tar.gz"
# NANOTUN_RELEASE_I_KNOW=1:build-release.sh 默认拒绝手工调用,那道锁是防止绕过
# cut.sh 发版的。这里构建的是**测试机用的**包,不对外发,所以显式解锁。
( cd "$ROOT" && NANOTUN_RELEASE_I_KNOW=1 NANOTUN_ARCHES="$ARCH" NANOTUN_VERSION="$VER" \
    ./scripts/build-release.sh >/dev/null 2>&1 ) || die "构建失败,单独跑一遍 build-release.sh 看报错"
[[ -f "$PKG" ]] || die "构建完了却没找到包:$PKG"
ok "$(basename "$PKG") ($(du -h "$PKG" | cut -f1))"

# ── 4. 热替 ─────────────────────────────────────────────────────────────────
step "4. 送上去并重启"
rcp "$PKG" /var/tmp/nanotun-head.tar.gz >/dev/null || die "scp 到 SRV 失败"
rsh 'set -e
  rm -rf /var/tmp/nanotun-head && mkdir -p /var/tmp/nanotun-head
  tar -xzf /var/tmp/nanotun-head.tar.gz -C /var/tmp/nanotun-head
  D=$(echo /var/tmp/nanotun-head/*/)
  install -m 0755 "$D/nanotund" "$D/nanotun-web" "$D/nanotun-admin" /usr/local/bin/
  install -m 0755 "$D/scripts/setup.sh"                /usr/local/bin/nanotun-setup
  install -m 0755 "$D/scripts/preflight.sh"            /usr/local/bin/nanotun-preflight
  install -m 0755 "$D/scripts/ensure-server-assets.sh" /usr/local/bin/nanotun-ensure-assets.sh
  # 开机前跑的那两个也要一起换,否则它们的改动永远不经门禁。
  #
  # 这份清单是手工维护的,漏一个不会有任何提示 —— 跑出来照样全绿,只是绿的是旧脚本。
  # tun-setup.sh 就这么漏了很久:它建的 14 张空网卡能把整台机器的网弄断(见该文件注释),
  # 而 e2e 从来没碰过它。
  install -m 0755 "$D/scripts/tun-setup.sh"    /usr/local/bin/nanotun-tun-setup.sh
  install -m 0755 "$D/scripts/tun-teardown.sh" /usr/local/bin/nanotun-tun-teardown.sh
  # 先重跑 tun-setup:它是 oneshot + RemainAfterExit,不 restart 就还是上次开机那一次的
  # 结果,新脚本等于没生效。nanotun.service Requires 它,所以顺序不能反。
  systemctl restart nanotun-tun-setup
  systemctl restart nanotun nanotun-web
  rm -rf /var/tmp/nanotun-head.tar.gz /var/tmp/nanotun-head' \
  || die "SRV 上安装或重启失败 —— 去看 journalctl -u nanotun -n 50"
sleep 3
ok "二进制与脚本已替换,nanotun / nanotun-web 已重启"

# ── 5. 回读校验 ─────────────────────────────────────────────────────────────
# 装完不回读,就等于把「装成功了」建立在 install 没报错上。而阶段 0 那条断言恰恰
# 是在替这一步收尾 —— 与其让它在 e2e 跑到一半时报,不如现在就报。
step "5. 回读"
NEW_VER="$(rsh 'nanotund --version 2>/dev/null | head -1' | tr -d '\r')"
ACTIVE="$(rsh 'systemctl is-active nanotun nanotun-web 2>/dev/null | tr "\n" " "' | tr -d '\r')"
[[ "$NEW_VER" == *"$VER"* ]] \
  || die "版本没变成 ${VER},读回来的是 [${NEW_VER}] —— 别开跑,先查 SRV"
case "$ACTIVE" in
  *inactive*|*failed*|"") die "服务没起来:${ACTIVE:-读不到} —— journalctl -u nanotun -n 50" ;;
esac
ok "$NEW_VER"
ok "服务 $ACTIVE"

# ── 6. 把版本钉子改成同一个值 ───────────────────────────────────────────────
step "6. 更新 e2e.env 的版本钉子"
CUR_PIN="$(sed -n 's/^E2E_EXPECT_VERSION=//p' "$ENVF" | head -1)"
if [[ "$CUR_PIN" == "$VER" ]]; then
  ok "E2E_EXPECT_VERSION 已经是 ${VER}"
else
  cp "$ENVF" "${ENVF}.bak.$(date +%Y%m%d-%H%M%S)" || die "备份 e2e.env 失败"
  if grep -q '^E2E_EXPECT_VERSION=' "$ENVF"; then
    # 不用 sed -i:GNU 与 BSD 的 -i 语义不一样(BSD 要一个备份后缀参数),
    # 而这个脚本要在开发者的 Mac 上跑。
    tmp="$(mktemp)" || die "创建临时文件失败"
    sed "s|^E2E_EXPECT_VERSION=.*|E2E_EXPECT_VERSION=${VER}|" "$ENVF" >"$tmp" \
      && cat "$tmp" >"$ENVF" && rm -f "$tmp"
  else
    printf 'E2E_EXPECT_VERSION=%s\n' "$VER" >>"$ENVF"
  fi
  ok "E2E_EXPECT_VERSION: ${CUR_PIN:-<空>} → ${VER}"
fi

printf '\n%s接着跑:%s ./scripts/e2e/run-remote.sh 00 10 20 30 40 50 60 70\n' "$_B" "$_N"
