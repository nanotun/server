#!/usr/bin/env bash
# 非默认 MagicDNS 后缀 · 端到端 drill(按需跑,不进发版门禁)
#
#   ./magic-suffix-drill.sh
#
# 退出码沿用套件约定:0 全通过,1 有断言失败,2 环境/脚手架问题(红绿不可信)。
#
# ── 为什么单独一支 ──────────────────────────────────────────────────────────
# 常规三机门禁(phases/10-exit.sh)只在**默认后缀 lan** 下验 MagicDNS。而「后缀可配」
# 这条链是:config.toml 的 [server.magic_dns].domain_suffix → nanotund 启动读进
# magicDNSResolved 快照 → 网关 :53 只对 `*.<该后缀>` 作答、别的后缀 NXDOMAIN → 客户端
# 解析 `<设备>.<用户>.<后缀>` 得到 mesh vIP。任何一环把后缀写死成 lan(或读错来源),
# 单测与默认后缀的门禁都照样全绿,而真给客户定制了后缀就整条解析失灵。这支把**非默认**
# 后缀在真机上走一遍,判据落在网关 DNS 的实际应答上。
#
# ── 判据为什么打网关 DNS(dig @网关)而不是客户端系统解析器 ────────────────────
# 网关 :53 的应答只由**服务端 config.toml 的后缀**决定,是这条特性最贴近根因的观测点:
# 改了 config、重启、A 能 `dig @10.201.0.1 vultr.u4.<新后缀>` 拿到 C 的 vIP,就证明
# 「config→服务端解析器」这半条链通了(客户端把该后缀锁进 split-DNS 是另一半,门禁已覆盖)。
# 同时断言**旧后缀**转为 NXDOMAIN —— 证明切换是排他的,不是新旧后缀都答的假通过。
#
# ── 对共享实验室的影响 ──────────────────────────────────────────────────────
# 改后缀要重启 nanotund(domain_suffix 不在 SIGHUP 热更白名单里),本 drill 会重启两次
# (改成测试后缀 / 还原回原后缀),其间 A、C 会 graceful 重连。收尾**必定**把后缀还原成
# 跑之前那个值(trap 兜底,幂等)。与 frag-acl-drill 改 ACL 再删同一种「用完即还原」口径。
#
# ── 仅 systemd 部署形态 ──────────────────────────────────────────────────────
# config.toml 改写 + 重启走宿主。docker 形态下配置在容器内、写文件要绕 `docker exec`
# (无 -i 时 stdin 进不去),不在本 drill 覆盖内 —— 那形态的后缀语义由单测 + 裸机装机测覆盖。
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/env.sh
source "$HERE/lib/env.sh"
# shellcheck source=lib/assert.sh
source "$HERE/lib/assert.sh"

e2e_load_env || exit 2
e2e_ssh_init

GW4="${E2E_MAGIC_GW4:-10.201.0.1}"               # 服务端 TUN 网关,MagicDNS 监听 :53
CFG="${E2E_SRV_CONFIG:-/etc/nanotun/config.toml}"
NAME_HOST="${E2E_C_DEVNAME:-vultr}.$E2E_C_USER"   # 前半段,拼上后缀即完整 magic 名字
TEST_PREF="${DRILL_SUFFIX:-nanotun}"             # 想验的非默认后缀(与原值撞车时下面会换)
SUFFIX_TOOL_LOCAL="$HERE/../set-magic-suffix.sh"   # 改后缀工具在 scripts/(本目录上一级)
SUFFIX_TOOL_REMOTE=/tmp/nte2e-set-suffix.sh

if [ "${E2E_SRV_MODE:-systemd}" != systemd ]; then
  echo "本 drill 仅支持 systemd 形态(当前 E2E_SRV_MODE=$E2E_SRV_MODE);docker 形态的后缀语义由单测+裸机装机测覆盖。" >&2
  exit 2
fi

# 读服务端 config.toml 里现有的 domain_suffix;缺行/被注释 → 运行期兜底 lan(resolveMagicDNSConfig 同口径)。
_read_suffix() {
  local line v
  line="$(s "grep -m1 -E '^[[:space:]]*domain_suffix[[:space:]]*=' $CFG" 2>/dev/null || true)"
  v="$(printf '%s' "$line" | sed -n 's/.*"\([^"]*\)".*/\1/p' | tr -d '[:space:]')"
  printf '%s' "${v:-lan}"
}

# 在 SRV 本地跑 set-magic-suffix.sh:校验→备份→段感知改写→重启→轮询→失败自动回滚(单一真源)。
_apply_suffix() {
  s "SERVICE=nanotun CONFIG=$CFG bash $SUFFIX_TOOL_REMOTE $1"
}

_dig_a()    { a "dig +short +time=4 +tries=1 @$GW4 $NAME_HOST.$1"        | head -1 | tr -d '[:space:]'; }
_dig_aaaa() { a "dig +short -t AAAA +time=4 +tries=1 @$GW4 $NAME_HOST.$1" | head -1 | tr -d '[:space:]'; }
# wait_until 谓词:当前后缀下 A 能把 magic 名字解析到 C 的 vIP4(= 重启完成 + A 已重连 + 网关就绪)。
_resolves() { [ "$(_dig_a "$1")" = "$E2E_C_VIP4" ]; }

ORIG=""       # 跑之前的后缀,收尾还原到它
RESTORED=0

_drill_cleanup() {
  # 只要动过后缀(ORIG 已知)且还没还原,就还原回去 —— 中途任何一步失败都不能把实验室
  # 留在测试后缀上。_apply_suffix 幂等(已是目标值即 no-op),重复调用安全。
  if [ -n "$ORIG" ] && [ "$RESTORED" != 1 ]; then
    echo "  [cleanup] 还原 MagicDNS 后缀 → $ORIG …" >&2
    _apply_suffix "$ORIG" >/dev/null 2>&1 \
      || echo "  [cleanup] !! 还原后缀失败,实验室可能停在测试后缀,请手动: sudo nanotun-set-suffix $ORIG" >&2
  fi
  a "rm -f $SUFFIX_TOOL_REMOTE" >/dev/null 2>&1 || true
  s "rm -f $SUFFIX_TOOL_REMOTE" >/dev/null 2>&1 || true
  e2e_ssh_cleanup
}
trap _drill_cleanup EXIT

# 只需要 SRV(改配置/重启)+ A(打网关 DNS)。C 不用在线,它有租约,MagicDNS 从 store 就能解析。
for pair in SRV:s A:a; do
  runner="${pair#*:}"
  if ! "$runner" true >/dev/null 2>&1; then
    echo "无法连接到 ${pair%%:*}(${runner})—— 检查 e2e.env 与网络" >&2
    exit 2
  fi
done

[ -f "$SUFFIX_TOOL_LOCAL" ] || { echo "找不到 $SUFFIX_TOOL_LOCAL(改后缀工具)" >&2; exit 2; }
push_file s "$SUFFIX_TOOL_LOCAL" "$SUFFIX_TOOL_REMOTE" || { echo "推送改后缀工具到 SRV 失败" >&2; exit 2; }

ORIG="$(_read_suffix)"
[ "$ORIG" = "$E2E_MAGIC_SUFFIX" ] || \
  echo "  提示:服务端现后缀 '$ORIG' 与 e2e.env 的 E2E_MAGIC_SUFFIX='$E2E_MAGIC_SUFFIX' 不一致,以现值为准。" >&2

# 测试后缀不能与原值相同(否则「改」是空操作,验不到切换)。撞车就退到 mesh。
TEST="$TEST_PREF"
[ "$TEST" = "$ORIG" ] && TEST=mesh
if [ "$TEST" = "$ORIG" ]; then
  echo "测试后缀与原后缀都算不出一个不同的值('$ORIG'),用 DRILL_SUFFIX=<别的> 指定。" >&2
  exit 2
fi

phase_begin "非默认后缀端到端 · $ORIG → $TEST → $ORIG(网关 $GW4)"
note "名字: $NAME_HOST.<后缀>  期望 vIP4=$E2E_C_VIP4 vIP6=$E2E_C_VIP6"

# ── 切到测试后缀 ────────────────────────────────────────────────────────────
if _apply_suffix "$TEST" >/tmp/nte2e-sfx.log 2>&1; then
  _pass "改后缀 $ORIG → $TEST(config 改写 + 重启 + 服务回 active)"
else
  _fail "改后缀 $ORIG → $TEST 失败" "见 SRV 上 set-magic-suffix 输出(工具已自动回滚)"
  sed 's/^/       /' /tmp/nte2e-sfx.log 2>/dev/null | tail -20
  e2e_report; exit $?
fi

# 重启后要等 A 重连、网关 :53 就绪,magic 名字才解析得到 —— 用正向解析当就绪信号。
wait_until "重启后 A 经网关 DNS 解析 *.$TEST(客户端重连 + 网关就绪)" 120 _resolves "$TEST"

check      "配置文件 domain_suffix 已写为 $TEST"                 "$TEST"          "$(_read_suffix)"
check      "网关 DNS · *.$TEST 的 A 记录 = C 的 vIP4"            "$E2E_C_VIP4"    "$(_dig_a "$TEST")"
check      "网关 DNS · *.$TEST 的 AAAA 记录 = C 的 vIP6"         "$E2E_C_VIP6"    "$(_dig_aaaa "$TEST")"
# 排他性:切了后缀,旧后缀就不该再被网关作答(空 = NXDOMAIN,check 对空期望是合法断言)。
check      "旧后缀 · *.$ORIG 已不再解析(NXDOMAIN)"              ""               "$(_dig_a "$ORIG")"

# ── 还原后缀,并验「还原也真的生效」──────────────────────────────────────────
if _apply_suffix "$ORIG" >/tmp/nte2e-sfx.log 2>&1; then
  RESTORED=1
  _pass "还原后缀 $TEST → $ORIG"
else
  _fail "还原后缀 $TEST → $ORIG 失败" "见 set-magic-suffix 输出;trap 会再试一次"
  sed 's/^/       /' /tmp/nte2e-sfx.log 2>/dev/null | tail -20
fi

if [ "$RESTORED" = 1 ]; then
  wait_until "还原后 A 经网关 DNS 恢复解析 *.$ORIG"              120 _resolves "$ORIG"
  check      "还原后 · 测试后缀 *.$TEST 不再解析(NXDOMAIN)"     ""  "$(_dig_a "$TEST")"
fi

rm -f /tmp/nte2e-sfx.log 2>/dev/null || true
e2e_report
exit $?
