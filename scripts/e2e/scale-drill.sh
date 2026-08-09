#!/usr/bin/env bash
# 规模 / 并发 —— 真机端到端 drill(按需跑,不进发版门禁)。
#
#   ./scale-drill.sh                 # 默认 40 个并发会话
#   SCALE_N=60 ./scale-drill.sh      # 加压到 60(受压力机内存约束,小机器别贪多)
#   SCALE_HOLD=120 ./scale-drill.sh  # 满载保持 120s 再看有没有内存爬升
#
# 退出码沿用套件约定:0 全通过,1 有断言失败,2 环境/脚手架问题(红绿不可信)。
#
# ── 为什么单独一支 ──────────────────────────────────────────────────────────
# 并发**正确性**(锁内 vIP 分配不撞、supersede 收敛、churn 不漏)已由进程内
# login_storm*/login_scale_lease 等在 -race 下钉死;三机 e2e 只有两条会话,结构上摸不到
# 「几十条真链路同时在线」这件事。这支补的正是那块:真实 reality 传输、真实 OS socket、
# 真实进程 RSS/线程/FD 随会话数怎么走、撤压后收不收得干净。判据全落在**服务端自证的
# 数字**上(会话数、租约唯一度、/proc 资源),不依赖客户端侧观测。
#
# ── 为什么用 A 当压力机、且要先停 nanotun-a ──────────────────────────────────
# 客户端 device_uuid 按机器派生,单机隔离 HOME 出不来第二台设备,所以用 N 个用户凑 N
# 条会话(见 scale-gen.sh)。A 上有客户端二进制,是现成的压力机;但 nanotun-a 带 --exit
# 接管了默认路由,不停它的话新起的实例 reality 握手会被塞进隧道 VPN-over-VPN。故开跑先
# 停 nanotun-a(A 回到直连 WAN),收尾再拉回。所有改动都在收尾 trap 里复原,中断也不留残。
#
# ── 判据阈值的取法 ──────────────────────────────────────────────────────────
#   租约唯一:distinct(v4)=distinct(v6)=distinct(dev)=会话数 —— 破了就是数据面串台,硬判。
#   线程:会话是 goroutine 不是 OS 线程,满载相对基线 +≤8 才算「没被摊成线程」。
#   FD:一条链路一个 socket,满载新增应 ≥ N。
#   内存:满载保持一段时间 RSS 增幅 < 50% 视作无爬升(Go 有锯齿,给足余量;真漏会远超)。
#   收敛:撤压后 FD 回到基线 +≤4 —— 每会话 socket 都被释放,是「无泄漏」最硬的一条。
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/env.sh
source "$HERE/lib/env.sh"
# shellcheck source=lib/assert.sh
source "$HERE/lib/assert.sh"
# shellcheck source=lib/fixtures.sh
source "$HERE/lib/fixtures.sh"

SCALE_N="${SCALE_N:-40}"
SCALE_HOLD="${SCALE_HOLD:-60}"
SCALE_SETTLE="${SCALE_SETTLE:-10}"   # 建齐后先沉淀:让登录期 argon2 峰值退掉再采稳态
PREFIX="${SCALE_PREFIX:-scaleu}"

e2e_load_env || exit 2
e2e_ssh_init

RS="${E2E_REMOTE_DIR:-/tmp/nte2e}"     # SRV 上放 helper 的目录
RA_CLIENTS=/tmp/nte2e-scale-clients.sh  # 压力机上的 launcher
BASE_A=/tmp/nte2e-scale                 # 压力机上客户端工作目录(与 scale-clients.sh 对齐)
TMP="$(mktemp -d)"

ORIG_SESSIONS=""   # 开跑前(停 A 之前)的会话数,收尾要回到这个数
_RESTORED=0

# 收尾:停掉所有 scale 客户端、删掉压测用户、复原 nanotun-a。任何一步中断都要走到这里,
# 否则会把几十个 scaleuNNN 用户和一堆瞬时 unit 留在共用环境上。幂等,可与正常流程重复。
_restore_once() {
  [[ "$_RESTORED" == 1 ]] && return 0
  _RESTORED=1
  a "bash $RA_CLIENTS teardown" >/dev/null 2>&1 || true
  s "NTE2E_DB=$E2E_DB_PATH bash $RS/scale-clean.sh $SCALE_N $PREFIX" >/dev/null 2>&1 || true
  a "rm -rf $BASE_A" >/dev/null 2>&1 || true
  client_a_start >/dev/null 2>&1 || true
}
_cleanup() { _restore_once; rm -rf "$TMP"; e2e_ssh_cleanup; }
trap _cleanup EXIT

# ── 数据源:全部从服务端自证 ────────────────────────────────────────────────
_srv_json() { adm "connection list --json" 2>/dev/null; }

_conn() {
  _srv_json | python3 -c 'import json,sys
raw=sys.stdin.read(); i=raw.find("{")
print(json.loads(raw[i:]).get("conn_count","") if i>=0 else "")' 2>/dev/null
}

# _distinct <v4|v6|dev> → 当前在线会话里该维度的**去重**计数。租约唯一性判据。
_distinct() {
  _srv_json | python3 -c 'import json,sys
raw=sys.stdin.read(); i=raw.find("{")
d=json.loads(raw[i:]) if i>=0 else {}
f=sys.argv[1]; seen=set()
for x in d.get("sessions",[]):
    if f=="dev":
        seen.add(x.get("device_id"))
    else:
        for v in (x.get("vips") or []):
            if (":" in v)==(f=="v6"): seen.add(v)
print(len(seen))' "$1" 2>/dev/null
}

_proc() { s "bash $RS/scale-proc.sh" | tail -1; }   # 打印 "rss_kB threads fds"

_conn_ge() { local n; n="$(_conn)"; [[ "$n" =~ ^[0-9]+$ ]] && (( n >= $1 )); }
_conn_eq() { [[ "$(_conn)" == "$1" ]]; }
_isnum()   { [[ "$1" =~ ^[0-9]+$ ]]; }

# _bounded <desc> <got_delta> <max> :把「增量 ≤ 上限」翻成 yes/no 给 check 用;
# 操作数非数字时报 ENV 并回 "?"(这条测不到,别当产品缺陷)。
_le_yn() { # _le_yn <a> <b> → yes if a<=b
  if _isnum "$1" && _isnum "$2"; then [[ "$1" -le "$2" ]] && echo yes || echo no; else echo "?"; fi
}
_ge_yn() { # _ge_yn <a> <b> → yes if a>=b
  if _isnum "$1" && _isnum "$2"; then [[ "$1" -ge "$2" ]] && echo yes || echo no; else echo "?"; fi
}

# ── 前置检查 ────────────────────────────────────────────────────────────────
for pair in SRV:s A:a; do
  runner="${pair#*:}"
  if ! "$runner" true >/dev/null 2>&1; then
    echo "无法连接到 ${pair%%:*}(${runner})—— 检查 e2e.env 与网络" >&2
    exit 2
  fi
done
a "test -x /usr/local/bin/nanotun" >/dev/null 2>&1 || { echo "A 上没有 /usr/local/bin/nanotun(客户端二进制,不在本仓库)" >&2; exit 2; }
s "command -v python3" >/dev/null 2>&1 || { echo "SRV 上没有 python3(取样/解析要用)" >&2; exit 2; }

phase_begin "规模 / 并发:${SCALE_N} 条真实会话同时在线(真机端到端)"

# ── 0. 推 helper、造身份 ────────────────────────────────────────────────────
s "mkdir -p $RS" >/dev/null
push_file s "$HERE/remote/scale-gen.sh"    "$RS/scale-gen.sh"    || { env_error "推 scale-gen.sh 到 SRV 失败"; e2e_report; exit $?; }
push_file s "$HERE/remote/scale-clean.sh"  "$RS/scale-clean.sh"  || { env_error "推 scale-clean.sh 到 SRV 失败"; e2e_report; exit $?; }
push_file s "$HERE/remote/scale-proc.sh"   "$RS/scale-proc.sh"   || { env_error "推 scale-proc.sh 到 SRV 失败"; e2e_report; exit $?; }
push_file a "$HERE/remote/scale-clients.sh" "$RA_CLIENTS"         || { env_error "推 scale-clients.sh 到 A 失败"; e2e_report; exit $?; }

# 记录开跑前会话数,并清掉任何上一轮的残留(幂等)。
ORIG_SESSIONS="$(_conn)"
_isnum "$ORIG_SESSIONS" || { env_error "取不到开跑前会话数(connection list 异常)"; e2e_report; exit $?; }
a "bash $RA_CLIENTS teardown" >/dev/null 2>&1 || true

gen_out="$(s "NTE2E_DB=$E2E_DB_PATH bash $RS/scale-gen.sh $SCALE_N $E2E_SRV_HOST $PREFIX")"
made="$(printf '%s\n' "$gen_out" | sed -nE 's/^MADE=([0-9]+).*/\1/p' | head -1)"
if [[ "$made" != "$SCALE_N" ]]; then
  env_error "造压测身份数不符:期望 $SCALE_N,实际 ${made:-空} —— 后面全不可信"
  e2e_report; exit $?
fi
b64="$(printf '%s\n' "$gen_out" | awk 'f{print; f=0} /=== BUNDLE_B64 ===/{f=1}' | tr -d '[:space:]')"
if [[ -z "$b64" ]]; then env_error "没拿到身份 bundle 的 base64"; e2e_report; exit $?; fi
printf '%s' "$b64" | base64 -d > "$TMP/bundle.tgz" 2>/dev/null || { env_error "bundle base64 解码失败"; e2e_report; exit $?; }

a "mkdir -p $BASE_A" >/dev/null
push_file a "$TMP/bundle.tgz" "$BASE_A/bundle.tgz" || { env_error "推 bundle 到 A 失败"; e2e_report; exit $?; }
a "cd $BASE_A && tar xzf bundle.tgz && rm -f bundle.tgz" >/dev/null 2>&1
n_creds="$(a "ls $BASE_A/cred_*.txt 2>/dev/null | wc -l" | tr -d '[:space:]')"
check "压力机上就绪 $SCALE_N 份凭据 + profile" "$SCALE_N" "$n_creds"

# ── 1. 腾出干净压力机:停 nanotun-a,取服务端基线 ────────────────────────────
client_a_stop
if ! wait_until "停掉 nanotun-a 后会话数下降(A 已下线)" 30 _conn_eq "$((ORIG_SESSIONS-1))"; then
  # A 本来可能就没在线(ORIG 里不含 A),那也没关系,继续用当前值当基线。
  note "开跑前 A 可能未在线,直接以当前会话数为基线"
fi
sleep 2
BASE_SESSIONS="$(_conn)"
read -r BASE_RSS BASE_THR BASE_FDS <<<"$(_proc)"
note "基线:会话=$BASE_SESSIONS  RSS=${BASE_RSS}kB  线程=$BASE_THR  FD=$BASE_FDS"
if ! _isnum "$BASE_SESSIONS" || ! _isnum "$BASE_FDS"; then
  env_error "基线采样异常(会话=$BASE_SESSIONS FD=$BASE_FDS),无法比对"
  e2e_report; exit $?
fi
EXP_TOTAL=$(( BASE_SESSIONS + SCALE_N ))

# ── 2. 起 N 条会话,等建齐 ──────────────────────────────────────────────────
a "bash $RA_CLIENTS launch $SCALE_N" >/dev/null 2>&1
# 单 IP 出题限速把登录摊成 ~1/s(burst 10),给足 60 + 3N 秒。
wait_until "$SCALE_N 条会话全部建立(单 IP 受 PoW 出题限速会摊开)" $(( 60 + 3*SCALE_N )) _conn_ge "$EXP_TOTAL"

# 沉淀:登录高峰每笔要跑一次 argon2id(m=64MB,受 argon2Sema 限并发),会把 RSS 顶到
# 上百 MB 的**瞬时峰值**;若在建齐那一刻就采,per-session 内存会被这波峰值严重夸大。
# 等一小会儿让这批临时缓冲被 GC 回收,采到的才是稳态。
sleep "$SCALE_SETTLE"

conn_full="$(_conn)"
v4="$(_distinct v4)"; v6="$(_distinct v6)"; dev="$(_distinct dev)"
read -r FULL_RSS FULL_THR FULL_FDS <<<"$(_proc)"
note "满载(沉淀 ${SCALE_SETTLE}s 后):会话=$conn_full  RSS=${FULL_RSS}kB  线程=$FULL_THR  FD=$FULL_FDS"

check "$SCALE_N 条会话全部在线(共 $EXP_TOTAL)"                 "$EXP_TOTAL" "$conn_full"
check "每会话唯一 v4 租约(无重叠 → 数据面不串台)"            "$EXP_TOTAL" "$v4"
check "每会话唯一 v6 租约"                                     "$EXP_TOTAL" "$v6"
check "每会话唯一设备身份"                                     "$EXP_TOTAL" "$dev"

if _isnum "$FULL_THR" && _isnum "$BASE_THR"; then
  check "线程数不随会话数线性增长(会话=goroutine,增量≤8)" "yes" "$(_le_yn $(( FULL_THR - BASE_THR )) 8)"
else
  env_error "线程采样异常(基线=$BASE_THR 满载=$FULL_THR)"
fi
if _isnum "$FULL_FDS"; then
  fd_delta=$(( FULL_FDS - BASE_FDS ))
  # FD 是稳态、干净的每会话信号:一条链路一个 socket,不受 argon2/GaGC 影响。
  check "FD 每会话约 1 个 socket(满载新增 ≥ $SCALE_N)" "yes" "$(_ge_yn "$fd_delta" "$SCALE_N")"
  # RSS 绝对值受「登录期 argon2 峰值 + Go 惰性归还」双重影响,不当每会话稳态用;
  # 内存是否泄漏改由下面「满载保持不爬升」+「撤压 FD 回基线」两条判。
  note "FD 增量 ${fd_delta}(每会话约 1);RSS 绝对值含登录期 argon2 峰值残留,不作每会话稳态解读"
fi

# ── 3. 满载保持:不该有内存爬升 ─────────────────────────────────────────────
note "满载保持 ${SCALE_HOLD}s,观察 RSS 是否爬升……"
sleep "$SCALE_HOLD"
conn_hold="$(_conn)"
read -r HOLD_RSS HOLD_THR HOLD_FDS <<<"$(_proc)"
note "保持后:会话=$conn_hold  RSS=${HOLD_RSS}kB  线程=$HOLD_THR  FD=$HOLD_FDS"
check "满载保持 ${SCALE_HOLD}s 会话数稳定" "$EXP_TOTAL" "$conn_hold"
if _isnum "$HOLD_RSS" && _isnum "$FULL_RSS"; then
  # 增幅 < 50%:hold_rss*2 ≤ full_rss*3
  [[ $(( HOLD_RSS * 2 )) -le $(( FULL_RSS * 3 )) ]] && creep=yes || creep=no
  check "满载保持无内存爬升(RSS 增幅 < 50%)" "yes" "$creep"
else
  env_error "保持段 RSS 采样异常(满载=$FULL_RSS 保持=$HOLD_RSS)"
fi

# ── 4. 撤压:必须收敛回基线、socket 全释放 ──────────────────────────────────
a "bash $RA_CLIENTS teardown" >/dev/null 2>&1
wait_until "撤压后会话收敛回基线($BASE_SESSIONS)" 90 _conn_eq "$BASE_SESSIONS"
read -r DRAIN_RSS DRAIN_THR DRAIN_FDS <<<"$(_proc)"
note "撤压后:RSS=${DRAIN_RSS}kB  线程=$DRAIN_THR  FD=$DRAIN_FDS(RSS 停在高位是 Go 惰性归还,非泄漏)"
check "撤压后 FD 回落到基线附近(每会话 socket 已释放,无泄漏)" "yes" "$(_le_yn "${DRAIN_FDS:-?}" "$(( BASE_FDS + 4 ))")"

# ── 5. 复原:删压测用户、拉回 nanotun-a ─────────────────────────────────────
clean_out="$(s "NTE2E_DB=$E2E_DB_PATH bash $RS/scale-clean.sh $SCALE_N $PREFIX")"
remaining="$(printf '%s\n' "$clean_out" | sed -nE 's/.*remaining=([0-9]+).*/\1/p' | head -1)"
a "rm -rf $BASE_A" >/dev/null 2>&1
check "复原:压测用户已全部删除(库无残留)" "0" "${remaining:-?}"
client_a_start
wait_until "复原:实验室回到压测前会话数($ORIG_SESSIONS)" 60 _conn_eq "$ORIG_SESSIONS"
_RESTORED=1   # 正常流程已复原,收尾 trap 不再重复

e2e_report
