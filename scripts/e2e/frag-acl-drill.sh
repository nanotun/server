#!/usr/bin/env bash
# 分片绕不过端口 ACL —— 数据面黑盒 drill(按需跑,不进发版门禁)。
#
#   ./frag-acl-drill.sh
#
# 退出码沿用套件约定:0 全通过,1 有断言失败,2 环境/脚手架问题(红绿不可信)。
#
# ── 为什么单独一支 ──────────────────────────────────────────────────────────
# 「端口 deny 不能被分片绕过」此前只有一条单测(acl_eval_guards_test.go 的
# TestEvaluateUser_PortDenyIsNotBypassableByFragmentation),它证的是**解析器**在拿到
# 一枚非首片时会 fail-closed。但真实攻击面是整条数据面:客户端从自己的 IP 栈发出分片
# → 隧道封装 → 服务端解包 → demux 取五元组 → ACL 判定 → 丢/放。任何一环把非首片
# 当「读不到端口就放行」处理,单测照样全绿,而线上的端口封锁实际是漏的。这支在三台
# 真机上把那条链走一遍,用服务端的 acl_drops 计数当判据。
#
# ── 判据为什么用 acl_drops 增量而不是「对端有没有收到」──────────────────────
# 不依赖在对端架 tcpdump:计数增量是服务端自证的、跨机器唯一稳的信号,CI 里也不用
# 装抓包工具。分辨力落在一个具体数字上 —— 一个「3 片对」= 3 首片 + 3 非首片:
#   fail-closed 正确 → 6 片全丢(增量 6);
#   回归成「非首片放行」→ 只剩首片被端口规则拦下(增量 3)。
# 6 与 3 之间就是这条缺陷的照妖镜。
#
# ── 一个刻意保留的非向量 ────────────────────────────────────────────────────
# 「只发孤立非首片」对服务端无意义:没有首片相伴时,**发送端本机内核的 defrag 队列**
# 就把它扣住、根本不出网卡(实测到不了服务端,也不计入 acl_drops)。真实攻击者从自己
# 的 IP 栈发也撞同一堵墙。所以有效判据是成对发(frag),让非首片搭着首片一起上路。
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/env.sh
source "$HERE/lib/env.sh"
# shellcheck source=lib/assert.sh
source "$HERE/lib/assert.sh"

e2e_load_env || exit 2
e2e_ssh_init

DRILL_PORT="${DRILL_PORT:-9100}"          # 一个平时没人用的端口,免得别的流量掺进增量
SENDER_REMOTE=/tmp/nte2e-fragsend.py

# 收尾:删掉本 drill 加的 ACL 规则、清掉推上去的发包器、关 ssh 复用连接。
# 中途任何一步失败都要走到这里 —— 否则会把一条 deny 规则留在共用环境上。
_drill_cleanup() {
  _acl_del_all 2>/dev/null || true
  a "rm -f $SENDER_REMOTE" >/dev/null 2>&1 || true
  e2e_ssh_cleanup
}
trap _drill_cleanup EXIT

# 只需要 SRV(判定)+ A(发包);C 不参与,acl_drops 增量就是判据。
for pair in SRV:s A:a; do
  runner="${pair#*:}"
  if ! "$runner" true >/dev/null 2>&1; then
    echo "无法连接到 ${pair%%:*}(${runner})—— 检查 e2e.env 与网络" >&2
    exit 2
  fi
done

_acl_count() {
  adm "acl list --json" 2>/dev/null | python3 -c 'import json,sys
try: print(len(json.load(sys.stdin)))
except Exception: print("?")'
}

_acl_del_all() {
  local ids id
  ids="$(adm "acl list --json" 2>/dev/null | python3 -c 'import json,sys
try: print(" ".join(str(r["id"]) for r in json.load(sys.stdin)))
except Exception: pass')"
  for id in $ids; do adm "acl delete $id" >/dev/null; done
}

_acl_drops() { adm "connection list" | sed -n 's/.*acl_drops: \([0-9]*\).*/\1/p' | head -1; }

# _send <mode> <ipid> [reps] :在 A 上以 root 跑发包器(SOCK_RAW 需要 root)。
_send() { a "python3 $SENDER_REMOTE $E2E_A_VIP4 $E2E_C_VIP4 $DRILL_PORT $1 $2 ${3:-3}"; }

# _delta <mode> <ipid> [reps] :发一批,回服务端 acl_drops 的增量(取不到回 "?")。
_delta() {
  local d0 d1
  d0="$(_acl_drops)"
  _send "$1" "$2" "${3:-3}" >/dev/null 2>&1
  sleep 1
  d1="$(_acl_drops)"
  [[ "$d0" =~ ^[0-9]+$ && "$d1" =~ ^[0-9]+$ ]] || { echo "?"; return; }
  echo $(( d1 - d0 ))
}

# _whole_dropped :发一枚不分片 SYN,若 acl_drops 因此上涨则成立。给 wait_until 用,
# 确认 deny 规则已经在数据面拦包(而不是只写了库)。
_whole_dropped() {
  local d0 d1
  d0="$(_acl_drops)"
  _send whole 9001 1 >/dev/null 2>&1
  sleep 1
  d1="$(_acl_drops)"
  [[ "$d0" =~ ^[0-9]+$ && "$d1" =~ ^[0-9]+$ ]] && (( d1 > d0 ))
}

phase_begin "分片不可绕过端口 deny(数据面黑盒)"

# ── 前置:ACL 必须为空 ──────────────────────────────────────────────────────
# 全靠 acl_drops 增量判定,库里已有的规则一旦在窗口里丢包就污染了增量。非空则停下
# 报 ENV(而不是替用户删),免得误伤共用环境上别人配的策略。
n="$(_acl_count)"
if [[ "$n" != "0" ]]; then
  env_error "开跑前 ACL 非空(有 $n 条规则),增量判定会被污染 —— 先清空 ACL 再跑"
  e2e_report; exit $?
fi

if ! push_file a "$HERE/remote/fragsend.py" "$SENDER_REMOTE"; then
  env_error "推送 fragsend.py 到 A 失败,这条 drill 测不到"
  e2e_report; exit $?
fi

# ── 1. 对照 + 污染守卫:无规则时分片对不触发任何 ACL 丢弃 ────────────────────
# 一箭双雕:证明「默认放行下分片(含非首片)能穿」(否则下一步的拦截没有对照),
# 且证明「窗口里除我造的包外没别的在丢」(基线增量为 0,后面的增量才可信)。
check "无规则时分片对不触发 ACL 丢弃(增量应为 0,兼作污染守卫)" "0" "$(_delta frag 3001 3)"

# ── 2. 加 deny A→C tcp:P,并确认它真的在数据面拦包 ──────────────────────────
adm "acl deny $E2E_A_USER $E2E_C_USER --port $DRILL_PORT --proto tcp" >/dev/null
wait_until "deny 规则即时生效(不分片 SYN 已被丢)" 20 _whole_dropped

# ── 3. 关键判据:分片对 6 片全丢(3 首片命中端口规则 + 3 无端口非首片 fail-closed)─
# 回归成「非首片读不到端口就放行」的话增量会掉到 3 —— 那正是分片绕过 ACL 的经典形态。
check "deny 下分片对 6 片全丢:无端口的非首片也被 fail-closed(而非放行)" "6" "$(_delta frag 4001 3)"

# ── 4. 旁证:不分片 SYN 命中端口规则,一片一丢 ──────────────────────────────
check "deny 下不分片 SYN 按端口规则逐个丢(增量 3)" "3" "$(_delta whole 4101 3)"

# ── 5. 复原:删掉本 drill 加的规则,校验 ACL 归空 ────────────────────────────
_acl_del_all
check "复原:删规则后 ACL 归空" "0" "$(_acl_count)"

e2e_report
