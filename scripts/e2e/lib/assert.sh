#!/usr/bin/env bash
# 断言原语与结果汇总。
#
# 设计要点是 wait_until:被测系统里几乎每个管理面动作都是**最终一致**的
# ——「exit designate」之后客户端要等下一次 EgressSelectAck、「acl deny」之后
# 要等快照重建、「kick」之后要等客户端自己重连。手工回归时这些地方一律用
# sleep 硬等,既拖时间又 flaky(网络抖一下就假失败)。这里统一改成轮询到
# 条件成立为止,超时才算失败:快的时候几百毫秒返回,慢的时候也不会误报。

set -uo pipefail

E2E_PASS=0
E2E_FAIL=0
E2E_SKIP=0
E2E_FAILURES=()
E2E_CUR_PHASE=""

# 环境问题必须跨子 shell 累计:取值函数几乎都是在 $(...) 里被调用的,
# 而子 shell 对数组的修改父 shell 根本看不见。落到文件上才靠得住。
E2E_ENVLOG="${TMPDIR:-/tmp}/nanotun-e2e-env.$$"
: > "$E2E_ENVLOG"

# 颜色只在 tty 上开,重定向到文件时保持纯文本。
if [[ -t 1 ]]; then
  _G=$'\033[32m'; _R=$'\033[31m'; _Y=$'\033[33m'; _B=$'\033[1m'; _N=$'\033[0m'
else
  _G=""; _R=""; _Y=""; _B=""; _N=""
fi

phase_begin() {
  E2E_CUR_PHASE="$1"
  printf '\n%s══ %s ══%s\n' "$_B" "$1" "$_N"
}

_pass() {
  E2E_PASS=$((E2E_PASS + 1))
  printf '  %sPASS%s %s\n' "$_G" "$_N" "$1"
}

_fail() {
  E2E_FAIL=$((E2E_FAIL + 1))
  E2E_FAILURES+=("[$E2E_CUR_PHASE] $1")
  printf '  %sFAIL%s %s\n' "$_R" "$_N" "$1"
  [[ -n "${2:-}" ]] && printf '       %s\n' "$2"
  return 0
}

skip() {
  E2E_SKIP=$((E2E_SKIP + 1))
  printf '  %sSKIP%s %s\n' "$_Y" "$_N" "$1"
}

note() { printf '       %s\n' "$1"; }

# env_error <说明>
#
# 脚手架或环境本身的问题,跟「被测系统有缺陷」是两回事,必须分开报。
# 混进 FAIL 里会把排查引向产品代码:2026-07-27 那轮五条限速断言全红,看着像
# 限速回归,实际是断言自己把登录名当 device_id 传了进去,取值恒为空。
#
# 同一条说明只记一次 —— 取值函数常被 wait_until 每秒调一遍,不去重会刷屏。
env_error() {
  local msg="$1"
  # 阶段开跑前(比如取初始快照)也可能出问题,那时还没有阶段名可加。
  [[ -n "$E2E_CUR_PHASE" ]] && msg="[$E2E_CUR_PHASE] $1"
  grep -Fxq -- "$msg" "$E2E_ENVLOG" 2>/dev/null && return 0
  printf '%s\n' "$msg" >> "$E2E_ENVLOG"
  # 只能写 stderr:本函数常在 $(...) 内被调用,写 stdout 会被当成取值结果收走。
  printf '  %sENV%s  %s\n' "$_Y" "$_N" "$1" >&2
  return 0
}

# 取值函数没能给出值:空串一般是命令挂了(SSH 断、python 抛异常、远端不存在),
# "?" 是取值函数自己声明的「没取到」。
#
# 期望值本身是空串时不适用 —— 「未知名字返回 NXDOMAIN(空结果)」是一条
# 合法断言,那里的空正是要断言的东西。
_no_value() { [[ -z "$1" || "$1" == "?" ]]; }

# 拿不到值时这条断言给不出任何结论,既不算通过也不算失败:
# 报成 FAIL 等于宣称「被测系统不对」,而实际情况是「我们没测到」。
_verdict_unavailable() {
  local desc="$1" want="$2" got="$3"
  env_error "$desc:取值为 [$got],无法与期望 [$want] 比对,这条没有测到"
}

# check <描述> <期望> <实际>
check() {
  local desc="$1" want="$2" got="$3"
  if [[ -n "$want" ]] && _no_value "$got"; then
    _verdict_unavailable "$desc" "$want" "$got"
  elif [[ "$want" == "$got" ]]; then
    _pass "$desc"
  else
    _fail "$desc" "期望 [$want],实际 [$got]"
  fi
}

# check_match <描述> <正则> <实际>
check_match() {
  local desc="$1" re="$2" got="$3"
  if _no_value "$got"; then
    _verdict_unavailable "$desc" "/$re/" "$got"
  elif [[ "$got" =~ $re ]]; then
    _pass "$desc"
  else
    _fail "$desc" "期望匹配 /$re/,实际 [$got]"
  fi
}

# check_contains <描述> <子串> <实际>
check_contains() {
  local desc="$1" needle="$2" got="$3"
  if _no_value "$got"; then
    _verdict_unavailable "$desc" "含 [$needle]" "$got"
  elif [[ "$got" == *"$needle"* ]]; then
    _pass "$desc"
  else
    _fail "$desc" "期望包含 [$needle],实际 [$got]"
  fi
}

# check_rc <描述> <期望退出码> <runner> <命令...>
# 专门给「这条管理命令应该失败」用:期望非 0 时必须核对具体的码,
# 只判断「非 0」会让「参数拼错」和「守卫生效」看起来一模一样。
check_rc() {
  local desc="$1" want="$2"; shift 2
  local got; got="$(rc_of "$@")"
  check "$desc" "$want" "$got"
}

# wait_until <描述> <超时秒> <命令...>
# 命令退出码为 0 即算成立。成立后顺带报告耗时,便于发现「虽然通过但明显变慢了」。
wait_until() {
  local desc="$1" timeout="$2"; shift 2
  local start elapsed
  start=$(date +%s)
  while :; do
    if "$@" >/dev/null 2>&1; then
      elapsed=$(( $(date +%s) - start ))
      _pass "${desc}（${elapsed}s）"
      return 0
    fi
    elapsed=$(( $(date +%s) - start ))
    if (( elapsed >= timeout )); then
      _fail "$desc" "${timeout}s 内未成立"
      return 1
    fi
    sleep 1
  done
}

# wait_while <描述> <超时秒> <命令...>
# 与 wait_until 相反:等到命令**不再**成功为止(例如等某条路径变为不可达)。
wait_while() {
  local desc="$1" timeout="$2"; shift 2
  local start elapsed
  start=$(date +%s)
  while :; do
    if ! "$@" >/dev/null 2>&1; then
      elapsed=$(( $(date +%s) - start ))
      _pass "${desc}（${elapsed}s）"
      return 0
    fi
    elapsed=$(( $(date +%s) - start ))
    if (( elapsed >= timeout )); then
      _fail "$desc" "${timeout}s 内条件仍然成立"
      return 1
    fi
    sleep 1
  done
}

# 汇总。退出码:0 全通过,1 有断言失败,2 环境/脚手架有问题(本轮结论不可信)。
#
# 2 优先于 1:取值都没取到的时候,那些「失败」讲的是脚手架自己的故障,
# 拿去当产品缺陷追会一路追错方向。
e2e_report() {
  local total=$((E2E_PASS + E2E_FAIL))
  local nenv=0
  [[ -s "$E2E_ENVLOG" ]] && nenv=$(grep -c '' "$E2E_ENVLOG")
  printf '\n%s────────────────────────────────────────%s\n' "$_B" "$_N"
  printf '合计 %d 项:%s通过 %d%s,%s失败 %d%s,跳过 %d\n' \
    "$total" "$_G" "$E2E_PASS" "$_N" "$_R" "$E2E_FAIL" "$_N" "$E2E_SKIP"
  if (( E2E_FAIL > 0 )); then
    printf '\n失败清单:\n'
    local f
    for f in "${E2E_FAILURES[@]}"; do printf '  - %s\n' "$f"; done
  fi
  if (( nenv > 0 )); then
    printf '\n%s环境/脚手架问题 %d 项 —— 本轮结论不可信,先修脚手架再看红绿:%s\n' \
      "$_Y" "$nenv" "$_N"
    local e
    while IFS= read -r e; do printf '  - %s\n' "$e"; done < "$E2E_ENVLOG"
    return 2
  fi
  (( E2E_FAIL > 0 )) && return 1
  return 0
}
