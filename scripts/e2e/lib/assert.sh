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

# check <描述> <期望> <实际>
check() {
  local desc="$1" want="$2" got="$3"
  if [[ "$want" == "$got" ]]; then
    _pass "$desc"
  else
    _fail "$desc" "期望 [$want],实际 [$got]"
  fi
}

# check_match <描述> <正则> <实际>
check_match() {
  local desc="$1" re="$2" got="$3"
  if [[ "$got" =~ $re ]]; then
    _pass "$desc"
  else
    _fail "$desc" "期望匹配 /$re/,实际 [$got]"
  fi
}

# check_contains <描述> <子串> <实际>
check_contains() {
  local desc="$1" needle="$2" got="$3"
  if [[ "$got" == *"$needle"* ]]; then
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

# 汇总。有失败时返回 1,供 CI / 调用方直接用退出码判断。
e2e_report() {
  local total=$((E2E_PASS + E2E_FAIL))
  printf '\n%s────────────────────────────────────────%s\n' "$_B" "$_N"
  printf '合计 %d 项:%s通过 %d%s,%s失败 %d%s,跳过 %d\n' \
    "$total" "$_G" "$E2E_PASS" "$_N" "$_R" "$E2E_FAIL" "$_N" "$E2E_SKIP"
  if (( E2E_FAIL > 0 )); then
    printf '\n失败清单:\n'
    local f
    for f in "${E2E_FAILURES[@]}"; do printf '  - %s\n' "$f"; done
    return 1
  fi
  return 0
}
