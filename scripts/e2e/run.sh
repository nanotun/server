#!/usr/bin/env bash
# nanotun 三机 e2e 回归入口。
#
#   ./run.sh                 跑全部阶段
#   ./run.sh 10 30           只跑阶段 1 和阶段 3
#   ./run.sh --list          列出阶段
#   ./run.sh --keep-target   跑完不停靶站(方便手工接着排查)
#
# 退出码:0 全通过,1 有失败,2 环境/配置问题(此时红绿都不可信)。

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=lib/env.sh
source "$HERE/lib/env.sh"
# shellcheck source=lib/assert.sh
source "$HERE/lib/assert.sh"
# shellcheck source=lib/fixtures.sh
source "$HERE/lib/fixtures.sh"

for f in "$HERE"/phases/*.sh; do
  # shellcheck disable=SC1090
  source "$f"
done

ALL_PHASES=(00:phase_00_baseline:"基线"
            10:phase_10_exit:"出口节点与 MagicDNS"
            20:phase_20_acl_rate:"ACL 与限速"
            30:phase_30_subnet:"子网路由与 4via6"
            40:phase_40_lease_account:"租约与账号状态"
            50:phase_50_ops:"运维面"
            60:phase_60_web:"端口转发与 Web 安全边界"
            70:phase_70_crash:"硬崩溃恢复")

usage() {
  echo "用法: $0 [--list] [--keep-target] [阶段号...]"
  echo
  echo "阶段:"
  local e
  for e in "${ALL_PHASES[@]}"; do
    printf '  %s  %s\n' "${e%%:*}" "${e##*:}"
  done
}

KEEP_TARGET=0
WANTED=()
while (( $# )); do
  case "$1" in
    --list) usage; exit 0 ;;
    --keep-target) KEEP_TARGET=1 ;;
    -h|--help) usage; exit 0 ;;
    [0-9]*) WANTED+=("$1") ;;
    *) echo "未知参数: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

e2e_load_env || exit 2

# 单实例锁。两轮 e2e 并发跑会**互相踩**:各自重启服务端、改同一份 config.toml、
# 把对方的靶站停掉、抢同一个公网端口 —— 症状是一大片看不出原因的红,而两边的日志
# 各自都「说得通」。2026-08-02 连着栽了两次(一次是同一条命令被执行了两遍),第二次
# 两轮还写进了同一个日志文件,PASS 和失败清单自相矛盾,查了很久才认出是并发。
#
# 用 mkdir 而不是 flock:mkdir 本身是原子的,而 macOS 上没有 flock(1)。
E2E_LOCK="${TMPDIR:-/tmp}/nanotun-e2e.lock"
if ! mkdir "$E2E_LOCK" 2>/dev/null; then
  _holder="$(cat "$E2E_LOCK/pid" 2>/dev/null || true)"
  if [[ "$_holder" =~ ^[0-9]+$ ]] && kill -0 "$_holder" 2>/dev/null; then
    echo "已有一轮 e2e 在跑(pid $_holder),两轮并发会互相踩,拒绝启动。" >&2
    echo "确认那轮确实已经死了再:rm -rf $E2E_LOCK" >&2
    exit 2
  fi
  echo "清掉上一轮留下的陈旧锁(pid ${_holder:-?} 已不在)" >&2
  rm -rf "$E2E_LOCK"
  mkdir "$E2E_LOCK" 2>/dev/null || { echo "抢锁失败:$E2E_LOCK" >&2; exit 2; }
fi
echo $$ > "$E2E_LOCK/pid"

for bin in sshpass python3 curl; do
  command -v "$bin" >/dev/null || { echo "缺少依赖: $bin" >&2; exit 2; }
done

e2e_ssh_init
cleanup() {
  local rc=$?
  (( KEEP_TARGET )) || target_stop
  e2e_ssh_cleanup
  rm -f "$E2E_ENVLOG"
  rm -rf "$E2E_LOCK"
  exit $rc
}
trap cleanup EXIT INT TERM

printf '%s目标环境%s  server=%s  A=%s  C=%s\n' "$_B" "$_N" \
  "$E2E_SRV_HOST" "$E2E_A_HOST" "$E2E_C_HOST"

if ! e2e_ssh_warmup; then
  echo "SSH 预热失败,三台机器未全部就绪。" >&2
  exit 2
fi

# 阶段 0 永远要跑:它既是基线校验,也负责把靶站和会话拉起来,
# 后面每个阶段都建立在它的前提之上。跳过它去跑单个阶段只会得到一堆无法解读的红。
selected=()
if (( ${#WANTED[@]} == 0 )); then
  selected=("${ALL_PHASES[@]}")
else
  selected+=("${ALL_PHASES[0]}")
  for want in "${WANTED[@]}"; do
    for e in "${ALL_PHASES[@]}"; do
      [[ "${e%%:*}" == "$want" && "${e%%:*}" != "00" ]] && selected+=("$e")
    done
  done
fi

# 快照拿不到时收尾的残留比对就整个失效了。这是覆盖被悄悄削掉一块,
# 不该只印一行滚过去的警告 —— 归为环境问题,让退出码把它顶出来。
state_snapshot || env_error "未能取得开跑前的状态快照,收尾的残留比对已失效"

for e in "${selected[@]}"; do
  fn="${e#*:}"; fn="${fn%%:*}"
  if ! "$fn"; then
    # 阶段返回非 0 表示「前提不成立,继续跑没有意义」(比如基线就不通)。
    printf '\n%s阶段 %s 判定为不可继续,提前结束。%s\n' "$_R" "${e%%:*}" "$_N"
    break
  fi
done

phase_begin "收尾"
state_verify

e2e_report
