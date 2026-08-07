#!/usr/bin/env bash
# 把「当前 HEAD 已跑过完整三机 e2e」盖成本地戳,供 scripts/release/cut.sh 核对。
#
# 用法(在 e2e 全绿之后):
#   ./scripts/e2e/run.sh 00 10 20 30 40 50 60 70
#   ./scripts/release/stamp-e2e.sh
#
# 戳不进 git(.gitignore)。盖戳后又 commit / 改文件,必须重跑 e2e 再盖。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "不在 git 仓库里,无法盖戳" >&2
  exit 2
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "工作树不干净:e2e 戳必须钉在一个确定的 commit 上。" >&2
  echo "先提交或 stash,再跑 e2e + 盖戳。" >&2
  git status --porcelain | head -20 >&2
  exit 2
fi

# 三机门禁跑在调度机上时,替人去核对那一轮的退出码。
#
# 原先这个脚本对「e2e 到底过没过」一个字都不看,全靠跑完的人记得瞄一眼。问题是最该
# 看的那一眼恰恰最容易漏:本地 wrapper 一断线,重新接上去的办法是 tail 调度机上的
# 日志 —— 而**退出码不在日志里**。日志末尾永远只有一句「合计 341 项:通过 341,
# 失败 0,跳过 0」,一轮环境塌了的跑法长得一模一样(断言没跑成不算失败,只记 ENV),
# 退出码 2 是它唯一的破绽,写在 last-run.rc 里。
# 2026-08-07 就差一点拿这样一轮去盖戳,躲过去纯属侥幸 —— 那次真正用的是另一轮。
E2E_ENV="$ROOT/scripts/e2e/e2e.env"
if [[ -f "$E2E_ENV" ]]; then set -a; . "$E2E_ENV"; set +a; fi
RUNNER_HOST="${E2E_RUNNER_HOST:-}"

if [[ -n "$RUNNER_HOST" && "${NANOTUN_STAMP_SKIP_RC_CHECK:-0}" != "1" ]]; then
  RUNNER_USER="${E2E_RUNNER_USER:-root}"
  RUNNER_DIR="${E2E_RUNNER_DIR:-/root/nte2e}"
  RC_FILE="$RUNNER_DIR/last-run.rc"

  if ! command -v sshpass >/dev/null 2>&1; then
    echo "配了调度机($RUNNER_HOST)却没有 sshpass,核不了上一轮 e2e 的退出码。" >&2
    echo "装上 sshpass,或自己确认后 NANOTUN_STAMP_SKIP_RC_CHECK=1 再跑本脚本:" >&2
    echo "  ssh $RUNNER_USER@$RUNNER_HOST 'cat $RC_FILE'" >&2
    exit 2
  fi

  # 退出码和「这轮有多久以前」一次问回来。
  # 年龄在调度机上用它自己的钟算成一个**时长**,再和本地算出的 commit 时长比 ——
  # 两边各用各的钟量各自的间隔,时钟不同步也不会把结论带偏。
  export SSHPASS="${E2E_RUNNER_PASS:-}"
  probe="$(sshpass -e ssh -o StrictHostKeyChecking=no -o ConnectTimeout=15 \
             "$RUNNER_USER@$RUNNER_HOST" \
             "cat '$RC_FILE' 2>/dev/null | tr -dc '0-9'; echo; \
              m=\$(stat -c %Y '$RC_FILE' 2>/dev/null || echo 0); \
              if [ \"\$m\" = 0 ]; then echo -1; else echo \$(( \$(date +%s) - m )); fi" \
           2>/dev/null)" || {
    echo "连不上调度机 $RUNNER_USER@$RUNNER_HOST,核不了上一轮 e2e 的退出码。" >&2
    echo "网络恢复后重跑;确实要跳过就 NANOTUN_STAMP_SKIP_RC_CHECK=1(你得自己担保那一轮是绿的)。" >&2
    exit 2
  }
  rc="$(printf '%s\n' "$probe" | sed -n 1p)"
  rc_age="$(printf '%s\n' "$probe" | sed -n 2p)"

  if [[ -z "$rc" || "${rc_age:--1}" == "-1" ]]; then
    echo "调度机上没有上一轮 e2e 的退出码($RC_FILE 不存在)。" >&2
    echo "先把门禁跑完再盖戳:./scripts/e2e/run-remote.sh 00 10 20 30 40 50 60 70" >&2
    exit 2
  fi

  if [[ "$rc" != "0" ]]; then
    case "$rc" in
      1) why="有断言失败" ;;
      2) why="环境或配置问题 —— 红绿都不可信,这轮的「全通过」不算数" ;;
      *) why="非正常退出" ;;
    esac
    echo "上一轮 e2e 的退出码是 $rc($why),不能盖戳。" >&2
    echo "日志末尾那句「合计…失败 0」在这种情况下照样是那个样子,别拿它当过了。" >&2
    echo "  完整日志:ssh $RUNNER_USER@$RUNNER_HOST 'less $RUNNER_DIR/last-run.log'" >&2
    exit 2
  fi

  # 绿是绿的,但得是**这个 commit** 的绿。
  # 跑完 e2e 之后又提交了东西,那轮门禁验的就是另一份代码了 —— 这正是脚本开头
  # 那句「盖戳后又 commit 必须重跑」原先只靠自觉的地方。
  # 差几秒也算数,所以不能只按分钟印:两边都不到一分钟时,「0 分钟 vs 0 分钟」
  # 读起来像是脚本算错了,而它其实是对的 —— 顺序错了就是错了,哪怕只差 20 秒。
  ago() { local s=$1; if (( s < 90 )); then echo "$s 秒前"; else echo "$((s/60)) 分钟前"; fi; }

  commit_age=$(( $(date +%s) - $(git log -1 --format=%ct HEAD) ))
  if (( rc_age > commit_age )); then
    echo "顺序反了:最后一轮 e2e 是 $(ago "$rc_age")跑完的,而 HEAD 这个 commit 是 $(ago "$commit_age")的 —— e2e 在前,commit 在后。" >&2
    echo "也就是说门禁验的是改之前的代码,没验过现在要发的这份。先跑门禁再盖戳:" >&2
    echo "  ./scripts/e2e/run-remote.sh 00 10 20 30 40 50 60 70" >&2
    exit 2
  fi
  echo "已核对调度机:上一轮 e2e 退出码 0,$(ago "$rc_age")跑完(晚于 HEAD,验的就是这份代码)。"
fi

sha="$(git rev-parse HEAD)"
short="$(git rev-parse --short HEAD)"
mkdir -p .release
{
  echo "$sha"
  echo "# stamped_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# required_phases=00 10 20 30 40 50 60 70"
  echo "# doc=docs/RELEASE.md"
} > .release/e2e-stamp

echo "已盖戳: HEAD ${short} (${sha})"
echo "下一步: ./scripts/release/cut.sh vX.Y.Z"
