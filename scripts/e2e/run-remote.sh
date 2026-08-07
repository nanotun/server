#!/usr/bin/env bash
# 把三机 e2e 交给「调度机」去跑,而不是在你自己的机器上跑。
#
# ── 为什么要这么一层 ────────────────────────────────────────────────────────
# run.sh 本身不参与被测,它只是个指挥:每做一次检查就 SSH 到三台机器上执行一条命令、
# 把结果收回来判断。所以指挥站在哪儿不影响测什么,只影响每条命令来回一趟要多久 ——
# 而这一趟的次数是四位数级别的。
#
# 2026-08-05 实测(同一 commit,同样 341 项断言全过):
#
#   从开发者的 Mac 跑   2838 秒 = 收敛等待 1188 秒 + 其余 1650 秒
#   从同机房调度机跑     1615 秒 = 收敛等待 1041 秒 + 其余  574 秒
#
# 差的那 20 分钟全在「其余」里,也就是纯网络往返:Mac 到三台机器 RTT 656~1052ms,
# 开着 ControlMaster 复用,一条什么都不干的远程命令仍要 1.56 秒;而调度机到 A/C 是
# 0.4ms、到 SRV 是 66ms。收敛等待那部分几乎纹丝不动,因为那是被测系统自己的速度
# (其中 841 秒是 39 次「等客户端重连」的退避,换谁来指挥都得等)。
#
# ── 它替你守的那条线 ────────────────────────────────────────────────────────
# 发版戳 (scripts/release/stamp-e2e.sh) 钉的是**本地仓库的 HEAD**,而 e2e 现在跑在
# 另一台机器上的另一份 checkout 里。两者一旦不是同一个 commit,就会出现「戳盖在 A,
# e2e 其实跑的是 B」—— 这恰恰是那个戳存在的全部意义,而且事后完全看不出来:戳里只有
# 一个 SHA,不会记录它当时到底验的是什么。
#
# 所以本脚本每次都强制把调度机 checkout 到本地 HEAD,并拒绝在工作树不干净时开跑
# (脏树意味着你手上的改动根本不在调度机那份代码里,跑出来的绿不属于你以为的那份)。
#
# 用法:
#   ./run-remote.sh                # 跑全部阶段
#   ./run-remote.sh 10 50          # 跑指定阶段,参数原样转交 run.sh
#
# e2e.env 里需要多三个变量(见 e2e.env.example):
#   E2E_RUNNER_HOST / E2E_RUNNER_PASS / E2E_RUNNER_DIR
#
# 退出码与 run.sh 一致:0 全通过 / 1 有失败 / 2 环境或配置问题。

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

RUNNER_HOST="${E2E_RUNNER_HOST:-}"
RUNNER_PASS="${E2E_RUNNER_PASS:-}"
RUNNER_DIR="${E2E_RUNNER_DIR:-/root/nte2e}"
RUNNER_USER="${E2E_RUNNER_USER:-${E2E_SSH_USER:-root}}"
[[ -n "$RUNNER_HOST" ]] || die "e2e.env 里没有 E2E_RUNNER_HOST —— 不知道该把这轮交给谁跑"

SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o LogLevel=ERROR -o ConnectTimeout=20 -o ServerAliveInterval=30)

rsh() { # rsh <命令...>:在调度机上执行
  if [[ -n "$RUNNER_PASS" ]]; then
    sshpass -p "$RUNNER_PASS" ssh "${SSH_OPTS[@]}" "$RUNNER_USER@$RUNNER_HOST" "$@"
  else
    ssh "${SSH_OPTS[@]}" "$RUNNER_USER@$RUNNER_HOST" "$@"
  fi
}
rcp() { # rcp <本地文件> <远端路径>
  if [[ -n "$RUNNER_PASS" ]]; then
    sshpass -p "$RUNNER_PASS" scp "${SSH_OPTS[@]}" "$1" "$RUNNER_USER@$RUNNER_HOST:$2"
  else
    scp "${SSH_OPTS[@]}" "$1" "$RUNNER_USER@$RUNNER_HOST:$2"
  fi
}

# ── 1. 本地这份代码到底是哪个 commit ────────────────────────────────────────
step "1. 核对 commit"
cd "$ROOT" || die "进不去仓库根目录 $ROOT"
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || die "不在 git 仓库里"
if [[ -n "$(git status --porcelain)" ]]; then
  printf '%s' "$_R" >&2
  {
    echo "工作树不干净。调度机跑的是**已提交**的那份代码,你手上的改动不在里面 ——"
    echo "跑出来的绿不属于你以为的那份代码,而发版戳又只认 HEAD 的 SHA,事后查不出来。"
    echo "先提交或 stash:"
  } >&2
  printf '%s' "$_N" >&2
  git status --porcelain | head -10 >&2
  exit 2
fi
SHA="$(git rev-parse HEAD)"
ok "本地 HEAD $(git rev-parse --short HEAD) $(git log -1 --pretty=%s | cut -c1-40)"

# ── 2. 调度机准备好没有 ─────────────────────────────────────────────────────
step "2. 调度机 $RUNNER_HOST"
rsh true >/dev/null 2>&1 || die "连不上调度机 $RUNNER_USER@$RUNNER_HOST"

# 依赖缺了要在开跑前说。尤其是 Go:阶段 5 会在调度机上现编 hy2udpprobe,缺了要跑到
# 二十分钟后才报一句 env_error,那时整轮退出码已经是 2,前面的绿全都白跑。
missing="$(rsh 'for b in sshpass python3 curl git go; do command -v $b >/dev/null || printf "%s " "$b"; done')"
[[ -z "${missing// /}" ]] || die "调度机缺依赖: ${missing}(apt install sshpass python3 curl git golang-go)"
ok "依赖齐备"

# 每次都强制对齐到本地 HEAD。用 fetch + reset --hard 而不是 pull:调度机那份 checkout
# 是一次性的执行环境,不该有「本地修改」这种概念,有也一律以本地仓库为准。
if ! rsh "test -d '$RUNNER_DIR/.git'" 2>/dev/null; then
  warn "调度机上还没有仓库,现在克隆到 $RUNNER_DIR"
  rsh "git clone --quiet https://github.com/nanotun/server '$RUNNER_DIR'" \
    || die "克隆失败(私有仓库的话请在调度机上先配好凭据)"
fi
rsh "cd '$RUNNER_DIR' && git fetch --quiet origin && git reset --quiet --hard $SHA && git clean -qfd" \
  || die "调度机对齐到 $SHA 失败 —— 这个 commit 推到 origin 了吗?"

REMOTE_SHA="$(rsh "cd '$RUNNER_DIR' && git rev-parse HEAD" | tr -d '\r')"
[[ "$REMOTE_SHA" == "$SHA" ]] || die "对齐后仍不一致:本地 $SHA,调度机 $REMOTE_SHA"
ok "调度机已对齐到同一个 commit"

# e2e.env 不进 git,只能每次推过去 —— 否则改了机器地址或凭据,调度机还在用旧的,
# 而症状会是一片莫名其妙的连接失败。
rcp "$ENVF" "$RUNNER_DIR/scripts/e2e/e2e.env" >/dev/null 2>&1 \
  || die "推送 e2e.env 失败"
rsh "chmod 600 '$RUNNER_DIR/scripts/e2e/e2e.env'"
ok "e2e.env 已同步(含明文口令,权限 600)"

# ── 3. 开跑 ─────────────────────────────────────────────────────────────────
LOG="${TMPDIR:-/tmp}/nanotun-e2e-$(date +%Y%m%d-%H%M%S).log"
step "3. 在调度机上跑 e2e($# 个参数)"
printf '    日志同时落到 %s\n\n' "$LOG"

START=$(date +%s)

# 这一轮跑在 setsid 里、输出落到调度机本地的文件,我们只是 tail 回来看。
#
# 直接 `ssh … ./run.sh` 看着简单得多,但那样这轮的命运就绑死在这条 SSH 连接上:
# 连接一断(网络抖一下、本地 Ctrl-C、终端被关),run.sh 不会跟着停 —— 它变成孤儿
# 继续跑到底,锁还攥在它手里,而它的 stdout 是一根没人读的管道。于是三件事同时发生:
# 拿不到这轮的结果、起不了新的一轮、只能 ssh 上去手工找 pid 杀掉。
# 2026-08-05 就这么丢过一轮:27 分钟的门禁跑完了,结果一个字都没留下。
#
# 落盘之后这些都不成立:连接断了重连 tail 就接着看,结果永远留在调度机上。
REMOTE_LOG="$RUNNER_DIR/last-run.log"
REMOTE_RC="$RUNNER_DIR/last-run.rc"
REMOTE_PID="$RUNNER_DIR/last-run.pid"

# 开跑前先看锁。run.sh 自己也有单实例锁,但那道锁是在**新一轮已经起来之后**才发现
# 撞车的 —— 而新一轮起来的第一件事就是 `> last-run.log`,把正在跑的那一轮的日志
# 拦腰截断。于是代价不对称:撞车的是新来的,挨刀的是老的。2026-08-06 实测就这样,
# 一轮跑到一半的门禁日志被清空,只剩尾巴。
# 在这里先问一句就都躲开了,顺便告诉人怎么接上那一轮,而不是让他去猜。
LOCKPID="$(rsh "cat /tmp/nanotun-e2e.lock/pid 2>/dev/null" | tr -d '\r[:space:]')"
if [[ "$LOCKPID" =~ ^[0-9]+$ ]] && rsh "kill -0 $LOCKPID 2>/dev/null"; then
  die "调度机上已有一轮 e2e 在跑(pid $LOCKPID),不能再起一轮 —— 两轮会互相踩。
   要看那一轮:ssh $RUNNER_USER@$RUNNER_HOST \"tail -f --pid=$LOCKPID $REMOTE_LOG\"
   跑完后看退出码(**别只看日志末尾那句合计**):
     ssh $RUNNER_USER@$RUNNER_HOST 'cat $REMOTE_RC'
   确认它真死了再:ssh $RUNNER_USER@$RUNNER_HOST 'rm -rf /tmp/nanotun-e2e.lock'"
fi

# 确定要起新一轮了,先把上一轮的退出码作废。
#
# 下面真正起跑那一步也 rm 了它,但那太晚:从这里到那里还要同步 commit、装依赖、传
# e2e.env,任何一步失败(或这个 wrapper 被掐掉)都会退出,而 last-run.rc 里还躺着**上一轮**
# 的 0。之后去调度机上 `cat last-run.rc` 看到的是一个绿色的退出码,配着一份末尾写着
# 「合计 341 项:通过 341」的日志 —— 没有任何迹象表明它属于另一个 commit、另一个小时。
# 2026-08-07 就这么误判了两次:两轮门禁其实压根没起来,而我按上一轮的记录当它们过了。
#
# 作废之后再失败,读到的是「没有退出码」——那是实话,而 stamp-e2e.sh 见到它会直接拒绝盖戳。
rsh "rm -f '$REMOTE_RC'" >/dev/null 2>&1 || true

# 不开 -t:没有伪终端时 assert.sh 自己会关掉颜色,落进日志的就是干净的纯文本。
#
# 几处都不能省:
#  · setsid **-f**:光 `setsid` 在调用者已经是进程组长时不会 fork,于是压根没脱离
#    这条 SSH 会话 —— 连接一关,SIGHUP 照样打到这一轮身上。实测就栽在这:341 条
#    断言全跑完、总结都打出来了,却在 cleanup 里被 SIGHUP 掐死,退出码没写成、锁
#    没清掉,一轮 28 分钟的门禁最后拿不出一个能盖戳的退出码。-f 强制 fork,断不掉。
#  · 三个 fd 全部重定向:留一个连着,sshd 就攥着这条连接不放,本地这条 rsh 一直挂着。
#  · 末尾 exit 0:让远端 shell 立刻收工,别等后台作业。
# setsid -f 自己就立刻返回,不需要再加 &。
rsh "cd '$RUNNER_DIR/scripts/e2e' && rm -f '$REMOTE_RC' '$REMOTE_PID' && \
     nohup setsid -f bash -c 'echo \$\$ > \"$REMOTE_PID\"; ./run.sh $*; echo \$? > \"$REMOTE_RC\"' \
       > '$REMOTE_LOG' 2>&1 < /dev/null; sleep 2; exit 0" >/dev/null 2>&1

RUN_PID="$(rsh "cat '$REMOTE_PID' 2>/dev/null" | tr -d '\r[:space:]')"
[[ "$RUN_PID" =~ ^[0-9]+$ ]] || die "没能在调度机上把 e2e 起来 —— 看看 $REMOTE_LOG"

# --pid:那个进程一结束,tail 自己退出,不用猜要跟多久。
rsh "tail -n +1 -f --pid=$RUN_PID '$REMOTE_LOG'" 2>&1 | tee "$LOG"

# 退出码从文件读,不是从 tail 读 —— tail 成功地跟完了日志,跟这轮红没红是两回事。
RC="$(rsh "cat '$REMOTE_RC' 2>/dev/null" | tr -d '\r[:space:]')"
[[ "$RC" =~ ^[0-9]+$ ]] || RC=2
SECS=$(( $(date +%s) - START ))

printf '\n'
printf '%s耗时 %d 分 %d 秒,退出码 %d%s\n' "$_B" $((SECS/60)) $((SECS%60)) "$RC" "$_N"

case "$RC" in
  0) ok "全部通过。这一轮验的是 $(git rev-parse --short HEAD),与本地 HEAD 一致。"
     printf '\n    要发版就接着盖戳(戳仍然盖在本地,认的就是这个 commit):\n'
     printf '      ./scripts/release/stamp-e2e.sh\n' ;;
  2) warn "退出码 2 = 环境或配置问题,红绿都不可信,别拿这轮去盖戳。" ;;
  *) warn "有断言失败,详见上面或 ${LOG}。" ;;
esac

# 本地这份是 tee 出来的副本,调度机上那份才是原件 —— 中途断线时它照样是全的。
printf '\n    调度机上的原始日志:%s@%s:%s\n' "$RUNNER_USER" "$RUNNER_HOST" "$REMOTE_LOG"
exit "$RC"
