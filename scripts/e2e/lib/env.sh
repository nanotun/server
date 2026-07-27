#!/usr/bin/env bash
# 三机 e2e 的配置装载与远程执行层。
#
# 为什么要 ControlMaster:手工回归阶段每个断言都新开一条 ssh,跑到后面必然撞上
# sshd 的 MaxStartups / 认证限速,表现为随机的「Permission denied」——那不是被测
# 系统的问题,但会把一次回归打断在中途,还容易被误读成登录路径出了 bug。
# 复用一条主连接后,后续都是 channel 复用,既没有认证开销也不会触发限速。

set -uo pipefail

E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export E2E_ROOT

# ── 配置装载 ────────────────────────────────────────────────────────────────
# 口令/主机不进仓库:优先读 E2E_ENV 指定的文件,否则读 scripts/e2e/e2e.env。
e2e_load_env() {
  local f="${E2E_ENV:-$E2E_ROOT/e2e.env}"
  if [[ -f "$f" ]]; then
    # shellcheck disable=SC1090
    source "$f"
  elif [[ -z "${E2E_SRV_HOST:-}" ]]; then
    echo "缺少配置:$f 不存在,且未通过环境变量提供 E2E_SRV_HOST 等参数。" >&2
    echo "请复制 $E2E_ROOT/e2e.env.example 为 $f 后填写。" >&2
    return 1
  fi

  : "${E2E_SRV_HOST:?必须设置 E2E_SRV_HOST}"
  : "${E2E_A_HOST:?必须设置 E2E_A_HOST(普通客户端)}"
  : "${E2E_C_HOST:?必须设置 E2E_C_HOST(出口节点 + 子网宣告方)}"

  : "${E2E_SSH_USER:=root}"
  : "${E2E_DB_PATH:=/var/lib/nanotun/nanotun.db}"
  : "${E2E_WEB_BASE:=https://127.0.0.1:7443}"

  # 被测拓扑里的固定身份。这些值必须和 e2e.env 里描述的环境一致,
  # 阶段脚本只认这几个变量,不再散落硬编码。
  : "${E2E_A_USER:=testcli}"          # A 所属的 VPN 用户名
  : "${E2E_C_USER:=u4}"               # C 所属的 VPN 用户名
  : "${E2E_A_VIP4:=10.201.0.77}"
  : "${E2E_C_VIP4:=10.201.0.3}"
  : "${E2E_C_VIP6:=fd00:200::4}"
  : "${E2E_C_LAN4:=192.168.88.0/24}"  # C 身后宣告的 IPv4 私网
  : "${E2E_C_LAN4_HOST:=192.168.88.1}"
  : "${E2E_C_LAN6:=fd77:88::/64}"
  : "${E2E_C_LAN6_HOST:=fd77:88::1}"
  : "${E2E_TARGET_PORT:=8088}"        # 靶站端口,须在 C 的 ufw 放行名单里
  : "${E2E_MAGIC_SUFFIX:=lan}"

  return 0
}

# ── SSH 复用 ────────────────────────────────────────────────────────────────
E2E_SSH_CTL=""

e2e_ssh_init() {
  # ControlPath 是 Unix socket,路径超过 ~104 字节会直接 bind 失败,
  # 因此固定放在 /tmp 下的短目录里,不要跟着仓库路径走。
  E2E_SSH_CTL="$(mktemp -d /tmp/nte2e.XXXXXX)"
  export E2E_SSH_CTL
}

e2e_ssh_cleanup() {
  [[ -n "$E2E_SSH_CTL" ]] || return 0
  local sock
  for sock in "$E2E_SSH_CTL"/*; do
    [[ -S "$sock" ]] || continue
    ssh -O exit -o ControlPath="$sock" placeholder >/dev/null 2>&1 || true
  done
  rm -rf "$E2E_SSH_CTL"
}

_e2e_ssh_opts() {
  printf '%s\n' \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR \
    -o ConnectTimeout=15 \
    -o ServerAliveInterval=15 \
    -o ControlMaster=auto \
    -o ControlPath="$E2E_SSH_CTL/%r@%h:%p" \
    -o ControlPersist=300
}

# _e2e_run <host> <password-or-empty> <command...>
#
# 两件事必须同时做到,而且互相冲突,所以不能图省事写成一条管道:
#   1. 保留远端 stderr —— nanotun-admin 的告警(比如「钉的 vIP 登录路径用不上」)
#      只走 stderr,统一 2>/dev/null 会把「命令已经报警了」误判成「静默失败」;
#   2. 透传远端退出码 —— 大量探针是「命令成功与否」而不是「输出是什么」。
# 直接 `ssh ... | grep -v` 会让退出码变成 grep 的:凡是没有输出的远程命令,
# grep 都因「没匹配到行」返回 1,于是每一个安静成功的命令都被判成失败。
# 因此先把输出收进变量、单独存下 rc,再过滤噪声。
_e2e_run() {
  local host="$1" pass="$2"; shift 2
  local -a opts
  mapfile -t opts < <(_e2e_ssh_opts)
  local out rc attempt
  # rc=255 是 ssh 自身失败(连不上/认证被限速),此时远端命令**根本没有执行**,
  # 重试是安全的。这类抖动跟被测系统无关,却会让整轮结果不可信 ——
  # 之前手工回归就多次被随机的「Permission denied」打断在半途。
  for attempt in 1 2 3; do
    if [[ -n "$pass" ]]; then
      out="$(sshpass -p "$pass" ssh "${opts[@]}" "$E2E_SSH_USER@$host" "$@" 2>&1)"; rc=$?
    else
      out="$(ssh "${opts[@]}" "$E2E_SSH_USER@$host" "$@" 2>&1)"; rc=$?
    fi
    (( rc == 255 )) || break
    sleep $(( attempt * 5 ))
  done
  out="$(printf '%s\n' "$out" | grep -v '^Warning: Permanently added')"
  [[ -n "$out" ]] && printf '%s\n' "$out"
  return "$rc"
}

# 开跑前先把三条主连接建起来。后续所有命令都复用它们,既避开认证限速,
# 也让「连不上」这种环境问题在第一时间暴露,而不是伪装成某条断言失败。
e2e_ssh_warmup() {
  local ok=0 name runner
  for name in SRV:s A:a C:c; do
    runner="${name#*:}"
    if "$runner" true >/dev/null 2>&1; then
      ok=$((ok + 1))
    else
      echo "无法连接到 ${name%%:*}(${runner})" >&2
    fi
  done
  (( ok == 3 ))
}

# 三台机器的执行入口。s=服务端,a=普通客户端,c=出口/宣告方客户端。
s() { _e2e_run "$E2E_SRV_HOST" "${E2E_SRV_PASS:-}" "$@"; }
a() { _e2e_run "$E2E_A_HOST"   "${E2E_A_PASS:-}"   "$@"; }
c() { _e2e_run "$E2E_C_HOST"   "${E2E_C_PASS:-}"   "$@"; }

# 断言「命令应当失败」时取真实退出码。用法:rc_of adm 'lease set ...'
rc_of() {
  local runner="$1"; shift
  "$runner" "$@" >/dev/null 2>&1
  echo $?
}

# nanotun-admin 统一带 --db-path,否则读命令会跑到 ./data/nanotun.db 上去,
# 看到的是一个空库却不报错。
adm() { s "nanotun-admin --db-path $E2E_DB_PATH $*"; }

# adm 的 stdin 喂 y:带确认提示的破坏性子命令(route delete / kick / vacuum ...)。
adm_y() { s "echo y | nanotun-admin --db-path $E2E_DB_PATH $*"; }

# 服务端运行时状态的 JSON,阶段脚本用 jq_field 取字段。
srv_status_json() { adm "connection list --json"; }

# jq 不一定装,统一用 python3 取字段,支持 a.b 形式的点路径。
jq_field() {
  local path="$1"
  python3 -c '
import json,sys
d=json.load(sys.stdin)
for k in sys.argv[1].split("."):
    d=d[k]
print(d)
' "$path"
}

srv_field() { srv_status_json | jq_field "$1"; }
