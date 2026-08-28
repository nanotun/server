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
  # 7443 只是**老默认**。2026-08-28 起 Web 后台端口在新装机器上是随机的(装机时挑,落在
  # /etc/nanotun/web.env 的 NANOTUN_WEB_LISTEN)。现役实验室是在那之前装的,所以还在 7443,
  # 这个默认值对它仍然成立。
  #
  # 但重建实验室(或换一台 SRV)之后它就不成立了,而失败长得毫无关联:阶段 60 的每一条都
  # 报「Web 后台连不上」,像是 nanotun-web 挂了,而真因是它听在一个随机端口上。重建之后
  # 记得照着改 e2e.env 的 E2E_WEB_BASE:
  #     ssh root@<SRV> 'grep NANOTUN_WEB_LISTEN /etc/nanotun/web.env'
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

  # 服务端部署形态:systemd(裸机,默认)或 docker(镜像)。docker 模式下服务端的
  # systemctl 调用经 remote/systemctl-docker-shim.sh 翻译到容器,见该文件的语义对照。
  : "${E2E_SRV_MODE:=systemd}"
  : "${E2E_SRV_CONTAINER:=nanotun}"
  case "$E2E_SRV_MODE" in
    systemd|docker) ;;
    *) echo "E2E_SRV_MODE 只能是 systemd 或 docker,当前:$E2E_SRV_MODE" >&2; return 1 ;;
  esac

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

# docker 模式下 systemctl 兼容层在服务端的落点。首次用到时推一次,之后复用。
E2E_SRV_SHIM=/tmp/nte2e-systemctl-shim.sh
_E2E_SHIM_READY=0

_e2e_srv_shim_ensure() {
  [[ "$_E2E_SHIM_READY" == 1 ]] && return 0
  # 这里不能用 s():它自己就在等这个文件,会绕回来。
  push_file s "$E2E_ROOT/remote/systemctl-docker-shim.sh" "$E2E_SRV_SHIM" || return 1
  _E2E_SHIM_READY=1
}

# 三台机器的执行入口。s=服务端,a=普通客户端,c=出口/宣告方客户端。
s() {
  if [[ "${E2E_SRV_MODE:-systemd}" == "docker" ]]; then
    _e2e_srv_shim_ensure || return 1
    # source 不读 stdin,所以 `s "cat > f" < g` 这类带重定向的用法不受影响。
    _e2e_run "$E2E_SRV_HOST" "${E2E_SRV_PASS:-}" \
      "NTE2E_CT='$E2E_SRV_CONTAINER'; . $E2E_SRV_SHIM; $*"
    return $?
  fi
  _e2e_run "$E2E_SRV_HOST" "${E2E_SRV_PASS:-}" "$@"
}
a() { _e2e_run "$E2E_A_HOST"   "${E2E_A_PASS:-}"   "$@"; }
c() { _e2e_run "$E2E_C_HOST"   "${E2E_C_PASS:-}"   "$@"; }

# srv_in_svc <命令> 在 **nanotund 所在的那个文件系统** 里跑命令:systemd 模式下就是
# 宿主,docker 模式下是容器内部。
#
# 探测「服务端有没有装某个工具」这类前置条件必须走它,不能直接用 s():镜像自带的
# ipset / iptables 宿主上未必有,反之亦然。2026-08-02 实测,跳板机防火墙那组就是因为
# 在宿主上探到「没装 ipset」而在容器里其实装了,断言期望与实际条件对不上。
srv_in_svc() {
  if [[ "${E2E_SRV_MODE:-systemd}" == "docker" ]]; then
    s "docker exec $E2E_SRV_CONTAINER sh -c \"$*\""
    return $?
  fi
  s "$*"
}

# push_file <s|a|c> <本地路径> <远端路径> 把文件推到指定机器。
#
# 已有的 `s "cat > f" < g` 那个写法只适合小文本:它把整个文件塞进 ssh 的 stdin,而
# _e2e_run 会把 stdout 收进变量 —— 传二进制时既慢又容易被中间环节掺进东西。需要传
# 可执行文件(比如 remote/hy2udpprobe)时用这个,走 scp。
push_file() {
  local who="$1" src="$2" dst="$3"
  local host pass
  case "$who" in
    s) host="$E2E_SRV_HOST"; pass="${E2E_SRV_PASS:-}" ;;
    a) host="$E2E_A_HOST";   pass="${E2E_A_PASS:-}"   ;;
    c) host="$E2E_C_HOST";   pass="${E2E_C_PASS:-}"   ;;
    *) echo "push_file: 未知目标 $who" >&2; return 2 ;;
  esac
  local -a opts
  mapfile -t opts < <(_e2e_ssh_opts)
  local attempt rc
  for attempt in 1 2 3; do
    if [[ -n "$pass" ]]; then
      sshpass -p "$pass" scp "${opts[@]}" "$src" "$E2E_SSH_USER@$host:$dst" >/dev/null 2>&1; rc=$?
    else
      scp "${opts[@]}" "$src" "$E2E_SSH_USER@$host:$dst" >/dev/null 2>&1; rc=$?
    fi
    (( rc == 0 )) && return 0
    sleep $(( attempt * 5 ))
  done
  return "$rc"
}

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
