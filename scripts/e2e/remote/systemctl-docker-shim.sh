#!/usr/bin/env bash
# e2e 专用:把打在 nanotun / nanotun-web 上的 systemctl 动作翻译到 Docker 容器。
#
# E2E_SRV_MODE=docker 时由 s() 自动 source 到每条服务端命令前面。单元名不是这两个的
# 一律原样交给真 systemctl —— 客户端那几个 unit(nte2e-target / nt-p*)不在这台机器上,
# 但宿主自己的 unit 仍可能被顺带查到。
#
# 为什么用 shim 而不是改那 40 个调用点:阶段脚本里大量是
# `python3 tomlset.py ... && systemctl restart nanotun` 这种一条 SSH 里的复合命令,
# 逐个拆开既啰嗦又容易改错;而真正要翻译的动作总共只有 8 种。
#
# 语义对照(左 = systemd 单元,右 = 容器):
#
#   is-active nanotun       容器在跑 **且** 里面 nanotund 活着
#   is-active nanotun-web   容器里 nanotun-web 活着
#   reload nanotun          SIGHUP 给 nanotund(= unit 里的 ExecReload)
#   stop / start nanotun    docker stop / docker start
#   show ... MainPID        nanotund 的**宿主侧** pid —— 阶段 7 要从宿主 kill -9 它
#   show ... ExecMainStatus 容器上次退出码
#
#   restart nanotun         重启整个容器。这一条**与 systemd 不等价**:镜像是单容器设计,
#                           nanotund 和 nanotun-web 由同一个 entrypoint 守护,没法只重启
#                           数据面。systemd 下 `restart nanotun` 不动 web,这里会一起重启。
#                           落到断言上的影响:重启后 web 会话要重新登录 —— 阶段 6 每次都
#                           自己登录,所以不受影响。

NTE2E_CT="${NTE2E_CT:-nanotun}"

_nte2e_ct_running() {
  [[ "$(docker inspect -f '{{.State.Running}}' "$NTE2E_CT" 2>/dev/null)" == "true" ]]
}

# docker top 打的是**宿主** pid(它在宿主上对容器进程跑 ps),正好是阶段 7 需要的那个:
# 容器默认独立 PID namespace,容器内的 pid 从宿主 kill 不到。
_nte2e_pid_of() {
  docker top "$NTE2E_CT" -eo pid,comm 2>/dev/null | awk -v c="$1" '$2==c{print $1; exit}'
}

# 等两个进程都回来。等不到也返回 0:调用方(restart/start)的语义是「命令下达成功」,
# 起不来该由后面的 is-active 断言指名道姓地报,不该在这里变成一个没有出处的非零。
_nte2e_wait_ready() {
  local i
  for i in $(seq 1 60); do
    # 光有进程不算就绪:nanotund 起进程之后还要建 TUN、落 iptables、开监听,
    # 控制面能应答才说明它真的在服务了(systemd 那边由 Type=notify 保证的语义)。
    if [[ -n "$(_nte2e_pid_of nanotund)" && -n "$(_nte2e_pid_of nanotun-web)" ]] \
       && nanotun-admin --db-path /var/lib/nanotun/nanotun.db connection list >/dev/null 2>&1; then
      return 0
    fi
    # nanotund 起不来时 entrypoint 会让整个容器退出,再等下去没有意义。
    _nte2e_ct_running || return 0
    sleep 1
  done
  return 0
}

systemctl() {
  local verb="${1:-}" unit="" tok
  for tok in "$@"; do
    case "$tok" in nanotun|nanotun-web) unit="$tok"; break ;; esac
  done
  if [[ -z "$unit" ]]; then
    command systemctl "$@"
    return $?
  fi

  case "$verb" in
    is-active)
      local proc=nanotund
      [[ "$unit" == "nanotun-web" ]] && proc=nanotun-web
      if _nte2e_ct_running && [[ -n "$(_nte2e_pid_of "$proc")" ]]; then
        echo active
        return 0
      fi
      # 容器在跑但进程不在 = 守护进程正在拉起它的那个窗口,报 activating;
      # 容器整个不在 = inactive。两者都不是 active,断言侧一视同仁。
      if _nte2e_ct_running; then echo activating; else echo inactive; fi
      return 3
      ;;
    # restart/start 要等到 web 也重新监听才返回,否则紧跟着打管理面的断言会撞上
    # 「nanotund 起来了、web 还没起」那个窗口 —— entrypoint 是等控制面 socket 出现
    # 之后才拉 web 的,这个窗口有好几秒。systemd 下 restart nanotun 根本不碰 web,
    # 调用方普遍假设 web 一直在,这里把那个假设补回来。
    restart) docker restart "$NTE2E_CT" >/dev/null || return $?; _nte2e_wait_ready ;;
    start)   docker start   "$NTE2E_CT" >/dev/null || return $?; _nte2e_wait_ready ;;
    stop)    docker stop    "$NTE2E_CT" >/dev/null; return $? ;;
    reload)  docker exec "$NTE2E_CT" pkill -HUP -x nanotund >/dev/null 2>&1; return $? ;;
    show)
      case "$*" in
        *MainPID*)        _nte2e_pid_of nanotund; return 0 ;;
        *ExecMainStatus*) docker inspect -f '{{.State.ExitCode}}' "$NTE2E_CT" 2>/dev/null; return 0 ;;
      esac
      command systemctl "$@"
      return $?
      ;;
    *) command systemctl "$@"; return $? ;;
  esac
}

# journalctl -u nanotun ... → docker logs。容器的日志在 Docker 的 json-file 里,
# journald 那边一条都没有(现象是断言拿到 "-- No entries --" 而不是报错)。
#
# 两个必须处理的差异:
#   * nanotund/nanotun-web 走 stderr 输出,而调用方普遍写成 `journalctl ... | grep`。
#     不 2>&1 的话管道里是空的 —— 于是每条日志断言都变成「日志里没有这句」。
#   * --since 的时间格式:journalctl 收 @<epoch> 和 -60s,docker 要 <epoch> 和 60s。
journalctl() {
  local unit="" since="" tok prev=""
  for tok in "$@"; do
    case "$prev" in
      -u|--unit)  unit="$tok" ;;
      --since|-S) since="$tok" ;;
    esac
    prev="$tok"
  done
  if [[ "$unit" != "nanotun" && "$unit" != "nanotun-web" ]]; then
    command journalctl "$@"
    return $?
  fi
  local -a args=(logs)
  if [[ -n "$since" ]]; then
    args+=(--since "${since#[@-]}")
  fi
  docker "${args[@]}" "$NTE2E_CT" 2>&1
}
