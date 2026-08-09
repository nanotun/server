#!/usr/bin/env bash
# scale-proc.sh —— 在 **SRV 本机** 采一次 nanotund 进程资源,打一行「rss_kB threads fds」。
#
# 规模测试真正要盯的是这三条随会话数怎么走:RSS(每会话内存)、Threads(会话是不是
# 被摊成 OS 线程)、FD(每条链路一个 socket)。取不到的字段回 "?"。
PID=$(systemctl show nanotun -p MainPID --value 2>/dev/null)
rss=$(awk '/VmRSS/{print $2}' /proc/"$PID"/status 2>/dev/null)
thr=$(awk '/Threads/{print $2}' /proc/"$PID"/status 2>/dev/null)
fds=$(ls /proc/"$PID"/fd 2>/dev/null | wc -l | tr -d '[:space:]')
echo "${rss:-?} ${thr:-?} ${fds:-?}"
