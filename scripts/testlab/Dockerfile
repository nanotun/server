# 一台「假 VPS」:带 systemd 的干净 Linux,用来把裸机安装脚本从头跑一遍。
#
# 为什么需要它:install.sh / install-self-hosted.sh 里最要紧的那些分支 —— 空的
# /etc/nanotun 从零落地、第一次 nanotun-admin init 出管理员凭据、config 模板占位
# 填充、卸载后重装 —— 只有在**全新机器**上才走得到。在已经装好的真机上验这些,
# 得先把 /etc/nanotun 和 /var/lib/nanotun 整个 tar 走再还原,一次几十分钟,且中途
# 手一抖就是真事故。容器装坏了 docker rm 就完了。
#
# 这**不是**产品的容器化分发路径 —— 那是仓库根的 Dockerfile 和 docker/ 目录,
# 跑的是 docker/entrypoint.sh。这里的容器扮演的是「一台刚开机的 VPS」,里面跑的
# 是给裸机用的那套安装脚本,两条路完全不同,别混。
#
# 预装的东西刻意贴近真实 VPS 的出厂状态:systemd + iproute2 + iptables + curl +
# openssl。多装会掩盖 preflight 本该报出来的缺包,少装则不像真机。

ARG BASE=ubuntu:26.04
FROM ${BASE}

# 一份 Dockerfile 覆盖四个发行版:Ubuntu / Debian 走 apt,Rocky 走 dnf,Alpine 走 apk。
#
# Alpine 这里**故意不补 systemd**(它本来就用 OpenRC,也装不上)。那正是要看的东西:
# preflight 应当明确报「这台机器没有 systemd,装不了」,而不是让人装到一半才在
# systemctl 那一行炸掉 —— 报错离原因太远,是这类脚本最贵的失败形态。
RUN set -eux; \
    if command -v apt-get >/dev/null 2>&1; then \
      export DEBIAN_FRONTEND=noninteractive; \
      apt-get update; \
      # 不补 procps:debian:13 官方最小镜像本来就不带它,于是这台机器天然是
      # 「缺 sysctl」这条路的现成样本 —— 正好用来验 preflight 给的包名对不对
      # (它该说 procps,而不是 RHEL 的 procps-ng)。ubuntu 的镜像自带,不受影响。
      apt-get install -y --no-install-recommends \
        systemd systemd-sysv dbus ca-certificates curl iproute2 iptables openssl; \
      rm -rf /var/lib/apt/lists/*; \
    elif command -v dnf >/dev/null 2>&1 || command -v microdnf >/dev/null 2>&1; then \
      if command -v dnf >/dev/null 2>&1; then PM=dnf; else PM=microdnf; fi; \
      # 这里刻意不写 curl 和 ca-certificates:RHEL 9 预装的是 curl-minimal,它与
      # curl 互斥,显式装 curl 会让整条 dnf 直接失败(conflicting requests)。
      # 包名也与 Debian 系不同:iproute(不是 iproute2)、procps-ng(不是 procps)。
      "$PM" -y install systemd iproute openssl procps-ng; \
      # 包名在 RHEL 8/9 之间变过:9 里 nft 后端单独叫 iptables-nft,8 里就叫 iptables
      # (那时 nft 已经是默认后端)。写死任一个,另一边的镜像就构建不出来 —— 而我们
      # 恰恰要用 Rocky 8 去验最低支持版本那句话。
      "$PM" -y install iptables-nft || "$PM" -y install iptables; \
      "$PM" clean all || true; \
    elif command -v apk >/dev/null 2>&1; then \
      apk add --no-cache bash ca-certificates curl iproute2 iptables openssl; \
    else \
      echo "未知发行版:没有 apt / dnf / apk" >&2; exit 1; \
    fi

# 屏蔽几个在容器里永远完不成的 getty:老 systemd(Ubuntu 20.04 的 245 实测)会为
# serial-getty@hvc0 去等一个 dev-hvc0.device,而容器里没有这个设备,那个 job 就一直
# "running",multi-user.target 跟着停在 waiting —— systemctl is-system-running 永远
# 停在 starting,开机检测就此超时。新版本上没这个现象,但屏蔽掉也无害。
#
# 用 ln 而不是 systemctl mask:构建时没有在跑的 systemd,mask 会因为连不上总线而报错。
RUN if [ -d /etc/systemd ]; then \
      mkdir -p /etc/systemd/system; \
      for u in serial-getty@hvc0.service getty@tty1.service console-getty.service; do \
        ln -sf /dev/null "/etc/systemd/system/$u"; \
      done; \
    fi

# systemd 只认 SIGRTMIN+3 是「关机」,默认的 SIGTERM 它当没看见,docker stop 会一直
# 等到超时再 SIGKILL —— 那样每次 down 都要多等十秒,且是不干净的断电式关机。
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
