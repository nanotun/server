#!/usr/bin/env bash
# nanotun 容器入口:顶替 systemd 做三件事 —— 起飞前自检、首次初始化、进程守护。
#
# 为什么需要它而不是直接 ENTRYPOINT ["nanotund"]:
#   * systemd 那套里,RuntimeDirectory 建 /run/nanotun、tun-setup.service 清理旧版残留的
#     TUN、install-self-hosted.sh 填密钥自签证书、两个 unit 各自守护。容器里这些全没了,
#     缺一样都是启动即死或者跑起来功能残缺 —— 所以这里一件件补上,包括调用镜像里那份
#     nanotun-tun-setup.sh(与裸机同一个脚本,不另抄一份)。
#   * nanotund 对 ip_forward / TUN 失败的处理是 FatalExit(exit 60),容器只会看到
#     "restarting" 循环。与其让人去翻日志,不如在起飞前把话说清楚。
#
# 环境变量(都有合理默认,不设也能跑):
#   NANOTUN_WEB_ENABLED=1        是否同时起 Web 管理面(0 = 只跑数据面)
#   NANOTUN_WEB_LISTEN=0.0.0.0:7443
#   NANOTUN_WEB_PORT=            NANOTUN_WEB_LISTEN 的简写,只给端口(裸机那边用的就是这个
#                                名字)。两个都给时以 NANOTUN_WEB_LISTEN 为准 —— 它更具体
#                                (能指定绑哪个地址)。
#   NANOTUN_WEB_EXTRA_SANS=      Web 自签证书额外 SAN,逗号分隔,如 vpn.example.com
#   NANOTUN_WEB_TRUSTED_PROXIES= 可信反代 IP/CIDR;放在 nginx 后面时必须设,否则按 IP
#                                限流会因为看到的全是反代地址而失效
#   NANOTUN_SKIP_INIT=0          跳过 nanotun-admin init(数据卷已有库时无副作用,
#                                init 本身幂等,这个开关只为特殊排查场景保留)
#   NANOTUN_FORCE_CONFIG=0       用镜像里的模板覆盖已有 config.toml(原文件会备份)
#   NANOTUN_MAGIC_SUFFIX=        MagicDNS 局域网后缀(客户端解析 *.<后缀> → mesh 虚拟 IP),
#                                默认取模板里的值(现为 nanotun)。只在**首次生成 config.toml**
#                                时生效(数据卷已有配置时不动,改法见下面 apply_magic_suffix 注释)。
#   NANOTUN_REALITY_PORT=        REALITY 的 TCP 端口,默认取模板里的值(现为 443)。宿主上 443
#                                已经被占时用它换一个。同样只在**首次生成 config.toml**时生效。
#                                与裸机的 --reality-port 同名同义(scripts/install.sh)。
#   NANOTUN_LANG=en              日志语言 en|zh,默认英文。也会传给 nanotun-admin /
#                                nanotun-web / nanotun-ensure-assets.sh,并落盘到
#                                $ETC_DIR/lang,所以 docker exec 进来敲 nanotun-admin
#                                不必再设一遍。
set -euo pipefail

ETC_DIR=/etc/nanotun
LIB_DIR=/var/lib/nanotun
RUN_DIR=/run/nanotun
CFG="$ETC_DIR/config.toml"
DIST_CFG=/usr/share/nanotun/config.toml.dist

# ── 语言 ─────────────────────────────────────────────────────────────────────
# 默认英文。优先级:NANOTUN_LANG > $ETC_DIR/lang(上次启动落下的)> en。
#
# 没有 --lang:本脚本的位置参数是「逃生阀」(传了就当普通命令 exec 掉,见 main),
# 加一个同名 flag 会跟那条路打架。容器里配环境变量本来就是常规做法。
#
# 与裸机安装链(scripts/install.sh 那套)同一个变量、同一套优先级 —— 两条入口的
# 语言开关不该有两种名字。
NT_LANG=en
nt_lang_normalize() {
  case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')" in
    en|en[-_]*|english)      printf 'en' ;;
    zh|zh[-_]*|chinese|cn)   printf 'zh' ;;
    *)                       printf '' ;;
  esac
}
if [[ -n "$(nt_lang_normalize "${NANOTUN_LANG:-}")" ]]; then
  NT_LANG="$(nt_lang_normalize "$NANOTUN_LANG")"
elif [[ -r "$ETC_DIR/lang" ]] && \
     [[ -n "$(nt_lang_normalize "$(head -1 "$ETC_DIR/lang" 2>/dev/null)")" ]]; then
  NT_LANG="$(nt_lang_normalize "$(head -1 "$ETC_DIR/lang" 2>/dev/null)")"
fi
# 往下传:nanotund / nanotun-web / nanotun-admin / nanotun-ensure-assets.sh 都认它。
export NANOTUN_LANG="$NT_LANG"

# tsel <英文> <中文> —— 按当前语言选一份。文案两种语言并排写在调用处,理由见
# scripts/install.sh 里同名那节。
tsel() { if [[ "$NT_LANG" == zh ]]; then printf '%s' "$2"; else printf '%s' "$1"; fi; }

log()  { printf '\033[1;36m[entrypoint]\033[0m %s\n' "$*" >&2; }
ok()   { printf '\033[1;32m[entrypoint]\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[1;33m[entrypoint]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[entrypoint] FATAL: %s\033[0m\n' "$*" >&2; exit 1; }

# 双语版本:英文在前、中文在后,与 tsel 同序。
log_t()  { log  "$(tsel "$1" "$2")"; }
ok_t()   { ok   "$(tsel "$1" "$2")"; }
warn_t() { warn "$(tsel "$1" "$2")"; }
die_t()  { die  "$(tsel "$1" "$2")"; }

# die_with_code <码> <说明>:把 nanotund 的退出码原样当成**容器的**退出码。
#
# nanotund 用语义化 code 区分死因(10 配置解析 / 11 配置语义 / 20 TLS 证书 / 60 网络配置),
# systemd 那边靠它做 RestartPreventExitStatus。早先这里一律 exit 1,于是
# `docker inspect -f '{{.State.ExitCode}}'` 永远是 1 ——「配置写错了」和「崩了」在
# **机器可读的那个通道**上无从区分,只剩日志里一行字。运维脚本、编排系统、告警规则
# 看的都是退出码。
#
# rc=0 是另一回事:没人要求关停,它却干净退了,这不是成功。给它 1,别让
# `docker ps` 显示成 "Exited (0)" —— 那看着像一次正常收工。
die_with_code() {
  local rc="$1"; shift
  (( rc == 0 )) && { printf '\033[1;31m[entrypoint] FATAL: %s\033[0m\n' \
    "$(tsel "nanotund exited with status 0 without being asked to stop; the container exits too" \
            "nanotund 未被要求停止却以 exit 0 退出,容器一并退出")" >&2; exit 1; }
  printf '\033[1;31m[entrypoint] FATAL: %s%s\033[0m\n' "$*" \
    "$(tsel " (the container reuses its exit code)" "(容器退出码沿用它)")" >&2
  exit "$rc"
}

# ─────────────────────────────────────────────────────────────────────────────
# 1. 起飞前自检
#
# 这一节的每一条都对应一种「容器起得来、功能却是坏的」形态。宁可在这里拒绝启动,
# 也不要让运维对着一个反复重启的容器猜原因。
# ─────────────────────────────────────────────────────────────────────────────
preflight() {
  # TUN 字符设备。没有它 tun.CreateTUN 直接失败,nanotund 以 exit 60 结束。
  if [[ ! -c /dev/net/tun ]]; then
    die_t "/dev/net/tun does not exist. The container needs this device mapped in explicitly:
       docker run --device /dev/net/tun ...
     in compose that is devices: [\"/dev/net/tun:/dev/net/tun\"]
     If the host has no /dev/net/tun either, run modprobe tun there first." \
          "/dev/net/tun 不存在。容器需要显式挂这个设备:
       docker run --device /dev/net/tun ...
     compose 里是 devices: [\"/dev/net/tun:/dev/net/tun\"]
     宿主上若连 /dev/net/tun 都没有,先 modprobe tun。"
  fi

  # CAP_NET_ADMIN(第 12 位)。创建 TUN、写 iptables、清 conntrack 都要它。
  # 直接读 CapEff 判定,而不是拿 `ip link add` 去试 —— host 网络模式下那种试探
  # 会真的在宿主网络栈里留下痕迹。
  local capeff
  capeff="$(awk '/^CapEff:/{print $2}' /proc/self/status 2>/dev/null || echo 0)"
  if (( ( 0x${capeff} >> 12 ) & 1 )); then
    :
  else
    die_t "CAP_NET_ADMIN is missing (CapEff=${capeff}). Add it:
       docker run --cap-add NET_ADMIN ...
     in compose that is cap_add: [NET_ADMIN]" \
          "缺少 CAP_NET_ADMIN(CapEff=${capeff})。加上:
       docker run --cap-add NET_ADMIN ...
     compose 里是 cap_add: [NET_ADMIN]"
  fi

  # IPv4 转发。nanotund 起 iptables 之前会 sysctl -w,失败即 FatalExit(exit 60)。
  # 容器默认 /proc/sys 只读,所以这里分三种情况说清楚该怎么办。
  local fwd
  fwd="$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)"
  if [[ "$fwd" != "1" ]]; then
    if sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1; then
      ok_t "net.ipv4.ip_forward=1 is now on" "已开启 net.ipv4.ip_forward=1"
    else
      die_t "net.ipv4.ip_forward=0 and it cannot be written, so nanotund would exit 60. Pick one:
       * host network mode: set it on the **host** — sysctl -w net.ipv4.ip_forward=1
         (to persist: echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-nanotun.conf && sysctl --system)
         In host mode Docker rejects --sysctl net.*, so the host is the only place.
       * bridge network mode: add sysctls: {net.ipv4.ip_forward: \"1\"} to compose" \
            "net.ipv4.ip_forward=0 且写不进去,nanotund 会以 exit 60 退出。二选一:
       * host 网络模式:在**宿主**上设 —— sysctl -w net.ipv4.ip_forward=1
         (持久化:echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-nanotun.conf && sysctl --system)
         host 模式下 Docker 不接受 --sysctl net.*,只能在宿主设。
       * bridge 网络模式:compose 里加 sysctls: {net.ipv4.ip_forward: \"1\"}"
    fi
  fi

  # iptables 后端只做记录,不拦。宿主与容器后端不一致时规则会写进内核里**另一张表**,
  # 现象是「命令成功、规则却不生效」—— 留一行日志,事后排查时能第一眼看到。
  local backend
  backend="$(iptables --version 2>/dev/null || echo unknown)"
  log "iptables: ${backend}$(tsel " (if the host uses the legacy backend, see docs/DOCKER.md on switching)" "(宿主若是 legacy 后端,见 docs/DOCKER.md 切换说明)")"

  # 这几个是 best-effort:容器里 /proc/sys 常只读,失败不影响主链路,
  # nanotund 内部同样按 best-effort 处理。
  sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
  # nanotun-web 保存 server_dial_host 时会做 unprivileged ICMP 探测,没这个只能勾"跳过检测"。
  sysctl -w net.ipv4.ping_group_range="0 2147483647" >/dev/null 2>&1 || true

  # 清理老版本(v0.1.14 及之前)留下的 persist TUN。裸机那边由 tun-setup.service 做,
  # 容器里没有 systemd,所以在这儿调同一个脚本 —— 不另抄一份逻辑。
  #
  # 为什么容器也需要:network_mode: host(官方 compose 用的就是它)下容器与宿主共用
  # netns,那些残留就在眼前。它们是 persist on 的,各占一个常见私网段(10.0.x.1 /
  # 192.168.10x.1 / 172.1x.0.1),轻则挡住宿主路由,重则和 nanotund 要建的 tun0 撞名,
  # 让它 exit 60 反复重启。而现象(容器 healthy 或反复重启、宿主出不了网)完全指不到
  # 「几个月前那次裸机安装留下的空网卡」上。
  #
  # 桥接模式下容器有自己的 netns,脚本什么也找不到,是个无害的空转。
  # 删除判据由脚本自己把关(名字 tun0–14 + 类型是 tun + persist on + 地址正好是老脚本
  # 分的那一个,四项全中才动手),所以不会误伤正在服务的网卡 —— nanotund 建的永远是
  # persist off。
  if [[ -x /usr/local/bin/nanotun-tun-setup.sh ]]; then
    NANOTUN_LANG="$NT_LANG" /usr/local/bin/nanotun-tun-setup.sh || warn_t \
      "the TUN pre-start script exited non-zero; if this host once had a bare-metal install, check for leftovers: ip -d link show type tun" \
      "TUN 预处理脚本非零退出;这台机器若装过裸机版,自己看一眼残留:ip -d link show type tun"
  else
    warn_t "/usr/local/bin/nanotun-tun-setup.sh is missing or not executable, so stale TUN devices left by an older bare-metal install are not cleaned up" \
           "/usr/local/bin/nanotun-tun-setup.sh 不存在或没有执行位,旧版裸机安装留下的 TUN 残留不会被清理"
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
# 2. 目录与首次初始化
# ─────────────────────────────────────────────────────────────────────────────

# gen_x25519_priv:32 字节 X25519 私钥,RawURL Base64 无 padding —— [reality].private_key 的格式。
# 与 scripts/install-self-hosted.sh 同款实现(PKCS8 DER 尾部 32 字节即裸私钥)。
gen_x25519_priv() {
  openssl genpkey -algorithm X25519 -outform DER \
    | tail -c 32 | openssl base64 -A | tr '+/' '-_' | tr -d '='
}

# fill_config_secrets:把模板里的 REPLACE_WITH_* 占位与文档示例值换成本机随机值。
# 只替换**仍是占位**的项,所以幂等 —— 重复启动不会重签已生效的密钥(那等于把所有
# 现有客户端一次性踢下线)。非法的 [reality].private_key 会让 nanotund 直接 exit 31,
# 所以这一步必须在启动之前完成。
fill_config_secrets() {
  local filled=0
  if grep -q 'REPLACE_WITH_YOUR_RANDOM_TOKEN' "$CFG"; then
    sed -i "s|REPLACE_WITH_YOUR_RANDOM_TOKEN|$(openssl rand -hex 16)|g" "$CFG"; filled=1
  fi
  if grep -q 'REPLACE_WITH_A_LONG_RANDOM_PASSWORD' "$CFG"; then
    sed -i "s|REPLACE_WITH_A_LONG_RANDOM_PASSWORD|$(openssl rand -hex 24)|g" "$CFG"; filled=1
  fi
  if grep -q 'REPLACE_WITH_ANOTHER_RANDOM_OBFS_PASSWORD' "$CFG"; then
    sed -i "s|REPLACE_WITH_ANOTHER_RANDOM_OBFS_PASSWORD|$(openssl rand -hex 16)|g" "$CFG"; filled=1
  fi
  if grep -q 'REPLACE_WITH_YOUR_X25519_PRIVATE_KEY' "$CFG"; then
    sed -i "s|REPLACE_WITH_YOUR_X25519_PRIVATE_KEY|$(gen_x25519_priv)|g" "$CFG"; filled=1
  fi
  # config.toml 自己就写着「替换示例值再上线」的两条 short_ids。
  if grep -q '"0123456789abcdef"' "$CFG"; then
    sed -i "s|\"0123456789abcdef\"|\"$(openssl rand -hex 8)\"|" "$CFG"; filled=1
  fi
  if grep -q '"fedcba9876543210"' "$CFG"; then
    sed -i "s|\"fedcba9876543210\"|\"$(openssl rand -hex 8)\"|" "$CFG"; filled=1
  fi
  # 兜底:模板将来新增占位而本函数没跟上时,**起不来**远好过「起来了但是 crash-loop」。
  if grep -n 'REPLACE_WITH' "$CFG" >&2; then
    die_t "config.toml still has unfilled placeholders (see above); fill them in and restart the container" \
          "config.toml 仍有未填占位(见上),补齐后重启容器"
  fi
  [[ "$filled" == 1 ]] && ok_t "generated this machine's REALITY private key / hy2 password / obfs password / WS path token / short_ids" \
                                "已生成本机的 REALITY 私钥 / hy2 口令 / obfs 口令 / WS path token / short_ids"
  return 0
}

# apply_magic_suffix:按 NANOTUN_MAGIC_SUFFIX 定制 MagicDNS 的 domain_suffix
# (客户端解析 *.<后缀> → mesh vIP)。与 scripts/install-self-hosted.sh 的同名函数**同一套**
# 校验 + 段感知改写(规则单一来源:那边改这边也要跟)。
#
# 运行期后缀只取 config.toml 的 [server.magic_dns].domain_suffix,且不在 SIGHUP 热更新
# 白名单里,须在 nanotund 启动前定好 —— 而 bootstrap 正是唯一会写 config.toml 的地方。
# 只在**这次真写了模板 config.toml**(CONFIG_FRESH=1:首次生成 / NANOTUN_FORCE_CONFIG=1)时改;
# 数据卷里已有配置时绝不擅自改它,只告警并给出改法。不给该变量就沿用模板默认,行为不变。
apply_magic_suffix() {
  local suf="${NANOTUN_MAGIC_SUFFIX:-}"
  [[ -n "$suf" ]] || return 0   # 没给:用模板默认后缀,不动 config.toml

  # 合法性:小写 DNS 标签(字母数字 + 连字符,可点分多级)。既防命令注入,也防写坏 TOML。
  if ! printf '%s' "$suf" | grep -Eq '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$'; then
    die_t "NANOTUN_MAGIC_SUFFIX is not valid (lowercase letters/digits/hyphens only, dot-separated levels allowed): '$suf'" \
          "NANOTUN_MAGIC_SUFFIX 不合法(只允许小写字母/数字/连字符,可点分多级):'$suf'"
  fi
  case "$suf" in
    local) die_t "NANOTUN_MAGIC_SUFFIX cannot be 'local' — it collides badly with mDNS/Bonjour (mac/iOS)." \
                 "NANOTUN_MAGIC_SUFFIX 不能用 'local' —— 与 mDNS/Bonjour(mac/iOS)严重冲突。" ;;
    lan|home|home.arpa|internal|corp)
      warn_t "The MagicDNS suffix '$suf' may collide with home routers / reserved domains (avoiding exactly that is why you would change it)." \
             "MagicDNS 后缀 '$suf' 可能与家用路由器 / 保留域冲突(想避开这类冲突正是换后缀的理由)。" ;;
  esac

  # 沿用数据卷里已有的 config.toml 就不改它 —— 升级/重启常态,擅自改后缀会踢乱在用的 mesh 名字。
  # 镜像里不带 set-magic-suffix.sh,故指路「直接改卷里的配置再重启」或 FORCE_CONFIG(会重签密钥)。
  if [[ "${CONFIG_FRESH:-0}" != 1 ]]; then
    warn_t "Kept the config.toml already in the data volume, so NANOTUN_MAGIC_SUFFIX='$suf' was not applied. To change the current suffix:" \
           "沿用了数据卷里已有的 config.toml,未套用 NANOTUN_MAGIC_SUFFIX='$suf'。要改现有后缀:"
    warn_t "  edit [server.magic_dns].domain_suffix in $CFG in the volume and restart the container;" \
           "  改卷里 $CFG 的 [server.magic_dns].domain_suffix 再重启容器;"
    warn_t "  or set NANOTUN_FORCE_CONFIG=1 to start over from the template (this re-signs the REALITY/hy2 keys and kicks off every existing client)." \
           "  或设 NANOTUN_FORCE_CONFIG=1 用模板重来(会重签 REALITY/hy2 密钥,踢掉所有现有客户端)。"
    return 0
  fi

  # 空白写 [ \t] 不用 [[:space:]]:兼容不认 POSIX 字符类的 mawk(与 install 脚本同因)。
  local cur
  cur="$(awk -F'"' '/^[ \t]*domain_suffix[ \t]*=/{print $2; exit}' "$CFG" || true)"
  if [[ "$cur" == "$suf" ]]; then
    ok_t "The MagicDNS suffix is already '$suf'" "MagicDNS 后缀已是 '$suf'"
    return 0
  fi

  # 段感知改写:仅动 [server.magic_dns] 段内的 domain_suffix(段内已有则原地替换,含被注释)。
  awk -v suf="$suf" '
    /^[ \t]*\[/ {
      if (insec && !done) { print "domain_suffix = \"" suf "\""; done=1 }
      insec = ($0 ~ /^[ \t]*\[server\.magic_dns\][ \t]*$/)
      if (insec) seen=1
      print; next
    }
    {
      if (insec && !done && $0 ~ /^[ \t]*#?[ \t]*domain_suffix[ \t]*=/) {
        print "domain_suffix = \"" suf "\""; done=1; next
      }
      print
    }
    END {
      if (insec && !done) print "domain_suffix = \"" suf "\""
      if (!seen) { print ""; print "[server.magic_dns]"; print "domain_suffix = \"" suf "\"" }
    }
  ' "$CFG" > "$CFG.new" && mv "$CFG.new" "$CFG" || { rm -f "$CFG.new"; die_t "Failed to write the MagicDNS suffix (config.toml was left untouched)" "写 MagicDNS 后缀失败(config.toml 未改动)"; }
  chmod 0600 "$CFG"
  ok_t "MagicDNS suffix set to '$suf' (clients resolve *.$suf → mesh virtual IP; the template default is 'nanotun')" \
       "MagicDNS 后缀设为 '$suf'(客户端解析 *.$suf → mesh 虚拟 IP;模板默认为 'nanotun')"
}

# apply_reality_port:按 NANOTUN_REALITY_PORT 定制 [reality].listen_addr。
# 与 scripts/install-self-hosted.sh 的同名函数**同一套**语义(规则单一来源:那边改这边也要跟),
# 也和 apply_magic_suffix 同一个口径 —— 只在这次真写了模板 config.toml 时改。
#
# 「已有配置就不动」这条在这里比后缀更硬:REALITY 的端口印在每一份已经发出去的客户端配置里,
# 悄悄挪走等于把所有现有客户端一次性踢下线,而他们看到的只是「连不上」。
#
# 默认 443 是有理由的(见 config.toml 的 [reality]:伪装成普通 HTTPS 站点),这个变量是给
# 「宿主上 443 已经被别的服务占着」的部署用的。
# NANOTUN_WEB_PORT 是裸机那边的名字,容器里也认它 —— 作为 NANOTUN_WEB_LISTEN 的简写。
#
# 不认的后果是**静默**:照着裸机文档设了 NANOTUN_WEB_PORT=9000 的人,容器里的后台纹丝不动
# 还在 7443,而屏幕上一句话都没有(2026-08-28 实测:entrypoint 里对这个名字 0 处引用)。
# 同一个概念在两条部署路径上叫两个名字,本来就容易记错,记错还不吭声就更糟。
#
# 归一化放在这儿(所有用到 Web 端口的地方之前),这样撞端口检查、启动参数、日志都自动跟着,
# 不必各处再判一次。两个都给时以 NANOTUN_WEB_LISTEN 为准:它更具体(能指定绑哪个地址),
# 而且明确指出来,免得人以为自己设的那个生效了。
normalize_web_listen() {
  local p="${NANOTUN_WEB_PORT:-}"
  [ -n "$p" ] || return 0
  if [[ ! "$p" =~ ^[0-9]+$ ]] || (( p < 1 || p > 65535 )); then
    die_t "NANOTUN_WEB_PORT must be a number from 1 to 65535: '$p'" \
          "NANOTUN_WEB_PORT 只认 1..65535 的整数:'$p'"
  fi
  if [ -n "${NANOTUN_WEB_LISTEN:-}" ]; then
    warn_t "Both NANOTUN_WEB_LISTEN and NANOTUN_WEB_PORT are set; going with NANOTUN_WEB_LISTEN=${NANOTUN_WEB_LISTEN} (it also says which address to bind)." \
           "同时给了 NANOTUN_WEB_LISTEN 和 NANOTUN_WEB_PORT,以 NANOTUN_WEB_LISTEN=${NANOTUN_WEB_LISTEN} 为准(它还指定了绑哪个地址)。"
    return 0
  fi
  export NANOTUN_WEB_LISTEN="0.0.0.0:${p}"
  log_t "Web console port: ${p} (from NANOTUN_WEB_PORT)" \
        "Web 后台端口:${p}(来自 NANOTUN_WEB_PORT)"
}

apply_reality_port() {
  local port="${NANOTUN_REALITY_PORT:-}"
  [[ -n "$port" ]] || return 0   # 没给:用模板默认的 443,不动 config.toml

  if [[ ! "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
    die_t "NANOTUN_REALITY_PORT must be a number from 1 to 65535: '$port'" \
          "NANOTUN_REALITY_PORT 只认 1..65535 的整数:'$port'"
  fi

  # 和 Web 管理面撞在同一个 TCP 端口上,是一台必坏的容器,而所有信号都会说没事:
  # 先起来的那个占住端口,后起来的拿 EADDRINUSE 反复重启,而健康检查走的是 control socket,
  # 照样 healthy。裸机那边由环境自检拦下,容器里没有那一步,只能在这儿拦。
  local web_port="${NANOTUN_WEB_LISTEN:-0.0.0.0:7443}"; web_port="${web_port##*:}"
  if [[ "${NANOTUN_WEB_ENABLED:-1}" != 0 && "$port" == "$web_port" ]]; then
    die_t "NANOTUN_REALITY_PORT=$port collides with the web console (NANOTUN_WEB_LISTEN=${NANOTUN_WEB_LISTEN:-0.0.0.0:7443}).
   One TCP port cannot have two owners: whichever starts second gets EADDRINUSE and restarts forever,
   while the health check keeps reporting healthy because it goes through the control socket.
   Move the web console instead — it is the one that can go anywhere: NANOTUN_WEB_LISTEN=0.0.0.0:<other>" \
          "NANOTUN_REALITY_PORT=$port 与 Web 管理面撞了(NANOTUN_WEB_LISTEN=${NANOTUN_WEB_LISTEN:-0.0.0.0:7443})。
   一个 TCP 端口不能有两个主人:后起来的那个会拿 EADDRINUSE 反复重启,而健康检查走的是
   control socket,会一直报 healthy。该挪的是 Web 管理面,它放哪儿都行:
   NANOTUN_WEB_LISTEN=0.0.0.0:<别的端口>"
  fi

  if [[ "${CONFIG_FRESH:-0}" != 1 ]]; then
    warn_t "Kept the config.toml already in the data volume, so NANOTUN_REALITY_PORT='$port' was not applied." \
           "沿用了数据卷里已有的 config.toml,未套用 NANOTUN_REALITY_PORT='$port'。"
    warn_t "  Moving REALITY on a deployment that is already serving cuts off every existing client — their" \
           "  在一个已经在服务的部署上挪动 REALITY,会让所有现有客户端连不上 —— 他们手上的配置里"
    warn_t "  profiles carry the old port. To do it deliberately: edit [reality].listen_addr in $CFG in the" \
           "  写的是旧端口。要有意这么做:改卷里 $CFG 的 [reality].listen_addr,重启容器,"
    warn_t "  volume, restart the container, then reissue every client profile." \
           "  然后给每个客户端重发配置。"
    return 0
  fi

  # 段感知改写:只动 [reality] 段内的 listen_addr。全局替换会把 [server] 和 [hysteria]
  # 的同名字段一起改掉,那是三个不同的东西。
  awk -v p="$port" '
    /^[ \t]*\[/ { insec = ($0 ~ /^[ \t]*\[reality\][ \t]*$/); print; next }
    {
      if (insec && $0 ~ /^[ \t]*#?[ \t]*listen_addr[ \t]*=/) { print "listen_addr = \":" p "\""; next }
      print
    }
  ' "$CFG" > "$CFG.tmp" && cat "$CFG.tmp" > "$CFG" && rm -f "$CFG.tmp"
  chmod 0600 "$CFG"

  local now
  now="$(awk '/^[ \t]*\[reality\][ \t]*$/{insec=1; next} /^[ \t]*\[/{insec=0} insec && /^[ \t]*listen_addr[ \t]*=/{gsub(/.*:|"/, ""); print; exit}' "$CFG")"
  [[ "$now" == "$port" ]] || die_t \
    "failed to write REALITY's port into $CFG (wanted $port, found '${now:-none}')" \
    "没能把 REALITY 端口写进 $CFG(想写 $port,读回 '${now:-空}')"

  ok_t "REALITY port: $port (the template default is 443; changed because you asked)" \
       "REALITY 端口:$port(模板默认 443,这次按你的要求改了)"
  # EXPOSE 是构建期写死的(443/tcp),挪走之后 `docker run -P` 不会发布这个新端口。
  # host 网络模式下无所谓;桥接模式下必须自己 -p。不说的话,现象是「容器好好的,外面连不上」。
  warn_t "  Bridge networking: the image only EXPOSEs 443/tcp, so publish this one yourself: -p $port:$port" \
         "  桥接模式:镜像 EXPOSE 的是 443/tcp,这个新端口要自己发布:-p $port:$port"
}

bootstrap() {
  mkdir -p "$ETC_DIR/certs" "$ETC_DIR/masquerade" "$LIB_DIR" "$RUN_DIR"
  chmod 0750 "$LIB_DIR" "$RUN_DIR"

  # 语言落盘。为的是 `docker exec <容器> nanotun-admin …` 这条路:它是新起的一个进程,
  # 不继承本脚本 export 的环境变量,而 compose 里的 environment 只作用于容器主进程。
  # 不落盘的话,同一台机器上主进程的日志是中文、docker exec 敲出来的却是英文。
  # 写失败不拦启动:它只影响语言,不值得为它让容器起不来。
  printf '%s\n' "$NT_LANG" > "$ETC_DIR/lang" 2>/dev/null \
    && chmod 0644 "$ETC_DIR/lang" 2>/dev/null \
    || warn_t "could not write $ETC_DIR/lang; nanotun-* commands run via docker exec will fall back to the default language" \
              "写不了 $ETC_DIR/lang,经 docker exec 敲的 nanotun-* 命令会回落到默认语言"

  # 模板始终刷新一份到 .dist,方便升级镜像后 diff 出新增字段(与 install 脚本同款做法)。
  install -m 0600 "$DIST_CFG" "$ETC_DIR/config.toml.dist"

  # CONFIG_FRESH 记「这次是不是真拿模板写了 config.toml」——apply_magic_suffix 靠它决定
  # 能不能改后缀:沿用数据卷里既有配置时它必须为 0,绝不擅自动别人已生效的 config。
  local CONFIG_FRESH
  if [[ -f "$CFG" && "${NANOTUN_FORCE_CONFIG:-0}" != "1" ]]; then
    ok_t "keeping the config.toml already in the data volume (the template is saved as config.toml.dist for diffing)" \
         "沿用数据卷里已有的 config.toml(模板另存 config.toml.dist 可 diff)"
    CONFIG_FRESH=0
  else
    if [[ -f "$CFG" ]]; then
      local bak="$ETC_DIR/config.toml.bak.$(date +%Y%m%d-%H%M%S)"
      cp -f "$CFG" "$bak"; chmod 0600 "$bak"
      warn_t "NANOTUN_FORCE_CONFIG=1: config.toml was overwritten from the template (the original is at $bak)" \
             "NANOTUN_FORCE_CONFIG=1:已用模板覆盖 config.toml(原文件 → $bak)"
    else
      log_t "first start: generating config.toml from the template" "首次启动:从模板生成 config.toml"
    fi
    install -m 0600 "$DIST_CFG" "$CFG"
    CONFIG_FRESH=1
  fi
  chmod 0600 "$CFG"
  chmod 0600 "$ETC_DIR"/config.toml.bak.* 2>/dev/null || true

  fill_config_secrets
  # MagicDNS 后缀:首次生成 config.toml 时可经 NANOTUN_MAGIC_SUFFIX 定制(默认取模板里的值)。
  # 同样须在 nanotund 启动前 —— 它启动时把后缀读进 magicDNSResolved 快照,起来后改要重启。
  apply_magic_suffix
  # 先把 NANOTUN_WEB_PORT 归一成 NANOTUN_WEB_LISTEN,再做 REALITY 端口 —— 后者的撞端口
  # 检查要读 Web 端口,顺序反了就会拿旧值去比。
  normalize_web_listen
  # REALITY 端口:同样只在首次生成 config.toml 时生效,且同样必须在 nanotund 起来之前。
  apply_reality_port

  # 按 config.toml 里配置的路径补齐缺失的 TLS 证书 / mTLS CA / masquerade 占位页。
  # 幂等:已存在的文件不动。
  bash /usr/local/bin/nanotun-ensure-assets.sh "$ETC_DIR"

  if [[ "${NANOTUN_SKIP_INIT:-0}" == "1" ]]; then
    warn_t "NANOTUN_SKIP_INIT=1: skipping nanotun-admin init" "NANOTUN_SKIP_INIT=1:跳过 nanotun-admin init"
    return 0
  fi

  # init 幂等:已 setup 过只回 {"noop":true},不会重置 PSK。首次的 PSK 只在这里出现一次,
  # 同时落一份 0600 的文件 —— 容器日志会滚动,而这是客户端接入的唯一凭证。
  local init_out
  init_out="$(printf '\n\n' | nanotun-admin --db-path "$LIB_DIR/nanotun.db" --json init 2>&1 || true)"
  if grep -q '"noop"[[:space:]]*:[[:space:]]*true' <<<"$init_out"; then
    ok_t "the database was initialized before; the existing PSK is kept" "数据库已初始化过,保留现有 PSK"
  else
    printf '%s\n' "$init_out" > "$LIB_DIR/init.out.json"
    chmod 600 "$LIB_DIR/init.out.json"
    ok_t "first-time initialization done. The PSK follows (also saved to $LIB_DIR/init.out.json — copy it somewhere safe now):" \
         "首次初始化完成,PSK 如下(也已存到 $LIB_DIR/init.out.json,请立即抄走):"
    printf '%s\n' "$init_out" >&2
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
# 3. 进程守护
#
# 两个进程的重启策略**刻意不同**,与 systemd 下两个独立 unit 的行为对齐:
#   * nanotund 挂了 → 整个容器退出,交给 Docker 的 restart 策略拉起。没有它什么都干不了。
#   * nanotun-web 挂了 → 就地重启,不动数据面。为了一个管理界面把所有 VPN 客户端踢下线,
#     代价和收益完全不成比例。
# ─────────────────────────────────────────────────────────────────────────────
DAEMON_PID=""
WEB_PID=""
SHUTTING_DOWN=0

# 放弃拉起 web 后留下的降级标记。HEALTHCHECK 是独立进程,看不到这里的 shell 变量,
# 只能靠文件传话 —— 否则管理面永久死掉时容器仍报 healthy,而 systemd 那边
# `systemctl is-active nanotun-web` 是会显示 failed 的,两条路的可观测性不该差这么远。
WEB_DEGRADED_FLAG="$RUN_DIR/web-degraded"

start_web() {
  local args=(
    -db "$LIB_DIR/nanotun.db"
    -control-socket "$RUN_DIR/control.sock"
    -cert-dir "$ETC_DIR/certs"
    -listen "${NANOTUN_WEB_LISTEN:-0.0.0.0:7443}"
  )
  [[ -n "${NANOTUN_WEB_EXTRA_SANS:-}" ]]      && args+=(-extra-sans "$NANOTUN_WEB_EXTRA_SANS")
  [[ -n "${NANOTUN_WEB_TRUSTED_PROXIES:-}" ]] && args+=(-trusted-proxies "$NANOTUN_WEB_TRUSTED_PROXIES")
  nanotun-web "${args[@]}" &
  WEB_PID=$!
  log_t "nanotun-web started (pid=$WEB_PID, listening on ${NANOTUN_WEB_LISTEN:-0.0.0.0:7443})" \
        "nanotun-web 已启动(pid=$WEB_PID,监听 ${NANOTUN_WEB_LISTEN:-0.0.0.0:7443})"
}

shutdown_handler() {
  trap '' TERM INT
  SHUTTING_DOWN=1
  log_t "stop signal received, shutting down ..." "收到停止信号,正在关停 ..."
  # 先停 web 再停 daemon:daemon 的退出路径要撤 iptables 规则、关 TUN、做 WAL checkpoint,
  # 让它最后走、走完整。docker stop 默认给 10s,这套清理通常 1~2s,不够时用 -t 调大。
  [[ -n "$WEB_PID" ]]    && kill -TERM "$WEB_PID"    2>/dev/null || true
  [[ -n "$DAEMON_PID" ]] && kill -TERM "$DAEMON_PID" 2>/dev/null || true
  [[ -n "$WEB_PID" ]]    && wait "$WEB_PID"    2>/dev/null || true
  [[ -n "$DAEMON_PID" ]] && wait "$DAEMON_PID" 2>/dev/null || true
  ok_t "stopped" "已停止"
  exit 0
}

supervise() {
  trap shutdown_handler TERM INT
  rm -f "$WEB_DEGRADED_FLAG"

  nanotund -config "$CFG" &
  DAEMON_PID=$!
  log_t "nanotund started (pid=$DAEMON_PID)" "nanotund 已启动(pid=$DAEMON_PID)"

  if [[ "${NANOTUN_WEB_ENABLED:-1}" == "1" ]]; then
    # 等控制面 socket 出现再起 web。它俩靠这个 socket 通信,早起几秒只会在日志里
    # 刷一串连接失败 —— 等一下更干净。超时也继续:web 自己会重试,不该因此拦住数据面。
    local waited=0
    while [[ ! -S "$RUN_DIR/control.sock" && $waited -lt 30 ]]; do
      kill -0 "$DAEMON_PID" 2>/dev/null || break
      sleep 1; waited=$((waited + 1))
    done
    # daemon 已经死了就别再拉 web:下面的循环马上要判定退出,起一个注定要被立刻杀掉的
    # 进程只会在日志里插一行误导人的「nanotun-web 已启动」,盖住真正的死因。
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
      warn_t "nanotund exited during startup, so web is not being started" "nanotund 在启动阶段就退出了,不再启动 web"
    else
      [[ -S "$RUN_DIR/control.sock" ]] || warn_t "waited ${waited}s and still no control-plane socket; starting web anyway" \
                                                  "等了 ${waited}s 仍没看到控制面 socket,照常启动 web"
      start_web
    fi
  else
    log_t "NANOTUN_WEB_ENABLED=0: data plane only, no web admin interface" \
          "NANOTUN_WEB_ENABLED=0:只跑数据面,不起 Web 管理面"
  fi

  # web 的重启节流:60 秒内连挂 5 次就不再拉起。配置写错时无限重启只会把日志刷爆,
  # 反而盖住真正的错误行。
  local web_fails=0 web_window_start=0

  while :; do
    # wait -n:任一子进程退出、或收到已设 trap 的信号时返回。
    wait -n 2>/dev/null || true
    [[ "$SHUTTING_DOWN" == 1 ]] && return 0

    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
      local rc=0
      wait "$DAEMON_PID" 2>/dev/null || rc=$?
      case "$rc" in
        10|11|20)
          # 与 nanotun.service 的 RestartPreventExitStatus=10 11 20 同一组:配置解析 /
          # 配置语义 / TLS 证书错误,重启一万次也是同样结果。Docker 的 restart 策略没有
          # "某些退出码不重启"这种表达,只能在这里把话说明白。
          warn_t "nanotund exited with status $rc (10=config parse, 11=config semantics, 20=TLS certificate) —
     restarting will not help with these; fix $CFG before starting the container again." \
                 "nanotund 以 exit $rc 退出(10=配置解析 11=配置语义 20=TLS 证书)——
     这类错误重启不会好转,请改 $CFG 后再启动容器。"
          ;;
        60) warn_t "nanotund exited with status 60 (network configuration failed: TUN / ip_forward / iptables)" \
                   "nanotund 以 exit 60 退出(网络配置失败:TUN / ip_forward / iptables)" ;;
      esac
      [[ -n "$WEB_PID" ]] && kill -TERM "$WEB_PID" 2>/dev/null || true
      die_with_code "$rc" "$(tsel "nanotund exited (code=$rc); the container exits too" \
                                   "nanotund 退出(code=$rc),容器一并退出")"
    fi

    if [[ -n "$WEB_PID" ]] && ! kill -0 "$WEB_PID" 2>/dev/null; then
      local wrc=0
      wait "$WEB_PID" 2>/dev/null || wrc=$?
      local now; now=$(date +%s)
      if (( now - web_window_start > 60 )); then web_window_start=$now; web_fails=0; fi
      web_fails=$((web_fails + 1))
      if (( web_fails > 5 )); then
        warn_t "nanotun-web died ${web_fails} times within 60 seconds (last one code=$wrc); it will no longer be restarted automatically.
     The data plane is unaffected and keeps running; the container turns unhealthy to signal that the admin interface is down. Fix it and restart the container to recover." \
               "nanotun-web 60 秒内连挂 ${web_fails} 次(最后一次 code=$wrc),不再自动重启。
     数据面不受影响,继续运行;容器会转为 unhealthy 提示管理面已失守,修好后重启容器恢复。"
        : > "$WEB_DEGRADED_FLAG"
        WEB_PID=""
        continue
      fi
      warn_t "nanotun-web exited (code=$wrc), restarting in 2 seconds (attempt ${web_fails})" \
             "nanotun-web 退出(code=$wrc),2 秒后重启(第 ${web_fails} 次)"
      sleep 2
      start_web
    fi
  done
}

# ─────────────────────────────────────────────────────────────────────────────
main() {
  # 逃生阀:传了参数就当普通命令跑,方便 `docker run --entrypoint ...` 之外的临时排查,
  # 比如 docker compose run --rm nanotun nanotun-admin user list
  if [[ $# -gt 0 ]]; then
    exec "$@"
  fi
  cd "$ETC_DIR"   # config.toml 里的证书是相对路径,与 systemd 的 WorkingDirectory 对齐
  preflight
  bootstrap
  supervise
}

main "$@"
