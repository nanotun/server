#!/usr/bin/env bash
# nanotun 容器入口:顶替 systemd 做三件事 —— 起飞前自检、首次初始化、进程守护。
#
# 为什么需要它而不是直接 ENTRYPOINT ["nanotund"]:
#   * systemd 那套里,RuntimeDirectory 建 /run/nanotun、tun-setup.service 备好设备、
#     install-self-hosted.sh 填密钥自签证书、两个 unit 各自守护。容器里这些全没了,
#     缺一样都是启动即死或者跑起来功能残缺。
#   * nanotund 对 ip_forward / TUN 失败的处理是 FatalExit(exit 60),容器只会看到
#     "restarting" 循环。与其让人去翻日志,不如在起飞前把话说清楚。
#
# 环境变量(都有合理默认,不设也能跑):
#   NANOTUN_WEB_ENABLED=1        是否同时起 Web 管理面(0 = 只跑数据面)
#   NANOTUN_WEB_LISTEN=0.0.0.0:7443
#   NANOTUN_WEB_EXTRA_SANS=      Web 自签证书额外 SAN,逗号分隔,如 vpn.example.com
#   NANOTUN_WEB_TRUSTED_PROXIES= 可信反代 IP/CIDR;放在 nginx 后面时必须设,否则按 IP
#                                限流会因为看到的全是反代地址而失效
#   NANOTUN_SKIP_INIT=0          跳过 nanotun-admin init(数据卷已有库时无副作用,
#                                init 本身幂等,这个开关只为特殊排查场景保留)
#   NANOTUN_FORCE_CONFIG=0       用镜像里的模板覆盖已有 config.toml(原文件会备份)
set -euo pipefail

ETC_DIR=/etc/nanotun
LIB_DIR=/var/lib/nanotun
RUN_DIR=/run/nanotun
CFG="$ETC_DIR/config.toml"
DIST_CFG=/usr/share/nanotun/config.toml.dist

log()  { printf '\033[1;36m[entrypoint]\033[0m %s\n' "$*" >&2; }
ok()   { printf '\033[1;32m[entrypoint]\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[1;33m[entrypoint]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[entrypoint] FATAL: %s\033[0m\n' "$*" >&2; exit 1; }

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
    "nanotund 未被要求停止却以 exit 0 退出,容器一并退出" >&2; exit 1; }
  printf '\033[1;31m[entrypoint] FATAL: %s(容器退出码沿用它)\033[0m\n' "$*" >&2
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
    die "/dev/net/tun 不存在。容器需要显式挂这个设备:
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
    die "缺少 CAP_NET_ADMIN(CapEff=${capeff})。加上:
       docker run --cap-add NET_ADMIN ...
     compose 里是 cap_add: [NET_ADMIN]"
  fi

  # IPv4 转发。nanotund 起 iptables 之前会 sysctl -w,失败即 FatalExit(exit 60)。
  # 容器默认 /proc/sys 只读,所以这里分三种情况说清楚该怎么办。
  local fwd
  fwd="$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)"
  if [[ "$fwd" != "1" ]]; then
    if sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1; then
      ok "已开启 net.ipv4.ip_forward=1"
    else
      die "net.ipv4.ip_forward=0 且写不进去,nanotund 会以 exit 60 退出。二选一:
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
  log "iptables: ${backend}(宿主若是 legacy 后端,见 docs/DOCKER.md 切换说明)"

  # 这几个是 best-effort:容器里 /proc/sys 常只读,失败不影响主链路,
  # nanotund 内部同样按 best-effort 处理。
  sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
  # nanotun-web 保存 server_dial_host 时会做 unprivileged ICMP 探测,没这个只能勾"跳过检测"。
  sysctl -w net.ipv4.ping_group_range="0 2147483647" >/dev/null 2>&1 || true
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
    die "config.toml 仍有未填占位(见上),补齐后重启容器"
  fi
  [[ "$filled" == 1 ]] && ok "已生成本机的 REALITY 私钥 / hy2 口令 / obfs 口令 / WS path token / short_ids"
  return 0
}

bootstrap() {
  mkdir -p "$ETC_DIR/certs" "$ETC_DIR/masquerade" "$LIB_DIR" "$RUN_DIR"
  chmod 0750 "$LIB_DIR" "$RUN_DIR"

  # 模板始终刷新一份到 .dist,方便升级镜像后 diff 出新增字段(与 install 脚本同款做法)。
  install -m 0600 "$DIST_CFG" "$ETC_DIR/config.toml.dist"

  if [[ -f "$CFG" && "${NANOTUN_FORCE_CONFIG:-0}" != "1" ]]; then
    ok "沿用数据卷里已有的 config.toml(模板另存 config.toml.dist 可 diff)"
  else
    if [[ -f "$CFG" ]]; then
      local bak="$ETC_DIR/config.toml.bak.$(date +%Y%m%d-%H%M%S)"
      cp -f "$CFG" "$bak"; chmod 0600 "$bak"
      warn "NANOTUN_FORCE_CONFIG=1:已用模板覆盖 config.toml(原文件 → $bak)"
    else
      log "首次启动:从模板生成 config.toml"
    fi
    install -m 0600 "$DIST_CFG" "$CFG"
  fi
  chmod 0600 "$CFG"
  chmod 0600 "$ETC_DIR"/config.toml.bak.* 2>/dev/null || true

  fill_config_secrets

  # 按 config.toml 里配置的路径补齐缺失的 TLS 证书 / mTLS CA / masquerade 占位页。
  # 幂等:已存在的文件不动。
  bash /usr/local/bin/nanotun-ensure-assets.sh "$ETC_DIR"

  if [[ "${NANOTUN_SKIP_INIT:-0}" == "1" ]]; then
    warn "NANOTUN_SKIP_INIT=1:跳过 nanotun-admin init"
    return 0
  fi

  # init 幂等:已 setup 过只回 {"noop":true},不会重置 PSK。首次的 PSK 只在这里出现一次,
  # 同时落一份 0600 的文件 —— 容器日志会滚动,而这是客户端接入的唯一凭证。
  local init_out
  init_out="$(printf '\n\n' | nanotun-admin --db-path "$LIB_DIR/nanotun.db" --json init 2>&1 || true)"
  if grep -q '"noop"[[:space:]]*:[[:space:]]*true' <<<"$init_out"; then
    ok "数据库已初始化过,保留现有 PSK"
  else
    printf '%s\n' "$init_out" > "$LIB_DIR/init.out.json"
    chmod 600 "$LIB_DIR/init.out.json"
    ok "首次初始化完成,PSK 如下(也已存到 $LIB_DIR/init.out.json,请立即抄走):"
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
  log "nanotun-web 已启动(pid=$WEB_PID,监听 ${NANOTUN_WEB_LISTEN:-0.0.0.0:7443})"
}

shutdown_handler() {
  trap '' TERM INT
  SHUTTING_DOWN=1
  log "收到停止信号,正在关停 ..."
  # 先停 web 再停 daemon:daemon 的退出路径要撤 iptables 规则、关 TUN、做 WAL checkpoint,
  # 让它最后走、走完整。docker stop 默认给 10s,这套清理通常 1~2s,不够时用 -t 调大。
  [[ -n "$WEB_PID" ]]    && kill -TERM "$WEB_PID"    2>/dev/null || true
  [[ -n "$DAEMON_PID" ]] && kill -TERM "$DAEMON_PID" 2>/dev/null || true
  [[ -n "$WEB_PID" ]]    && wait "$WEB_PID"    2>/dev/null || true
  [[ -n "$DAEMON_PID" ]] && wait "$DAEMON_PID" 2>/dev/null || true
  ok "已停止"
  exit 0
}

supervise() {
  trap shutdown_handler TERM INT

  nanotund -config "$CFG" &
  DAEMON_PID=$!
  log "nanotund 已启动(pid=$DAEMON_PID)"

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
      warn "nanotund 在启动阶段就退出了,不再启动 web"
    else
      [[ -S "$RUN_DIR/control.sock" ]] || warn "等了 ${waited}s 仍没看到控制面 socket,照常启动 web"
      start_web
    fi
  else
    log "NANOTUN_WEB_ENABLED=0:只跑数据面,不起 Web 管理面"
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
          warn "nanotund 以 exit $rc 退出(10=配置解析 11=配置语义 20=TLS 证书)——
     这类错误重启不会好转,请改 $CFG 后再启动容器。"
          ;;
        60) warn "nanotund 以 exit 60 退出(网络配置失败:TUN / ip_forward / iptables)" ;;
      esac
      [[ -n "$WEB_PID" ]] && kill -TERM "$WEB_PID" 2>/dev/null || true
      die_with_code "$rc" "nanotund 退出(code=$rc),容器一并退出"
    fi

    if [[ -n "$WEB_PID" ]] && ! kill -0 "$WEB_PID" 2>/dev/null; then
      local wrc=0
      wait "$WEB_PID" 2>/dev/null || wrc=$?
      local now; now=$(date +%s)
      if (( now - web_window_start > 60 )); then web_window_start=$now; web_fails=0; fi
      web_fails=$((web_fails + 1))
      if (( web_fails > 5 )); then
        warn "nanotun-web 60 秒内连挂 ${web_fails} 次(最后一次 code=$wrc),不再自动重启。
     数据面不受影响,继续运行;修好后重启容器即可恢复管理面。"
        WEB_PID=""
        continue
      fi
      warn "nanotun-web 退出(code=$wrc),2 秒后重启(第 ${web_fails} 次)"
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
