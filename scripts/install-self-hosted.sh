#!/usr/bin/env bash
# nanotun 自托管（PSK 模式）服务器端一键安装脚本（本地交叉编译版）
#
# 由本机 deploy 上传至 /root/nanotun_deploy/install.sh 后 ssh 执行。
#
# 前置：本地已 GOOS=linux GOARCH=amd64 编好 nanotund + nanotun-admin，
# 与本脚本一并放在 /root/nanotun_deploy/ 下。
#
# $EXTRAS_DIR/nanotun.service 的权威模板是 repo 内 cmd/nanotund/nanotun.service —
# 包含 G_exit_code 的 RestartPreventExitStatus 等关键字段;打部署包时请直接 cp
# 该文件,不要手改 / 漂版本。
#
# 行为（不再装 Go、不在服务器编译）：
#   1. 安装文件到位：
#      /usr/local/bin/{nanotund, nanotun-admin, nanotun-tun-setup.sh, ...}
#      /etc/nanotun/{config.toml, certs/, masquerade/}（证书由 ensure-server-assets.sh 按需自签）
#      /var/lib/nanotun/                        （SQLite home）
#      /etc/systemd/system/{nanotun-tun-setup,nanotun-tun-isolate,nanotun}.service
#   2. 开启 IP forwarding（v4 + v6）+ unprivileged ICMP ping（nanotun-web
#      pro-bing 探测 server_dial_host 可达性必备），写 /etc/sysctl.d/99-nanotun.conf
#   3. ufw active 时自动放行 8080/8443/tcp + 443/udp（装了 web 再加 7443/tcp；INPUT 默认 DROP 时必须）
#   4. K1 旧 DB 自检:若新 DB 空 + 旧 DB(/root/nanotun/data/nanotun.db)有终端用户 →
#      默认拒绝继续(2026-05-21 事故场景);设置 NANOTUN_IMPORT_LEGACY_DB=1 显式导入。
#   5. 跑 nanotun-admin --json --yes init 创建 admin（PSK 自动生成）
#   6. enable + start systemd units（重启系统会自动拉起）
#   7. 打印 init 输出 + 端口监听 + journalctl tail，方便人工核对
#
# 幂等：重复跑不会破坏数据；init 自带「同名管理员只重置 PSK」逻辑；
#       ufw allow / systemctl enable 都是幂等命令；K1 旧 DB 检查在新 DB 已有真实
#       用户(NEW_USERS>0)时永远跳过,不会覆盖二次部署。

set -euo pipefail

DEPLOY_DIR=/root/nanotun_deploy
EXTRAS_DIR="$DEPLOY_DIR/extras"
SCRIPTS_DIR="$DEPLOY_DIR/scripts"
ETC_DIR=/etc/nanotun
LIB_DIR=/var/lib/nanotun

step() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[1;32m✓\033[0m %s\n' "$*"; }
warn() { printf '    \033[1;33m!\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mFATAL: %s\033[0m\n' "$*" >&2; exit 1; }

# 必要文件存在性自检。nanotun-web 是 M2 引入的 Web 后台:可选,缺了不会 fatal,
# 但会跳过其安装步骤并 warn。这样老 deploy 包不会因为多一个二进制就失败。
#
# 证书不随包分发:发布包里没有任何 dev-*.pem。TLS / mTLS CA / masquerade 页由
# ensure-server-assets.sh 在 config.toml 落位后按需自签(见 step 1 末尾)。
for f in "$DEPLOY_DIR/nanotund" "$DEPLOY_DIR/nanotun-admin" \
         "$EXTRAS_DIR/config.toml" "$EXTRAS_DIR/nanotun.service" \
         "$SCRIPTS_DIR/tun-setup.sh" "$SCRIPTS_DIR/tun-isolate.sh" \
         "$SCRIPTS_DIR/tun-isolate-teardown.sh" \
         "$SCRIPTS_DIR/tun-teardown.sh" "$SCRIPTS_DIR/tun-setup.service" \
         "$SCRIPTS_DIR/tun-isolate.service" \
         "$SCRIPTS_DIR/ensure-server-assets.sh"; do
  [ -e "$f" ] || die "缺文件: $f"
done

WEB_AVAILABLE=0
if [ -f "$DEPLOY_DIR/nanotun-web" ] && [ -f "$EXTRAS_DIR/nanotun-web.service" ]; then
  WEB_AVAILABLE=1
fi

step "1. 安装二进制 / 脚本 / 证书 / 配置 / systemd 单元"
install -m 0755 "$DEPLOY_DIR/nanotund"  /usr/local/bin/nanotund
install -m 0755 "$DEPLOY_DIR/nanotun-admin"    /usr/local/bin/nanotun-admin
install -m 0755 "$SCRIPTS_DIR/tun-setup.sh"     /usr/local/bin/nanotun-tun-setup.sh
install -m 0755 "$SCRIPTS_DIR/tun-isolate.sh"   /usr/local/bin/nanotun-tun-isolate.sh
# teardown 与 UPGRADE_M0.md 里「关掉历史隔离」的卸载指引配套,必须一起装上。
install -m 0755 "$SCRIPTS_DIR/tun-isolate-teardown.sh" /usr/local/bin/nanotun-tun-isolate-teardown.sh
install -m 0755 "$SCRIPTS_DIR/tun-teardown.sh"  /usr/local/bin/nanotun-tun-teardown.sh

mkdir -p "$ETC_DIR/certs" "$ETC_DIR/masquerade" "$LIB_DIR"
chmod 0750 "$LIB_DIR"

# config.toml：旧文件备份后覆盖
if [ -f "$ETC_DIR/config.toml" ]; then
  cp -f "$ETC_DIR/config.toml" "$ETC_DIR/config.toml.bak.$(date +%Y%m%d-%H%M%S)"
fi
install -m 0644 "$EXTRAS_DIR/config.toml" "$ETC_DIR/config.toml"

# 证书 / masquerade 页：按 config.toml 里配置的路径**按需自签**(不随包分发)。
# ensure-server-assets.sh 读 [server] / [hysteria] 的 tls_* 与 masquerade_dir,
# 只在文件缺失时生成,幂等;WorkingDirectory 传 $ETC_DIR,相对路径落到 $ETC_DIR/certs 等。
install -m 0755 "$SCRIPTS_DIR/ensure-server-assets.sh" /usr/local/bin/nanotun-ensure-assets.sh
bash "$SCRIPTS_DIR/ensure-server-assets.sh" "$ETC_DIR"

# systemd 单元。tun-isolate 是「恢复历史客户端隔离」的逃生阀:装上但**不** enable,
# 需要时 `systemctl enable --now nanotun-tun-isolate.service`(单元本身无 [Install] 段)。
install -m 0644 "$SCRIPTS_DIR/tun-setup.service" /etc/systemd/system/nanotun-tun-setup.service
install -m 0644 "$SCRIPTS_DIR/tun-isolate.service" /etc/systemd/system/nanotun-tun-isolate.service
install -m 0644 "$EXTRAS_DIR/nanotun.service"  /etc/systemd/system/nanotun.service
systemctl daemon-reload
ok "二进制 / 配置 / 证书 / systemd 单元已就位"

step "2. 开启 IP forwarding + unprivileged ICMP ping"
cat > /etc/sysctl.d/99-nanotun.conf <<'SYSCTL'
# nanotun 自托管 VPN 网关：转发数据包给客户端访问公网 / 互访
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv6.conf.all.forwarding = 1
# nanotun-web 在保存 server_dial_host 时跑 unprivileged ICMP ping(pro-bing)
# 做可达性检测。Linux 默认 ping_group_range=0 0,非 root 无法创建 ping socket →
# pro-bing 初始化失败 → admin 被迫永远勾「跳过 ICMP 可达性检测」绕过。
# 放开为全范围让任意 group 都能跑 unprivileged ping。
net.ipv4.ping_group_range = 0 2147483647
SYSCTL
sysctl --system >/dev/null
ok "ip_forward = $(sysctl -n net.ipv4.ip_forward), v6.forwarding = $(sysctl -n net.ipv6.conf.all.forwarding), ping_group_range = '$(sysctl -n net.ipv4.ping_group_range 2>/dev/null || echo 'n/a')'"

step "3. 防火墙：放行 nanotun 监听端口（仅 ufw active 时）"
# ufw 默认 INPUT DROP（Ubuntu 全新系统常见配置），不放行端口客户端会全部被静默丢包，
# 表现为「TCP 三次握手超时」「QUIC 重传无响应」。这里检测 ufw 状态后幂等放行。
# 如果你用的是 firewalld / iptables / 云厂商安全组，请按各自方式自行放行：
#   tcp 8080 (WSS gateway)  tcp 8443 (REALITY)  udp 443 (hy2 QUIC)
# 2026-07-17:hy2 独立 WSS 保活(:8444)已下线,不再放行,并清理历史规则。
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
  WEB_PORTS=()
  # nanotun-web 监听 7443/tcp(见 nanotun-web.service),装了才放行;否则保持 LAN/隧道内可达。
  [ "$WEB_AVAILABLE" -eq 1 ] && WEB_PORTS+=("7443/tcp")
  for rule in "8080/tcp" "8443/tcp" "443/udp" "${WEB_PORTS[@]}"; do
    ufw allow "$rule" >/dev/null
  done
  ufw delete allow "8444/tcp" >/dev/null 2>&1 || true
  if [ "$WEB_AVAILABLE" -eq 1 ]; then
    ok "ufw 放行：8080/tcp 8443/tcp 443/udp 7443/tcp(web)"
  else
    ok "ufw 放行：8080/tcp 8443/tcp 443/udp"
  fi
else
  warn "未检测到 ufw active；如使用其他防火墙，请手动放行 8080/8443/tcp 与 443/udp（装了 web 再加 7443/tcp）"
fi

step "4. 旧 DB 路径迁移自检（K1：2026-05-21 事故防再发）"
# 背景:历史上 nanotun 曾用 /root/nanotun/data/nanotun.db 作为 SQLite home,
# 新版本搬到了 /var/lib/nanotun/nanotun.db。若部署脚本只在新路径建空库 + 一个 admin,
# 旧 DB 里的 smoker / 设备 / lease 留在原地不会被自动迁移 → 所有终端 401/403 「用户不存在」,
# iOS / macOS 表面看到的是 「NECP policy denied」「No route to host」(实际是登录失败 EOF)。
# 这里做的检查:
#   • 新 DB 没有「非 admin 用户」(空库 / 刚 init 的库都属于这种)
#   • 旧路径 /root/nanotun/data/nanotun.db 存在,且里面**有**非 admin 用户
# → 阻断安装,提示用户:要么明确导入(NANOTUN_IMPORT_LEGACY_DB=1),要么先手动归档。
# 这两种动作都需要人工确认,绝不**默认**覆盖。
LEGACY_DB=/root/nanotun/data/nanotun.db
count_real_users() {
  # 第三列 ADMIN 为 "no" 视为终端用户。
  # nanotun-admin user list 在空库 / 不存在表时返回空,这种就是 0。
  /usr/local/bin/nanotun-admin --db-path "$1" user list 2>/dev/null \
    | awk 'NR>1 && $3=="no" {n++} END {print n+0}'
}
NEW_USERS=$(count_real_users "$LIB_DIR/nanotun.db" 2>/dev/null || echo 0)
LEGACY_USERS=0
if [ -f "$LEGACY_DB" ]; then
  LEGACY_USERS=$(count_real_users "$LEGACY_DB" 2>/dev/null || echo 0)
fi
if [ "$NEW_USERS" -eq 0 ] && [ "$LEGACY_USERS" -gt 0 ]; then
  if [ "${NANOTUN_IMPORT_LEGACY_DB:-0}" = "1" ]; then
    BAK="$LIB_DIR/nanotun.db.preimport.$(date +%Y%m%d-%H%M%S)"
    [ -f "$LIB_DIR/nanotun.db" ] && cp -a "$LIB_DIR/nanotun.db"     "$BAK"     || true
    [ -f "$LIB_DIR/nanotun.db-wal" ] && cp -a "$LIB_DIR/nanotun.db-wal" "$BAK-wal" || true
    [ -f "$LIB_DIR/nanotun.db-shm" ] && cp -a "$LIB_DIR/nanotun.db-shm" "$BAK-shm" || true
    install -m 0600 "$LEGACY_DB" "$LIB_DIR/nanotun.db"
    [ -f "$LEGACY_DB-wal" ] && install -m 0600 "$LEGACY_DB-wal" "$LIB_DIR/nanotun.db-wal" || rm -f "$LIB_DIR/nanotun.db-wal"
    [ -f "$LEGACY_DB-shm" ] && install -m 0600 "$LEGACY_DB-shm" "$LIB_DIR/nanotun.db-shm" || rm -f "$LIB_DIR/nanotun.db-shm"
    ok "已从旧路径导入 DB:$LEGACY_DB → $LIB_DIR/nanotun.db (备份原文件 → $BAK)"
    ok "Batch J 二进制启动时会自动跑 store.Migrate 应用新 migration"
  else
    SELF_PATH="$(realpath "$0" 2>/dev/null || echo "$0")"
    printf >&2 '\n\033[1;31mFATAL: 旧 DB 路径 %s 检出 %d 个终端用户,\n新路径 %s/nanotun.db 没有,直接装会让所有终端登录失败「用户不存在」(2026-05-21 事故场景)。\033[0m\n\n' \
      "$LEGACY_DB" "$LEGACY_USERS" "$LIB_DIR"
    printf >&2 '请二选一明确处理:\n  1) 导入旧数据(保留 PSK / device UUID / lease):\n       systemctl stop nanotun.service 2>/dev/null || true\n       NANOTUN_IMPORT_LEGACY_DB=1 bash %s\n  2) 确认旧数据已无用,归档后再装:\n       mv %s %s.archived.$(date +%%Y%%m%%d-%%H%%M%%S)\n       bash %s\n\n' \
      "$SELF_PATH" "$LEGACY_DB" "$LEGACY_DB" "$SELF_PATH"
    die "拒绝在「旧 DB 仍有用户、新 DB 空」状态下完成安装"
  fi
else
  if [ "$LEGACY_USERS" -gt 0 ] && [ "$NEW_USERS" -gt 0 ]; then
    warn "旧 DB $LEGACY_DB 仍有 $LEGACY_USERS 个终端用户,但新 DB 已有 $NEW_USERS 个 — 不会自动覆盖。"
    warn "确认无用后请手动 mv 归档:mv $LEGACY_DB $LEGACY_DB.archived.\$(date +%Y%m%d-%H%M%S)"
  fi
fi

step "5. 初始化 admin 用户（首次部署生成 PSK；重复部署 noop 保留现有 PSK）"
# init 默认幂等：setup_completed=1 时再跑只输出 admin 元信息（{"noop":true}），不改 PSK。
# 想强制重置请手动 `nanotun-admin --json init --reset-psk`，不要让脚本自动做。
INIT_OUT=$(printf '\n\n' | /usr/local/bin/nanotun-admin --db-path "$LIB_DIR/nanotun.db" --json init 2>&1 || true)
if echo "$INIT_OUT" | grep -q '"noop"[[:space:]]*:[[:space:]]*true'; then
  ok "已 setup，init 跳过（不重置 PSK）"
  echo "$INIT_OUT"
else
  ok "首次 init，生成新 PSK（写入 $DEPLOY_DIR/init.out.txt 仅 600）"
  echo "$INIT_OUT" > "$DEPLOY_DIR/init.out.txt"
  chmod 600 "$DEPLOY_DIR/init.out.txt"
  echo "$INIT_OUT"
fi

step "6. 启动并设为开机自启"
systemctl enable --now nanotun-tun-setup.service
sleep 1
# enable + restart：保证开机自启 + 应用最新配置
systemctl enable nanotun.service >/dev/null 2>&1 || true
systemctl restart nanotun.service
sleep 2

if [ "$WEB_AVAILABLE" -eq 1 ]; then
  step "6b. 安装 nanotun-web(Web 管理后台,M2)"
  install -m 0755 "$DEPLOY_DIR/nanotun-web" /usr/local/bin/nanotun-web
  install -m 0644 "$EXTRAS_DIR/nanotun-web.service" /etc/systemd/system/nanotun-web.service
  mkdir -p "$ETC_DIR/certs"  # web TLS 自签证书会落到这里
  systemctl daemon-reload
  systemctl enable nanotun-web.service >/dev/null 2>&1 || true
  systemctl restart nanotun-web.service
  sleep 2
  ok "nanotun-web 已启动,首次访问请打开 https://<server>:7443/setup 创建管理员"
fi

step "7. 状态自检"
echo "[systemctl is-enabled]"
CHECK_UNITS=(nanotun-tun-setup nanotun)
[ "$WEB_AVAILABLE" -eq 1 ] && CHECK_UNITS+=(nanotun-web)
for unit in "${CHECK_UNITS[@]}"; do
  printf '    %-22s %s\n' "$unit" "$(systemctl is-enabled "$unit.service" 2>/dev/null || echo unknown)"
done
echo "---"
echo "[systemctl status nanotun-tun-setup]"
systemctl --no-pager status nanotun-tun-setup.service | head -12 || true
echo "---"
echo "[systemctl status nanotun]"
systemctl --no-pager status nanotun.service | head -22 || true
echo "---"
echo "[ports listening on 443/8080/8443 (TCP)]"
ss -lntp 2>&1 | grep -E ":(443|8080|8443)" || warn "无 TCP 监听（请检查 journalctl）"
echo "[hy2 UDP :443]"
ss -lunp 2>&1 | grep -E ":443" || warn "hy2 UDP :443 未起"
echo "---"
echo "[journalctl -u nanotun --no-pager -n 40]"
journalctl -u nanotun.service --no-pager -n 40 || true

echo
ok "部署完成。常用运维："
echo "    journalctl -u nanotun -f                                       # 实时日志"
echo "    /usr/local/bin/nanotun-admin --db-path $LIB_DIR/nanotun.db user list"
echo "    /usr/local/bin/nanotun-admin --db-path $LIB_DIR/nanotun.db device list"
echo "    /usr/local/bin/nanotun-admin --db-path $LIB_DIR/nanotun.db lease list"
echo "    /usr/local/bin/nanotun-admin --db-path $LIB_DIR/nanotun.db setting list"
if [ "$WEB_AVAILABLE" -eq 1 ]; then
  echo
  echo "  Web 管理后台(M2):"
  echo "    journalctl -u nanotun-web -f"
  echo "    浏览器访问 https://<server>:7443/setup 创建第一位 Web 管理员"
  echo "    证书: $ETC_DIR/certs/{cert.pem,key.pem}(可作为 root CA 装入信任库)"
fi
