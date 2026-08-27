#!/usr/bin/env bash
# set-magic-suffix.sh — 修改 nanotun 的 MagicDNS domain_suffix 并重启服务。
#
# 为什么要重启：domain_suffix 不在 SIGHUP 热更新白名单里（见 cmd/nanotund/reload.go 的
#   applyConfigReload / classifyDeferredFields），它在 startMagicDNS() 启动时被读进
#   magicDNSResolved 快照，故必须 `systemctl restart nanotun` 才生效。SIGTERM 会走
#   graceful drain（广播 LinkTypeClose），客户端友好重连。
#
# 安全保证：先备份 config.toml → 段感知精确改写（只动 [server.magic_dns].domain_suffix）
#   → 重启 → 轮询服务状态；若在超时内未回到 active（例如配置被改坏，unit 因
#   RestartPreventExitStatus 落 failed），自动回滚备份并重启，绝不把服务器改趴。
#
# 用法：
#   A) 远程（从本机 SSH 到服务器执行）：
#        SSH_HOST=<nanotun服务器IP> SSH_PASS='密码' ./scripts/set-magic-suffix.sh nanotun
#      或用 SSH 密钥（不设 SSH_PASS）：
#        SSH_HOST=<nanotun服务器IP> ./scripts/set-magic-suffix.sh nanotun
#
#   B) 本地（已 SSH 到服务器后，直接在服务器上以 root 跑）：
#        sudo ./scripts/set-magic-suffix.sh nanotun
#
# 注意：这里的目标机是**运行 nanotun 的网关服务器**（客户端连接的后端），不是 mesh 里
#   的某个客户端节点。多台网关都需各自执行一次。
#
# 可选环境变量：CONFIG（默认 /etc/nanotun/config.toml）、SERVICE（默认 nanotun）。
set -euo pipefail

# --help 得在取后缀之前拦下。
#
# 之前没有这一条,于是 `--help` 直接落进 SUFFIX,被下面那条合法性正则判死,打出
# 「FATAL: 后缀不合法（只允许小写字母/数字/连字符）：'--help'」—— 装成命令的这几个里
# 只有它没有帮助,而想确认参数的人第一反应恰恰是敲 --help,收到的却是一句红色的致命错误。
#
# 装成 /usr/local/bin/nanotun-set-suffix 之后只剩「就在这台服务器上跑」这一种用法,
# 头部那段里的 SSH_HOST 远程形态反而会让人以为还要再 SSH 一次,所以两种形态各给各的。
case "${1:-}" in
  -h|--help)
    if [ "$(basename "$0")" = set-magic-suffix.sh ]; then
      awk 'NR>1 && /^#/ {sub(/^#[ \t]?/,""); print; next} NR>1 {exit}' "$0"
    else
      cat <<EOF
用法: sudo $(basename "$0") <新后缀>        例如: sudo $(basename "$0") nanotun

修改 nanotun 的 MagicDNS 后缀(客户端解析 *.<后缀> → mesh 虚拟 IP)并重启服务。
domain_suffix 不在 SIGHUP 热更白名单里,只有重启才生效;重启走 graceful drain,
客户端会自动重连。

先备份 config.toml → 只改 [server.magic_dns].domain_suffix → 重启 → 轮询状态;
超时内没回到 active 就自动回滚备份并重启,不会把服务器改趴。

后缀只允许小写字母 / 数字 / 连字符,可点分多级。'local' 与 mDNS 冲突,禁用。

可选环境变量:CONFIG(默认 /etc/nanotun/config.toml)、SERVICE(默认 nanotun)。
EOF
    fi
    exit 0 ;;
  # 别的 -开头参数同样别当后缀。判死的措辞得指向 --help,而不是让人对着一条
  # 「后缀不合法」去想自己的后缀哪里写错了 —— 他压根没在写后缀。
  -?*)
    echo "FATAL: 未知参数 '$1'（本命令只接一个后缀;--help 看用法）" >&2; exit 2 ;;
esac

SUFFIX="${1:-${SUFFIX:-}}"
CONFIG="${CONFIG:-/etc/nanotun/config.toml}"
SERVICE="${SERVICE:-nanotun}"

if [ -z "$SUFFIX" ]; then
  # 用命令名而不是 $0:装成 /usr/local/bin/nanotun-set-suffix 之后,$0 是一整条绝对路径,
  # 而这行是给人照着敲的。SSH_HOST 那段只在从仓库直跑时才提 —— 装成命令就意味着人已经
  # 在这台服务器上了,再提「SSH 到服务器」只会让人以为还差一步。
  me="$(basename "$0")"
  if [ "$me" = set-magic-suffix.sh ]; then
    echo "用法: [SSH_HOST=.. SSH_PASS=..] ./scripts/${me} <新后缀>    例如: ./scripts/${me} nanotun" >&2
  else
    echo "用法: sudo ${me} <新后缀>    例如: sudo ${me} nanotun    (--help 看详细说明)" >&2
  fi
  exit 2
fi

# 后缀合法性：小写 DNS 标签（字母数字 + 连字符，可点分多级）。既防命令注入，也防写坏 TOML。
if ! printf '%s' "$SUFFIX" | grep -Eq '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$'; then
  echo "FATAL: 后缀不合法（只允许小写字母/数字/连字符，可用点分多级）：'$SUFFIX'" >&2
  exit 2
fi
case "$SUFFIX" in
  local)
    echo "FATAL: 'local' 与 mDNS/Bonjour 冲突严重（mac/iOS），禁止使用。" >&2; exit 2 ;;
  lan|home|home.arpa|internal|corp)
    echo "!! 警告: '$SUFFIX' 可能与家用路由器 / 保留域冲突（这正是要迁移后缀的原因）。3 秒后继续，Ctrl-C 取消。" >&2
    sleep 3 ;;
esac

# ── 真正在服务器上执行的 worker（本地/远程共用；从 stdin 读入，参数经 env 传入）──
read -r -d '' WORKER <<'WORKER_EOF' || true
set -euo pipefail
: "${SUFFIX:?}"; : "${CONFIG:?}"; : "${SERVICE:?}"

if [ "$(id -u)" != 0 ]; then
  echo "FATAL: 需要 root（systemctl / 写 ${CONFIG}）。请用 sudo，或以 root SSH。" >&2
  exit 1
fi
[ -f "$CONFIG" ] || { echo "FATAL: 找不到配置文件 $CONFIG" >&2; exit 1; }

# 空白写 [ \t] 而不是 [[:space:]]:mawk 1.3.3(Ubuntu 18.04 / Debian 10 的默认 awk)
# 不认 POSIX 字符类,正则会永不匹配 —— 这里的后果是「读不到现有值」被当成「还没设过」,
# 下面那段改写于是走插入分支,给配置里塞进第二个 domain_suffix。
CUR="$(awk -F'"' '/^[ \t]*domain_suffix[ \t]*=/{print $2; exit}' "$CONFIG" || true)"
echo "当前 domain_suffix = '${CUR:-<未设置>}'  →  目标 '$SUFFIX'"
if [ "$CUR" = "$SUFFIX" ]; then
  echo "已是目标值，无需改动。"
  exit 0
fi

TS="$(date +%Y%m%d-%H%M%S)"
BACKUP="${CONFIG}.bak.${TS}"
cp -a "$CONFIG" "$BACKUP"
echo "已备份: $BACKUP"

# 段感知改写：仅在 [server.magic_dns] 段内设置 domain_suffix。
#   - 段内已有该键（含被注释）→ 原地替换；
#   - 段内无该键 → 段末插入；
#   - 全文无该段 → 文件末尾追加该段（边界情况，正常 config 不会走到）。
awk -v suf="$SUFFIX" '
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
' "$CONFIG" > "${CONFIG}.new"

echo "--- 改动 diff ---"
diff -u "$BACKUP" "${CONFIG}.new" || true
mv "${CONFIG}.new" "$CONFIG"

echo "重启 ${SERVICE}（SIGTERM graceful drain → 客户端重连）..."
systemctl restart "$SERVICE"

ok=0; st=""
for _ in $(seq 1 15); do
  st="$(systemctl is-active "$SERVICE" 2>/dev/null || true)"
  [ "$st" = active ] && { ok=1; break; }
  [ "$st" = failed ] && break
  sleep 1
done

if [ "$ok" != 1 ]; then
  echo "!! 服务未能回到 active（状态=${st}），自动回滚到备份 $BACKUP ..." >&2
  cp -a "$BACKUP" "$CONFIG"
  systemctl restart "$SERVICE" || true
  echo "--- journalctl -u $SERVICE 最近 40 行 ---" >&2
  journalctl -u "$SERVICE" -n 40 --no-pager >&2 || true
  echo "已回滚到旧后缀。请看上面日志排错后再试。" >&2
  exit 1
fi

echo "✓ $SERVICE 已 active。"
echo "--- MagicDNS 启动确认（应出现 suffix=${SUFFIX}）---"
journalctl -u "$SERVICE" --no-pager -n 300 2>/dev/null | grep -F 'magic-dns' | tail -3 \
  || echo "（最近日志未见 magic-dns 行；可手动: journalctl -u $SERVICE | grep magic-dns）"
echo "完成：domain_suffix 已改为 '$SUFFIX'。各客户端重连一次即自动使用新后缀。"
WORKER_EOF

# ── 分发：远程 SSH 或本地执行 ──
if [ -n "${SSH_HOST:-}" ]; then
  SSH_OPTS=(-o StrictHostKeyChecking=no -o ConnectTimeout=30 -o ServerAliveInterval=5)
  REMOTE_CMD="SUFFIX=$(printf %q "$SUFFIX") CONFIG=$(printf %q "$CONFIG") SERVICE=$(printf %q "$SERVICE") bash -s"
  if [ -n "${SSH_PASS:-}" ]; then
    command -v sshpass >/dev/null || { echo "FATAL: 需要 sshpass（brew install hudochenkov/sshpass/sshpass），或改用 SSH 密钥（不设 SSH_PASS）。" >&2; exit 1; }
    printf '%s' "$WORKER" | sshpass -p "$SSH_PASS" ssh "${SSH_OPTS[@]}" "root@${SSH_HOST}" "$REMOTE_CMD"
  else
    printf '%s' "$WORKER" | ssh "${SSH_OPTS[@]}" "root@${SSH_HOST}" "$REMOTE_CMD"
  fi
else
  echo "（本地模式：假定当前机器就是 nanotun 服务器）"
  printf '%s' "$WORKER" | SUFFIX="$SUFFIX" CONFIG="$CONFIG" SERVICE="$SERVICE" bash -s
fi
