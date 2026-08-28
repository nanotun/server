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
# 选项：--lang en|zh（界面语言，默认英文；也认 NANOTUN_LANG 与装机时落在
#   /etc/nanotun/lang 的那份）。
#
# 可选环境变量：CONFIG（默认 /etc/nanotun/config.toml）、SERVICE（默认 nanotun）。
set -euo pipefail

# ── 语言 ─────────────────────────────────────────────────────────────────────
# 默认英文。优先级:--lang > NANOTUN_LANG > /etc/nanotun/lang(装机时落下的)> en。
# 这里不问语言:本脚本是装好之后由人单独敲的,读落盘的那份就跟这台机器装机时选的一致。
#
# 文案的组织方式:两种语言**并排写在调用处**(tsel / *_t),不抽成 key → 文案的目录。
# 理由见 scripts/install.sh 里同名那节 —— 这些提示几乎每句都在插值,搬进目录得把每处
# 插值改写成 %s 参数,错了还不会有任何东西红;而每句提示上面那段「为什么这么措辞」的
# 注释也会和它解释的文案隔开好几百行。
NT_LANG=en

nt_lang_normalize() {
  case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')" in
    en|en[-_]*|english)      printf 'en' ;;
    zh|zh[-_]*|chinese|cn)   printf 'zh' ;;
    *)                       printf '' ;;
  esac
}

_nt_l=""
for _nt_a in "$@"; do
  case "$_nt_a" in
    --lang=*) _nt_l="$(nt_lang_normalize "${_nt_a#--lang=}")" ;;
    --lang)   _nt_l=__next__ ;;
    *)        [ "$_nt_l" = __next__ ] && _nt_l="$(nt_lang_normalize "$_nt_a")" ;;
  esac
done
[ "$_nt_l" = __next__ ] && _nt_l=""
if [ -n "$_nt_l" ]; then
  NT_LANG="$_nt_l"
elif [ -n "$(nt_lang_normalize "${NANOTUN_LANG:-}")" ]; then
  NT_LANG="$(nt_lang_normalize "$NANOTUN_LANG")"
elif [ -r /etc/nanotun/lang ] && \
     [ -n "$(nt_lang_normalize "$(head -1 /etc/nanotun/lang 2>/dev/null)")" ]; then
  NT_LANG="$(nt_lang_normalize "$(head -1 /etc/nanotun/lang 2>/dev/null)")"
fi
unset _nt_l _nt_a
export NANOTUN_LANG="$NT_LANG"

# tsel <英文> <中文> —— 按当前语言选一份。
tsel() { if [ "$NT_LANG" = zh ]; then printf '%s' "$2"; else printf '%s' "$1"; fi; }

# --lang 已经在上面扫过了(必须早于任何一句提示),这里只负责把它从参数里吃掉、顺带校验值。
# 吃掉这一步是必需的:本脚本的位置参数就是后缀,`--lang` 留在里面会被下面当成后缀,
# 而这正是历史上 `--help` 踩过的坑 —— 收到的是一句「后缀不合法」,而人压根没在写后缀。
# 值不合法要当场说,别默默回落到英文:那样 `--lang fr` 看着像生效了。
_nt_rest=()
while [ $# -gt 0 ]; do
  case "$1" in
    --lang)
      if [ -z "$(nt_lang_normalize "${2:-}")" ]; then
        printf '%s\n' "$(tsel \
          "FATAL: --lang takes en or zh (got '${2:-}')" \
          "FATAL: --lang 只认 en 或 zh(收到 '${2:-}')")" >&2
        exit 2
      fi
      shift 2 ;;
    --lang=*)
      if [ -z "$(nt_lang_normalize "${1#--lang=}")" ]; then
        printf '%s\n' "$(tsel \
          "FATAL: --lang takes en or zh (got '${1#--lang=}')" \
          "FATAL: --lang 只认 en 或 zh(收到 '${1#--lang=}')")" >&2
        exit 2
      fi
      shift ;;
    *) _nt_rest+=("$1"); shift ;;
  esac
done
set -- ${_nt_rest[@]+"${_nt_rest[@]}"}
unset _nt_rest

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
      # 中文那份打的是文件头那段注释;英文那份只能是这里手写的 —— 那段注释是给维护者看的,
      # 一直是中文。
      if [ "$NT_LANG" = zh ]; then
        awk 'NR>1 && /^#/ {sub(/^#[ \t]?/,""); print; next} NR>1 {exit}' "$0"
      else
        cat <<EOF
set-magic-suffix.sh — change nanotun's MagicDNS domain_suffix and restart the service.

Why a restart is needed: domain_suffix is not on the SIGHUP hot-reload list (see
  applyConfigReload / classifyDeferredFields in cmd/nanotund/reload.go). It is read
  into the magicDNSResolved snapshot when startMagicDNS() starts, so only
  "systemctl restart nanotun" makes a new value take effect. SIGTERM goes through a
  graceful drain (it broadcasts LinkTypeClose), so clients reconnect cleanly.

What keeps this safe: back up config.toml → section-aware, surgical rewrite (only
  [server.magic_dns].domain_suffix is touched) → restart → poll the service state.
  If it does not come back to active within the timeout (say the config was broken
  and the unit landed in failed because of RestartPreventExitStatus), the backup is
  restored and the service restarted. It will not leave your server down.

Usage:
  A) Remote (run on your own machine, over SSH to the server):
       SSH_HOST=<nanotun server IP> SSH_PASS='<password>' ./scripts/set-magic-suffix.sh nanotun
     or with an SSH key (leave SSH_PASS unset):
       SSH_HOST=<nanotun server IP> ./scripts/set-magic-suffix.sh nanotun

  B) Local (already SSHed in — run it on the server itself, as root):
       sudo ./scripts/set-magic-suffix.sh nanotun

Note: the target is the **gateway server running nanotun** (the backend clients dial),
  not one of the client nodes in the mesh. Every gateway needs its own run.

Options: --lang en|zh (interface language, default en; NANOTUN_LANG and the
  /etc/nanotun/lang written at install time are honoured too).

Optional environment: CONFIG (default /etc/nanotun/config.toml), SERVICE (default nanotun).
EOF
      fi
    elif [ "$NT_LANG" = zh ]; then
      cat <<EOF
用法: sudo $(basename "$0") <新后缀>        例如: sudo $(basename "$0") nanotun

修改 nanotun 的 MagicDNS 后缀(客户端解析 *.<后缀> → mesh 虚拟 IP)并重启服务。
domain_suffix 不在 SIGHUP 热更白名单里,只有重启才生效;重启走 graceful drain,
客户端会自动重连。

先备份 config.toml → 只改 [server.magic_dns].domain_suffix → 重启 → 轮询状态;
超时内没回到 active 就自动回滚备份并重启,不会把服务器改趴。

后缀只允许小写字母 / 数字 / 连字符,可点分多级。'local' 与 mDNS 冲突,禁用。

选项:--lang en|zh(界面语言,默认英文;也认 NANOTUN_LANG 与 /etc/nanotun/lang)。

可选环境变量:CONFIG(默认 /etc/nanotun/config.toml)、SERVICE(默认 nanotun)。
EOF
    else
      cat <<EOF
Usage: sudo $(basename "$0") <new-suffix>        e.g.: sudo $(basename "$0") nanotun

Change nanotun's MagicDNS suffix (clients resolve *.<suffix> → mesh virtual IP) and
restart the service. domain_suffix is not on the SIGHUP hot-reload list, so only a
restart makes it take effect; the restart goes through a graceful drain and clients
reconnect on their own.

First config.toml is backed up → only [server.magic_dns].domain_suffix is changed →
restart → poll the state; if it does not come back to active within the timeout, the
backup is restored and the service restarted, so your server is not left down.

A suffix may use lowercase letters / digits / hyphens, dot-separated into several
labels. 'local' clashes with mDNS and is refused.

Options: --lang en|zh (interface language, default en; NANOTUN_LANG and
/etc/nanotun/lang are honoured too).

Optional environment: CONFIG (default /etc/nanotun/config.toml), SERVICE (default nanotun).
EOF
    fi
    exit 0 ;;
  # 别的 -开头参数同样别当后缀。判死的措辞得指向 --help,而不是让人对着一条
  # 「后缀不合法」去想自己的后缀哪里写错了 —— 他压根没在写后缀。
  -?*)
    echo "$(tsel \
      "FATAL: unknown argument '$1' (this command takes one suffix and nothing else; see --help)" \
      "FATAL: 未知参数 '$1'（本命令只接一个后缀;--help 看用法）")" >&2; exit 2 ;;
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
    echo "$(tsel \
      "Usage: [SSH_HOST=.. SSH_PASS=..] ./scripts/${me} <new-suffix>    e.g.: ./scripts/${me} nanotun" \
      "用法: [SSH_HOST=.. SSH_PASS=..] ./scripts/${me} <新后缀>    例如: ./scripts/${me} nanotun")" >&2
  else
    echo "$(tsel \
      "Usage: sudo ${me} <new-suffix>    e.g.: sudo ${me} nanotun    (--help for the details)" \
      "用法: sudo ${me} <新后缀>    例如: sudo ${me} nanotun    (--help 看详细说明)")" >&2
  fi
  exit 2
fi

# 后缀合法性：小写 DNS 标签（字母数字 + 连字符，可点分多级）。既防命令注入，也防写坏 TOML。
if ! printf '%s' "$SUFFIX" | grep -Eq '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$'; then
  echo "$(tsel \
    "FATAL: not a valid suffix (only lowercase letters/digits/hyphens, dot-separated into several labels): '$SUFFIX'" \
    "FATAL: 后缀不合法（只允许小写字母/数字/连字符，可用点分多级）：'$SUFFIX'")" >&2
  exit 2
fi
# 每一级标签不超过 63 字节 —— DNS 的硬上限(RFC 1035)。上面那条正则只管字符集不管长度,
# 于是 80 个字符的单标签也能过,而它拼出来的名字在任何解析器上都是非法的:改是改成功了,
# 客户端却谁都解析不动,而症状(某些名字不通)跟「后缀太长」看不出关系。
if printf '%s' "$SUFFIX" | awk -F. '{ for (i = 1; i <= NF; i++) if (length($i) > 63) exit 0; exit 1 }'; then
  echo "$(tsel \
    "FATAL: one of the labels is longer than 63 characters (the DNS label limit): '$SUFFIX'" \
    "FATAL: 后缀里有超过 63 个字符的一级（DNS 标签上限）：'$SUFFIX'")" >&2
  exit 2
fi
case "$SUFFIX" in
  # *.local 也要拦,不能只拦 local 本身。禁用它的理由是 mac/iOS 和装了 Avahi 的 Linux
  # 把整个 .local 交给 mDNS 组播解析 —— 那对 lan.local、home.local 一样成立,而这两个
  # 恰恰是人顺手会写的(想避开 lan 的人写 lan.local,等于从一个坑跳进更深的一个)。
  # 原来是精确匹配 local,于是 lan.local 一路绿灯装完,客户端在 mac 上永远解析不到。
  local|*.local)
    if [ "$NT_LANG" = zh ]; then
      echo "FATAL: '$SUFFIX' 落在 .local 下 —— mac/iOS 与 Avahi 把整个 .local 交给 mDNS 组播," >&2
      echo "       这些名字到不了 nanotun 的解析器。换一个不带 .local 的后缀。" >&2
    else
      echo "FATAL: '$SUFFIX' sits under .local — mac/iOS and Avahi hand all of .local to mDNS" >&2
      echo "       multicast, so these names never reach nanotun's resolver. Pick a suffix" >&2
      echo "       that is not under .local." >&2
    fi
    exit 2 ;;
  lan|home|home.arpa|internal|corp|*.lan|*.home|*.home.arpa|*.internal|*.corp)
    echo "$(tsel \
      "!! Warning: '$SUFFIX' may clash with home routers / reserved domains (which is exactly why one migrates the suffix). Continuing in 3 seconds, Ctrl-C to cancel." \
      "!! 警告: '$SUFFIX' 可能与家用路由器 / 保留域冲突（这正是要迁移后缀的原因）。3 秒后继续，Ctrl-C 取消。")" >&2
    sleep 3 ;;
esac

# ── 真正在服务器上执行的 worker（本地/远程共用；从 stdin 读入，参数经 env 传入）──
read -r -d '' WORKER <<'WORKER_EOF' || true
set -euo pipefail
: "${SUFFIX:?}"; : "${CONFIG:?}"; : "${SERVICE:?}"

# worker 自己再定一遍语言。它是另一个 shell —— 远程形态下甚至是另一台机器上的 bash,
# 只拿得到下面显式传过去的那几个环境变量,外层的 NT_LANG / tsel 一概不在。
# 这里只认 NANOTUN_LANG:目标机上的 /etc/nanotun/lang 不该压掉调用方这次选的语言。
NT_LANG="$(printf '%s' "${NANOTUN_LANG:-en}" | tr '[:upper:]' '[:lower:]')"
case "$NT_LANG" in zh|zh[-_]*|chinese|cn) NT_LANG=zh ;; *) NT_LANG=en ;; esac
tsel() { if [ "$NT_LANG" = zh ]; then printf '%s' "$2"; else printf '%s' "$1"; fi; }

if [ "$(id -u)" != 0 ]; then
  echo "$(tsel \
    "FATAL: root is required (systemctl / writing ${CONFIG}). Use sudo, or SSH in as root." \
    "FATAL: 需要 root（systemctl / 写 ${CONFIG}）。请用 sudo，或以 root SSH。")" >&2
  exit 1
fi
[ -f "$CONFIG" ] || { echo "$(tsel \
  "FATAL: config file not found: $CONFIG" \
  "FATAL: 找不到配置文件 $CONFIG")" >&2; exit 1; }

# 空白写 [ \t] 而不是 [[:space:]]:mawk 1.3.3(Ubuntu 18.04 / Debian 10 的默认 awk)
# 不认 POSIX 字符类,正则会永不匹配 —— 这里的后果是「读不到现有值」被当成「还没设过」,
# 下面那段改写于是走插入分支,给配置里塞进第二个 domain_suffix。
CUR="$(awk -F'"' '/^[ \t]*domain_suffix[ \t]*=/{print $2; exit}' "$CONFIG" || true)"
echo "$(tsel \
  "current domain_suffix = '${CUR:-<unset>}'  →  target '$SUFFIX'" \
  "当前 domain_suffix = '${CUR:-<未设置>}'  →  目标 '$SUFFIX'")"
if [ "$CUR" = "$SUFFIX" ]; then
  echo "$(tsel "Already the target value, nothing to change." "已是目标值，无需改动。")"
  exit 0
fi

TS="$(date +%Y%m%d-%H%M%S)"
BACKUP="${CONFIG}.bak.${TS}"
cp -a "$CONFIG" "$BACKUP"
echo "$(tsel "Backed up: $BACKUP" "已备份: $BACKUP")"

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

echo "$(tsel "--- diff of the change ---" "--- 改动 diff ---")"
diff -u "$BACKUP" "${CONFIG}.new" || true
mv "${CONFIG}.new" "$CONFIG"

echo "$(tsel \
  "Restarting ${SERVICE} (SIGTERM graceful drain → clients reconnect) ..." \
  "重启 ${SERVICE}（SIGTERM graceful drain → 客户端重连）...")"
systemctl restart "$SERVICE"

ok=0; st=""
for _ in $(seq 1 15); do
  st="$(systemctl is-active "$SERVICE" 2>/dev/null || true)"
  [ "$st" = active ] && { ok=1; break; }
  [ "$st" = failed ] && break
  sleep 1
done

if [ "$ok" != 1 ]; then
  echo "$(tsel \
    "!! The service did not come back to active (state=${st}); rolling back to the backup $BACKUP ..." \
    "!! 服务未能回到 active（状态=${st}），自动回滚到备份 $BACKUP ...")" >&2
  cp -a "$BACKUP" "$CONFIG"
  systemctl restart "$SERVICE" || true
  echo "$(tsel \
    "--- last 40 lines of journalctl -u $SERVICE ---" \
    "--- journalctl -u $SERVICE 最近 40 行 ---")" >&2
  journalctl -u "$SERVICE" -n 40 --no-pager >&2 || true
  echo "$(tsel \
    "Rolled back to the old suffix. Work out the cause from the log above, then try again." \
    "已回滚到旧后缀。请看上面日志排错后再试。")" >&2
  exit 1
fi

echo "$(tsel "✓ $SERVICE is active." "✓ $SERVICE 已 active。")"
echo "$(tsel \
  "--- MagicDNS startup check (suffix=${SUFFIX} should show up) ---" \
  "--- MagicDNS 启动确认（应出现 suffix=${SUFFIX}）---")"
journalctl -u "$SERVICE" --no-pager -n 300 2>/dev/null | grep -F 'magic-dns' | tail -3 \
  || echo "$(tsel \
       "(no magic-dns line in the recent log; check by hand: journalctl -u $SERVICE | grep magic-dns)" \
       "（最近日志未见 magic-dns 行；可手动: journalctl -u $SERVICE | grep magic-dns）")"
echo "$(tsel \
  "Done: domain_suffix is now '$SUFFIX'. Each client picks up the new suffix after one reconnect." \
  "完成：domain_suffix 已改为 '$SUFFIX'。各客户端重连一次即自动使用新后缀。")"
WORKER_EOF

# ── 分发：远程 SSH 或本地执行 ──
if [ -n "${SSH_HOST:-}" ]; then
  SSH_OPTS=(-o StrictHostKeyChecking=no -o ConnectTimeout=30 -o ServerAliveInterval=5)
  # NANOTUN_LANG 也得显式带过去:ssh 不转发环境变量,少了它远端那半程会退回英文,
  # 一次操作里前后两种语言。
  REMOTE_CMD="SUFFIX=$(printf %q "$SUFFIX") CONFIG=$(printf %q "$CONFIG") SERVICE=$(printf %q "$SERVICE") NANOTUN_LANG=$(printf %q "$NT_LANG") bash -s"
  if [ -n "${SSH_PASS:-}" ]; then
    command -v sshpass >/dev/null || { echo "$(tsel \
      "FATAL: sshpass is required (brew install hudochenkov/sshpass/sshpass), or use an SSH key instead (leave SSH_PASS unset)." \
      "FATAL: 需要 sshpass（brew install hudochenkov/sshpass/sshpass），或改用 SSH 密钥（不设 SSH_PASS）。")" >&2; exit 1; }
    printf '%s' "$WORKER" | sshpass -p "$SSH_PASS" ssh "${SSH_OPTS[@]}" "root@${SSH_HOST}" "$REMOTE_CMD"
  else
    printf '%s' "$WORKER" | ssh "${SSH_OPTS[@]}" "root@${SSH_HOST}" "$REMOTE_CMD"
  fi
else
  echo "$(tsel \
    "(local mode: assuming this machine is the nanotun server)" \
    "（本地模式：假定当前机器就是 nanotun 服务器）")"
  printf '%s' "$WORKER" \
    | SUFFIX="$SUFFIX" CONFIG="$CONFIG" SERVICE="$SERVICE" NANOTUN_LANG="$NT_LANG" bash -s
fi
