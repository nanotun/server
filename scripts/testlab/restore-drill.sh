#!/usr/bin/env bash
# 灾难恢复演练:备份 → 把库彻底删掉 → 还原 → 逐字对账。
#
#   scripts/testlab/lab.sh drill          常用入口,不必直接调这个文件
#
# ── 为什么要有它 ────────────────────────────────────────────────────────────
# 没验过还原的备份不叫备份。scripts/e2e 那边只验 `restore` 的守卫会拒绝,不敢真去
# 覆盖生产库 —— 三台真机是共用环境,盖坏了代价太大(见 scripts/e2e/README.md 的
# 「已知边界」)。而这里的假 VPS 本来就是用完即弃的,正好补上那一段:
# 停服 → 还原 → 启动 → 校验,一整条走完。
#
# 顺带把 restore 的每一道守卫都真的踩一遍。它们平时不出声,只在灾难现场出声,
# 而那种时候人手抖、终端里贴的是从聊天记录翻出来的命令 —— 守卫失灵的代价是
# 「生产库当场报废且没有回头路」。
#
# ── 它测什么 ──────────────────────────────────────────────────────────────
#   1. 热备份(服务不停)拿得到强一致快照,且落盘就是 0600
#   2. 服务还开着时 restore 拒绝
#   3. 只停了 nanotun、漏停 nanotun-web 时 restore 也拒绝(并点名是谁还占着)
#   4. 坏源一律拒绝:不是库 / 半截截断 / 是合法 sqlite 但不是 nanotun 的库
#   5. 没有 TTY 又没给 --yes 时什么都不做,并以非 0 退出
#   6. 库整个删掉之后,服务照样 active、静默重建空库(这是真实行为,不是 bug)
#   7. /setup 抢占入口在库丢失后的去向 —— 按这台机器的装法分别断言
#   8. 还原之后用户 / 后台管理员 / 设置逐字回到灾难前,旧库留了 .pre-restore-* 后悔路
set -euo pipefail

CONTAINER=""
WEB_URL=""
while (( $# )); do
  case "$1" in
    --container) CONTAINER="${2:?--container 后面要跟容器名}"; shift 2 ;;
    --base)      WEB_URL="${2:?--base 后面要跟 Web 地址}"; shift 2 ;;
    *) echo "不认识的参数 $1" >&2; exit 2 ;;
  esac
done
[ -n "$CONTAINER" ] || { echo "要 --container" >&2; exit 2; }

if [ -t 1 ]; then
  C_OK=$'\033[1;32m'; C_ERR=$'\033[1;31m'; C_STEP=$'\033[1;36m'; C_OFF=$'\033[0m'
else
  C_OK=''; C_ERR=''; C_STEP=''; C_OFF=''
fi

PASSN=0; FAILN=0
step()  { printf '\n%s══ %s%s\n' "$C_STEP" "$*" "$C_OFF"; }
check() { # check <名字> <条件是否成立:0/1> [细节]
  if [ "$2" = 0 ]; then
    PASSN=$((PASSN+1)); printf '  %sPASS%s  %s%s\n' "$C_OK" "$C_OFF" "$1" "${3:+  — $3}"
  else
    FAILN=$((FAILN+1)); printf '  %sFAIL%s  %s%s\n' "$C_ERR" "$C_OFF" "$1" "${3:+  — $3}"
  fi
}

DB=/var/lib/nanotun/nanotun.db
dex()  { docker exec "$CONTAINER" "$@"; }
adm()  { docker exec "$CONTAINER" nanotun-admin --db-path "$DB" "$@"; }
# 快照口径:CLI 的表格输出不本地化,逐字比得过。
snap() { { adm user list; adm webadmin list; adm setting list; } 2>&1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

step "0. 先造点身家出来"
adm user create drill_alice >/dev/null 2>&1 || true
adm user create drill_bob   >/dev/null 2>&1 || true
adm setting set server_dial_host 198.51.100.7 >/dev/null 2>&1 || true
snap > "$WORK/before.txt"
check "记下灾难前的状态" 0 "$(grep -c . "$WORK/before.txt") 行"

step "1. 服务不停,热备份"
dex rm -f /var/tmp/drill.db >/dev/null 2>&1 || true
if adm backup /var/tmp/drill.db >/dev/null 2>&1; then rc=0; else rc=1; fi
check "备份拿到了" "$rc"
mode="$(dex stat -c %a /var/tmp/drill.db 2>/dev/null || echo '?')"
# 备份库里是全套密材(PSK 哈希 / TOTP secret / mTLS key),同机别的用户不该读得到。
check "备份是 0600" "$([ "$mode" = 600 ] && echo 0 || echo 1)" "实际 $mode"

# 跑一次 restore 并把「退出码」和「说了什么」一起带回来,免得为了两条断言跑两遍。
try_restore() { out="$(adm restore "$1" --yes 2>&1)" && rc=0 || rc=$?; }

step "2. 服务还开着就 restore"
try_restore /var/tmp/drill.db
check "被拒绝" "$([ "$rc" -ne 0 ] && echo 0 || echo 1)" "exit=$rc"
check "说清了是因为服务在跑" "$(echo "$out" | grep -qi 'running server\|服务' && echo 0 || echo 1)"

step "3. 只停 nanotun,漏停 nanotun-web"
dex systemctl stop nanotun
try_restore /var/tmp/drill.db
check "照样被拒绝" "$([ "$rc" -ne 0 ] && echo 0 || echo 1)" "exit=$rc"
# 这一条最要紧:光探 control socket 的话 nanotun-web 探不到,而它同样握着这个库文件。
# 放过去的后果是它继续往一个被换掉的 inode 里写,全程不报错,谁也不会发现。
check "点名了还占着库的进程" "$(echo "$out" | grep -q 'nanotun-web' && echo 0 || echo 1)"

step "4. 坏备份源一律挡在门外"
dex systemctl stop nanotun-web
before_sz="$(dex stat -c %s "$DB")"
dex bash -c 'echo "这不是数据库" > /var/tmp/junk.db; head -c 3000 /var/tmp/drill.db > /var/tmp/trunc.db'
# 合法 sqlite、但不是 nanotun 的库 —— 这种最险:前两道校验全过,盖上去 server 会把它
# 自动迁移成一个「正常」的空库,用户和设备凭空消失且一切看起来都对。
python3 - "$WORK/foreign.db" <<'PY'
import sqlite3, sys
c = sqlite3.connect(sys.argv[1]); c.execute("create table cats(name text)"); c.commit(); c.close()
PY
docker cp "$WORK/foreign.db" "$CONTAINER:/var/tmp/foreign.db" >/dev/null
for f in junk trunc foreign; do
  try_restore "/var/tmp/$f.db"
  check "拒绝 ${f}.db" "$([ "$rc" -ne 0 ] && echo 0 || echo 1)" \
    "$(echo "$out" | tr '\n' ' ' | cut -c1-72)…"
done
check "生产库一个字节没动" "$([ "$(dex stat -c %s "$DB")" = "$before_sz" ] && echo 0 || echo 1)"

step "5. 没有 TTY 又忘了 --yes"
# ssh / 脚本里最常见的写法。这时它问不到人,必须什么都不做并以非 0 退出 ——
# 退 0 会让调用方以为库已经换过来了。
dex nanotun-admin --db-path "$DB" restore /var/tmp/drill.db < /dev/null > "$WORK/tty.txt" 2>&1 && rc=0 || rc=$?
check "非 0 退出" "$([ "${rc:-0}" -ne 0 ] && echo 0 || echo 1)" "exit=${rc:-0}"
check "生产库仍然没动" "$([ "$(dex stat -c %s "$DB")" = "$before_sz" ] && echo 0 || echo 1)"

step "6. 灾难:把库整个删掉再起服务"
dex rm -f "$DB" "$DB-wal" "$DB-shm"
dex systemctl start nanotun nanotun-web
sleep 4
act="$(dex systemctl is-active nanotun nanotun-web | tr '\n' ' ')"
# 库没了服务也不会停 —— 它重建一个空库照常起来。这是真实行为,写在 README 里,
# 之所以要断言是提醒:别指望「服务挂了」来告诉你库丢了,没有任何症状。
check "服务照常 active" "$([ "$act" = "active active " ] && echo 0 || echo 1)" "$act"
check "库被静默重建成空的" "$([ "$(adm user list | tail -n +2 | grep -c .)" = 0 ] && echo 0 || echo 1)"

step "7. 零管理员时 /setup 抢占入口去哪了"
if [ -n "$WEB_URL" ]; then
  code="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 "$WEB_URL/setup" || echo 000)"
  if dex grep -qE '^NANOTUN_WEB_ALLOW_SETUP=(0|false|no)' /etc/nanotun/web.env 2>/dev/null; then
    # 向导装的机器:开关钉在库外,库丢了也顶得住。
    check "web.env 顶住了,/setup 仍然关着" "$([ "$code" = 302 ] && echo 0 || echo 1)" "HTTP $code"
  else
    # 没跑向导、管理员是 CLI 建的:那道关闭只活在库里,库一丢就跟着丢。
    # 这不是回归,是这条装法的真实代价 —— 断言它,是为了它哪天变了有人知道。
    check "没有 web.env,/setup 如实重新敞开" "$([ "$code" = 200 ] && echo 0 || echo 1)" "HTTP $code"
    check "nanotun-web 为此警告过" \
      "$(dex journalctl -u nanotun-web -n 40 --no-pager 2>/dev/null | grep -q 'setup_gate=open' && echo 0 || echo 1)"
  fi
else
  echo "  (没给 --base,跳过 /setup 这一段)"
fi

step "8. 照 README 的三条命令还原"
dex systemctl stop nanotun nanotun-web
try_restore /var/tmp/drill.db
check "restore 成功" "$([ "$rc" = 0 ] && echo 0 || echo 1)" "exit=$rc"
check "旧库留了 .pre-restore-* 后悔路" \
  "$(dex bash -c 'ls /var/lib/nanotun/*.pre-restore-* >/dev/null 2>&1' && echo 0 || echo 1)"
dex systemctl start nanotun nanotun-web
sleep 4
act="$(dex systemctl is-active nanotun nanotun-web | tr '\n' ' ')"
check "两个服务都起来了" "$([ "$act" = "active active " ] && echo 0 || echo 1)" "$act"

step "9. 逐字对账"
snap > "$WORK/after.txt"
if diff -u "$WORK/before.txt" "$WORK/after.txt" > "$WORK/diff.txt" 2>&1; then
  check "用户 / 后台管理员 / 设置与灾难前逐字相同" 0
else
  check "用户 / 后台管理员 / 设置与灾难前逐字相同" 1
  sed -n '1,40p' "$WORK/diff.txt"
fi
# server_id 变了的话,客户端会把同一台服务器当成两台。它在库里,是这次还原的一部分。
sid="$(adm setting list | awk '$1=="server_id"{print $2}')"
check "server_id 回来了" "$([ -n "$sid" ] && grep -q "$sid" "$WORK/before.txt" && echo 0 || echo 1)" "$sid"
# REALITY 私钥 / hy2 口令在 /etc/nanotun/config.toml,不在库里,这一步同时验它们没被牵连。
adm profile show drill_alice > "$WORK/profile.txt" 2>&1 \
  && check "还出得了客户端配置" 0 \
  || check "还出得了客户端配置" 1 "$(tail -1 "$WORK/profile.txt")"

printf '\n%s\n' "──────────────────────────────────────────────"
printf '合计 %d 项:通过 %d,失败 %d\n' "$((PASSN+FAILN))" "$PASSN" "$FAILN"
[ "$FAILN" = 0 ]
