#!/usr/bin/env bash
# 阶段 1:出口节点 + MagicDNS。
#
# 核心是 fail-closed:出口不可用时必须**阻断**,而不是悄悄改走服务端出口。
# 这条一旦回归,现象是「网还能上」,不会有任何报错 —— 属于最难靠肉眼发现、
# 后果又最严重的那类(用户以为流量走的是指定出口,实际暴露在服务端 IP 上)。

phase_10_exit() {
  phase_begin "阶段 1 · 出口节点与 MagicDNS"

  # ── MagicDNS ──────────────────────────────────────────────────────────────
  local c_name="${E2E_C_DEVNAME:-vultr}.$E2E_C_USER.$E2E_MAGIC_SUFFIX"
  local a_name="${E2E_A_DEVNAME:-vultr}.$E2E_A_USER.$E2E_MAGIC_SUFFIX"

  check "MagicDNS · A 记录解析到 C 的 vIP" "$E2E_C_VIP4" \
    "$(a "dig +short +time=4 +tries=1 @10.201.0.1 $c_name" | head -1 | tr -d '[:space:]')"
  check "MagicDNS · AAAA 记录" "$E2E_C_VIP6" \
    "$(a "dig +short -t AAAA +time=4 +tries=1 @10.201.0.1 $c_name" | head -1 | tr -d '[:space:]')"

  # 走系统解析器而不是直接问网关:这一条覆盖客户端的 DNS 接管逻辑
  # (systemd-resolved 在不在解析路径上、要不要直接改写 resolv.conf),
  # 历史上「网关能解析但应用解析不了」就是栽在这里。
  local via_resolver
  via_resolver="$(a "getent hosts $a_name" | head -1 | awk '{print $1}' | tr -d '[:space:]')"
  check_match "MagicDNS · 经系统解析器可解析（客户端 DNS 接管生效）" '^[0-9a-fA-F:.]+$' "$via_resolver"

  check "MagicDNS · 未知名字返回 NXDOMAIN（空结果）" "" \
    "$(a "dig +short +time=4 +tries=1 @10.201.0.1 nosuch.$E2E_C_USER.$E2E_MAGIC_SUFFIX" | tr -d '[:space:]')"
  check_match "MagicDNS · 非 magic 域名转发上游" '^[0-9]+\.[0-9]+\.' \
    "$(a "dig +short +time=5 @10.201.0.1 example.com" | head -1 | tr -d '[:space:]')"

  # ── 出口数据面 ────────────────────────────────────────────────────────────
  check_match "出口 · 公网 UDP DNS 可用" '^[0-9]+\.[0-9]+\.' \
    "$(a "dig +short +time=4 +tries=1 +notcp @8.8.8.8 example.com" | head -1 | tr -d '[:space:]')"

  local dl
  dl="$(a "curl -s -o /dev/null -w '%{size_download}' --max-time 60 'https://speed.cloudflare.com/__down?bytes=2000000'" | tr -d '[:space:]')"
  check "出口 · 2MB 下载完整" "2000000" "$dl"

  # MTU 边界:比隧道 MSS 大 1 字节的 DF 包必须被拒。这条能抓住「隧道 MTU 算错」
  # 导致的大包黑洞 —— 小包一切正常,只有大传输会卡死,极难定位。
  local mtu="${E2E_MTU_PROBE:-1252}"
  check_contains "出口 · DF 包 -s $mtu 通过" "1 received" \
    "$(a "ping -c1 -W4 -M do -s $mtu 8.8.8.8 2>&1")"
  check_contains "出口 · DF 包 -s $((mtu + 1)) 被拒（MTU 边界正确）" "Message too long" \
    "$(a "ping -c1 -W4 -M do -s $((mtu + 1)) 8.8.8.8 2>&1")"

  # ── revoke → fail-closed → designate → 自动恢复 ───────────────────────────
  adm_y "exit revoke $E2E_C_DEVICE_ID" >/dev/null
  wait_until "撤销出口资格后 A 公网流量被阻断（fail-closed，未回落服务端出口）" 25 probe_egress_blocked
  # 关键的反面条件:阻断的只该是公网流量,mesh 必须还通。
  check "撤销期间 mesh 仍可达（阻断范围精确）" "0" "$(probe_ping a "$E2E_C_VIP4" && echo 0 || echo 1)"

  adm_y "exit designate $E2E_C_DEVICE_ID" >/dev/null
  wait_until "重新指定出口后自动恢复（无需客户端重连）" 40 probe_egress_is "$E2E_C_HOST"

  # ── 出口离线 → 上线 ───────────────────────────────────────────────────────
  client_c_stop
  wait_until "出口节点离线后阻断" 30 probe_egress_blocked

  client_c_start
  wait_until "出口节点回归后自动恢复" 60 probe_egress_is "$E2E_C_HOST"
  # C 重连后子网宣告要重新生效,后面的阶段依赖它。
  wait_until "出口节点回归后子网重新可达" 30 probe_ping a "$E2E_C_LAN4_HOST"
}
