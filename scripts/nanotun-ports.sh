#!/usr/bin/env bash
# nanotun-ports.sh —— 从**实际配置**里读出三个对外端口。
#
# 装机脚本、卸载脚本、环境自检都要回答同一个问题:「这台机器对外听哪几个端口」。
# 在此之前三处各自把 8443/443/7443 写死,于是改过端口的机器上同时出三种错:
#
#   · 防火墙放行的是 8443,而 REALITY 实际在 9443 —— 客户端连不上,而屏幕上打着
#     「✓ ufw 放行：8443/tcp」,一切看着都对(2026-08-27 实测)。
#   · 状态自检去看 8443,看不到,报「! 没听上:8443/tcp(REALITY)」并跟一大段诊断 ——
#     指向「服务没起来」这个错误结论,而服务好好地在 9443 上跑着。
#   · 卸载时收回的也是那三条写死的规则,自定义端口那条被永久留在防火墙里。
#
# 这条路不是边角:环境自检遇到端口被占时,给出的建议正是「去改 [reality] 的 listen_addr」。
# 照做的人恰好落进上面三个坑。
#
# 用法:source 本文件,然后 nanotun_load_ports [config.toml 路径];结果放在:
#   NT_PORT_REALITY  REALITY 的 tcp 端口
#   NT_PORT_HY2      hy2 的**主** udp 端口(开了端口跳跃时是列表里第一个 —— nanotund
#                    只在首端口 listen,其余靠 iptables REDIRECT 过来)
#   NT_PORT_WEB      Web 后台 tcp 端口
#   NT_HY2_SPECS     hy2 要放行的全部条目,空格分隔;区间保留 a-b 形态,由调用方按
#                    自己那套语法渲染(ufw 要 a:b,firewalld 要 a-b)
#
# 配置文件不存在时(全新机器,配置装完才有)一律回落到默认值 —— 那时默认就是对的。

NT_DEFAULT_REALITY=8443
NT_DEFAULT_HY2=443
NT_DEFAULT_WEB=7443

# 取某个段里的 listen_addr。空白类用 [ \t] 而非 [[:space:]]:mawk 1.3.3(老 Ubuntu /
# Debian 的默认 awk)不认 POSIX 字符类,会永不匹配 —— 与 set-magic-suffix.sh 同口径。
_nt_listen_addr() { # _nt_listen_addr <配置文件> <段名>
  [ -f "$1" ] || return 1
  awk -v want="[$2]" '
    /^[ \t]*\[/ { sec = $0; sub(/^[ \t]*/, "", sec); sub(/[ \t]*$/, "", sec) }
    sec == want && /^[ \t]*listen_addr[ \t]*=/ {
      if (match($0, /"[^"]*"/)) { print substr($0, RSTART+1, RLENGTH-2); exit }
    }
  ' "$1" 2>/dev/null
}

# 从 host:port 里取端口。IPv6 字面量([::1]:443)也吃得下 —— 取最后一个冒号之后的部分。
_nt_port_of() { # _nt_port_of <listen_addr>
  printf '%s' "${1##*:}"
}

nanotun_load_ports() { # nanotun_load_ports [config.toml] [web.env]
  local cfg="${1:-/etc/nanotun/config.toml}"
  local envf="${2:-/etc/nanotun/web.env}"
  local raw port

  NT_PORT_REALITY="$NT_DEFAULT_REALITY"
  NT_PORT_HY2="$NT_DEFAULT_HY2"
  NT_PORT_WEB="$NT_DEFAULT_WEB"
  NT_HY2_SPECS=""

  raw="$(_nt_listen_addr "$cfg" reality || true)"
  port="$(_nt_port_of "$raw")"
  case "$port" in ''|*[!0-9]*) ;; *) NT_PORT_REALITY="$port" ;; esac

  # hy2 支持端口跳跃:listen_addr = ":443,8443,5000-5100"。首端口是真正 listen 的那个,
  # 其余由 iptables REDIRECT 过来 —— 但防火墙得**全部**放行,否则跳过去的包在门口就没了。
  raw="$(_nt_listen_addr "$cfg" hysteria || true)"
  raw="$(_nt_port_of "$raw")"
  if [ -n "$raw" ]; then
    local first="" item
    local IFS=,
    for item in $raw; do
      case "$item" in
        ''|*[!0-9-]*) continue ;;   # 认不出来的条目跳过,别把垃圾喂给 ufw
      esac
      [ -n "$first" ] || first="${item%%-*}"
      NT_HY2_SPECS="$NT_HY2_SPECS $item"
    done
    case "$first" in ''|*[!0-9]*) ;; *) NT_PORT_HY2="$first" ;; esac
  fi
  # 没解析出任何条目(配置不存在 / 写法认不得)时,按默认那一个来。
  [ -n "${NT_HY2_SPECS// /}" ] || NT_HY2_SPECS="$NT_PORT_HY2"
  NT_HY2_SPECS="${NT_HY2_SPECS# }"

  # Web 后台的监听地址不在 config.toml 里 —— 它由 nanotun-web 读 NANOTUN_WEB_LISTEN
  # 决定(systemd 单元 EnvironmentFile 指向 web.env),没设就是内置默认 0.0.0.0:7443。
  if [ -f "$envf" ]; then
    raw="$(awk -F= '/^[ \t]*NANOTUN_WEB_LISTEN[ \t]*=/ {sub(/^[^=]*=/, ""); v=$0} END {print v}' "$envf" 2>/dev/null)"
    raw="${raw%\"}"; raw="${raw#\"}"; raw="${raw%\'}"; raw="${raw#\'}"
    raw="$(printf '%s' "$raw" | tr -d '[:space:]')"
    port="$(_nt_port_of "$raw")"
    case "$port" in ''|*[!0-9]*) ;; *) NT_PORT_WEB="$port" ;; esac
  fi
}
