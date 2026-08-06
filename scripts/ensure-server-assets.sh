#!/usr/bin/env bash
# 在部署机（WorkingDirectory=BASE）上运行：按 config.toml 的 [hysteria] 补全缺失的 hy2 TLS 与 masquerade/index.html
# 用法: bash ensure-server-assets.sh [BASE 目录|config.toml 路径]
#   缺省 BASE=/etc/nanotun(标准 install-self-hosted 布局,CFG=$BASE/config.toml);
#   传源码树根时自动找 cmd/nanotund/config.toml。
set -euo pipefail

ARG="${1:-/etc/nanotun}"
if [[ -f "$ARG" ]]; then
  CFG="$ARG"
  BASE="$(cd "$(dirname "$ARG")" && pwd)"
elif [[ -f "$ARG/config.toml" ]]; then
  BASE="$ARG"
  CFG="$ARG/config.toml"
else
  BASE="$ARG"
  CFG="$ARG/cmd/nanotund/config.toml"
fi

if [[ ! -f "$CFG" ]]; then
  echo "[ensure-server-assets] 跳过：不存在 $CFG" >&2
  exit 0
fi

read_toml_field() {
  local section="$1" key="$2"
  awk -v sect="[$section]" -v k="$key" '
    $0 == sect { insection=1; next }
    /^\[/ { if (insection) exit }
    insection && $0 ~ "^[[:space:]]*" k "[[:space:]]*=" {
      sub(/^[[:space:]]*[^=]+=[[:space:]]*/, "")
      gsub(/^["\047]|[\047"]$/, "")
      gsub(/^[[:space:]]+|[[:space:]]+$/, "")
      print
      exit
    }
  ' "$CFG"
}

read_hysteria_field() { read_toml_field hysteria "$1"; }

# usable_pem <path> <cert|key> —— 判断一份 PEM 是不是真能用。
#
# 从前只判 `-f`：文件在就算数。磁盘写满 / 恢复备份中断留下的 0 字节证书因此被当成
# 「已经有了」而跳过，机器起不来（ExitTLSCert），而文档教的修复手段正是「重跑一遍
# install.sh」—— 它什么也不会做，人只能自己去猜要删哪个文件。
#
# 两种坏法分开处置，理由是代价不同：
#   - 0 字节：里面没有任何信息，删了不会丢东西，直接当缺失重新生成。
#   - 非空但解析不出来：可能只是权限/编码问题，也可能还有备份能救。重签等于换掉服务器
#     身份、踢掉所有已发出去的客户端配置 —— 这种不可逆的事不该由脚本替人决定。
usable_pem() {
  local p="$1" kind="$2"
  [[ -s "$p" ]] || return 1
  case "$kind" in
    cert) openssl x509 -in "$p" -noout >/dev/null 2>&1 || return 2 ;;
    key)  openssl pkey -in "$p" -noout >/dev/null 2>&1 || return 2 ;;
  esac
  return 0
}

# check_pem_or_die <path> <kind> —— 非空但坏掉时停下来说清楚,别默默覆盖。
check_pem_or_die() {
  local p="$1" kind="$2" rc=0
  # 必须捕获返回码:脚本开了 errexit,裸调一个返回非 0 的函数会当场把整个脚本打断。
  usable_pem "$p" "$kind" || rc=$?
  case "$rc" in
    2) echo "[ensure-server-assets] $p 存在但不是合法的 ${kind}(内容损坏?)。
    没有替你重新生成 —— 重签会换掉服务器身份,已发出去的客户端配置全部作废。
    先确认有没有备份可恢复;确实要重来的话删掉它再跑一次本脚本。" >&2
       exit 1 ;;
  esac
}

gen_self_signed() {
  # gen_self_signed <cert_path> <key_path> <subject> —— 缺文件时生成自签（带 SAN，失败退回无 SAN）。
  local cert_path="$1" key_path="$2" subj="$3"
  check_pem_or_die "$cert_path" cert
  check_pem_or_die "$key_path" key
  if usable_pem "$cert_path" cert && usable_pem "$key_path" key; then
    return 0
  fi
  # 走到这里说明至少一边是缺失或 0 字节。两边一起重签:半新半旧的证书/私钥配不上对。
  rm -f "$cert_path" "$key_path"
  echo "[ensure-server-assets] 未找到 TLS 证书，生成自签 -> $cert_path" >&2
  mkdir -p "$(dirname "$cert_path")" "$(dirname "$key_path")"
  if openssl req -x509 -newkey rsa:2048 \
    -keyout "$key_path" -out "$cert_path" -days 3650 -nodes \
    -subj "$subj" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null; then
    :
  else
    openssl req -x509 -newkey rsa:2048 \
      -keyout "$key_path" -out "$cert_path" -days 3650 -nodes \
      -subj "$subj"
  fi
  chmod 600 "$key_path" 2>/dev/null || true
  chmod 644 "$cert_path" 2>/dev/null || true
}

resolve_path() {
  local p="$1"
  [[ -z "$p" ]] && return 1
  if [[ "$p" == /* ]]; then
    printf '%s\n' "$p"
  else
    printf '%s\n' "${BASE}/${p}"
  fi
}

# [server] 数据面 WSS TLS：配置了 tls_cert_file/tls_key_file 但文件缺失时自签。
# install-self-hosted.sh 不再随包分发 dev-*.pem，改由这里按需生成——否则 [server]
# 启了 TLS 却没证书，nanotund 启动即 Fatal。
srv_cert_rel=$(read_toml_field server "tls_cert_file")
srv_key_rel=$(read_toml_field server "tls_key_file")
if [[ -n "${srv_cert_rel// }" && -n "${srv_key_rel// }" ]]; then
  gen_self_signed "$(resolve_path "$srv_cert_rel")" "$(resolve_path "$srv_key_rel")" \
    "/CN=localhost/O=nanotun-deploy"
fi

password=$(read_hysteria_field "password")
cert_rel=$(read_hysteria_field "tls_cert_file")
key_rel=$(read_hysteria_field "tls_key_file")
client_ca_rel=$(read_hysteria_field "tls_client_ca_file")
masq_rel=$(read_hysteria_field "masquerade_dir")

# hy2：已配置主密码且 tls 路径齐全、但文件缺失时生成自签（与 自签证书说明 类似）
if [[ -n "${password// }" && -n "$cert_rel" && -n "$key_rel" ]]; then
  gen_self_signed "$(resolve_path "$cert_rel")" "$(resolve_path "$key_rel")" \
    "/CN=localhost/O=nanotun-deploy"
fi

# mTLS：配置了 tls_client_ca_file 但 CA 证书缺失时生成自签 CA（与 自签证书说明 一致）
if [[ -n "${client_ca_rel// }" ]]; then
  client_ca_path=$(resolve_path "$client_ca_rel")
  client_ca_key_path="${client_ca_path%.pem}-key.pem"
  if [[ "$client_ca_key_path" == "$client_ca_path" ]]; then
    client_ca_key_path="${client_ca_path}.key"
  fi
  check_pem_or_die "$client_ca_path" cert
  if ! usable_pem "$client_ca_path" cert; then
    echo "[ensure-server-assets] 未找到 tls_client_ca_file，生成开发用 CA -> $client_ca_path" >&2
    mkdir -p "$(dirname "$client_ca_path")"
    rm -f "$client_ca_path"
    if openssl req -x509 -newkey rsa:2048 -nodes \
      -keyout "$client_ca_key_path" -out "$client_ca_path" -days 3650 \
      -subj "/CN=nanotun-client-ca/O=nanotun-deploy" \
      -addext "basicConstraints=critical,CA:TRUE" \
      -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null; then
      :
    else
      openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$client_ca_key_path" -out "$client_ca_path" -days 3650 \
        -subj "/CN=nanotun-client-ca/O=nanotun-deploy"
    fi
    chmod 600 "$client_ca_key_path" 2>/dev/null || true
    chmod 644 "$client_ca_path" 2>/dev/null || true
  fi
fi

# masquerade：配置了目录但无 index.html 时写入极简占位页
if [[ -n "${masq_rel// }" ]]; then
  masq_dir=$(resolve_path "$masq_rel")
  idx="${masq_dir}/index.html"
  if [[ ! -f "$idx" ]]; then
    echo "[ensure-server-assets] 生成 masquerade 占位页 -> $idx" >&2
    mkdir -p "$masq_dir"
    cat >"$idx" <<'HTML'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Welcome</title>
</head>
<body>
  <h1>Welcome</h1>
  <p>OK</p>
</body>
</html>
HTML
  fi
fi

echo "[ensure-server-assets] 完成。" >&2
