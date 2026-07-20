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

read_hysteria_field() {
  local key="$1"
  awk -v k="$key" '
    /^\[hysteria\]/ { insection=1; next }
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

resolve_path() {
  local p="$1"
  [[ -z "$p" ]] && return 1
  if [[ "$p" == /* ]]; then
    printf '%s\n' "$p"
  else
    printf '%s\n' "${BASE}/${p}"
  fi
}

password=$(read_hysteria_field "password")
cert_rel=$(read_hysteria_field "tls_cert_file")
key_rel=$(read_hysteria_field "tls_key_file")
client_ca_rel=$(read_hysteria_field "tls_client_ca_file")
masq_rel=$(read_hysteria_field "masquerade_dir")

# hy2：已配置主密码且 tls 路径齐全、但文件缺失时生成自签（与 自签证书说明 类似）
if [[ -n "${password// }" && -n "$cert_rel" && -n "$key_rel" ]]; then
  cert_path=$(resolve_path "$cert_rel")
  key_path=$(resolve_path "$key_rel")
  if [[ ! -f "$cert_path" || ! -f "$key_path" ]]; then
    echo "[ensure-server-assets] 未找到 hy2 TLS，生成自签证书 -> $cert_path" >&2
    mkdir -p "$(dirname "$cert_path")" "$(dirname "$key_path")"
    if openssl req -x509 -newkey rsa:2048 \
      -keyout "$key_path" -out "$cert_path" -days 3650 -nodes \
      -subj "/CN=localhost/O=nanotun-deploy" \
      -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null; then
      :
    else
      openssl req -x509 -newkey rsa:2048 \
        -keyout "$key_path" -out "$cert_path" -days 3650 -nodes \
        -subj "/CN=localhost/O=nanotun-deploy"
    fi
    chmod 600 "$key_path" 2>/dev/null || true
    chmod 644 "$cert_path" 2>/dev/null || true
  fi
fi

# mTLS：配置了 tls_client_ca_file 但 CA 证书缺失时生成自签 CA（与 自签证书说明 一致）
if [[ -n "${client_ca_rel// }" ]]; then
  client_ca_path=$(resolve_path "$client_ca_rel")
  client_ca_key_path="${client_ca_path%.pem}-key.pem"
  if [[ "$client_ca_key_path" == "$client_ca_path" ]]; then
    client_ca_key_path="${client_ca_path}.key"
  fi
  if [[ ! -f "$client_ca_path" ]]; then
    echo "[ensure-server-assets] 未找到 tls_client_ca_file，生成开发用 CA -> $client_ca_path" >&2
    mkdir -p "$(dirname "$client_ca_path")"
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
