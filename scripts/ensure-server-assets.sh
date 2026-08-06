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

# 空白一律写成 [ \t],不用 [[:space:]]。
#
# mawk 1.3.3(Ubuntu 18.04、Debian 10 的默认 awk)不认 POSIX 字符类,整条正则于是
# 永不匹配 —— 本函数把每个字段都读成空串,而调用方把「空」理解成「配置里没写」,
# 于是一份证书都不生成。装完看着一路绿灯,nanotund 起来却是 ExitTLSCert(20):
# "open certs/dev-cert.pem: no such file or directory"。
#
# 报错离原因隔了十万八千里:文件确实不在,但为什么不在,要一路倒推回 awk 的方言差异。
# TOML 里的缩进本来就只有空格和制表符两种,[ \t] 覆盖得完完整整,而它是所有 awk
# 实现都认的写法。
read_toml_field() {
  local section="$1" key="$2"
  awk -v sect="[$section]" -v k="$key" '
    $0 == sect { insection=1; next }
    /^\[/ { if (insection) exit }
    insection && $0 ~ "^[ \t]*" k "[ \t]*=" {
      sub(/^[ \t]*[^=]+=[ \t]*/, "")
      gsub(/^["\047]|[\047"]$/, "")
      gsub(/^[ \t]+|[ \t]+$/, "")
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
  # 已经落地的坏 CA 要能自愈。
  #
  # 1.1.1 生成的那份带重复扩展的证书,在 openssl 眼里完全正常(usable_pem 过得去),
  # 所以下面的「缺了才生成」永远不会重签 —— 而「重跑一遍安装」正是文档给出的修复
  # 动作,修不好的话人就卡死在那儿了。这里显式把它判成坏的。
  #
  # 重签会换掉 CA 身份,但这只影响 hy2 的 mTLS:能走到这一步的机器,nanotund 本来就
  # 因为 Go 拒收这份 CA 而起不来,不存在「已经在用它的客户端」。
  if [[ -f "$client_ca_path" ]]; then
    ca_bc_count="$(openssl x509 -in "$client_ca_path" -noout -text 2>/dev/null \
      | grep -c 'X509v3 Basic Constraints' || true)"
    if [[ "${ca_bc_count:-0}" -gt 1 ]]; then
      echo "[ensure-server-assets] client CA 带重复扩展(OpenSSL 1.1.1 的老毛病,Go 会拒收),重新生成 -> $client_ca_path" >&2
      rm -f "$client_ca_path" "$client_ca_key_path"
    fi
  fi

  check_pem_or_die "$client_ca_path" cert
  if ! usable_pem "$client_ca_path" cert; then
    echo "[ensure-server-assets] 未找到 tls_client_ca_file，生成开发用 CA -> $client_ca_path" >&2
    mkdir -p "$(dirname "$client_ca_path")"
    rm -f "$client_ca_path"
    # 这里**不能**用 -addext。
    #
    # OpenSSL 1.1.1 的 -addext 不会覆盖默认 openssl.cnf 里 [v3_ca] 已经写好的
    # basicConstraints,两边各写一份,证书里同一个扩展就出现了两次。openssl 自己
    # 读得下去(x509 -text 照常打印),但 Go 的 x509.ParseCertificate 直接拒绝重复
    # 扩展,AppendCertsFromPEM 于是返回 false —— 表现是 nanotund 起不来:
    # "hysteria: tls_client_ca_file 中无有效 PEM 证书",退 31,服务 crash-loop。
    #
    # 症状离原因很远:文件在、权限对、openssl 验得过,肉眼完全看不出毛病。
    # OpenSSL 3 改掉了这个行为,所以只在 1.1.1 的发行版上炸 —— Ubuntu 20.04、
    # Debian 11、RHEL/Rocky 8 全在其列,而这些恰恰是自建用户手上最多的老 LTS。
    #
    # 改用 -config 指一份只含所需扩展的临时配置:默认 cnf 的 x509_extensions 不再
    # 参与,1.1.1 和 3.x 上得到的都是干净的单份扩展。
    ca_cnf="$(mktemp)"
    cat >"$ca_cnf" <<'CACNF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = nanotun-client-ca
O = nanotun-deploy
[v3_nanotun_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
CACNF
    openssl req -x509 -newkey rsa:2048 -nodes \
      -keyout "$client_ca_key_path" -out "$client_ca_path" -days 3650 \
      -config "$ca_cnf" -extensions v3_nanotun_ca
    rm -f "$ca_cnf"
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
