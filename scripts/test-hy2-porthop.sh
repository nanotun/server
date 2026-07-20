#!/usr/bin/env bash
# Hy2 端口跳跃：Go 单测 + Rust probe E2E（Linux root 时含 iptables）。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMMON="${RUST_VPN_CLIENT_LIB_COMMON_DIR:-$(cd "$ROOT/../rust_vpn_client_lib_common" 2>/dev/null && pwd || true)}"

echo "== nanotun util =="
(cd "$ROOT" && go test ./util/... -count=1)

echo "== nanotun-admin profile port hop =="
(cd "$ROOT" && go test ./cmd/nanotun-admin/... -count=1 -run 'PortHop|PortUnion|PlanHy2')

echo "== nanotun server (unit + hy2 port hop, skip legacy integration) =="
export RUST_VPN_CLIENT_LIB_COMMON_DIR="${COMMON}"
(cd "$ROOT/cmd/nanotund" && go test -count=1 -skip 'Integration|Stress|KCPBench|GoroutineLeak' -run 'PortHop|PlanHy2|PortUnionBinds|RustProbe')

if [[ "$(uname -s)" == Linux ]] && [[ "$(id -u)" -eq 0 ]]; then
  echo "== nanotun server iptables E2E (root) =="
  (cd "$ROOT/cmd/nanotund" && go test -count=1 -run 'TestHy2PortHop_E2E|TestHy2PortHop_Iptables')
else
  echo "== skip iptables E2E (need Linux root); run: sudo $0 =="
fi

if [[ -n "${COMMON}" && -f "${COMMON}/Cargo.toml" ]]; then
  echo "== rust_vpn_client_lib_common =="
  (cd "$COMMON" && cargo test -q)
else
  echo "warn: rust_vpn_client_lib_common not found at $COMMON"
fi

echo "OK"
