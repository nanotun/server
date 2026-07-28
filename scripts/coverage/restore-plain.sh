#!/usr/bin/env bash
# 把服务端从插桩二进制换回采集前的原版，并摘掉 GOCOVERDIR drop-in。
# 在 SRV 上执行。deploy-instrumented.sh 的逆操作。
set -euo pipefail

BIN=/usr/local/bin

for n in nanotund nanotun-web nanotun-admin; do
  if [ -f "$BIN/$n.preinstr" ]; then
    install -m 0755 "$BIN/$n.preinstr" "$BIN/$n"
    rm -f "$BIN/$n.preinstr"
  fi
done
rm -f "$BIN/nanotun-admin.real"

rm -f /etc/systemd/system/nanotun.service.d/coverage.conf
rm -f /etc/systemd/system/nanotun-web.service.d/coverage.conf
rmdir /etc/systemd/system/nanotun.service.d 2>/dev/null || true
rmdir /etc/systemd/system/nanotun-web.service.d 2>/dev/null || true

systemctl daemon-reload
systemctl restart nanotun.service
sleep 2
systemctl restart nanotun-web.service
sleep 3
systemctl is-active nanotun.service nanotun-web.service
