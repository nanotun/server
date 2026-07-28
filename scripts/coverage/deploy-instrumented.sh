#!/usr/bin/env bash
# 在服务端就地把三个二进制换成带覆盖插桩的版本，并接好 GOCOVERDIR。
# 在 SRV 上执行。原二进制备份到 <name>.preinstr，用 restore-plain.sh 换回来。
#
# GOCOVERDIR 必须落在 unit 的 ReadWritePaths 里：两个 service 都开着 ProtectHome=yes，
# /root 在它们的 mount namespace 里根本不存在，写不进去只会在日志里留一行
# "coverage meta-data emit failed"，然后静默丢掉全部计数。
set -euo pipefail

COVDIR=/var/lib/nanotun/cov/e2e
BIN=/usr/local/bin

mkdir -p "$COVDIR"
chmod 777 "$COVDIR"

for n in nanotund nanotun-web nanotun-admin; do
  if [ ! -f "$BIN/$n.preinstr" ]; then
    cp -a "$BIN/$n" "$BIN/$n.preinstr"
  fi
done

# nanotun-admin 是 CLI，e2e 通过 ssh 直接调，没有 systemd 可以挂环境变量。
# 真二进制改名放旁边，PATH 上留一层 wrapper 注入 GOCOVERDIR。
install -m 0755 /tmp/cov-bin/nanotund       "$BIN/nanotund"
install -m 0755 /tmp/cov-bin/nanotun-web    "$BIN/nanotun-web"
install -m 0755 /tmp/cov-bin/nanotun-admin  "$BIN/nanotun-admin.real"
cat > "$BIN/nanotun-admin" <<'EOF'
#!/bin/sh
export GOCOVERDIR=/var/lib/nanotun/cov/e2e
exec /usr/local/bin/nanotun-admin.real "$@"
EOF
chmod 0755 "$BIN/nanotun-admin"

for u in nanotun nanotun-web; do
  mkdir -p "/etc/systemd/system/$u.service.d"
  cat > "/etc/systemd/system/$u.service.d/coverage.conf" <<EOF
[Service]
Environment=GOCOVERDIR=$COVDIR
EOF
done

systemctl daemon-reload
systemctl restart nanotun.service
sleep 2
systemctl restart nanotun-web.service
sleep 3

systemctl is-active nanotun.service nanotun-web.service
echo "--- covdir ---"
ls -la "$COVDIR" | head
