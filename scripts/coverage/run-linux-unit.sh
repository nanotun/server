#!/usr/bin/env bash
# 在 Linux 机上逐包跑交叉编译好的测试二进制，采集覆盖剖面。
#
# 为什么要这么绕：macOS 上跑单测会漏掉所有 *_linux.go —— 那些文件在 darwin 上根本
# 不参与编译，既不进分子也不进分母，得出的百分比虚高。详见 docs/COVERAGE.md。
#
# CWD 必须是各自的包目录：有测试按相对路径读 fixture / 模板。
set -u

ROOT=/root/nttest
COV=$ROOT/cov
mkdir -p "$COV"
rm -f "$COV"/*.cov "$COV"/*.log

# 包目录 : 二进制名
PKGS="
auth:auth
certs:certs
config:config
store:store
util:util
cmd/nanotund:nanotund
cmd/nanotun-web:nanotun-web
cmd/nanotun-admin:nanotun-admin
"

fail=0
for entry in $PKGS; do
  dir="${entry%%:*}"
  bin="${entry##*:}"
  echo "=== $dir ==="
  cd "$ROOT/src/$dir" || { echo "SKIP $dir (no dir)"; continue; }
  start=$(date +%s)
  "$ROOT/bin/$bin.test" \
    -test.count=1 -test.timeout=60m \
    -test.coverprofile="$COV/$bin.cov" \
    >"$COV/$bin.log" 2>&1
  rc=$?
  dur=$(( $(date +%s) - start ))
  cov=$(grep -o 'coverage: [0-9.]*%' "$COV/$bin.log" | tail -1)
  if [ $rc -ne 0 ]; then
    fail=1
    echo "FAIL rc=$rc ${dur}s $cov"
    grep -E '^(--- FAIL|    --- FAIL|panic)' "$COV/$bin.log" | head -20
  else
    echo "ok ${dur}s $cov"
  fi
done

# 拼成一份：保留一行 mode: 头即可。
#
# 输出**必须**落在 $COV 外面：写在里面的话 "$COV"/*.cov 会把正在写的输出文件
# 自己也匹配进来，tail 读自己写自己，几分钟就能把根分区撑满（踩过一次）。
OUT=$ROOT/unit-linux.cov
{
  echo "mode: set"
  for f in "$COV"/*.cov; do
    [ -f "$f" ] || continue
    tail -n +2 "$f"
  done
} > "$OUT"

echo "=== merged: $(wc -l < "$OUT") lines -> $OUT ==="
exit $fail
