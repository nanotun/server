#!/usr/bin/env bash
# 在 Linux 机上逐包跑交叉编译好的测试二进制，采集覆盖剖面。
#
# 为什么要这么绕：macOS 上跑单测会漏掉所有 *_linux.go —— 那些文件在 darwin 上根本
# 不参与编译，既不进分子也不进分母，得出的百分比虚高。详见 docs/COVERAGE.md。
#
# CWD 必须是各自的包目录：有测试按相对路径读 fixture / 模板。
#
# 目标机需要一套 Go 工具链：web / admin 的子进程冒烟测试会真的 `go build` 出二进制。
# 没有 go 的话那几条不是跳过而是 t.Fatalf（`go test` 一向假定工具链在场），整包 rc=1。
# 装好 Go 之后先在 src/ 里跑一次 `go mod download`：目标机若把默认路由指到 VPN 上，
# 边跑边拉模块会慢到不可用（实测 110 KB/s），临时停掉客户端会话走自己的 WAN 再拉。
set -u

ROOT=/root/nttest
COV=$ROOT/cov
mkdir -p "$COV"
rm -f "$COV"/*.cov "$COV"/*.log

[ -d /usr/local/go/bin ] && export PATH=/usr/local/go/bin:$PATH

# 子进程冒烟测试认这个变量：设了就用 `go build -cover` 编，被测二进制的语句计数
# 落进 GOCOVERDIR。不设的话 web / admin 的 main() 在单测这一侧永远是空白
# （只有 e2e 摸得到），合并账里会被算进「仅 e2e」那一列。
export NANOTUN_SUBPROC_COVERDIR=$ROOT/covdir
rm -rf "$NANOTUN_SUBPROC_COVERDIR"
mkdir -p "$NANOTUN_SUBPROC_COVERDIR"

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

# 子进程那部分计数是二进制格式，得转成文本剖面才能进 merge-coverage.py。
# 再跟上面的逐包剖面拼成 unit-side.cov —— 这才是「单测这一侧」的完整账，
# merge-coverage.py 该吃的是它，不是 unit-linux.cov。
SUB=$ROOT/subproc.cov
SIDE=$ROOT/unit-side.cov
if command -v go >/dev/null && [ -n "$(ls -A "$NANOTUN_SUBPROC_COVERDIR" 2>/dev/null)" ]; then
  if go tool covdata textfmt -i="$NANOTUN_SUBPROC_COVERDIR" -o="$SUB"; then
    { cat "$OUT"; tail -n +2 "$SUB"; } > "$SIDE"
    echo "=== +subproc: $(wc -l < "$SUB") lines -> $SIDE ==="
  else
    echo "WARN covdata textfmt 失败，$SIDE 退化为纯逐包剖面"
    cp "$OUT" "$SIDE"
  fi
else
  echo "WARN 没有 go 或 covdir 为空：web/admin 的 main() 不会计入单测这一侧"
  cp "$OUT" "$SIDE"
fi

exit $fail
