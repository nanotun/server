#!/usr/bin/env bash
# 发版唯一入口。见 docs/RELEASE.md。
#
#   ./scripts/release/cut.sh
#
# 顺序:
#   1. 工作树干净 + 有 e2e 戳且与 HEAD 一致
#   2. go test ./... + e2e selftest(合并门再跑一遍)
#   3. scripts/build-release.sh 打包
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

red() { printf '%s\n' "$*" >&2; }

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  red "不在 git 仓库里"
  exit 2
fi

if [[ -n "$(git status --porcelain)" ]]; then
  red "工作树不干净,拒绝发版。先提交或清理。"
  git status --porcelain | head -20 >&2
  exit 2
fi

stamp=".release/e2e-stamp"
if [[ ! -f "$stamp" ]]; then
  red "缺少 e2e 戳: $stamp"
  red "按 docs/RELEASE.md:先跑 ./scripts/e2e/run.sh 00 10 20 30 40 50 60 70"
  red "再跑 ./scripts/release/stamp-e2e.sh"
  exit 2
fi

head_sha="$(git rev-parse HEAD)"
# 戳文件第一行是完整 SHA;其余是注释。
stamp_sha="$(grep -E '^[0-9a-f]{40}$' "$stamp" | head -1 || true)"
if [[ -z "$stamp_sha" ]]; then
  red "e2e 戳格式不对(第一行应是 40 字符 SHA): $stamp"
  exit 2
fi
if [[ "$stamp_sha" != "$head_sha" ]]; then
  red "e2e 戳与当前 HEAD 不一致 —— 盖戳后又改过代码/提交。"
  red "  戳:  $stamp_sha"
  red "  HEAD: $head_sha"
  red "必须在当前 HEAD 上重跑三机 e2e,再 stamp-e2e.sh。"
  exit 2
fi

echo "== 发版门: e2e 戳与 HEAD 一致 ($(git rev-parse --short HEAD)) =="

echo "== 发版门: go test ./... =="
go test ./... -count=1 -timeout 25m

echo "== 发版门: e2e 断言库自测 =="
./scripts/e2e/selftest.sh

echo "== 发版门: 打包 =="
# 内部调用:已过门,允许 build-release 真正打包。
NANOTUN_RELEASE_GATED=1 ./scripts/build-release.sh

echo
echo "发版完成。记得对照 docs/RELEASE.md 的人工检查单写发版说明。"
