#!/usr/bin/env bash
# 把「当前 HEAD 已跑过完整三机 e2e」盖成本地戳,供 scripts/release/cut.sh 核对。
#
# 用法(在 e2e 全绿之后):
#   ./scripts/e2e/run.sh 00 10 20 30 40 50 60 70
#   ./scripts/release/stamp-e2e.sh
#
# 戳不进 git(.gitignore)。盖戳后又 commit / 改文件,必须重跑 e2e 再盖。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "不在 git 仓库里,无法盖戳" >&2
  exit 2
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "工作树不干净:e2e 戳必须钉在一个确定的 commit 上。" >&2
  echo "先提交或 stash,再跑 e2e + 盖戳。" >&2
  git status --porcelain | head -20 >&2
  exit 2
fi

sha="$(git rev-parse HEAD)"
short="$(git rev-parse --short HEAD)"
mkdir -p .release
{
  echo "$sha"
  echo "# stamped_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# required_phases=00 10 20 30 40 50 60 70"
  echo "# doc=docs/RELEASE.md"
} > .release/e2e-stamp

echo "已盖戳: HEAD ${short} (${sha})"
echo "下一步: ./scripts/release/cut.sh"
