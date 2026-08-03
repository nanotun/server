#!/usr/bin/env bash
# 发版唯一入口。见 docs/RELEASE.md。
#
#   ./scripts/release/cut.sh v0.1.0
#
# 顺序:
#   1. 版本号合法 + tag 不存在 + 工作树干净 + HEAD 在 main 上
#   2. 有 e2e 戳且与 HEAD 一致
#   3. go test ./... + e2e selftest(合并门再跑一遍)
#   4. scripts/build-release.sh 打包(amd64 + arm64)
#   5. 打 annotated tag,message 里带 e2e 戳 —— 这是 .github/workflows/release.yml
#      唯一认的凭证:三机 e2e 跑不进 GitHub Actions,所以门禁留在本地,由 tag 把
#      「已过门」这件事带到 CI。tag **不自动 push**,最后一步留给人。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

red() { printf '%s\n' "$*" >&2; }

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
  red "用法: $0 vX.Y.Z"
  red "例:   $0 v0.1.0        (预发布用 v0.1.0-rc1)"
  exit 2
fi

# 版本号格式钉死:release.yml 会按 vX.Y.Z 拆出 X.Y / latest 的镜像 tag,
# 格式漂了那边就得跟着猜。-rcN 允许,但下面会跳过 latest 那类浮动 tag。
if [[ ! "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-rc[0-9]+)?$ ]]; then
  red "版本号格式不对: $VERSION"
  red "要求 vX.Y.Z 或 vX.Y.Z-rcN,例如 v0.1.0 / v0.1.0-rc1"
  exit 2
fi

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  red "不在 git 仓库里"
  exit 2
fi

if git rev-parse -q --verify "refs/tags/$VERSION" >/dev/null; then
  red "tag 已存在: $VERSION"
  red "改版本号,或先删掉本地 tag: git tag -d $VERSION"
  exit 2
fi

if [[ -n "$(git status --porcelain)" ]]; then
  red "工作树不干净,拒绝发版。先提交或清理。"
  git status --porcelain | head -20 >&2
  exit 2
fi

head_sha="$(git rev-parse HEAD)"

# HEAD 必须在 main 上。release.yml 会做同样的校验(--is-ancestor),在这里先拦一道,
# 免得 tag 都推上去了才发现发的是个没合并的分支。
if git rev-parse -q --verify refs/heads/main >/dev/null; then
  if ! git merge-base --is-ancestor "$head_sha" refs/heads/main; then
    red "HEAD 不在 main 上 —— 拒绝从未合并的分支发版。"
    red "  HEAD: $head_sha"
    exit 2
  fi
else
  red "警告:本地没有 main 分支,跳过祖先校验(CI 侧仍会按 origin/main 核对)。"
fi

stamp=".release/e2e-stamp"
if [[ ! -f "$stamp" ]]; then
  red "缺少 e2e 戳: $stamp"
  red "按 docs/RELEASE.md:先跑 ./scripts/e2e/run.sh 00 10 20 30 40 50 60 70"
  red "再跑 ./scripts/release/stamp-e2e.sh"
  exit 2
fi

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

echo "== 发版门: 打包 $VERSION =="
# 内部调用:已过门,允许 build-release 真正打包。
NANOTUN_RELEASE_GATED=1 NANOTUN_VERSION="$VERSION" ./scripts/build-release.sh

echo "== 发版门: 打 tag $VERSION =="
# annotated(-a),不是 lightweight:release.yml 要读 tag message 里的 e2e-stamp。
# 那行是机器校验项,格式改了要同步 workflow 的 verify-tag。
git tag -a "$VERSION" -m "$(printf 'nanotun %s\n\ne2e-stamp=%s\ne2e-phases=00 10 20 30 40 50 60 70\n' "$VERSION" "$head_sha")"

echo
echo "本地已完成。dist/ 里的 tar 是自检产物,对外分发的由 CI 构建。"
echo
echo "推送 tag 触发发布(GitHub Release + GHCR 镜像):"
echo "    git push origin $VERSION"
echo
echo "推之前对照 docs/RELEASE.md 的人工检查单;要反悔就 git tag -d $VERSION。"
