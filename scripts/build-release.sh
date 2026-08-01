#!/bin/bash
# 打包发布：交叉编译 Linux amd64 三个二进制(nanotund / nanotun-admin / nanotun-web),
# 连同 config 样例、systemd unit、TUN 辅助脚本打入 tar.gz。
# 证书不随包分发:部署机首次运行 ensure-server-assets.sh 会按需自签。
#
# **不要直接跑本脚本发版。** 唯一入口是:
#   ./scripts/release/cut.sh
# 见 docs/RELEASE.md。未过发版门时本脚本直接拒绝,避免「本地随便编一个 tar 就当发布包」。
#
# 调试例外(不会进正式发版流程):
#   NANOTUN_RELEASE_I_KNOW=1 ./scripts/build-release.sh
# cut.sh 内部调用时会设 NANOTUN_RELEASE_GATED=1。
#
# 输出: dist/nanotun-YYYYMMDD-HHMMSS-linux-amd64.tar.gz
set -euo pipefail

if [[ "${NANOTUN_RELEASE_GATED:-}" != "1" && "${NANOTUN_RELEASE_I_KNOW:-}" != "1" ]]; then
  echo "拒绝:请用 ./scripts/release/cut.sh 发版(见 docs/RELEASE.md)。" >&2
  echo "若只是本地试打包:NANOTUN_RELEASE_I_KNOW=1 $0" >&2
  exit 2
fi
if [[ "${NANOTUN_RELEASE_I_KNOW:-}" == "1" && "${NANOTUN_RELEASE_GATED:-}" != "1" ]]; then
  echo "警告:绕过发版门打包 —— 产出物不能当正式发布包。" >&2
fi

GOOS="${GOOS:-linux}"
GOARCH="${GOARCH:-amd64}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
DIR_NAME="nanotun-${TIMESTAMP}-${GOOS}-${GOARCH}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="${ROOT}/dist"
STAGING="${DIST}/${DIR_NAME}"

cd "$ROOT"
mkdir -p "${STAGING}/extras" "${STAGING}/scripts"

echo "1. 交叉编译 ${GOOS}/${GOARCH} ..."
CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" go build -trimpath -ldflags "-s -w" -o "${STAGING}/nanotund" ./cmd/nanotund
CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" go build -trimpath -ldflags "-s -w" -o "${STAGING}/nanotun-admin" ./cmd/nanotun-admin
CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" go build -trimpath -ldflags "-s -w -X main.webVersion=${TIMESTAMP}" -o "${STAGING}/nanotun-web" ./cmd/nanotun-web
chmod +x "${STAGING}/nanotund" "${STAGING}/nanotun-admin" "${STAGING}/nanotun-web"

echo "2. 复制 config 样例、systemd unit、TUN 脚本 ..."
cp cmd/nanotund/config.toml "${STAGING}/extras/"
cp cmd/nanotund/nanotun.service "${STAGING}/extras/"
cp cmd/nanotun-web/nanotun-web.service "${STAGING}/extras/" 2>/dev/null || true
# 这些文件是 install-self-hosted.sh 的硬性依赖(缺了装不上),缺失时要在打包阶段就失败。
cp cmd/nanotund/tun-setup.sh cmd/nanotund/tun-teardown.sh cmd/nanotund/tun-setup.service \
   cmd/nanotund/tun-isolate.sh cmd/nanotund/tun-isolate-teardown.sh cmd/nanotund/tun-isolate.service \
   "${STAGING}/scripts/"
cp scripts/ensure-server-assets.sh scripts/install-self-hosted.sh "${STAGING}/scripts/"
chmod +x "${STAGING}/scripts/"*.sh

echo "3. 打包 ${DIR_NAME}.tar.gz ..."
# COPYFILE_DISABLE=1:macOS 上打包时 bsdtar 默认把 xattr 另存成 AppleDouble(`._foo`)
# 一并塞进 tar,解到 Linux 部署机上就是一堆 0755 的垃圾文件(2026-07-25 实测)。
(cd "$DIST" && COPYFILE_DISABLE=1 tar -czf "${DIR_NAME}.tar.gz" "$DIR_NAME")

echo "4. 清理临时目录 ..."
rm -rf "$STAGING"

echo "完成。发布包: $DIST/${DIR_NAME}.tar.gz"
ls -la "$DIST/${DIR_NAME}.tar.gz"
