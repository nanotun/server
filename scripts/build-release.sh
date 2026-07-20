#!/bin/bash
# 打包发布：交叉编译 Linux amd64 三个二进制(nanotund / nanotun-admin / nanotun-web),
# 连同 config 样例、systemd unit、TUN 辅助脚本打入 tar.gz。
# 证书不随包分发:部署机首次运行 ensure-server-assets.sh 会按需自签。
# 使用: ./scripts/build-release.sh
# 输出: dist/nanotun-YYYYMMDD-HHMMSS-linux-amd64.tar.gz
set -e
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
(cd "$DIST" && tar -czf "${DIR_NAME}.tar.gz" "$DIR_NAME")

echo "4. 清理临时目录 ..."
rm -rf "$STAGING"

echo "完成。发布包: $DIST/${DIR_NAME}.tar.gz"
ls -la "$DIST/${DIR_NAME}.tar.gz"
