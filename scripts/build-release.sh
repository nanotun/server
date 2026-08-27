#!/bin/bash
# 打包发布：交叉编译三个二进制(nanotund / nanotun-admin / nanotun-web),连同 config 样例、
# systemd unit、TUN 辅助脚本打入 tar.gz,每个目标架构一份,外加一份 SHA256SUMS。
# 证书不随包分发:部署机首次运行 ensure-server-assets.sh 会按需自签。
#
# **不要直接跑本脚本发版。** 唯一入口是:
#   ./scripts/release/cut.sh vX.Y.Z
# 见 docs/RELEASE.md。未过发版门时本脚本直接拒绝,避免「本地随便编一个 tar 就当发布包」。
#
# 调试例外(不会进正式发版流程):
#   NANOTUN_RELEASE_I_KNOW=1 ./scripts/build-release.sh
# cut.sh 内部调用时会设 NANOTUN_RELEASE_GATED=1。
#
# 版本号来自 NANOTUN_VERSION(cut.sh 传入的 tag,如 v0.1.0);没传就退化成时间戳,
# 这条路径只服务于本地试打包。
#
# 架构由 NANOTUN_ARCHES 控制,默认 "amd64 arm64" —— Oracle / AWS 免费层大量是 arm64,
# 只发 amd64 等于把这批用户挡在 Docker 之外。
#
# 输出: dist/nanotun-<版本>-linux-<arch>.tar.gz + dist/SHA256SUMS
set -euo pipefail

if [[ "${NANOTUN_RELEASE_GATED:-}" != "1" && "${NANOTUN_RELEASE_I_KNOW:-}" != "1" ]]; then
  echo "拒绝:请用 ./scripts/release/cut.sh vX.Y.Z 发版(见 docs/RELEASE.md)。" >&2
  echo "若只是本地试打包:NANOTUN_RELEASE_I_KNOW=1 $0" >&2
  exit 2
fi
if [[ "${NANOTUN_RELEASE_I_KNOW:-}" == "1" && "${NANOTUN_RELEASE_GATED:-}" != "1" ]]; then
  echo "警告:绕过发版门打包 —— 产出物不能当正式发布包。" >&2
fi

GOOS="${GOOS:-linux}"
ARCHES="${NANOTUN_ARCHES:-amd64 arm64}"
VERSION="${NANOTUN_VERSION:-$(date +%Y%m%d-%H%M%S)}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="${ROOT}/dist"

cd "$ROOT"

# 版本元数据:三者一起注入,dashboard / control socket / metrics 都会展示。
# git 信息取自当前工作树;CI 上是 tag 指向的 commit,本地是 HEAD。
GIT_SHA="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# nanotund / nanotun-admin / nanotun-web 各自的注入点不同名,历史原因,别去统一 ——
# 改名要同步 cmd/nanotund/server.go、cmd/nanotun-admin/main.go、cmd/nanotun-web/main.go
# 以及 Dockerfile。这里漏掉任何一个,发出去的包就会在版本页显示 "unknown" / "dev"。
LDFLAGS_COMMON="-s -w"
LDFLAGS_SERVER="${LDFLAGS_COMMON} -X main.serverVersion=${VERSION} -X main.serverGitSHA=${GIT_SHA} -X main.serverBuildTime=${BUILD_TIME}"
LDFLAGS_ADMIN="${LDFLAGS_COMMON} -X main.version=${VERSION}"
LDFLAGS_WEB="${LDFLAGS_COMMON} -X main.webVersion=${VERSION}"

mkdir -p "$DIST"

# 校验和文件按本次构建重写,不累积历史产物:dist/ 里可能还躺着上几次的 tar,
# 把它们一起算进 SHA256SUMS 会让下载者对着一份含无关条目的清单校验。
TARBALLS=()

for GOARCH in $ARCHES; do
  DIR_NAME="nanotun-${VERSION}-${GOOS}-${GOARCH}"
  STAGING="${DIST}/${DIR_NAME}"
  rm -rf "$STAGING"
  mkdir -p "${STAGING}/extras" "${STAGING}/scripts"

  echo "1. 交叉编译 ${GOOS}/${GOARCH} (${VERSION}) ..."
  CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" go build -trimpath -ldflags "$LDFLAGS_SERVER" -o "${STAGING}/nanotund" ./cmd/nanotund
  CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" go build -trimpath -ldflags "$LDFLAGS_ADMIN" -o "${STAGING}/nanotun-admin" ./cmd/nanotun-admin
  CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" go build -trimpath -ldflags "$LDFLAGS_WEB" -o "${STAGING}/nanotun-web" ./cmd/nanotun-web
  chmod +x "${STAGING}/nanotund" "${STAGING}/nanotun-admin" "${STAGING}/nanotun-web"

  echo "2. 复制 config 样例、systemd unit、TUN 脚本 ..."
  cp cmd/nanotund/config.toml "${STAGING}/extras/"
  cp cmd/nanotund/nanotun.service "${STAGING}/extras/"
  cp cmd/nanotun-web/nanotun-web.service "${STAGING}/extras/" 2>/dev/null || true
  # 这些文件是 install-self-hosted.sh 的硬性依赖(缺了装不上),缺失时要在打包阶段就失败。
  cp cmd/nanotund/tun-setup.sh cmd/nanotund/tun-teardown.sh cmd/nanotund/tun-setup.service \
     "${STAGING}/scripts/"
  # setup.sh 是安装之后的开服向导,必须随包走 —— 它是「服务起来了」到「客户端能连」
  # 之间那段的唯一引导,install-self-hosted.sh 的结尾会指向它。
  # preflight.sh 是环境判据的唯一真源,install-self-hosted.sh 直接调它;不随包走的话
  # 从 tar 装的人就只能退回到那套简化的兜底检查。
  # uninstall.sh 必须跟安装脚本同包:它删的是一份**写死的文件清单**(共用目录里还有客户端的
  # device_id 等文件,不能按目录删),这份清单只有和它同版本的 install-self-hosted.sh 对得上。
  # set-magic-suffix.sh 同理:install-self-hosted.sh 把它装成 nanotun-set-suffix,
  # 开服向导的「MagicDNS 后缀」那步也只认它。
  cp scripts/ensure-server-assets.sh scripts/install-self-hosted.sh \
     scripts/setup.sh scripts/preflight.sh scripts/uninstall.sh \
     scripts/set-magic-suffix.sh "${STAGING}/scripts/"
  chmod +x "${STAGING}/scripts/"*.sh

  # 打包清单不能和安装脚本的需求各自漂移。
  #
  # 2026-08-27 查出来:上面这份 cp 清单漏了 set-magic-suffix.sh,而 install-self-hosted.sh
  # 那侧是 `[ -f … ] && install …`,注释写着「老包没有不 fatal」—— 于是**每一个**发布包都
  # 被当成老包,nanotun-set-suffix 从来没被装上过,装机一路全绿。README 双语却都写着它
  # 「随包装成命令」。连带 setup.sh 的 resolve_suffix_tool 两个候选全落空,向导里改后缀
  # 那步也是坏的。一个为向后兼容加的守卫,把打包遗漏变成了静默。
  #
  # 这类事在本仓库不是第一次:e2e 的 deploy-srv.sh 有一份同样手工维护的替换清单,
  # tun-setup.sh 就在那儿漏了很久(见该文件注释)。所以这里不再手工核对,而是直接从
  # install-self-hosted.sh 里把它引用的文件名抠出来当作真源 —— 清单只有一份,漏不了。
  #
  # 放在打包阶段失败而不是留给安装期:装机时才发现缺文件,包已经发出去了。
  need_missing=""
  while read -r want; do
    [ -n "$want" ] || continue
    [ -e "${STAGING}/scripts/${want}" ] || need_missing="${need_missing} ${want}"
  done <<EOF
$(grep -oE '\$SCRIPTS_DIR/[A-Za-z0-9._-]+' scripts/install-self-hosted.sh | sed 's#.*/##' | sort -u)
EOF
  if [ -n "$need_missing" ]; then
    echo "拒绝打包:install-self-hosted.sh 会用到这些文件,但没打进包 ——${need_missing}" >&2
    echo "  把它们加进上面那条 cp,或者确认安装脚本里对应的引用已经不需要了。" >&2
    exit 1
  fi

  echo "3. 打包 ${DIR_NAME}.tar.gz ..."
  # COPYFILE_DISABLE=1:macOS 上打包时 bsdtar 默认把 xattr 另存成 AppleDouble(`._foo`)
  # 一并塞进 tar,解到 Linux 部署机上就是一堆 0755 的垃圾文件(2026-07-25 实测)。
  #
  # --no-xattrs:上面那个变量管不到 xattr 的另一条出路 —— bsdtar 还会把
  # com.apple.provenance 写成 PAX 扩展头,GNU tar 解包时对**每个文件**打一行
  # "Ignoring unknown extended header keyword",十几行告警刷在用户第一次安装的屏幕上。
  # 两种 tar 都认这个 flag。
  (cd "$DIST" && COPYFILE_DISABLE=1 tar --no-xattrs -czf "${DIR_NAME}.tar.gz" "$DIR_NAME")

  echo "4. 清理临时目录 ..."
  rm -rf "$STAGING"

  TARBALLS+=("${DIR_NAME}.tar.gz")
done

echo "5. 生成 SHA256SUMS ..."
# macOS 没有 sha256sum,只有 shasum;CI 上反过来。两边都要能跑 —— cut.sh 在维护者的
# Mac 上跑,release workflow 在 ubuntu runner 上跑。
if command -v sha256sum >/dev/null 2>&1; then
  SHA_CMD=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
  SHA_CMD=(shasum -a 256)
else
  echo "既没有 sha256sum 也没有 shasum,无法生成校验和" >&2
  exit 1
fi
# 在 dist/ 内执行,让清单里是裸文件名 —— 下载者 `sha256sum -c SHA256SUMS` 时
# 文件就在同目录,带路径前缀会直接校验失败。
(cd "$DIST" && "${SHA_CMD[@]}" "${TARBALLS[@]}" > SHA256SUMS)

echo
echo "完成。发布包(${VERSION}):"
for t in "${TARBALLS[@]}"; do
  ls -la "$DIST/$t"
done
ls -la "$DIST/SHA256SUMS"
