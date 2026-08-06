# nanotun 自托管网关容器镜像（nanotund + nanotun-web + nanotun-admin 单容器）。
#
# 用法见 docs/DOCKER.md。构建:
#   docker build -t nanotun:dev .
#
# 两处刻意的选择,改之前先读:
#
# 1) runtime 基底用 debian-slim 而不是 alpine。体积贵 60MB 左右,换的是 **iptables 后端
#    与宿主一致**。debian 的 iptables 包默认走 nft 后端(update-alternatives),与现代
#    Ubuntu/Debian 宿主同款;alpine 的 iptables 是 legacy 后端。两者写的是内核里**不同的**
#    表:后端不匹配时 `iptables -L` 看着干净、规则却没进宿主实际生效的那张表 —— NAT 不生效、
#    出口静默黑洞,而且完全没有报错。这类「安静地坏掉」正是本项目最不能接受的失败形态。
#    宿主确实是 legacy 后端时,见 docs/DOCKER.md 里切换 alternatives 的说明。
#
# 2) 编译产物全静态(CGO_ENABLED=0),与 scripts/build-release.sh 同款参数。SQLite 用的是
#    modernc 纯 Go 实现,所以 runtime 层不需要 gcc / libsqlite3,只需要那几个网络工具。

# 基础镜像钉到 digest。浮动 tag 下同一份 Dockerfile 隔几天构建出来的东西就不一样了 ——
# 出问题时"我这儿好好的"和"线上炸了"可能真的是两个镜像,而 git 上看不出任何差异。
#
# 钉的是**多架构 index** 的 digest(OCI image index),不是某个平台的 manifest,
# 所以 amd64 / arm64 都还能正常解析。用单平台 digest 会把多架构构建钉死在一个架构上。
# tag 保留在前面只为可读,真正生效的是 @sha256。
#
# 更新方式(基础镜像发安全更新时要做,不然就等于永远用着旧的 libc/openssl):
#   docker buildx imagetools inspect golang:1.26-bookworm   # 取 Digest 行
#   docker buildx imagetools inspect debian:bookworm-slim
# 换完跑一次 `docker build` 让 archcheck 过一遍,CI 的 docker-image job 也会两个架构都构建。
#
# GO_IMAGE 里的 Go 版本要跟得上 go.mod 的 toolchain 行(当前两边都是 go1.26.5),
# 否则 go 会在构建时按 GOTOOLCHAIN 现下一个 —— 能成,但凭空多一次网络依赖,
# 而且镜像里到底用哪个版本编的就看不出来了。ci.yml 的 setup-go 是同一个约束。
ARG GO_IMAGE=golang:1.26-bookworm@sha256:1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651
ARG RUNTIME_IMAGE=debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

# ─────────────────────────────────────────────────────────────────────────────
# 构建阶段
# ─────────────────────────────────────────────────────────────────────────────
# --platform=$BUILDPLATFORM:构建阶段永远跑**本机**架构的 Go 工具链,靠下面的 GOARCH
# 交叉编译出目标架构。这是 Go 多架构镜像的惯用写法,而交叉编译的机制本来就在(GOARCH),
# 缺的只是这半句 —— 不写的话 `--platform linux/amd64` 会去拉目标架构的 golang 镜像,
# 把整条工具链塞进模拟层跑。
#
# 主要收益不是快,是**不依赖模拟层能不能跑工具链**:没给目标架构注册 binfmt 的机器上,
# 原来的写法直接构建不了。速度只是顺带,而且省多少取决于宿主用哪种模拟 ——
# Apple Silicon 上 Docker Desktop 走 Rosetta,实测 builder 阶段 2:08 → 1:47(只快 16%);
# 退到 QEMU 的宿主上差距会大得多。别拿这里的 16% 当预期值。
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS builder

WORKDIR /src

# 先只拷依赖清单,让 go mod download 这一层能被缓存 —— 改业务代码不必重下模块。
# third_party 必须一起拷:go.mod 里 xtls/reality 是 `replace` 到 ./third_party/xtls-reality 的,
# 缺了这个目录 go mod download 会直接失败(读不到被替换模块的 go.mod)。它极少变动,
# 放在这一层不影响缓存命中。
COPY go.mod go.sum ./
COPY third_party/ ./third_party/
RUN go mod download

COPY . .

# NANOTUN_VERSION 是三个二进制共用的版本号,release.yml 会把 tag(如 v0.1.0)传进来,
# 与 build-release.sh 注入的是同一批变量。不传则用构建时间戳。
#
# 三个二进制的注入点不同名(serverVersion / version / webVersion),历史原因。
# 漏掉任何一个,镜像跑起来对应的组件就报 "unknown" / "dev" —— 用户报障时说不清
# 自己跑的是哪个版本,而这正是版本号存在的唯一理由。
ARG NANOTUN_VERSION=""

# git SHA 必须由外部传入:.dockerignore 排掉了 .git,所以镜像里既 `git rev-parse` 不了,
# 也没有 debug/buildinfo 的 vcs.revision 可回填(那玩意也依赖 .git 在上下文里)。
# 不传就是 "unknown",本地 `docker build` 属于这种情况,可以接受;release.yml 会传。
ARG NANOTUN_GIT_SHA=""

# TARGETARCH 必须**不带默认值**地声明。它是 buildkit 的内置全局 ARG,在 stage 里
# "redeclare without value" 才会被自动填成当前构建平台的架构;一旦写成
# `ARG TARGETARCH=amd64`,这个默认值会盖掉自动填充,于是 GOARCH 被钉死在 amd64 ——
# 而运行阶段的 debian-slim 仍按本机平台拉取。
#
# 后果是 arm64 机器上 `docker build` 出来的镜像:arm64 的基底 + amd64 的二进制,
# 而且镜像自称 arm64。Mac 上察觉不到,Docker Desktop 有 Rosetta/binfmt 在背后模拟;
# 换成真正的 arm64 Linux 主机就是 exec format error。x86 上因为两边凑巧都是 amd64,
# 一直没暴露。2026-08-02 实测撞出来的。
ARG TARGETARCH

RUN set -eux; \
    ver="${NANOTUN_VERSION:-$(date +%Y%m%d-%H%M%S)}"; \
    sha="${NANOTUN_GIT_SHA:-unknown}"; \
    built="$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
    export CGO_ENABLED=0 GOOS=linux GOARCH="${TARGETARCH:-$(go env GOARCH)}"; \
    go build -trimpath -ldflags "-s -w -X main.serverVersion=${ver} -X main.serverGitSHA=${sha} -X main.serverBuildTime=${built}" -o /out/nanotund ./cmd/nanotund; \
    go build -trimpath -ldflags "-s -w -X main.version=${ver}"    -o /out/nanotun-admin ./cmd/nanotun-admin; \
    go build -trimpath -ldflags "-s -w -X main.webVersion=${ver}" -o /out/nanotun-web   ./cmd/nanotun-web

# ─────────────────────────────────────────────────────────────────────────────
# 运行阶段
# ─────────────────────────────────────────────────────────────────────────────
FROM ${RUNTIME_IMAGE}

# 运行阶段是新的 stage,builder 里声明的 ARG 到这儿失效,要重新声明一次才能用。
ARG NANOTUN_VERSION=""
ARG NANOTUN_GIT_SHA=""

# OCI 标准标签。source 那条不是装饰:GHCR 靠它把镜像包关联到仓库,没有的话
# 包页面既不显示 README 也没有指回源码的链接,对一个要人信任的 VPN 网关镜像来说
# 是硬伤。其余几条让 `docker inspect` 能答出「这是什么、什么许可、哪个版本」。
LABEL org.opencontainers.image.title="nanotun" \
      org.opencontainers.image.description="自托管组网网关(nanotund + nanotun-web + nanotun-admin)" \
      org.opencontainers.image.source="https://github.com/nanotun/server" \
      org.opencontainers.image.documentation="https://github.com/nanotun/server/blob/main/docs/DOCKER.md" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${NANOTUN_VERSION}" \
      org.opencontainers.image.revision="${NANOTUN_GIT_SHA}"

# 这些不是"顺手装上"的:每一个都有生产路径在调。
#   iproute2   —— ip addr / ip link / ip route,TUN 起不来就全盘不可用
#   iptables   —— NAT / FORWARD / connlimit / hy2 端口跳跃 REDIRECT;含 iptables-save,
#                 启动 sweep 靠它按 comment 找上一条命的残留规则
#   ipset      —— jump_host_firewall=true 时必需(缺了是 fail-closed,直接拒绝启动)
#   openssl    —— 首次启动自签 TLS 证书 / 生成 REALITY 私钥与 hy2 口令
#   curl       —— HEALTHCHECK 走 control socket 探活
#   ca-certificates —— 出站 TLS 校验
#   procps     —— 提供 sysctl(entrypoint 与守护进程都要写 ip_forward)
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        iproute2 iptables ipset openssl curl ca-certificates procps; \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/nanotund      /usr/local/bin/nanotund
COPY --from=builder /out/nanotun-admin /usr/local/bin/nanotun-admin
COPY --from=builder /out/nanotun-web   /usr/local/bin/nanotun-web

# 断言二进制架构与基底一致。这道检查存在的理由就是上面 TARGETARCH 那段说的事故:
# 两边不一致时镜像能构建成功、能推、还自称是基底的架构,只在真机启动那一刻才炸,
# 而在带 binfmt 模拟的开发机上连炸都不炸 —— 典型的「安静地坏掉」。
# 读 ELF 的 e_machine 而不是执行一下试试:执行会被模拟层接住,验不出东西。
# 认不出的架构放行,别为了 armv7/s390x 这种没在用的目标把构建拦下来。
RUN set -eux; \
    want="$(dpkg --print-architecture)"; \
    case "$want" in \
        amd64) want_machine="3e00" ;; \
        arm64) want_machine="b700" ;; \
        *)     echo "[archcheck] 基底架构 $want 未在检查表内,跳过"; exit 0 ;; \
    esac; \
    for b in nanotund nanotun-admin nanotun-web; do \
        got="$(od -An -tx1 -j18 -N2 "/usr/local/bin/$b" | tr -d ' \n')"; \
        [ "$got" = "$want_machine" ] || { \
            echo "[archcheck] $b 的架构与基底不符:ELF e_machine=$got,基底=$want($want_machine)。" >&2; \
            echo "[archcheck] 多半是 TARGETARCH 被写死了 —— 它必须不带默认值声明。" >&2; \
            exit 1; \
        }; \
    done; \
    echo "[archcheck] 三个二进制均为 $want,与基底一致"

# 配置模板与自签脚本放到 /usr/share/nanotun:entrypoint 在 /etc/nanotun 为空时
# 用它做首次初始化。**不**直接写进 /etc/nanotun —— 那是数据卷挂载点,镜像里放东西
# 会在挂了卷之后被遮住,给人「模板丢了」的错觉。
COPY cmd/nanotund/config.toml            /usr/share/nanotun/config.toml.dist
COPY scripts/ensure-server-assets.sh     /usr/local/bin/nanotun-ensure-assets.sh
COPY docker/entrypoint.sh                /usr/local/bin/nanotun-entrypoint.sh
RUN chmod 0755 /usr/local/bin/nanotun-ensure-assets.sh /usr/local/bin/nanotun-entrypoint.sh

# nanotun-admin 的 --db-path 默认是**相对 cwd** 的 data/nanotun.db。不固定住的话,
# `docker compose exec nanotun nanotun-admin user list` 会去找 /etc/nanotun/data/nanotun.db
# 然后报「库不存在」—— 明明库就在卷里。用官方支持的环境变量钉死,让 exec 进来直接可用。
ENV NANOTUN_DB=/var/lib/nanotun/nanotun.db \
    NANOTUN_CONTROL_SOCKET=/run/nanotun/control.sock

# 相对路径的证书(config.toml 里写的是 "certs/dev-cert.pem")按工作目录解析,
# 与 systemd unit 的 WorkingDirectory=/etc/nanotun 保持一致。
WORKDIR /etc/nanotun

VOLUME ["/etc/nanotun", "/var/lib/nanotun"]

# 443/udp   hysteria2 QUIC
# 8443/tcp  REALITY
# 7443/tcp  nanotun-web 管理面 HTTPS
# 8080/tcp 数据面 WS 与 8081/tcp /health 默认只绑回环,不 EXPOSE。
EXPOSE 443/udp 8443/tcp 7443/tcp

# 探活走控制面 unix socket,而不是 /health 的 127.0.0.1:8081 —— 后者在 host 网络模式下
# 与宿主回环共用,容易和宿主上别的服务撞端口;socket 是文件,不存在这个问题。
#
# 除了数据面探活,还要看 entrypoint 有没有留下 web-degraded 标记:管理面连挂到不再重启时,
# 数据面照样健康,只探 socket 会一直报 healthy,而用户此时已经进不去后台了。
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -sf --unix-socket /run/nanotun/control.sock http://localhost/status >/dev/null \
        && [ ! -e /run/nanotun/web-degraded ] || exit 1

ENTRYPOINT ["/usr/local/bin/nanotun-entrypoint.sh"]
