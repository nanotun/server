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

ARG GO_IMAGE=golang:1.26-bookworm
ARG RUNTIME_IMAGE=debian:bookworm-slim

# ─────────────────────────────────────────────────────────────────────────────
# 构建阶段
# ─────────────────────────────────────────────────────────────────────────────
FROM ${GO_IMAGE} AS builder

WORKDIR /src

# 先只拷依赖清单,让 go mod download 这一层能被缓存 —— 改业务代码不必重下模块。
# third_party 必须一起拷:go.mod 里 xtls/reality 是 `replace` 到 ./third_party/xtls-reality 的,
# 缺了这个目录 go mod download 会直接失败(读不到被替换模块的 go.mod)。它极少变动,
# 放在这一层不影响缓存命中。
COPY go.mod go.sum ./
COPY third_party/ ./third_party/
RUN go mod download

COPY . .

# NANOTUN_VERSION 只影响 nanotun-web 页脚展示的版本号,与 build-release.sh 的
# -X main.webVersion 同一个变量。不传则用构建时间戳。
ARG NANOTUN_VERSION=""

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
    export CGO_ENABLED=0 GOOS=linux GOARCH="${TARGETARCH:-$(go env GOARCH)}"; \
    go build -trimpath -ldflags "-s -w" -o /out/nanotund       ./cmd/nanotund; \
    go build -trimpath -ldflags "-s -w" -o /out/nanotun-admin  ./cmd/nanotun-admin; \
    go build -trimpath -ldflags "-s -w -X main.webVersion=${ver}" -o /out/nanotun-web ./cmd/nanotun-web

# ─────────────────────────────────────────────────────────────────────────────
# 运行阶段
# ─────────────────────────────────────────────────────────────────────────────
FROM ${RUNTIME_IMAGE}

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
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -sf --unix-socket /run/nanotun/control.sock http://localhost/status >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/nanotun-entrypoint.sh"]
