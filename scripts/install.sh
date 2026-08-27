#!/usr/bin/env bash
# nanotun 一条命令开服 —— 检查环境 → 下载发布包 → 安装 → 开服向导。
#
#   sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/nanotun/server/main/scripts/install.sh)"
#
# 跑完就能用:向导会问拨号地址、建第一个 VPN 用户、出两个二维码。
#
# 为什么不是更眼熟的 `curl … | sudo bash`:Ubuntu / Debian 的 sudo 默认 use_pty,会
# 另开一个 pty 跑命令,叠加管道占着 sudo 的 stdin,向导一问话就被挂起(全新 Ubuntu
# 26.04 上实测两次两挂)。把脚本当参数传给 bash 则 bash 的 stdin 就是终端,
# 不存在这个问题。管道形态仍然能装,只是本脚本会认出这个组合、装完跳过向导让人手动跑。
#
# 无人值守(CI / cloud-init)不需要问话,不认得的参数一律转交向导。先落盘再执行 ——
#   curl -fsSL .../install.sh -o nanotun-install.sh \
#     && sudo NANOTUN_WEB_ADMIN_PASSWORD='<密码>' bash nanotun-install.sh \
#          --dial-host vpn.example.com --user alice --web-admin ops --yes
#
# 两处都不是可有可无的:
#  ① **不能**写成 `curl … | sudo bash`。curl 失败时 bash 拿到的是个空脚本,老老实实跑完
#     那零行内容然后**以 0 退出** —— 人在旁边看着无所谓(屏幕上什么都没发生),但 cloud-init
#     / Ansible / CI 只认退出码,会把「一个字节都没下下来」当成装好了继续往下走。先落盘,
#     curl 的失败就由 && 如实挡住了。(落在当前目录而不是 /tmp:/tmp 人人可写,下载完到
#     sudo 执行之间那一瞬,同机的其他用户能把文件换掉,而下一步是 root 在跑它。)
#  ② --web-admin 得带上。不带的话向导不会建后台管理员(它不替调用方凭空造账号),而
#     /setup 在第一个管理员出现之前对全网敞着 —— 谁先打开谁就是这台机器的后台管理员,
#     偏偏 7443 是上面防火墙那步刚放行的。无人值守下没人会去看那句警告。
#
# 只想先看看这台机器行不行(不下载、不安装、不改任何东西):
#   curl -fsSL .../install.sh | bash -s -- --check-only
#   环境检查也可以单独跑:curl -fsSL .../preflight.sh | bash
#
# 装指定版本(生产建议钉版本,别跟着 latest 漂):
#   sudo NANOTUN_VERSION=v0.1.25 bash -c "$(curl -fsSL .../install.sh)"
#
# 要**完全**钉死(连这个脚本和 preflight.sh 一起钉),把 URL 里的 main 也换成同一个 tag:
#   sudo NANOTUN_VERSION=v0.1.25 bash -c "$(curl -fsSL \
#     https://raw.githubusercontent.com/nanotun/server/v0.1.25/scripts/install.sh)"
#   NANOTUN_VERSION 是 tag 时 NANOTUN_BRANCH 默认跟着它走,所以 preflight.sh 也来自同一个 tag。
#   这条联动是 v0.1.25 加的,所以示例里的 tag 不能低于它 —— 更早的 tag 上这个脚本还没有
#   这段,环境检查仍从 main 取,而紧挨着的这句话会让人以为三样都钉住了。
#
# github.com / raw.githubusercontent.com 不通(镜像):见下面 NANOTUN_GH_BASE / NANOTUN_RAW_BASE。
#
# 只下载不安装(想先看看包里是什么):
#   curl -fsSL .../install.sh | NANOTUN_NO_INSTALL=1 bash
#
# 注意跟 install-self-hosted.sh 的分工:本脚本是**网络入口**,负责把发布包弄到这台
# 机器上;真正动系统的那些活(systemd / 防火墙 / 密钥)都在 install-self-hosted.sh
# 里,它随发布包走,也可以从解压好的目录单独跑。
#
# 选项:
#   --check-only   只做环境检查,一次列全问题后退出(不需要 root)
#   --skip-check   跳过环境检查直接装(不建议;装到一半失败比现在就知道难收拾)
#   --no-setup     装完不自动进开服向导
#   --magic-suffix <后缀>  MagicDNS 局域网后缀(客户端解析 *.<后缀> → mesh 虚拟 IP),
#                  默认 lan;只在首次装机(真写模板 config.toml)时生效。等价于环境变量
#                  NANOTUN_MAGIC_SUFFIX。改现有机器的后缀用 sudo nanotun-set-suffix <后缀>
#                  (装机时一并装成了命令;发布包里对应 scripts/set-magic-suffix.sh)。
#   其余参数        原样转交开服向导,例如 --dial-host / --user / --web-admin / --yes
#
# 环境变量:
#   NANOTUN_MAGIC_SUFFIX        同 --magic-suffix(命令行参数优先);走 sudo 时记得写在
#                       sudo 后面:sudo NANOTUN_MAGIC_SUFFIX=nanotun bash -c "$(curl ...)"
#   NANOTUN_WEB_ADMIN_PASSWORD  Web 后台管理员密码,配合 --web-admin <名字> 使用。
#                       走环境变量而不是命令行参数:argv 对同机所有用户可见(ps),
#                       还会落进 shell history。注意 sudo 默认不传环境变量,得写成
#                       `sudo NANOTUN_WEB_ADMIN_PASSWORD=... bash -c "$(curl ...)"`。
#   NANOTUN_VERSION     要装的版本,默认取最新 Release
#   NANOTUN_INSTALL_DIR 解压落点,默认 /opt/nanotun
#   NANOTUN_NO_INSTALL  =1 时只下载解压,不执行 install-self-hosted.sh
#   NANOTUN_REPO        换仓库(fork 自用)
#   NANOTUN_BRANCH      从哪个 ref 取 preflight.sh。默认:NANOTUN_VERSION 是 tag 时跟着它,
#                       否则 main。显式设了就以它为准
#   NANOTUN_GH_BASE     发布包的下载前缀,默认 https://github.com/<repo>。给的是**完整前缀**,
#                       所以路径型和 ghproxy 那种前缀型镜像都装得下:
#                         NANOTUN_GH_BASE=https://ghproxy.net/https://github.com/nanotun/server
#   NANOTUN_RAW_BASE    preflight.sh 的下载前缀,默认
#                       https://raw.githubusercontent.com/<repo>/<ref>/scripts
#                       (设了它就绕过 NANOTUN_REPO / NANOTUN_BRANCH 的拼装)
#   NANOTUN_VERBOSE     =1 时安装过程连 systemd 状态和日志一起打出来(默认只给结论)
#
# 安装要 root(写 /usr/local/bin、/etc/systemd/system、sysctl)。
# --check-only 和 NANOTUN_NO_INSTALL=1 不需要 root。

# 整个脚本包在这对花括号里,收尾在文件最后一行。**不是**排版,是防下载被截断。
#
# 本脚本的正常用法是 `bash -c "$(curl …)"` / `curl … | bash`,而 bash 读一段执行一段。
# 连接在中途断掉(移动网络、代理超时、CDN 抽风)时,curl 交出来的是**前半截脚本**,bash
# 会把这半截老老实实执行到断点为止,然后才在 EOF 处报个语法错 —— 那时候前面那些命令
# 早跑完了。半个安装脚本跑出来的状态没人定义过,而屏幕上只有一句看不懂的 syntax error。
#
# 花括号是复合命令:bash 必须先读到配对的那个 `}` 才能开始执行里面任何一条。截断的话
# 它在解析阶段就失败,一条都不会跑。代价是两行,换掉的是一整类「装了一半」。
#
# 所以这个 `}` 不能删,也不能在它后面再加执行语句。
{

set -euo pipefail

REPO="${NANOTUN_REPO:-nanotun/server}"
INSTALL_DIR="${NANOTUN_INSTALL_DIR:-/opt/nanotun}"

# 没显式指定分支时,钉了版本就跟着那个版本的 tag 走。
#
# 之前 BRANCH 恒为 main,于是「钉版本」是残缺的:NANOTUN_VERSION 只钉住**发布包**,而
# preflight.sh 仍然从 main 取。即便把 URL 换成 tag 路径去拉 install.sh 也一样 —— 脚本
# 内部不知道自己是从哪个 ref 被取下来的。结果是没有任何一条命令能给出完全钉死的安装:
# 同一条命令今天和下个月跑出来的东西不一样,而差异来自一个用户没写在命令里的地方。
#
# 这件事的另一面更要紧:发布包有 e2e 342 项 + 盖章 + cut 那一整套门禁,而 main 上的
# 这几个脚本一次 push 就对全世界所有新安装生效,不经任何门 —— 受保护的是被下载的产物,
# 不受保护的恰恰是**以 root 执行的那段脚本**。钉得住版本,至少让在意的人有办法退出这条路。
#
# 所有已发布的 tag 都带 scripts/preflight.sh(逐个 tag 核对过),所以这条联动不会把老版本
# 的安装弄坏。真遇到取不到的(比如 fork 的老 tag),下面下载失败那条会给出 NANOTUN_BRANCH=main
# 的退路 —— 宁可报错给退路,也不悄悄回落到 main:悄悄回落等于把「钉死」这件事变成一句空话。
BRANCH="${NANOTUN_BRANCH:-}"
if [ -z "$BRANCH" ]; then
  case "${NANOTUN_VERSION:-}" in
    v[0-9]*) BRANCH="${NANOTUN_VERSION}" ;;
    *)       BRANCH=main ;;
  esac
fi

# 两个下载源都可以整体换掉,给的是**完整前缀**而不是主机名。
#
# 原来这两处主机写死,只有 repo / branch 两段可换 —— 而 raw.githubusercontent.com 与
# github.com 在不少地区是常年不稳的那种。现有的离线指引(去能上网的机器下 tar,再跑
# install-self-hosted.sh)写得很好,但那等于放弃一键;能指到镜像的话这台机器本来是装得上的。
#
# 之所以是完整前缀:国内两类常见镜像的形状不一样,主机名换不出来。
#   · 路径型:NANOTUN_RAW_BASE=https://raw.gitmirror.com/nanotun/server/main/scripts
#   · 前缀型(ghproxy 那类,把整条 URL 挂在后面):
#       NANOTUN_GH_BASE=https://ghproxy.net/https://github.com/nanotun/server
#     拼出来正好是它要的 https://ghproxy.net/https://github.com/.../releases/download/...
# 一个变量两种都装得下,不必为每种镜像各加一个开关。
RAW_BASE="${NANOTUN_RAW_BASE:-https://raw.githubusercontent.com/${REPO}/${BRANCH}/scripts}"
GH_BASE="${NANOTUN_GH_BASE:-https://github.com/${REPO}}"

# curl 的停滞防护。--retry 只在**失败**时重试,而最难受的一种失败根本不算失败:
# 连接建好了、数据一个字节都不来。curl 会一直等下去,屏幕停在「下载 …」那一行 ——
# 没有超时、没有进度、也没法判断该不该继续等。实测容器里就这么卡了 8 分钟,
# 目标文件始终 0 字节;下面那个 `28) 下载失败:超时` 分支从来没有机会被走到。
#
# 大文件不能用 --max-time:真慢的小机器(几百 K 带宽拉十几 M)会被无辜掐断,而它
# 本来是能装完的。--speed-limit/--speed-time 只掐「停住不动」的那种 —— 慢但在动的
# 照样让它下完,这才是要区分的两件事。
CURL_BASE=(--fail --silent --show-error --location --retry 3 --connect-timeout 20)
# 几十 KB 的脚本与清单:整体封顶即可(最坏 4 次尝试 × 30 秒)。
CURL_SMALL=("${CURL_BASE[@]}" --max-time 30)
# 十几 M 的发布包:30 秒内传不满 1KB/s 就判死,重试 3 次,最坏约 2 分钟收敛。
CURL_BIG=("${CURL_BASE[@]}" --speed-limit 1024 --speed-time 30)

# 下载器:有 curl 就用 curl,只在它不在时才退到 wget。
#
# 要这条退路是因为 Debian netinst 和一部分云厂商的最小镜像**只带 wget**。原来这里硬依赖
# curl,而缺 curl 的表现特别误导:第一个网络动作是取 preflight.sh,失败后打的是「下载
# preflight.sh 失败 / 网络不通的话可以 --skip-check」—— 网络明明是通的,而 --skip-check
# 也救不了,下一步取发布包用的还是 curl。人会照着去查网络,查不出所以然。
#
# 为什么不干脆整个换成 wget:下面有两处用到 curl 的 -w('%{url_effective}' 解 latest 的
# 重定向、'%{http_code}' 区分 SHA256SUMS 的 404),wget 没有对应物,只能去翻
# --server-response 的响应头。curl 在场时没理由走那条更绕、更容易被输出格式变动咬到的路,
# 所以 curl 分支一个字都没动,wget 只是缺 curl 时顶上。
#
# wget 的等价参数:
#   --tries=4          对 curl 的 --retry 3(curl 数的是「重试」,wget 数的是「总次数」)
#   --timeout=20       连接/读取超时;wget 没有分开的 --connect-timeout
#   --read-timeout=30  停滞防护,对应 --speed-time 30。粒度比 curl 粗:curl 掐的是
#                      「30 秒内不足 1KB/s」,wget 掐的是「30 秒内一个字节都没有」——
#                      慢但在动的照样能下完,要区分的那件事仍然区分得开。
WGET_SMALL=(--quiet --tries=4 --timeout=20)
WGET_BIG=(--quiet --tries=4 --timeout=20 --read-timeout=30)
# 探响应头的那两处**不能**带 --quiet:-q 会把 --server-response 打到 stderr 的那些头
# 一并吞掉,于是 Location / 状态码永远解析成空,而调用方只会看到「解析不出版本号」这种
# 跟真因毫无关系的报错。
WGET_PROBE=(--tries=4 --timeout=20 --server-response --spider)
DL=""
if command -v curl >/dev/null 2>&1; then DL=curl
elif command -v wget >/dev/null 2>&1; then DL=wget
fi

# dl_rc_class <退出码> 把两个工具各自的退出码归到同一组**原因**上。
#
# 下面几处报错是按原因分岔的,而分错方向的建议比不给还糟(这个文件里已经栽过一次:磁盘写满
# 时让人去 GitHub 查有没有这个产物)。两个工具的码不通用,所以先归一,再让报错只认类别。
#
#   curl  23 写目标文件失败 → write
#         6/7 解析不了 / 连不上 → unreachable
#         28 连上了但数据不来 → stall
#         22 HTTP 错(404 之类)→ http
#   wget  3 文件 I/O → write
#         8 服务器返回错误响应 → http
#         4/5/7 network failure / SSL 校验失败 / 协议错 → netfail
#
# curl 的分辨力一格没丢。wget 单列一个 netfail 而不是硬塞进 unreachable 或 stall:它把
# DNS 失败、连接被拒、读超时全并进 4,分不出「压根没通」和「连上了不给数据」—— 硬塞进
# 任一边都会在另一半的情形下断言一件没发生的事。宁可措辞含糊,不可言之凿凿地说错。
dl_rc_class() {
  if [ "$DL" = curl ]; then
    case "$1" in
      23)  echo write ;;
      6|7) echo unreachable ;;
      28)  echo stall ;;
      22)  echo http ;;
      *)   echo other ;;
    esac
  else
    case "$1" in
      3)     echo write ;;
      8)     echo http ;;
      4|5|7) echo netfail ;;
      *)     echo other ;;
    esac
  fi
}

# dl_unreachable <退出码> 这次失败是不是「网络这一层没成」。
# 从 dl_rc_class 派生,别再列一份码表 —— 两份迟早对不上,而对不上的那天没有任何测试会红。
dl_unreachable() {
  case "$(dl_rc_class "$1")" in unreachable|stall|netfail) return 0 ;; esac
  return 1
}

# dl_file <url> <落点> <small|big> 下载到文件,返回底层工具的退出码。
dl_file() {
  if [ "$DL" = curl ]; then
    case "$3" in
      big) curl "${CURL_BIG[@]}" -o "$2" "$1" ;;
      *)   curl "${CURL_SMALL[@]}" -o "$2" "$1" ;;
    esac
  else
    case "$3" in
      big) wget "${WGET_BIG[@]}" -O "$2" "$1" ;;
      *)   wget "${WGET_SMALL[@]}" -O "$2" "$1" ;;
    esac
  fi
}

# dl_stdout <url> 取到标准输出;取不到就是空,由调用方判断。
dl_stdout() {
  if [ "$DL" = curl ]; then curl "${CURL_SMALL[@]}" "$1" 2>/dev/null
  else wget "${WGET_SMALL[@]}" -O - "$1" 2>/dev/null; fi
}

# dl_final_url <url> 跟完重定向后的最终地址(用来从 /releases/latest 解出 tag)。
#
# wget 这边没有 -w '%{url_effective}',只能读 --server-response 打出来的响应头,取最后
# 一个 Location。取**最后**一个而不是第一个:GitHub 这条会重定向不止一跳,取第一个拿到的
# 是中间地址,解出来的「版本号」会是个不存在的东西。拿不到 Location 就回显原地址 ——
# 与 curl 没发生重定向时的行为一致,交给上面那段 v[0-9]* 的校验去判。
dl_final_url() {
  if [ "$DL" = curl ]; then
    curl "${CURL_SMALL[@]}" -I -o /dev/null -w '%{url_effective}' "$1" 2>/dev/null
  else
    local rc=0 out loc
    out="$(wget "${WGET_PROBE[@]}" "$1" 2>&1)" || rc=$?
    # 失败必须原样把退出码交出去。吞掉的话上面会拿着回显的原地址往下走,把版本号解析成
    # 字面的 "latest",最后报一句「没能解析出版本号」—— 而真因是网络没通,两者差着十万八千里。
    [ "$rc" = 0 ] || return "$rc"
    loc="$(printf '%s\n' "$out" | awk 'tolower($1)=="location:"{print $2}' | tail -1)"
    printf '%s' "${loc:-$1}"
  fi
}

# dl_file_code <url> <落点> 下载并打出 HTTP 状态码(SHA256SUMS 要靠它把 404 和别的错分开)。
#
# wget 同样没有 -w '%{http_code}':成功就按 200 报,失败时从响应头里捞状态码,捞不到就报
# 000(与 curl 连不上时的输出一致)。
dl_file_code() {
  if [ "$DL" = curl ]; then
    curl "${CURL_SMALL[@]}" -o "$2" -w '%{http_code}' "$1" 2>/dev/null
  else
    local rc=0 code
    wget "${WGET_SMALL[@]}" -O "$2" "$1" 2>/dev/null || rc=$?
    if [ "$rc" = 0 ]; then printf '200'; return 0; fi
    # 和 curl --fail 一个契约:退出码说明「没取到」,打出来的状态码说明「为什么」。
    # 调用方靠这两样把「这个版本本来就没有清单(404)」和「这次没取到」分开,少给一样都判不了。
    code="$(wget "${WGET_PROBE[@]}" "$1" 2>&1 | awk '/^ *HTTP\//{c=$2} END{print c}')"
    printf '%s' "${code:-000}"
    return "$rc"
  fi
}

CHECK_ONLY=0; SKIP_CHECK=0; NO_SETUP=0; SETUP_ARGS=()
# MagicDNS 后缀:预置的环境变量作默认,--magic-suffix 覆盖。本脚本不校验(规则单一来源在
# install-self-hosted.sh 的 apply_magic_suffix),只透传;非法值会在那边写 config.toml 前被拦。
MAGIC_SUFFIX="${NANOTUN_MAGIC_SUFFIX:-}"
while [ $# -gt 0 ]; do
  case "$1" in
    --check-only) CHECK_ONLY=1; shift ;;
    --skip-check) SKIP_CHECK=1; shift ;;
    --no-setup)   NO_SETUP=1; shift ;;
    # MagicDNS 后缀经环境变量下传给 install-self-hosted.sh(它只吃 env,argv 全归向导)。
    # 在这里拦下来,别落进 SETUP_ARGS —— 否则会被开服向导当未知参数拒掉(exit 2)。
    # 不用 die():它在本循环之后才定义(与下面 SETUP_ARGS 冲突检查同一口径,直接 printf+exit)。
    --magic-suffix)
      case "${2:-}" in
        ''|-*) printf 'install.sh: --magic-suffix 后面要跟一个后缀。例:--magic-suffix nanotun\n' >&2; exit 2 ;;
      esac
      MAGIC_SUFFIX="$2"; shift 2 ;;
    # 打开头那段注释。不写死行号 —— 改文档时忘了同步行号,--help 就会截半句话。
    # 被 curl | bash 时 $0 不是文件,读不到就退回一个链接。
    -h|--help)
      # 退回的那份必须自己够用。--help 最常见的用法恰恰是 curl | bash -s -- --help,
      # 而那时 $0 是 "bash"、读不到文件 —— 只回一个链接等于让人再去开一次浏览器。
      awk 'NR>1 && /^#/ {sub(/^#[ \t]?/,""); print; next} NR>1 {exit}' "$0" 2>/dev/null || cat <<EOF
nanotun 一条命令开服 —— 检查环境 → 下载发布包 → 安装 → 开服向导。

  sudo bash -c "\$(curl -fsSL ${RAW_BASE}/install.sh)"

  别用 curl … | sudo bash:Ubuntu/Debian 的 sudo 默认 use_pty,向导会被挂死。

无人值守(CI / cloud-init)—— 先落盘再执行,而且要带 --web-admin:

  curl -fsSL ${RAW_BASE}/install.sh -o nanotun-install.sh \\
    && sudo NANOTUN_WEB_ADMIN_PASSWORD='<密码>' bash nanotun-install.sh \\
         --dial-host <域名> --user <名> --web-admin <后台用户名> --yes

  别写成管道:curl 失败时 bash 拿到空脚本,跑完零行内容后**以 0 退出**,而 CI 只认
  退出码 —— 它会把「什么都没下下来」当成装好了。先落盘则由 && 如实挡住。
  漏掉 --web-admin 则不会建后台管理员,/setup 一直敞着,谁先打开谁就是管理员。

选项:
  --check-only   只做环境检查,一次列全问题后退出(不需要 root)
  --skip-check   跳过环境检查直接装(不建议)
  --no-setup     装完不自动进开服向导
  --magic-suffix <后缀>  MagicDNS 局域网后缀(*.<后缀> → mesh 虚拟 IP),默认 lan;
                 只在首次装机生效(等价 NANOTUN_MAGIC_SUFFIX)。
                 改现有机器:sudo nanotun-set-suffix <后缀>

环境变量:
  NANOTUN_MAGIC_SUFFIX 同 --magic-suffix(命令行优先)
  NANOTUN_WEB_ADMIN_PASSWORD  Web 后台密码,配合 --web-admin <名字>。走环境变量而不是
                      参数:argv 对同机所有用户可见(ps),还会落进 shell history
  NANOTUN_VERSION     要装的版本,默认取最新 Release(不含预发布)
  NANOTUN_INSTALL_DIR 解压落点,默认 /opt/nanotun
  NANOTUN_NO_INSTALL  =1 时只下载解压,不安装(不需要 root)
  NANOTUN_REPO        换仓库(fork 自用)
  NANOTUN_BRANCH      从哪个 ref 取 preflight.sh。默认 NANOTUN_VERSION 是 tag 时跟着它,
                      否则 main
  NANOTUN_VERBOSE     =1 时连 systemd 状态和日志一起打出来(默认只给结论)

github.com 连不上(被墙 / 出站受限)时,把两个下载前缀指到镜像,一键仍然可用。
给的是**完整前缀**,路径型和 ghproxy 那种前缀型镜像都装得下:
  NANOTUN_GH_BASE     发布包的下载前缀,默认 https://github.com/${REPO}
  NANOTUN_RAW_BASE    preflight.sh 的下载前缀,默认
                      https://raw.githubusercontent.com/${REPO}/<ref>/scripts
  例:
    sudo NANOTUN_GH_BASE=https://<镜像>/https://github.com/${REPO} \\
         NANOTUN_RAW_BASE=https://<镜像>/https://raw.githubusercontent.com/${REPO}/main/scripts \\
         bash -c "\$(curl -fsSL https://<镜像>/https://raw.githubusercontent.com/${REPO}/main/scripts/install.sh)"

卸载(装机时一并装成了命令):
  sudo nanotun-uninstall --dry-run    # 先看会动哪些文件
  sudo nanotun-uninstall              # 停服务、删程序,保留配置与数据库

完整说明: https://github.com/${REPO}
EOF
      exit 0 ;;
    # 自己不认得的一律转交开服向导。这条是「一条命令装完就能用」的关键:
    #
    #   curl -fsSL .../install.sh -o nanotun-install.sh \
    #     && sudo bash nanotun-install.sh --dial-host vpn.example.com --user alice --yes
    #
    # 没有它,无人值守就只能拆成两条命令(装完再 sudo nanotun-setup ...),而中间那步
    # 恰恰是最容易被忘掉的 —— 忘了它,服务是起着的,客户端却因为没有 server_dial_host
    # 而连不上,现象离原因很远。
    #
    # 不认得的参数不在这里判死,是因为判据在向导那边(它才知道自己收哪些 flag),
    # 在这里再抄一份必然跟它分头演化。写错的 flag 仍然会被向导当场拒掉并点名。
    *) SETUP_ARGS+=("$1"); shift ;;
  esac
done

# 但如果向导压根不会跑,这些参数就没人接了 —— 而且此刻大概率是把 install.sh 的
# flag 敲错了(比如 --skip-chek)。这种要在动系统之前就拦下,不能装完一整套再说。
if [ ${#SETUP_ARGS[@]} -gt 0 ] && { [ "$CHECK_ONLY" = 1 ] || [ "$NO_SETUP" = 1 ]; }; then
  if [ "$CHECK_ONLY" = 1 ]; then why="--check-only 只检查不安装"; else why="--no-setup 明说了不跑向导"; fi
  printf 'install.sh: 这些参数本该转交开服向导,但这次向导不会跑(%s):%s\n' "$why" "${SETUP_ARGS[*]}" >&2
  printf '   install.sh 自己只认 --check-only / --skip-check / --no-setup,其余一律转交向导(--help 看用法)。\n' >&2
  exit 2
fi

info() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
ok()   { printf '    \033[1;32m✓\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mFATAL: %s\033[0m\n' "$*" >&2; exit 1; }

# 这两个一起给是矛盾的,而按原来的写法后果是**静默装上**:--skip-check 会让下面那段
# `if [ "$SKIP_CHECK" = 0 ]` 整个跳过,而「只检查就退出」正好写在那段里面 ——
# 于是一条本意是「只看看」的命令,以 root 把整个服务端装了。宁可让它报错。
if [ "$CHECK_ONLY" = 1 ] && [ "$SKIP_CHECK" = 1 ]; then
  die "--check-only 和 --skip-check 是矛盾的:一个是只检查不安装,另一个是不检查直接装。
   只想看看这台机器行不行:--check-only
   明知有问题也要硬装:--skip-check"
fi

# curl 和 wget 一个都没有的话,当场说清楚,别等到第一个网络动作再失败。
#
# 早退是为了给对建议。这个脚本第一个碰网络的地方是取 preflight.sh,而那条失败路径给的是
# 「网络不通的话可以 --skip-check」—— 缺下载器时这句话双重误导:网络是通的,而 --skip-check
# 也救不了(下一步取发布包同样要下载器)。照着做的人会去查网络,查不出所以然。
#
# 包名在三大发行版上都叫 curl,不必按发行版分岔;给两条是因为最小镜像上装哪个都行,而
# 已经有 wget 的机器上再装 curl 是多余的一步。
if [ -z "$DL" ]; then
  die "这台机器上既没有 curl 也没有 wget,下载不了任何东西(网络本身可能是好的)。
   装其中一个再重跑本命令:
     apt-get update && apt-get install -y curl      # Debian / Ubuntu
     dnf install -y curl                            # RHEL / Fedora / Alma / Rocky
     zypper install -y curl                         # openSUSE
   实在都装不了,就绕开这台机器的网络:在能上网的机器上打开
     https://github.com/${REPO}/releases
   下对应架构的包拷进来,解压后跑 scripts/install-self-hosted.sh(那一步不联网)。"
fi

# ── 1. 环境自检 ──────────────────────────────────────────────────────────────
#
# 判据全在 preflight.sh 里,这里只负责把它弄到手再跑。不在本文件里重写一份 ——
# 同一套「这台机器行不行」的规则散在三个脚本里,迟早对不上。
#
# 被 curl | bash 时本地没有 scripts/ 目录,得先把 preflight.sh 也下下来;
# 从解压好的发布包里跑时它就在隔壁,直接用本地那份(还能离线)。
run_preflight() {
  local self local_pf pf args=()

  if [ "$CHECK_ONLY" = 1 ]; then
    args+=(--dry-run)          # 只是看看,连 sysctl 都别写
  elif [ "${NANOTUN_NO_INSTALL:-0}" = "1" ]; then
    # 只下载解压,同样不动系统。本脚本头部和 --help 都明写它「不需要 root」,
    # 上面那道 root 硬检查也确实为它放了行 —— 漏的是这里:环境检查照样收到
    # --for-install,于是非 root 被判死在「不是 root」上,一个字节都没下就退了。
    # 文档说不用 root、代码却拦下,这种自相矛盾比单纯的限制更难自查。
    args+=(--dry-run)
  else
    # 跑完就要装,所以非 root 在这条路上是硬伤,得当场判死。
    # --check-only 那条路相反:它明确不需要 root,preflight 只会提醒一句。
    args+=(--for-install)
  fi

  # 只有在「本脚本确实是磁盘上的一个文件」时才找隔壁的 preflight.sh。
  # 这个 -f 判断不能省:被 curl | sudo bash 时 BASH_SOURCE[0] 是字符串 "bash",
  # dirname 出来是 ".",于是「隔壁」就成了用户当前所在目录 —— 那意味着谁在自己
  # 目录里放一个 preflight.sh,我们就以 root 跑了它。走网络那条路反而是安全的。
  self="${BASH_SOURCE[0]:-}"
  if [ -n "$self" ] && [ -f "$self" ]; then
    local_pf="$(cd "$(dirname "$self")" 2>/dev/null && pwd)/preflight.sh"
    if [ -f "$local_pf" ]; then
      bash "$local_pf" "${args[@]+"${args[@]}"}"
      return $?
    fi
  fi

  # 下载器的存在性在文件开头统一判过(那里连 wget 的退路一起说清楚了),这里不再重复一份
  # 口径 —— 两份判据迟早对不上,而对不上的那天,先撞上的那一份说了算。

  # mktemp 失败必须当场拦下,不能让一个空变量顺着往下走。
  #
  # 本函数是在 `if ! run_preflight` 里调用的,而 bash 在条件上下文中会关掉**整个函数体**
  # 的 errexit —— 所以 mktemp 挂了脚本不会停,$pf 只是留空,接着 curl -o "" 报
  # 「blank argument」,最终打出来的是「下载 preflight.sh 失败 / 网络不通的话可以
  # --skip-check」。真实原因是临时目录写不进去:既指错了方向,又建议跳过环境检查。
  # 一台 /tmp 是 0700 root 的机器上,非 root 跑 --check-only 就是这个下场。
  pf="$(mktemp)" || pf=""
  [ -n "$pf" ] || die "创建临时文件失败 —— ${TMPDIR:-/tmp} 写不进去(权限 / 只读 / 配额 / 空间不足)。
   换个位置重试,例如:TMPDIR=/var/tmp <刚才那条命令>"
  # 失败时要分清两种原因,它们的下一步完全不同。
  #
  # BRANCH 现在默认跟着 NANOTUN_VERSION 走(见文件开头),所以钉了一个**没有这个文件的
  # tag**(比如 fork 上的老版本)也会走到这里 —— 那不是网络问题,而 --skip-check 恰好是
  # 这种情形下最坏的建议:它把一次「取错了地方」升级成一次不做检查的安装。
  if ! dl_file "$RAW_BASE/preflight.sh" "$pf" small; then
    rm -f "$pf"
    local hint="   网络不通的话可以 --skip-check 跳过检查直接装(风险自负)。"
    if [ "$BRANCH" != main ]; then
      # 钉了 ref 却取不到,有两种原因,下一步完全相反 ——
      #   ① 这个版本根本不存在(版本号敲错、或猜了一个还没发的号)。要做的是改版本号。
      #   ② tag 在,只是那会儿还没有 scripts/preflight.sh(老版本 / fork)。要做的是走主干。
      # 原来这里一律按 ② 说,而 ① 才是常见的那个。照 ② 的建议走(NANOTUN_BRANCH=main)会
      # 顺利跑完一整屏环境检查、打出「✓ 版本: v0.1.99」和「✓ 这台机器可以装 nanotun」,
      # 二十秒后才在下载发布包时撞上真正的原因 —— 中间每一步都在替那个不存在的版本背书。
      #
      # 探针取同目录下的 install.sh:任何真实 tag 上都有它(它就是正在跑的这个脚本),
      # 而 ref 不存在时 raw 对该 ref 下的任何路径都回 404,两种情形一次请求就分开了。
      local probe code=000
      probe="$(mktemp)" || probe=""
      if [ -n "$probe" ]; then
        code="$(dl_file_code "$RAW_BASE/install.sh" "$probe" 2>/dev/null || true)"
        rm -f "$probe"
      fi
      # 指了镜像时不下断言:镜像缺这个 tag、或路径形状对不上,同样是 404,而那跟「版本不存在」
      # 是两回事,照着去改版本号只会越走越远。这一支单独写,别拿哨兵值混进下面的 case ——
      # 混进去的下场是文案里冒出一句「探 install.sh 得到 mirror」,内部值直接糊到用户脸上。
      if [ -n "${NANOTUN_RAW_BASE:-}" ]; then
        hint="   用的是自定义 NANOTUN_RAW_BASE(镜像),从它那儿没取到这个文件。
   先确认镜像地址本身对不对 —— 它要能拼出 <前缀>/preflight.sh 这个形状:
     ${RAW_BASE}/preflight.sh
   镜像不灵就先不设 NANOTUN_RAW_BASE 直连试试,或 --skip-check 跳过检查(风险自负)。"
      else
      case "$code" in
        404)
          hint="   ${BRANCH} 这个版本不存在 —— 同一个 ref 下连 install.sh 也是 404。
   核对版本号:${GH_BASE}/releases
   想装最新版就不要设 NANOTUN_VERSION,不设时脚本会自己解析 latest。" ;;
        200)
          hint="   ${BRANCH} 这个 tag 在,但它里面没有 scripts/preflight.sh(老版本 / fork 会这样)。
   加 NANOTUN_BRANCH=main 让脚本走主干(发布包仍按 NANOTUN_VERSION 钉住),或者
   --skip-check 跳过检查直接装(风险自负)。" ;;
        000)
          # 一个 HTTP 响应都没拿到 —— 网络 / DNS / TLS 那一层就断了,跟版本号无关。
          # 这时候把「先核对版本号」摆在第一句是把人往错的方向支:版本再对也取不到。
          hint="   连 ${RAW_BASE%/scripts} 都没连上(探 install.sh 一个 HTTP 响应都没拿到)——
   先查网络、DNS、出站防火墙或代理。这时候换个 NANOTUN_VERSION 没用,取包走的是同一个地址。
   上不去 github.com 的话,可以指到镜像(NANOTUN_GH_BASE / NANOTUN_RAW_BASE,见 --help),
   或 --skip-check 跳过检查直接装(风险自负)。" ;;
        *)
          # 服务器答了,但不是 200 也不是 404:多半是 429 / 403 限流,或 5xx。
          hint="   取的是 ${BRANCH} 这个 ref,没能分清是版本不存在还是这次没取到(探 install.sh 得到 ${code})。
   ${code} 这种多半是限流(429 / 403)或对面临时故障(5xx)—— 隔几分钟重试常常就好了。
   一直这样的话先核对版本号:${GH_BASE}/releases
   版本没错的话,加 NANOTUN_BRANCH=main 走主干,或 --skip-check 跳过检查(风险自负)。" ;;
      esac
      fi
    fi
    die "下载 preflight.sh 失败: $RAW_BASE/preflight.sh
$hint"
  fi
  bash "$pf" "${args[@]+"${args[@]}"}"
  local rc=$?
  rm -f "$pf"
  return $rc
}

if [ "$SKIP_CHECK" = 0 ]; then
  if ! run_preflight; then
    if [ "$CHECK_ONLY" = 1 ]; then exit 1; fi
    die "环境检查没过(见上面的修复清单)。修完重跑本命令;
   确认要带着问题硬装可以加 --skip-check。"
  fi
  [ "$CHECK_ONLY" = 1 ] && exit 0
else
  printf '    \033[1;33m!\033[0m --skip-check:跳过环境检查\n'
fi

case "$(uname -m)" in
  x86_64|amd64)  ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "不支持的架构 $(uname -m)。发布包只有 linux-amd64 与 linux-arm64;
   其它架构请自行 go build(见仓库 README 的源码构建一节)。" ;;
esac

# --skip-check 绕过了 preflight,这两条最基本的还是要拦,否则后面直接报错更难懂。
# 装法按本机的包管理器给 —— 原来一律写 apt,在 openSUSE(zypper)/ RHEL(dnf)上就是
# 一条粘上去必定失败的命令。preflight 那条正路早按发行版给对了命令,这里是 --skip-check
# 绕开 preflight 后的兜底,不能反而退化成 Debian 专用。
_pkg_hint() { # _pkg_hint <包名> —— 猜一条能直接粘的安装命令
  if   command -v apt-get >/dev/null 2>&1; then echo "apt install $1"
  elif command -v dnf     >/dev/null 2>&1; then echo "dnf install $1"
  elif command -v zypper  >/dev/null 2>&1; then echo "zypper install $1"
  elif command -v yum     >/dev/null 2>&1; then echo "yum install $1"
  elif command -v apk     >/dev/null 2>&1; then echo "apk add $1"
  elif command -v pacman  >/dev/null 2>&1; then echo "pacman -S $1"
  else echo "用本机包管理器装上 $1"; fi
}
# 下载器同上,开头已判(有 curl 用 curl,没有就退到 wget)。这里只留 tar ——
# 它没有替代品,而且解包这一步在没有网络的手工安装路径上同样要用。
command -v tar  >/dev/null 2>&1 || die "缺少 tar($(_pkg_hint tar))"
if [ "${NANOTUN_NO_INSTALL:-0}" != "1" ] && [ "$(id -u)" != "0" ]; then
  die "安装需要 root。请用 sudo 跑,或设 NANOTUN_NO_INSTALL=1 只下载。"
fi

# ── 2. 定版本 ────────────────────────────────────────────────────────────────
VERSION="${NANOTUN_VERSION:-}"
if [ -z "$VERSION" ]; then
  info "查询最新 Release ..."
  # 不解析 JSON(机器上不一定有 jq),跟着 /releases/latest 的 302 读 Location 里的 tag。
  # 比 grep API 返回体稳:API 有速率限制,未认证时一小时 60 次,CI 或反复重试很容易撞到。
  # 失败原因要分开说。原来一律是「检查网络或用 NANOTUN_VERSION 指定版本」,而最常撞上
  # 这一步的恰恰是「这台机器连不上 github.com」—— 那种情形下指定版本号救不了:下一步取
  # 发布包走的还是 github.com,照做只会在二十秒后死在同一堵墙上。给不通的建议比不给更糟。
  LATEST_RC=0
  latest_url="$(dl_final_url "${GH_BASE}/releases/latest")" || LATEST_RC=$?
  if [ "$LATEST_RC" != 0 ]; then
    # 报的是 $GH_BASE 而不是写死的「github.com」:设了镜像时,一句「连不上 github.com」
    # 会让人去查一个跟这次失败无关的域名 —— 真正没通的是他自己填的那个前缀。
    if dl_unreachable "$LATEST_RC"; then
      die "查询最新版本失败:连不上 ${GH_BASE}($DL $LATEST_RC:解析不了 / 连不上 / 连上了不给数据)。
   先检查网络、DNS、出站防火墙或代理。注意这时候**指定 NANOTUN_VERSION 也没用** ——
   下一步取发布包走的是同一个地址。
   这台机器上不去 github.com 的话,有两条路:
     一、指到镜像(一键仍然可用):
       sudo NANOTUN_GH_BASE=<镜像前缀> NANOTUN_RAW_BASE=<镜像前缀>/scripts bash -c \"\$(curl -fsSL …/install.sh)\"
     二、绕开这台机器的网络:在能上网的机器上打开
       https://github.com/${REPO}/releases
     下 linux-$ARCH 那个包,拷到这台机器上装(装的这一步不联网):
       tar -xzf nanotun-<版本>-linux-$ARCH.tar.gz
       sudo ./nanotun-<版本>-linux-$ARCH/scripts/install-self-hosted.sh"
    else
      die "查询最新版本失败($DL $LATEST_RC)。
   可以用 NANOTUN_VERSION 钉一个版本绕开这次查询,版本号见
     https://github.com/${REPO}/releases"
    fi
  fi
  VERSION="${latest_url##*/}"
  case "$VERSION" in
    v[0-9]*) ;;
    # 走到这儿有两种可能,而它们的下一步动作完全不同,所以别只说「还没发过 Release」:
    # /releases/latest **不含预发布**,只发过 rc 时它会退回 /releases 这个列表页,
    # 于是这里拿到的是字面的 "releases"。仓库明明有能装的版本,却被告知「还没发过」——
    # 用户只会以为没得装,而不是去挑一个 rc。这正是 v0.1.0-rc1 发出去当天的实况。
    releases)
      # 顺手把最新那个报出来,别让人自己去翻网页。
      # releases.atom 是公开 RSS:含预发布、按时间倒序、不像 API 有 60 次/小时的限速,
      # 也不需要 jq。写死一个示例版本号是会烂的 —— 这里原本举的例子是 rc1,
      # 而 rc2 第二天就把它顶掉了,照着抄只会装到一个过时的版本。
      newest="$(dl_stdout "${GH_BASE}/releases.atom" \
        | sed -n 's#.*<link[^>]*releases/tag/\([^"]*\)".*#\1#p' | head -1)"
      case "$newest" in
        # URL 要写全。这条命令是给人**原样粘走**的 —— 原来这里是 `.../install.sh`,
        # 省略号粘过去就是一个不存在的地址,等于还得自己回去翻文档拼一遍。
        v[0-9]*) die "${REPO} 目前只有预发布版本(rc),而 /releases/latest 不含预发布。
   最新的是 ${newest},照抄这条:
     sudo NANOTUN_VERSION=${newest} bash -c \"\$(curl -fsSL ${RAW_BASE}/install.sh)\"" ;;
        *) die "${REPO} 目前只有预发布版本(rc),而 /releases/latest 不含预发布。
   到 https://github.com/${REPO}/releases 挑一个,再用 NANOTUN_VERSION=vX.Y.Z 指定。" ;;
      esac ;;
    *) die "没能从 $latest_url 解析出版本号。可能该仓库还没发过 Release;
   用 NANOTUN_VERSION=vX.Y.Z 显式指定。" ;;
  esac
fi
ok "版本: $VERSION"

TARBALL="nanotun-${VERSION}-linux-${ARCH}.tar.gz"
BASE="${GH_BASE}/releases/download/${VERSION}"

# ── 3. 下载 + 校验 ───────────────────────────────────────────────────────────
TMP="$(mktemp -d)" || TMP=""
[ -n "$TMP" ] || die "创建临时目录失败 —— ${TMPDIR:-/tmp} 写不进去(权限 / 只读 / 配额 / 空间不足)。
   换个位置重试,例如:TMPDIR=/var/tmp <刚才那条命令>"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

info "下载 $TARBALL ..."
# curl 的退出码要分开看。原来无论怎么失败都归结成「确认该版本存在且有 linux-xxx 产物」,
# 于是磁盘写满时(curl 23,它自己已经打了 "Failure writing output to destination")
# 屏幕上让人去 GitHub Releases 查有没有这个产物 —— 方向完全错了,而真正要做的是腾地方
# 或换 TMPDIR。实测在一个只剩 1M 的 TMPDIR 上就是这个下场。
CURL_RC=0
dl_file "$BASE/$TARBALL" "$TMP/$TARBALL" big || CURL_RC=$?
if [ "$CURL_RC" != 0 ]; then
  # 「在别处下好再拷进来」这段在 stall 和 netfail 两条里都要说,提出来免得两份各自漂移。
  OFFLINE_HINT="   一直不通的话,在能上网的机器上下好这个包,拷到这台机器上装(装的这一步不联网):
     $BASE/$TARBALL
     tar -xzf $TARBALL && sudo ./${TARBALL%.tar.gz}/scripts/install-self-hosted.sh"
  case "$(dl_rc_class "$CURL_RC")" in
    write) die "下载失败:写不进 ${TMPDIR:-/tmp}($DL $CURL_RC:写目标文件失败)。
   多半是空间不足或只读。腾出空间,或换个位置重试:TMPDIR=/var/tmp <刚才那条命令>
   当前可用:$(df -h "$TMP" 2>/dev/null | awk 'NR==2{print $4}')" ;;
    # 报 $GH_BASE 而不是写死的「github.com」:设了镜像时没通的是那个前缀,而一句
    # 「连不上 github.com」会把人支到一个跟这次失败无关的域名上去查。
    unreachable) die "下载失败:连不上 ${GH_BASE}($DL $CURL_RC:DNS 解析不了 / 连接被拒)。
   检查网络、DNS、出站防火墙或代理。${NANOTUN_GH_BASE:+
   这是你用 NANOTUN_GH_BASE 指定的镜像 —— 先确认它本身是通的。}" ;;
    # 这里**不能**建议 NANOTUN_NO_INSTALL=1:那条路自己也要先下同一个包,照做只会在
    # 同一步再失败一次。给不通的建议比不给更糟 —— 人会以为是自己哪里做错了,再试一遍。
    # 真正的出路是绕开这台机器的网络:在别处把 tar 下好,拷进来,直接跑包里的安装脚本
    # (那一步不联网)。
    stall) die "下载失败:连上了但数据不来($DL $CURL_RC:30 秒内速度不到 1KB/s,已重试 3 次)。
   不是「你的网慢」—— 慢但在动的下载不会走到这里,这是彻底停住了。多半是到
   ${GH_BASE} 的链路被中断或被墙,换个时间 / 换条线路重试${NANOTUN_GH_BASE:+
   (这是你用 NANOTUN_GH_BASE 指定的镜像)}${NANOTUN_GH_BASE:-
   (被墙的话可以用 NANOTUN_GH_BASE 指到镜像,见 --help)}。
$OFFLINE_HINT" ;;
    # wget 分不出「压根没通」和「连上了不给数据」,所以这条把两种都覆盖掉,而不去断言
    # 具体是哪一种 —— 断错了会把人往错的方向支。
    netfail) die "下载失败:网络这一层没成($DL $CURL_RC:DNS / 连接 / TLS / 读超时,wget 把这几种并成一个码)。
   先检查网络、DNS、出站防火墙或代理;都正常的话多半是到 ${GH_BASE} 的链路被中断或被墙,
   换个时间 / 换条线路重试${NANOTUN_GH_BASE:+
   (这是你用 NANOTUN_GH_BASE 指定的镜像 —— 先确认它本身是通的)}${NANOTUN_GH_BASE:-
   (被墙的话可以用 NANOTUN_GH_BASE 指到镜像,见 --help)}。
$OFFLINE_HINT" ;;
    http) die "下载失败:服务器返回 404 之类的错($DL $CURL_RC): $BASE/$TARBALL
   确认该版本存在且有 linux-$ARCH 产物:https://github.com/${REPO}/releases" ;;
    *)    die "下载失败($DL $CURL_RC): $BASE/$TARBALL
   确认该版本存在且有 linux-$ARCH 产物:https://github.com/${REPO}/releases" ;;
  esac
fi

info "校验 SHA256 ..."
# 取不到清单要分清是「这个版本本来就没有」还是「这次没取到」。原来一律归成前者,
# 打一句「该版本没有 SHA256SUMS,跳过校验」就往下走 —— 可眼下每一个已发布版本都带
# 着 SHA256SUMS,于是这句话真出现的时候,说的必然是假话:真因是取失败(网络被掐、
# CDN 抽风、出站被拦),而不是清单不存在。代价是悄悄把完整性校验降级了,接着还要
# 以 root 解包、跑里面的安装脚本 —— 而管道形态下那行黄字多半没人看见。
# 404 才是「真没有」(留给将来手工补发的老版本),其余一律当失败处理。
SHA_RC=0
SHA_HTTP="$(dl_file_code "$BASE/SHA256SUMS" "$TMP/SHA256SUMS")" || SHA_RC=$?
if [ "$SHA_RC" = 0 ]; then
  if command -v sha256sum >/dev/null 2>&1; then
    SHA_SUM=(sha256sum); SHA_CHECK=(sha256sum -c --ignore-missing -)
  elif command -v shasum >/dev/null 2>&1; then
    SHA_SUM=(shasum -a 256); SHA_CHECK=(shasum -a 256 -c --ignore-missing -)
  else
    SHA_SUM=(); SHA_CHECK=()
  fi

  if [ "${#SHA_CHECK[@]}" -gt 0 ]; then
    # 校验失败之前,先分清「清单本身有问题」和「包真的对不上」——
    # `sha256sum -c` 对这三件事给的是同一个非零退出码,而它们的处置完全不同:
    #
    #   ① 取到的根本不是校验清单(代理 / 门户 / 坏镜像回一页 HTML,状态码还是 200)
    #   ② 清单是真的,但里面没有本机架构这一条(发布时清单没覆盖全)
    #   ③ 清单里有这一条,而算出来的哈希对不上 —— 这才是「传输损坏或被人替换」
    #
    # 原来三种一律报 ③ 那句「下载的包与官方清单不符,可能是被中间人替换过」。①② 两种
    # 情形下这句话是假的:包压根没跟任何东西比对过。它既指错了方向(让人去查网络、
    # 疑心被劫持),又把真正该做的事(换条链路 / 手动核对)藏了起来。
    #
    # awk 里不用 {64} 这种区间写法。新一点的 mawk(实测 1.3.4)是支持的,但老 mawk(1.3.3)
    # 不认,而它还躺在一些老镜像里 —— 真碰上的话后果是这条永不匹配,于是**每一份正常清单**
    # 都被判成「不是清单」,安装全线中断。用 length() 换个写法就不必赌这件事。
    if ! awk '$1 ~ /^[0-9a-fA-F]+$/ && length($1) == 64 { ok = 1 } END { exit(ok ? 0 : 1) }' \
         "$TMP/SHA256SUMS"; then
      die "取到的 SHA256SUMS 不是一份校验清单 —— 里面没有任何一行是「64 位十六进制 + 文件名」。
   开头是这样:$(head -c 120 "$TMP/SHA256SUMS" | tr -d '\r' | head -1)
   多半是这条链路上有东西把响应换掉了:公司代理、酒店 / 机场的登录门户,或者不灵的镜像 ——
   它们对任何请求都回一页 HTML,而 HTTP 状态码照样是 200。
   包没有跟任何东西比对过,别装。换条网络或换个镜像重来;
   $BASE/SHA256SUMS 在浏览器里打开应当是一页纯文本。"
    fi
    # 清单里有没有本机这个包。用 awk 逐行比第二列(去掉二进制模式的 * 前缀),
    # 而不是拿文件名去拼正则 —— 名字里有点号,拼出来的正则会把它当通配符。
    if ! awk -v want="$TARBALL" '{ f = $2; sub(/^\*/, "", f); if (f == want) found = 1 }
                                 END { exit(found ? 0 : 1) }' "$TMP/SHA256SUMS"; then
      die "校验清单里没有 $TARBALL 这一条,没法核对下载的包。
   清单里有的是:
$(awk '{ f = $2; sub(/^\*/, "", f); if (f != "") print "     " f }' "$TMP/SHA256SUMS" | head -10)
   包本身未必有问题 —— 更像是这个版本发布时清单没覆盖全(比如只生成了另一个架构的)。
   但没核对过就不该装:到 https://github.com/${REPO}/releases 手动核对后再装,或换一个版本。
   本机算出来的是:$("${SHA_SUM[@]}" "$TMP/$TARBALL" 2>/dev/null | awk '{print $1}')"
    fi
    # --ignore-missing:清单里同时有 amd64 和 arm64 两条,我们只下了一个。
    # 在 tar 所在目录执行,清单里是裸文件名。
    # 走到这里,清单是真的、里面也有我们这个文件 —— 再失败就确实是哈希对不上了。
    ( cd "$TMP" && "${SHA_CHECK[@]}" < SHA256SUMS >/dev/null ) \
      || die "SHA256 校验失败 —— 下载的包与官方清单不符,已中止。
   可能是传输损坏,也可能是被中间人替换过。别装,重下一次;还不行就去
   https://github.com/${REPO}/releases 手动核对。"
    ok "校验通过"
  else
    printf '    \033[1;33m!\033[0m 本机既无 sha256sum 也无 shasum,跳过校验\n'
  fi
elif [ "$SHA_HTTP" = 404 ]; then
  printf '    \033[1;33m!\033[0m %s 确实没有 SHA256SUMS(404),跳过校验\n' "$VERSION"
else
  die "取不到校验清单 SHA256SUMS(curl $SHA_RC,HTTP ${SHA_HTTP:-无响应}): $BASE/SHA256SUMS
   包已经下下来了,但没法核对它是不是官方那一份 —— 这一步不能跳过就装,
   下一步要以 root 解包并执行里面的安装脚本。
   多半是网络抖动或出站被拦,重跑一次即可;确认这个版本本就没有清单的话,
   到 https://github.com/${REPO}/releases 手动核对 SHA256 再装。"
fi

# ── 4. 解压 ──────────────────────────────────────────────────────────────────
DEST="${INSTALL_DIR}/${VERSION}-${ARCH}"
info "解压到 $DEST ..."
mkdir -p "$DEST" || die "建不出 $DEST —— 检查 $INSTALL_DIR 的权限,或用 NANOTUN_INSTALL_DIR 换个落点。"
# --strip-components=1:tar 内是 nanotun-<ver>-linux-<arch>/ 一层目录,
# 剥掉它,免得路径变成 /opt/nanotun/v0.1.0-amd64/nanotun-v0.1.0-linux-amd64/。
#
# 解压失败最常见的就是磁盘不够:包 ~19MB,解开约 150MB。preflight 那道空间检查看的是
# /usr/local(装二进制的地方),与这里的落点未必同一个文件系统,而且它是 soft 警告、
# 不拦安装。所以这里必须自己兜住 —— 否则用户只看到 tar 的一行 "No space left on
# device" 然后脚本戛然而止,不知道要腾多少、腾在哪。
if ! tar -xzf "$TMP/$TARBALL" -C "$DEST" --strip-components=1; then
  rm -rf "$DEST"   # 半个解压目录留着只会让下次重跑以为装过了
  die "解压失败:$DEST
   包解开约 150MB。当前该分区可用:$(df -h "$INSTALL_DIR" 2>/dev/null | awk 'NR==2{print $4}')
   腾出空间后重跑,或换个落点:NANOTUN_INSTALL_DIR=/data/nanotun <刚才那条命令>"
fi
ok "已解压"

if [ "${NANOTUN_NO_INSTALL:-0}" = "1" ]; then
  echo
  info "NANOTUN_NO_INSTALL=1,到此为止。手动安装:"
  echo "    sudo $DEST/scripts/install-self-hosted.sh    # 装二进制 / systemd / 防火墙"
  echo "    sudo $DEST/scripts/setup.sh                  # 开服向导:拨号地址 / 用户 / 二维码"
  exit 0
fi

# /proc/<pid>/stat 取字段。comm 那一项裹在括号里、且允许含空格甚至右括号,所以从
# **最后**一个 ") " 之后才开始数。编号以 state 为第 1 项:2=ppid,5=tty_nr。
proc_stat_field() { # <pid> <字段号>
  local s
  s="$(cat "/proc/$1/stat" 2>/dev/null)" || return 1
  s="${s##*) }"
  printf '%s\n' "$s" | awk -v n="$2" '{print $n}'
}

# 认出「sudo 另开了 pty」这个组合 —— `curl … | sudo bash` 会在交棒给向导时挂死,
# 而原因不在 nanotun:
#
# Ubuntu / Debian 的 /etc/sudoers 默认带 `Defaults use_pty`,sudo 会另建一个 pty
# 会话把命令跑在里面,而不是直接用你正在敲字的那个终端。于是进程眼里的 /dev/tty 是
# sudo 造出来的内层 pty;再叠加 sudo 的 stdin 是 curl 那根管道(而且已读到底),
# 向导一去读它就被作业控制的停止信号挂起(ps 里是 T 状态、wchan=do_signal_stop),
# 父进程正等着它的输出 —— 死锁。用户看到的是提示符出来了、回车毫无反应。
#
# 实测(Ubuntu 26.04 全新 VPS):`curl … | sudo bash` 两次两挂;换成把脚本当参数传
# (`sudo bash -c "$(curl …)"`)则 71 秒装完 —— 那种形态下 bash 的 stdin 本身就是终端,
# 压根不用绕 /dev/tty。
#
# 所以认出来就不碰 /dev/tty:装照样装完,向导留给人手动跑,并把能一次到底的命令原样
# 打出来。宁可多敲一条,也不能挂在那儿让人以为装崩了。
#
# 判据是「祖先里存在一个 sudo,它的控制终端跟本进程不是同一个」—— 那就说明中间隔着
# 一层 sudo 新造的 pty,我们的 /dev/tty 不是用户正在敲字的那个终端。
#
# 必须把整条链走完,不能撞见第一个 sudo 就下结论:开了 pty 时链上会**同时有两个 sudo**,
# 内层那个(监督进程)跟命令一起待在新 pty 里、tty 与我们相同,只有外层那个还留在用户的
# 真终端上。只看最近的那个,永远得出「没开 pty」的结论 —— 第一版就是这么漏掉的。
#
# 没开 pty 的发行版上,链上唯一的 sudo 与我们同 tty,判定为假,照走原来的 /dev/tty 路径。
under_sudo_pty() {
  [ -r /proc/self/stat ] || return 1   # 没有 /proc 就不猜,交给原路径
  local mytty pid ttynr
  mytty="$(proc_stat_field $$ 5)"; [ -n "$mytty" ] || return 1
  pid="$(proc_stat_field $$ 2)"
  while [ -n "$pid" ] && [ "$pid" -gt 1 ] 2>/dev/null; do
    if [ "$(cat "/proc/$pid/comm" 2>/dev/null)" = sudo ]; then
      ttynr="$(proc_stat_field "$pid" 5)"
      if [ -n "$ttynr" ] && [ "$ttynr" != "$mytty" ]; then return 0; fi
    fi
    pid="$(proc_stat_field "$pid" 2)"
  done
  return 1
}

# 向导要问话,所以先弄清楚这次到底有没有人能回答。置 SETUP_STDIN(空 = 没人能答)
# 与 SKIP_WHY(跳过的原因,给收尾提示用)。
#
# 被 `curl … | bash` 跑时 stdin 是 curl 那根管道(而且已经读到底了),`-t 0` 永远为假 ——
# 哪怕人就坐在终端前面。但管道占的只是 stdin,控制终端还在,/dev/tty 就是它,把向导的
# stdin 重新指过去就能照常问话(rustup 之流的老做法)。
#
# 判据是「能不能真的打开 /dev/tty」,不是「文件在不在」:CI、cron、systemd 里
# /dev/tty 这个节点通常也在,但进程没有控制终端,一 open 就 ENXIO。所以这里真去开一次。
SETUP_STDIN=""; SKIP_WHY=""
setup_stdin_probe() {
  if [ -t 0 ]; then
    SETUP_STDIN=/dev/stdin
  elif { : </dev/tty; } 2>/dev/null; then
    if under_sudo_pty; then SKIP_WHY=sudo_pty; else SETUP_STDIN=/dev/tty; fi
  fi
}

# ── 5. 安装 ──────────────────────────────────────────────────────────────────
#
# 「等下会不会自动进向导」这件事必须**在安装之前**就定下来,虽然向导要装完才跑。
# 因为 install-self-hosted.sh 的收尾语要照它分岔:向导紧接着就来的话,它只说一句
# 「马上开始」;没人接的话才该郑重催「还差最后一步:sudo nanotun-setup」。之前不分
# 情形一律催,于是催完向导自己启动了 —— 照着做的人会在向导跑完后又原样敲一遍。
#
# 判据只跟终端和参数有关,跟装没装成无关,所以提前算没有副作用。
setup_stdin_probe
WIZARD_FOLLOWS=0
if [ "$NO_SETUP" = 0 ] && { [ -n "$SETUP_STDIN" ] || [ ${#SETUP_ARGS[@]} -gt 0 ]; }; then
  WIZARD_FOLLOWS=1
fi

info "执行安装脚本 ..."
echo
# 安装脚本按自身位置推导发布包根目录,不必再传 DEPLOY_DIR。
# 环境已经在第 1 步验过了,不必再验一遍。
# NANOTUN_MAGIC_SUFFIX 显式下传:--magic-suffix 已合并进它,空值在 install-self-hosted.sh
# 里被 apply_magic_suffix 直接跳过(沿用模板默认后缀)。
NANOTUN_PREFLIGHT_DONE=1 NANOTUN_WIZARD_FOLLOWS="$WIZARD_FOLLOWS" \
  NANOTUN_MAGIC_SUFFIX="$MAGIC_SUFFIX" \
  "$DEST/scripts/install-self-hosted.sh"

# ── 6. 开服向导 ──────────────────────────────────────────────────────────────
#
# 装完不等于能用:还差拨号地址、Web 管理员、用户的二维码。以前这里就结束了,
# 把这三件事留给用户自己从输出里读出来 —— 既然是「一条命令开服」,就一路走到底。
if [ "$NO_SETUP" = 1 ]; then
  echo
  # 「还差最后一步」只对首装成立。--no-setup 的头号用法恰恰是**升级**(README 就是这么
  # 推荐的:重跑 install.sh 加 --no-setup),而那台机器早就配好、正跑着 —— 于是屏幕上
  # 最后一句在通知人「你的部署没配完」,而它上面十五行刚说过「此前已配置过,现有用户与
  # 密钥都没动」。两句话出自同一次运行,互相拆台,而最后那句最显眼。
  #
  # install-self-hosted.sh 早就按 server_dial_host 分岔出了正确的说法(见那边的
  # DIAL_SET),只是本脚本这条早退路径绕过了它,自己又催了一遍。判据取同一个值。
  if [ -n "$(/usr/local/bin/nanotun-admin --db-path /var/lib/nanotun/nanotun.db \
       setting get server_dial_host 2>/dev/null | tail -1 | tr -d '[:space:]')" ]; then
    info "--no-setup:跳过开服向导(这台机器此前已配置过,现有用户与密钥都没动)。"
    echo "    要加用户 / 重出二维码 / 改拨号地址:sudo nanotun-setup"
  else
    info "--no-setup:跳过开服向导。想连上客户端还差最后一步:"
    echo "    sudo nanotun-setup"
  fi
  exit 0
fi

if [ ! -x /usr/local/bin/nanotun-setup ]; then
  echo
  info "这个版本的发布包里没有开服向导,手动完成剩下的配置:"
  echo "    见 https://github.com/${REPO}#快速启动"
  exit 0
fi

# 给了参数就未必需要人回答了 —— 带 --yes 的那套本来就是无人值守用的,
# 这种情况下没有终端也照跑,不然 CI / cloud-init 里永远进不了向导。
if [ -z "$SETUP_STDIN" ] && [ ${#SETUP_ARGS[@]} -eq 0 ]; then
  echo
  if [ "$SKIP_WHY" = sudo_pty ]; then
    info "安装完成。开服向导这次不自动进 —— sudo 另开了一个 pty(Ubuntu/Debian 的"
    echo "  Defaults use_pty),向导在里面问话会被挂死,所以主动跳过。接着跑:"
    echo
    echo "    sudo nanotun-setup"
    echo
    echo "  下次换成这条就能一次装完,不用再补这一步:"
    echo "    sudo bash -c \"\$(curl -fsSL ${RAW_BASE}/install.sh)\""
  else
    info "安装完成。这次既没有终端可问话、也没给向导参数,开服向导跳过。手动跑:"
    echo "    sudo nanotun-setup"
  fi
    # 这段恰好打在最像 CI 的那一刻(没终端、没参数),所以给的必须是**能直接抄进
    # cloud-init 的那条** —— 而不是眼熟但会骗过退出码的管道形态,也不是漏掉
    # --web-admin、装完把 /setup 敞给全网的那条。
    echo
    echo "  无人值守(CI / cloud-init)可以一条命令做完 —— 先落盘,再带上 --web-admin:"
    echo "    curl -fsSL ${RAW_BASE}/install.sh -o nanotun-install.sh \\"
    echo "      && sudo NANOTUN_WEB_ADMIN_PASSWORD='<密码>' bash nanotun-install.sh \\"
    echo "           --dial-host <域名或IP> --user <用户名> --web-admin <后台用户名> --yes"
    echo
    echo "  别写成 curl … | sudo bash:curl 失败时 bash 拿到空脚本,跑完零行内容以 0 退出,"
    echo "  CI 只认退出码,会把「什么都没下下来」当成装好了。先落盘则由 && 如实挡住。"
    echo "  漏掉 --web-admin 则不会建后台管理员,/setup 一直敞着 —— 谁先打开谁就是管理员。"
  exit 0
fi

echo
info "进入开服向导 ..."
echo
# exec 会拿新进程映像顶掉自己,EXIT trap **不会**执行 —— $TMP 里那个十几 MB 的
# tar 就此长住 /tmp。交棒前自己收干净,并撤掉 trap 免得留个悬空的处理器。
cleanup
trap - EXIT
if [ "$SETUP_STDIN" = /dev/tty ]; then
  exec /usr/local/bin/nanotun-setup ${SETUP_ARGS[@]+"${SETUP_ARGS[@]}"} </dev/tty
else
  exec /usr/local/bin/nanotun-setup ${SETUP_ARGS[@]+"${SETUP_ARGS[@]}"}
fi

} # 防截断的花括号收尾于此,理由见文件开头。这一行之后不要再加任何东西。
