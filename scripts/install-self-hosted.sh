#!/usr/bin/env bash
# nanotun 自托管（PSK 模式）服务器端一键安装脚本
#
# 用法：从 GitHub Releases 下载对应架构的发布包，解压后跑里面的这个脚本：
#
#   tar -xzf nanotun-vX.Y.Z-linux-<arch>.tar.gz
#   cd nanotun-vX.Y.Z-linux-<arch>
#   sudo ./scripts/install-self-hosted.sh
#
# 更省事的是 scripts/install.sh（网络入口：自动挑架构、验校验和、解压、调用本脚本，
# 装完还接着跑开服向导）。本脚本是那条链路里真正动系统的一环，也可以单独跑。
#
# 脚本按**自身位置**推导发布包根目录（scripts/ 的上一级），所以解压到哪都能跑。
# 历史部署（固定 /root/nanotun_deploy）仍可用 NANOTUN_DEPLOY_DIR 显式指定。
#
# 架构：发布包分 linux-amd64 / linux-arm64 两份，下面会核对二进制与本机是否匹配 ——
# 装错架构的表现是 systemd 反复 "Exec format error"，不先拦一道很难一眼看出来。
#
# 语言：默认英文,--lang en|zh 或环境变量 NANOTUN_LANG 切换。一键安装时 install.sh 已经
# 问过一次并经环境变量传进来,本脚本不再问。选定的那一个会落到 /etc/nanotun/lang ——
# 装完之后 nanotun-setup / nanotun-uninstall / nanotun-set-suffix 都是用户单独跑的,
# 那时候没人再传环境变量,读这份才能跟装机时选的语言一致。
#
# $EXTRAS_DIR/nanotun.service 的权威模板是 repo 内 cmd/nanotund/nanotun.service —
# 包含 G_exit_code 的 RestartPreventExitStatus 等关键字段;打部署包时请直接 cp
# 该文件,不要手改 / 漂版本。
#
# 行为（不再装 Go、不在服务器编译）：
#   0. 环境自检：委托给 scripts/preflight.sh（判据的唯一真源，install.sh 也调它）。
#      root、systemd 在跑、/dev/net/tun、iptables/ip6tables、iproute2、openssl、
#      ip_forward 可写。全在动任何文件之前。
#   1. 安装文件到位：
#      /usr/local/bin/{nanotund, nanotun-admin, nanotun-tun-setup.sh, ...}
#      /etc/nanotun/{config.toml, certs/, masquerade/, lang}（证书由 ensure-server-assets.sh 按需自签）
#      /var/lib/nanotun/                        （SQLite home）
#      /etc/systemd/system/{nanotun-tun-setup,nanotun}.service
#      config.toml 已存在则**原样保留**（模板另存 config.toml.dist 供 diff）；模板里的
#      REPLACE_WITH_* 占位与示例 short_ids 由 fill_config_secrets 就地换成本机随机值，
#      否则 [reality].private_key 非法会让 nanotund 起不来（exit 31）。权限 0600。
#      MagicDNS 后缀（客户端解析 *.<后缀> → mesh vIP）默认模板里的 "nanotun"，可用
#      NANOTUN_MAGIC_SUFFIX=<后缀> 在首次装机时定制（只在真写模板时生效；保留既有
#      config.toml 时不动，改现有后缀用 scripts/set-magic-suffix.sh）。
#   2. 开启 IP forwarding（v4 + v6）+ unprivileged ICMP ping（nanotun-web
#      pro-bing 探测 server_dial_host 可达性必备），写 /etc/sysctl.d/99-nanotun.conf
#   3. ufw active 时自动放行 8443/tcp（REALITY）+ 443/udp（hy2）（装了 web 再加 7443/tcp；
#      INPUT 默认 DROP 时必须）。数据面 WS(:8080)默认绑回环、不放行,客户端经 hy2/REALITY 接入。
#   4. K1 旧 DB 自检:若新 DB 空 + 旧 DB(/root/nanotun/data/nanotun.db)有终端用户 →
#      默认拒绝继续(2026-05-21 事故场景);设置 NANOTUN_IMPORT_LEGACY_DB=1 显式导入。
#   5. 跑 nanotun-admin --json --yes init 创建 admin（PSK 自动生成）
#   6. enable + start systemd units（重启系统会自动拉起）
#   7. 状态自检：逐个单元报 enabled/active + 监听端口。一切正常只给这几行结论；
#      任何一项不对才把 systemctl status / ss / journalctl 的原始输出整个倒出来。
#      想在正常情况下也看全套：NANOTUN_VERBOSE=1。
#
# 幂等：重复跑不会破坏数据，**也不会动已生效的 config.toml / 密钥**（重签密钥等于
#       踢掉全部现有客户端）；init 自带「同名管理员只重置 PSK」逻辑；ufw allow /
#       systemctl enable 都是幂等命令；K1 旧 DB 检查在新 DB 已有真实用户
#       (NEW_USERS>0)时永远跳过,不会覆盖二次部署。
#       想用模板推倒重来：NANOTUN_FORCE_CONFIG=1（原配置会备份到 config.toml.bak.*）。

set -euo pipefail

# 装系统文件不看调用者的 umask。关键文件都有显式 -m,但用重定向建出来的那些(sysctl
# 片段、备份、web.env 之类)会原样继承 —— umask 0 下就是 0666。装机这件事常常发生在
# 别人的 wrapper、CI、或者一句随手的 umask 之后,这里归一比逐个补 chmod 可靠。
umask 022

# 发布包根目录 = 本脚本所在 scripts/ 的上一级。写死路径的老行为靠环境变量保留:
# 2026-08 之前这里钉的是 /root/nanotun_deploy,那是维护者自己的 scp 落点,
# 对下载发布包的人没有任何意义 —— 解压到 ~/nanotun 就装不了,而报错只会说「缺文件」。
DEPLOY_DIR="${NANOTUN_DEPLOY_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
EXTRAS_DIR="$DEPLOY_DIR/extras"
SCRIPTS_DIR="$DEPLOY_DIR/scripts"
ETC_DIR=/etc/nanotun
LIB_DIR=/var/lib/nanotun

# ── 语言 ─────────────────────────────────────────────────────────────────────
# 默认英文。优先级:--lang > NANOTUN_LANG > /etc/nanotun/lang(上次装机落下的)> en。
# 只有 install.sh 会交互询问语言;这里不问 —— 一键安装时它已经问过并经环境变量传进来,
# 从解压好的发布包直接跑这个脚本时则读落盘的那份或用默认。
#
# 文案的组织方式:两种语言**并排写在调用处**(tsel / *_t),不抽成 key → 文案的目录。
# 理由见 scripts/install.sh 里同名那节 —— 这些提示几乎每句都在插值,搬进目录得把每处
# 插值改写成 %s 参数,错了还不会有任何东西红;而每句提示上面那段「为什么这么措辞」的
# 注释也会和它解释的文案隔开好几百行。
NT_LANG=en

nt_lang_normalize() {
  case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')" in
    en|en[-_]*|english)      printf 'en' ;;
    zh|zh[-_]*|chinese|cn)   printf 'zh' ;;
    *)                       printf '' ;;
  esac
}

_nt_l=""
for _nt_a in "$@"; do
  case "$_nt_a" in
    --lang=*) _nt_l="$(nt_lang_normalize "${_nt_a#--lang=}")" ;;
    --lang)   _nt_l=__next__ ;;
    *)        [ "$_nt_l" = __next__ ] && _nt_l="$(nt_lang_normalize "$_nt_a")" ;;
  esac
done
[ "$_nt_l" = __next__ ] && _nt_l=""
if [ -n "$_nt_l" ]; then
  NT_LANG="$_nt_l"
elif [ -n "$(nt_lang_normalize "${NANOTUN_LANG:-}")" ]; then
  NT_LANG="$(nt_lang_normalize "$NANOTUN_LANG")"
elif [ -r /etc/nanotun/lang ] && \
     [ -n "$(nt_lang_normalize "$(head -1 /etc/nanotun/lang 2>/dev/null)")" ]; then
  NT_LANG="$(nt_lang_normalize "$(head -1 /etc/nanotun/lang 2>/dev/null)")"
fi
unset _nt_l _nt_a

# 往下传。nanotun-admin 本来就认这个变量(它的默认也是英文),所以整条链只有一处决定语言。
# 原来这里是 `${NANOTUN_LANG:-zh}` —— 那时本脚本只有中文,把 admin 按回中文是为了别让
# 英文夹在中文里。现在脚本自己双语了,反过来:语言由上面解析出的那一个说了算。
#
# 对本脚本的解析没有影响:init 走 --json(键名与语言无关),count_real_users 读的
# user list 表格两种语言下逐字一致 —— K1 守卫靠 $3=="no" 数人,已实测两边相同。
export NANOTUN_LANG="$NT_LANG"

# tsel <英文> <中文> —— 按当前语言选一份。
tsel() { if [ "$NT_LANG" = zh ]; then printf '%s' "$2"; else printf '%s' "$1"; fi; }

step() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[1;32m✓\033[0m %s\n' "$*"; }
warn() { printf '    \033[1;33m!\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mFATAL: %s\033[0m\n' "$*" >&2; exit 1; }

# 双语版本:英文在前、中文在后,与 tsel 同序。并排放着的理由见上面「语言」那节。
step_t() { step "$(tsel "$1" "$2")"; }
ok_t()   { ok   "$(tsel "$1" "$2")"; }
warn_t() { warn "$(tsel "$1" "$2")"; }
die_t()  { die  "$(tsel "$1" "$2")"; }

# 除了 --lang / --help,本脚本不接受任何参数,而在此之前它是**默默**不接受的:多传什么都
# 照装不误,装完退 0。
#
# 踩点很集中。README 的无人值守示例是给 install.sh 的:
#   sudo bash nanotun-install.sh --dial-host vpn.example.com --user alice --yes
# 而离线安装那段(下 tar 自己装)给的是 `sudo ./scripts/install-self-hosted.sh`。
# 两段隔了几十行,把上面那串参数接到下面这条命令上是很自然的动作 —— 结果是安装成功、
# 退出码 0、屏幕全绿,而 --dial-host 一个字都没生效,客户端仍然连不上。人会去查网络、
# 查防火墙、查证书,因为「装成功了」这件事看起来毫无疑问。
#
# 本仓库自己也踩了:scripts/testlab/lab.sh 的 --local 路径把用户参数原样传给了这个脚本。
#
# 转交给向导是行不通的:本脚本压根不跑向导(它只把 setup.sh 装成命令),转交就得把
# 「装完自动接向导」这层职责也搬进来,而那正是 install.sh 存在的理由。所以只做一件事:
# 拒绝,并把该去哪儿说清楚。
#
# --lang 是例外,而且必须真的进这套解析:一键安装会把它原样传下来,少了这一条,
# `install.sh --lang zh` 就会被自己的下游顶回去(exit 2),而那句报错长得像「用户参数写错了」。
# 语言在文件上方已经扫过一遍(必须早于任何一句提示),这里只负责把它从 argv 里吃掉、顺带校验值。

# nt_lang_bad <收到的值> —— 语言写错就当场退,别默默回落到英文:那样 `--lang fr` 看着像生效了。
# 退 2 而不是 die 的 1:与下面那条「本脚本不接受参数」同口径,都是参数错误。
nt_lang_bad() {
  printf '\033[1;31mFATAL: %s\033[0m\n' "$(tsel \
    "install-self-hosted.sh: --lang takes en or zh (got '$1')" \
    "install-self-hosted.sh: --lang 只认 en 或 zh(收到 '$1')")" >&2
  exit 2
}

NT_ARGV=()
_nt_want=0
for _nt_a in "$@"; do
  if [ "$_nt_want" = 1 ]; then
    _nt_want=0
    [ -n "$(nt_lang_normalize "$_nt_a")" ] || nt_lang_bad "$_nt_a"
    continue
  fi
  case "$_nt_a" in
    --lang)   _nt_want=1 ;;
    --lang=*) [ -n "$(nt_lang_normalize "${_nt_a#--lang=}")" ] || nt_lang_bad "${_nt_a#--lang=}" ;;
    *)        NT_ARGV+=("$_nt_a") ;;
  esac
done
# `--lang` 是最后一个词、后面什么都没跟。这一条不能静静地当成「没给语言」:少打的那个 zh
# 会让机器按英文装完,而敲的人以为自己选了中文,直到装完满屏英文才发现。
[ "$_nt_want" = 0 ] || nt_lang_bad ""
unset _nt_a _nt_want
set -- ${NT_ARGV[@]+"${NT_ARGV[@]}"}
unset NT_ARGV

if [ "$#" -gt 0 ]; then
  case "${1:-}" in
    -h|--help)
      if [ "$NT_LANG" = zh ]; then
      cat <<'USAGE'
用法: sudo ./scripts/install-self-hosted.sh [--lang en|zh]      (不接受开服向导的参数)

把发布包装成一台在跑的服务:二进制、systemd 单元、IP 转发、REALITY/hy2 密钥与自签证书、
防火墙放行、第一个 VPN 管理员。**装完还不等于客户端能连** —— 拨号地址、Web 后台管理员、
第一个用户和二维码在开服向导里,装完跑:

    sudo nanotun-setup

联网一键安装(下载 + 安装 + 向导一条龙)用 install.sh,它认得向导的参数并自动转交:
    sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/nanotun/server/main/scripts/install.sh)"

选项:
  --lang en|zh   界面语言,默认英文。不给时按 NANOTUN_LANG,再不给就读上次装机落在
                 /etc/nanotun/lang 的那份。选定的那一个会写回这个文件,之后单独跑的
                 nanotun-setup / nanotun-uninstall / nanotun-set-suffix 默认沿用
  -h, --help     显示本帮助

可用的环境变量见本文件头部注释(NANOTUN_MAGIC_SUFFIX / NANOTUN_FORCE_CONFIG 等)。
USAGE
      else
      cat <<'USAGE'
Usage: sudo ./scripts/install-self-hosted.sh [--lang en|zh]   (takes no wizard arguments)

Turns the release tarball into a running service: binaries, systemd units, IP
forwarding, REALITY/hy2 keys and self-signed certificates, firewall openings, the
first VPN administrator. **Installed is not yet reachable** — the dial host, the
web administrator, the first user and its QR codes belong to the setup wizard.
When this finishes, run:

    sudo nanotun-setup

For the one-command install over the network (download + install + wizard) use
install.sh; it knows the wizard's arguments and passes them on:
    sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/nanotun/server/main/scripts/install.sh)"

Options:
  --lang en|zh   interface language (default: en). Without it NANOTUN_LANG
                 decides, and failing that the value the last install left in
                 /etc/nanotun/lang. Whichever is chosen is written back to that
                 file, so nanotun-setup / nanotun-uninstall / nanotun-set-suffix
                 keep to it when run on their own later
  -h, --help     show this help

The environment variables this script honours are documented in the comment at
the top of the file (NANOTUN_MAGIC_SUFFIX / NANOTUN_FORCE_CONFIG and so on).
USAGE
      fi
      exit 0 ;;
    *)
      if [ "$NT_LANG" = zh ]; then
        printf '\033[1;31mFATAL: 本脚本不接受参数,收到:%s\033[0m\n' "$*" >&2
        printf '\n' >&2
        printf '  --dial-host / --user / --web-admin / --yes 这些是**开服向导**的参数。\n' >&2
        printf '  本脚本只负责把系统装起来,装完之后跑:\n' >&2
        printf '\n' >&2
        printf '      sudo nanotun-setup %s\n' "$*" >&2
        printf '\n' >&2
        printf '  想一条命令做到底(下载 + 安装 + 向导),用 install.sh —— 它认得这些参数并转交:\n' >&2
        printf '      curl -fsSL https://raw.githubusercontent.com/nanotun/server/main/scripts/install.sh -o nanotun-install.sh \\\n' >&2
        printf '        && sudo bash nanotun-install.sh %s\n' "$*" >&2
        printf '\n' >&2
        printf '  完整用法:%s --help\n' "$0" >&2
      else
        printf '\033[1;31mFATAL: this script takes no arguments; got: %s\033[0m\n' "$*" >&2
        printf '\n' >&2
        printf '  --dial-host / --user / --web-admin / --yes belong to the **setup wizard**.\n' >&2
        printf '  This script only gets the system installed. When it is done, run:\n' >&2
        printf '\n' >&2
        printf '      sudo nanotun-setup %s\n' "$*" >&2
        printf '\n' >&2
        printf '  To do it all in one command (download + install + wizard), use install.sh —\n' >&2
        printf '  it knows these arguments and passes them on:\n' >&2
        printf '      curl -fsSL https://raw.githubusercontent.com/nanotun/server/main/scripts/install.sh -o nanotun-install.sh \\\n' >&2
        printf '        && sudo bash nanotun-install.sh %s\n' "$*" >&2
        printf '\n' >&2
        printf '  Full usage: %s --help\n' "$0" >&2
      fi
      exit 2 ;;
  esac
fi

# systemctl restart 返回 0 只代表「systemd 接受了这次启动」,不代表服务真的活着。
#
# nanotun-web.service 是 Type=simple:进程 exec 出来那一刻就算启动成功。它下一秒
# 因为 7443 被占而退出,restart 照样返回 0 —— 于是屏幕上写着「✓ nanotun-web 已启动」,
# 而它正以 RestartSec=5s 的节奏反复重启。这种「绿着的谎」比直接报错难查得多:
# 用户会拿着一句「已启动」去浏览器上撞 404,而不会想到去看 journalctl。
#
# (nanotun.service 是 Type=notify,restart 本身就能判失败。这里对两者用同一把尺子。)
#
# 判据是「过几秒之后还 active」。崩溃重启的单元在 RestartSec 等待期里是
# activating (auto-restart),3 秒足以把它跟真正起来的区分开。
settled_active() {
  sleep 3
  [ "$(systemctl is-active "$1" 2>/dev/null)" = active ]
}

# 32 字节 X25519 私钥,编成 RawURL Base64(无 padding)—— [reality].private_key 要的格式。
# PKCS8 DER 恒为 48 字节,尾部 32 字节即裸私钥。刻意不用 basenc(coreutils ≥8.31 才有),
# 走 openssl + tr 让老发行版也能跑。
gen_x25519_priv() {
  openssl genpkey -algorithm X25519 -outform DER \
    | tail -c 32 | openssl base64 -A | tr '+/' '-_' | tr -d '='
}

# 把 config.toml 里仍为占位 / 文档示例的密钥换成本机随机值。
#
# 2026-07-25 部署实测:发布包模板带 REPLACE_WITH_* 占位,而 [reality].private_key
# 非法会让 nanotund 直接 ExitListenOther(31) —— 本脚本跑完(含 systemctl start)留下的
# 是一个 crash-loop 的服务,「一键安装」实际装不出可用服务器。这里在启动前补齐。
#
# 只替换**仍是占位**的项,故幂等:重复跑不会重签已生效的密钥(那会踢掉所有现有客户端),
# 也能把历史上装完即 crash-loop 的机器一次性救活。
# 生成值都是 hex / base64url([A-Za-z0-9_-]),不含 sed 元字符,可直接内插。
fill_config_secrets() {
  local cfg="$ETC_DIR/config.toml" filled=0
  command -v openssl >/dev/null 2>&1 || die_t "openssl is missing, so the REALITY / hy2 keys cannot be generated" \
                                              "缺 openssl,无法生成 REALITY / hy2 密钥"

  if grep -q 'REPLACE_WITH_YOUR_RANDOM_TOKEN' "$cfg"; then
    sed -i "s|REPLACE_WITH_YOUR_RANDOM_TOKEN|$(openssl rand -hex 16)|g" "$cfg"; filled=1
  fi
  if grep -q 'REPLACE_WITH_A_LONG_RANDOM_PASSWORD' "$cfg"; then
    sed -i "s|REPLACE_WITH_A_LONG_RANDOM_PASSWORD|$(openssl rand -hex 24)|g" "$cfg"; filled=1
  fi
  if grep -q 'REPLACE_WITH_ANOTHER_RANDOM_OBFS_PASSWORD' "$cfg"; then
    sed -i "s|REPLACE_WITH_ANOTHER_RANDOM_OBFS_PASSWORD|$(openssl rand -hex 16)|g" "$cfg"; filled=1
  fi
  if grep -q 'REPLACE_WITH_YOUR_X25519_PRIVATE_KEY' "$cfg"; then
    sed -i "s|REPLACE_WITH_YOUR_X25519_PRIVATE_KEY|$(gen_x25519_priv)|g" "$cfg"; filled=1
  fi
  # short_ids 的两条文档示例值:config.toml 自己就写着「替换示例值再上线」。
  if grep -q '"0123456789abcdef"' "$cfg"; then
    sed -i "s|\"0123456789abcdef\"|\"$(openssl rand -hex 8)\"|" "$cfg"; filled=1
  fi
  if grep -q '"fedcba9876543210"' "$cfg"; then
    sed -i "s|\"fedcba9876543210\"|\"$(openssl rand -hex 8)\"|" "$cfg"; filled=1
  fi

  # 兜底自检:模板将来新增占位而本函数没跟上时,**装不上**比「装完 crash-loop」好得多。
  if grep -n 'REPLACE_WITH' "$cfg" >&2; then
    die_t "config.toml still has unfilled placeholders (listed above); nanotund will fail to start. Fill them in and rerun this script" \
          "config.toml 仍有未填占位(见上),nanotund 会启动失败;补齐后重跑本脚本"
  fi

  if [ "$filled" = 1 ]; then
    ok_t "Generated this machine's REALITY private key / hy2 password / obfs password / WS path token / short_ids" \
         "已为本机生成 REALITY 私钥 / hy2 密码 / obfs 密码 / WS path token / short_ids"
  else
    ok_t "config.toml has no placeholders left to fill; the keys were left as they are" \
         "config.toml 无待填占位,密钥原样保留"
  fi
}

# 按 NANOTUN_MAGIC_SUFFIX 定制 MagicDNS 的 domain_suffix(客户端解析 *.<后缀> → mesh vIP)。
#
# 为什么在装机脚本里做:运行期后缀**只**取 config.toml 的 [server.magic_dns].domain_suffix
# (magicDNSSuffixForClient / resolveMagicDNSConfig 都读它),且它不在 SIGHUP 热更新白名单里
# (见 set-magic-suffix.sh 抬头),须在服务启动前定好 —— 而这里正是唯一会写 config.toml 的地方。
# 模板默认写死 "nanotun";不给 NANOTUN_MAGIC_SUFFIX 就沿用模板,行为不变。
#
# 只在**这次真写了模板 config.toml**(CONFIG_FRESH=1:全新装 / NANOTUN_FORCE_CONFIG=1)时改。
# 保留既有配置时绝不擅自改它(与「绝不覆盖已有配置」同一口径),只告警并指路 set-magic-suffix.sh。
# 校验与段感知改写与 set-magic-suffix.sh 同一套(规则单一来源:那边改这边也要跟)。
apply_magic_suffix() {
  local suf="${NANOTUN_MAGIC_SUFFIX:-}"
  [ -n "$suf" ] || return 0   # 没给:用模板默认后缀,不动 config.toml

  # 合法性:小写 DNS 标签(字母数字 + 连字符,可点分多级)。既防命令注入,也防写坏 TOML。
  if ! printf '%s' "$suf" | grep -Eq '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$'; then
    die_t "NANOTUN_MAGIC_SUFFIX is not valid (lowercase letters/digits/hyphens only, dot-separated labels allowed): '$suf'" \
          "NANOTUN_MAGIC_SUFFIX 不合法(只允许小写字母/数字/连字符,可点分多级):'$suf'"
  fi
  case "$suf" in
    local) die_t "NANOTUN_MAGIC_SUFFIX cannot be 'local' — it collides badly with mDNS/Bonjour (mac/iOS)." \
                 "NANOTUN_MAGIC_SUFFIX 不能用 'local' —— 与 mDNS/Bonjour(mac/iOS)严重冲突。" ;;
    lan|home|home.arpa|internal|corp)
      warn_t "The MagicDNS suffix '$suf' may collide with home routers / reserved domains (avoiding exactly that is the reason to change it)." \
             "MagicDNS 后缀 '$suf' 可能与家用路由器 / 保留域冲突(想避开这类冲突正是换后缀的理由)。" ;;
  esac

  # 保留了既有 config.toml 就不改它 —— 那是升级路径,擅自改后缀会踢乱已在用的 mesh 名字。
  if [ "${CONFIG_FRESH:-0}" != 1 ]; then
    warn_t "The existing config.toml was kept, so NANOTUN_MAGIC_SUFFIX='$suf' was not applied. To change the current suffix:" \
           "已保留既有 config.toml,未套用 NANOTUN_MAGIC_SUFFIX='$suf'。要改现有后缀:"
    warn_t "  scripts/set-magic-suffix.sh $suf   (back up → section-aware rewrite → restart → rolled back automatically on failure)" \
           "  scripts/set-magic-suffix.sh $suf   （备份→段感知改写→重启→失败自动回滚）"
    return 0
  fi

  local cfg="$ETC_DIR/config.toml" cur
  # 空白写 [ \t] 不用 [[:space:]]:mawk 1.3.3(老 Ubuntu/Debian 默认 awk)不认 POSIX 字符类。
  cur="$(awk -F'"' '/^[ \t]*domain_suffix[ \t]*=/{print $2; exit}' "$cfg" || true)"
  if [ "$cur" = "$suf" ]; then
    ok_t "The MagicDNS suffix is already '$suf'" "MagicDNS 后缀已是 '$suf'"
    return 0
  fi

  # 段感知改写:仅动 [server.magic_dns] 段内的 domain_suffix(段内已有则原地替换,含被注释)。
  awk -v suf="$suf" '
    /^[ \t]*\[/ {
      if (insec && !done) { print "domain_suffix = \"" suf "\""; done=1 }
      insec = ($0 ~ /^[ \t]*\[server\.magic_dns\][ \t]*$/)
      if (insec) seen=1
      print; next
    }
    {
      if (insec && !done && $0 ~ /^[ \t]*#?[ \t]*domain_suffix[ \t]*=/) {
        print "domain_suffix = \"" suf "\""; done=1; next
      }
      print
    }
    END {
      if (insec && !done) print "domain_suffix = \"" suf "\""
      if (!seen) { print ""; print "[server.magic_dns]"; print "domain_suffix = \"" suf "\"" }
    }
  ' "$cfg" > "$cfg.new" && mv "$cfg.new" "$cfg" \
    || { rm -f "$cfg.new"; die_t "Could not write the MagicDNS suffix (config.toml was left untouched)" \
                                 "写 MagicDNS 后缀失败(config.toml 未改动)"; }
  chmod 0600 "$cfg"
  ok_t "MagicDNS suffix set to '$suf' (clients resolve *.$suf → mesh virtual IP; the template default is 'nanotun')" \
       "MagicDNS 后缀设为 '$suf'(客户端解析 *.$suf → mesh 虚拟 IP;模板默认为 'nanotun')"
}

# 环境自检:先验这台机器能不能跑,再验发布包对不对。
#
# 每一条都对应一种真实的坏结局,而它们的共同点是**报错的地方离原因很远**:
#   - 没 systemd:脚本会先把二进制、config、证书全写完,走到 systemctl daemon-reload
#     才炸,留下一个装了一半的系统和一句 "command not found";
#   - 没 /dev/net/tun:安装全程「成功」,然后 nanotund 起来就 exit 60 反复重启。
#     便宜的 OpenVZ / 部分 LXC VPS 就是这样,而这类机器恰恰是自托管用户最常买的;
#   - 没 iptables:同上,装完才死,得翻 journalctl 才知道缺的是个命令。
#
# docker/entrypoint.sh 里一直有一份同职责的 preflight(TUN / CAP_NET_ADMIN /
# ip_forward),裸机这条路反而只验了架构。2026-08-03 补齐,判据尽量与那份对齐。
#
# 时机是关键:必须在 step 1 动 /usr/local/bin 和 /etc/nanotun 之前跑完。
# 判据不写在这里,一律走 scripts/preflight.sh —— 它同时被 install.sh 和本脚本
# 调用。同一套「这台机器行不行」的规则要是各写一份,迟早对不上,而对不上的那天
# 表现是「引导脚本说能装,安装脚本说不能」。
#
# --offline:发布包已经在本地了,不需要 curl / tar。
# NANOTUN_PREFLIGHT_DONE=1:install.sh 在下载之前已经验过一遍,不必重复。
if [ "${NANOTUN_PREFLIGHT_DONE:-0}" = "1" ]; then
  ok_t "The bootstrap script already ran the environment check, skipping" \
       "环境自检已由引导脚本完成,跳过"
elif [ -f "$SCRIPTS_DIR/preflight.sh" ]; then
  # --for-install:本脚本下一步就动 /usr/local/bin,非 root 必须当场拦下。
  # (不传的话 preflight 只会把非 root 记成一条提醒 —— 那是给「单独跑来问问
  # 机器行不行」准备的口径,不适用于这里。)
  bash "$SCRIPTS_DIR/preflight.sh" --offline --for-install \
    || die_t "The environment check did not pass (see the fix list above); the install was aborted." \
             "环境检查没过(见上面的修复清单),已中止安装。"
else
  # 老发布包里没有 preflight.sh。不能因此放行 —— 缺 systemd / TUN 装下去必炸,
  # 所以退回到最小一组硬检查,报错简短但至少能拦住。
  warn_t "This release tarball has no preflight.sh; falling back to the minimal checks" \
         "发布包里没有 preflight.sh,退回最小检查"
  [ "$(id -u)" = 0 ]        || die_t "This needs root; run it with sudo" \
                                     "需要 root,请用 sudo 跑"
  [ -d /run/systemd/system ] || die_t "There is no systemd running, so a bare-metal install is not possible; use Docker instead" \
                                      "没有正在运行的 systemd,裸机安装用不了,请改走 Docker"
  [ -c /dev/net/tun ]        || die_t "/dev/net/tun does not exist; modprobe tun first" \
                                      "/dev/net/tun 不存在,先 modprobe tun"
  for c in iptables ip6tables ip openssl sysctl; do
    command -v "$c" >/dev/null 2>&1 || die_t "The command $c is missing" "缺少命令 $c"
  done
fi

# 必要文件存在性自检。nanotun-web 是 M2 引入的 Web 后台:可选,缺了不会 fatal,
# 但会跳过其安装步骤并 warn。这样老 deploy 包不会因为多一个二进制就失败。
#
# 证书不随包分发:发布包里没有任何 dev-*.pem。TLS / mTLS CA / masquerade 页由
# ensure-server-assets.sh 在 config.toml 落位后按需自签(见 step 1 末尾)。
for f in "$DEPLOY_DIR/nanotund" "$DEPLOY_DIR/nanotun-admin" \
         "$EXTRAS_DIR/config.toml" "$EXTRAS_DIR/nanotun.service" \
         "$SCRIPTS_DIR/tun-setup.sh" \
         "$SCRIPTS_DIR/tun-teardown.sh" "$SCRIPTS_DIR/tun-setup.service" \
         "$SCRIPTS_DIR/ensure-server-assets.sh" \
         "$SCRIPTS_DIR/nanotun-ports.sh"; do
  [ -e "$f" ] || die_t "Missing file: $f" "缺文件: $f"
done

WEB_AVAILABLE=0
if [ -f "$DEPLOY_DIR/nanotun-web" ] && [ -f "$EXTRAS_DIR/nanotun-web.service" ]; then
  WEB_AVAILABLE=1
fi

# 架构自检:发布包分 amd64 / arm64 两份,下错了要在装之前说清楚。
#
# 不装完再靠 systemd 报错 —— 那时看到的是 "Exec format error" 加一个 crash-loop 的
# 单元,而这行日志跟「你下载的包架构不对」之间的距离,足够让人查半小时。
# arm64 机器尤其容易踩:Oracle / AWS 免费层默认给的就是 aarch64,而下载页面上
# amd64 那个链接在最前面。
#
# 读 ELF header 的 e_machine(偏移 18,小端 2 字节)而不是执行一下试试:
# 装了 qemu-user-static / binfmt 的机器上,错架构的二进制照样能跑起来,
# 执行法验不出东西。与 Dockerfile 里 archcheck 同一套判据。
check_arch() {
  local host_machine want got bin desc
  case "$(uname -m)" in
    x86_64|amd64)  host_machine="3e00"; desc="amd64" ;;
    aarch64|arm64) host_machine="b700"; desc="arm64" ;;
    *)
      warn_t "This machine's architecture $(uname -m) is not in the table, skipping the architecture check" \
             "本机架构 $(uname -m) 不在检查表内,跳过架构自检"
      return 0 ;;
  esac

  command -v od >/dev/null 2>&1 || { warn_t "od is missing, skipping the architecture check" \
                                            "缺 od,跳过架构自检"; return 0; }

  for bin in nanotund nanotun-admin nanotun-web; do
    [ -f "$DEPLOY_DIR/$bin" ] || continue
    got="$(od -An -tx1 -j18 -N2 "$DEPLOY_DIR/$bin" | tr -d ' \n')"
    if [ "$got" != "$host_machine" ]; then
      case "$got" in
        3e00) want="amd64" ;;
        b700) want="arm64" ;;
        *)    want="$(tsel "unknown (e_machine=$got)" "未知(e_machine=$got)")" ;;
      esac
      if [ "$NT_LANG" = zh ]; then
        printf '\033[1;31mFATAL: 发布包架构不匹配\033[0m\n' >&2
        printf '  本机: %s (%s)\n' "$(uname -m)" "$desc" >&2
        printf '  包里的 %s: %s\n' "$bin" "$want" >&2
        printf '\n请下载 linux-%s 那一份:\n' "$desc" >&2
      else
        printf '\033[1;31mFATAL: the release tarball is for another architecture\033[0m\n' >&2
        printf '  This machine: %s (%s)\n' "$(uname -m)" "$desc" >&2
        printf '  %s in the tarball: %s\n' "$bin" "$want" >&2
        printf '\nDownload the linux-%s one instead:\n' "$desc" >&2
      fi
      printf '  https://github.com/nanotun/server/releases/latest\n' >&2
      printf '  nanotun-vX.Y.Z-linux-%s.tar.gz\n' "$desc" >&2
      exit 1
    fi
  done
  ok_t "Architecture check passed: the tarball and this machine are both $desc" \
       "架构自检通过:发布包与本机同为 $desc"
}
check_arch

# 从这里往下开始改这台机器,先占住单实例锁。
#
# 两个安装同时跑会撞在 install 上:coreutils 的 install 是先 unlink 再以 O_EXCL 建,
# 两边都 unlink 成功、只有一边能建出来,输的那个拿到
# "install: cannot create regular file '/usr/local/bin/nanotun-admin': File exists"
# —— 一句完全看不出「另一个安装正在跑」的话,而它是在第 1 步中途退的,二进制只换了
# 一半。实测两个并发安装必现,退出码 1。
#
# 自动化里这不是奇景:Ansible 超时重试、cloud-init 与人工同时动手、CI 里两个 job 撞车,
# 都会到这一步。
#
# 用 -n 立刻拒绝而不是排队等:后来者等半天再把同样的活重做一遍没有意义,而「有人正在
# 装」这件事本身就是要告诉人的。锁在 fd 上,进程一退就释放,不留死锁。
#
# 开锁那句要写成 `{ exec 9>…; } 2>/dev/null`,花括号不能省。
# 写成 `exec 9>"$LOCK_FILE" 2>/dev/null` 的话,这是一条没有命令的 exec —— 两个重定向
# **都**会永久落到当前 shell 上,于是整个脚本剩下的 stderr 全进了 /dev/null:下面每一句
# die 都还照常退出,但一个字都不会显示。实测就是这样:并发那次被拒的进程静静地退了 1,
# 屏幕上最后一行是「架构自检通过」。花括号把 stderr 的重定向限定在这个语句组里。
LOCK_FILE=/run/nanotun-install.lock
if command -v flock >/dev/null 2>&1 && { exec 9>"$LOCK_FILE"; } 2>/dev/null; then
  if ! flock -n 9; then
    die_t "Another nanotun install / upgrade is in progress (lock: $LOCK_FILE).
   Wait for it to finish and try again. If you are sure no other install is
   running and this still says so, the lock is left over from one that was killed:
     fuser -k $LOCK_FILE   # or just reboot this machine" \
          "另一个 nanotun 安装 / 升级正在进行(锁:$LOCK_FILE)。
   等它跑完再重试。确认没有别的安装在跑却仍报这句的话,是上次被强杀留下的:
     fuser -k $LOCK_FILE   # 或直接重启这台机器"
  fi
fi

step_t "1. Install binaries / scripts / certificates / config / systemd units" \
       "1. 安装二进制 / 脚本 / 证书 / 配置 / systemd 单元"

# 动手之前先确认几个落点是真的写得进去、也放得下。
#
# 原来这里是一串裸的 install:任何一次写失败都被 set -e 直接带走,屏幕上最后一行是
# coreutils 自己的英文 —— 换成 uutils 版(有些发行版已经默认它)更糟,吐的是一段 Rust
# 调试结构:`Os { code: 30, kind: ReadOnlyFilesystem, .. }`。没有 FATAL、没有原因、
# 没有下一步,而这是第 1 步:失败时 /usr/local/bin 里已经装进去一半,人却看不出
# 机器现在是什么状态、自己的服务还在不在。实测把 /usr/local/bin 挂成只读就是这个下场。
#
# 放在写第一个文件之前,是因为「拦住」比「事后说清楚」值钱:检查不过就一个文件都没动,
# 机器还是原样,修完重跑即可。只读挂载(加固过的系统会把 /usr 挂 ro)、权限、
# 空间不足、目录被设了 immutable —— 都在这一关拦下。
NEED_MB=60   # 二进制 + 脚本实测约 41MB,留出余量
for d in /usr/local/bin /etc/systemd/system "$ETC_DIR"; do
  if [ ! -d "$d" ] && ! mkdir -p "$d" 2>/dev/null; then
    die_t "Could not create the directory $d — the level above may be a read-only mount, or permissions are missing.
   Fix that and rerun this script (it is idempotent; rerunning does not destroy existing config or keys)." \
          "建不出目录 $d —— 上层可能是只读挂载,或没有权限。
   修好之后重跑本脚本(它是幂等的,重跑不会破坏已有配置和密钥)。"
  fi
  # 用真写一个文件来判,而不是 [ -w ]:后者对只读挂载是判不出来的 —— root 对目录的
  # 权限位永远是够的,拦住写入的是挂载选项,而那要等到真正 write 的时候才报出来。
  if ! touch "$d/.nanotun-write-test" 2>/dev/null; then
    die_t "$d is not writable.
   Common causes: this partition is a read-only mount (hardened systems often
   mount /usr ro), a quota is blocking it, or the directory is immutable
   (lsattr $d to look, chattr -i to undo).
   If it is read-only: mount -o remount,rw $(df -P "$d" 2>/dev/null | awk 'NR==2{print $6}').
   Not one file has been touched, this machine is still as it was; fix that and rerun this script." \
          "$d 写不进去。
   常见原因:这个分区是只读挂载(加固过的系统常把 /usr 挂 ro)、被 quota 卡住,
   或者目录设了 immutable(lsattr $d 看一眼,chattr -i 解开)。
   只读的话先 mount -o remount,rw $(df -P "$d" 2>/dev/null | awk 'NR==2{print $6}')。
   一个文件都还没动,机器仍是原样;修好之后重跑本脚本即可。"
  fi
  rm -f "$d/.nanotun-write-test"
done
AVAIL_MB="$(df -Pm /usr/local/bin 2>/dev/null | awk 'NR==2{print $4}')"
if [ -n "$AVAIL_MB" ] && [ "$AVAIL_MB" -lt "$NEED_MB" ]; then
  die_t "Not enough space on the filesystem holding /usr/local/bin: about ${NEED_MB}MB is needed, ${AVAIL_MB}MB is available.
   Free some space and rerun. Do not let it install halfway — a truncated nanotund
   on disk keeps working off the already-open old file until the next reboot, and
   only then fails to start, which may be a long time from now.
   Not one file has been touched, this machine is still as it was." \
        "/usr/local/bin 所在分区空间不够:要装的约 ${NEED_MB}MB,当前可用 ${AVAIL_MB}MB。
   腾出空间后重跑。别让它装到一半 —— 半截的 nanotund 落在盘上,正在跑的服务
   靠着已打开的旧文件还能撑到下次重启,重启就起不来了,而那时离现在可能隔了很久。
   一个文件都还没动,机器仍是原样。"
fi

install -m 0755 "$DEPLOY_DIR/nanotund"  /usr/local/bin/nanotund
install -m 0755 "$DEPLOY_DIR/nanotun-admin"    /usr/local/bin/nanotun-admin
install -m 0755 "$SCRIPTS_DIR/tun-setup.sh"     /usr/local/bin/nanotun-tun-setup.sh
install -m 0755 "$SCRIPTS_DIR/tun-teardown.sh"  /usr/local/bin/nanotun-tun-teardown.sh
# 老版本装过的 tun-isolate 那套(脚本 + 单元)在这里主动铲掉:它不起作用还会断服
# (原因写在 tun-setup.sh 里),留在盘上只会被人当成还能用的功能。规则残留由
# tun-setup.sh 每次开机顺手清。要客户端隔离用 config.toml 的 exit_mode = "isolate"。
systemctl disable --quiet --now nanotun-tun-isolate.service 2>/dev/null || true
rm -f /etc/systemd/system/nanotun-tun-isolate.service \
      /usr/local/bin/nanotun-tun-isolate.sh \
      /usr/local/bin/nanotun-tun-isolate-teardown.sh
# 下面这几个都装成 /usr/local/bin 里的命令,而不是只留在发布包里。
#
# 共同的理由:解压出来的那个目录用完多半就删了(或者用户压根不知道它在
# /opt/nanotun/<版本>-<架构>/),而这几件事都是**装完之后**才需要、且要反复用的。
# 留在包里等于用一次就丢。
#
# 上面的必需文件自检已经保证它们都在,所以这里不再 `[ -f ] &&` —— 那个守卫的历史见那段注释。
SETUP_AVAILABLE=1
# 开服向导:加用户、重出二维码、改拨号地址都靠它。
install -m 0755 "$SCRIPTS_DIR/setup.sh" /usr/local/bin/nanotun-setup
# 环境检查:排查「服务起不来」时第一件该做的事就是重跑它。
install -m 0755 "$SCRIPTS_DIR/preflight.sh" /usr/local/bin/nanotun-preflight
# 改 MagicDNS 局域网后缀:装机时用 NANOTUN_MAGIC_SUFFIX 定一次,之后想换就
# `sudo nanotun-set-suffix <后缀>`(备份→段感知改写→重启→失败自动回滚)。开服向导
# nanotun-setup 的「MagicDNS 后缀」步也优先调它(同一份逻辑,单一真源)。
install -m 0755 "$SCRIPTS_DIR/set-magic-suffix.sh" /usr/local/bin/nanotun-set-suffix
# 卸载:原来只躺在发布包里,README 教的是 `sudo ./scripts/uninstall.sh` —— 那条命令对
# 一键安装的人根本不成立,他们的当前目录没有 scripts/,而真实路径
# /opt/nanotun/<版本>-<架构>/scripts/uninstall.sh 文档里也没写。于是「怎么卸载」这个
# 问题的答案藏在一个要先知道版本号和架构才拼得出来的路径里。
#
# 装成命令还有一层:卸载脚本删的是一份写死的文件清单,必须和装它的这一版对得上
# (共用目录里还有客户端的 device_id,不能按目录删)。装进 PATH 的这份天然同版本。
install -m 0755 "$SCRIPTS_DIR/uninstall.sh" /usr/local/bin/nanotun-uninstall

# 目录权限写死,不跟调用者的 umask 走。
#
# 实测 umask 000 装出来:/etc/nanotun 是 0777。里面的密钥文件仍然是 0600(上面全是
# install -m),看着像没事 —— 但目录可写就已经够了:本机任何用户可以把 config.toml
# 整个 mv 走、换上自己的一份,而 nanotund 以 root 读它,证书路径、监听地址、出口策略
# 都在里面。等于把本机提权和全体客户端的 MITM 一起送出去。
#
# umask 是调用者说了算的东西(CI、别人的 wrapper、手滑的一句 umask 0),不该由它决定
# /etc 下的目录权限。install -d -m 对已存在的目录同样会纠正模式,所以老机器重跑一次
# 安装就能修回来。
install -d -m 0755 "$ETC_DIR" "$ETC_DIR/masquerade"
install -d -m 0700 "$ETC_DIR/certs"
install -d -m 0750 "$LIB_DIR"

# 语言落盘。本脚本是创建 $ETC_DIR 的那个,也是这条链上唯一以 root 跑、拥有那个目录的
# 一环,所以这份由它写。
#
# 为什么要落:装完之后 nanotun-setup / nanotun-uninstall / nanotun-set-suffix 都是用户
# 单独敲的,那时候没有 install.sh 把 NANOTUN_LANG 传进来了 —— 读这份才能跟装机时选的
# 语言一致。不落的话,一台按中文装好的机器上,之后每一条 nanotun-* 命令都蹦回英文,
# 而人根本不知道有个语言可选。
#
# 写失败只 warn,不中断安装:它只影响后面那几条命令的默认语言,为它把一台已经装到
# 第 1 步的机器丢在半路不划算。内容就是一行 en 或 zh,重复装机就是把同一行再写一遍,
# 天然幂等。
#
# `2>/dev/null` 必须写在 `>` **前面**。重定向是从左往右生效的:反过来写的时候,`>` 已经
# 失败了而 stderr 还指着终端,于是 bash 自己那句裸的 "Permission denied" 会抢在下面这条
# warn 前面印出来 —— 同一件事说两遍,而先说的那遍没有语言、也没有下一步。
if printf '%s\n' "$NT_LANG" 2>/dev/null > "$ETC_DIR/lang"; then
  chmod 0644 "$ETC_DIR/lang" 2>/dev/null || true
else
  warn_t "Could not write $ETC_DIR/lang — later nanotun-* commands will fall back to the default language (English) instead of the one chosen here" \
         "写不了 $ETC_DIR/lang —— 之后的 nanotun-* 命令会退回默认语言(英文),而不是这次选的这个"
fi

# config.toml：**绝不覆盖已有配置**。
#
# 2026-07-25 部署实测:原逻辑无条件用发布包模板覆盖 $ETC_DIR/config.toml(只留 .bak)。
# 模板带 REPLACE_WITH_* 占位,而非法的 [reality].private_key 会让 nanotund 直接
# ExitListenOther(31) —— 于是「重复跑做升级」这个本脚本自己宣称幂等的正常用法,会把
# 一台正在服务的机器打成 crash-loop,且必须人工从 .bak 里捞回四个密钥才能恢复。
# 现在:已有配置原样保留,模板另存 config.toml.dist 供 diff 出新增字段;确实想推倒
# 重来的显式走 NANOTUN_FORCE_CONFIG=1。
#
# 权限一律 0600:填充后的 config.toml 含 hy2 密码 / obfs 密码 / REALITY 私钥,
# 原来的 0644 等于把它们摊给机器上任何本地用户读(两个 unit 都 User=root,收紧无副作用)。
install -m 0600 "$EXTRAS_DIR/config.toml" "$ETC_DIR/config.toml.dist"
# CONFIG_FRESH 记「这次是不是真拿模板写了 config.toml」——apply_magic_suffix 靠它决定
# 能不能改后缀:保留既有配置(升级路径)时它必须为 0,绝不擅自动别人已生效的 config。
if [ -f "$ETC_DIR/config.toml" ] && [ "${NANOTUN_FORCE_CONFIG:-0}" != "1" ]; then
  ok_t "Kept the existing config.toml (the tarball's template is saved as config.toml.dist, so new fields can be diffed)" \
       "保留已有 config.toml(发布包模板另存 config.toml.dist,可 diff 新增字段)"
  CONFIG_FRESH=0
else
  if [ -f "$ETC_DIR/config.toml" ]; then
    CFG_BAK="$ETC_DIR/config.toml.bak.$(date +%Y%m%d-%H%M%S)"
    cp -f "$ETC_DIR/config.toml" "$CFG_BAK"
    chmod 0600 "$CFG_BAK"
    warn_t "NANOTUN_FORCE_CONFIG=1: config.toml was overwritten with the template (the old file → $CFG_BAK)" \
           "NANOTUN_FORCE_CONFIG=1:已用模板覆盖 config.toml(原文件 → $CFG_BAK)"
  fi
  install -m 0600 "$EXTRAS_DIR/config.toml" "$ETC_DIR/config.toml"
  CONFIG_FRESH=1
fi
chmod 0600 "$ETC_DIR/config.toml"
# 顺带收紧历史遗留的 0644 备份:里面同样有 hy2 密码 / REALITY 私钥。
chmod 0600 "$ETC_DIR"/config.toml.bak.* 2>/dev/null || true

# 占位密钥填充。必须在 ensure-server-assets.sh / systemctl start 之前完成。
fill_config_secrets
# MagicDNS 后缀:装机时可经 NANOTUN_MAGIC_SUFFIX 定制(默认沿用模板里的 "nanotun")。同样须在
# systemctl start 之前 —— 它在 nanotund 启动时被读进 magicDNSResolved 快照,起来后改要重启。
# apply_reality_port —— 把 NANOTUN_REALITY_PORT 写进 [reality] 的 listen_addr。
#
# 与 apply_magic_suffix 同一口径,包括「只在这次真写了模板才改」这条:已有 config.toml 的
# 机器一律不动。理由比后缀那边更硬 —— REALITY 的端口印在每一份已经发出去的客户端配置里,
# 悄悄挪走等于把所有现有客户端一次性踢下线,而他们看到的只是「连不上」,没有任何线索指向
# 服务端换了端口。所以这里只警告,并把代价和做法一起说清。
#
# 默认 443 是有理由的(见 config.toml 的 [reality] 注释:伪装成普通 HTTPS 站点),这个旋钮
# 是给「443 已经被 nginx 占着」的机器用的,不是鼓励随便挪。
apply_reality_port() {
  local port="${NANOTUN_REALITY_PORT:-}"
  [ -n "$port" ] || return 0   # 没给:用模板默认的 443,不动 config.toml

  case "$port" in
    ''|*[!0-9]*) die_t "NANOTUN_REALITY_PORT is not a number: '$port'" \
                       "NANOTUN_REALITY_PORT 不是数字:'$port'" ;;
  esac
  if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
    die_t "NANOTUN_REALITY_PORT is out of range (1..65535): '$port'" \
          "NANOTUN_REALITY_PORT 超出范围(1..65535):'$port'"
  fi

  if [ "${CONFIG_FRESH:-0}" != 1 ]; then
    warn_t "The existing config.toml was kept, so NANOTUN_REALITY_PORT='$port' was not applied." \
           "已保留既有 config.toml,未套用 NANOTUN_REALITY_PORT='$port'。"
    warn_t "  Moving REALITY on a machine that is already serving cuts off every existing client:" \
           "  在一台已经在服务的机器上挪动 REALITY,会让所有现有客户端连不上:"
    warn_t "  their profiles carry the old port. To do it deliberately: edit listen_addr under [reality]" \
           "  他们手上的配置里写的是旧端口。要有意这么做:改 $ETC_DIR/config.toml 里 [reality] 的"
    warn_t "  in $ETC_DIR/config.toml, systemctl restart nanotun, then reissue every client profile" \
           "  listen_addr,systemctl restart nanotun,然后给每个客户端重发配置"
    warn_t "  (nanotun-setup can reissue the QR codes)." \
           "  (二维码可以用 nanotun-setup 重发)。"
    return 0
  fi

  local cfg="$ETC_DIR/config.toml"
  # 段感知改写:只动 [reality] 段内的 listen_addr。和后缀那边同样的写法 ——
  # 全局 sed 会把 [server] / [hysteria] 的 listen_addr 一起改掉,那是三个不同的东西。
  awk -v p="$port" '
    /^[ \t]*\[/ {
      insec = ($0 ~ /^[ \t]*\[reality\][ \t]*$/)
      print; next
    }
    {
      if (insec && $0 ~ /^[ \t]*#?[ \t]*listen_addr[ \t]*=/) {
        print "listen_addr = \":" p "\""; next
      }
      print
    }
  ' "$cfg" > "$cfg.tmp" && cat "$cfg.tmp" > "$cfg" && rm -f "$cfg.tmp"

  local now
  now="$(awk '/^[ \t]*\[reality\][ \t]*$/{insec=1; next} /^[ \t]*\[/{insec=0} insec && /^[ \t]*listen_addr[ \t]*=/{gsub(/.*:|"/, ""); print; exit}' "$cfg")"
  if [ "$now" != "$port" ]; then
    die_t "failed to write REALITY's port into $cfg (wanted $port, found '${now:-none}')" \
          "没能把 REALITY 端口写进 $cfg(想写 $port,读回 '${now:-空}')"
  fi
  ok_t "REALITY port: $port (443 is the default; changed because you asked)" \
       "REALITY 端口:$port(默认是 443,这次按你的要求改了)"
}

apply_magic_suffix
apply_reality_port

# 证书 / masquerade 页：按 config.toml 里配置的路径**按需自签**(不随包分发)。
# ensure-server-assets.sh 读 [server] / [hysteria] 的 tls_* 与 masquerade_dir,
# 只在文件缺失时生成,幂等;WorkingDirectory 传 $ETC_DIR,相对路径落到 $ETC_DIR/certs 等。
install -m 0755 "$SCRIPTS_DIR/ensure-server-assets.sh" /usr/local/bin/nanotun-ensure-assets.sh
# 端口解析器也装成命令旁边的一个文件:卸载脚本和环境自检都要 source 它,而它们装完之后
# 是从 /usr/local/bin 跑的 —— 发布包目录用完多半就没了。
install -m 0755 "$SCRIPTS_DIR/nanotun-ports.sh" /usr/local/bin/nanotun-ports.sh
# 它会逐条播报自己生成了什么(自签证书 / 开发 CA / 占位页),四行裸日志夹在本脚本的 ✓
# 中间,前缀和标点都是另一套。正常装完这一步的结论由下面那句 ✓ 概括就够了 —— 首次
# 安装本来就该生成这些。出错时才把它说过的话原样倒出来,那时每一行都是线索。
ASSETS_LOG="$(mktemp)" \
  || die_t "Could not create a temporary file — ${TMPDIR:-/tmp} is not writable (permissions / read-only / out of space). You can rerun with TMPDIR=/var/tmp." \
           "创建临时文件失败 —— ${TMPDIR:-/tmp} 写不进去(权限 / 只读 / 空间不足)。可以 TMPDIR=/var/tmp 重跑。"
if bash "$SCRIPTS_DIR/ensure-server-assets.sh" "$ETC_DIR" >"$ASSETS_LOG" 2>&1; then
  [ "${NANOTUN_VERBOSE:-0}" = 1 ] && sed 's/^/    /' "$ASSETS_LOG"
else
  cat "$ASSETS_LOG" >&2; rm -f "$ASSETS_LOG"
  die_t "Could not generate the certificates / masquerade assets (its raw output is above)" \
        "生成证书 / masquerade 资产失败(上面是它的原始输出)"
fi
rm -f "$ASSETS_LOG"

install -m 0644 "$SCRIPTS_DIR/tun-setup.service" /etc/systemd/system/nanotun-tun-setup.service
install -m 0644 "$EXTRAS_DIR/nanotun.service"  /etc/systemd/system/nanotun.service
systemctl daemon-reload
ok_t "Binaries / config / certificates / systemd units are in place" \
     "二进制 / 配置 / 证书 / systemd 单元已就位"

step_t "2. Enable IP forwarding + unprivileged ICMP ping" \
       "2. 开启 IP forwarding + unprivileged ICMP ping"
# /etc/sysctl.d 不是哪里都有:Rocky 9 的 minimal 镜像(以及最小化安装的 RHEL 系)
# 只带 /usr/lib/sysctl.d,/etc/sysctl.d 要管理员自己建。少这一句的后果是安装在第 2 步
# 当场炸在一行裸的 `No such file or directory` 上 —— 前一步刚把二进制和 systemd 单元
# 都写下去了,机器停在装了一半的状态,而屏幕上没有任何能照着做的话。
# 两边 sysctl --system 都读,建出来就行。
mkdir -p /etc/sysctl.d
cat > /etc/sysctl.d/99-nanotun.conf <<'SYSCTL'
# nanotun self-hosted VPN gateway: forward packets so clients can reach the internet
# and each other
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv6.conf.all.forwarding = 1
# When saving server_dial_host, nanotun-web runs an unprivileged ICMP ping (pro-bing)
# as a reachability check. Linux defaults to ping_group_range=0 0, so a non-root process
# cannot create a ping socket -> pro-bing fails to initialize -> the admin is forced to
# tick "skip the ICMP reachability check" forever just to get past it.
# Opening the full range lets any group run an unprivileged ping.
net.ipv4.ping_group_range = 0 2147483647
SYSCTL
# -e:遇到内核里不存在的键只警告,不作为错误。
#
# 不加这个的话,IPv6 被内核关掉的机器(`ipv6.disable=1`,一些 VPS 镜像和加固过的系统默认
# 就这样)上 /proc/sys/net/ipv6/conf/all/forwarding 根本不存在,sysctl 返回 1,而本脚本
# 开着 set -e —— 安装在第 2 步当场中断。此时二进制和 systemd 单元**已经写进盘里**了,
# 机器停在装了一半的状态,而用户看到的是 sysctl 那句
#   sysctl: cannot stat /proc/sys/net/ipv6/conf/all/forwarding: No such file or directory
# 没有任何一句话把它和「你的内核关了 IPv6,这不影响 IPv4 的使用」联系起来。
# (2026-08-27 在 Ubuntu + procps-ng 4.0.4 上实测过退出码和中断行为。)
#
# 还有一层:--system 读的是 /etc/sysctl.d 下的**所有**文件,不只我们这一份。系统镜像里
# 任何一个带废弃键的 drop-in 都会连累我们的安装 —— 而那跟 nanotun 毫无关系。
sysctl -e --system >/dev/null
# 每个值都带 `|| echo` 兜底,别只兜 ping_group_range 那一个:v6.forwarding 在上面那种
# 机器上读不出来,而命令替换失败不触发 set -e —— 结果是这行打印成 "v6.forwarding = ",
# 一个看着像 bug 的空值。写成 n/a 才说得清「这台机器没有 IPv6」。
NO_V6="$(tsel 'n/a (IPv6 is disabled in the kernel; IPv4 is unaffected)' 'n/a（内核未启用 IPv6，不影响 IPv4）')"
ok "ip_forward = $(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 'n/a'), v6.forwarding = $(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || echo "$NO_V6"), ping_group_range = '$(sysctl -n net.ipv4.ping_group_range 2>/dev/null || echo 'n/a')'"

# 三个对外端口一律从**实际配置**里读出来,不写死。
#
# 写死过一次,代价是「改了端口就连不上」:REALITY 挪到 9443 的机器上,这一步放行的仍是
# 8443(没人听),而 9443 关着(客户端要连的正是它),屏幕上却打着「✓ ufw 放行：8443/tcp」——
# 一切看着都对。而「端口被占就去改 [reality] 的 listen_addr」恰恰是环境自检自己给的建议。
#
# 必须放在第 1 步之后:全新机器上 config.toml 是那一步才落地的,更早读只会读到空。
# shellcheck source=scripts/nanotun-ports.sh
. "$SCRIPTS_DIR/nanotun-ports.sh"

# ── Web 后台端口:默认随机,并落进 web.env ────────────────────────────────────
#
# 后台登录页不需要「看起来像正常流量」,它需要的是别被顺手扫到 —— 所有部署都长在 7443 上
# 等于给扫描器一份现成的名单。所以默认随机。数据面那两个端口刻意不随机(REALITY 443/tcp
# + hy2 443/udp 合起来正是任何支持 HTTP/3 的网站的指纹),理由见 config.toml 的 [reality]。
#
# 端口从哪来,三种情形:
#   ① NANOTUN_WEB_PORT 有值 —— install.sh 问过之后 export 下来的,或调用方显式指定;
#   ② web.env 里已经钉了一个 —— 这台机器装过,**沿用**。升级是重跑本脚本的头号理由,
#      此刻换端口等于把一台正在服务的机器的管理入口挪走,而人只是想升级;
#   ③ 都没有 —— 从发布包目录直接跑(没经过 install.sh)。自己挑一个随机的,并打出来。
#
# 必须在放行防火墙**之前**定下来:下面 FW_TCP 用的就是它。也必须真的写进 web.env ——
# nanotun-web 的监听地址只从那儿读(systemd 单元的 EnvironmentFile),不写就还是内置的 7443,
# 于是会出现「防火墙放行了随机端口、服务却听在 7443」这种三方各自成功的局面。
nt_ish_random_port() {
  # 10000..31999:上界避开 Linux 默认临时端口段(32768–60999)——在那个区间 listen 会和
  # 本机对外连接的源端口撞,症状是偶发绑定失败,极难复现。
  # 用 /dev/urandom 而非 $RANDOM:同镜像同秒启动的批量云主机用 $RANDOM 有相当概率撞同一个。
  local n
  n="$(od -An -N2 -tu2 /dev/urandom 2>/dev/null | tr -d '[:space:]')"
  case "$n" in ''|*[!0-9]*) n="$RANDOM" ;; esac
  printf '%s' "$(( 10000 + n % 22000 ))"
}

NT_WEB_PORT_PINNED=""
if [ -r "$ETC_DIR/web.env" ]; then
  NT_WEB_PORT_PINNED="$(awk -F= '/^[ \t]*NANOTUN_WEB_LISTEN[ \t]*=/ {sub(/^[^=]*=/, ""); v=$0} END {print v}' \
    "$ETC_DIR/web.env" 2>/dev/null | tr -d '[:space:]"'"'"'' | sed 's/.*://')"
  case "$NT_WEB_PORT_PINNED" in ''|*[!0-9]*) NT_WEB_PORT_PINNED="" ;; esac
fi

if [ "$WEB_AVAILABLE" -eq 1 ]; then
  if [ -n "${NANOTUN_WEB_PORT:-}" ]; then
    :                                   # ① 上游定了
  elif [ -n "$NT_WEB_PORT_PINNED" ]; then
    NANOTUN_WEB_PORT="$NT_WEB_PORT_PINNED"   # ② 沿用本机现值
  else
    NANOTUN_WEB_PORT="$(nt_ish_random_port)" # ③ 自己挑
    ok_t "Web console port: $NANOTUN_WEB_PORT (randomized; set NANOTUN_WEB_PORT to pin it)" \
         "Web 后台端口:$NANOTUN_WEB_PORT(随机挑的;要固定就设 NANOTUN_WEB_PORT)"
  fi
  export NANOTUN_WEB_PORT

  # 落进 web.env。已经钉着同一个值就什么都不做(幂等,重跑不刷屏也不重启服务)。
  if [ "$NANOTUN_WEB_PORT" != "$NT_WEB_PORT_PINNED" ]; then
    install -d -m 0755 "$ETC_DIR"
    if [ -n "$NT_WEB_PORT_PINNED" ]; then
      # 原地替换,别追加第二行 —— EnvironmentFile 后者覆盖前者,两行并存时「改了却没生效」
      # 和「改了生效了」长得一模一样,而排查的人只会看到第一行。
      tmp_env="$(mktemp)" || tmp_env=""
      if [ -n "$tmp_env" ]; then
        sed "s|^[ \t]*NANOTUN_WEB_LISTEN[ \t]*=.*|NANOTUN_WEB_LISTEN=0.0.0.0:${NANOTUN_WEB_PORT}|" \
          "$ETC_DIR/web.env" > "$tmp_env" && cat "$tmp_env" > "$ETC_DIR/web.env"
        rm -f "$tmp_env"
      fi
    else
      printf 'NANOTUN_WEB_LISTEN=0.0.0.0:%s\n' "$NANOTUN_WEB_PORT" >> "$ETC_DIR/web.env"
    fi
    chmod 600 "$ETC_DIR/web.env" 2>/dev/null || true
  fi
fi

nanotun_load_ports "$ETC_DIR/config.toml" "$ETC_DIR/web.env"

# 要放行的 tcp 端口:REALITY 一条;Web 后台装了才放(没装就保持只在 LAN / 隧道内可达)。
FW_TCP=("$NT_PORT_REALITY")
[ "$WEB_AVAILABLE" -eq 1 ] && FW_TCP+=("$NT_PORT_WEB")

step_t "3. Firewall: open the ports nanotun listens on (when ufw / firewalld is active)" \
       "3. 防火墙：放行 nanotun 监听端口（ufw / firewalld active 时）"
# ufw 默认 INPUT DROP（Ubuntu 全新系统常见配置），不放行端口客户端会全部被静默丢包，
# 表现为「TCP 三次握手超时」「QUIC 重传无响应」。这里检测 ufw 状态后幂等放行。
# 如果你用的是 firewalld / iptables / 云厂商安全组，请按各自方式自行放行：
#   tcp $NT_PORT_REALITY (REALITY)  udp $NT_HY2_SPECS (hy2 QUIC)
# 数据面 WS(:8080)默认绑 127.0.0.1、不放行:客户端经 hy2/REALITY 接入,服务端在本机
# 桥接到它。若你把 [server].listen_addr 改回 ":8080" 想让客户端直连,请自行 `ufw allow 8080/tcp`。
# 2026-07-17:hy2 独立 WSS 保活(:8444)已下线,不再放行,并清理历史规则。
# 2026-07-20:数据面 WS(:8080)改绑回环,从放行清单移除,并回收历史 8080/tcp 规则。
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
  # 放行失败不 die,与下面 firewalld 分支同口径。
  #
  # 原来这里是裸的 `ufw allow "$rule" >/dev/null`,set -e 下失败即整个安装中断 —— 而
  # firewalld 那边同样的失败只 warn 并把手打命令给出来。同一件事两种严重程度,且严重的
  # 那种给错了:防火墙没放行,服务本身照样跑得好好的,该做的是告诉用户手动补一条,而不是
  # 把一台已经装到第 3 步的机器丢在半路。ufw 规则表损坏、被别的工具锁着的机器上会踩到。
  UFW_PORTS=()
  for rule in "${FW_TCP[@]}"; do UFW_PORTS+=("$rule/tcp"); done
  # hy2 开了端口跳跃时是一串,区间在 ufw 里写成 a:b(firewalld 那边是 a-b,所以两边各自渲染)。
  for rule in $NT_HY2_SPECS; do UFW_PORTS+=("${rule/-/:}/udp"); done
  UFW_BAD=0
  for rule in "${UFW_PORTS[@]}"; do
    ufw allow "$rule" >/dev/null 2>&1 || UFW_BAD=1
  done
  ufw delete allow "8444/tcp" >/dev/null 2>&1 || true
  # 历史部署曾放行 8080/tcp(当时数据面 WS 绑 0.0.0.0);现在绑回环,回收这条规则。
  ufw delete allow "8080/tcp" >/dev/null 2>&1 || true
  # 端口改过之后,默认那条得收回 —— 否则机器上留着一个对公网敞着、却没有任何东西在听的
  # 端口,而它看起来和一条正当的放行规则毫无区别。
  if [ "$NT_PORT_REALITY" != "$NT_DEFAULT_REALITY" ]; then
    ufw delete allow "${NT_DEFAULT_REALITY}/tcp" >/dev/null 2>&1 || true
  fi
  if [ "$WEB_AVAILABLE" -eq 1 ] && [ "$NT_PORT_WEB" != "$NT_DEFAULT_WEB" ]; then
    ufw delete allow "${NT_DEFAULT_WEB}/tcp" >/dev/null 2>&1 || true
  fi
  # Web 端口挪走之后,**旧那条**也得收 —— 而「旧」现在几乎总是个随机数。
  #
  # 上面那条只收 $NT_DEFAULT_WEB(7443)。在固定端口的年代它是够的:唯一可能的旧值就是
  # 默认值。改成随机默认之后,每台机器的旧值都是随机数,于是那条清理覆盖的恰好是一个
  # 不再发生的情况 —— 而 --web-port / NANOTUN_WEB_PORT 每换一次,就在机器上留下一个
  # 对公网敞着、却没有任何东西在听的端口,且它跟一条正当放行规则长得毫无区别。
  # 后果不是「有洞」(没人听就进不去),而是 ufw status 从此高估这台机器的暴露面 ——
  # 对一个隐私工具来说,审计时看到的东西必须是真的。
  # 旧值不用猜:写 web.env 之前就读到了(NT_WEB_PORT_PINNED)。
  if [ "$WEB_AVAILABLE" -eq 1 ] && [ -n "$NT_WEB_PORT_PINNED" ] && \
     [ "$NT_PORT_WEB" != "$NT_WEB_PORT_PINNED" ]; then
    ufw delete allow "${NT_WEB_PORT_PINNED}/tcp" >/dev/null 2>&1 || true
  fi
  if [ "$UFW_BAD" -eq 1 ]; then
    warn_t "ufw is running, but opening the ports automatically did not work. Run this by hand:" \
           "ufw 在跑,但自动放行没成功。请手动执行:"
    warn "  ufw allow$(printf -- ' %s' "${UFW_PORTS[@]}")"
  else
    ok_t "ufw opened: ${UFW_PORTS[*]}" "ufw 放行：${UFW_PORTS[*]}"
  fi
elif command -v firewall-cmd >/dev/null 2>&1 && [ "$(firewall-cmd --state 2>/dev/null)" = running ]; then
  # RHEL 系(Rocky / Alma / CentOS / Fedora)默认跑的是 firewalld,而它的默认 zone 同样
  # 拒绝入站。原来这里只认 ufw,其余一律 warn 一句「请手动放行」—— 于是 Rocky 用户装完
  # 满屏绿灯,客户端却连不上,而症状(TCP 握手超时 / QUIC 无响应)跟防火墙看不出关系,
  # 那句 warn 早被后面几十行刷走了。既然对 ufw 是自动放行的,没有理由只对它。
  FW_PORTS=()
  for rule in "${FW_TCP[@]}"; do FW_PORTS+=("$rule/tcp"); done
  # firewalld 的区间语法就是 a-b,和 nanotun-ports.sh 里保留的形态一致,原样传即可。
  for rule in $NT_HY2_SPECS; do FW_PORTS+=("$rule/udp"); done
  FW_BAD=0
  for rule in "${FW_PORTS[@]}"; do
    firewall-cmd --permanent --add-port="$rule" >/dev/null 2>&1 || FW_BAD=1
  done
  # 与 ufw 分支同口径:回收历史上放行过、现在不再需要的端口。
  firewall-cmd --permanent --remove-port=8444/tcp >/dev/null 2>&1 || true
  firewall-cmd --permanent --remove-port=8080/tcp >/dev/null 2>&1 || true
  if [ "$NT_PORT_REALITY" != "$NT_DEFAULT_REALITY" ]; then
    firewall-cmd --permanent --remove-port="${NT_DEFAULT_REALITY}/tcp" >/dev/null 2>&1 || true
  fi
  if [ "$WEB_AVAILABLE" -eq 1 ] && [ "$NT_PORT_WEB" != "$NT_DEFAULT_WEB" ]; then
    firewall-cmd --permanent --remove-port="${NT_DEFAULT_WEB}/tcp" >/dev/null 2>&1 || true
  fi
  # 与 ufw 分支同口径:旧的随机端口也要收(理由见那边的注释)。
  if [ "$WEB_AVAILABLE" -eq 1 ] && [ -n "$NT_WEB_PORT_PINNED" ] && \
     [ "$NT_PORT_WEB" != "$NT_WEB_PORT_PINNED" ]; then
    firewall-cmd --permanent --remove-port="${NT_WEB_PORT_PINNED}/tcp" >/dev/null 2>&1 || true
  fi
  firewall-cmd --reload >/dev/null 2>&1 || FW_BAD=1
  if [ "$FW_BAD" -eq 0 ]; then
    ok_t "firewalld opened: ${FW_PORTS[*]}" "firewalld 放行：${FW_PORTS[*]}"
  else
    # 放行失败不该 die:服务本身能跑,只是外面进不来,而这在云上还可能被安全组兜着。
    # 但必须把那条命令原样给出来,不能只说「请自行放行」。
    warn_t "firewalld is running, but opening the ports automatically did not work. Run this by hand:" \
           "firewalld 在跑,但自动放行没成功。请手动执行:"
    warn "  firewall-cmd --permanent$(printf -- ' --add-port=%s' "${FW_PORTS[@]}") && firewall-cmd --reload"
  fi
else
  warn_t "Neither ufw nor firewalld was found active; if you use another firewall, open ${NT_PORT_REALITY}/tcp and $(printf '%s' "$NT_HY2_SPECS" | tr ' ' ',')/udp by hand (plus ${NT_PORT_WEB}/tcp when web is installed)" \
         "未检测到 ufw / firewalld active；如使用其他防火墙，请手动放行 ${NT_PORT_REALITY}/tcp 与 $(printf '%s' "$NT_HY2_SPECS" | tr ' ' ',')/udp（装了 web 再加 ${NT_PORT_WEB}/tcp）"
fi

# 云厂商安全组:这一句必须在**任何一条分支之后**都印出来,包括「ufw 放行成功」那条。
#
# 原来它只活在上面那段代码注释里,以及开服向导的结尾。于是两类人拿不到它:跳过向导的
# (无人值守、或者装完就去干别的),和 ufw 装了但没启用因而落进 else 分支的 —— 后者是
# 全新 Ubuntu 的常态,那句 warn 里也没有「安全组」三个字。
#
# 这是自托管 VPN 最贵的一个坑:主机防火墙放行成功、服务全绿、端口在听,客户端就是连不上,
# 而症状(握手超时 / QUIC 无响应)和「你还没在网页控制台上点放行」之间隔着整个心智模型。
# ufw 放了不等于安全组放了,而 ufw 那条绿色的 ✓ 恰恰会让人以为防火墙这件事已经办完了。
#
# 443/**UDP** 单独点名:云厂商的默认安全组模板几乎都是 22 + 80/443 TCP,UDP 一条没有。
# 也就是说照着模板走的人,REALITY(8443/tcp)自己加了,hy2 那条最容易漏 —— 而漏了它的
# 表现不是连不上,是「能连但慢」(客户端悄悄退到别的传输),更难往防火墙上想。
# 端口同样取实际值:安全组要放行的是这台机器真正在听的那个,照着默认值去填等于白填。
if [ "$NT_LANG" = zh ]; then
  note_ports="${NT_PORT_REALITY}/tcp（REALITY）、$(printf '%s' "$NT_HY2_SPECS" | tr ' ' ',')/udp（hysteria2）"
  [ "$WEB_AVAILABLE" -eq 1 ] && note_ports="${note_ports}、${NT_PORT_WEB}/tcp（Web 后台）"
else
  note_ports="${NT_PORT_REALITY}/tcp (REALITY), $(printf '%s' "$NT_HY2_SPECS" | tr ' ' ',')/udp (hysteria2)"
  [ "$WEB_AVAILABLE" -eq 1 ] && note_ports="${note_ports}, ${NT_PORT_WEB}/tcp (web console)"
fi
warn_t "On a cloud server you also have to open these in the provider's **security group / network ACL**: ${note_ports}" \
       "云服务器还要去厂商控制台的**安全组 / 网络 ACL** 里放行：${note_ports}"
warn_t "  This script cannot do that step. An open ufw is not an open security group; 443 is UDP, and security-group templates usually only cover TCP." \
       "  这一步脚本做不了。ufw 放了不等于安全组放了；443 是 UDP，而安全组模板通常只给 TCP。"

step_t "4. Check for a database at the old path (K1: guard against the 2026-05-21 incident)" \
       "4. 旧 DB 路径迁移自检（K1：2026-05-21 事故防再发）"
# 背景:历史上 nanotun 曾用 /root/nanotun/data/nanotun.db 作为 SQLite home,
# 新版本搬到了 /var/lib/nanotun/nanotun.db。若部署脚本只在新路径建空库 + 一个 admin,
# 旧 DB 里的 smoker / 设备 / lease 留在原地不会被自动迁移 → 所有终端 401/403 「用户不存在」,
# iOS / macOS 表面看到的是 「NECP policy denied」「No route to host」(实际是登录失败 EOF)。
# 这里做的检查:
#   • 新 DB 没有「非 admin 用户」(空库 / 刚 init 的库都属于这种)
#   • 旧路径 /root/nanotun/data/nanotun.db 存在,且里面**有**非 admin 用户
# → 阻断安装,提示用户:要么明确导入(NANOTUN_IMPORT_LEGACY_DB=1),要么先手动归档。
# 这两种动作都需要人工确认,绝不**默认**覆盖。
LEGACY_DB=/root/nanotun/data/nanotun.db
count_real_users() {
  # 第三列 ADMIN 为 "no" 视为终端用户。
  # nanotun-admin user list 在空库 / 不存在表时返回空,这种就是 0。
  #
  # `|| true` 不可省:本脚本开了 pipefail,而 DB 不存在时 nanotun-admin 退非零会
  # 让整条管线非零。若把兜底写成调用侧的 `|| echo 0`,awk 已打印的 "0" 会再被追加
  # 一个 "0",变量成 "0\n0",下面的 `[ -eq ]` 直接语法错 → if 静默走 else,
  # 本节的旧库保护检查等于没跑(2026-07-25 部署实测到)。计数固定由 awk 单独输出。
  { /usr/local/bin/nanotun-admin --db-path "$1" user list 2>/dev/null || true; } \
    | awk 'NR>1 && $3=="no" {n++} END {print n+0}'
}
NEW_USERS=$(count_real_users "$LIB_DIR/nanotun.db")
LEGACY_USERS=0
if [ -f "$LEGACY_DB" ]; then
  LEGACY_USERS=$(count_real_users "$LEGACY_DB")
fi
if [ "$NEW_USERS" -eq 0 ] && [ "$LEGACY_USERS" -gt 0 ]; then
  if [ "${NANOTUN_IMPORT_LEGACY_DB:-0}" = "1" ]; then
    # 备份是**有条件**的:新路径本来就没有库时,没有东西可备份。而从老布局升级
    # 恰恰就是这种情况 —— 建新库的 init 在第 5 步,比这里晚。原来这句 ok 无条件
    # 报「备份原文件 → ${BAK}」,于是在这条最主要的升级路径上点名了一个根本不存在的
    # 文件:照着去 ls 会扑空,而扑空的时机正是「刚覆盖完新路径」,最容易被读成
    # 「导入只做了一半」。有备份才说备份;没有就说清楚回滚从哪来。
    BAK=""
    if [ -f "$LIB_DIR/nanotun.db" ]; then
      BAK="$LIB_DIR/nanotun.db.preimport.$(date +%Y%m%d-%H%M%S)"
      cp -a "$LIB_DIR/nanotun.db" "$BAK"
      [ -f "$LIB_DIR/nanotun.db-wal" ] && cp -a "$LIB_DIR/nanotun.db-wal" "$BAK-wal" || true
      [ -f "$LIB_DIR/nanotun.db-shm" ] && cp -a "$LIB_DIR/nanotun.db-shm" "$BAK-shm" || true
    fi
    install -m 0600 "$LEGACY_DB" "$LIB_DIR/nanotun.db"
    [ -f "$LEGACY_DB-wal" ] && install -m 0600 "$LEGACY_DB-wal" "$LIB_DIR/nanotun.db-wal" || rm -f "$LIB_DIR/nanotun.db-wal"
    [ -f "$LEGACY_DB-shm" ] && install -m 0600 "$LEGACY_DB-shm" "$LIB_DIR/nanotun.db-shm" || rm -f "$LIB_DIR/nanotun.db-shm"
    if [ -n "$BAK" ]; then
      ok_t "Imported the database from the old path: ${LEGACY_DB} → ${LIB_DIR}/nanotun.db (the database that was at the new path is backed up → ${BAK})" \
           "已从旧路径导入 DB:${LEGACY_DB} → ${LIB_DIR}/nanotun.db(新路径原有的库已备份 → ${BAK})"
    else
      ok_t "Imported the database from the old path: ${LEGACY_DB} → ${LIB_DIR}/nanotun.db (there was no database at the new path, so nothing to back up)" \
           "已从旧路径导入 DB:${LEGACY_DB} → ${LIB_DIR}/nanotun.db(新路径原本没有库,无需备份)"
    fi
    # 导入是 copy 不是 move。这句不是客套:上面那条没有备份的路径里,旧库就是唯一的回滚点。
    ok_t "The old database is left exactly where it was, at ${LEGACY_DB} (not deleted); archive it by hand once you have checked the new one" \
         "旧库原样留在 ${LEGACY_DB}(未删除);确认新库无误后再手动归档"
    ok_t "The Batch J binaries run store.Migrate on startup, so new migrations are applied automatically" \
         "Batch J 二进制启动时会自动跑 store.Migrate 应用新 migration"
  else
    SELF_PATH="$(realpath "$0" 2>/dev/null || echo "$0")"
    if [ "$NT_LANG" = zh ]; then
      printf >&2 '\n\033[1;31mFATAL: 旧 DB 路径 %s 检出 %d 个终端用户,\n新路径 %s/nanotun.db 没有,直接装会让所有终端登录失败「用户不存在」(2026-05-21 事故场景)。\033[0m\n\n' \
        "$LEGACY_DB" "$LEGACY_USERS" "$LIB_DIR"
      printf >&2 '请二选一明确处理:\n  1) 导入旧数据(保留 PSK / device UUID / lease):\n       systemctl stop nanotun.service 2>/dev/null || true\n       NANOTUN_IMPORT_LEGACY_DB=1 bash %s\n  2) 确认旧数据已无用,归档后再装:\n       mv %s %s.archived.$(date +%%Y%%m%%d-%%H%%M%%S)\n       bash %s\n\n' \
        "$SELF_PATH" "$LEGACY_DB" "$LEGACY_DB" "$SELF_PATH"
    else
      printf >&2 '\n\033[1;31mFATAL: the database at the old path %s holds %d end-user accounts,\nand %s/nanotun.db does not. Installing straight over that makes every client fail to log in with "user does not exist" (the 2026-05-21 incident).\033[0m\n\n' \
        "$LEGACY_DB" "$LEGACY_USERS" "$LIB_DIR"
      printf >&2 'Pick one of these explicitly:\n  1) Import the old data (keeps PSKs / device UUIDs / leases):\n       systemctl stop nanotun.service 2>/dev/null || true\n       NANOTUN_IMPORT_LEGACY_DB=1 bash %s\n  2) The old data is of no use — archive it, then install:\n       mv %s %s.archived.$(date +%%Y%%m%%d-%%H%%M%%S)\n       bash %s\n\n' \
        "$SELF_PATH" "$LEGACY_DB" "$LEGACY_DB" "$SELF_PATH"
    fi
    die_t "Refusing to finish the install while the old database still has users and the new one is empty" \
          "拒绝在「旧 DB 仍有用户、新 DB 空」状态下完成安装"
  fi
else
  if [ "$LEGACY_USERS" -gt 0 ] && [ "$NEW_USERS" -gt 0 ]; then
    warn_t "The old database $LEGACY_DB still holds $LEGACY_USERS end-user accounts, but the new one already has $NEW_USERS — it will not be overwritten automatically." \
           "旧 DB $LEGACY_DB 仍有 $LEGACY_USERS 个终端用户,但新 DB 已有 $NEW_USERS 个 — 不会自动覆盖。"
    warn_t "Once you are sure it is of no use, archive it by hand: mv $LEGACY_DB $LEGACY_DB.archived.\$(date +%Y%m%d-%H%M%S)" \
           "确认无用后请手动 mv 归档:mv $LEGACY_DB $LEGACY_DB.archived.\$(date +%Y%m%d-%H%M%S)"
  else
    ok_t "There is no legacy database that needs migrating" "没有需要迁移的历史 DB"
  fi
fi

# ── 升级前给数据库留一份还原点 ──────────────────────────────────────────────
#
# schema 迁移是一路向前的:现有的三十来个迁移里有 DROP COLUMN、有改名,跑过去就回不来。
# 而降级守卫(ErrSchemaFromFuture)拦下旧二进制时,给的出路正是「从降级前的备份恢复
# 数据库」—— 在此之前,产品里没有任何一处会产生那份备份。那句话指着一个不存在的东西,
# 而它出现的时机恰恰是人已经把机器降级、正着急的时候。
#
# 位置选在这里:第 1 步已经把新的 nanotun-admin 装好了,而服务要到第 6 步才重启 ——
# 也就是说库还停在旧 schema,迁移还没发生,这是唯一一个「还能留下迁移前状态」的窗口。
#
# 用 nanotun-admin backup(VACUUM INTO):强一致快照,只读,老服务还跑着也能拿,
# 落盘 0600。它不跑 Migrate,所以拿新 admin 去备份一个尚未迁移的库是安全的。
#
# 失败只 warn 不 die:备份是保险,不是安装的前置条件 —— 为了它把一台已经装到第 4 步的
# 机器丢在半路不划算。但要说清没留成,否则人会以为有。
DB_FILE="$LIB_DIR/nanotun.db"
if [ -f "$DB_FILE" ]; then
  BACKUP_DIR="$LIB_DIR/backups"
  BACKUP_FILE="$BACKUP_DIR/nanotun-$(date +%Y%m%d-%H%M%S).db"
  mkdir -p "$BACKUP_DIR" && chmod 0700 "$BACKUP_DIR"
  if nanotun-admin --db-path "$DB_FILE" backup "$BACKUP_FILE" >/dev/null 2>&1; then
    ok_t "Backed up the database before upgrading → $BACKUP_FILE" \
         "升级前已备份数据库 → $BACKUP_FILE"
    # 只留最近 3 份。不设上限的话,每升一次多一份,而这个目录没人会去看 ——
    # 直到某天磁盘满了才发现,那时症状是「服务起不来」,跟备份看不出关系。
    ls -1t "$BACKUP_DIR"/nanotun-*.db 2>/dev/null | tail -n +4 | while read -r old; do
      rm -f "$old"
    done
  else
    warn_t "The database backup did not succeed (this install is unaffected, carrying on)." \
           "数据库备份没做成(不影响本次安装,继续)。"
    warn_t "  To take one by hand: nanotun-admin --db-path $DB_FILE backup <destination>" \
           "  想手动留一份:nanotun-admin --db-path $DB_FILE backup <落点>"
    warn_t "  If you care, back it up before upgrading — a schema migration cannot be undone." \
           "  在意的话先备份再升级 —— schema 迁移过去就回不来了。"
  fi
fi

step_t "5. Initialise the admin user (first deploy generates a PSK; a repeat deploy is a noop and keeps the existing one)" \
       "5. 初始化 admin 用户（首次部署生成 PSK；重复部署 noop 保留现有 PSK）"
# init 默认幂等：setup_completed=1 时再跑只输出 admin 元信息（{"noop":true}），不改 PSK。
# 想强制重置请手动 `nanotun-admin --json init --reset-psk`，不要让脚本自动做。
# 输出要洗两遍,不能 2>&1 一把抓:
#   · nanotun-admin 的启动日志走 stderr。混进来之后 init.out.txt 既不是干净文本、
#     也不是能解析的 JSON —— 而它是这个管理员 PSK 的唯一留档。
#   · init 会问用户名和 PSK 两个问题(两个空行 = 都取默认值),提示语走 stdout,
#     会贴在 JSON 前面变成「admin username [admin]: {」,所以从第一个 { 起截断。
INIT_ERR="$(mktemp)" || INIT_ERR=""
[ -n "$INIT_ERR" ] || die_t "Could not create a temporary file — ${TMPDIR:-/tmp} is not writable (permissions / read-only / quota / out of space)." \
                            "创建临时文件失败 —— ${TMPDIR:-/tmp} 写不进去(权限 / 只读 / 配额 / 空间不足)。"
INIT_RC=0
INIT_OUT="$(printf '\n\n' | /usr/local/bin/nanotun-admin --db-path "$LIB_DIR/nanotun.db" --json init 2>"$INIT_ERR")" || INIT_RC=$?
INIT_JSON="$(printf '%s\n' "$INIT_OUT" | awk 'f {print; next} /{/ {sub(/^[^{]*/, ""); print; f=1}')"

# 原来这里是 `|| true`:init 挂掉也照样报「首次 init,生成新 PSK」,还把错误信息
# 当作凭据写进 init.out.txt。结果是一个没有管理员、根本管不了的库,而屏幕全绿。
if [ "$INIT_RC" != 0 ] || [ -z "$INIT_JSON" ]; then
  printf '%s\n' "$INIT_OUT" >&2
  cat "$INIT_ERR" >&2
  rm -f "$INIT_ERR"
  # 这句只交代后果,不能顺口把原因也说了。
  #
  # 原文是「—— 库里没有管理员,装完也管不了」,读起来像在断因:问题出在缺管理员。
  # 可 init 挂掉的原因五花八门,而上面几行刚原样倒出来的 stdout/stderr 里就写着。
  # 实测降级到旧版、库的 schema 却来自新版时,上一行明明白白写着「库的 schema 版本
  # 是 99,本程序只认到 30」,而这行红字却把人引去建管理员 —— 建一次再失败一次。
  # 扫红字的人只看得到这一行,所以它必须把视线送回上面,而不是自己猜一个原因。
  die_t "nanotun-admin init failed (exit code ${INIT_RC}) — the reason is in init's raw output a few lines above.
   There is no administrator in the database, so this machine cannot be managed once
   installed. Deal with what it says above, then rerun this script." \
        "nanotun-admin init 失败(退出码 ${INIT_RC})—— 原因见上面几行 init 的原始输出。
   库里没有管理员,这台机器装完也管不了,先按上面的提示解决再重跑本脚本。"
fi
rm -f "$INIT_ERR"

if printf '%s' "$INIT_JSON" | grep -q '"noop"[[:space:]]*:[[:space:]]*true'; then
  ok_t "Already set up, init skipped (the PSK was not reset)" \
       "已 setup，init 跳过（不重置 PSK）"
else
  INIT_FILE="$DEPLOY_DIR/init.out.txt"
  printf '%s\n' "$INIT_JSON" > "$INIT_FILE"
  chmod 600 "$INIT_FILE"
  ok_t "First init, the administrator account has been created" \
       "首次 init,已创建管理员账号"
  # 摆出来,别让人从 JSON 里自己捞。这是整个安装过程产出的最重要的一样东西。
  echo
  INIT_USERNAME="$(printf '%s' "$INIT_JSON" | sed -n 's/.*"username"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
  INIT_PSK="$(printf '%s' "$INIT_JSON" | sed -n 's/.*"psk"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
  # 两份各自写全,不用 tsel 拼:标签宽度要跟着语言变(「用户名」占 6 列、Username 占 8),
  # 而这两行是**唯一**一次明文露出 PSK 的地方 —— 值必须对齐在同一列,扫一眼就能抄。
  if [ "$NT_LANG" = zh ]; then
    printf '        用户名  %s\n' "$INIT_USERNAME"
    printf '        PSK     %s\n' "$INIT_PSK"
  else
    printf '        Username  %s\n' "$INIT_USERNAME"
    printf '        PSK       %s\n' "$INIT_PSK"
  fi
  echo
  warn_t "These are the credentials of the VPN account called admin (a different thing from the web console administrator) — copy them now." \
         "这是 admin 这个 VPN 账号的凭据(跟 Web 后台管理员是两回事),现在就抄走。"
  warn_t "A second copy is kept in ${INIT_FILE} (0600) — that is the release tarball's extraction directory, so do not delete it by reflex." \
         "另存了一份在 ${INIT_FILE}(0600)—— 那是发布包解压目录,别顺手删了。"
fi

step_t "6. Start the services and enable them at boot" "6. 启动并设为开机自启"
# 起不来**不能**在这一步就终止脚本。
#
# nanotun.service 是 Type=notify:服务没发出 READY 时 systemctl restart 返回非零,
# 配上本脚本的 set -e 就是当场退出 —— 而第 7 步的 systemctl status 与 journalctl -n 40
# 恰恰是唯一能说明「为什么没起来」的输出。于是最常见的那种失败(配置有问题、
# 端口被占、缺 TUN),给出的信息反而最少:屏幕停在「6. 启动并设为开机自启」,
# 一个字的原因都没有,用户只能自己去想到该翻 journalctl。
#
# 所以这里把失败记下来继续走,让诊断打完,最后再以非零退出。
START_FAILED=0
# --quiet 只是压掉 "Created symlink ..." 那行 —— 它是 systemd 的实现细节,
# 对着装机的人说不出任何有用的东西,却混在本脚本的 ✓ 里显得像出了什么事。
systemctl enable --quiet nanotun-tun-setup.service || START_FAILED=1
# 必须是 restart,不能是 --now(那等于 start)。
#
# 这个单元是 oneshot + RemainAfterExit=yes:装过一次之后它就一直是 active,于是
# 升级时 start 是个空操作 —— 盘上换成了新脚本,跑的还是上次开机那一次的结果,新逻辑
# 要等到下次重启才生效。而它现在的正事恰恰是**升级时**清掉旧版留下的那 14 张空网卡
# (见 tun-setup.sh),偏偏就是这条路上不生效:升级完一看,tun1-14 一张没少,
# 而屏幕上全是 ✓。
#
# 它是 Requires= 的被依赖方,restart 会把 nanotun 一起带停 —— 下面紧接着就 restart
# nanotun,顺序不能反。
systemctl restart nanotun-tun-setup.service || START_FAILED=1
sleep 1
# enable + restart：保证开机自启 + 应用最新配置
systemctl enable nanotun.service >/dev/null 2>&1 || true
if systemctl restart nanotun.service && settled_active nanotun.service; then
  # 成功也说一声。失败那条路现在很详细,这里再什么都不打,第 6 步在屏幕上就只剩一个
  # 空标题 —— 而它恰恰是全脚本最慢的一步,看着像卡住了。
  [ "$START_FAILED" = 0 ] && ok_t "nanotun.service is running and enabled at boot" \
                                  "nanotun.service 已启动并设为开机自启"
else
  START_FAILED=1
fi

if [ "$WEB_AVAILABLE" -eq 1 ]; then
  step_t "6b. Install nanotun-web (the web console, M2)" \
         "6b. 安装 nanotun-web(Web 管理后台,M2)"
  install -m 0755 "$DEPLOY_DIR/nanotun-web" /usr/local/bin/nanotun-web
  install -m 0644 "$EXTRAS_DIR/nanotun-web.service" /etc/systemd/system/nanotun-web.service
  install -d -m 0700 "$ETC_DIR/certs"  # web TLS 自签证书会落到这里
  systemctl daemon-reload
  systemctl enable nanotun-web.service >/dev/null 2>&1 || true
  # 同上:先记账,别让它把第 7 步的诊断挤掉。
  # settled_active 不能省 —— 这个单元是 Type=simple,restart 的返回值判不出死活。
  if systemctl restart nanotun-web.service && settled_active nanotun-web.service; then
      # 别再把人往 /setup 引。那个页面在第一个管理员出现之前对全网公开(谁先打开谁是
      # 管理员),而紧接着要跑的开服向导会当场把账号建掉 —— 指向它才是短的那条路,
      # 也不留窗口。手动建也不必开浏览器:nanotun-admin webadmin create。
      ok_t "nanotun-web is running; its console account is set up by the setup wizard in the next step (or with nanotun-admin webadmin create)" \
           "nanotun-web 已启动,后台账号在下一步的开服向导里设(也可 nanotun-admin webadmin create)"
  else
    START_FAILED=1
    warn_t "nanotun-web did not start (the reason is in the step 7 diagnostics below)" \
           "nanotun-web 没能启动(原因见下面第 7 步的诊断)"
  fi
fi

step_t "7. Status check" "7. 状态自检"

# 这一步以前无条件把三份 systemctl status、ss 表和 journalctl -n 40 全倒出来 ——
# 九十来行原始日志,占掉整个安装输出的三分之一。代价不是「话多」这么简单:第 5 步
# 刚打印的 admin PSK 会被顶出屏幕,而那是它明文出现的**唯一**一次,还写着「现在就抄走」。
# 日志里又混着 IPv6 的 level=warning 和一句 TLS handshake error(都无害),第一次装的人
# 只会以为哪里出了事。
#
# 所以正常路径只给结论;任何一项不对(单元没起、没设自启、端口没听)才把原始诊断整个
# 倒出来 —— 那时候它每一行都是线索。想主动看:NANOTUN_VERBOSE=1 重跑。
CHECK_UNITS=(nanotun-tun-setup nanotun)
[ "$WEB_AVAILABLE" -eq 1 ] && CHECK_UNITS+=(nanotun-web)
STATUS_BAD=0
for unit in "${CHECK_UNITS[@]}"; do
  # 不能写成 `$(systemctl is-active … || echo inactive)`:这两个子命令在「有话要说」的
  # 时候恰恰是非零退出 —— activating 打印 activating 并返回 3、disabled 打印 disabled
  # 并返回 1,于是 || 分支也跟着跑,变量里就成了两行("activating\ninactive"),
  # 屏幕上多出一行凭空的 inactive,而那正是出事时最需要看清状态的时刻。
  # 所以:只在真的**什么都没输出**(单元不存在)时才兜底。
  en="$(systemctl is-enabled "$unit.service" 2>/dev/null | head -1)" || true
  ac="$(systemctl is-active  "$unit.service" 2>/dev/null | head -1)" || true
  en="${en:-unknown}"; ac="${ac:-inactive}"
  line="$(printf '%-18s %s · %s' "$unit" "$en" "$ac")"
  # tun-setup 是 oneshot + RemainAfterExit,跑完仍报 active,和另外两个同口径。
  if [ "$ac" = active ] && [ "$en" = enabled ]; then ok "$line"; else warn "$line"; STATUS_BAD=1; fi
done

# 端口是「客户端到底连不连得上」最直接的证据,比服务 active 更贴近现象,所以即使
# 在安静模式下也要有一行。hy2 听的是 **UDP** 443,漏掉 -u 就会把它误报成没起来。
# 带上 -p:光看「这个端口上有没有人听」是不够的,还得看是**谁**在听。
#
# 少了这一问,任何一次端口被别人占着的安装都会拿到一个假绿灯:占用者满足了「有人在听」,
# 于是自检替一个根本没起来的服务背书。实测两种(2026-08-28):
#   · REALITY 和 Web 落到同一个端口 —— nanotund 先起来占住,自检对两者都打勾,而
#     nanotun-web 正拿着 EADDRINUSE crash-loop;
#   · --skip-check 装到一台 nginx 占着 443 的机器上 —— 同理。
# 这两条现在都在环境自检那边被拦下了,但拦不住的还有:装完之后别人抢了端口、或者有人
# 手改了 config.toml 再重跑。屏幕上打绿灯的代价太高,宁可多问一句。
LISTEN_TCP="$(ss -lntp 2>/dev/null | awk 'NR>1{print $4" "$NF}')"
LISTEN_UDP="$(ss -lnup 2>/dev/null | awk 'NR>1{print $4" "$NF}')"
PORTS_UP=(); PORTS_DOWN=(); PORTS_ALIEN=()
check_port() { # <tcp|udp> <端口> <标签> <该由谁听>
  local pool line; [ "$1" = tcp ] && pool="$LISTEN_TCP" || pool="$LISTEN_UDP"
  # `|| true` 不能省:set -e 下,独立赋值里的 grep 没匹配到会让**整个脚本当场退出**。
  # 原先的写法把 grep 放在 if 条件里(那是 set -e 豁免的),改成赋值就踩上了。
  # 2026-08-28 实测:nanotun 起不来时 hy2 那条查不到监听,脚本从第 7 步中间静默断掉 ——
  # 而「有端口没听上」正是这段检查存在的唯一理由,等于它在最需要的时候消失。
  line="$(printf '%s\n' "$pool" | grep -E ":$2 " | head -1 || true)"
  if [ -z "$line" ]; then PORTS_DOWN+=("$3"); STATUS_BAD=1; return; fi
  # 进程名看不出来时(ss 没有 -p、或者内核不给)不作负面判断 —— 「看不见」不等于「不对」,
  # 在这上面报错比不报更糟。
  case "$line" in
    *users:*)
      if printf '%s' "$line" | grep -q "\"$4\""; then PORTS_UP+=("$3")
      else
        PORTS_ALIEN+=("$3 → $(printf '%s' "$line" | sed 's/.*users:((\"\([^"]*\)\".*/\1/')")
        STATUS_BAD=1
      fi ;;
    *) PORTS_UP+=("$3") ;;
  esac
}
# 同样看实际端口。写死 8443 时,改过端口的机器每次装完都报一句「! 没听上:8443/tcp(REALITY)」
# 并跟一大段诊断 —— 而服务正好好地在新端口上跑着。那句话把人指向「服务没起来」,
# 离真相(自检看错了地方)很远。
check_port tcp "$NT_PORT_REALITY" "${NT_PORT_REALITY}/tcp(REALITY)" nanotund
# hy2 开端口跳跃时只有首端口真的 listen,其余靠 iptables REDIRECT 过来,所以这里只看首端口。
check_port udp "$NT_PORT_HY2"     "${NT_PORT_HY2}/udp(hy2)" nanotund
[ "$WEB_AVAILABLE" -eq 1 ] && check_port tcp "$NT_PORT_WEB" "${NT_PORT_WEB}/tcp(Web)" nanotun-web
[ ${#PORTS_UP[@]}   -gt 0 ] && ok_t   "Listening: ${PORTS_UP[*]}"     "监听中:${PORTS_UP[*]}"
[ ${#PORTS_DOWN[@]} -gt 0 ] && warn_t "Not listening: ${PORTS_DOWN[*]}" "没听上:${PORTS_DOWN[*]}"
# 「有人在听,但不是它」必须和「没人听」分开说:两者的修法完全不同 —— 前者要么挪端口、
# 要么停掉占用者,后者是服务本身没起来。混成一句会把人指向错误的方向。
[ ${#PORTS_ALIEN[@]} -gt 0 ] && warn_t \
  "Held by someone else: ${PORTS_ALIEN[*]} — nanotun's own service is not the one listening there, so it did not get the port" \
  "被别人占着:${PORTS_ALIEN[*]} —— 在那儿听的不是 nanotun 自己的服务,也就是说它没拿到这个端口"

# TUN 到底有没有拿到 IPv4 —— 这一项服务状态和端口都照不出来。
#
# [tun].subnets 里的候选如果**全部**与本机网段冲突,nanotund 会跳过 IPv4 继续跑:
# 服务 active、端口都听上了、这个脚本一路打勾,而客户端从此拿不到 IPv4 虚拟 IP,
# 等于一台只剩 IPv6 的 VPN。原因只在 journal 里留一句 warning,而装完一切正常的人
# 是不会去翻 journal 的。
#
# 触发它不需要多奇怪的配置:本机地址是 10.x/**8**(企业内网、部分云内网的常规分法)
# 就能一次撞掉 10.200-10.202 三段。实测 10.5.3.4/8 必现。
TUN_DEV="$(sed -n 's/^[[:space:]]*device_name[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' \
             "$ETC_DIR/config.toml" 2>/dev/null | head -1)"
TUN_DEV="${TUN_DEV:-tun0}"
if [ "$START_FAILED" != 1 ] && ip link show "$TUN_DEV" >/dev/null 2>&1 \
   && ! ip -4 addr show dev "$TUN_DEV" 2>/dev/null | grep -q 'inet '; then
  warn_t "$TUN_DEV has no IPv4 address — every candidate in [tun].subnets collides with a subnet this machine already uses, so IPv4 was skipped." \
         "$TUN_DEV 没有 IPv4 地址 —— [tun].subnets 里的候选网段与本机网段全部冲突,已跳过 IPv4。"
  warn_t "  The service did come up, but clients get no IPv4 virtual IP, so this VPN is IPv6-only for now." \
         "  服务是起来了,但客户端拿不到 IPv4 虚拟 IP,这台 VPN 眼下只有 IPv6 能用。"
  warn_t "  This machine holds: $(ip -o -4 addr show scope global 2>/dev/null | awk '{print $4}' | tr '\n' ' ')" \
         "  本机占着:$(ip -o -4 addr show scope global 2>/dev/null | awk '{print $4}' | tr '\n' ' ')"
  warn_t "  Pick a range that does not collide in [tun].subnets of $ETC_DIR/config.toml, then systemctl restart nanotun" \
         "  改 $ETC_DIR/config.toml 的 [tun].subnets 换一段不冲突的,再 systemctl restart nanotun"
  STATUS_BAD=1
fi

if [ "$STATUS_BAD" = 1 ] || [ "$START_FAILED" = 1 ] || [ "${NANOTUN_VERBOSE:-0}" = 1 ]; then
  echo
  echo "--- systemctl status nanotun-tun-setup ---"
  systemctl --no-pager status nanotun-tun-setup.service | head -12 || true
  echo "--- systemctl status nanotun ---"
  systemctl --no-pager status nanotun.service | head -22 || true
  if [ "$WEB_AVAILABLE" -eq 1 ]; then
    echo "--- systemctl status nanotun-web ---"
    systemctl --no-pager status nanotun-web.service | head -18 || true
  fi
  echo "--- $(tsel 'listening ports' '监听端口') ---"
  # 端口清单从实际配置里拼。写死的话,改过端口(或 Web 随机)的机器上这条 grep 会什么都
  # 不显示,而「一个端口都没听上」恰恰是最容易被当成结论的假象 —— 服务其实好好地跑在
  # 别的端口上,而这段诊断正是给「装完像是坏了」的人看的。
  NT_DIAG_PORTS="${NT_PORT_REALITY}|${NT_PORT_HY2}|8080"
  [ "$WEB_AVAILABLE" -eq 1 ] && NT_DIAG_PORTS="${NT_DIAG_PORTS}|${NT_PORT_WEB}"
  ss -lntup 2>&1 | grep -E ":(${NT_DIAG_PORTS})" \
    || echo "$(tsel "(nothing is listening on ${NT_DIAG_PORTS//|/, })" "(${NT_DIAG_PORTS//|/、} 上没有任何监听)")"
  echo "--- journalctl -u nanotun -n 40 ---"
  journalctl -u nanotun.service --no-pager -n 40 || true
  # nanotun-web 的日志也要抓 —— 只抓 status 是不够的。
  #
  # 挂的是 web 时,status 那段只有一句 status=1/FAILURE,而**为什么**挂全在它自己的
  # 日志里(比如「cert dir … is half-populated」这种一句话就能照着修的)。少了这一段,
  # 屏幕上就成了:一个没有信息量的失败码,配上 40 行**健康的** nanotund 日志 —— 人会
  # 拿着那些正常日志反复找茬,而真正的原因一个字都没露面。实测一个 0 字节的 cert.pem
  # 就是这个下场:web 早就把话说清楚了,只是没人转达。
  if [ "$WEB_AVAILABLE" -eq 1 ]; then
    echo "--- journalctl -u nanotun-web -n 30 ---"
    journalctl -u nanotun-web.service --no-pager -n 30 || true
  fi
else
  printf '    \033[2m· %s\033[0m\n' "$(tsel \
    'For the full status and logs: rerun with NANOTUN_VERBOSE=1, or journalctl -u nanotun -n 50' \
    '详细状态与日志:NANOTUN_VERBOSE=1 重跑,或 journalctl -u nanotun -n 50')"
fi

echo
# 文件都装好了,但服务没起来 —— 这时候印「安装完成」是骗人的:用户会照着往下走去跑
# nanotun-setup,而向导第一步就要连控制面,只会得到一个更晚、更难懂的错误。
# 上面第 7 步已经把 status 和 journalctl 打出来了,这里只负责把结论说清楚。
if [ "$START_FAILED" = 1 ]; then
  # 同上:建议里的端口必须是这台机器实际要听的那几个。
  NT_FAIL_PORTS="${NT_PORT_REALITY}|${NT_PORT_HY2}"
  [ "$WEB_AVAILABLE" -eq 1 ] && NT_FAIL_PORTS="${NT_FAIL_PORTS}|${NT_PORT_WEB}"
  echo
  if [ "$NT_LANG" = zh ]; then
    printf '\033[1;31mFATAL: 文件已装好,但服务没能启动(诊断见上面第 7 步)。\033[0m\n' >&2
    printf '\n常见原因:\n' >&2
    printf '  · 配置有问题        nanotun-admin config lint %s/config.toml\n' "$ETC_DIR" >&2
    # 必须带 u:hysteria2 听的是 **UDP** 443,而端口冲突里它恰恰是最常撞的一个
    # (systemd-resolved、别的代理都爱占 UDP)。给一条 -lntp 的命令,人照着敲,
    # 屏幕上空空如也,于是把「端口被占」这条正确的线索排除掉了。
    printf '  · 端口被占          ss -lntup | grep -E ":(%s)"\n' "$NT_FAIL_PORTS" >&2
    printf '  · 环境不满足        nanotun-preflight\n' >&2
    printf '\n改完重跑本脚本即可(幂等,不会动已生效的配置和密钥)。\n' >&2
  else
    printf '\033[1;31mFATAL: the files are installed, but the service did not start (diagnostics in step 7 above).\033[0m\n' >&2
    printf '\nUsual causes:\n' >&2
    printf '  · a bad config       nanotun-admin config lint %s/config.toml\n' "$ETC_DIR" >&2
    printf '  · a port is taken    ss -lntup | grep -E ":(%s)"\n' "$NT_FAIL_PORTS" >&2
    printf '  · the machine falls short   nanotun-preflight\n' >&2
    printf '\nFix it and rerun this script (it is idempotent and does not touch config or keys already in effect).\n' >&2
  fi
  exit 1
fi

# 装完不等于能用:还差 server_dial_host、Web 管理员、用户的两个二维码,
# 而这三件事安装脚本都替不了人做决定。setup.sh 把它们串成一条交互流程。
#
# 但收尾该说哪句话,取决于两件本脚本自己不知道的事:
#
#   一、向导有没有人接着跑。install.sh 会在本脚本结束后立刻 exec 它(前提是有终端
#       可问话),而单独跑本脚本的人得自己去敲。之前不分情形一律催「还差最后一步:
#       sudo nanotun-setup」,然后向导当场自己启动了 —— 照着做的人会在向导跑完之后
#       又原样敲一遍。这个由 install.sh 置 NANOTUN_WIZARD_FOLLOWS 告知。
#
#   二、这是首次部署还是重装 / 升级。「还差最后一步,客户端才连得上」只对首次成立;
#       在一台早就配好、正常服务着的机器上重跑(升级二进制就是这么做的),这句话等于
#       通知人「你的部署没配完」,而它明明好好的。判据取 server_dial_host —— 它正是
#       向导第一步要解决的东西,也是客户端连得上的硬前提,比「库里有没有用户」更贴近
#       这句话想表达的意思。没设过时 stdout 为空(报错走 stderr),所以这么取是准的。
DIAL_SET="$(/usr/local/bin/nanotun-admin --db-path "$LIB_DIR/nanotun.db" \
  setting get server_dial_host 2>/dev/null | tail -1 | tr -d '[:space:]')" || DIAL_SET=""

if [ "${NANOTUN_WIZARD_FOLLOWS:-0}" = 1 ]; then
  # 向导接着就来,而且它结束时会把这些运维命令再列一遍。这里少说几句,
  # 好让上面第 5 步那段 admin PSK 尽量留在屏幕上。
  if [ -n "$DIAL_SET" ]; then
    ok_t "Installed. The setup wizard starts in a moment — values already configured are shown, and Enter keeps them." \
         "安装完成,开服向导马上开始 —— 已配好的值会显示出来,回车即保留。"
  else
    ok_t "Installed. The setup wizard starts in a moment — it sets the dial host, creates the first user and prints its QR codes." \
         "安装完成,开服向导马上开始 —— 设置拨号地址、建第一个用户、出二维码。"
  fi
elif [ -n "$DIAL_SET" ]; then
  ok_t "Installed. This machine was configured before (dial host $DIAL_SET); existing users and keys were left alone." \
       "安装完成。这台机器此前已配置过(拨号地址 $DIAL_SET),现有用户与密钥都没动。"
  echo
  echo "    $(tsel 'To add users / reissue QR codes / change the dial host:' '要加用户 / 重出二维码 / 改拨号地址:') sudo nanotun-setup"
  echo
elif [ "${SETUP_AVAILABLE:-0}" -eq 1 ]; then
  ok_t "Installed. **One step is still missing** before a client can connect:" \
       "安装完成。**还差最后一步**,客户端才连得上:"
  echo
  printf '        \033[1;36msudo nanotun-setup\033[0m\n'
  echo
  echo "    $(tsel \
    'It walks you through the client dial host, the web administrator, the first user and its QR codes.' \
    '它会带你设置客户端拨号地址、创建 Web 管理员、建第一个用户并出二维码。')"
  echo
else
  ok_t "Installed." "安装完成。"
fi

if [ "${NANOTUN_WIZARD_FOLLOWS:-0}" != 1 ]; then
  ok_t "Day-to-day commands:" "常用运维："
  echo "    journalctl -u nanotun -f                                       $(tsel '# live logs' '# 实时日志')"
  echo "    /usr/local/bin/nanotun-admin --db-path $LIB_DIR/nanotun.db user list"
  echo "    /usr/local/bin/nanotun-admin --db-path $LIB_DIR/nanotun.db device list"
  echo "    /usr/local/bin/nanotun-admin --db-path $LIB_DIR/nanotun.db lease list"
  echo "    /usr/local/bin/nanotun-admin --db-path $LIB_DIR/nanotun.db setting list"
  if [ "$WEB_AVAILABLE" -eq 1 ]; then
    echo
    echo "  $(tsel 'Web console (M2):' 'Web 管理后台(M2):')"
    echo "    journalctl -u nanotun-web -f"
    # 「/setup 对全网公开」只在这台机器**真的一个后台管理员都没有**时才成立。
    #
    # 这段原来是无条件打的,于是升级一台配好的机器时(而升级正是重跑本脚本的头号理由),
    # 屏幕上会通知你后台正敞着、要去补个管理员 —— 两件事都不成立:实测那台机器
    # /setup 回 302,web.env 里 NANOTUN_WEB_ALLOW_SETUP=0 早就钉上了。而这条假警报偏偏
    # 长得和真警报一模一样,见得多了,真敞着的那次也就跟着一起被略过去了。
    #
    # 判据与向导同一口径(scripts/setup.sh 的 setup_gate_closed / WEB_ADMIN_COUNT):
    # 有人 → 报个数并给登录地址;没人但门已关 → 谁也进不去,只能从 CLI 补;
    # 没人且门开着 → 才是原来那句话。
    WEB_ADMINS="$({ /usr/local/bin/nanotun-admin --db-path "$LIB_DIR/nanotun.db" \
      webadmin list 2>/dev/null || true; } | awk 'NR>1 && NF {n++} END {print n+0}')"
    if [ "${WEB_ADMINS:-0}" -gt 0 ]; then
      if [ "$NT_LANG" = zh ]; then
        echo "    已有 $WEB_ADMINS 个后台管理员,/setup 已关闭。登录: https://<server>:${NT_PORT_WEB}/"
        echo "    看都有谁: nanotun-admin --db-path $LIB_DIR/nanotun.db webadmin list"
      else
        echo "    There are $WEB_ADMINS console administrators, so /setup is closed. Log in at: https://<server>:${NT_PORT_WEB}/"
        echo "    To see who they are: nanotun-admin --db-path $LIB_DIR/nanotun.db webadmin list"
      fi
    elif grep -qE '^NANOTUN_WEB_ALLOW_SETUP=(0|false|no)[[:space:]]*$' "$ETC_DIR/web.env" 2>/dev/null; then
      if [ "$NT_LANG" = zh ]; then
        echo "    这台机器的 /setup 已关闭,而一个后台管理员都没有 —— 网页那条路进不去,只能:"
        echo "    nanotun-admin --db-path $LIB_DIR/nanotun.db webadmin create <名字>"
      else
        echo "    /setup is closed on this machine and there is no console administrator at all —"
        echo "    the browser route is shut, so the only way in is:"
        echo "    nanotun-admin --db-path $LIB_DIR/nanotun.db webadmin create <name>"
      fi
    else
      if [ "$NT_LANG" = zh ]; then
        echo "    建后台账号: nanotun-admin --db-path $LIB_DIR/nanotun.db webadmin create <名字>"
        echo "    (开服向导 nanotun-setup 会问这一步;在建好之前 https://<server>:${NT_PORT_WEB}/setup"
        echo "     对全网公开 —— 谁先打开谁就是管理员)"
      else
        echo "    Create a console account: nanotun-admin --db-path $LIB_DIR/nanotun.db webadmin create <name>"
        echo "    (the setup wizard nanotun-setup asks for this; until one exists,"
        echo "     https://<server>:${NT_PORT_WEB}/setup is open to the whole internet — whoever opens it"
        echo "     first becomes the administrator)"
      fi
    fi
    echo "    $(tsel 'Certificates:' '证书:') $ETC_DIR/certs/{cert.pem,key.pem}$(tsel ' (can be installed into a trust store as a root CA)' '(可作为 root CA 装入信任库)')"
  fi
  echo
  # 卸载放在这里说一次。它此前唯一的出处是 README 里的 `sudo ./scripts/uninstall.sh`,
  # 而一键安装的人当前目录并没有 scripts/ —— 想卸载得先知道自己装的是哪个版本、什么架构,
  # 才拼得出 /opt/nanotun/<版本>-<架构>/scripts/uninstall.sh。现在它装成了命令。
  if [ "$NT_LANG" = zh ]; then
    echo "  卸载:"
    echo "    sudo nanotun-uninstall --dry-run   # 先看会动哪些文件"
    echo "    sudo nanotun-uninstall             # 停服务、删程序,保留配置与数据库"
  else
    echo "  Uninstall:"
    echo "    sudo nanotun-uninstall --dry-run   # show which files would be touched"
    echo "    sudo nanotun-uninstall             # stop services, remove programs, keep config + database"
  fi
fi
