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
#      /etc/nanotun/{config.toml, certs/, masquerade/}（证书由 ensure-server-assets.sh 按需自签）
#      /var/lib/nanotun/                        （SQLite home）
#      /etc/systemd/system/{nanotun-tun-setup,nanotun}.service
#      config.toml 已存在则**原样保留**（模板另存 config.toml.dist 供 diff）；模板里的
#      REPLACE_WITH_* 占位与示例 short_ids 由 fill_config_secrets 就地换成本机随机值，
#      否则 [reality].private_key 非法会让 nanotund 起不来（exit 31）。权限 0600。
#      MagicDNS 后缀（客户端解析 *.<后缀> → mesh vIP）默认模板里的 "lan"，可用
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

# nanotun-admin 默认输出英文,而本脚本从头到尾是中文。第 5 步 init 那两句问话
# (admin username / admin PSK)会直接夹在中文安装过程里,还紧挨着最重要的凭据输出。
# 自己显式设过 NANOTUN_LANG 的按你的来。
#
# 对本脚本的解析没有影响:init 走 --json(键名与语言无关),count_real_users 读的
# user list 表格两种语言下逐字一致 —— K1 守卫靠 $3=="no" 数人,已实测两边相同。
export NANOTUN_LANG="${NANOTUN_LANG:-zh}"

step() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[1;32m✓\033[0m %s\n' "$*"; }
warn() { printf '    \033[1;33m!\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mFATAL: %s\033[0m\n' "$*" >&2; exit 1; }

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
  command -v openssl >/dev/null 2>&1 || die "缺 openssl,无法生成 REALITY / hy2 密钥"

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
    die "config.toml 仍有未填占位(见上),nanotund 会启动失败;补齐后重跑本脚本"
  fi

  if [ "$filled" = 1 ]; then
    ok "已为本机生成 REALITY 私钥 / hy2 密码 / obfs 密码 / WS path token / short_ids"
  else
    ok "config.toml 无待填占位,密钥原样保留"
  fi
}

# 按 NANOTUN_MAGIC_SUFFIX 定制 MagicDNS 的 domain_suffix(客户端解析 *.<后缀> → mesh vIP)。
#
# 为什么在装机脚本里做:运行期后缀**只**取 config.toml 的 [server.magic_dns].domain_suffix
# (magicDNSSuffixForClient / resolveMagicDNSConfig 都读它),且它不在 SIGHUP 热更新白名单里
# (见 set-magic-suffix.sh 抬头),须在服务启动前定好 —— 而这里正是唯一会写 config.toml 的地方。
# 模板默认写死 "lan";不给 NANOTUN_MAGIC_SUFFIX 就沿用模板,行为不变。
#
# 只在**这次真写了模板 config.toml**(CONFIG_FRESH=1:全新装 / NANOTUN_FORCE_CONFIG=1)时改。
# 保留既有配置时绝不擅自改它(与「绝不覆盖已有配置」同一口径),只告警并指路 set-magic-suffix.sh。
# 校验与段感知改写与 set-magic-suffix.sh 同一套(规则单一来源:那边改这边也要跟)。
apply_magic_suffix() {
  local suf="${NANOTUN_MAGIC_SUFFIX:-}"
  [ -n "$suf" ] || return 0   # 没给:用模板默认后缀,不动 config.toml

  # 合法性:小写 DNS 标签(字母数字 + 连字符,可点分多级)。既防命令注入,也防写坏 TOML。
  if ! printf '%s' "$suf" | grep -Eq '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$'; then
    die "NANOTUN_MAGIC_SUFFIX 不合法(只允许小写字母/数字/连字符,可点分多级):'$suf'"
  fi
  case "$suf" in
    local) die "NANOTUN_MAGIC_SUFFIX 不能用 'local' —— 与 mDNS/Bonjour(mac/iOS)严重冲突。" ;;
    lan|home|home.arpa|internal|corp)
      warn "MagicDNS 后缀 '$suf' 可能与家用路由器 / 保留域冲突(想避开这类冲突正是换后缀的理由)。" ;;
  esac

  # 保留了既有 config.toml 就不改它 —— 那是升级路径,擅自改后缀会踢乱已在用的 mesh 名字。
  if [ "${CONFIG_FRESH:-0}" != 1 ]; then
    warn "已保留既有 config.toml,未套用 NANOTUN_MAGIC_SUFFIX='$suf'。要改现有后缀:"
    warn "  scripts/set-magic-suffix.sh $suf   （备份→段感知改写→重启→失败自动回滚）"
    return 0
  fi

  local cfg="$ETC_DIR/config.toml" cur
  # 空白写 [ \t] 不用 [[:space:]]:mawk 1.3.3(老 Ubuntu/Debian 默认 awk)不认 POSIX 字符类。
  cur="$(awk -F'"' '/^[ \t]*domain_suffix[ \t]*=/{print $2; exit}' "$cfg" || true)"
  if [ "$cur" = "$suf" ]; then
    ok "MagicDNS 后缀已是 '$suf'"
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
  ' "$cfg" > "$cfg.new" && mv "$cfg.new" "$cfg" || { rm -f "$cfg.new"; die "写 MagicDNS 后缀失败(config.toml 未改动)"; }
  chmod 0600 "$cfg"
  ok "MagicDNS 后缀设为 '$suf'(客户端解析 *.$suf → mesh 虚拟 IP;默认原为 'lan')"
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
  ok "环境自检已由引导脚本完成,跳过"
elif [ -f "$SCRIPTS_DIR/preflight.sh" ]; then
  # --for-install:本脚本下一步就动 /usr/local/bin,非 root 必须当场拦下。
  # (不传的话 preflight 只会把非 root 记成一条提醒 —— 那是给「单独跑来问问
  # 机器行不行」准备的口径,不适用于这里。)
  bash "$SCRIPTS_DIR/preflight.sh" --offline --for-install \
    || die "环境检查没过(见上面的修复清单),已中止安装。"
else
  # 老发布包里没有 preflight.sh。不能因此放行 —— 缺 systemd / TUN 装下去必炸,
  # 所以退回到最小一组硬检查,报错简短但至少能拦住。
  warn "发布包里没有 preflight.sh,退回最小检查"
  [ "$(id -u)" = 0 ]        || die "需要 root,请用 sudo 跑"
  [ -d /run/systemd/system ] || die "没有正在运行的 systemd,裸机安装用不了,请改走 Docker"
  [ -c /dev/net/tun ]        || die "/dev/net/tun 不存在,先 modprobe tun"
  for c in iptables ip6tables ip openssl sysctl; do
    command -v "$c" >/dev/null 2>&1 || die "缺少命令 $c"
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
         "$SCRIPTS_DIR/ensure-server-assets.sh"; do
  [ -e "$f" ] || die "缺文件: $f"
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
      warn "本机架构 $(uname -m) 不在检查表内,跳过架构自检"
      return 0 ;;
  esac

  command -v od >/dev/null 2>&1 || { warn "缺 od,跳过架构自检"; return 0; }

  for bin in nanotund nanotun-admin nanotun-web; do
    [ -f "$DEPLOY_DIR/$bin" ] || continue
    got="$(od -An -tx1 -j18 -N2 "$DEPLOY_DIR/$bin" | tr -d ' \n')"
    if [ "$got" != "$host_machine" ]; then
      case "$got" in
        3e00) want="amd64" ;;
        b700) want="arm64" ;;
        *)    want="未知(e_machine=$got)" ;;
      esac
      printf '\033[1;31mFATAL: 发布包架构不匹配\033[0m\n' >&2
      printf '  本机: %s (%s)\n' "$(uname -m)" "$desc" >&2
      printf '  包里的 %s: %s\n' "$bin" "$want" >&2
      printf '\n请下载 linux-%s 那一份:\n' "$desc" >&2
      printf '  https://github.com/nanotun/server/releases/latest\n' >&2
      printf '  nanotun-vX.Y.Z-linux-%s.tar.gz\n' "$desc" >&2
      exit 1
    fi
  done
  ok "架构自检通过:发布包与本机同为 $desc"
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
    die "另一个 nanotun 安装 / 升级正在进行(锁:$LOCK_FILE)。
   等它跑完再重试。确认没有别的安装在跑却仍报这句的话,是上次被强杀留下的:
     fuser -k $LOCK_FILE   # 或直接重启这台机器"
  fi
fi

step "1. 安装二进制 / 脚本 / 证书 / 配置 / systemd 单元"
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
# 开服向导装成 nanotun-setup:它是要反复用的(加用户、重出二维码、改拨号地址),
# 而解压出来的发布包目录用完多半就删了,只留在包里等于用一次就丢。
# 老发布包没有这个文件,缺了不 fatal。
if [ -f "$SCRIPTS_DIR/setup.sh" ]; then
  install -m 0755 "$SCRIPTS_DIR/setup.sh" /usr/local/bin/nanotun-setup
  SETUP_AVAILABLE=1
else
  SETUP_AVAILABLE=0
fi
# 环境检查也装成命令:排查「服务起不来」时第一件该做的事就是重跑它,
# 而那时候解压出来的发布包目录通常已经不在了。
[ -f "$SCRIPTS_DIR/preflight.sh" ] && \
  install -m 0755 "$SCRIPTS_DIR/preflight.sh" /usr/local/bin/nanotun-preflight

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
  ok "保留已有 config.toml(发布包模板另存 config.toml.dist,可 diff 新增字段)"
  CONFIG_FRESH=0
else
  if [ -f "$ETC_DIR/config.toml" ]; then
    CFG_BAK="$ETC_DIR/config.toml.bak.$(date +%Y%m%d-%H%M%S)"
    cp -f "$ETC_DIR/config.toml" "$CFG_BAK"
    chmod 0600 "$CFG_BAK"
    warn "NANOTUN_FORCE_CONFIG=1:已用模板覆盖 config.toml(原文件 → $CFG_BAK)"
  fi
  install -m 0600 "$EXTRAS_DIR/config.toml" "$ETC_DIR/config.toml"
  CONFIG_FRESH=1
fi
chmod 0600 "$ETC_DIR/config.toml"
# 顺带收紧历史遗留的 0644 备份:里面同样有 hy2 密码 / REALITY 私钥。
chmod 0600 "$ETC_DIR"/config.toml.bak.* 2>/dev/null || true

# 占位密钥填充。必须在 ensure-server-assets.sh / systemctl start 之前完成。
fill_config_secrets
# MagicDNS 后缀:装机时可经 NANOTUN_MAGIC_SUFFIX 定制(默认沿用模板里的 "lan")。同样须在
# systemctl start 之前 —— 它在 nanotund 启动时被读进 magicDNSResolved 快照,起来后改要重启。
apply_magic_suffix

# 证书 / masquerade 页：按 config.toml 里配置的路径**按需自签**(不随包分发)。
# ensure-server-assets.sh 读 [server] / [hysteria] 的 tls_* 与 masquerade_dir,
# 只在文件缺失时生成,幂等;WorkingDirectory 传 $ETC_DIR,相对路径落到 $ETC_DIR/certs 等。
install -m 0755 "$SCRIPTS_DIR/ensure-server-assets.sh" /usr/local/bin/nanotun-ensure-assets.sh
# 它会逐条播报自己生成了什么(自签证书 / 开发 CA / 占位页),四行裸日志夹在本脚本的 ✓
# 中间,前缀和标点都是另一套。正常装完这一步的结论由下面那句 ✓ 概括就够了 —— 首次
# 安装本来就该生成这些。出错时才把它说过的话原样倒出来,那时每一行都是线索。
ASSETS_LOG="$(mktemp)" \
  || die "创建临时文件失败 —— ${TMPDIR:-/tmp} 写不进去(权限 / 只读 / 空间不足)。可以 TMPDIR=/var/tmp 重跑。"
if bash "$SCRIPTS_DIR/ensure-server-assets.sh" "$ETC_DIR" >"$ASSETS_LOG" 2>&1; then
  [ "${NANOTUN_VERBOSE:-0}" = 1 ] && sed 's/^/    /' "$ASSETS_LOG"
else
  cat "$ASSETS_LOG" >&2; rm -f "$ASSETS_LOG"
  die "生成证书 / masquerade 资产失败(上面是它的原始输出)"
fi
rm -f "$ASSETS_LOG"

install -m 0644 "$SCRIPTS_DIR/tun-setup.service" /etc/systemd/system/nanotun-tun-setup.service
install -m 0644 "$EXTRAS_DIR/nanotun.service"  /etc/systemd/system/nanotun.service
systemctl daemon-reload
ok "二进制 / 配置 / 证书 / systemd 单元已就位"

step "2. 开启 IP forwarding + unprivileged ICMP ping"
# /etc/sysctl.d 不是哪里都有:Rocky 9 的 minimal 镜像(以及最小化安装的 RHEL 系)
# 只带 /usr/lib/sysctl.d,/etc/sysctl.d 要管理员自己建。少这一句的后果是安装在第 2 步
# 当场炸在一行裸的 `No such file or directory` 上 —— 前一步刚把二进制和 systemd 单元
# 都写下去了,机器停在装了一半的状态,而屏幕上没有任何能照着做的话。
# 两边 sysctl --system 都读,建出来就行。
mkdir -p /etc/sysctl.d
cat > /etc/sysctl.d/99-nanotun.conf <<'SYSCTL'
# nanotun 自托管 VPN 网关：转发数据包给客户端访问公网 / 互访
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv6.conf.all.forwarding = 1
# nanotun-web 在保存 server_dial_host 时跑 unprivileged ICMP ping(pro-bing)
# 做可达性检测。Linux 默认 ping_group_range=0 0,非 root 无法创建 ping socket →
# pro-bing 初始化失败 → admin 被迫永远勾「跳过 ICMP 可达性检测」绕过。
# 放开为全范围让任意 group 都能跑 unprivileged ping。
net.ipv4.ping_group_range = 0 2147483647
SYSCTL
sysctl --system >/dev/null
ok "ip_forward = $(sysctl -n net.ipv4.ip_forward), v6.forwarding = $(sysctl -n net.ipv6.conf.all.forwarding), ping_group_range = '$(sysctl -n net.ipv4.ping_group_range 2>/dev/null || echo 'n/a')'"

step "3. 防火墙：放行 nanotun 监听端口（ufw / firewalld active 时）"
# ufw 默认 INPUT DROP（Ubuntu 全新系统常见配置），不放行端口客户端会全部被静默丢包，
# 表现为「TCP 三次握手超时」「QUIC 重传无响应」。这里检测 ufw 状态后幂等放行。
# 如果你用的是 firewalld / iptables / 云厂商安全组，请按各自方式自行放行：
#   tcp 8443 (REALITY)  udp 443 (hy2 QUIC)
# 数据面 WS(:8080)默认绑 127.0.0.1、不放行:客户端经 hy2/REALITY 接入,服务端在本机
# 桥接到它。若你把 [server].listen_addr 改回 ":8080" 想让客户端直连,请自行 `ufw allow 8080/tcp`。
# 2026-07-17:hy2 独立 WSS 保活(:8444)已下线,不再放行,并清理历史规则。
# 2026-07-20:数据面 WS(:8080)改绑回环,从放行清单移除,并回收历史 8080/tcp 规则。
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
  WEB_PORTS=()
  # nanotun-web 监听 7443/tcp(见 nanotun-web.service),装了才放行;否则保持 LAN/隧道内可达。
  [ "$WEB_AVAILABLE" -eq 1 ] && WEB_PORTS+=("7443/tcp")
  for rule in "8443/tcp" "443/udp" "${WEB_PORTS[@]}"; do
    ufw allow "$rule" >/dev/null
  done
  ufw delete allow "8444/tcp" >/dev/null 2>&1 || true
  # 历史部署曾放行 8080/tcp(当时数据面 WS 绑 0.0.0.0);现在绑回环,回收这条规则。
  ufw delete allow "8080/tcp" >/dev/null 2>&1 || true
  if [ "$WEB_AVAILABLE" -eq 1 ]; then
    ok "ufw 放行：8443/tcp 443/udp 7443/tcp(web)"
  else
    ok "ufw 放行：8443/tcp 443/udp"
  fi
elif command -v firewall-cmd >/dev/null 2>&1 && [ "$(firewall-cmd --state 2>/dev/null)" = running ]; then
  # RHEL 系(Rocky / Alma / CentOS / Fedora)默认跑的是 firewalld,而它的默认 zone 同样
  # 拒绝入站。原来这里只认 ufw,其余一律 warn 一句「请手动放行」—— 于是 Rocky 用户装完
  # 满屏绿灯,客户端却连不上,而症状(TCP 握手超时 / QUIC 无响应)跟防火墙看不出关系,
  # 那句 warn 早被后面几十行刷走了。既然对 ufw 是自动放行的,没有理由只对它。
  FW_PORTS=(8443/tcp 443/udp)
  [ "$WEB_AVAILABLE" -eq 1 ] && FW_PORTS+=(7443/tcp)
  FW_BAD=0
  for rule in "${FW_PORTS[@]}"; do
    firewall-cmd --permanent --add-port="$rule" >/dev/null 2>&1 || FW_BAD=1
  done
  # 与 ufw 分支同口径:回收历史上放行过、现在不再需要的端口。
  firewall-cmd --permanent --remove-port=8444/tcp >/dev/null 2>&1 || true
  firewall-cmd --permanent --remove-port=8080/tcp >/dev/null 2>&1 || true
  firewall-cmd --reload >/dev/null 2>&1 || FW_BAD=1
  if [ "$FW_BAD" -eq 0 ]; then
    ok "firewalld 放行：${FW_PORTS[*]}"
  else
    # 放行失败不该 die:服务本身能跑,只是外面进不来,而这在云上还可能被安全组兜着。
    # 但必须把那条命令原样给出来,不能只说「请自行放行」。
    warn "firewalld 在跑,但自动放行没成功。请手动执行:"
    warn "  firewall-cmd --permanent$(printf -- ' --add-port=%s' "${FW_PORTS[@]}") && firewall-cmd --reload"
  fi
else
  warn "未检测到 ufw / firewalld active；如使用其他防火墙，请手动放行 8443/tcp 与 443/udp（装了 web 再加 7443/tcp）"
fi

step "4. 旧 DB 路径迁移自检（K1：2026-05-21 事故防再发）"
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
      ok "已从旧路径导入 DB:${LEGACY_DB} → ${LIB_DIR}/nanotun.db(新路径原有的库已备份 → ${BAK})"
    else
      ok "已从旧路径导入 DB:${LEGACY_DB} → ${LIB_DIR}/nanotun.db(新路径原本没有库,无需备份)"
    fi
    # 导入是 copy 不是 move。这句不是客套:上面那条没有备份的路径里,旧库就是唯一的回滚点。
    ok "旧库原样留在 ${LEGACY_DB}(未删除);确认新库无误后再手动归档"
    ok "Batch J 二进制启动时会自动跑 store.Migrate 应用新 migration"
  else
    SELF_PATH="$(realpath "$0" 2>/dev/null || echo "$0")"
    printf >&2 '\n\033[1;31mFATAL: 旧 DB 路径 %s 检出 %d 个终端用户,\n新路径 %s/nanotun.db 没有,直接装会让所有终端登录失败「用户不存在」(2026-05-21 事故场景)。\033[0m\n\n' \
      "$LEGACY_DB" "$LEGACY_USERS" "$LIB_DIR"
    printf >&2 '请二选一明确处理:\n  1) 导入旧数据(保留 PSK / device UUID / lease):\n       systemctl stop nanotun.service 2>/dev/null || true\n       NANOTUN_IMPORT_LEGACY_DB=1 bash %s\n  2) 确认旧数据已无用,归档后再装:\n       mv %s %s.archived.$(date +%%Y%%m%%d-%%H%%M%%S)\n       bash %s\n\n' \
      "$SELF_PATH" "$LEGACY_DB" "$LEGACY_DB" "$SELF_PATH"
    die "拒绝在「旧 DB 仍有用户、新 DB 空」状态下完成安装"
  fi
else
  if [ "$LEGACY_USERS" -gt 0 ] && [ "$NEW_USERS" -gt 0 ]; then
    warn "旧 DB $LEGACY_DB 仍有 $LEGACY_USERS 个终端用户,但新 DB 已有 $NEW_USERS 个 — 不会自动覆盖。"
    warn "确认无用后请手动 mv 归档:mv $LEGACY_DB $LEGACY_DB.archived.\$(date +%Y%m%d-%H%M%S)"
  else
    ok "没有需要迁移的历史 DB"
  fi
fi

step "5. 初始化 admin 用户（首次部署生成 PSK；重复部署 noop 保留现有 PSK）"
# init 默认幂等：setup_completed=1 时再跑只输出 admin 元信息（{"noop":true}），不改 PSK。
# 想强制重置请手动 `nanotun-admin --json init --reset-psk`，不要让脚本自动做。
# 输出要洗两遍,不能 2>&1 一把抓:
#   · nanotun-admin 的启动日志走 stderr。混进来之后 init.out.txt 既不是干净文本、
#     也不是能解析的 JSON —— 而它是这个管理员 PSK 的唯一留档。
#   · init 会问用户名和 PSK 两个问题(两个空行 = 都取默认值),提示语走 stdout,
#     会贴在 JSON 前面变成「admin username [admin]: {」,所以从第一个 { 起截断。
INIT_ERR="$(mktemp)" || INIT_ERR=""
[ -n "$INIT_ERR" ] || die "创建临时文件失败 —— ${TMPDIR:-/tmp} 写不进去(权限 / 只读 / 配额 / 空间不足)。"
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
  die "nanotun-admin init 失败(退出码 ${INIT_RC})—— 原因见上面几行 init 的原始输出。
   库里没有管理员,这台机器装完也管不了,先按上面的提示解决再重跑本脚本。"
fi
rm -f "$INIT_ERR"

if printf '%s' "$INIT_JSON" | grep -q '"noop"[[:space:]]*:[[:space:]]*true'; then
  ok "已 setup，init 跳过（不重置 PSK）"
else
  INIT_FILE="$DEPLOY_DIR/init.out.txt"
  printf '%s\n' "$INIT_JSON" > "$INIT_FILE"
  chmod 600 "$INIT_FILE"
  ok "首次 init,已创建管理员账号"
  # 摆出来,别让人从 JSON 里自己捞。这是整个安装过程产出的最重要的一样东西。
  echo
  printf '        用户名  %s\n' "$(printf '%s' "$INIT_JSON" | sed -n 's/.*"username"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
  printf '        PSK     %s\n' "$(printf '%s' "$INIT_JSON" | sed -n 's/.*"psk"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
  echo
  warn "这是 admin 这个 VPN 账号的凭据(跟 Web 后台管理员是两回事),现在就抄走。"
  warn "另存了一份在 ${INIT_FILE}(0600)—— 那是发布包解压目录,别顺手删了。"
fi

step "6. 启动并设为开机自启"
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
  [ "$START_FAILED" = 0 ] && ok "nanotun.service 已启动并设为开机自启"
else
  START_FAILED=1
fi

if [ "$WEB_AVAILABLE" -eq 1 ]; then
  step "6b. 安装 nanotun-web(Web 管理后台,M2)"
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
      ok "nanotun-web 已启动,后台账号在下一步的开服向导里设(也可 nanotun-admin webadmin create)"
  else
    START_FAILED=1
    warn "nanotun-web 没能启动(原因见下面第 7 步的诊断)"
  fi
fi

step "7. 状态自检"

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
LISTEN_TCP="$(ss -lnt 2>/dev/null | awk 'NR>1{print $4}')"
LISTEN_UDP="$(ss -lnu 2>/dev/null | awk 'NR>1{print $4}')"
PORTS_UP=(); PORTS_DOWN=()
check_port() { # <tcp|udp> <端口> <标签>
  local pool; [ "$1" = tcp ] && pool="$LISTEN_TCP" || pool="$LISTEN_UDP"
  if printf '%s\n' "$pool" | grep -qE ":$2\$"; then PORTS_UP+=("$3"); else PORTS_DOWN+=("$3"); STATUS_BAD=1; fi
}
check_port tcp 8443 "8443/tcp(REALITY)"
check_port udp 443  "443/udp(hy2)"
[ "$WEB_AVAILABLE" -eq 1 ] && check_port tcp 7443 "7443/tcp(Web)"
[ ${#PORTS_UP[@]}   -gt 0 ] && ok   "监听中:${PORTS_UP[*]}"
[ ${#PORTS_DOWN[@]} -gt 0 ] && warn "没听上:${PORTS_DOWN[*]}"

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
  warn "$TUN_DEV 没有 IPv4 地址 —— [tun].subnets 里的候选网段与本机网段全部冲突,已跳过 IPv4。"
  warn "  服务是起来了,但客户端拿不到 IPv4 虚拟 IP,这台 VPN 眼下只有 IPv6 能用。"
  warn "  本机占着:$(ip -o -4 addr show scope global 2>/dev/null | awk '{print $4}' | tr '\n' ' ')"
  warn "  改 $ETC_DIR/config.toml 的 [tun].subnets 换一段不冲突的,再 systemctl restart nanotun"
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
  echo "--- 监听端口 ---"
  ss -lntup 2>&1 | grep -E ":(443|7443|8080|8443)" || echo "(443/7443/8080/8443 上没有任何监听)"
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
  printf '    \033[2m· 详细状态与日志:NANOTUN_VERBOSE=1 重跑,或 journalctl -u nanotun -n 50\033[0m\n'
fi

echo
# 文件都装好了,但服务没起来 —— 这时候印「安装完成」是骗人的:用户会照着往下走去跑
# nanotun-setup,而向导第一步就要连控制面,只会得到一个更晚、更难懂的错误。
# 上面第 7 步已经把 status 和 journalctl 打出来了,这里只负责把结论说清楚。
if [ "$START_FAILED" = 1 ]; then
  echo
  printf '\033[1;31mFATAL: 文件已装好,但服务没能启动(诊断见上面第 7 步)。\033[0m\n' >&2
  printf '\n常见原因:\n' >&2
  printf '  · 配置有问题        nanotun-admin config lint %s/config.toml\n' "$ETC_DIR" >&2
  # 必须带 u:hysteria2 听的是 **UDP** 443,而端口冲突里它恰恰是最常撞的一个
  # (systemd-resolved、别的代理都爱占 UDP)。给一条 -lntp 的命令,人照着敲,
  # 屏幕上空空如也,于是把「端口被占」这条正确的线索排除掉了。
  printf '  · 端口被占          ss -lntup | grep -E ":(443|7443|8443)"\n' >&2
  printf '  · 环境不满足        nanotun-preflight\n' >&2
  printf '\n改完重跑本脚本即可(幂等,不会动已生效的配置和密钥)。\n' >&2
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
    ok "安装完成,开服向导马上开始 —— 已配好的值会显示出来,回车即保留。"
  else
    ok "安装完成,开服向导马上开始 —— 设置拨号地址、建第一个用户、出二维码。"
  fi
elif [ -n "$DIAL_SET" ]; then
  ok "安装完成。这台机器此前已配置过(拨号地址 $DIAL_SET),现有用户与密钥都没动。"
  echo
  echo "    要加用户 / 重出二维码 / 改拨号地址:sudo nanotun-setup"
  echo
elif [ "${SETUP_AVAILABLE:-0}" -eq 1 ]; then
  ok "安装完成。**还差最后一步**,客户端才连得上:"
  echo
  printf '        \033[1;36msudo nanotun-setup\033[0m\n'
  echo
  echo "    它会带你设置客户端拨号地址、创建 Web 管理员、建第一个用户并出二维码。"
  echo
else
  ok "安装完成。"
fi

if [ "${NANOTUN_WIZARD_FOLLOWS:-0}" != 1 ]; then
  ok "常用运维："
  echo "    journalctl -u nanotun -f                                       # 实时日志"
  echo "    /usr/local/bin/nanotun-admin --db-path $LIB_DIR/nanotun.db user list"
  echo "    /usr/local/bin/nanotun-admin --db-path $LIB_DIR/nanotun.db device list"
  echo "    /usr/local/bin/nanotun-admin --db-path $LIB_DIR/nanotun.db lease list"
  echo "    /usr/local/bin/nanotun-admin --db-path $LIB_DIR/nanotun.db setting list"
  if [ "$WEB_AVAILABLE" -eq 1 ]; then
    echo
    echo "  Web 管理后台(M2):"
    echo "    journalctl -u nanotun-web -f"
    echo "    建后台账号: nanotun-admin --db-path $LIB_DIR/nanotun.db webadmin create <名字>"
    echo "    (开服向导 nanotun-setup 会问这一步;在建好之前 https://<server>:7443/setup"
    echo "     对全网公开 —— 谁先打开谁就是管理员)"
    echo "    证书: $ETC_DIR/certs/{cert.pem,key.pem}(可作为 root CA 装入信任库)"
  fi
fi
