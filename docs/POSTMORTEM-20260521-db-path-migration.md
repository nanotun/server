# 事故复盘:2026-05-21 DB 路径漂移导致 iOS/macOS 客户端登录全失败

**严重级别**:P1(单节点用户全断)
**节点**:203.0.113.10
**MTTD**:约 11 小时
**MTTR**(开始诊断 → 用户感知恢复):≈ 90 分钟
**最终修复**:服务端老库迁移到新库 + 客户端 toggle VPN
**根因**:install-self-hosted.sh 把 SQLite home 从 `/root/nanotun/data/`
切到 `/var/lib/nanotun/`,但**没有迁移旧库**,新库只有自动 init 的 admin,
所有终端登录返回 403「用户不存在」。

## 时间线(UTC,主要节点)

| 时刻 | 事件 |
|------|------|
| 05-21 ~16:02 | 自托管 install-self-hosted.sh 部署完成,nanotun.service 起在新 DB(/var/lib/nanotun/nanotun.db,只有 admin)。原 vpn-server.service 仍跑在旧路径 /root/nanotun + 旧 DB。 |
| 05-21 ~17:00 | 旧 vpn-server.service 在某次 SIGTERM 测试后落入 inactive(dead),Restart=on-failure + 干净 exit 0 → systemd 不拉起。8080 端口被新 nanotun.service(PID 150620)持有。 |
| 05-21 全程 | iOS / macOS 客户端开始连接到 8080(其实是新 nanotun.service),登录返回 code=403,raw_msg=用户不存在;客户端层堆栈表现为「NECP policy denied」「No route to host」「TLS: No route to host」—— **症状误导**。 |
| 05-22 ~03:00 | 用户反馈连不上 + 拉日志。最初怀疑客户端 VpnTunnelManager.swift 里 proto.serverAddress = "Nanotun" 占位串(后排除)。 |
| 05-22 ~03:30 | 用户反驳「优化 nanotun 之前是能连的」,聚焦点切到服务端。 |
| 05-22 ~04:00 | journalctl -u nanotun 发现连续 "登录验证失败 code=403 raw_msg=用户不存在",尝试系统级排查。 |
| 05-22 ~04:15 | 发现并存的两个 unit:vpn-server.service(legacy,inactive)和 nanotun.service(active)。 |
| 05-22 ~04:25 | 对比两个 DB 用户表:旧库 /root/nanotun/data/nanotun.db 含 smoker + Snoopy 设备,新库 /var/lib/nanotun/nanotun.db 只有 admin。 |
| 05-22 ~04:30 | 停 nanotun.service,新 DB 备份后旧 DB 整文件 cp 过去,重启服务。 |
| 05-22 ~04:35 | 服务端日志干净;客户端仍卡住,提示用户手动 toggle VPN。 |
| 05-22 ~04:40 | 用户确认已连通,事故关闭。 |

## 根因分析(5 Whys)

1. **为什么 iOS/macOS 客户端连不上?**
   登录返回 403「用户不存在」,client EOF after login → NEPacketTunnelProvider
   读不到 TUN 配置 → 内核 NECP 给 default route 走默认网卡,直连 VPN server 的
   流量被 includeAllNetworks=true 的 tunnel disallowed → No route to host。
2. **为什么登录返回 403「用户不存在」?**
   服务端按 LoginReq.Name 在 SQLite users 表里查不到。
3. **为什么 users 表查不到?**
   nanotun.service 启动时打开的是 `/var/lib/nanotun/nanotun.db`,这库是
   install-self-hosted.sh 第 4 步`nanotun-admin init` 新建的,只有 admin。
   smoker 用户实际在 `/root/nanotun/data/nanotun.db`(老路径)。
4. **为什么没有迁过去?**
   install-self-hosted.sh 部署时只新建 `$LIB_DIR/nanotun.db`,**完全没有**
   检测 / 提示 / 导入旧路径数据。运维当时也不知道老 DB 存在。
5. **为什么之前没暴露?**
   8080 端口被新 nanotun.service 抢到(老 vpn-server.service 先停了),所有
   iOS 客户端只能连到新服务。两套服务的 DB 路径不同 + 不互通,新服务的
   PSK 模式登录直接落库到新 DB 查 —— 但库是空的,所以**没有任何客户端能登录**。

## 直接修复(已落地,事故当晚)

1. 停 nanotun.service。
2. `mv /var/lib/nanotun/nanotun.db /var/lib/nanotun/nanotun.db.preimport.<ts>`(空库备份)。
3. `cp -a /root/nanotun/data/nanotun.db /var/lib/nanotun/nanotun.db`。
4. 启 nanotun.service。
5. 用户 toggle VPN 触发新连接。

## 二次防御(2026-05-22 落地,本批 P0)

### K1 — install-self-hosted.sh 部署期防呆
- 安装第 4 步新增「旧 DB 路径迁移自检」:若新 DB 没有非 admin 用户、旧路径
  `/root/nanotun/data/nanotun.db` 检出 > 0 终端用户 → **默认 die**。
- 运维必须二选一:`NANOTUN_IMPORT_LEGACY_DB=1` 显式导入,或
  `mv $LEGACY_DB $LEGACY_DB.archived.<ts>` 归档后重跑。
- 已有终端用户(NEW_USERS>0)时永远跳过该检查,二次部署安全。

### K2 — 服务端登录失败审计 + 速率告警
- 新增 `auditActionForLoginCode(code)`:把每个 backend.Code* 映射成独立
  audit action(`login.fail.user_not_found` / `.bad_psk` / `.user_disabled` / ...
  共 10 类)。`nanotun-admin audit list --action login.fail.user_not_found` 可
  直接定位 「整库被清空 / DB 路径漂移 / 用户被误删」类问题。
- 新增 `noteLoginUserNotFound`:60s 窗口聚合;窗口内累计 ≥ 12 次 user_not_found
  → 跨窗口结算时打 ERROR 总结,带 count / window / 排查 hint。
- log shipper 关键字 `[audit] login.fail.user_not_found 速率异常` 直接告警。
- **如果当时有 K2,事故 1 分钟内升级 ERROR + audit 子类聚合可直接定位,MTTD 11h → < 5min。**

### K3 — Legacy 部署路径硬下线
- 服务端归档了 `/etc/systemd/system/vpn-server.service`、
  `/root/nanotun/nanotund`、`/root/nanotun/data/nanotun.db*`
  (全部加 `.archived.<ts>` 后缀,留作 audit 可恢复)。
- scripts/deploy.sh + scripts/update.sh 加 DEPRECATED 头注释 + 默认 exit 2
  拒绝运行;显式 `NANOTUN_ALLOW_LEGACY_DEPLOY=1` 才放行(老节点维护逃生口)。

## 顺手补的 P1 改进

K1/K2/K3 完成后,顺手把堆积已久的可观测性/容错任务一起做了,降低未来同类事故
MTTD:

| ID | 内容 |
|----|------|
| G_exit_code | logrus.Fatal* 全部替换为带语义化 ExitCode + 字段的 util.FatalExit,systemd unit 加 RestartPreventExitStatus=10 11 20 阻止配置 / 证书类错的无脑重启 |
| C3          | tunDemuxToLink 加 per-write 写超时(5s)+ ctx watchdog,慢客户端再也不能把 linkWrMu 卡到天荒地老,同时让 shutdown_drain 的 deadline 真正生效(之前 type 断言一直 ok=false) |
| G6          | SIGHUP hot reload MVP:log.level / jump_host_allowed_ips 真热更新,其它字段 deferred + 列名提示(无停机改两类高频参数) |
| G_wss_ping  | WSS 数据面 server→client 应用层 Ping/Pong + 90s 判活,默认禁用待 Rust client 验证后启用(docs/wss-data-plane-keepalive.md 含协调发布步骤) |
| C6_full     | jump_host_firewall 扩展为多协议多端口/段(`[server].jump_host_protected_ports`),hy2 / REALITY / 保活 wss 一并能被跳板机 ipset 限制 |

## 留给未来的债

- **Migration tooling**: nanotun-admin 应加 `db migrate <src> <dst>` 子命令,
  做 schema-aware 合并(避免直接 cp 整库的 lossy 风险)。这次直接 cp 能跑是
  因为新旧 schema 一致(Batch J 后已统一)。
- **IPv6 跳板机**: C6_full 只覆盖 IPv4 ipset,IPv6 跳板机需新建
  `nanotun_jump_src6` hash:ip family inet6 + ip6tables 一套。
- **G_wss_ping rollout**: Rust 客户端是否能响应 server→client Ping 待 grep
  确认,确认后再灰度启用。
- **Restart=on-failure 与 graceful exit 的歧义**: 老 vpn-server.service 干净
  exit 0(SIGTERM 路径)不被 systemd 拉起,部分场景下是 footgun。已通过 K3
  下线该 unit;新 nanotun.service 配合 G_exit_code 的 RestartPreventExitStatus
  给运维更细粒度控制。

- **TestStartEmbeddedHysteria_PortUnionBindsPrimary flaky**: 单测期望
  `gotPort == primary`(传给 `pickFreeUDPPort` 的第一个返回值),但生产代码
  `PrimaryPortFromUDPListenAddr` 通过 `hyutils.ParsePortUnion(...)[0].Start`
  会按数值排序,所以实际行为是「数值最小的那个 = primary」,与传入顺序无关。
  本质是 50/50 抛硬币:两个随机端口哪个数值小决定胜负。修法二选一:
    a) 测试侧改成 `expected := min(primary, secondary)` 再比对(承认生产语义);
    b) 生产侧改成保留 portUnion 字符串里的首项作为 primary(承认 toml 语义)。
  目前不修;下次有 hysteria port hopping 工作时一并处理。

## 教训

1. **任何路径迁移都必须自带迁移工具或拒绝部署**。silent default 是事故温床。
2. **失败日志要分级 + 分类**。warning 级 + 千篇一律的 "登录验证失败" 让事故
   藏了 11h 才被注意。K2 之后同类失败 ≥ 12/min 自动 ERROR,运维一眼看到。
3. **不要让两套部署布局长期并存**。vpn-server.service + nanotun.service
   并存给了「8080 被新服务抢走但运维以为还在跑老服务」的几小时窗口期。
4. **客户端报错 ≠ 服务端无错**。"NECP policy denied" 是表象,根因是更上层的
   登录失败让 tunnel 数据面拿不到合法配置。下次类似症状先去看 server 的
   登录审计行,再走 client 路径。
