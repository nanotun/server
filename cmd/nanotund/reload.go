package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nanotun/server/config"
	"github.com/nanotun/server/store"
)

// hotReloadCfgMu 保护「SIGHUP 可原地热更、且被数据面 goroutine 无锁读」的少数 cfg
// 字段(当前:Server.MaxSessionsPerUser / Server.RateLimitByPlatform /
// Server.JumpHostAllowedIPs)。rs.cfg 与 gw.cfg 指向**同一个** *config.Config:
// applyConfigReload 在只持 rs.mu 的情况下原地改这些字段,而登录路径在别的锁(或无锁)
// 下读它们 —— 按 Go 内存模型这是数据竞争(`go test -race` / 生产 -race 会报),slice
// header 之类多字长字段还可能读到撕裂值。这把 RWMutex 让「写(reload)」与「读(热路径)」
// 串行化。锁序:任何已持有的锁(如 connIDMapMu)→ hotReloadCfgMu;reload 侧只持有它,
// 不再向下取 connIDMapMu,故无环。
var hotReloadCfgMu sync.RWMutex

// reloadState 把 SIGHUP hot reload 需要触摸的运行时句柄收在一起,避免在 main 里
// 散一堆全局变量。锁串行整次 reload,防止两个并发 SIGHUP 同时改 effective cfg
// 出现 partial apply。
type reloadState struct {
	mu         sync.Mutex
	configPath string
	cfg        *config.Config // 当前 effective(已应用)的完整配置快照
	jumpFW     *jumpHostFirewall
	// store 用于 P1-4 reload audit 与 P0-1 ACL 热重载。
	// 测试场景下可为 nil(setupGateway helper);生产代码 main 启动时一定非 nil。
	store *store.Store
}

// G6 + P2#15(2026-05-22): 当前可热更新的字段白名单。
//
// 设计原则:只把「读写都在单个写者 + 多读者」、可幂等覆盖、不涉及网络栈 / 监听
// 句柄重建的字段放进来。
// 其它字段(listen_addr / tls_cert / hysteria 套件 / TUN 网段 / DB 路径等)必须
// systemctl restart 重启进程 —— SIGTERM 会跑 graceful drain 广播 LinkTypeClose,
// 客户端友好。
//
// 当前白名单(reload 后立刻生效,无需重连):
//   - log.level                              日志级别(运维实时调试用,最高频需求)
//   - server.jump_host_allowed_ips           跳板机白名单(轮换 IP 不必停服)
//   - acl_rules                              ACL 全量重建(在 acl_runtime 里原子替换)
//   - acl_default_action                     acl_runtime 默认动作(同 acl_rules 一起 swap)
//
// 当前白名单(reload 后对**新登录 / 新连接**生效;旧连接保留登录时刻值):
//   - server.max_sessions_per_user           evictOldestSessionsLocked 每次都读 cfg
//   - server.rate_limit_by_platform          rateLimitsForPlatform 每次都读 cfg
//   - server.login_rate_limit_per_min        globalLoginIPLimiter.ratePerMin(atomic);
//                                            切 0=不限制瞬时生效,N>0 对新建 per-IP entry 生效
//
// 已明确「reload 不会生效」的字段:仅在 deferred 列表里提示 + ERROR 级日志
// (见 classifyDeferredFields),不让运维静默踩坑:
//   - server.user_invalidate_interval_sec    ticker 初始化时塞死(看 user_invalidate.go)
//   - server.lease_gc_idle_days / interval   同上(看 lease_gc.go)
//   - server.data_plane_ping_interval / miss WSS 链路启动时塞死(看 wss_keepalive.go)
//   - server.control_socket_path             unix socket 启动时塞死
//   - server.pow.*                           PoW 段(hmac_key 启动随机,难度公式跟
//                                            challenge 签名绑定,reload 即让运行中题目
//                                            全部作废,等价于强制重连所有客户端)。
//                                            **future 注意**:不要随手把 PoWConfig
//                                            加进 reload 路径,改 PoW 必须重启 server
//                                            (跟重启等价,反正 hmac_key 也会换)。

// applyConfigReload 应用一次 SIGHUP 触发的 reload。
// 失败时 logrus.Error + 保留旧配置(进程不退,运维可继续用旧值)。
//
// 返回 (appliedFields, deferredFields):便于单测断言「哪些热更新成功 / 哪些必须重启」。
func applyConfigReload(rs *reloadState, loader func(path string) (config.Config, error)) (applied []string, deferred []string) {
	if rs == nil || rs.cfg == nil {
		return nil, nil
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()

	newCfg, err := loader(rs.configPath)
	if err != nil {
		logrus.WithError(err).WithField("config_path", rs.configPath).Error("[reload] 加载新配置失败,保留旧配置")
		return nil, nil
	}

	old := rs.cfg

	// 1) log.level —— 直接 SetLevel(logrus 内部 atomic,不需 lock)。
	if newCfg.Log.Level != old.Log.Level {
		if newCfg.Log.Level != "" {
			lvl, errLv := logrus.ParseLevel(newCfg.Log.Level)
			if errLv != nil {
				logrus.WithError(errLv).WithField("requested", newCfg.Log.Level).Warn("[reload] log.level 无效,保留旧值")
			} else {
				logrus.SetLevel(lvl)
				logrus.WithFields(logrus.Fields{"old": old.Log.Level, "new": newCfg.Log.Level}).Info("[reload] log.level 已热更新")
				old.Log.Level = newCfg.Log.Level
				applied = append(applied, "log.level")
			}
		}
	}

	// 2) server.jump_host_allowed_ips —— 透传到 jumpFW.Replace。
	// 仅 jump_host_firewall=true 时有意义;关闭状态下不动名单避免后续重新打开
	// 时拿到一份「reload 期间偷偷写过」的不可见快照。
	if !sameStringSetSorted(newCfg.Server.JumpHostAllowedIPs, old.Server.JumpHostAllowedIPs) {
		switch {
		case rs.jumpFW == nil:
			deferred = append(deferred, "server.jump_host_allowed_ips(jumpFW 未启用,需重启)")
		case !newCfg.Server.JumpHostFirewall:
			// 配置改成关闭 jump_host_firewall:这是 enabled 切换,属于非热更新路径
			deferred = append(deferred, "server.jump_host_firewall(开关切换需重启)")
		default:
			rs.jumpFW.Replace(newCfg.Server.JumpHostAllowedIPs)
			logrus.WithFields(logrus.Fields{
				"old_count": len(old.Server.JumpHostAllowedIPs),
				"new_count": len(newCfg.Server.JumpHostAllowedIPs),
			}).Info("[reload] server.jump_host_allowed_ips 已热更新")
			hotReloadCfgMu.Lock()
			old.Server.JumpHostAllowedIPs = append([]string(nil), newCfg.Server.JumpHostAllowedIPs...)
			hotReloadCfgMu.Unlock()
			applied = append(applied, "server.jump_host_allowed_ips")
		}
	}

	// 3) ACL 规则集热重载(P0-1):无 diff 概念,直接从 store 重新拉一次快照原子替换。
	// 失败时保留旧快照,不影响数据面;成功时打 INFO,detail 写规则条数 + 当前累计 drops。
	// 把 aclSummaryForLog 带上是为了 SIGHUP 兼做「观测点」:运维只要 `kill -HUP` 就能
	// 在日志里看到 drops_so_far 增量,不需要单独埋 /metrics 端点。
	if rs.store != nil {
		if n, err := reloadACLSnapshotFromStore(rs.store); err != nil {
			logrus.WithError(err).Warn("[reload] acl 规则集刷新失败,保留旧快照")
			deferred = append(deferred, "acl_rules(load_error)")
		} else {
			logrus.WithField("rule_count", n).WithFields(aclSummaryForLog()).Info("[reload] acl 规则集已刷新")
			applied = append(applied, "acl_rules")
		}
	}

	// P2#15:max_sessions_per_user 实际可热更(evictOldestSessionsLocked 每次都读 cfg)。
	// 立刻生效但只对**下次登录**起作用,旧会话不会被回踢。文案标清楚避免误判。
	if newCfg.Server.MaxSessionsPerUser != old.Server.MaxSessionsPerUser {
		logrus.WithFields(logrus.Fields{
			"old": old.Server.MaxSessionsPerUser,
			"new": newCfg.Server.MaxSessionsPerUser,
		}).Info("[reload] server.max_sessions_per_user 已热更(仅对未来登录生效;现役会话不会被回踢)")
		hotReloadCfgMu.Lock()
		old.Server.MaxSessionsPerUser = newCfg.Server.MaxSessionsPerUser
		hotReloadCfgMu.Unlock()
		applied = append(applied, "server.max_sessions_per_user")
	}

	// login_rate_limit_per_min(2026-06-23):per-IP 登录限速可热更。
	// globalLoginIPLimiter.ratePerMin 是 atomic,SetRatePerMin 立即生效:
	//   - 切到 0(不限制)→ AllowLogin 无锁短路全量放行,瞬时生效;
	//   - 切到 N>0 → 后续**新建** per-IP entry 按新速率(旧 entry 30min GC 后重建)。
	if newCfg.Server.LoginRateLimitPerMin != old.Server.LoginRateLimitPerMin {
		globalLoginIPLimiter.SetRatePerMin(newCfg.Server.LoginRateLimitPerMin)
		logrus.WithFields(logrus.Fields{
			"old": old.Server.LoginRateLimitPerMin,
			"new": newCfg.Server.LoginRateLimitPerMin,
		}).Info("[reload] server.login_rate_limit_per_min 已热更(0=不限制立即生效;N>0 对新建 per-IP entry 生效)")
		old.Server.LoginRateLimitPerMin = newCfg.Server.LoginRateLimitPerMin
		applied = append(applied, "server.login_rate_limit_per_min")
	}

	// P2#15:rate_limit_by_platform 同上 —— 字典直接整体替换。
	// 旧 conn 在 Connection 上挂着自己的 rate.Limiter,不会被更新;新 conn 读到新表。
	// map 由 cfg load 时新建,reload 后 old.Server.RateLimitByPlatform 直接换指针即可,
	// 没有 map 共享 mutation 风险(rateLimitsForPlatform 是只读访问)。
	if !sameRateLimitMap(newCfg.Server.RateLimitByPlatform, old.Server.RateLimitByPlatform) {
		// deep copy 一份,避免 newCfg 上的引用被运维「先 toml.Unmarshal 再改」干扰。
		cp := make(map[string]config.LinkRateLimitPlatform, len(newCfg.Server.RateLimitByPlatform))
		for k, v := range newCfg.Server.RateLimitByPlatform {
			cp[k] = v
		}
		hotReloadCfgMu.Lock()
		old.Server.RateLimitByPlatform = cp
		hotReloadCfgMu.Unlock()
		logrus.WithFields(logrus.Fields{
			"platform_count": len(cp),
		}).Info("[reload] server.rate_limit_by_platform 已热更(仅对未来登录生效)")
		applied = append(applied, "server.rate_limit_by_platform")
	}

	// 4) 非热更新字段:diff + 提示需重启。
	// 不做完整 reflect diff,只看「最常被修改且最容易踩坑」的几项。其它字段改了
	// 不打 warn —— 信号噪音权衡:全列会很吵,运维若改了不该改的会自己在重启日志里看到。
	deferred = append(deferred, classifyDeferredFields(old, &newCfg)...)
	sort.Strings(deferred)

	// P1-4: SIGHUP 热更全程写 audit_logs(合规与排障)。
	// 成功/无 op/失败统一一条;detail 列举 applied/deferred,便于按 action 过滤复盘。
	if rs.store != nil {
		detail := fmt.Sprintf("applied=[%s] deferred=[%s]",
			strings.Join(applied, ","), strings.Join(deferred, ","))
		_ = rs.store.Audit(context.Background(), "sighup", "config_reload", "", detail)
	}

	if len(applied) == 0 && len(deferred) == 0 {
		logrus.Info("[reload] 配置无任何变化,no-op")
		return
	}
	logrus.WithFields(logrus.Fields{
		"applied":  applied,
		"deferred": deferred,
	}).Info("[reload] 完成。deferred 列表内的字段需 systemctl restart 才生效")
	return
}

// classifyDeferredFields 列出常见的「改了但没生效」字段,提示运维做下一步操作。
//
// 这是有意「不完整」:只覆盖最容易被运维频繁改的几项,避免 noise。
//
// P2-14:对「改了但 reload 不生效、运维很容易误以为已生效」的字段(max_sessions /
// 带宽限速),不仅返回 deferred 列表,还在这里**单独打 ERROR 级日志**,让 log shipper
// 关键字告警能直接命中,降低「改了配置但没看到效果」造成的误判。
func classifyDeferredFields(old, newCfg *config.Config) []string {
	var out []string
	if newCfg.Server.ListenAddr != old.Server.ListenAddr {
		out = append(out, "server.listen_addr")
	}
	if newCfg.Server.TLSCertFile != old.Server.TLSCertFile || newCfg.Server.TLSKeyFile != old.Server.TLSKeyFile {
		out = append(out, "server.tls_cert_file/tls_key_file")
	}
	if newCfg.Server.JumpHostFirewall != old.Server.JumpHostFirewall {
		out = append(out, "server.jump_host_firewall")
	}
	if newCfg.Hysteria.Password != old.Hysteria.Password {
		out = append(out, "hysteria.password")
	}
	if newCfg.Hysteria.ListenAddr != old.Hysteria.ListenAddr {
		out = append(out, "hysteria.listen_addr")
	}
	if newCfg.Reality.ListenAddr != old.Reality.ListenAddr {
		out = append(out, "reality.listen_addr")
	}
	if newCfg.Store.DBPath != old.Store.DBPath {
		out = append(out, "store.db_path")
	}
	// upload_rate / download_rate / 探活 / 后台扫描 ticker 都是「初始化时塞死」,
	// reload 不会重启 loop;明确写 ERROR 让运维不要静默踩坑。
	if newCfg.Server.UploadRate != old.Server.UploadRate {
		logrus.WithFields(logrus.Fields{
			"field": "server.upload_rate",
			"old":   old.Server.UploadRate,
			"new":   newCfg.Server.UploadRate,
		}).Error("[reload] 带宽限速不可热更,新值仅对 restart 后新建连接生效")
		out = append(out, "server.upload_rate")
	}
	if newCfg.Server.DownloadRate != old.Server.DownloadRate {
		logrus.WithFields(logrus.Fields{
			"field": "server.download_rate",
			"old":   old.Server.DownloadRate,
			"new":   newCfg.Server.DownloadRate,
		}).Error("[reload] 带宽限速不可热更,新值仅对 restart 后新建连接生效")
		out = append(out, "server.download_rate")
	}
	if newCfg.Server.UserInvalidateIntervalSec != old.Server.UserInvalidateIntervalSec {
		logrus.WithFields(logrus.Fields{
			"old": old.Server.UserInvalidateIntervalSec,
			"new": newCfg.Server.UserInvalidateIntervalSec,
		}).Error("[reload] server.user_invalidate_interval_sec 不可热更(loop ticker 启动时塞死),需重启 server")
		out = append(out, "server.user_invalidate_interval_sec")
	}
	if newCfg.Server.LeaseGCIdleDays != old.Server.LeaseGCIdleDays {
		logrus.WithFields(logrus.Fields{
			"old": old.Server.LeaseGCIdleDays,
			"new": newCfg.Server.LeaseGCIdleDays,
		}).Error("[reload] server.lease_gc_idle_days 不可热更,需重启 server")
		out = append(out, "server.lease_gc_idle_days")
	}
	if newCfg.Server.LeaseGCIntervalHours != old.Server.LeaseGCIntervalHours {
		logrus.WithFields(logrus.Fields{
			"old": old.Server.LeaseGCIntervalHours,
			"new": newCfg.Server.LeaseGCIntervalHours,
		}).Error("[reload] server.lease_gc_interval_hours 不可热更,需重启 server")
		out = append(out, "server.lease_gc_interval_hours")
	}
	if time.Duration(newCfg.Server.DataPlanePingInterval) != time.Duration(old.Server.DataPlanePingInterval) {
		logrus.Error("[reload] server.data_plane_ping_interval 不可热更(WSS 启动时塞死),需重启 server")
		out = append(out, "server.data_plane_ping_interval")
	}
	if newCfg.Server.DataPlanePingMissThreshold != old.Server.DataPlanePingMissThreshold {
		logrus.Error("[reload] server.data_plane_ping_miss_threshold 不可热更,需重启 server")
		out = append(out, "server.data_plane_ping_miss_threshold")
	}
	if newCfg.Server.ControlSocketPath != old.Server.ControlSocketPath {
		logrus.Error("[reload] server.control_socket_path 不可热更(unix listener 启动时塞死),需重启 server")
		out = append(out, "server.control_socket_path")
	}
	if newCfg.TUN.ResolveExitMode() != old.TUN.ResolveExitMode() {
		logrus.WithFields(logrus.Fields{
			"old": old.TUN.ResolveExitMode(),
			"new": newCfg.TUN.ResolveExitMode(),
		}).Error("[reload] tun.exit_mode 不可热更(SNAT + FORWARD 链涉及活跃连接 conntrack),需重启 server")
		out = append(out, "tun.exit_mode")
	}
	// 深扫第十轮 LOW:exit_dns_redirect 与 exit_mode 同为出口 DNS 拦截 iptables 规则,
	// 启动时一次性落链,SIGHUP 不重建。此前漏进 deferred 列表 → 运维改了 off↔1.1.1.1
	// reload 后无任何提示,误以为已生效。这里补上告警,和 exit_mode 一个口径。
	if strings.TrimSpace(newCfg.TUN.ExitDNSRedirect) != strings.TrimSpace(old.TUN.ExitDNSRedirect) {
		logrus.WithFields(logrus.Fields{
			"old": old.TUN.ExitDNSRedirect,
			"new": newCfg.TUN.ExitDNSRedirect,
		}).Error("[reload] tun.exit_dns_redirect 不可热更(出口 DNS 拦截 iptables 规则启动时落链),需重启 server")
		out = append(out, "tun.exit_dns_redirect")
	}
	// [server.pow] 段:hmac_key 启动随机,公式参数初始化时塞死,reload 不重建
	// PoWService(否则会让运行中的所有 challenge 一次失效,等价于踢所有 pre-login
	// 连接,反而比 restart 更激进)。统一 ERROR 提示 + 进 deferred 列表,让运维
	// 通过 SIGHUP audit / log shipper 监控感知"我改的 PoW 没生效"。
	if newCfg.Server.Pow.FailuresEnable != old.Server.Pow.FailuresEnable {
		logrus.WithFields(logrus.Fields{
			"old": old.Server.Pow.FailuresEnable,
			"new": newCfg.Server.Pow.FailuresEnable,
		}).Error("[reload] server.pow.failures_enable 不可热更(PoWService 启动时塞死),需重启 server")
		out = append(out, "server.pow.failures_enable")
	}
	if newCfg.Server.Pow.BaseDifficulty != old.Server.Pow.BaseDifficulty {
		logrus.WithFields(logrus.Fields{
			"old": old.Server.Pow.BaseDifficulty,
			"new": newCfg.Server.Pow.BaseDifficulty,
		}).Error("[reload] server.pow.base_difficulty 不可热更(PoWService 启动时塞死),需重启 server")
		out = append(out, "server.pow.base_difficulty")
	}
	if newCfg.Server.Pow.RampDifficulty != old.Server.Pow.RampDifficulty {
		logrus.WithFields(logrus.Fields{
			"old": old.Server.Pow.RampDifficulty,
			"new": newCfg.Server.Pow.RampDifficulty,
		}).Error("[reload] server.pow.ramp_difficulty 不可热更(PoWService 启动时塞死),需重启 server")
		out = append(out, "server.pow.ramp_difficulty")
	}
	if newCfg.Server.Pow.StepPerFailure != old.Server.Pow.StepPerFailure {
		logrus.WithFields(logrus.Fields{
			"old": old.Server.Pow.StepPerFailure,
			"new": newCfg.Server.Pow.StepPerFailure,
		}).Error("[reload] server.pow.step_per_failure 不可热更(PoWService 启动时塞死),需重启 server")
		out = append(out, "server.pow.step_per_failure")
	}
	if newCfg.Server.Pow.AdaptiveCeiling != old.Server.Pow.AdaptiveCeiling {
		logrus.WithFields(logrus.Fields{
			"old": old.Server.Pow.AdaptiveCeiling,
			"new": newCfg.Server.Pow.AdaptiveCeiling,
		}).Error("[reload] server.pow.adaptive_ceiling 不可热更(PoWService 启动时塞死),需重启 server")
		out = append(out, "server.pow.adaptive_ceiling")
	}
	if newCfg.Server.Pow.TTLSec != old.Server.Pow.TTLSec {
		logrus.WithFields(logrus.Fields{
			"old": old.Server.Pow.TTLSec,
			"new": newCfg.Server.Pow.TTLSec,
		}).Error("[reload] server.pow.ttl_sec 不可热更(PoWService 启动时塞死),需重启 server")
		out = append(out, "server.pow.ttl_sec")
	}
	return out
}

// sameRateLimitMap 判断两个 RateLimitByPlatform 字典是否相等(key + value 完全一致)。
// 用于 SIGHUP 热更前 diff;不相等才会真正替换 cfg.Server.RateLimitByPlatform。
// nil 与 0 长度 map 视作相等(运维删空 vs. 删 section 不区分)。
func sameRateLimitMap(a, b map[string]config.LinkRateLimitPlatform) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		v2, ok := b[k]
		if !ok || v != v2 {
			return false
		}
	}
	return true
}

// sameStringSetSorted 判断两个字符串切片**作为集合**是否相等(忽略顺序、忽略重复)。
// 用于 IP 白名单 diff —— 运维改顺序但内容没变时不应当作改动。
func sameStringSetSorted(a, b []string) bool {
	if len(a) != len(b) {
		// 长度不同也可能集合相等(去重后),但不重要,保守判为不同触发一次 Replace。
		// Replace 是幂等的,误触发只是一次 ipset 同步开销,不影响正确性。
		return false
	}
	ac := append([]string(nil), a...)
	bc := append([]string(nil), b...)
	sort.Strings(ac)
	sort.Strings(bc)
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}
