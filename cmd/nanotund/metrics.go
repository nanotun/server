package main

// J3(2026-05-22)Prometheus exposition format(0.0.4 文本格式)。
//
// 设计选择:
//   - **不**引入 prometheus/client_golang(它和 grpc / collectors / push gateway 一堆
//     代码绑在一起,300+ KB 二进制 + 多依赖,对一个组网工具过重);
//   - 直接 fmt.Fprintf 输出 # HELP / # TYPE / metric value 三行结构 ——
//     prometheus / VictoriaMetrics / OpenMetrics 全兼容;
//   - 复用现有 atomic.Uint64 counters + snapshot,不重复维护一套 metrics;
//   - 加 build_info gauge,运维一眼能知道当前 server 版本 / git SHA。
//
// 不暴露 per-session / per-IP 维度(高基数会让 prometheus 自己崩);只暴露聚合计数。

import (
	"fmt"
	"io"
	"time"
)

// writePrometheusMetrics 暴露所有内置 metric。gw 可以为 nil(测试场景),
// 此时 PoW 段会用 lazy fallback PoWService 快照(全 0 计数)。
func writePrometheusMetrics(w io.Writer, gw *gatewayState) {
	uptime := time.Since(controlStartTime).Seconds()

	// build_info:运维 dashboard 上能直接关联 panic 到 git SHA。
	fmt.Fprintln(w, "# HELP nanotun_build_info Server build metadata, value always 1")
	fmt.Fprintln(w, "# TYPE nanotun_build_info gauge")
	fmt.Fprintf(w, "nanotun_build_info{version=%q,git_sha=%q,build_time=%q} 1\n",
		serverVersion, serverGitSHA, serverBuildTime)

	// uptime 用 gauge:prometheus 约定只有 _total 后缀的累加才叫 counter,
	// 单调增的"自启动以来秒数"也可以,但用 gauge 更符合 OpenMetrics 习惯。
	fmt.Fprintln(w, "# HELP nanotun_uptime_seconds Process uptime since start in seconds")
	fmt.Fprintln(w, "# TYPE nanotun_uptime_seconds gauge")
	fmt.Fprintf(w, "nanotun_uptime_seconds %.0f\n", uptime)

	// 数据面 readiness:做成 gauge 便于 alertmanager 直接告警「TUN/store 没起」。
	fmt.Fprintln(w, "# HELP nanotun_tun_ready 1=TUN device is up, 0=not yet")
	fmt.Fprintln(w, "# TYPE nanotun_tun_ready gauge")
	tunReady := 0
	if sharedTUN != nil {
		tunReady = 1
	}
	fmt.Fprintf(w, "nanotun_tun_ready %d\n", tunReady)

	// 会话计数:不暴露 per-session 维度,只暴露当前总数。
	connIDMapMu.RLock()
	connCount := len(connIDMap)
	connIDMapMu.RUnlock()
	fmt.Fprintln(w, "# HELP nanotun_active_sessions Current count of active VPN sessions")
	fmt.Fprintln(w, "# TYPE nanotun_active_sessions gauge")
	fmt.Fprintf(w, "nanotun_active_sessions %d\n", connCount)

	// ACL 丢包:user-kind、exit-kind、exit-gate、mesh-off 四个分桶。
	// kind=mesh_off(2026-05-23):管理员关闭组网模式时跨用户流量被截下来的总数,
	// 与 ACL 规则丢的(kind=user)区分,便于运维定位「为啥流量不通」。
	fmt.Fprintln(w, "# HELP nanotun_acl_drops_total Packets dropped by ACL since process start, by kind")
	fmt.Fprintln(w, "# TYPE nanotun_acl_drops_total counter")
	fmt.Fprintf(w, "nanotun_acl_drops_total{kind=\"user\"} %d\n", aclDropCount.Load())
	fmt.Fprintf(w, "nanotun_acl_drops_total{kind=\"exit_acl\"} %d\n", aclExitDropCount.Load())
	fmt.Fprintf(w, "nanotun_acl_drops_total{kind=\"exit_gate\"} %d\n", exitGateDropCount.Load())
	fmt.Fprintf(w, "nanotun_acl_drops_total{kind=\"mesh_off\"} %d\n", meshOffDropCount.Load())
	// kind=src_spoof(M2 源地址反欺骗):普通会话以非本会话 vIP 作源发包被丢的总数(冒充他人 vIP / 注入伪造回包)。
	fmt.Fprintf(w, "nanotun_acl_drops_total{kind=\"src_spoof\"} %d\n", srcSpoofDropCount.Load())

	// mesh 总开关状态:0 / 1,gauge,便于报警「mesh 是不是被人误关了」。
	meshOn := 0
	if snap := aclCurrent.Load(); snap != nil && snap.meshEnabled {
		meshOn = 1
	}
	fmt.Fprintln(w, "# HELP nanotun_mesh_enabled 1 if mesh mode is on (cross-user traffic flows through ACL), 0 if cross-user traffic is hard-dropped")
	fmt.Fprintln(w, "# TYPE nanotun_mesh_enabled gauge")
	fmt.Fprintf(w, "nanotun_mesh_enabled %d\n", meshOn)

	// 后台 GC / 踢线计数:
	fmt.Fprintln(w, "# HELP nanotun_lease_gc_total Idle VIP leases reclaimed by background GC")
	fmt.Fprintln(w, "# TYPE nanotun_lease_gc_total counter")
	fmt.Fprintf(w, "nanotun_lease_gc_total %d\n", leaseGCCount.Load())

	fmt.Fprintln(w, "# HELP nanotun_user_invalidate_kicks_total Sessions kicked due to user/profile invalidation")
	fmt.Fprintln(w, "# TYPE nanotun_user_invalidate_kicks_total counter")
	fmt.Fprintf(w, "nanotun_user_invalidate_kicks_total %d\n", userInvalidateKickCount.Load())

	// 2026-05-23:同 device_uuid 重登踢旧会话总数。预期持续走高 = 客户端在频繁重连
	// (network flap / app crash 循环);单条计数不告警,但增速突然 >> 平时基线时
	// 值得排查 client 端连接稳定性。
	fmt.Fprintln(w, "# HELP nanotun_session_supersede_total Sessions superseded by a fresh login from the same device_uuid (kept old behavior of waiting for idle GC otherwise)")
	fmt.Fprintln(w, "# TYPE nanotun_session_supersede_total counter")
	fmt.Fprintf(w, "nanotun_session_supersede_total %d\n", sessionSupersedeCount.Load())

	// Magic DNS counters。
	dns := snapshotMagicDNSStats()
	fmt.Fprintln(w, "# HELP nanotun_magic_dns_queries_total Total Magic DNS queries received")
	fmt.Fprintln(w, "# TYPE nanotun_magic_dns_queries_total counter")
	fmt.Fprintf(w, "nanotun_magic_dns_queries_total %d\n", dns.Queries)
	fmt.Fprintln(w, "# HELP nanotun_magic_dns_outcomes_total Magic DNS query outcomes, by outcome label")
	fmt.Fprintln(w, "# TYPE nanotun_magic_dns_outcomes_total counter")
	fmt.Fprintf(w, "nanotun_magic_dns_outcomes_total{outcome=\"magic_hit\"} %d\n", dns.MagicHit)
	fmt.Fprintf(w, "nanotun_magic_dns_outcomes_total{outcome=\"upstream\"} %d\n", dns.Upstream)
	fmt.Fprintf(w, "nanotun_magic_dns_outcomes_total{outcome=\"servfail\"} %d\n", dns.Servfail)
	fmt.Fprintf(w, "nanotun_magic_dns_outcomes_total{outcome=\"unknown_name\"} %d\n", dns.UnknownName)
	fmt.Fprintf(w, "nanotun_magic_dns_outcomes_total{outcome=\"malformed\"} %d\n", dns.Malformed)
	// exit-bound DNS 路径(direction 1)观测:经出口失败回 SERVFAIL(fail-closed) / 早期窗口 TTL 钳制 / :53 数据面拦截。
	fmt.Fprintf(w, "nanotun_magic_dns_outcomes_total{outcome=\"exit_servfail\"} %d\n", dns.ExitServfail)
	fmt.Fprintf(w, "nanotun_magic_dns_outcomes_total{outcome=\"early_ttl_clamp\"} %d\n", dns.EarlyTTLClamp)
	fmt.Fprintf(w, "nanotun_magic_dns_outcomes_total{outcome=\"intercept_dns\"} %d\n", dns.InterceptDNS)
	fmt.Fprintln(w, "# HELP nanotun_magic_dns_inflight_drops_total Queries dropped because inflight cap reached(possible attack)")
	fmt.Fprintln(w, "# TYPE nanotun_magic_dns_inflight_drops_total counter")
	fmt.Fprintf(w, "nanotun_magic_dns_inflight_drops_total %d\n", dns.InflightDrops)

	// Subnet route advertise(控制面,任意 CIDR 数据面尚未实现;出口 0/0 特例见下方 exit_node)。
	ra := snapshotRouteAdvStats()
	fmt.Fprintln(w, "# HELP nanotun_route_adv_total Route advertise frames processed, by outcome")
	fmt.Fprintln(w, "# TYPE nanotun_route_adv_total counter")
	fmt.Fprintf(w, "nanotun_route_adv_total{outcome=\"accepted\"} %d\n", ra.Accepted)
	fmt.Fprintf(w, "nanotun_route_adv_total{outcome=\"rejected\"} %d\n", ra.Rejected)

	// Exit-node:出口选择(控制面)+ 转发(数据面)。出口 = approved 0/0 子网路由特例,数据面已落地。
	ex := snapshotExitNodeStats()
	fmt.Fprintln(w, "# HELP nanotun_egress_select_total EgressSelect control frames processed, by outcome")
	fmt.Fprintln(w, "# TYPE nanotun_egress_select_total counter")
	fmt.Fprintf(w, "nanotun_egress_select_total{outcome=\"accepted\"} %d\n", ex.SelectAccepted)
	fmt.Fprintf(w, "nanotun_egress_select_total{outcome=\"rejected\"} %d\n", ex.SelectRejected)
	fmt.Fprintf(w, "nanotun_egress_select_total{outcome=\"failed\"} %d\n", ex.SelectFailed)
	fmt.Fprintln(w, "# HELP nanotun_exit_forward_total Packets handled by the exit-node forward path, by outcome")
	fmt.Fprintln(w, "# TYPE nanotun_exit_forward_total counter")
	fmt.Fprintf(w, "nanotun_exit_forward_total{outcome=\"forwarded\"} %d\n", ex.Forwarded)
	fmt.Fprintf(w, "nanotun_exit_forward_total{outcome=\"dropped_offline\"} %d\n", ex.DroppedOffline)
	fmt.Fprintf(w, "nanotun_exit_forward_total{outcome=\"dropped_full\"} %d\n", ex.DroppedFull)
	fmt.Fprintf(w, "nanotun_exit_forward_total{outcome=\"dropped_oversize\"} %d\n", ex.DroppedOversize)
	fmt.Fprintf(w, "nanotun_exit_forward_total{outcome=\"dropped_rate\"} %d\n", ex.DroppedRate)
	// 出口转发字节(单列计量:中转双倍带宽)。
	fmt.Fprintln(w, "# HELP nanotun_exit_forward_bytes_total Bytes forwarded through the exit-node relay path")
	fmt.Fprintln(w, "# TYPE nanotun_exit_forward_bytes_total counter")
	fmt.Fprintf(w, "nanotun_exit_forward_bytes_total %d\n", ex.ForwardedBytes)

	// 登录 rate-limit cap:运维一眼能看到「IPv6 灌包攻击发生过没有」。
	globalLoginIPLimiter.mu.Lock()
	rlCount := len(globalLoginIPLimiter.limits)
	rlCapExceeded := globalLoginIPLimiter.capExceeded
	globalLoginIPLimiter.mu.Unlock()
	fmt.Fprintln(w, "# HELP nanotun_login_ratelimit_entries Currently tracked per-IP login limiters")
	fmt.Fprintln(w, "# TYPE nanotun_login_ratelimit_entries gauge")
	fmt.Fprintf(w, "nanotun_login_ratelimit_entries %d\n", rlCount)
	fmt.Fprintln(w, "# HELP nanotun_login_ratelimit_cap_exceeded_total Login attempts rejected because per-IP table is full")
	fmt.Fprintln(w, "# TYPE nanotun_login_ratelimit_cap_exceeded_total counter")
	fmt.Fprintf(w, "nanotun_login_ratelimit_cap_exceeded_total %d\n", rlCapExceeded)

	// V1(2026-05-26):VPN 业务流量字节计数,跟宿主机网卡 metric 对照可看
	// 加密/复用 overhead。方向语义与 settings.rate_up_* / rate_down_* 对齐:
	//   up   = 客户端上传 = server 从 link 读出
	//   down = 客户端下载 = server 向 link 写入
	fmt.Fprintln(w, "# HELP nanotun_bytes_total Total VPN data-plane bytes since process start, by direction")
	fmt.Fprintln(w, "# TYPE nanotun_bytes_total counter")
	fmt.Fprintf(w, "nanotun_bytes_total{direction=\"up\"} %d\n", vpnBytesUp.Load())
	fmt.Fprintf(w, "nanotun_bytes_total{direction=\"down\"} %d\n", vpnBytesDown.Load())

	// tunWriteChan 满丢包:回程数据面唯一的用户态静默丢包点(见 server.go tunWriteDropCount)。
	// 平时应恒为 0;持续增长 = TUN 写线程跟不上(宿主 CPU / 磁盘 IO 抖动),客户端表现为下行丢包。
	fmt.Fprintln(w, "# HELP nanotun_tun_write_drops_total Packets dropped because tunWriteChan was full (TUN writer backpressure)")
	fmt.Fprintln(w, "# TYPE nanotun_tun_write_drops_total counter")
	fmt.Fprintf(w, "nanotun_tun_write_drops_total %d\n", tunWriteDropCount.Load())

	// =========================================================================
	// PoW(P1-2 / P2#16 防 PSK 暴力破解)
	//
	// 监控目标:
	//   - challenges_issued_total: 跟连接数对齐应该 ~1:1,显著偏离说明 attacker 灌
	//     PoWChallengeReq 但不上 LoginReq;
	//   - verify_failed_total{reason=...}: 平时应 ≈ 0,>0 说明 attacker 在试错;
	//     按 reason 分桶让运维直接判断是签名错(replay 老题)、过期(慢解)、
	//     难度低(借题)还是重放;
	//   - global_limited_total: 应保持 0,>0 直接告警(大规模 DoS);
	//   - ratelimit_cap_exceeded_total: per-IP 表满次数,IPv6 灌包指标;
	//   - used_table_size: 防重放表当前大小,GC 不健康会持续涨;
	//   - ip_failures_tracked: 当前跟踪的失败 IP 数,DDoS 时会突涨。
	// =========================================================================
	// nil-safe: gw == nil 时 effectivePoWService 内部 lazyPoWService 兜底。
	var powSvc *PoWService
	if gw != nil {
		powSvc = gw.effectivePoWService()
	} else {
		powSvc = lazyPoWService()
	}
	snap := powSvc.MetricsSnapshot()

	fmt.Fprintln(w, "# HELP nanotun_pow_challenges_issued_total PoW challenges successfully issued to clients")
	fmt.Fprintln(w, "# TYPE nanotun_pow_challenges_issued_total counter")
	fmt.Fprintf(w, "nanotun_pow_challenges_issued_total %d\n", snap.Issued)

	fmt.Fprintln(w, "# HELP nanotun_pow_verify_success_total PoW proofs verified ok")
	fmt.Fprintln(w, "# TYPE nanotun_pow_verify_success_total counter")
	fmt.Fprintf(w, "nanotun_pow_verify_success_total %d\n", snap.VerifySuccess)

	fmt.Fprintln(w, "# HELP nanotun_pow_verify_failed_total PoW proofs rejected, by reason")
	fmt.Fprintln(w, "# TYPE nanotun_pow_verify_failed_total counter")
	fmt.Fprintf(w, "nanotun_pow_verify_failed_total{reason=\"bad_cid\"} %d\n", snap.FailBadCID)
	fmt.Fprintf(w, "nanotun_pow_verify_failed_total{reason=\"bad_sig\"} %d\n", snap.FailBadSig)
	fmt.Fprintf(w, "nanotun_pow_verify_failed_total{reason=\"bad_salt\"} %d\n", snap.FailBadSalt)
	fmt.Fprintf(w, "nanotun_pow_verify_failed_total{reason=\"expired\"} %d\n", snap.FailExpired)
	fmt.Fprintf(w, "nanotun_pow_verify_failed_total{reason=\"difficulty_low\"} %d\n", snap.FailDiffLow)
	fmt.Fprintf(w, "nanotun_pow_verify_failed_total{reason=\"invalid\"} %d\n", snap.FailInvalid)
	fmt.Fprintf(w, "nanotun_pow_verify_failed_total{reason=\"replay\"} %d\n", snap.FailReplay)

	fmt.Fprintln(w, "# HELP nanotun_pow_used_table_size Active challenge IDs in the anti-replay table")
	fmt.Fprintln(w, "# TYPE nanotun_pow_used_table_size gauge")
	fmt.Fprintf(w, "nanotun_pow_used_table_size %d\n", snap.UsedTableSize)

	fmt.Fprintln(w, "# HELP nanotun_pow_ip_failures_tracked Per-IP login failure entries currently tracked for adaptive PoW difficulty")
	fmt.Fprintln(w, "# TYPE nanotun_pow_ip_failures_tracked gauge")
	fmt.Fprintf(w, "nanotun_pow_ip_failures_tracked %d\n", snap.IPFailuresTracked)

	// per-IP 出题速率表(60/分钟/IP)。
	globalPoWIPLimiter.mu.Lock()
	powIPCount := len(globalPoWIPLimiter.limits)
	powIPCapExceeded := globalPoWIPLimiter.capExceeded
	globalPoWIPLimiter.mu.Unlock()
	fmt.Fprintln(w, "# HELP nanotun_pow_ratelimit_entries Currently tracked per-IP PoW challenge rate-limit entries")
	fmt.Fprintln(w, "# TYPE nanotun_pow_ratelimit_entries gauge")
	fmt.Fprintf(w, "nanotun_pow_ratelimit_entries %d\n", powIPCount)
	fmt.Fprintln(w, "# HELP nanotun_pow_ratelimit_cap_exceeded_total PoW challenge requests rejected because per-IP table is full")
	fmt.Fprintln(w, "# TYPE nanotun_pow_ratelimit_cap_exceeded_total counter")
	fmt.Fprintf(w, "nanotun_pow_ratelimit_cap_exceeded_total %d\n", powIPCapExceeded)

	// 全局出题限速(1000/秒)。
	fmt.Fprintln(w, "# HELP nanotun_pow_global_limited_total PoW challenges rejected by global 1000/s rate limit (cross-IP DoS indicator)")
	fmt.Fprintln(w, "# TYPE nanotun_pow_global_limited_total counter")
	fmt.Fprintf(w, "nanotun_pow_global_limited_total %d\n", globalPoWGlobalLimitedTotal.Load())
}
