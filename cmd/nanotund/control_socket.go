package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// P1#6/7/8:admin <-> server 控制面(Unix Domain Socket)
//
// 设计与 health endpoint 正交:
//   - /health 给外部 monitoring(loopback),只 readiness,不接 admin 操作;
//   - control socket 仅给本地 root(权限 0600),提供 reload / kick / status;
//     不监听 TCP,不需要 auth(信任「能 read 这个文件就是管理员」)。
//
// 失败模式约定:
//   - socket 文件已存在 → unlink 后重试(典型场景:上次 kill -9 没退干净);
//   - 父目录不存在 → MkdirAll;
//   - 起 listener 失败 → Warn,不 fatal(没有 control socket 不影响 VPN 数据面)。

const (
	defaultControlSocketPath = "/run/nanotun/control.sock"
	controlSocketFileMode    = 0o600
	controlSocketDirMode     = 0o700
	// statusPageLimitMax(2026-05-24):/status?limit= 的硬上限。客户端拼错 limit=999999
	// 一次拉穷 server 不被允许;1000 已足够覆盖单页 dashboard,N_conn 上万时分页拉。
	statusPageLimitMax = 1000
	// controlMaxBodyBytes:控制面 POST body 上限。请求体都是小 JSON(几个 id + reason),
	// 1 MiB 远超任何合法请求;用 http.MaxBytesReader 兜住,防卡死 / bug 客户端发超大 body 撑爆内存。
	controlMaxBodyBytes = 1 << 20
)

// startControlSocket 创建 unix socket 并起 HTTP server。
// path 为空时使用默认值,显式 "off" 关闭。
//
// 返回 cleanup func(关 listener + unlink socket 文件)。
func startControlSocket(path string, gw *gatewayState) func() {
	if strings.EqualFold(strings.TrimSpace(path), "off") {
		logrus.Info("[control] control_socket_path=off,管理面已关闭")
		return func() {}
	}
	if strings.TrimSpace(path) == "" {
		path = defaultControlSocketPath
	}

	if err := prepareControlSocketPath(path); err != nil {
		logrus.WithError(err).WithField("path", path).Warn("[control] 准备 socket 路径失败,管理面未启动(reload/kick/list 不可用)")
		return func() {}
	}

	// E2(2026-05-22):net.Listen("unix",...) 创建 socket 文件时遵循进程 umask,
	// 默认创建模式 0666 & ~umask;之后再 chmod 会有一个窗口期,期间其它本地用户
	// 能 connect 上来。用 syscall.Umask 包住 Listen 调用确保 socket 一开始就是
	// 0600/0700(由后续 Chmod 兜底);Linux/Darwin 都支持。
	prev := setRestrictiveUmask()
	ln, err := net.Listen("unix", path)
	restoreUmask(prev)
	if err != nil {
		logrus.WithError(err).WithField("path", path).Warn("[control] 监听 unix socket 失败,管理面未启动")
		return func() {}
	}
	// fail-closed:控制面**无鉴权**——kick / reload / rate-refresh 等特权操作全靠「只有能读这个
	// socket 的本地用户才是管理员」这一文件权限前提。若无法把 socket 收紧到 0600,任何本地用户都能
	// 连上执行特权操作(踢会话 / 改限速 / reload),等于本地提权。此前 chmod 失败只 Warn 后**继续**
	// 提供服务,违背这个安全前提。改为:chmod 失败 → 关监听 + 删文件 + 不启动管理面。
	if err := os.Chmod(path, controlSocketFileMode); err != nil {
		logrus.WithError(err).WithField("path", path).
			Error("[control] chmod socket 失败,管理面拒绝启动(fail-closed:无法保证 socket 仅 owner 可访问,不提供无鉴权特权面)")
		_ = ln.Close()
		_ = os.Remove(path)
		return func() {}
	}
	// 复核实际权限:umask + chmod 之后再 Stat 确认 group/other 位确为 0。个别 FS / 容器 overlay 上
	// chmod 可能"成功返回"却未真正落到 0600;控制面无鉴权,这里必须以实测权限为准 fail-closed。
	if info, err := os.Stat(path); err != nil || info.Mode().Perm()&0o077 != 0 {
		perm := "unknown"
		if info != nil {
			perm = info.Mode().Perm().String()
		}
		logrus.WithField("path", path).WithField("perm", perm).WithError(err).
			Error("[control] socket 权限复核未通过(group/other 仍可访问),管理面拒绝启动(fail-closed)")
		_ = ln.Close()
		_ = os.Remove(path)
		return func() {}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/status", controlHandleStatus(gw))
	mux.HandleFunc("/reload", controlHandleReload(gw))
	mux.HandleFunc("/kick", controlHandleKick(gw))
	mux.HandleFunc("/rate/refresh", controlHandleRateRefresh(gw))
	mux.HandleFunc("/users/rate/refresh", controlHandleUserRateRefresh(gw))
	// M1(2026-05-24):轻量 endpoint 只返 rate_config(toml/settings/burst),不组装
	// sessions[]。web 的 settings 跟 device_detail 高频拉这个就够,免去 O(N_conn) 拼装。
	mux.HandleFunc("/rate/config", controlHandleRateConfig(gw))

	// A4(2026-05-26):轻量 endpoint 只返 VPN 字节计数。/sysmon 前端 2s 一次,
	// 比 /status?limit=1(server 仍要拼 1 个 session 元素 + sort 全 N 算 SessionsTotal)
	// 更便宜。N=10K 时 /status?limit=1 大概 ~5ms,这条 endpoint < 10µs。
	mux.HandleFunc("/sysmon/counters", controlHandleSysmonCounters())

	// FRP 反向端口转发运行态:web 后台端口转发列表页读它,把每条映射的真实状态(listening /
	// bind_failed / route_degraded)回填到 UI —— 让「配置了但没真正生效」(端口占用/路由没装上)可见。
	mux.HandleFunc("/portforward/status", controlHandlePortForwardStatus())

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go safeGlobalGoroutine("controlSocket", globalContextCancel, func() {
		logrus.WithField("path", path).Info("[control] 管理面 socket 已就绪")
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			logrus.WithError(err).Warn("[control] socket Serve 退出")
		}
	})

	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = ln.Close()
		_ = os.Remove(path) // 避免下次启动时 bind 报 "address already in use"
	}
}

// prepareControlSocketPath 确保父目录存在 + socket 文件不残留。
func prepareControlSocketPath(path string) error {
	if path == "" {
		return errors.New("control socket path is empty")
	}
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		// 记录目录是否由我们新建:新建的才收紧到 0700。**不**擅自 chmod 已存在的目录——
		// 它可能是 /run(systemd RuntimeDirectory,常 0755 root-owned)或 /tmp(1777),强改会
		// 误伤其它服务/整机;已存在目录只做下面的 fail-closed 权限校验。Stat 与 MkdirAll 间的
		// TOCTOU 只影响"是否 chmod",无安全后果(最终以 fail-closed 校验为准)。
		_, statErr := os.Stat(dir)
		createdByUs := os.IsNotExist(statErr)
		if err := os.MkdirAll(dir, controlSocketDirMode); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
		if createdByUs {
			// 第四轮深扫 LOW(e_ctrl_dir):chmod 错误不再吞掉。新建目录必须能收紧到 0700,
			// 否则无鉴权控制面的"父目录也受控"前提不成立 → fail-closed 拒绝启动。
			if err := os.Chmod(dir, controlSocketDirMode); err != nil {
				return fmt.Errorf("chmod control socket dir %s to %#o: %w", dir, controlSocketDirMode, err)
			}
		}
		// fail-closed:控制面 socket 无鉴权,靠 0600 socket 文件把关;但若**父目录**可被 group/other
		// 写入且无 sticky 位,本地非 owner 用户能 unlink 我们的 socket 再在同路径 squat 一个自己的
		// listener —— 后续管理员 CLI 连上去就把 reload/kick/rate 等特权指令发给了攻击者的进程(路径
		// 抢占 / 潜在中间人),或纯粹 DoS 掉管理面。这里以实测目录权限为准,不安全即拒绝启动管理面
		// (与下方 socket 文件权限复核同口径)。
		info, serr := os.Stat(dir)
		if serr != nil {
			return fmt.Errorf("stat control socket dir %s: %w", dir, serr)
		}
		if !controlSocketDirPermSafe(info.Mode()) {
			return fmt.Errorf("control socket 父目录 %s 权限不安全(%s):group/other 可写且未设 sticky 位,"+
				"拒绝在其中放置无鉴权管理面 socket(改成 owner-only 0700,或用带 sticky 的目录)", dir, info.Mode())
		}
	}
	// 上次没退干净留下的 socket 文件:Listen("unix") 会因 EADDRINUSE 失败;
	// unlink 之前先 stat 确认这是 socket(避免误删运维误放的同名文件)。
	if info, err := os.Stat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("control socket path %s already exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("unlink stale socket %s: %w", path, err)
		}
	}
	return nil
}

// controlSocketDirPermSafe 判定承载**无鉴权**控制面 socket 的父目录权限是否安全(e_ctrl_dir)。
//
// 允许 group/other 的 r/x —— 目录可读/可遍历本身无害,真正把关的是 socket 文件的 0600;
// **禁止** group/other 写,除非目录设了 sticky 位(如 /tmp 的 1777):sticky 下非 owner 无法
// unlink/rename 他人文件,socket 抢占不成立,故视为安全。
func controlSocketDirPermSafe(m os.FileMode) bool {
	if m&0o022 == 0 {
		return true // group/other 均不可写
	}
	return m&os.ModeSticky != 0 // 有写位:仅 sticky 才安全
}

// controlSessionInfo:GET /status 返回的单条会话信息。
//
// 2026-05-23 增字段 DeviceID / DeviceUUID:给 nanotun-web 的「在线会话」页面 join
// 出 device 的 device_name / platform / fixed_vip。两字段都可能为空(客户端未上报
// 合法 device_uuid 或 UpsertDevice 失败时),前端拿到 "" 表示「匿名会话」即可。
//
// 0012(2026-05-23)增 LinkRateUpBPS / LinkRateDownBPS / LinkBurstBytes:
// 从 rlConn.snapshotLimits() 取「当前生效」的 link-level cap(min(device, settings, toml, user) 之后),
// 与 BWUpBPS/BWDownBPS(只是 user-level snapshot)分开 — 后者是登录时凝固的 user 字段,
// 前者是 admin 任何时候改任意层热更后的真实生效值。0 = 不限。
type controlSessionInfo struct {
	ConnIDStr   string   `json:"conn_id"`
	UserID      string   `json:"user_id"`
	DeviceID    int64    `json:"device_id,omitempty"`
	DeviceUUID  string   `json:"device_uuid,omitempty"`
	VIPs        []string `json:"vips,omitempty"`
	CreatedAt   int64    `json:"created_at"`
	ExitAllowed bool     `json:"exit_allowed"`
	BWUpBPS     int64    `json:"bw_up_bps,omitempty"`
	BWDownBPS   int64    `json:"bw_down_bps,omitempty"`
	// M3(2026-05-24):link_ready 区分「数据面 limiter 已建立」vs「登录路径还没走到
	// c.rlConn 写入」。后者亚毫秒窗口内 LinkRate* 字段都是 0,但 0 在限速语义里 = 不限,
	// 运维 dashboard 拉到看 link_rate_up_bps=0 会误以为这条 conn 完全无 cap,
	// 实际是数据面尚未建立。link_ready=false 时 LinkRate* 字段不参考。
	LinkReady       bool  `json:"link_ready"`
	LinkRateUpBPS   int64 `json:"link_rate_up_bps,omitempty"`
	LinkRateDownBPS int64 `json:"link_rate_down_bps,omitempty"`
	LinkBurstBytes  int   `json:"link_burst_bytes,omitempty"`
}

// controlRateConfig:GET /status.rate_config — server 当前生效的「全局限速三件套」。
// 给 web 设置页展示「toml fallback 到底是多少」「burst 现在是多少」用,免去前端再去
// 拉 toml / settings 自己算。0 = 不限 / 沿用更下一层。
type controlRateConfig struct {
	// SettingsUpBPS / SettingsDownBPS / SettingsBurst:app_settings 当前值(可热改)。
	SettingsUpBPS   int64 `json:"settings_up_bps"`
	SettingsDownBPS int64 `json:"settings_down_bps"`
	SettingsBurst   int64 `json:"settings_burst_bytes"`
	// TomlUpBPS / TomlDownBPS:toml [server].upload_rate/download_rate(没设则取 [kcp] 兜底),
	// 是 settings=0 时的 fallback。运维清 settings 看不到「实际还有 toml 撑底」就在这。
	TomlUpBPS   int64 `json:"toml_up_bps"`
	TomlDownBPS int64 `json:"toml_down_bps"`
	// EffectiveBurst:settings.burst 走 effectiveBurst 计算后的最终值(默认 64 KiB)。
	EffectiveBurst int `json:"effective_burst_bytes"`
}

// controlStatusResp:GET /status 顶层结构。
//
// 分页(2026-05-24):?offset=X&limit=N 控制 sessions[] 返回窗口。
//
//   - 不带 limit:全量返回(老 dashboard 兼容)。
//   - 带 limit:返回 [offset, offset+limit) 这一段;sessions_total 给出筛选后总数,
//     方便客户端做翻页。conn_count 始终是全局总数(不受 filter / offset / limit
//     影响),给出 server 级总览。
type controlStatusResp struct {
	OK            bool   `json:"ok"`
	TUNReady      bool   `json:"tun_ready"`
	StoreReady    bool   `json:"store_ready"`
	ServerVersion string `json:"server_version"`
	Uptime        string `json:"uptime,omitempty"`
	ConnCount     int    `json:"conn_count"`
	// SessionsTotal:filter(device_id 过滤)之后的总数。无 filter 时 == ConnCount;
	// 有 filter 时 == 该 filter 命中数。分页时客户端用 SessionsTotal 算翻页范围,
	// 用 Sessions 实际渲染本页。
	SessionsTotal int `json:"sessions_total"`
	// SessionsOffset / SessionsLimit:本次返回窗口的入参快照,方便客户端跟自己
	// 的请求对齐(尤其是 limit 被 server clamp 上限的情况)。
	// SessionsLimit=0 表示「全量」(老兼容路径,客户端不带 limit)。SessionsOffset
	// 不 omitempty 是因为 offset=0 是常见入参,展示 0 比省略对运维更清晰。
	SessionsOffset int                  `json:"sessions_offset"`
	SessionsLimit  int                  `json:"sessions_limit"`
	Sessions       []controlSessionInfo `json:"sessions"`
	// RaceWindowTotal(可观测, 2026-05-24):safeRLConn() 返回 nil 累计次数,
	// 代表 N38 类「c 已进 map 但 rlConn 还没写」窗口期被撞中的次数。
	// 一般预期 0;非 0 可定量评估 race 在生产实际出现频率,Prometheus 抓为
	// race_window_total 指标。
	RaceWindowTotal uint64 `json:"race_window_total"`
	ACLDropTotal    uint64 `json:"acl_drop_total"`
	ACLExitDrops    uint64 `json:"acl_exit_drops"`
	ExitGateDrops   uint64 `json:"exit_gate_drops"`
	MeshOffDrops    uint64 `json:"mesh_off_drops"`
	MeshEnabled     bool   `json:"mesh_enabled"`
	UserKickTotal   uint64 `json:"user_invalidate_kicks"`
	// 2026-05-23:同 device_uuid 重登触发的踢旧次数(语义见 supersede.go 顶部注释)。
	SessionSupersedeTotal uint64              `json:"session_supersede_total"`
	LeaseGCTotal          uint64              `json:"lease_gc_total"`
	MagicDNS              MagicDNSStats       `json:"magic_dns,omitempty"`
	RouteAdvertise        RouteAdvertiseStats `json:"route_advertise,omitempty"`

	// ExitNode:出口节点选择(控制面)+ 转发(数据面)计数。出口 = approved 0/0 子网路由的特例,
	// 数据面已落地(见 ExitNodeDataplaneEnabled),与下方「任意 CIDR subnet route 数据面」相互独立。
	ExitNode ExitNodeStats `json:"exit_node,omitempty"`

	// A3:subnet route 数据面已落地(SR-M1)。client/server 控制面能 advertise + approve,
	// 数据面 forwarding 也已把任意 approved 非 0/0 CIDR 转发给宣告方会话(出口 0/0 特例见 ExitNode)。
	// 设成常量 true(见 routeDataplaneEnabled),前端 admin UI / 巡检脚本据此知道"approved == 真正生效"。
	RouteAdvertiseDataplaneEnabled bool `json:"route_advertise_dataplane_enabled"`

	// ExitNodeDataplaneEnabled:出口节点(approved 0/0)数据面转发是否已接入。已落地 = true
	// (M2:forwardPacketToExitNode)。
	ExitNodeDataplaneEnabled bool `json:"exit_node_dataplane_enabled"`

	// SubnetRoute:任意 CIDR 子网路由数据面(SR-M1)转发计数 + 当前生效的已批准非 0/0 路由条数。
	SubnetRoute SubnetRouteStats `json:"subnet_route,omitempty"`

	// RateConfig:0012 — server 当前生效的全局限速三件套(settings + toml fallback + burst)。
	// 给前端 settings 页 / debug 用,sessions 单条的 LinkRate* 是这里的 min 之后值。
	RateConfig controlRateConfig `json:"rate_config"`

	// V1(2026-05-26):VPN 业务流量累计字节(rateLimitedConn Read/Write 全埋点)。
	// 重启清零。前端 /sysmon 用差分算速度,跟宿主机网卡(/proc/net/dev)做对比能
	// 看出加密/复用 overhead。方向语义对齐 settings.rate_up_* / rate_down_*:
	//   up   = 客户端上传 = server 从 link 读出
	//   down = 客户端下载 = server 向 link 写入
	VPNBytesUp   uint64 `json:"vpn_bytes_up"`
	VPNBytesDown uint64 `json:"vpn_bytes_down"`
}

// routeDataplaneEnabled:任意 CIDR subnet route 数据面 forwarding 是否已接入。
// SR-M1 已落地(forwardPacketToSubnetRoute + 已批准子网路由表),置 true —— admin approved 的非 0/0 CIDR
// 现在会真正把使用方流量转发给宣告方会话(由其本机转进 LAN,SR-M2)。前端 admin UI / 巡检脚本据此知道
// 「approved == 真正生效」。出口 0/0 特例另见 exitNodeDataplaneEnabled。
const routeDataplaneEnabled = true

// exitNodeDataplaneEnabled:出口节点(approved 0/0/::/0)数据面转发已落地(M2:forwardPacketToExitNode)。
// 出口是 0/0 的特例(转进公网);任意 CIDR 的 subnet route 数据面见 routeDataplaneEnabled(同样已落地)。
const exitNodeDataplaneEnabled = true

var controlStartTime = time.Now()

func controlHandleStatus(gw *gatewayState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// mesh_enabled 直接从当前 ACL snapshot 取(reload 时已凝固),不再二次查 DB,
		// 避免 status 接口因 DB 抖动失败 — 数据面真实生效值就是 snapshot 里这个。
		meshOn := true
		if snap := aclCurrent.Load(); snap != nil {
			meshOn = snap.meshEnabled
		}
		resp := controlStatusResp{
			TUNReady:                       sharedTUN != nil,
			StoreReady:                     gw == nil || gw.store == nil || gw.store.DB() != nil,
			ServerVersion:                  serverVersion,
			Uptime:                         time.Since(controlStartTime).Round(time.Second).String(),
			ACLDropTotal:                   aclDropCount.Load(),
			ACLExitDrops:                   aclExitDropCount.Load(),
			ExitGateDrops:                  exitGateDropCount.Load(),
			MeshOffDrops:                   meshOffDropCount.Load(),
			MeshEnabled:                    meshOn,
			UserKickTotal:                  userInvalidateKickCount.Load(),
			SessionSupersedeTotal:          sessionSupersedeCount.Load(),
			LeaseGCTotal:                   leaseGCCount.Load(),
			MagicDNS:                       snapshotMagicDNSStats(),
			RouteAdvertise:                 snapshotRouteAdvStats(),
			RouteAdvertiseDataplaneEnabled: routeDataplaneEnabled,
			ExitNode:                       snapshotExitNodeStats(),
			ExitNodeDataplaneEnabled:       exitNodeDataplaneEnabled,
			SubnetRoute:                    snapshotSubnetRouteStats(),
		}
		resp.OK = resp.TUNReady && resp.StoreReady

		// 0012:全局限速三件套(settings + toml + effective burst)统一暴露。
		// M1(2026-05-24):buildRateConfig helper 与 /rate/config 共享,避免漂移。
		resp.RateConfig = buildRateConfig(r.Context(), gw)

		// V1(2026-05-26):VPN 字节计数器,/sysmon 前端做差分算速度。
		// 跟下方 sessions 一样在锁外读 — atomic.Uint64.Load 无锁。
		resp.VPNBytesUp = vpnBytesUp.Load()
		resp.VPNBytesDown = vpnBytesDown.Load()

		// 0012 query 过滤:?device_id=X 时只回该 device 的 sessions(其它字段照常返回)。
		// web 改 fixed_vip 时只想知道这个 device 的活跃会话,拉全量 N 千条 JSON 浪费;
		// 留全量行为(无 query 时)给 dashboard / 巡检脚本兼容。
		// N22:非数字 → 400,避免拼错时静默回退到全量(影响 dashboard 数据 + 浪费 IO)。
		var filterDeviceID int64
		if q := r.URL.Query().Get("device_id"); q != "" {
			v, err := stringToInt64(q)
			if err != nil || v < 0 {
				http.Error(w, "device_id 必须是非负整数,空 = 全量返回", http.StatusBadRequest)
				return
			}
			filterDeviceID = v
		}

		// 分页(2026-05-24 → 2026-05-25 Q1+Q2 加固):?offset=&limit= 切窗口。
		//
		//   - 不带 limit:全量(老 dashboard 兼容)。
		//   - 带 limit:[offset, offset+limit) 切片。limit 硬上限 statusPageLimitMax
		//     防 DoS(运维拼错 limit=999999 一次拉穷 server)。
		//   - offset > 0 但无 limit:Q2 强校验 400 — 静默忽略 offset 会让运维拼错
		//     命令时拿到「以为是 offset=100 那一页,其实是全量」的错觉,显式失败更安全。
		//   - offset 越界:返回空 sessions[] + 正确 SessionsTotal,客户端自行处理。
		var offset, limit int
		offsetGiven := false
		if q := r.URL.Query().Get("offset"); q != "" {
			v, err := stringToInt64(q)
			if err != nil || v < 0 {
				http.Error(w, "offset 必须是非负整数", http.StatusBadRequest)
				return
			}
			offset = int(v)
			offsetGiven = true
		}
		if q := r.URL.Query().Get("limit"); q != "" {
			v, err := stringToInt64(q)
			if err != nil || v <= 0 {
				http.Error(w, "limit 必须是正整数;不传 = 全量", http.StatusBadRequest)
				return
			}
			limit = int(v)
			if limit > statusPageLimitMax {
				limit = statusPageLimitMax
			}
		}
		// Q2(2026-05-25):offset 单传无 limit 是误用。如果想要「跳过前 N 条」语义,
		// 必须配合 limit 才有翻页含义;不配 limit 全量返回的话,offset 字段被静默吞,
		// 客户端看 sessions_offset=0 误以为没生效。显式 400 比 silent 好。
		if offsetGiven && offset > 0 && limit == 0 {
			http.Error(w, "offset 必须配合 limit 一起传(独传 offset 没有翻页语义)", http.StatusBadRequest)
			return
		}

		// R1(2026-05-26):RLock 内只快速收集指针,RUnlock 之后做 sort + build info。
		// 锁持有时间从 ~5.5ms(N=10K) 降到 ~50µs,期间登录路径的 Lock() 不被阻塞。
		//
		// 锁外读 c 字段的安全性:
		//
		//   c.connIDStr / userID / deviceID / deviceUUID / createdAt / exitAllowed /
		//   bw*BPS / clientIPs  ← 登录路径一次写,生命周期只读,GC 保证 matched 持有
		//                          指针时 conn 对象不被回收。
		//   c.safeRLConn()      ← atomic.Pointer.Load,定义上无锁安全。
		//
		// 容忍 conn 在 RUnlock 后被 cleanupConnection close:read 到的是 close 之前的
		// snapshot,不影响 dashboard 展示一瞬间的快照视图(下次刷新就消失)。
		connIDMapMu.RLock()
		resp.ConnCount = len(connIDMap)
		matched := make([]*Connection, 0, resp.ConnCount)
		for _, c := range connIDMap {
			if c == nil {
				continue
			}
			if filterDeviceID > 0 && c.deviceID != filterDeviceID {
				continue
			}
			matched = append(matched, c)
		}
		connIDMapMu.RUnlock()

		// R2(2026-05-26):排序策略 = created_at DESC + conn_id ASC 二级稳定。
		//
		// 历史:Q1(2026-05-25)第一版只按 connIDStr 字典序排,保证翻页稳定。但
		// dashboard 用 WithLimit(10) 拿前 10 条想要「最新会话」时,拿到的是
		// 「conn_id 字典序前 10 条」 — 跟「最新连接」毫无关系,UX 破功。
		//
		// 现在策略:
		//
		//   primary:   c.createdAt 倒序(最新连接靠前)  ← 给 dashboard 用
		//   secondary: c.connIDStr 字典序                 ← 同秒并发连接 tiebreaker
		//
		// 两个 key 一起保证:
		//   a) dashboard 拉前 N 拿到全局最新 N 条;
		//   b) 翻页跨次调用仍稳定(只要 conn 集合 + createdAt 没变,顺序固定)。
		//
		// 排序代价 O(N log N),N=10K 时 ~500µs,锁外执行不影响登录。
		sort.Slice(matched, func(i, j int) bool {
			ai, aj := matched[i].createdAt, matched[j].createdAt
			if !ai.Equal(aj) {
				return ai.After(aj)
			}
			return matched[i].connIDStr < matched[j].connIDStr
		})
		resp.SessionsTotal = len(matched)
		// 算窗口 [start, end)。limit==0 表示全量(等价于 [0, len(matched)))。
		start, end := 0, len(matched)
		if limit > 0 {
			start = offset
			if start > len(matched) {
				start = len(matched)
			}
			end = start + limit
			if end > len(matched) {
				end = len(matched)
			}
			resp.SessionsOffset = offset
			resp.SessionsLimit = limit
		}
		for _, c := range matched[start:end] {
			info := controlSessionInfo{
				ConnIDStr:   c.connIDStr,
				UserID:      c.userID,
				DeviceID:    c.deviceID,
				DeviceUUID:  c.deviceUUID,
				CreatedAt:   c.createdAt.Unix(),
				ExitAllowed: c.exitAllowed,
				BWUpBPS:     c.bwUpBPS,
				BWDownBPS:   c.bwDownBPS,
			}
			// N38(2026-05-23 → 2026-05-24 atomic.Pointer):c.rlConn 写后进 map 有
			// 窗口期。safeRLConn 内部 atomic.Load,Go memory model 保证 happens-before,
			// 零锁。M3:link_ready 显式区分「未建立」vs「无 cap」。
			if rl := c.safeRLConn(); rl != nil {
				up, down, ub, db := rl.snapshotLimits()
				info.LinkReady = true
				info.LinkRateUpBPS = up
				info.LinkRateDownBPS = down
				// burst 两方向理论相同(都从 effectiveBurst 算),展示用上行;
				// 万一未来分方向,运维去 logs 看,这里只保留一个字段省 JSON 体积。
				info.LinkBurstBytes = ub
				_ = db
			}
			// S1(2026-05-26):走 safeClientIPs() — atomic.Pointer.Load 锁外安全。
			// 登录路径 c.clientIPs.Store(...) 与本 Load 之间有 Go memory model 保证的
			// happens-before,Load 后 range 不会撕裂切片 header。
			for _, a := range c.safeClientIPs() {
				if a.VirtualIP != "" {
					info.VIPs = append(info.VIPs, a.VirtualIP)
				}
			}
			resp.Sessions = append(resp.Sessions, info)
		}
		// race counter 必须在 sessions 遍历**之后**读 — 遍历内的 safeRLConn() 调用
		// 才会 +1 我们本次新触发的 nil 路径,提前读拿不到这次的增量。
		resp.RaceWindowTotal = safeRLConnNilCount.Load()

		w.Header().Set("Content-Type", "application/json")
		if !resp.OK {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// buildRateConfig 组装当前 server 全局限速三件套(toml fallback + settings + effective burst)。
// /status 与 /rate/config 共享,避免两条路径漂移。
//
// gw==nil 或各分支失败时按零值降级,前端拿到全 0 时凭 effective_burst_bytes>0 判
// 「server 跟 store 起码有一边能拉到」。ctx 控超时(各分支独立 3s),caller 给 request ctx。
func buildRateConfig(ctx context.Context, gw *gatewayState) controlRateConfig {
	rateCfg := controlRateConfig{}
	if gw != nil && gw.cfg != nil {
		tomlUp, tomlDown := linkRatesForPlatform(gw, "")
		rateCfg.TomlUpBPS = int64(tomlUp)
		rateCfg.TomlDownBPS = int64(tomlDown)
	}
	if gw != nil && gw.store != nil {
		sctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		if d, err := gw.store.GetRateDefaults(sctx); err == nil {
			rateCfg.SettingsUpBPS = d.UploadBPS
			rateCfg.SettingsDownBPS = d.DownloadBPS
			rateCfg.SettingsBurst = d.BurstBytes
		}
		cancel()
	}
	rateCfg.EffectiveBurst = effectiveBurst(rateCfg.SettingsBurst)
	return rateCfg
}

// controlHandleRateConfig(M1, 2026-05-24):GET /rate/config — 轻量 endpoint。
//
// 只返 rate_config(settings + toml + effective burst),不组装 sessions[] 跟其它
// counter。web settings + device_detail 高频拉「四层 cap 兜底」时走这条,免去
// /status 路径下持 connIDMapMu.RLock 遍历全 conn 拼数组(N_conn 大时 hot)。
//
// 行为细节与 /status 内的 rate_config 字段完全一致(buildRateConfig 共享 helper)。
// /status 仍保留 rate_config 字段以保兼容(dashboard 还在用,且加一次 cap computation 几乎免费)。
func controlHandleRateConfig(gw *gatewayState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		rateCfg := buildRateConfig(r.Context(), gw)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rateCfg)
	}
}

// controlHandleSysmonCounters(A4, 2026-05-26):/sysmon/counters 轻量 endpoint。
//
// 只返 4 个字段(VPN 上下行累计字节 + uptime 秒 + ts_ms),供 nanotun-web /sysmon 页
// 2s 一次高频拉取。比走 /status?limit=1 省 ~99.9%:
//   - /status?limit=1:RLock connIDMap → 全量收集指针快照 O(N) → filter +
//     sort.Slice O(N log N) → build_info 1 个 session → JSON 拼接,N=10K 时 ~5ms;
//   - /sysmon/counters:2 次 atomic.Uint64.Load + 1 次 time.Since,< 10µs。
//
// 不复用 controlStatusResp 是为了 zero-allocation hot path — 直接 fmt 输出最小 JSON。
// 字段命名跟 /status 对齐(vpn_bytes_up / vpn_bytes_down),客户端切换不需改 unmarshal。
//
// 老 server 没本 endpoint → web 端 fallback 回 /status?limit=1(M1 同模式)。
func controlHandleSysmonCounters() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		// 直接 fmt.Fprintf 输出最小 JSON,避免 encoding/json struct 反射开销。
		// 字段顺序对客户端 unmarshal 无影响(JSON object 无序)。
		fmt.Fprintf(w,
			`{"ts_ms":%d,"uptime_seconds":%d,"vpn_bytes_up":%d,"vpn_bytes_down":%d}`,
			time.Now().UnixMilli(),
			int64(time.Since(controlStartTime).Seconds()),
			vpnBytesUp.Load(),
			vpnBytesDown.Load(),
		)
	}
}

// controlHandlePortForwardStatus:GET /portforward/status — 返回所有 FRP 端口转发映射的运行态快照。
// 只读、无副作用(不触发 reload),供 web 端口转发列表页按 public_port join 到 DB 行、展示实时状态。
func controlHandlePortForwardStatus() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":       true,
			"forwards": portForwardStatusSnapshot(),
		})
	}
}

// controlHandleReload 接 POST /reload?what=acl;目前仅支持 acl,未来可扩 log_level 等。
func controlHandleReload(gw *gatewayState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		what := r.URL.Query().Get("what")
		if what == "" {
			what = "acl"
		}
		switch what {
		case "acl":
			if gw == nil || gw.store == nil {
				http.Error(w, "store not initialized", http.StatusServiceUnavailable)
				return
			}
			n, err := reloadACLSnapshotFromStore(gw.store)
			if err != nil {
				http.Error(w, "reload acl: "+err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "what": "acl", "rules": n})
		case "exits":
			// exit-node:admin 改了出口批准(designate/revoke/route approve/reject/delete)后调用,让运行中的 server 即时:
			//   ① 复核所有「已绑定出口」的会话——绑定的设备若已不再被批准(撤销)→ 原子重置回 server 自出口 + 通知客户端
			//     (修「撤销对正在用的会话不实时生效」的 gap);
			//   ② 重算并广播「可选出口列表」给所有 exit_allowed 客户端(顺带修「admin 新批准不即时推送到下拉」)。
			if gw == nil || gw.store == nil {
				http.Error(w, "store not initialized", http.StatusServiceUnavailable)
				return
			}
			reset := revalidateExitBindings(r.Context())
			broadcastExitsList(r.Context())
			// exit-node（宣告方审批回显）：admin 批准 / 撤销 0/0 出口后，把审批态实时推回**宣告方**设备，
			// 使其「作为出口节点」UI 从「待审批」翻到「已批准 / 已拒绝」，无需宣告方重连。使用方下拉由上面的
			// broadcastExitsList 负责；本推送面向宣告方自身状态显示。
			broadcastRouteApproveStatusToAdvertisers(r.Context())
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "what": "exits", "rebound_to_server": reset})
		case "routes":
			// subnet route(SR-M1):admin 改了子网路由批准(route approve/reject/delete 非 0/0 CIDR)后调用,让运行中
			// 的 server 即时重建「已批准子网路由表」—— per-packet 最长前缀匹配的数据源。低频;不重建则改动要等下次
			// 启动 / 任意触发重建才生效(approved 已入库,数据面会在重建后收敛)。
			if gw == nil || gw.store == nil {
				http.Error(w, "store not initialized", http.StatusServiceUnavailable)
				return
			}
			rebuildSubnetRouteTable(r.Context())
			// SR-M3:新批准/撤销的子网路由即时推给所有客户端（请求方据此增删 TUN 路由）。
			broadcastRoutesList(r.Context())
			// subnet route（宣告方审批回显）：把审批态实时推回**宣告方**设备，使其「作为子网路由器」UI 从
			// 「待审批」翻到「已批准 / 已拒绝」，无需重连。请求方可用列表由上面的 broadcastRoutesList 负责。
			broadcastRouteApproveStatusToAdvertisers(r.Context())
			n := 0
			if tbl := subnetRouteTable.Load(); tbl != nil {
				n = len(*tbl)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "what": "routes", "routes": n})
		case "portforward":
			// FRP 反向端口转发：admin 在 web 后台增删映射后调用，让运行中的 server 即时按最新 enabled 映射启停
			// 公网端口监听（见 cmd/nanotund/port_forward.go）。管理器未启用（无 store）时 reloadPortForwards 返回 0。
			n := reloadPortForwards(r.Context())
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "what": "portforward", "active": n})
		default:
			http.Error(w, "unknown reload target: "+what, http.StatusBadRequest)
		}
	}
}

// controlKickReq:POST /kick body。
//
// Kind 取值:
//   - "session" + ID = connIDStr        踢一条会话
//   - "device"  + ID = "<device_uuid>"  踢该 device 上所有会话
//   - "user"    + ID = "u<userID>" 或 username   踢该 user 所有会话
type controlKickReq struct {
	Kind   string `json:"kind"`
	ID     string `json:"id"`
	Reason string `json:"reason,omitempty"`
}

type controlKickResp struct {
	OK      bool     `json:"ok"`
	Kicked  int      `json:"kicked"`
	ConnIDs []string `json:"conn_ids,omitempty"`
	Reason  string   `json:"reason,omitempty"`
}

func controlHandleKick(gw *gatewayState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req controlKickReq
		r.Body = http.MaxBytesReader(w, r.Body, controlMaxBodyBytes)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.Reason == "" {
			req.Reason = "kicked_by_admin"
		}
		targetUserID := int64(0)
		matchKind := strings.ToLower(req.Kind)

		// 把 device / user 形态规范成「conn 选择函数」,session 直接按 connIDStr 精确匹配。
		var picker func(c *Connection) bool
		switch matchKind {
		case "session":
			id := req.ID
			picker = func(c *Connection) bool { return c.connIDStr == id }
		case "device":
			// 2026-05-23:Connection.deviceID / deviceUUID 已就位(P2#12 + 0011),
			// kick by device 真正落地。req.ID 接受两种格式:
			//   - 纯数字字符串 → 当 devices.id (int64) 比对 c.deviceID;
			//   - 其它(典型是 RFC 4122 v4)→ 小写归一后比对 c.deviceUUID。
			//
			// 用法场景:web 改完 fixed_vip 后想立刻让客户端拿新 IP 时,以 device 维度
			// kick;CLI `nanotun-admin kick device <id>` 也走这条路径。
			raw := strings.TrimSpace(req.ID)
			if raw == "" {
				http.Error(w, "device id 不能为空", http.StatusBadRequest)
				return
			}
			if did, err := stringToInt64(raw); err == nil && did > 0 {
				picker = func(c *Connection) bool { return c.deviceID == did }
			} else {
				uuidNorm := strings.ToLower(raw)
				picker = func(c *Connection) bool { return c.deviceUUID == uuidNorm }
			}
		case "user":
			uid, ok := resolveControlKickUser(r.Context(), gw, req.ID)
			if !ok {
				http.Error(w, "user not found: "+req.ID, http.StatusNotFound)
				return
			}
			targetUserID = uid
			picker = func(c *Connection) bool { return parseUserIDStr(c.userID) == uid }
		default:
			http.Error(w, "unknown kind: "+req.Kind, http.StatusBadRequest)
			return
		}

		// P3-a:user/session 两类有 O(1) 索引,优先走快速路径;只有 fallback 时全表扫描。
		var victims []*Connection
		switch matchKind {
		case "session":
			connIDMapMu.RLock()
			if c, ok := connIDMap[req.ID]; ok && c != nil {
				victims = append(victims, c)
			}
			connIDMapMu.RUnlock()
		case "user":
			connIDMapMu.RLock()
			victims = byUserSnapshotLocked(userIDFromStoreID(targetUserID))
			connIDMapMu.RUnlock()
		default:
			connIDMapMu.RLock()
			for _, c := range connIDMap {
				if c != nil && picker(c) {
					victims = append(victims, c)
				}
			}
			connIDMapMu.RUnlock()
		}

		resp := controlKickResp{Reason: req.Reason}
		ctx := r.Context()
		for _, c := range victims {
			uid := parseUserIDStr(c.userID)
			if matchKind == "user" && uid == 0 {
				uid = targetUserID
			}
			kickConnForUserInvalidate(ctx, gw, c, uid, req.Reason)
			resp.Kicked++
			resp.ConnIDs = append(resp.ConnIDs, c.connIDStr)
		}
		resp.OK = true

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// resolveControlKickUser 把 "u<id>" / 数字 id / username 都映射成 int64。
func resolveControlKickUser(ctx context.Context, gw *gatewayState, raw string) (int64, bool) {
	if raw == "" {
		return 0, false
	}
	if id := parseUserIDStr(raw); id > 0 {
		return id, true
	}
	// 纯数字直接当 user_id。
	for _, ch := range raw {
		if ch < '0' || ch > '9' {
			goto byName
		}
	}
	if id, err := stringToInt64(raw); err == nil && id > 0 {
		return id, true
	}
byName:
	if gw == nil || gw.store == nil {
		return 0, false
	}
	queryCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	u, err := gw.store.GetUserByUsername(queryCtx, raw)
	if err != nil || u == nil {
		return 0, false
	}
	return u.ID, true
}

func stringToInt64(s string) (int64, error) {
	var v int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("non-digit %q", c)
		}
		d := int64(c - '0')
		// 溢出防御:此前 v=v*10+d 无上限检查,超长数字串(control socket 的 offset/limit/user_id/
		// device_id query)会环绕成负值 / 任意值 —— 可能翻页越界或误匹配到别的 user/device。
		// 到达 int64 上限即报错,由调用方回 400。
		if v > (math.MaxInt64-d)/10 {
			return 0, fmt.Errorf("value overflows int64")
		}
		v = v*10 + d
	}
	return v, nil
}

// controlRateRefreshReq:POST /rate/refresh body / query 字段。
//
// 用法:
//   - device_id > 0 → 只刷该 device 上的 active conn(per-device 限速改后调用);
//   - device_id == 0 → 全量刷所有 conn(settings.rate_default_* 改后调用)。
//
// 不带任何 conn / lease 鉴权(本接口是 unix socket + root-only,信任「能 read 这个 socket 就是管理员」)。
type controlRateRefreshReq struct {
	DeviceID int64 `json:"device_id"`
}

type controlRateRefreshResp struct {
	OK        bool   `json:"ok"`
	Refreshed int    `json:"refreshed"`
	Scope     string `json:"scope"` // "device:<id>" / "all"
}

// applyConnRateLimit 把多层 effective rate(device → settings → toml → user)算出来
// 后,通过 safeRLConn 短锁拿 rlConn 副本,然后调 SetUploadLimit/SetDownloadLimit
// 落到底层 *rate.Limiter。
//
// 这个 helper 是 /rate/refresh 跟 /users/rate/refresh 的公共体(N2 去重):
//   - /rate/refresh 调用前自己 GetDevice 拿最新 devUp/devDown,userUp/userDown
//     传 c.bwUpBPS/c.bwDownBPS(登录快照);
//   - /users/rate/refresh 调用前先 GetUser 拿最新 userUp/userDown,devUp/devDown
//     传 c.deviceRateUpBPS/DownBPS(登录快照,本接口聚焦 user 维度)。
//
// 返回 true 表示真刷到了 limiter;返回 false 表示 c 还没建立数据面或已 close
// (safeRLConn() 返回 nil)、被 takeover、c 为 nil 等可跳过场景。
func applyConnRateLimit(
	c *Connection,
	gw *gatewayState,
	devUp, devDown int64,
	defaults storeRateDefaultsView,
	userUp, userDown int64,
	burst int,
) bool {
	if c == nil {
		return false
	}
	// N20:被 takeover 的 oldConn 在 cleanup 完成前可能仍在 connByUser 索引,对它调
	// SetUploadLimit 是无效的(rlConn 马上会被 close)。提前跳过省一次锁 + audit 准确。
	if c.takenOver.Load() {
		return false
	}
	up, down := effectiveLinkRates(gw, "", devUp, devDown, defaults)
	up = minPositiveBPS(up, userUp)
	down = minPositiveBPS(down, userDown)
	rl := c.safeRLConn()
	if rl == nil {
		return false
	}
	rl.SetUploadLimit(int64(up), burst)
	rl.SetDownloadLimit(int64(down), burst)
	return true
}

// controlHandleRateRefresh:0011(2026-05-23)。管理面改了 devices.rate_*_bps 或
// app_settings.rate_default_*_bps 之后,调一次本接口把 active conn 的 limiter 立刻
// 同步过来,免去客户端重连。
//
// 实现:
//  1. 重新读 settings(可能刚被 web/CLI 改);
//  2. body / query 取 device_id;= 0 表示全量。query 非数字 → 400(N22,避免静默
//     回退到全量,运维拼错时能立即看见报错)。
//  3. 遍历 connIDMap,选中 conn 后重查它的 Device(可能 admin 刚改完 rate_*_bps),
//     算 effectiveLinkRates,调 c.rlConn.SetUploadLimit/SetDownloadLimit;
//     N26:device_id > 0 时所有 victim 必属同一 device,提前一次性 GetDevice 缓存,
//     避免 N 条 conn 触发 N 次 SQLite 查询。
//  4. **不**回写 c.deviceRateUpBPS/DownBPS:那两个是登录快照,真正生效值由 rlConn
//     limiter 持有;无锁回写会与 takeover 路径形成 race,且收益为 0。
//  5. 审计一条 rate.refresh。
//
// 兼容:device 早就不在 conn 列表(刚下线/还没登录)时返回 refreshed=0,不报错;
//
//	c.rlConn == nil 的 conn 跳过(老路径 / 单测,不影响)。
func controlHandleRateRefresh(gw *gatewayState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if gw == nil {
			http.Error(w, "gateway not initialized", http.StatusServiceUnavailable)
			return
		}
		var req controlRateRefreshReq
		// body 允许空(全量刷)。bad json 不阻塞 — 允许走 query 兜底。
		// 第四轮深扫 MED:此前仅在 ContentLength>0 时才 MaxBytesReader;chunked / 未知长度(ContentLength==-1)
		// 会绕过上限。改为**无条件**先包 MaxBytesReader 再解码(空 body 解码得 io.EOF,被忽略,不影响 query 兜底),
		// 与 /kick 一致地封顶请求体,杜绝本地畸形调用方 memory-DoS 守护进程。
		r.Body = http.MaxBytesReader(w, r.Body, controlMaxBodyBytes)
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.DeviceID == 0 {
			// N22:query 解析失败显式 400,避免运维拼错(device_5、abc)时静默回退到
			// 全量刷,触发不必要的 N 条 conn 重算。
			if q := r.URL.Query().Get("device_id"); q != "" {
				v, err := stringToInt64(q)
				if err != nil || v < 0 {
					http.Error(w, "device_id 必须是非负整数,空 = 全量刷", http.StatusBadRequest)
					return
				}
				req.DeviceID = v
			}
		}

		// 读最新 settings;失败按零值降级,逻辑等价于「settings 层不强制」。
		// 0012:burst 一起读出来,SetUploadLimit/SetDownloadLimit 共用同一 effective burst。
		defaults := storeRateDefaultsView{}
		if gw.store != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
			defer cancel()
			if d, err := gw.store.GetRateDefaults(ctx); err == nil {
				defaults = storeRateDefaultsView{UploadBPS: d.UploadBPS, DownloadBPS: d.DownloadBPS, BurstBytes: d.BurstBytes}
			}
		}
		burst := effectiveBurst(defaults.BurstBytes)

		// 选受影响 conn:整个流程持读锁,c.deviceID 是登录路径**写一次**后只读字段,
		// 持 RLock 期间不会改。c.rlConn 的并发读放到 applyConnRateLimit → safeRLConn,
		// 短锁 c.linkWrMu(N38 race 防御)。
		var victims []*Connection
		connIDMapMu.RLock()
		for _, c := range connIDMap {
			if c == nil {
				continue
			}
			if req.DeviceID > 0 && c.deviceID != req.DeviceID {
				continue
			}
			victims = append(victims, c)
		}
		connIDMapMu.RUnlock()

		// N26:device_id > 0 时所有 victim 必属同一 device,一次性 GetDevice 缓存。
		// device_id == 0(全量)时按 deviceID 缓存到 map,跨 conn 复用查询结果(同
		// device 上 N 条 conn 只查 1 次)。失败键也缓存(用 nil),避免反复重试。
		type devSnap struct {
			up, down int64
		}
		devCache := make(map[int64]devSnap, 8)
		getDev := func(c *Connection) (int64, int64) {
			if c.deviceID == 0 || gw.store == nil {
				// 匿名 conn 或 store 不可用 → 沿用登录快照。
				return c.deviceRateUpBPS, c.deviceRateDownBPS
			}
			if v, ok := devCache[c.deviceID]; ok {
				return v.up, v.down
			}
			up, down := c.deviceRateUpBPS, c.deviceRateDownBPS
			ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
			if d, err := gw.store.GetDevice(ctx, c.deviceID); err == nil && d != nil {
				up, down = d.RateUploadBPS, d.RateDownloadBPS
			}
			cancel()
			devCache[c.deviceID] = devSnap{up: up, down: down}
			return up, down
		}

		refreshed := 0
		for _, c := range victims {
			devUp, devDown := getDev(c)
			// user 维度走 conn 登录快照 c.bwUpBPS/c.bwDownBPS;真正改 user bw 由
			// /users/rate/refresh 单独刷,这里聚焦 device/settings/toml 三层。
			if applyConnRateLimit(c, gw, devUp, devDown, defaults, c.bwUpBPS, c.bwDownBPS, burst) {
				refreshed++
			}
		}

		scope := "all"
		if req.DeviceID > 0 {
			scope = fmt.Sprintf("device:%d", req.DeviceID)
		}
		// audit:谁触发(remote=control-socket-local,固定常量)+ scope + refreshed 数量。
		if gw.store != nil {
			_ = gw.store.Audit(context.Background(), "control-socket",
				"rate_refresh", scope, fmt.Sprintf("refreshed=%d", refreshed))
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(controlRateRefreshResp{
			OK: true, Refreshed: refreshed, Scope: scope,
		})
	}
}

// controlUserRateRefreshReq:POST /users/rate/refresh body / query。
type controlUserRateRefreshReq struct {
	UserID int64 `json:"user_id"`
}

// controlHandleUserRateRefresh(0012, 2026-05-23):user-level bandwidth 改了之后
// 立刻把所有该 user 下 active conn 的 limiter 同步过来。
//
// 与 /rate/refresh 区别:那条是按 device 维度刷,这条按 user 维度刷;两者都从 DB 重读
// 各自层级的最新值,再走相同的 effectiveLinkRates 重算 min,最后调 rlConn.SetUploadLimit
// 跟 SetDownloadLimit。**不**写回 Connection 上的快照字段(避免与 takeover 路径 race)。
//
// user_id == 0 → 拒绝(/rate/refresh 的全量刷已经覆盖,这条接口只为按 user 局部刷)。
func controlHandleUserRateRefresh(gw *gatewayState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if gw == nil {
			http.Error(w, "gateway not initialized", http.StatusServiceUnavailable)
			return
		}
		var req controlUserRateRefreshReq
		// 无条件封顶请求体(见 /rate/refresh 同款说明,第四轮深扫 MED):chunked/未知长度也不再绕过上限。
		r.Body = http.MaxBytesReader(w, r.Body, controlMaxBodyBytes)
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.UserID == 0 {
			// N22:query 非数字 → 400(对齐 /rate/refresh 行为)。
			if q := r.URL.Query().Get("user_id"); q != "" {
				v, err := stringToInt64(q)
				if err != nil || v < 0 {
					http.Error(w, "user_id 必须是正整数", http.StatusBadRequest)
					return
				}
				req.UserID = v
			}
		}
		if req.UserID <= 0 {
			http.Error(w, "user_id 必须 > 0(全量刷请用 /rate/refresh)", http.StatusBadRequest)
			return
		}

		// 拿该 user 最新 bandwidth_*_bps(可能 CLI 刚改完)。读失败 → 沿用 conn 上快照值,
		// 不阻塞热更其它层(等价于「user 维度本次不动」)。
		var userUp, userDown int64
		if gw.store != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
			if u, err := gw.store.GetUser(ctx, req.UserID); err == nil && u != nil {
				userUp = u.BandwidthUpBPS
				userDown = u.BandwidthDownBPS
			}
			cancel()
		}

		// settings + burst 重读;失败按零值降级。
		defaults := storeRateDefaultsView{}
		if gw.store != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
			if d, err := gw.store.GetRateDefaults(ctx); err == nil {
				defaults = storeRateDefaultsView{UploadBPS: d.UploadBPS, DownloadBPS: d.DownloadBPS, BurstBytes: d.BurstBytes}
			}
			cancel()
		}
		burst := effectiveBurst(defaults.BurstBytes)

		// 选 victim:走已有的 by-user 二级索引(O(1)),不要全表扫。
		uidStr := userIDFromStoreID(req.UserID)
		connIDMapMu.RLock()
		victims := byUserSnapshotLocked(uidStr)
		connIDMapMu.RUnlock()

		refreshed := 0
		for _, c := range victims {
			// device 层取 conn 上的登录快照(takeover 路径同步过的)。本接口聚焦 user-level
			// 热更,device-level 改请走 /rate/refresh(它会重读 devices 表)。
			if applyConnRateLimit(c, gw, c.deviceRateUpBPS, c.deviceRateDownBPS, defaults, userUp, userDown, burst) {
				refreshed++
			}
		}

		scope := fmt.Sprintf("user:%d", req.UserID)
		if gw.store != nil {
			_ = gw.store.Audit(context.Background(), "control-socket",
				"users_rate_refresh", scope, fmt.Sprintf("refreshed=%d", refreshed))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(controlRateRefreshResp{
			OK: true, Refreshed: refreshed, Scope: scope,
		})
	}
}
