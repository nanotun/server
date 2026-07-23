package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

// V1(2026-05-26):/sysmon 系统监控页面。
//
// 两个 endpoint:
//   - GET /sysmon       → 渲染 sysmon.html(Canvas 折线 + 数字概览)
//   - GET /sysmon/data  → 一次性 JSON 采样,前端 2s 轮询(setTimeout 递归 + 5s 超时)
//
// 数据组成:
//   - 宿主机 CPU / 内存 / 网卡(/proc/{stat,meminfo,net/dev},sysmon_linux.go;
//     server 端已过滤只返物理+TUN,A8)
//   - VPN 业务流量(control.sock /sysmon/counters 拿 vpn_bytes_up/down;A4,
//     老 server 无本 endpoint 时 fallback /status?limit=1)
//
// 设计选择:
//
//	a) 不在 server 端做差分算速度 — server 只暴露累计计数,差分让前端做,避免
//	   server 维护时间窗口状态(无锁、无 ringbuffer、无 GC 头疼);
//	b) A4 加了轻量 /sysmon/counters server endpoint(< 10µs),取代之前每帧调
//	   /status?limit=1(N=10K 时 ~5ms);老 server 自动 fallback,过渡兼容;
//	c) /sysmon/data 失败时返 200 + JSON {"error": "..."} 而非 5xx — 前端能直接
//	   渲染错误横幅,而不是 fetch 抛异常 / 整页崩。403/401 仍走原中间件常规路径。

// handleSysmon 渲染监控页面(纯 HTML shell,数据全部 JS 异步拉)。
//
// Nav.Active = "sysmon",顶栏菜单高亮。
func (s *Server) handleSysmon(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// 第八轮深扫 LOW:宿主机 CPU/内存/网卡 + uptime 属基础设施遥测,超出「只读业务视图」范畴,收敛到 admin。
	if !s.requireAdminRole(w, r) {
		return
	}
	s.renderPage(w, r, "sysmon.html", PageData{
		Title: tr(r, "page.sysmon.title"),
		Nav:   NavContext{Active: "sysmon"},
	})
}

// sysmonDataResp 是 /sysmon/data 的 JSON 响应。
//
// 把累计计数器交给前端:CPU / NIC / VPN 都用同一思路 — 客户端两次采样差分。
// 内存是 gauge 直接画。
type sysmonDataResp struct {
	// 时间戳(web 进程视角,host 指标采样时刻)。前端用它跟 prev.ts_ms 算 dt,
	// host 指标(CPU/Mem/NIC)是 web 进程同步读 /proc/* 拿到的,跟 ts_ms 同源
	// 时差 < 1ms,差分精度有保证。
	TimestampMS int64 `json:"ts_ms"`

	// ts_source(2026-05-26):server 进程视角时间戳(/sysmon/counters 返的)。
	// 前端跟本地 Date.now() 做 clock skew 检查 — 如果 web 跟 server 时钟偏差
	// 超过 5s 显示 banner 提示 admin "NTP 异常,差分速度可能不准"。
	//
	// 老 server fallback 路径(/status?limit=1)没该字段 → controlClient 用本地
	// time.Now() 补,此时 ServerTimestampMS == TimestampMS,clock skew = 0 不报警。
	ServerTimestampMS int64 `json:"server_ts_ms,omitempty"`

	// 宿主机指标(sysmon_linux.go);非 Linux 平台为 nil。
	Host *SysmonSnapshot `json:"host,omitempty"`

	// VPN 业务字节(从 control.sock /status 拿)。
	// VPNAvailable=false 时 server 不可达或字段缺失(老 server / control sock 没起);
	// 前端隐藏 VPN 卡片,只显宿主机。
	VPNAvailable bool   `json:"vpn_available"`
	VPNBytesUp   uint64 `json:"vpn_bytes_up,omitempty"`
	VPNBytesDown uint64 `json:"vpn_bytes_down,omitempty"`
	// A4.8(2026-05-26):server uptime 秒数,从 /sysmon/counters 拿。
	//
	// uptime_zero(2026-05-26):**不**加 omitempty — 因为 0 跟 -1 是两个不同语义:
	//   -  0:新 server 刚启动 < 1 秒(也合法)→ 前端显 "0s";
	//   - -1:老 server fallback(/status?limit=1)没该字段 → 前端显 "—";
	// omitempty 会让 0 被吞,前端拿不到、误显 "—"。-1 是 controlClient 在
	// fallback 路径主动写的 sentinel,Go JSON int64 不会因 omitempty 省略 -1。
	ServerUptimeSeconds int64 `json:"server_uptime_seconds"`

	// 错误描述。非空时前端在页面顶部展示横幅("/proc 不可读"/"control sock 断")。
	// HostError 跟 VPNError 分开,允许"只 VPN 不可用但宿主机 OK"。
	HostError string `json:"host_error,omitempty"`
	VPNError  string `json:"vpn_error,omitempty"`
}

func (s *Server) handleSysmonData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// 第八轮深扫 LOW:与 /sysmon 页面一致,遥测数据端点也收敛到 admin;非 admin 走标准 403(前端 fetch 非 200
	// 即显错误横幅,不再吐宿主机指标)。
	if !s.requireAdminRole(w, r) {
		return
	}
	resp := sysmonDataResp{
		TimestampMS: time.Now().UnixMilli(),
	}

	host, hostErr := collectSysmonSnapshot()
	if hostErr != nil {
		if errors.Is(hostErr, ErrSysmonUnsupported) {
			resp.HostError = trErr(r, ErrSysmonUnsupported)
		} else {
			resp.HostError = trErr(r, hostErr)
			logrus.WithError(hostErr).Warn("[sysmon] 采样宿主机指标失败")
		}
	}
	if host != nil {
		resp.Host = host
	}

	// VPN 字节计数器:A4(2026-05-26)走轻量 /sysmon/counters — 后端 < 10µs(只 2 次
	// atomic.Load),不再走 /status?limit=1(N=10K 时 ~5ms)。
	//
	// 老 server 无本 endpoint → controlClient.SysmonCounters 自动 404 fallback 到
	// /status?limit=1,过渡兼容。
	//
	// 超时短(2s)— 前端每 2s 轮询,要是 control sock 卡住,本次跳过,下次再拉,
	// 不要让本 handler 整体跟 dashboard 同步阻塞。
	cctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	counters, err := s.control.SysmonCounters(cctx)
	if err != nil {
		resp.VPNError = trErr(r, err)
		// VPN 不可用时 uptime 也无意义,标 -1 让前端显 "—" 而不是 "0s"。
		resp.ServerUptimeSeconds = -1
	} else {
		resp.VPNAvailable = true
		resp.VPNBytesUp = counters.VPNBytesUp
		resp.VPNBytesDown = counters.VPNBytesDown
		// A4.8 / uptime_zero(2026-05-26):透传 server uptime + server ts_ms。
		// controlClient 在老 server fallback 路径会用 -1 标记 UptimeSeconds = unknown,
		// 用本地 time.Now() 填 TimestampMS(此时 clock skew = 0)。
		resp.ServerUptimeSeconds = counters.UptimeSeconds
		resp.ServerTimestampMS = counters.TimestampMS
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// 始终 200 — 错误信息编在 JSON 里,前端能直接渲染横幅;5xx 会让 fetch().catch
	// 路径分流,反而麻烦。
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		logrus.WithError(err).Warn("[sysmon] 编码响应失败")
	}
}
