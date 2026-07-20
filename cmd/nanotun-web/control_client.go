package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/sirupsen/logrus"
)

// M2:nanotun-web → nanotund control socket 的 client。
//
// 与 nanotun-admin/control_client.go 是同一套协议(unix HTTP),独立一份避免
// 跨二进制 import。任何 server 接口变化都要同步 admin + web 两份(代价小)。

// newControlHTTPClient 返回经 unix socket 转发的 http.Client。
// socket 不存在 / server 没起 → 调用方调用时返回 error,handler 应当容忍降级
// (例:dashboard 上 "运行时数据 unavailable",仍展示数据库里的列表)。
func newControlHTTPClient(socketPath string) *http.Client {
	return &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: 3 * time.Second}
				return d.DialContext(ctx, "unix", socketPath)
			},
			// 单 host(unix socket)默认就够;但显式禁掉 keepalive 也行 —— socket
			// 关闭后 reuse 会失败,reuse 节省的几毫秒不值得调试时长。
			IdleConnTimeout: 30 * time.Second,
		},
	}
}

// controlClient 把所有 control socket 的具体调用封装,handler 只用 .Reload / .Kick / .Status。
// 上层 not nil 但 socketPath = "" 时一切方法都直接返回 error,方便测试场景。
type controlClient struct {
	httpc      *http.Client
	socketPath string
}

func newControlClient(socketPath string) *controlClient {
	return &controlClient{
		httpc:      newControlHTTPClient(socketPath),
		socketPath: socketPath,
	}
}

// do 发起 unix HTTP 请求。host 必须随意填一个合法值(http.NewRequest 会校验)。
func (c *controlClient) do(ctx context.Context, method, path string, body any) ([]byte, int, error) {
	var reqBody io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("encode body: %w", err)
		}
		reqBody = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://unix"+path, reqBody)
	if err != nil {
		return nil, 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpc.Do(req)
	if err != nil {
		// newLocErr:socket 拨号失败会经 renderError 冒泡到浏览器,交给 trErr 按请求
		// 语言翻译;底层 net 错误(第三方)作 %s 参数原样透传(不强译)。
		return nil, 0, newLocErr("control.socketReqFail", c.socketPath, err.Error())
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return out, resp.StatusCode, fmt.Errorf("server %d: %s", resp.StatusCode, string(out))
	}
	return out, resp.StatusCode, nil
}

// ReloadACL 调用 POST /reload?what=acl,让 nanotund 把 ACL snapshot 刷新。
//
// 失败时只 Warn(写库已经成功,reload 失败让管理员可以手动 systemctl reload)。
// 返回新生效的规则数 / error。
func (c *controlClient) ReloadACL(ctx context.Context) (int, error) {
	out, _, err := c.do(ctx, http.MethodPost, "/reload?what=acl", nil)
	if err != nil {
		return 0, err
	}
	var r struct {
		OK    bool `json:"ok"`
		Rules int  `json:"rules"`
	}
	if err := json.Unmarshal(out, &r); err != nil {
		return 0, fmt.Errorf("parse reload resp: %w", err)
	}
	if !r.OK {
		return r.Rules, fmt.Errorf("server returned ok=false: %s", string(out))
	}
	return r.Rules, nil
}

// ReloadRoutes 通知 server 重建「已批准子网路由表」+ 广播 routes-list（POST /reload?what=routes）。
// 删设备 / 改子网路由批准后调，使数据面快照（subnetRouteTable/via6SiteTable）与客户端可用列表即时收敛。
// 失败只 Warn（写库已成功，下次任意路由变更 / reload / 重启会收敛）。返回当前生效路由条数 / error。
func (c *controlClient) ReloadRoutes(ctx context.Context) (int, error) {
	out, _, err := c.do(ctx, http.MethodPost, "/reload?what=routes", nil)
	if err != nil {
		return 0, err
	}
	var r struct {
		OK     bool `json:"ok"`
		Routes int  `json:"routes"`
	}
	if err := json.Unmarshal(out, &r); err != nil {
		return 0, fmt.Errorf("parse reload resp: %w", err)
	}
	if !r.OK {
		return r.Routes, fmt.Errorf("server returned ok=false: %s", string(out))
	}
	return r.Routes, nil
}

// ReloadExits 通知 server 复核/重算出口节点（POST /reload?what=exits）：
//   - 撤销出口 → server 即时把绑定它的会话踢回 server 自出口并通知客户端；
//   - 新批准/指定出口 → server 即时把可选出口列表推给客户端下拉。
//
// 与 nanotun-admin 的 notifyExitsChanged 同协议。失败只 Warn（DB 已落，
// 客户端重连 / 下次出口上下线时自然收敛）。返回被重置回 server 出口的会话数 / error。
func (c *controlClient) ReloadExits(ctx context.Context) (int, error) {
	out, _, err := c.do(ctx, http.MethodPost, "/reload?what=exits", nil)
	if err != nil {
		return 0, err
	}
	var r struct {
		OK             bool `json:"ok"`
		ReboundToServe int  `json:"rebound_to_server"`
	}
	if err := json.Unmarshal(out, &r); err != nil {
		return 0, fmt.Errorf("parse reload resp: %w", err)
	}
	if !r.OK {
		return r.ReboundToServe, fmt.Errorf("server returned ok=false: %s", string(out))
	}
	return r.ReboundToServe, nil
}

// tryReloadExitsBackground:出口路由（0/0、::/0）批准/撤销/删除后的 best-effort 通知。
// 异步短超时，失败只 Warn。nil control（未配 control socket）直接跳过。
func tryReloadExitsBackground(c *controlClient) {
	if c == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		n, err := c.ReloadExits(ctx)
		if err != nil {
			logrus.WithError(err).Warn("[web] 自动 reload 出口节点失败,客户端待重连/下次出口变化收敛")
			return
		}
		logrus.WithField("rebound_to_server", n).Info("[web] 已通知 server 复核出口节点")
	}()
}

// ReloadPortForwards 通知 server 按最新 DB 映射启停公网端口监听（POST /reload?what=portforward）。
// FRP 反向端口转发映射增删后调，使监听即时对齐。失败只 Warn（写库已成功，下次变更 / reload / 重启收敛）。
// 返回当前活跃监听数 / error。
func (c *controlClient) ReloadPortForwards(ctx context.Context) (int, error) {
	out, _, err := c.do(ctx, http.MethodPost, "/reload?what=portforward", nil)
	if err != nil {
		return 0, err
	}
	var r struct {
		OK     bool `json:"ok"`
		Active int  `json:"active"`
	}
	if err := json.Unmarshal(out, &r); err != nil {
		return 0, fmt.Errorf("parse reload resp: %w", err)
	}
	if !r.OK {
		return r.Active, fmt.Errorf("server returned ok=false: %s", string(out))
	}
	return r.Active, nil
}

// PortForwardStatusItem:server 端一条端口转发映射的运行态（GET /portforward/status）。
// State 取值:listening / bind_failed / route_degraded（见 cmd/nanotund/port_forward.go pfState）。
type PortForwardStatusItem struct {
	PublicPort int    `json:"public_port"`
	Target     string `json:"target"`
	DeviceUUID string `json:"device_uuid"`
	LAN        bool   `json:"lan"`
	State      string `json:"state"`
	Err        string `json:"err,omitempty"`
}

// PortForwardStatus 拉取 server 端所有端口转发映射的运行态（GET /portforward/status，只读无副作用）。
// 供列表页把「配置了但没真正生效」（端口占用 / LAN 路由没装上）显式呈现给管理员。
// 返回 public_port → 运行态 的 map；server 不可用 / 未启用时返回 error（调用方降级为「状态未知」）。
func (c *controlClient) PortForwardStatus(ctx context.Context) (map[int]PortForwardStatusItem, error) {
	out, _, err := c.do(ctx, http.MethodGet, "/portforward/status", nil)
	if err != nil {
		return nil, err
	}
	var r struct {
		OK       bool                    `json:"ok"`
		Forwards []PortForwardStatusItem `json:"forwards"`
	}
	if err := json.Unmarshal(out, &r); err != nil {
		return nil, fmt.Errorf("parse portforward status resp: %w", err)
	}
	m := make(map[int]PortForwardStatusItem, len(r.Forwards))
	for _, it := range r.Forwards {
		m[it.PublicPort] = it
	}
	return m, nil
}

// tryReloadPortForwardsBackground:写完端口转发映射后的 best-effort reload。异步短超时，失败只 Warn
// （DB 已落，下次变更 / systemctl reload / 重启收敛）。nil control（未配 control socket）直接跳过。
func tryReloadPortForwardsBackground(c *controlClient) {
	if c == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		n, err := c.ReloadPortForwards(ctx)
		if err != nil {
			logrus.WithError(err).Warn("[web] 自动 reload 端口转发失败,需要 systemctl reload 或待下次变更收敛")
			return
		}
		logrus.WithField("active", n).Info("[web] 已通知 server 重载端口转发")
	}()
}

// StatusOptions:Q3(2026-05-25)。控制 /status 返回 sessions[] 窗口大小。
//
// 用法:
//
//	c.Status(ctx)                                     ← 全量(老路径)
//	c.Status(ctx, WithLimit(5))                       ← 前 5 条
//	c.Status(ctx, WithLimit(20), WithOffset(20))      ← 第 2 页
//
// 字段:
//   - Limit  > 0:server 端切 [Offset, Offset+Limit) 窗口,server-side clamp 到
//     statusPageLimitMax=1000;sessions_total 字段给出 filter 后总数,客户端按
//     它算翻页。
//   - Offset >= 0:窗口起点,必须配 Limit 用(server 端 offset>0&&limit==0 → 400)。
type StatusOptions struct {
	Limit  int
	Offset int
}

// StatusOption:functional options pattern,后续要加 device_id filter 等不破坏调用方。
type StatusOption func(*StatusOptions)

func WithLimit(n int) StatusOption  { return func(o *StatusOptions) { o.Limit = n } }
func WithOffset(n int) StatusOption { return func(o *StatusOptions) { o.Offset = n } }

// Status 转发 GET /status 的原始 JSON。dashboard 用。
//
// 兼容:不传 opts 等价于老行为(全量)。dashboard 端要前 5 条传 WithLimit(5),
// N_conn 上千时省 99% 带宽 + JSON 解析。
func (c *controlClient) Status(ctx context.Context, opts ...StatusOption) ([]byte, error) {
	cfg := StatusOptions{}
	for _, opt := range opts {
		opt(&cfg)
	}
	path := "/status"
	q := url.Values{}
	if cfg.Limit > 0 {
		q.Set("limit", fmt.Sprintf("%d", cfg.Limit))
	}
	if cfg.Offset > 0 {
		q.Set("offset", fmt.Sprintf("%d", cfg.Offset))
	}
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	out, _, err := c.do(ctx, http.MethodGet, path, nil)
	return out, err
}

// RateConfigSnapshot:0012(2026-05-23)。/status.rate_config 的解析视图,settings 页用。
type RateConfigSnapshot struct {
	SettingsUpBPS   int64
	SettingsDownBPS int64
	SettingsBurst   int64
	TomlUpBPS       int64
	TomlDownBPS     int64
	EffectiveBurst  int
}

// RateConfig 拉 /rate/config 然后解析。失败 → 返回零值 + error,settings handler
// 应当容忍降级("toml 默认: 不可用" 等)。
//
// M1(2026-05-24):0012 时拉的是 /status 全量(含 sessions[]),N_conn 大时浪费
// O(N) 拼装。改走轻量 /rate/config(只返 rate_config),server 端老 server 没
// /rate/config 时 404 fallback 回 /status — 保留过渡兼容。
func (c *controlClient) RateConfig(ctx context.Context) (RateConfigSnapshot, error) {
	body, status, err := c.do(ctx, http.MethodGet, "/rate/config", nil)
	// 老 server(< M1)没 /rate/config,返回 404 — do() 把 404 算 err,但我们想吞掉
	// 并 fallback 到 /status。先看 status,后看 err。
	if status == http.StatusNotFound {
		return c.rateConfigViaStatus(ctx)
	}
	if err != nil {
		return RateConfigSnapshot{}, err
	}
	var rc struct {
		SettingsUpBPS   int64 `json:"settings_up_bps"`
		SettingsDownBPS int64 `json:"settings_down_bps"`
		SettingsBurst   int64 `json:"settings_burst_bytes"`
		TomlUpBPS       int64 `json:"toml_up_bps"`
		TomlDownBPS     int64 `json:"toml_down_bps"`
		EffectiveBurst  int   `json:"effective_burst_bytes"`
	}
	if err := json.Unmarshal(body, &rc); err != nil {
		return RateConfigSnapshot{}, fmt.Errorf("parse /rate/config: %w", err)
	}
	return RateConfigSnapshot{
		SettingsUpBPS:   rc.SettingsUpBPS,
		SettingsDownBPS: rc.SettingsDownBPS,
		SettingsBurst:   rc.SettingsBurst,
		TomlUpBPS:       rc.TomlUpBPS,
		TomlDownBPS:     rc.TomlDownBPS,
		EffectiveBurst:  rc.EffectiveBurst,
	}, nil
}

// SysmonCounters(A4, 2026-05-26):/sysmon 页面专用的 VPN 字节累计 + uptime。
//
// 走轻量 /sysmon/counters endpoint(< 10µs 后端开销),老 server 没本 endpoint 时
// fallback 到 /status?limit=1 拿 vpn_bytes_*。M1 同模式。
//
// 字段:
//   - TimestampMS:server 视角时间戳。前端跟客户端 Date.now() 做 clock skew 检查。
//     fallback 路径用 web 本地 time.Now() 填(此时跟 web 同源,差 0)。
//   - UptimeSeconds:server 进程启动秒数。fallback 路径填 **-1** sentinel 表示
//     "未知" — 跟 0 (新 server 刚启动 < 1s) 区分,前端能展示 "—"
//     而不是误显 "0s"。
//   - VPNBytesUp / VPNBytesDown:rateLimitedConn Read/Write 全埋点累计字节。
type SysmonCounters struct {
	TimestampMS   int64  `json:"ts_ms"`
	UptimeSeconds int64  `json:"uptime_seconds"`
	VPNBytesUp    uint64 `json:"vpn_bytes_up"`
	VPNBytesDown  uint64 `json:"vpn_bytes_down"`
}

func (c *controlClient) SysmonCounters(ctx context.Context) (SysmonCounters, error) {
	body, status, err := c.do(ctx, http.MethodGet, "/sysmon/counters", nil)
	// 404 → 老 server 没本 endpoint,fallback。先看 status 再看 err。
	if status == http.StatusNotFound {
		return c.sysmonCountersViaStatus(ctx)
	}
	if err != nil {
		return SysmonCounters{}, err
	}
	var r SysmonCounters
	if jerr := json.Unmarshal(body, &r); jerr != nil {
		return SysmonCounters{}, fmt.Errorf("parse /sysmon/counters: %w", jerr)
	}
	return r, nil
}

func (c *controlClient) sysmonCountersViaStatus(ctx context.Context) (SysmonCounters, error) {
	body, _, err := c.do(ctx, http.MethodGet, "/status?limit=1", nil)
	if err != nil {
		return SysmonCounters{}, err
	}
	var resp struct {
		VPNBytesUp   uint64 `json:"vpn_bytes_up"`
		VPNBytesDown uint64 `json:"vpn_bytes_down"`
	}
	if jerr := json.Unmarshal(body, &resp); jerr != nil {
		return SysmonCounters{}, fmt.Errorf("parse /status fallback: %w", jerr)
	}
	return SysmonCounters{
		TimestampMS:   time.Now().UnixMilli(), // 老 server 没 ts_ms,本地补(=== web ts,clock skew 0)
		UptimeSeconds: -1,                     // uptime_zero(2026-05-26):sentinel 标记"未知",前端区分 0 vs 未知
		VPNBytesUp:    resp.VPNBytesUp,
		VPNBytesDown:  resp.VPNBytesDown,
	}, nil
}

// rateConfigViaStatus:M1 fallback 路径,老 server(< M1)没 /rate/config 时走 /status
// 兜底。逻辑跟原来一致,仅在 404 时被调。
func (c *controlClient) rateConfigViaStatus(ctx context.Context) (RateConfigSnapshot, error) {
	body, _, err := c.do(ctx, http.MethodGet, "/status", nil)
	if err != nil {
		return RateConfigSnapshot{}, err
	}
	var resp struct {
		RateConfig struct {
			SettingsUpBPS   int64 `json:"settings_up_bps"`
			SettingsDownBPS int64 `json:"settings_down_bps"`
			SettingsBurst   int64 `json:"settings_burst_bytes"`
			TomlUpBPS       int64 `json:"toml_up_bps"`
			TomlDownBPS     int64 `json:"toml_down_bps"`
			EffectiveBurst  int   `json:"effective_burst_bytes"`
		} `json:"rate_config"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return RateConfigSnapshot{}, fmt.Errorf("parse /status: %w", err)
	}
	return RateConfigSnapshot{
		SettingsUpBPS:   resp.RateConfig.SettingsUpBPS,
		SettingsDownBPS: resp.RateConfig.SettingsDownBPS,
		SettingsBurst:   resp.RateConfig.SettingsBurst,
		TomlUpBPS:       resp.RateConfig.TomlUpBPS,
		TomlDownBPS:     resp.RateConfig.TomlDownBPS,
		EffectiveBurst:  resp.RateConfig.EffectiveBurst,
	}, nil
}

// DeviceSession:DeviceSessions 的返回元素。
type DeviceSession struct {
	ConnID string
	VIPs   []string // 既包含 v4 也包含 v6,顺序不保证
}

// DeviceSessions 返回某 device 当前所有活跃会话(0 或多条;supersede 后多数情况是 0/1)。
//
// 2026-05-23(0011 配套):web 改 fixed_vip / 限速时拿来做「IP 已经一致 → 不踢」之类的
// 智能决策,避免无谓打扰客户端。失败(server 没起 / 解析失败)返回 nil + error,
// 调用方应当走「保守地不踢」分支(reload IP 不是必须的)。
//
// 0012:走 /status?device_id=X server 端过滤,只回该 device 的 sessions —
// 千级在线时 JSON 体积小 1000× 倍。老版本(没该 query)server 会回全量,这里再过滤一次
// 保底兼容(虽然 web 和 server 同步部署,理论上版本永远对齐)。
func (c *controlClient) DeviceSessions(ctx context.Context, deviceID int64) ([]DeviceSession, error) {
	path := fmt.Sprintf("/status?device_id=%d", deviceID)
	body, _, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Sessions []struct {
			ConnID   string   `json:"conn_id"`
			DeviceID int64    `json:"device_id"`
			VIPs     []string `json:"vips"`
		} `json:"sessions"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse /status: %w", err)
	}
	var out []DeviceSession
	for _, s := range resp.Sessions {
		// 兼容老 server:它会忽略 query 回全量,这里再过滤一遍。新 server 已 server 端过滤,
		// 这一行是 noop。
		if s.DeviceID == deviceID {
			out = append(out, DeviceSession{ConnID: s.ConnID, VIPs: s.VIPs})
		}
	}
	return out, nil
}

// KickReq 镜像 cmd/nanotund/control_socket.go 的 controlKickReq 结构。
type KickReq struct {
	Kind   string `json:"kind"`
	ID     string `json:"id"`
	Reason string `json:"reason,omitempty"`
}

// KickResp 镜像 cmd/nanotund/control_socket.go 的 controlKickResp 结构。
type KickResp struct {
	OK      bool     `json:"ok"`
	Kicked  int      `json:"kicked"`
	ConnIDs []string `json:"conn_ids,omitempty"`
	Reason  string   `json:"reason,omitempty"`
}

// Kick 调 POST /kick。
func (c *controlClient) Kick(ctx context.Context, req KickReq) (*KickResp, error) {
	out, _, err := c.do(ctx, http.MethodPost, "/kick", req)
	if err != nil {
		return nil, err
	}
	var r KickResp
	if err := json.Unmarshal(out, &r); err != nil {
		return nil, fmt.Errorf("parse kick resp: %w", err)
	}
	return &r, nil
}

// RateRefresh:0011(2026-05-23)。调 POST /rate/refresh?device_id=X(或 0=全量)。
// device 限速 / 全局默认改完之后调,把 active conn 的 rate.Limiter 热更过去。
// 失败只 warn,DB 已写入 → 客户端下次重连必生效。
func (c *controlClient) RateRefresh(ctx context.Context, deviceID int64) (refreshed int, err error) {
	path := "/rate/refresh"
	if deviceID > 0 {
		path = fmt.Sprintf("/rate/refresh?device_id=%d", deviceID)
	}
	out, _, err := c.do(ctx, http.MethodPost, path, nil)
	if err != nil {
		return 0, err
	}
	var r struct {
		OK        bool `json:"ok"`
		Refreshed int  `json:"refreshed"`
	}
	if err := json.Unmarshal(out, &r); err != nil {
		return 0, fmt.Errorf("parse rate-refresh resp: %w", err)
	}
	return r.Refreshed, nil
}

// tryRateRefreshBackground:与 tryReloadACLBackground 一脉相承。device/settings 改完
// 立即触发,失败只 warn(DB 已落,客户端下次重连必生效;active conn 那条只是少刷一次)。
func tryRateRefreshBackground(c *controlClient, deviceID int64) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		n, err := c.RateRefresh(ctx, deviceID)
		if err != nil {
			logrus.WithError(err).WithField("device_id", deviceID).
				Warn("[web] 自动 rate-refresh 失败,active conn 待下次重连生效")
			return
		}
		logrus.WithFields(logrus.Fields{"device_id": deviceID, "refreshed": n}).
			Info("[web] 已通知 server 热更限速")
	}()
}

// tryReloadACLBackground:写完 ACL 后的「best effort」reload。
// 异步起一个短超时 goroutine,失败只 Warn(不阻塞用户操作)。
//
// 这是一个常见模式:UI 上 "save → 成功" 之后,后台让 server 把内存 snapshot
// 替换。失败的话用户可以在 dashboard 上看到 "ACL 待 reload" 横幅。
func tryReloadACLBackground(c *controlClient) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		n, err := c.ReloadACL(ctx)
		if err != nil {
			logrus.WithError(err).Warn("[web] 自动 reload ACL 失败,需要 systemctl reload nanotun")
			return
		}
		logrus.WithField("rules", n).Info("[web] 已通知 server 重载 ACL")
	}()
}

// tryReloadRoutesBackground:写完设备/子网路由后的 best-effort routes reload（重建子网路由表 + 广播 routes-list）。
// 异步短超时，失败只 Warn（DB 已落，下次路由变更 / reload / 重启收敛）。nil control（未配 control socket）直接跳过。
func tryReloadRoutesBackground(c *controlClient) {
	if c == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		n, err := c.ReloadRoutes(ctx)
		if err != nil {
			logrus.WithError(err).Warn("[web] 自动 reload 子网路由失败,需要 systemctl reload 或待下次路由变更收敛")
			return
		}
		logrus.WithField("routes", n).Info("[web] 已通知 server 重建子网路由表")
	}()
}
