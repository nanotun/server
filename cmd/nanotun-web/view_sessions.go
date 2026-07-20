package main

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// 2026-05-23 新增:M2 web 后台「在线会话/在线设备」视图。
//
// nanotund control socket 的 /status 里已经返回 sessions[]:conn_id / user_id /
// device_id / device_uuid / vips / created_at / exit_allowed / bw_*。但 web 后台
// 还想顺手展示 device_name / platform / username 这些 "人话" 字段,所以这里 join 一下
// store。一次渲染最多 256 条左右(超过 conn_count 上限根本走不到),join 走 GetUser /
// GetDevice 都是主键 SELECT,DB 命中 < 1ms,聚合 200 条 < 250ms。如果未来 conn 数会上
// 千,这里要么换 batch query(WHERE id IN (...))要么前端走 lazy join。
//
// 失败策略:control socket 拿不到 = 返回 (nil, err),handler 渲染时降级展示
// "数据面不可用" 横幅;join 单条失败 = 该条 device_name/username 留空,不阻断列表
// (孤儿 conn 也要让 admin 看见 → 才能踢)。

// sessionRowFromControl 镜像 cmd/nanotund/control_socket.go 的 controlSessionInfo。
// 字段名(json tag)必须保持一致;新增字段只追加在末尾。
type sessionRowFromControl struct {
	ConnIDStr   string   `json:"conn_id"`
	UserID      string   `json:"user_id"`
	DeviceID    int64    `json:"device_id,omitempty"`
	DeviceUUID  string   `json:"device_uuid,omitempty"`
	VIPs        []string `json:"vips,omitempty"`
	CreatedAt   int64    `json:"created_at"`
	ExitAllowed bool     `json:"exit_allowed"`
	BWUpBPS     int64    `json:"bw_up_bps,omitempty"`
	BWDownBPS   int64    `json:"bw_down_bps,omitempty"`
}

// SessionView 是 dashboard / sessions_list 模板里直接渲染的"人话"行。
//
// 凡是从 control socket 直接拿到的字段保持原样;DeviceName / Platform / Username /
// FixedVIPv4 / FixedVIPv6 是模板渲染前补的 join 结果,失败 / 空 = 留空字符串。
//
// FixedVIPv4 / FixedVIPv6 含义:
//   - "" + 当前 VIPv4 有值 → 该 device 是动态分配 vIP,sessions 页面会展示「绑
//     定当前 IP 为固定」按钮;
//   - 非空 → 该 device 已钉死,FixedVIPv4 与 VIPv4 通常一致(因为 alloc_lease.go
//     的 preferredLeasedVIPs 会优先用 fixed)。
type SessionView struct {
	ConnID string
	UserID string
	// StoreUserID:从数据面 "u<id>" 反解出的 store 主键(join 成功时 > 0)。
	// 第十轮深扫 P2:sessions 页用户名此前只能链到 /users 列表页,有 ID 就该
	// 直达 /users/{id} 详情。
	StoreUserID int64
	Username    string
	DeviceID    int64
	DeviceUUID  string
	DeviceName  string
	Platform    string
	VIPv4       string
	VIPv6       string
	FixedVIPv4  string
	FixedVIPv6  string
	CreatedAt   int64
	ExitAllowed bool
	BWUpBPS     int64
	BWDownBPS   int64
}

// HasAnyFixedVIP:模板写 .HasAnyFixedVIP 比 .FixedVIPv4 or .FixedVIPv6 简洁。
func (v SessionView) HasAnyFixedVIP() bool {
	return v.FixedVIPv4 != "" || v.FixedVIPv6 != ""
}

// collectSessionsForView 拿 control sock /status,解出 sessions,join store 拿
// username / device 信息,按 created_at 倒序返回。
//
// 失败语义:
//   - control sock 不可达 → (nil, err);handler 必须降级显示"数据面 unavailable"
//   - sessions 字段缺失(老 server) → 返回空切片 + nil error(算正常,只是没在线)
//   - 单条 join 失败 → 该条对应字段留空,继续聚合
//
// 性能上限: conn_count 通常 < 256,N 次主键 SELECT 完全 OK。
//
// Q3(2026-05-25):接收可变 opts 透传 server 端分页。
//
//	dashboard 只要前 5 条 → 传 WithLimit(10)(N>5 也只渲染前 5,留余量给 join 失败 fallback)。
//	sessions 列表页要全量 → 不传 opts(老行为)。
//	N_conn=10K 时 dashboard 不再每次拉 10K 条 JSON;省 99% 带宽 + 解析。
func (s *Server) collectSessionsForView(ctx context.Context, opts ...StatusOption) ([]SessionView, error) {
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	raw, err := s.control.Status(cctx, opts...)
	if err != nil {
		return nil, err
	}
	// 只解我们关心的子结构。控制 socket 的 /status 顶层字段比较多,但 sessions[] 字
	// 段名稳定。
	var wrap struct {
		Sessions []sessionRowFromControl `json:"sessions"`
	}
	if err := json.Unmarshal(raw, &wrap); err != nil {
		return nil, err
	}
	out := make([]SessionView, 0, len(wrap.Sessions))
	// 缓存 user 信息,同一 user 多设备时少查几次。
	usernameCache := make(map[int64]string, 16)
	for _, row := range wrap.Sessions {
		v := SessionView{
			ConnID:      row.ConnIDStr,
			UserID:      row.UserID,
			DeviceID:    row.DeviceID,
			DeviceUUID:  row.DeviceUUID,
			CreatedAt:   row.CreatedAt,
			ExitAllowed: row.ExitAllowed,
			BWUpBPS:     row.BWUpBPS,
			BWDownBPS:   row.BWDownBPS,
		}
		for _, ip := range row.VIPs {
			if strings.Contains(ip, ":") {
				if v.VIPv6 == "" {
					v.VIPv6 = ip
				}
			} else {
				if v.VIPv4 == "" {
					v.VIPv4 = ip
				}
			}
		}
		// userID 是 "u<id>" 格式,反解出 int64 再 join store。
		// 匿名 / takeover 临时会话有可能拿到空串,跳过 join 即可。
		if uid, ok := parseUserIDStrWeb(row.UserID); ok {
			v.StoreUserID = uid
			if name, hit := usernameCache[uid]; hit {
				v.Username = name
			} else if u, err := s.store.GetUser(ctx, uid); err == nil && u != nil {
				usernameCache[uid] = u.Username
				v.Username = u.Username
			} else if err != nil {
				logrus.WithError(err).WithField("user_id", uid).
					Debug("[web] sessions join: GetUser 失败,留空 username")
			}
		}
		if row.DeviceID > 0 {
			if d, err := s.store.GetDevice(ctx, row.DeviceID); err == nil && d != nil {
				v.DeviceName = d.DisplayName() // alias(0020):优先管理员别名
				v.Platform = d.Platform
				v.FixedVIPv4 = d.FixedVIPv4
				v.FixedVIPv6 = d.FixedVIPv6
			} else if err != nil {
				logrus.WithError(err).WithField("device_id", row.DeviceID).
					Debug("[web] sessions join: GetDevice 失败,留空 device_name")
			}
		}
		out = append(out, v)
	}
	// R2(2026-05-26):删二次排序。Server 端 /status 已经按 created_at DESC,
	// conn_id ASC 二级稳定排好,这里再 sort 是冗余。更关键的是:dashboard 用
	// WithLimit(N) 让 server 端只返「最新 N 条」,客户端再 sort 也无意义
	// (window 是 server 在排序后切的)。保持 server 顺序直接输出。
	return out, nil
}

// parseUserIDStrWeb:"u123" → 123, true。其它输入 / 空 / 不带 u → false。
// 与 cmd/nanotund/server.go 里 parseUserIDStr 同义,这里独立一份避免跨 module import。
func parseUserIDStrWeb(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	if len(s) < 2 || s[0] != 'u' {
		return 0, false
	}
	n, err := strconv.ParseInt(s[1:], 10, 64)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

// fmtAge 一个简易"已连接 X 秒/分/时"。模板用 fmtDuration 也能渲染,这里多一层
// 是为了未来按需扩展(比如颜色区分新/旧会话)。
func sessionAge(unix int64) time.Duration {
	if unix <= 0 {
		return 0
	}
	return time.Since(time.Unix(unix, 0))
}
