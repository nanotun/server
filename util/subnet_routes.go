package util

// P2#12(2026-05-22):subnet route advertise wire types。
//
// 这是 LinkType 15 / 16 的 JSON body 结构,server 与 client 共同遵守。
// 客户端实现见 docs/DESIGN_SUBNET_ROUTES.md。

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// RouteSchemaCurrent 是 wire schema 版本号;不兼容变更 → 自增 + bump server 校验。
const RouteSchemaCurrent = 1

// RouteAdvertise 是客户端 → server 的 LinkTypeRouteAdvertise(15) JSON body。
//
// 客户端在登录成功后任何时刻都可以发(更新声明);server 把每条 cidr upsert 到
// subnet_routes 表(status=pending,等 admin 审批)。已 approved 的条目若客户端
// 不再上报,server 不会自动 demote —— 路由生效与否由 admin 显式控制,避免短暂网络
// 抖动让 approved 状态丢失。
type RouteAdvertise struct {
	Schema int      `json:"schema"`
	Routes []string `json:"routes"` // CIDR 文本列表;空 / nil 视作"撤回所有未审批的路由声明"
	// Exit（exit-node 特性）：本帧是否为「出口节点」声明。
	//   - false（默认/老客户端）：Routes 走 NormalizeAdvertisedCIDR，**拒绝** 0/0、::/0；
	//   - true：本设备自荐为公网出口，Routes 允许携带 0.0.0.0/0 / ::/0（走 NormalizeExitAdvertisedCIDR）。
	// 仍需 admin 审批后才真正承载流量。空 Routes + Exit=true 语义同空 Routes（撤回 pending）。
	Exit bool `json:"exit,omitempty"`
}

// RouteApproveStatus 是 server → client 的 LinkTypeRouteApproveStatus(16) JSON body。
//
// server 在 admin 审批后主动推一帧给目标 device,告诉它哪些 CIDR 通过 / 拒绝。
// 客户端可据此提示 UI("等待管理员审批" → "已批准")。也可以在 LoginResp 之后
// server 主动 push 一次当前状态快照,让重连 client 同步。
type RouteApproveStatus struct {
	Schema  int                `json:"schema"`
	Updated []RouteStatusEntry `json:"updated"`
}

// RouteStatusEntry 描述一条 CIDR 的当前状态。
//
// Status 取值:"pending" / "approved" / "rejected"。
// Reason 仅在 rejected 时有值(可选,给客户端 UI 提示用)。
// At 是服务端的 Unix 秒,客户端用于显示时间戳。
type RouteStatusEntry struct {
	CIDR   string `json:"cidr"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
	At     int64  `json:"at,omitempty"`
}

// Status 取值常量,与 store/subnet_routes.go 共享。
const (
	RouteStatusPending  = "pending"
	RouteStatusApproved = "approved"
	RouteStatusRejected = "rejected"
)

// MarshalRouteAdvertise / Parse 配套。
func MarshalRouteAdvertise(routes []string) ([]byte, error) {
	return json.Marshal(RouteAdvertise{Schema: RouteSchemaCurrent, Routes: routes})
}

func ParseRouteAdvertise(data []byte) (*RouteAdvertise, error) {
	var ra RouteAdvertise
	if err := json.Unmarshal(data, &ra); err != nil {
		return nil, fmt.Errorf("parse route advertise: %w", err)
	}
	if ra.Schema != RouteSchemaCurrent {
		return nil, fmt.Errorf("route advertise schema = %d, want %d", ra.Schema, RouteSchemaCurrent)
	}
	return &ra, nil
}

// MarshalRouteApproveStatus / Parse 配套。
func MarshalRouteApproveStatus(updated []RouteStatusEntry) ([]byte, error) {
	return json.Marshal(RouteApproveStatus{Schema: RouteSchemaCurrent, Updated: updated})
}

func ParseRouteApproveStatus(data []byte) (*RouteApproveStatus, error) {
	var rs RouteApproveStatus
	if err := json.Unmarshal(data, &rs); err != nil {
		return nil, fmt.Errorf("parse route approve status: %w", err)
	}
	if rs.Schema != RouteSchemaCurrent {
		return nil, fmt.Errorf("route approve status schema = %d, want %d", rs.Schema, RouteSchemaCurrent)
	}
	return &rs, nil
}

// NormalizeAdvertisedCIDR 把客户端送上来的 CIDR 文本归一化:
//   - 必须 parse 成有效的 netip.Prefix;
//   - 拒绝 ::/0 与 0.0.0.0/0(避免误声明"全网代理");
//   - 拒绝典型私有/保留段以外的公网 CIDR? **不**强校验,
//     server 把决策权留给 admin —— 反正要审批通过才生效。
//   - 把网络地址 mask 化(192.168.1.5/24 → 192.168.1.0/24)避免重复条目。
//
// 返回归一后的字符串 + 错误。
func NormalizeAdvertisedCIDR(in string) (string, error) {
	in = strings.TrimSpace(in)
	if in == "" {
		return "", errors.New("empty cidr")
	}
	p, err := netip.ParsePrefix(in)
	if err != nil {
		return "", fmt.Errorf("invalid cidr %q: %w", in, err)
	}
	if p.Bits() == 0 {
		return "", errors.New("cidr /0 not allowed(请勿声明全网路由)")
	}
	return p.Masked().String(), nil
}

// ExitDefaultRouteV4 / ExitDefaultRouteV6 是「出口节点」声明用的全网路由（归一形态）。
// 出口能力即「我能 forward 任意目的地（公网）」，对应 0.0.0.0/0 与 ::/0。
const (
	ExitDefaultRouteV4 = "0.0.0.0/0"
	ExitDefaultRouteV6 = "::/0"
)

// IsExitDefaultRoute 判断一条已归一 CIDR 是否为出口全网路由（0.0.0.0/0 或 ::/0）。
func IsExitDefaultRoute(cidr string) bool {
	c := strings.TrimSpace(cidr)
	return c == ExitDefaultRouteV4 || c == ExitDefaultRouteV6
}

// NormalizeExitAdvertisedCIDR 是 [NormalizeAdvertisedCIDR] 的出口语境变体：**允许** 0/0 与 ::/0
// （出口节点声明「我能 forward 全网」），其余规则一致（须可解析、网络地址 mask 化）。
//
// 仅在 RouteAdvertise.Exit=true 的帧里对每条 CIDR 调用；非出口帧仍走 [NormalizeAdvertisedCIDR]
// 拒绝 /0，防普通设备误声明全网代理。
func NormalizeExitAdvertisedCIDR(in string) (string, error) {
	in = strings.TrimSpace(in)
	if in == "" {
		return "", errors.New("empty cidr")
	}
	p, err := netip.ParsePrefix(in)
	if err != nil {
		return "", fmt.Errorf("invalid cidr %q: %w", in, err)
	}
	return p.Masked().String(), nil
}
