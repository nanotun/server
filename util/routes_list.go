package util

// subnet route（SR-M3）：server → client 推送的「可用子网路由列表」wire type（LinkTypeRoutesList=22 的 JSON body）。
//
// 语义见 docs/PLAN_SUBNET_ROUTE_DATAPLANE.md。server 在客户端连上时推一帧当前列表，并在 admin 改路由批准后广播更新；
// 请求方据此把 CIDR 装进本机 TUN 路由（引流进隧道），发往这些内网网段的包才会到 server → 子网路由转发（SR-M1）。
// 与出口选择器（ExitsList=21）并列、各自独立：ExitsList 是「可选公网出口设备」，RoutesList 是「可达内网子网」。

import (
	"encoding/json"
	"fmt"
)

// SubnetRouteInfo 是一条「可用子网路由」的摘要。请求方按 CIDR 引流（不关心具体宣告方 device）；DeviceUUID/Name 仅展示用。
type SubnetRouteInfo struct {
	// CIDR：已归一的网段（网络地址形态，如 `192.168.1.0/24`）。请求方据此装 TUN 路由。
	CIDR string `json:"cidr"`
	// DeviceUUID：宣告该网段的设备 UUID（可能为空——server 查库失败时）。仅展示用。
	DeviceUUID string `json:"device_uuid,omitempty"`
	// DeviceName：宣告方可读设备名（可能为空）。仅展示用。
	DeviceName string `json:"device_name,omitempty"`
	// Online：该网段的宣告方当前是否在线（有活跃会话）。**离线也列出**（避免请求方路由频繁增删），但请求方发往它的
	// 流量会在 server 侧因宣告方离线被丢弃（内网暂不可达）。请求方可据此在 UI 置灰 / 提示。
	Online bool `json:"online"`
	// SiteID：4via6 站点号（SR-VIA6）。宣告方设备的稳定 16 位站点标识。请求方用它 + 内置前缀 fdbc:4a60::/64
	// 构造访问该网段主机的 4via6 地址（前缀 + siteID + 目标 v4），从而在与本地 LAN 同网段时仍能无歧义访问远端。
	// 0 = 该宣告方尚未分配站点号（旧数据 / 分配失败）；请求方此时可回退纯 v4（可能与本地冲突）。omitempty 向后兼容。
	SiteID uint16 `json:"site_id,omitempty"`
}

// RoutesList 是 server → client 的 LinkTypeRoutesList(22) JSON body：当前所有已批准（非 0/0）子网路由。
type RoutesList struct {
	Schema int               `json:"schema"`
	Routes []SubnetRouteInfo `json:"routes"`
}

// MarshalRoutesList 配套（nil → 空数组，保证 JSON 始终是 `[]` 而非 null）。
func MarshalRoutesList(routes []SubnetRouteInfo) ([]byte, error) {
	if routes == nil {
		routes = []SubnetRouteInfo{}
	}
	return json.Marshal(RoutesList{Schema: RouteSchemaCurrent, Routes: routes})
}

// ParseRoutesList 解析并校验 schema。
func ParseRoutesList(data []byte) (*RoutesList, error) {
	var rl RoutesList
	if err := json.Unmarshal(data, &rl); err != nil {
		return nil, fmt.Errorf("parse routes list: %w", err)
	}
	if rl.Schema != RouteSchemaCurrent {
		return nil, fmt.Errorf("routes list schema = %d, want %d", rl.Schema, RouteSchemaCurrent)
	}
	return &rl, nil
}
