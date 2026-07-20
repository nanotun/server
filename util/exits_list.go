package util

// exit-node 选择器:server → client 推送的「可选出口设备列表」wire type（LinkTypeExitsList=21 的 JSON body）。
//
// 语义见 docs/DESIGN_EXIT_NODE.md。server 在「使用客户端连上(exit_allowed)」时推一帧初始列表，并在某
// 「本会话真在跑出口」的设备上线/下线时广播更新；客户端据此把出口下拉**实时**刷新，免手填设备 UUID。
//
// 「可列出的出口」三条件同时满足（见 server 端 buildExitsList）：
//   1. 该设备有 admin approved 的 0.0.0.0/0 或 ::/0 路由；
//   2. 该设备当前有活跃会话且**本会话已声明出口**（发过 RouteAdvertise{exit}，即真在跑 --exit-node）；
//   3.（Online 字段恒 true：能进列表就意味着在线在跑——离线/未跑的出口压根不进列表。保留字段供将来"离线置灰"用。）

import (
	"encoding/json"
	"fmt"
)

// ExitInfo 是一个可选出口设备的摘要。
type ExitInfo struct {
	// DeviceUUID:出口设备的 RFC4122 v4 UUID（小写）；使用方据此发 EgressSelect。
	DeviceUUID string `json:"device_uuid"`
	// DeviceName:可读设备名（仅展示用，可能为空）。
	DeviceName string `json:"device_name,omitempty"`
	// Online:该出口当前是否在线在跑。当前实现只列出在线在跑的出口（恒 true）；保留字段以便将来改为
	// "也列离线出口并置灰"。
	Online bool `json:"online"`
}

// ExitsList 是 server → client 的 LinkTypeExitsList(21) JSON body。
type ExitsList struct {
	Schema int        `json:"schema"`
	Exits  []ExitInfo `json:"exits"`
}

// MarshalExitsList 配套（nil → 空数组，保证 JSON 始终是 `[]` 而非 null）。
func MarshalExitsList(exits []ExitInfo) ([]byte, error) {
	if exits == nil {
		exits = []ExitInfo{}
	}
	return json.Marshal(ExitsList{Schema: RouteSchemaCurrent, Exits: exits})
}

// ParseExitsList 解析并校验 schema。
func ParseExitsList(data []byte) (*ExitsList, error) {
	var el ExitsList
	if err := json.Unmarshal(data, &el); err != nil {
		return nil, fmt.Errorf("parse exits list: %w", err)
	}
	if el.Schema != RouteSchemaCurrent {
		return nil, fmt.Errorf("exits list schema = %d, want %d", el.Schema, RouteSchemaCurrent)
	}
	return &el, nil
}
