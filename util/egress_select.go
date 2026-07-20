package util

// exit-node 特性:使用方「公网出口选择」wire types（LinkType 19 / 20 的 JSON body）。
//
// 语义见 docs/DESIGN_EXIT_NODE.md。使用客户端登录成功后，可随时发一帧 EgressSelect
// 把自己的公网出口切到「某台已被 admin 批准为出口的设备」或退回 server 自出口；
// server 回一帧 EgressSelectAck 告知是否接受。

import (
	"encoding/json"
	"fmt"
	"strings"
)

// EgressDefault 是「走 server 自出口」的哨兵值（Egress 为空亦等价）。
const EgressDefault = "server"

// EgressSelect 是 client → server 的 LinkTypeEgressSelect(19) JSON body。
//
// Egress:
//   - 空字符串或 "server" → 公网流量由 server 自己 NAT 出口（默认/历史行为）;
//   - 否则为目标出口设备的 RFC4122 v4 UUID（小写）—— 该设备须已被 admin 批准为出口
//     （approved 0.0.0.0/0 / ::/0）且当前在线，否则 server 回 Ack 拒绝、不改变现状。
type EgressSelect struct {
	Schema int    `json:"schema"`
	Egress string `json:"egress"`
}

// EgressSelectAck 是 server → client 的 LinkTypeEgressSelectAck(20) JSON body。
//
// Accepted=true 时 Egress 回显最终生效的出口（"server" 或设备 UUID）。
// Accepted=false 时 Reason 给出原因（unknown_exit / not_approved / offline / exit_not_allowed / bad_request）。
type EgressSelectAck struct {
	Schema   int    `json:"schema"`
	Accepted bool   `json:"accepted"`
	Egress   string `json:"egress,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// IsDefaultEgress 判断一个 Egress 值是否表示「走 server 自出口」。
func IsDefaultEgress(egress string) bool {
	e := strings.TrimSpace(egress)
	return e == "" || strings.EqualFold(e, EgressDefault)
}

// MarshalEgressSelect / Parse 配套。
func MarshalEgressSelect(egress string) ([]byte, error) {
	return json.Marshal(EgressSelect{Schema: RouteSchemaCurrent, Egress: egress})
}

// ParseEgressSelect 解析并校验 schema。
func ParseEgressSelect(data []byte) (*EgressSelect, error) {
	var es EgressSelect
	if err := json.Unmarshal(data, &es); err != nil {
		return nil, fmt.Errorf("parse egress select: %w", err)
	}
	if es.Schema != RouteSchemaCurrent {
		return nil, fmt.Errorf("egress select schema = %d, want %d", es.Schema, RouteSchemaCurrent)
	}
	es.Egress = strings.TrimSpace(es.Egress)
	return &es, nil
}

// MarshalEgressSelectAck / Parse 配套。
func MarshalEgressSelectAck(ack EgressSelectAck) ([]byte, error) {
	ack.Schema = RouteSchemaCurrent
	return json.Marshal(ack)
}

func ParseEgressSelectAck(data []byte) (*EgressSelectAck, error) {
	var ack EgressSelectAck
	if err := json.Unmarshal(data, &ack); err != nil {
		return nil, fmt.Errorf("parse egress select ack: %w", err)
	}
	if ack.Schema != RouteSchemaCurrent {
		return nil, fmt.Errorf("egress select ack schema = %d, want %d", ack.Schema, RouteSchemaCurrent)
	}
	return &ack, nil
}
