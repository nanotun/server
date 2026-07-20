package main

import (
	"fmt"
	"strings"
)

const profileSchemaVersionV2 = 2

const profileURLPrefixV2 = "nanotun://v2?d="

// profileSchemaNode 为 v2 的一条可选**入口**（出口为 profile.host）。
type profileSchemaNode struct {
	ID      string                `json:"id,omitempty"`
	Name    string                `json:"name,omitempty"`
	Reality *profileSchemaReality `json:"reality,omitempty"`
	Hy2     *profileSchemaHy2     `json:"hy2,omitempty"`
}

// nodeSpec 由 `--node` 解析：入口拨号用的 host/IP（可与出口 host 不同）。
type nodeSpec struct {
	ID   string
	Name string
	Host string
}

// stringList 支持重复 `-node` flag。
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// parseNodeSpec 解析 `--node` 参数。
//
//   - 裸字符串视为 host（如 `1.2.3.4` 或 `hk.example.com`）；
//   - 或 `id=hk,name=香港,host=1.2.3.4`（键值对，逗号分隔）。
func parseNodeSpec(raw string) (nodeSpec, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nodeSpec{}, newLocErr("profilenode.empty")
	}
	if !strings.Contains(raw, "=") {
		return nodeSpec{Host: raw}, nil
	}
	var spec nodeSpec
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return nodeSpec{}, newLocErr("profilenode.segmentForm", part)
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "id":
			spec.ID = strings.TrimSpace(v)
		case "name":
			spec.Name = strings.TrimSpace(v)
		case "host":
			spec.Host = strings.TrimSpace(v)
		default:
			return nodeSpec{}, newLocErr("profilenode.unknownKey", k)
		}
	}
	if spec.Host == "" {
		return nodeSpec{}, newLocErr("profilenode.needHost")
	}
	return spec, nil
}

// attachEntryAddresses 把入口 host 写入各段 `address`，并清掉已并入 address 的冗余
// 端口字段（`reality.port` / `hy2.udp_port` / `hy2.udp_ports`）。
//
// 客户端（Rust [`reality_section_to_connect_json`] / [`hy2_section_to_connect_json`]）
// 在 `address` 非空时优先使用 address；保留 port 字段只会重复 ~70 B/节点。
func attachEntryAddresses(entryHost string, r *profileSchemaReality, h *profileSchemaHy2) {
	entryHost = strings.TrimSpace(entryHost)
	if entryHost == "" {
		return
	}
	if r != nil {
		port := r.Port
		if port == 0 {
			port = defaultRealityTCPPort
		}
		r.Address = fmt.Sprintf("%s:%d", entryHost, port)
		r.Port = 0
	}
	if h != nil {
		h.Address = hy2DialAddress(entryHost, h)
		h.UDPPort = 0
		h.UDPPorts = ""
	}
}

func hy2DialAddress(entryHost string, h *profileSchemaHy2) string {
	if ports := strings.TrimSpace(h.UDPPorts); ports != "" {
		return entryHost + ":" + ports
	}
	port := h.UDPPort
	if port == 0 {
		port = defaultHy2UDPPort
	}
	return fmt.Sprintf("%s:%d", entryHost, port)
}

// buildProfileV2 组装 version=2 profile：`host` 为唯一出口，`nodes` 为入口列表。
//
// 设计权衡：**节点完全自描述**，每个 `nodes[i]` 含独立 reality + hy2 段（含独立
// Ed25519 mTLS 客户端证书），顶层不再放公共默认。
// 优点：每节点证书可独立吊销 / 轮换；某节点泄露不影响其它节点；调试链路时
// 单节点 JSON 完整可读。
// 代价：profile 体积线性 ~1.8 KB / 节点（开 mTLS 时），2 个入口起就超 QR Low
// 2953 阈值；多入口建议走文件 / 复制粘贴分发，单入口仍能进 QR。
func buildProfileV2(in buildProfileInput, nodeSpecs []nodeSpec) (*profileSchema, error) {
	if len(nodeSpecs) == 0 {
		return nil, newLocErr("profilenode.needOne")
	}
	p := &profileSchema{
		Version:        profileSchemaVersionV2,
		ServerID:       strings.TrimSpace(in.serverID),
		Name:           strings.TrimSpace(in.name),
		Host:           in.host,
		AdvertisedHost: strings.TrimSpace(in.advertisedHost),
		Note:           strings.TrimSpace(in.note),
	}
	if shouldIncludeGateway(in) {
		applyGateway(p, in)
	}

	// 探测能否生成 reality / hy2（依赖 server config）。若两者都不可生成则拒绝。
	probe := in
	probe.realityPort = 0
	probe.hy2UDPPort = 0
	probe.noIssueHy2ClientCert = true
	var canReality, canHy2 bool
	if !in.noReality {
		if r, err := buildReality(probe); err == nil && r != nil {
			canReality = true
		} else if err != nil {
			return nil, err
		}
	}
	if !in.noHy2 {
		if h, err := buildHy2(probe); err == nil && h != nil {
			canHy2 = true
		} else if err != nil {
			return nil, err
		}
	}
	if !canReality && !canHy2 {
		return nil, newLocErr("profilenode.cannotGen")
	}

	seenIDs := map[string]struct{}{}
	for _, spec := range nodeSpecs {
		if spec.ID != "" {
			if _, dup := seenIDs[spec.ID]; dup {
				return nil, newLocErr("profilenode.dupID", spec.ID)
			}
			seenIDs[spec.ID] = struct{}{}
		}
		entryHost := strings.TrimSpace(spec.Host)
		if entryHost == "" {
			return nil, newLocErr("profilenode.hostEmpty")
		}
		// 每节点独立生成完整 reality / hy2（含独立 mTLS 客户端证书）。
		nodeIn := in
		nodeIn.realityPort = 0
		nodeIn.hy2UDPPort = 0
		// 让 buildHy2 自己按 server config 决定是否签发 mTLS 证书（per-node 独立）。
		nodeIn.noIssueHy2ClientCert = in.noIssueHy2ClientCert
		var r *profileSchemaReality
		var h2 *profileSchemaHy2
		var err error
		if canReality {
			if r, err = buildReality(nodeIn); err != nil {
				return nil, err
			}
		}
		if canHy2 {
			if h2, err = buildHy2(nodeIn); err != nil {
				return nil, err
			}
		}
		attachEntryAddresses(entryHost, r, h2)
		p.Nodes = append(p.Nodes, profileSchemaNode{
			ID:      spec.ID,
			Name:    spec.Name,
			Reality: r,
			Hy2:     h2,
		})
	}
	return p, nil
}

func profileURLPrefixFor(p *profileSchema) string {
	if p.Version == profileSchemaVersionV2 {
		return profileURLPrefixV2
	}
	return profileURLPrefix
}
