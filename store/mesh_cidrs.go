package store

import (
	"context"
	"fmt"
	"strings"
)

// MeshCIDRsKey 是 server 启动配好 TUN 后写入 app_settings 的**本 mesh 网段快照**(TUN 网关 v4/v6 CIDR,逗号分隔)。
//
// 第十八轮深扫 MED:nanotun-admin / nanotun-web 是与 nanotund **独立的进程**,各自不知道数据面的 mesh 网段
// (它只在 server 配置里、不入库)。批准子网路由时若批了一条**覆盖/落入 mesh 网段**的 CIDR,发往「离线 mesh
// 地址」的包会被子网路由中继进宣告方 LAN —— 跨信任域泄漏。要在**批准期**就拒绝这类重叠(而不是等数据面转发
// 时补救),CLI/web 必须能读到 mesh 网段;故 server 启动时把它落到这枚系统托管 key,两个进程只读取用于交叠判定。
//
// 系统托管:只由 server 经 SetMeshCIDRs 直写(绕过 SettingsSet 的保留键守卫),已登记进 reservedSettingKeys,
// 任何 SettingsSet / CLI `setting set` 都拒改。
const MeshCIDRsKey = "mesh_cidrs"

// SetMeshCIDRs 由 nanotund 启动配好 TUN 后调用,把本 mesh 的 v4/v6 网关 CIDR 快照落库(逗号分隔;空切片写空串=清除)。
// 直连 SQL,不走 SettingsSet —— 该 key 是 reserved,SettingsSet 会拒;与 server_id 的专用写路径同风格。
func (s *Store) SetMeshCIDRs(ctx context.Context, cidrs []string) error {
	val := strings.Join(cidrs, ",")
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO app_settings(key,value) VALUES(?,?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		MeshCIDRsKey, val,
	); err != nil {
		return fmt.Errorf("store: set mesh cidrs: %w", err)
	}
	return nil
}

// GetMeshCIDRs 读回 server 落库的 mesh 网段快照(逗号分隔 → 去空白项)。未设置(server 从未跑过 / 老库)返回
// (nil,nil):调用方据此**跳过**批准期重叠检查(退回数据面 rebuild 侧的运行时兜底),不误拦。
func (s *Store) GetMeshCIDRs(ctx context.Context) ([]string, error) {
	v, ok, err := s.SettingsGet(ctx, MeshCIDRsKey)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}
