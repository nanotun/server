package store

import (
	"context"
	"strconv"
	"strings"
)

// MeshEnabledKey 是 app_settings 表里持久化「全网组网模式总开关」的 key。
//
// 语义(2026-05-23 引入;2026-07-19 深扫后按「跨用户全断,fail-closed」定稿):
//   - true(默认):跨用户流量按 ACL 规则集 + acl_default_action 裁决,允许节点互通(mesh)。
//   - false:不论 ACL 规则怎么配,server 数据面在 demux 入口直接 drop 所有跨用户 vIP→vIP 流量。
//     被切断的包括:跨用户设备互访、访问他人宣告的子网(含 4via6)、以及**借用他人设备做
//     公网出口**——出口回程(出口机→server,dst=请求方 vIP)是跨用户 vIP 流量,同样被拦,
//     表现为去程可发、回程全丢(连接超时)。这是有意的 fail-closed:隔离闸拉下时不自动
//     改道他人流量(不静默切回 server 出口),宁断不漏。
//     不受影响的:user-internal(自己 device 间)、server 自出口与**自己的**出口节点——
//     客户端仍能用 VPN 上公网。
//
// 这是一个**部署级**总开关,跟「ACL 细粒度规则」是两个层级:
//   - 管理员配置好的 acl_pairs 不会因为 toggle 此开关而被删除或修改;
//   - toggle 回 true 后,所有原有 ACL 规则原状恢复生效;
//   - 适合的运维场景:临时关闭 mesh 隔离一批客户端、安全演习、做大版本数据面变更前的预防性切流量。
const MeshEnabledKey = "mesh_enabled"

// GetMeshEnabled 读 mesh_enabled setting。
//
// 三类 case 都视为 true(默认放开):
//  1. key 不存在(新部署 / 老数据库未迁过此键);
//  2. key 存在但 value 是空串 / 解析失败 — 不让坏数据破坏既有 mesh 流量;
//  3. key 存在且 value ∈ {"true","1","yes","on"}(大小写不敏感)。
//
// 仅当 value 明确是 {"false","0","no","off"} 时返回 false。
//
// 任何 DB 错误都返回 (true, err) — 调用方可以选择记日志但仍按 "默认 on" 走,
// 避免 SQLite 临时不可读时把整个 mesh 网络误关闭。
func (s *Store) GetMeshEnabled(ctx context.Context) (bool, error) {
	v, ok, err := s.SettingsGet(ctx, MeshEnabledKey)
	if err != nil {
		return true, err
	}
	if !ok {
		return true, nil
	}
	return parseMeshEnabled(v), nil
}

// SetMeshEnabled 写 mesh_enabled setting。落库后调用方应主动触发 server reload,
// 让数据面 snapshot 同步新值(不 reload 也不会破坏数据,只是要等下一次 SIGHUP / 重启)。
func (s *Store) SetMeshEnabled(ctx context.Context, enabled bool) error {
	v := "false"
	if enabled {
		v = "true"
	}
	return s.SettingsSet(ctx, MeshEnabledKey, v)
}

// parseMeshEnabled 把 setting value 字符串解析为 bool,容错处理常见多种写法。
// 暴露成包级函数是为了让 server / web 在直接读 SettingsGet 后也能复用同一套语义。
func parseMeshEnabled(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "false", "0", "no", "off":
		return false
	case "true", "1", "yes", "on":
		return true
	}
	// 兜底再试一次 strconv.ParseBool(它接受 "T","F","TRUE","FALSE" 等)。
	if b, err := strconv.ParseBool(v); err == nil {
		return b
	}
	// 完全不认识的值 → 按默认 true 处理,避免坏数据让整网误隔离。
	return true
}
