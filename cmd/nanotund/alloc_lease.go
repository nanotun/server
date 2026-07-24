package main

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nanotun/server/store"
	"github.com/nanotun/server/util"
)

// contextWithTimeout 给 store 操作一个统一的短超时；500ms 对本地 SQLite 绰绰有余。
func contextWithTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 500*time.Millisecond)
}

// P3-e(2026-05-22):AllocOrLeaseVIP / VIPAssignment / pickFamilyVIP /
// tryUsePinnedVIP / previousLeaseVIP 已**整体删除**。
//
// 历史:这条路径是 PSK 模式早期为 "一次性按 device 分配 v4+v6" 写的便捷封装。
// 它的 tryUsePinnedVIP 不把 used 集传进去校验,存在「fixed-vip 撞别 device lease
// 时直接接受」的潜在 bug;且自始至终只被 alloc_lease_test.go 用,production 登录
// 路径走的是 server.go 里 preferredLeasedVIPs + dbReservedVIPs + mergeUsedVIPs +
// persistDeviceLease 组合(直接在 connectionsMu 锁内调 AllocClientIP)。
//
// 保留死代码会让未来读者误以为这是另一条等价路径,所以本期彻底拆除。
// preferredLeasedVIPs / persistDeviceLease / dbReservedVIPs / mergeUsedVIPs /
// gatewayAddrFromCIDR / isIPv4 / sameSubnet / contextWithTimeout 都是 production
// 仍在用的 helper,保留。

// sameSubnet 判断 candidate 是否在 gatewayCIDR 描述的网段内。
// 与 alloc.go 的 netip 解析保持一致；解析失败一律返回 false。
func sameSubnet(gatewayCIDR, candidate string) bool {
	prefix, err := netip.ParsePrefix(gatewayCIDR)
	if err != nil {
		return false
	}
	addr, err := netip.ParseAddr(candidate)
	if err != nil {
		return false
	}
	return prefix.Contains(addr)
}

// gatewayAddrFromCIDR 把 "100.64.0.1/24" 这种网关 CIDR 拆出网关地址 "100.64.0.1"。
// 解析失败返回原串前的子串，让调用方仍能往下走（最坏只是日志里 gateway 字段不规范）。
func gatewayAddrFromCIDR(gatewayCIDR string) string {
	prefix, err := netip.ParsePrefix(gatewayCIDR)
	if err != nil {
		return gatewayCIDR
	}
	return prefix.Addr().Unmap().String()
}

// preferredLeasedVIPs 在 PSK + device 模式下查询出该设备应当优先获得的 vIP。
//
// 0008(2026-05-23):「固定 vIP」从 user 级搬到 device 级,因为协议层 device_uuid
// 强制 RFC 4122 v4,(user_id, device_uuid) 在 devices 表本来就 UNIQUE,「这台设备
// 每次拿同一个 vIP」是更自然的 fixed 语义,且支持多设备用户每台独立钉死。
//
// 优先级:device.fixed_vip_* > 该 device 上一次的 lease。返回 (v4, v6),任一
// 为空表示无偏好。
//
// 设备不存在(客户端没上报 device_uuid 等非常规场景)时,直接返回 "",""  ——
// 与之前「user.fixed_vip」语义不同:之前哪怕没 device 也会把 fixed 当 hint,但
// 这反而是个 bug(没 device 写不了 lease,fixed 偏好也无处落地;只在 alloc 时
// 影响 in-memory 分配,下次连进来又拿不到同样的 IP)。改成 device 级后,语义统一:
//   - 没 device → 走纯自动分配, fixed 与本次会话无关
//   - 有 device → fixed > 历史 lease > 自动分配
//
// 任何 DB 错误都被吞掉（仅日志路径外回 ""），把决策权让回标准 AllocClientIP,
// 确保登录健壮。
func preferredLeasedVIPs(gw *gatewayState, res *loginAuthResult) (v4, v6 string) {
	if gw == nil || gw.store == nil || res == nil || res.Device == nil {
		return "", ""
	}
	if res.Device.FixedVIPv4 != "" {
		v4 = res.Device.FixedVIPv4
	}
	if res.Device.FixedVIPv6 != "" {
		v6 = res.Device.FixedVIPv6
	}
	ctx, cancel := contextWithTimeout()
	defer cancel()
	prev, err := gw.store.GetLeaseByDevice(ctx, res.Device.ID)
	if err != nil || prev == nil {
		return v4, v6
	}
	if v4 == "" && prev.VIPv4 != "" {
		v4 = prev.VIPv4
	}
	if v6 == "" && prev.VIPv6 != "" {
		v6 = prev.VIPv6
	}
	return v4, v6
}

// preferredVIPUsable 判断一个「偏好 vIP」(device.fixed_vip 或历史 lease)能否直接采用:非空、内存 used 集
// 未占用、在网段内、且**既不是网关地址也不是网络地址**。
//
// 此前登录 fast-path 只判 `!clientIPUsed[vip] && sameSubnet(...)`,漏了网关 / 网络地址:自动分配路径
// (AllocClientIP)从 i=2 起扫且显式 `continue` 掉网关,天然避开网关 / 网络 / 广播;但 fast-path 直接采用
// 偏好 vIP 没有这层过滤——若 admin 把 fixed_vip 手钉成网关(如 10.0.0.1),sameSubnet 通过、used 里也没有,
// 客户端就被分到网关地址,与 server 网关冲突、该客户端路由全断。这里补齐同等过滤。
func preferredVIPUsable(gatewayCIDR, vip string, used map[string]bool) bool {
	if vip == "" || used[vip] {
		return false
	}
	prefix, err := netip.ParsePrefix(gatewayCIDR)
	if err != nil {
		return false
	}
	addr, err := netip.ParseAddr(vip)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	if !prefix.Contains(addr) {
		return false
	}
	if addr == prefix.Addr().Unmap() {
		return false // 网关地址
	}
	if addr == prefix.Masked().Addr().Unmap() {
		return false // 网络地址(全 0 主机位)
	}
	// IPv4 定向广播地址(全 1 主机位,如 10.0.0.255/24)也必须排除(第四轮深扫 MED):AllocClientIP 从 i=2 起
	// 扫描不会碰到广播位,但 fast-path 直接采用偏好 vIP 没这层过滤——admin 把 fixed_vip 手钉成广播地址会让该
	// 客户端拿到广播 IP,内核对广播源地址的报文处理异常(部分栈直接丢弃),该客户端数据面不可用。
	if bcast, ok := ipv4DirectedBroadcast(prefix); ok && addr == bcast {
		return false
	}
	return true
}

// ipv4DirectedBroadcast 返回 IPv4 前缀的定向广播地址(网络地址 | 全 1 主机位)。仅对 IPv4 且掩码 < /31 有效
// (/31、/32 无广播概念,RFC 3021)。非 IPv4 / 无广播时 ok=false。
func ipv4DirectedBroadcast(prefix netip.Prefix) (netip.Addr, bool) {
	network := prefix.Masked().Addr().Unmap()
	if !network.Is4() {
		return netip.Addr{}, false
	}
	bits := prefix.Bits()
	if bits < 0 || bits >= 31 {
		return netip.Addr{}, false
	}
	b := network.As4()
	netU := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	hostMask := uint32(0xffffffff) >> uint(bits) // 低 (32-bits) 位全 1
	bU := netU | hostMask
	return netip.AddrFrom4([4]byte{byte(bU >> 24), byte(bU >> 16), byte(bU >> 8), byte(bU)}), true
}

// persistDeviceLease 把本次分配到的 v4 / v6 写回 leases 表。
//
// 仅在 PSK + 设备已注册时生效；其它情况是无害 noop(返回 nil)。
// 注意：本调用故意放在 connectionsMu/clientIPUsedMu 之外，避免长时间持锁等 SQLite。
//
// 返回值约定:
//   - nil:                    持久化成功(或本就是 noop 情况);
//   - store.ErrDuplicate:     vIP UNIQUE 冲突(同一 vIP 已被另一台设备持有)。这是
//     业务层必须严肃处理的错误,意味着 alloc 路径漏算了 db
//     里的离线 lease,继续登录会让数据面双重占用同一个 vIP,
//     路由黑洞。调用方应拒登并撤销内存里的 clientIPUsed。
//   - 其它 error:              非致命 DB 故障(timeout / 暂时 IO 问题等)。调用方应记
//     warn,但**可以继续放行登录** —— lease 表存不下不影响
//     本次会话的数据面,下次登录会重新分配,符合「DB 故障
//     降级到无 lease 模式」的设计目标。
func persistDeviceLease(gw *gatewayState, res *loginAuthResult, assignments []util.VirtualIPAssignment) error {
	if gw == nil || gw.store == nil || res == nil || res.Device == nil {
		return nil
	}
	if len(assignments) == 0 {
		return nil
	}
	var v4, v6 string
	for _, a := range assignments {
		if isIPv4(a.VirtualIP) {
			if v4 == "" {
				v4 = a.VirtualIP
			}
		} else {
			if v6 == "" {
				v6 = a.VirtualIP
			}
		}
	}
	if v4 == "" && v6 == "" {
		return nil
	}
	// 0008:manual 标记表示「这次 lease 来自管理员手钉的 fixed_vip,不是 pool 自动分配」。
	// 之前看 res.User.Fixed*,改 device 级后看 res.Device.Fixed*。
	manual := false
	if res.Device != nil {
		if (v4 != "" && v4 == res.Device.FixedVIPv4) ||
			(v6 != "" && v6 == res.Device.FixedVIPv6) {
			manual = true
		}
	}
	ctx, cancel := contextWithTimeout()
	defer cancel()
	if _, err := gw.store.UpsertLease(ctx, res.Device.ID, v4, v6, manual); err != nil {
		if errors.Is(err, store.ErrDuplicate) {
			// UNIQUE 冲突:必须拒登,避免数据面双重占用同一个 vIP。
			logrus.WithError(err).WithFields(logrus.Fields{
				"device_id": res.Device.ID,
				"vip_v4":    v4,
				"vip_v6":    v6,
			}).Error("upsert lease 撞 vIP UNIQUE 冲突 -> 拒登 -> 释放内存占用 vIP;请检查 alloc 路径是否把 db 中离线 lease 算入 used 集合(dbReservedVIPs / mergeUsedVIPs)")
			return err
		}
		// 非冲突类故障:仅 Warn,但放行登录(返回 nil)。
		logrus.WithError(err).WithFields(logrus.Fields{
			"device_id": res.Device.ID,
			"vip_v4":    v4,
			"vip_v6":    v6,
		}).Warn("upsert lease 失败(非 UNIQUE 冲突),下次登录会重新分配,不影响当前会话")
		return nil
	}
	return nil
}

// dbReservedVIPs 返回除本设备 lease 之外、db leases 表里被占用的 v4 / v6 集合。
//
// 用于登录路径的 AllocClientIP 调用：把「虽然离线但 lease 还在」的 vIP 也算进 used，
// 避免给新设备分到已被持久化的别人的 vIP（写 lease 时撞 leases.vip_v4/_v6 UNIQUE
// 索引 → UpsertLease 静默失败 → 同一个 vIP 在多台 device 上「重叠分配」）。
//
// exceptV4 / exceptV6：本次登录的设备**自身**占用的 vIP 列表(fixed + lease,两族),从已用集里剔除,避免把
// 自己挡在外面。见 deviceReservedVIPExceptions。
//
// 任何错误都被吞掉、仅日志：lease 一致性是 best-effort，不应让登录失败。
func dbReservedVIPs(gw *gatewayState, exceptV4, exceptV6 []string) (map[string]bool, map[string]bool) {
	if gw == nil || gw.store == nil {
		return nil, nil
	}
	ctx, cancel := contextWithTimeout()
	defer cancel()
	v4, v6, err := gw.store.AllUsedVIPs(ctx)
	if err != nil {
		logrus.WithError(err).Warn("加载 db lease used 失败，登录回落仅用内存 used 集分配 vIP")
		return nil, nil
	}
	for _, e := range exceptV4 {
		if e != "" {
			delete(v4, e)
		}
	}
	for _, e := range exceptV6 {
		if e != "" {
			delete(v6, e)
		}
	}
	return v4, v6
}

// deviceReservedVIPExceptions 返回本设备**自己**占用的全部 vIP(devices.fixed_vip_* + 当前 leases.vip_*,两族,去空),
// 供 dbReservedVIPs 从「db 已用集」里剔除 —— 本设备自身的地址不该被当成「别人占用」而把自己挡在外面。
//
// 第十九轮深扫 MED:此前登录路径把 preferredLeasedVIPs(fixed **优先于** lease 的**合并**结果)当 except 传入。
// 当 fixed≠lease(如 `set-fixed-vip --force` 撞上仍在线的旧持有者、或 fixed 地址掉出网段)时,只剔除了 fixed、
// **漏剔本设备的实际 lease** → 该 lease 被当他人占用、本设备既复用不到也回收不了 → 分到第三个地址,于是 fixed 与
// 新 lease 并存、同一设备双占两个 vIP(小前缀上白烧地址)。这里返回**fixed 与 lease 全部**,确保本设备自身地址
// 一律被 except。查库出错(best-effort)时仅退回 fixed 部分,不阻断登录。
func deviceReservedVIPExceptions(gw *gatewayState, res *loginAuthResult) (v4s, v6s []string) {
	if gw == nil || gw.store == nil || res == nil || res.Device == nil {
		return nil, nil
	}
	add := func(dst *[]string, v string) {
		if v != "" {
			*dst = append(*dst, v)
		}
	}
	add(&v4s, res.Device.FixedVIPv4)
	add(&v6s, res.Device.FixedVIPv6)
	ctx, cancel := contextWithTimeout()
	defer cancel()
	if prev, err := gw.store.GetLeaseByDevice(ctx, res.Device.ID); err == nil && prev != nil {
		add(&v4s, prev.VIPv4)
		add(&v6s, prev.VIPv6)
	}
	return v4s, v6s
}

// mergeUsedVIPs 返回 a ∪ b 的新集合（不修改任一入参；nil 视为空集）。
//
// 用于把「内存 clientIPUsed」与「db dbReservedVIPs」临时合并喂给 AllocClientIP，
// 不污染 clientIPUsed 全局变量本身（clientIPUsed 仅追踪「在线 device」）。
func mergeUsedVIPs(a, b map[string]bool) map[string]bool {
	out := make(map[string]bool, len(a)+len(b))
	for k := range a {
		out[k] = true
	}
	for k := range b {
		out[k] = true
	}
	return out
}

func isIPv4(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return addr.Is4() || addr.Is4In6()
}
