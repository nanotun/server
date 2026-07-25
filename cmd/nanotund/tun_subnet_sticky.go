package main

import (
	"context"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/nanotun/server/store"
	"github.com/sirupsen/logrus"
)

// 本文件解决「重启后 mesh 网段漂移」：`[tun] subnets` 配多个候选时，选中哪一个此前只取决于
// 「与本机不冲突的候选列表」+ 一个进程内计数器（见 server.go 的 tunRandSeed）。于是本机接口
// 一变（多起一个 VPN / Docker / 同机跑一个 nanotun 客户端），可用候选集合的**下标含义**就变了，
// 重启后整个 mesh 换网段：
//
//   - 所有 lease 作废，客户端全部换 vIP（用户侧按 vIP 写的防火墙 / 文档 / 端口转发目标全失配）；
//   - admin 用 `device set-fixed-vip` 钉的地址掉出新网段 → 登录时被**静默**跳过（见
//     logFixedVIPOutOfRange），而 `device list` 仍然显示那个钉住的地址；
//   - 2026-07-25 双机实测复现：停掉一个占着 10.201/16 的残留客户端后重启 server，mesh 从
//     10.202.0.1/16 变成 10.201.0.1/16，钉住的 10.202.0.77 被无声忽略、设备拿到 10.201.0.3。
//
// 修法：把上次实际用过的网段（server 启动时落库的 mesh_cidrs 快照）当**优先项**——只要它这次仍在
// 可用候选里就继续用，否则才回退原有轮转。纯偏好，不改冲突过滤，也不改「候选全冲突就跳过该族」。

// stickySubnetProbeTimeout 给「启动前只读探一次上次网段」的 SQLite 操作一个短超时。
// 探测失败一律当「没有偏好」处理，绝不阻断启动。
const stickySubnetProbeTimeout = 2 * time.Second

// readPersistedMeshGateways 只读探测上次落库的 mesh 网关 CIDR 快照（mesh_cidrs）。
//
// 调用点在 TUN 配置之前，此时主 store 还没打开（initAuthBackend 在后面），故这里独立开一个
// **只读**连接、读完即关。库文件不存在（首次部署）/ 打不开 / 无该 key → 返回 nil，调用方按
// 「无偏好」走原有选择逻辑。
func readPersistedMeshGateways(dbPath string) []string {
	dbPath = strings.TrimSpace(dbPath)
	if dbPath == "" {
		return nil
	}
	// 首次部署库文件还不存在：直接返回，避免只读打开在某些驱动下创建空库。
	if _, err := os.Stat(dbPath); err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), stickySubnetProbeTimeout)
	defer cancel()
	st, err := store.Open(ctx, dbPath, store.Options{ReadOnly: true})
	if err != nil {
		logrus.WithError(err).Debug("[tun-subnet] 只读探测上次 mesh 网段失败,按无偏好处理")
		return nil
	}
	defer func() { _ = st.Close() }()
	cidrs, err := st.GetMeshCIDRs(ctx)
	if err != nil {
		logrus.WithError(err).Debug("[tun-subnet] 读 mesh_cidrs 失败,按无偏好处理")
		return nil
	}
	return cidrs
}

// pickStickySubnet 在 usable 候选里挑上次用过的那个，返回其下标；没有匹配返回 -1。
//
// prevGateways 是网关 CIDR（如 "10.202.0.1/16"），候选是网段 CIDR（如 "10.202.0.0/16"），
// 故按「候选前缀是否包含上次的网关地址」比对，而不是字符串相等。族由 wantV4 选定：同一次启动
// 要分别为 v4 / v6 各挑一次，不能让 v6 的快照影响 v4 的选择。
func pickStickySubnet(usable []string, prevGateways []string, wantV4 bool) int {
	for _, gwCIDR := range prevGateways {
		prevPrefix, err := netip.ParsePrefix(strings.TrimSpace(gwCIDR))
		if err != nil {
			continue
		}
		prevAddr := prevPrefix.Addr().Unmap()
		if prevAddr.Is4() != wantV4 {
			continue
		}
		for i, cand := range usable {
			candPrefix, err := netip.ParsePrefix(strings.TrimSpace(cand))
			if err != nil {
				continue
			}
			// 前缀长度也要一致：同一网段换掩码等于换地址池，不能当「同一个网段」沿用。
			if candPrefix.Bits() != prevPrefix.Bits() {
				continue
			}
			if candPrefix.Contains(prevAddr) {
				return i
			}
		}
	}
	return -1
}

// chooseTUNSubnet 挑本次要用的网段：优先沿用上次（sticky），否则退回原有轮转计数器。
// 返回选中的候选与「是否沿用了上次」。usable 非空由调用方保证。
func chooseTUNSubnet(usable []string, prevGateways []string, wantV4 bool) (subnet string, sticky bool) {
	if i := pickStickySubnet(usable, prevGateways, wantV4); i >= 0 {
		return usable[i], true
	}
	// 无偏好（首次部署 / 上次网段这次不可用 / 运维改了 subnets 列表）→ 原有轮转。
	return usable[int(tunRandSeed.Add(1))%len(usable)], false
}

// fixedVIPWarnOnce 给 warnFixedVIPOutOfMesh 去重:key = "<device_id>|<pin>|<gateway>"。
// 每次重启清零(网段漂移正是重启时发生的),在线设备数量级有界,不会无限增长。
var fixedVIPWarnOnce sync.Map

// warnFixedVIPOutOfMesh 在设备的 fixed vIP 掉出当前 mesh 网段时告警一次。
//
// 掉出网段的钉住地址会被 preferredVIPUsable 判为不可用 → 登录路径静默改走自动分配，设备拿到一个
// 陌生 vIP，而 `nanotun-admin device list` 仍然显示 FIXED_V4=<旧地址>。运维看到的是「钉了但没用上，
// 且没人说为什么」。数据面行为不变（继续自动分配，这是对的——钉的地址在新网段里不可路由），
// 只补上缺失的可观测性；要恢复钉住语义得 `device set-fixed-vip` 改到新网段内。
func warnFixedVIPOutOfMesh(res *loginAuthResult) {
	if res == nil || res.Device == nil {
		return
	}
	for _, p := range []struct {
		pin     string
		gateway string
		family  string
	}{
		{res.Device.FixedVIPv4, sharedTUNGateway, "ipv4"},
		{res.Device.FixedVIPv6, sharedTUNGatewayV6, "ipv6"},
	} {
		if p.pin == "" || p.gateway == "" {
			continue
		}
		if sameSubnet(p.gateway, p.pin) {
			continue
		}
		key := p.pin + "|" + p.gateway
		if _, dup := fixedVIPWarnOnce.LoadOrStore(key, struct{}{}); dup {
			continue
		}
		logrus.WithFields(logrus.Fields{
			"device_id":   res.Device.ID,
			"device_uuid": res.Device.DeviceUUID,
			"fixed_vip":   p.pin,
			"mesh":        p.gateway,
			"family":      p.family,
		}).Warn("[tun-subnet] 设备的 fixed vIP 不在当前 mesh 网段内,本次登录已改为自动分配 " +
			"(device list 仍会显示这个钉住的值;要恢复请 `nanotun-admin device set-fixed-vip` 改到网段内)")
	}
}

// logMeshSubnetMoved 在本次选中的网段与上次快照不一致时**显式告警**。
//
// 网段漂移会作废全部 lease 与钉住的 fixed vIP，是运维必须知道的事件；此前整条路径一行日志都没有，
// 只能靠客户端拿到陌生 vIP 反推。走 sticky 之后正常重启不会再触发，真触发就说明上次网段这次不可用
// （本机新增了冲突接口 / 运维改了 subnets），日志会点明该去看什么。
func logMeshSubnetMoved(prevGateways []string, newGatewayV4, newGatewayV6 string) {
	if len(prevGateways) == 0 {
		return // 首次部署：没有「上次」可比
	}
	prev := make(map[string]bool, len(prevGateways))
	for _, g := range prevGateways {
		if g = strings.TrimSpace(g); g != "" {
			prev[g] = true
		}
	}
	for _, cur := range []string{newGatewayV4, newGatewayV6} {
		if cur == "" || prev[cur] {
			continue
		}
		logrus.WithFields(logrus.Fields{
			"previous": strings.Join(prevGateways, ","),
			"current":  cur,
		}).Warn("[tun-subnet] mesh 网段与上次启动不同:全部 lease 将重新分配,掉出新网段的 fixed vIP 会被跳过 " +
			"(多为本机新增了与旧网段冲突的接口,或 [tun] subnets 列表被改动)")
	}
}
