//go:build linux

package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// V1(2026-05-26):Linux 实现 — 读 /proc/{stat,meminfo,net/dev}。
//
// 性能:三个文件总计 ~5KiB,bufio 流式扫描 < 0.1ms。/sysmon 前端 2s 拉一次,
// 每秒 ~500 Op,几乎 free。
//
// 安全:全是 read-only,sysctl 也不写;handler 端走 requireCSRFAndAuth(GET 路径)。
// 即便管理员账号被盗,泄露的也是 system stat — 没有比 dashboard 已有信息更敏感的。

// collectSysmonSnapshot 一次性采样所有三类指标。
//
// 任一文件读失败 → 返回 partial 结果 + 第一个错误(让 handler 决定要不要降级)。
// 设计选择:不"一错全失败"是因为容器场景 /proc/net/dev 可能被 securityContext
// hide 但 /proc/stat 可见,前端能看 CPU 也比一片 503 强。
func collectSysmonSnapshot() (*SysmonSnapshot, error) {
	snap := &SysmonSnapshot{}
	var firstErr error

	if total, idle, cores, err := readCPUStat(); err != nil {
		if firstErr == nil {
			firstErr = err
		}
	} else {
		snap.CPUTotalJiffies = total
		snap.CPUIdleJiffies = idle
		snap.CPUCores = cores
	}

	if err := readMemInfo(snap); err != nil {
		if firstErr == nil {
			firstErr = err
		}
	}

	if nics, err := readNetDev(); err != nil {
		if firstErr == nil {
			firstErr = err
		}
	} else {
		snap.NICs = nics
	}

	return snap, firstErr
}

// readCPUStat 解析 /proc/stat 第一行(聚合)+ 数 "cpuN " 行算核数。
//
// 格式参考(jiffies 单位,/proc/stat 第一行):
//
//	cpu  user nice system idle iowait irq softirq steal guest guest_nice
//	cpu0 ...
//	cpu1 ...
//
// 历史踩坑:不能用 runtime.NumCPU() 替代 cores —— 容器环境里 GOMAXPROCS 是
// cgroup cpu.cfs quota 算出的值(可能 < 物理核数),而 /proc/stat "cpuN" 行
// 还是按宿主机看到的物理核数列(/proc 没被容器 namespace 切),这里我们想要的
// 是"前端展示的核数",取后者更稳。
func readCPUStat() (totalJiffies, idleJiffies uint64, cores int, err error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0, 0, fmt.Errorf("open /proc/stat: %w", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "cpu ") {
			fields := strings.Fields(line)[1:] // 去掉 "cpu" 标签
			var sum uint64
			for i, fs := range fields {
				v, perr := strconv.ParseUint(fs, 10, 64)
				if perr != nil {
					continue
				}
				sum += v
				// idle 是第 4 列(index 3),iowait 是第 5 列(index 4)。
				// 老 kernel(2.4)只有 4 列,没 iowait — fallback 只算 idle。
				if i == 3 {
					idleJiffies += v
				}
				if i == 4 {
					idleJiffies += v
				}
			}
			totalJiffies = sum
			continue
		}
		// 数 cpuN 行算物理核数。Anchoring "cpu" + 数字 + 空格,避免误吞 "cpu" 单独那行。
		if len(line) >= 4 && line[:3] == "cpu" && line[3] >= '0' && line[3] <= '9' {
			cores++
		}
	}
	if err := sc.Err(); err != nil {
		return 0, 0, 0, fmt.Errorf("scan /proc/stat: %w", err)
	}
	if totalJiffies == 0 {
		return 0, 0, 0, newLocErr("sysmon.procStatNoCPU")
	}
	if cores == 0 {
		cores = 1 // 至少 1,防 0 除
	}
	return
}

// readMemInfo 解析 /proc/meminfo 关键字段,填入 snap.MemXxx / SwapXxx(字节)。
//
// /proc/meminfo 字段单位是 kB(实际是 KiB,man proc(5) 说就是 1024,只是写法
// 一直历史遗留写 kB)。本函数统一乘 1024 转 bytes。
//
// 字段:
//
//	MemTotal:     物理 RAM
//	MemFree:      完全空闲(应用一申请就被吃掉,实际不是"可用"维度)
//	MemAvailable: kernel 3.14+ 给出的"应用可申请且不触发 swap 的估算",首选
//	Buffers / Cached: page cache / slab,前端可显示让用户区分"真用了"和"被缓存吃"
//	SwapTotal / SwapFree: swap 总量 / 剩余
func readMemInfo(snap *SysmonSnapshot) error {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return fmt.Errorf("open /proc/meminfo: %w", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		key := line[:colon]
		// 取数字字段(空格分隔的第一个数字,后面可能是单位 "kB")。
		valStr := strings.TrimSpace(line[colon+1:])
		valStr = strings.TrimSuffix(valStr, " kB")
		valStr = strings.TrimSpace(valStr)
		v, perr := strconv.ParseUint(valStr, 10, 64)
		if perr != nil {
			continue
		}
		bytes := v * 1024
		switch key {
		case "MemTotal":
			snap.MemTotalBytes = bytes
		case "MemFree":
			snap.MemFreeBytes = bytes
		case "MemAvailable":
			snap.MemAvailableBytes = bytes
		case "Buffers":
			snap.MemBuffersBytes = bytes
		case "Cached":
			snap.MemCachedBytes = bytes
		case "SwapTotal":
			snap.SwapTotalBytes = bytes
		case "SwapFree":
			snap.SwapFreeBytes = bytes
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("scan /proc/meminfo: %w", err)
	}
	if snap.MemTotalBytes == 0 {
		return newLocErr("sysmon.procMeminfoNoMemTotal")
	}
	// 老内核没 MemAvailable,fallback 估算:free + buffers + cached
	// (内核 3.14- 上,这是当时 admin 工具的传统算法,误差 < 5%)。
	if snap.MemAvailableBytes == 0 {
		snap.MemAvailableBytes = snap.MemFreeBytes + snap.MemBuffersBytes + snap.MemCachedBytes
	}
	return nil
}

// readNetDev 解析 /proc/net/dev,**只返**物理网卡 + TUN 类(IsPhysical||IsTUN)。
//
// A8(2026-05-26):server-side 过滤而不是前端过滤。原因:
//
//   - 带宽:典型生产服务器有 docker(brige + 每 container 一个 veth)+ k8s pod 网络
//     veth + WireGuard wg* + loopback,粗算 10+ 张不感兴趣的网卡。每帧 JSON +500B
//     × N admin × 0.5 Hz = 不小累积浪费;
//   - 隐私:暴露内部网络拓扑(docker container 数 / k8s pod 数都能数出来),即便
//     只 admin 能看,仍是 unnecessary information disclosure;
//   - 客户端简化:前端不用再做 `n.is_physical || n.is_tun` 检查,后端契约清晰。
//
// 同时按 Name 字母序 sort(A5)— /proc/net/dev 是 kernel 内部 hash 顺序,网卡热插拔
// 后顺序会跳;sort 后前端列表稳定,折线图不会突然换位置。
//
// /proc/net/dev 格式(头两行是表头,从第 3 行起每行一个 iface):
//
//	Inter-|   Receive                                                |  Transmit
//	 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
//	    lo: 1234567   8910   0    0    0    0          0         0   1234567   8910   0    0    0    0       0          0
//	  eth0: ...
//
// 字段顺序:name: rx_bytes rx_packets rx_errs rx_drop rx_fifo rx_frame rx_compressed
//
//	rx_multicast tx_bytes tx_packets tx_errs tx_drop tx_fifo tx_colls tx_carrier tx_compressed
//
// 取 rx_bytes(field 0)、rx_packets(1)、tx_bytes(8)、tx_packets(9)。
func readNetDev() ([]SysmonNIC, error) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return nil, fmt.Errorf("open /proc/net/dev: %w", err)
	}
	defer f.Close()

	var out []SysmonNIC
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		if lineNo <= 2 {
			continue // 跳过两行表头
		}
		line := sc.Text()
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		name := strings.TrimSpace(line[:colon])
		fields := strings.Fields(line[colon+1:])
		if len(fields) < 10 {
			continue
		}
		isPhys := nicIsPhysical(name)
		isTUN := nicIsTUN(name)
		// A8 过滤:lo / docker0 / br-* / veth* / virbr* 等内部网卡跳过 — 既省带宽
		// 又不暴露内部网络拓扑。
		if !isPhys && !isTUN {
			continue
		}
		rxBytes, _ := strconv.ParseUint(fields[0], 10, 64)
		rxPackets, _ := strconv.ParseUint(fields[1], 10, 64)
		txBytes, _ := strconv.ParseUint(fields[8], 10, 64)
		txPackets, _ := strconv.ParseUint(fields[9], 10, 64)

		out = append(out, SysmonNIC{
			Name:       name,
			RXBytes:    rxBytes,
			RXPackets:  rxPackets,
			TXBytes:    txBytes,
			TXPackets:  txPackets,
			IsPhysical: isPhys,
			IsTUN:      isTUN,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan /proc/net/dev: %w", err)
	}
	// A5(2026-05-26):字母序 sort,前端列表稳定。kernel hash 顺序在网卡热插拔
	// 后会跳,sort 后用户视觉一致 — 重启 docker / 切 wg interface 后顺序不变。
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// nicIsPhysical:匹配常见物理网卡命名前缀。
//
// 注意 systemd predictable naming(udev/net.ifnames=1)规则:
//
//	en*  Ethernet(eno# / ens# / enp# / enx*)
//	wl*  WLAN
//	ww*  WWAN
//	eth* 传统名(net.ifnames=0 时的 fallback,virtio / vmware tools 仍常见)
//
// 不包含 lo / docker* / br-* / veth* / wg* / tun* / utun* / tap* / virbr*。
// 这是"主机对外网卡"集合,VPN 部署关心的是它跟 /vpn_bytes_* 的对照。
func nicIsPhysical(name string) bool {
	switch {
	case strings.HasPrefix(name, "eth"),
		strings.HasPrefix(name, "eno"),
		strings.HasPrefix(name, "ens"),
		strings.HasPrefix(name, "enp"),
		strings.HasPrefix(name, "enx"),
		strings.HasPrefix(name, "wlan"),
		strings.HasPrefix(name, "wlp"),
		strings.HasPrefix(name, "wls"),
		strings.HasPrefix(name, "wwan"),
		strings.HasPrefix(name, "wwp"):
		return true
	}
	return false
}

// nicIsTUN:VPN 自己的虚拟网卡前缀。
//
// 跨平台习惯:Linux tun* / tap*,Darwin utun*,部分 VPN 用 wg*(WireGuard),
// 自建项目里 vpn* 比较常见。/vpn_bytes_* 计的是 link 层(WSS / Reality)而不是
// TUN,但 TUN 流量统计跟它能合验:理论上 vpn_bytes_down ≈ tun_rx + 协议头/加密
// overhead。
func nicIsTUN(name string) bool {
	switch {
	case strings.HasPrefix(name, "tun"),
		strings.HasPrefix(name, "tap"),
		strings.HasPrefix(name, "utun"),
		strings.HasPrefix(name, "wg"),
		strings.HasPrefix(name, "vpn"):
		return true
	}
	return false
}
