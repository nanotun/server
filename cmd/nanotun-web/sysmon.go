package main

// V1(2026-05-26):/sysmon 页面所需的系统资源采样接口。
//
// 与具体 OS 解耦:实现走 `sysmon_linux.go`(读 /proc/{stat,meminfo,net/dev})
// 或 `sysmon_other.go`(stub,本机 macOS / Windows 开发可编译,返回 ErrSysmonUnsupported)。
//
// 设计选择 — 为什么不直接引第三方库(gopsutil / procfs):
//   - 我们只读 3 个 /proc 文件 + 简单正则解析,共 ~120 行,跨进程零分配;
//   - gopsutil 把 disk/CPU/temperature/process/swap/load 全捆一起,binary +1.5MB
//     还引 cgo,nanotun-web 当前 13MiB,加上去 +12%,对一台小内存 VPS 不友好;
//   - 调试简单:直接 cat /proc/stat 对照本接口输出,几秒钟就能定位问题。
//
// 错误模型:本机不可读 /proc(非 Linux / 容器 securityContext 太严)直接返
// ErrSysmonUnsupported,handler 把它转 503 + JSON {"error":...} 让前端展示
// "本机暂不支持系统监控",而不是 500 panic。

// SysmonSnapshot:一次采样结果。前端做两次采样差分算速度。
type SysmonSnapshot struct {
	// CPU(/proc/stat 第一行 "cpu" 聚合):
	//
	//	CPUTotalJiffies   = user + nice + system + idle + iowait + irq + softirq + steal + ...
	//	CPUIdleJiffies    = idle + iowait(传统约定,iowait 等同空闲)
	//
	// 前端两次采样差分:busy% = 1 - (idleΔ / totalΔ)
	CPUTotalJiffies uint64 `json:"cpu_total_jiffies"`
	CPUIdleJiffies  uint64 `json:"cpu_idle_jiffies"`
	CPUCores        int    `json:"cpu_cores"` // 用 /proc/stat "cpuN " 行数算,不依赖 runtime.NumCPU(容器 cgroup quota 可能比实际少)

	// 内存(/proc/meminfo,单位 KiB,本接口已乘 1024 转字节):
	MemTotalBytes     uint64 `json:"mem_total_bytes"`
	MemFreeBytes      uint64 `json:"mem_free_bytes"`
	MemAvailableBytes uint64 `json:"mem_available_bytes"` // Linux 3.14+ 自带 MemAvailable;老内核 fallback 到 free+buffers+cached
	MemBuffersBytes   uint64 `json:"mem_buffers_bytes"`
	MemCachedBytes    uint64 `json:"mem_cached_bytes"`
	SwapTotalBytes    uint64 `json:"swap_total_bytes"`
	SwapFreeBytes     uint64 `json:"swap_free_bytes"`

	// 网卡:每个网卡的累计 RX/TX 字节,前端差分算 bytes/sec。
	//
	// A8(2026-05-26):server 端已过滤,只返 IsPhysical || IsTUN 的网卡 ——
	// lo / docker* / br-* / veth* / virbr* 等容器内部网卡都在 readNetDev 内被
	// drop,既省带宽又不暴露内部网络拓扑。
	//
	// A5(2026-05-26):字母序 sort,渲染顺序稳定(kernel hash 顺序在网卡热
	// 插拔后会跳)。
	//
	// 前端 sysmon.html 直接 `var keep = nics || []`,不再二次 filter。
	NICs []SysmonNIC `json:"nics"`
}

// SysmonNIC:单个网卡的累计字节计数(/proc/net/dev "Receive bytes" / "Transmit bytes")。
//
// IsPhysical / IsTUN 是 server 端 readNetDev 设的标签,前端用来:
//   - 决定 badge 颜色(物理=绿色,TUN=灰色);
//   - 排查 — admin 一眼能区分 eth0 跟 tun0 谁的速率是什么。
//
// A8 之后,SysmonSnapshot.NICs 只会有 IsPhysical=true 或 IsTUN=true 的条目,
// 其它内部网卡(lo / docker* / br-* / veth*)在 server 端已 drop,不会出现在切片里。
type SysmonNIC struct {
	Name       string `json:"name"`
	RXBytes    uint64 `json:"rx_bytes"`
	TXBytes    uint64 `json:"tx_bytes"`
	RXPackets  uint64 `json:"rx_packets"`
	TXPackets  uint64 `json:"tx_packets"`
	IsPhysical bool   `json:"is_physical"` // 命中常见物理网卡前缀(eth*/ens*/eno*/enp*/wlan*/...)
	IsTUN      bool   `json:"is_tun"`      // tun* / utun* / vpn* / tap* / wg*(VPN 自身的虚拟网卡)
}

// ErrSysmonUnsupported:非 Linux 平台返回。handler 应翻译为 503 + JSON 提示。
// 用 newLocErr,让展示到 dashboard 的 HostError 能按请求语言翻译(trErr);
// Error() 仍返回 zh 供日志/errors.Is 之外场景与旧行为一致。
var ErrSysmonUnsupported = newLocErr("sysmon.unsupported")
