package main

import (
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/songgao/water"

	"github.com/nanotun/server/util"
)

func dialVPN(addr string, preferWSS, tlsInsecure bool) (net.Conn, error) {
	s := strings.TrimSpace(addr)
	low := strings.ToLower(s)
	if strings.HasPrefix(low, "ws://") || strings.HasPrefix(low, "wss://") {
		var tlsCfg *tls.Config
		if strings.HasPrefix(low, "wss://") && tlsInsecure {
			tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}
		}
		return util.DialVPNWebSocket(s, 30*time.Second, tlsCfg)
	}
	if strings.HasPrefix(low, "tcp://") {
		s = s[6:]
	}
	if strings.Contains(s, "://") {
		return nil, fmt.Errorf("不支持的 server 地址 %q：请使用 host:port 或 ws(s)://host:port/path", addr)
	}
	scheme := "ws"
	if preferWSS {
		scheme = "wss"
	}
	wsURL := scheme + "://" + s + util.DefaultVPNWebSocketPath
	var tlsCfg *tls.Config
	if preferWSS && tlsInsecure {
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}
	}
	return util.DialVPNWebSocket(wsURL, 30*time.Second, tlsCfg)
}

func main() {
	logrus.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})
	logrus.SetLevel(logrus.InfoLevel)

	serverAddr := flag.String("server", "localhost:8080", "VPN：host:port 或完整 ws(s)://host:port/路径；-wss 时 host:port 走 wss+默认路径")
	vpnWSS := flag.Bool("wss", false, "与 host:port 组合为 wss://（服务端 [server] 启用 TLS 时使用）")
	vpnTLSInsecure := flag.Bool("vpn-tls-insecure", false, "wss 时跳过证书校验（自签/内测；生产勿用）")
	token := flag.String("token", "", "PSK 明文（由 nanotun-admin 创建用户时签发）")
	tunnelMode := flag.Bool("tunnel", false, "隧道模式：创建本地 TUN，与同一条 TCP 链路双向转发 IP 包（类型 5，需 root）")
	tunIP := flag.String("tun-ip", "10.0.0.2/24", "隧道模式下本机 TUN 的 IP（可由下发表覆盖）")
	simulateIcmp := flag.Bool("simulate-icmp", false, "经链路类型 5 发送 ICMP Echo Request 到网关并等待 Echo Reply")
	// 接管模式（与 Rust 客户端同步的 e2e/smoke 工具）：
	//   先用一个常规客户端登录，server 在 LoginResp 中下发 sessionID 与 takeoverSecret；
	//   再开第二个客户端，把这两个值通过下面两个 flag 传入 → 走 PURPOSE_TAKEOVER 路径
	//   接管原会话（PSK 模式下原 vip 原子复用，无需任何外部调用）。
	takeoverSessionID := flag.String("takeover-session-id", "", "接管模式：上一次 LoginResp 返回的 session_id；非空则本次 LoginReq 走 PURPOSE_TAKEOVER")
	takeoverSecret := flag.String("takeover-secret", "", "接管模式：上一次 LoginResp 返回的 takeover_secret；非空与 -takeover-session-id 配合启用接管")
	flag.Parse()

	logrus.Infof("连接 VPN 链路: %s", *serverAddr)

	conn, err := dialVPN(*serverAddr, *vpnWSS, *vpnTLSInsecure)
	if err != nil {
		logrus.Fatalf("Dial 失败: %v", err)
	}
	defer conn.Close()
	logrus.Info("WebSocket VPN 已连接")

	isTakeover := *takeoverSessionID != "" || *takeoverSecret != ""
	var loginBody []byte
	if isTakeover {
		if *takeoverSessionID == "" || *takeoverSecret == "" {
			logrus.Fatal("-takeover-session-id 与 -takeover-secret 必须同时提供（或同时为空走 primary 登录）")
		}
		loginBody, err = util.MarshalLoginReqTakeoverJSON(
			"", "", *token, "client", runtime.GOOS, util.LinkTransportWebSocket,
			*takeoverSessionID, *takeoverSecret,
		)
		if err != nil {
			logrus.Fatalf("构造接管登录请求失败: %v", err)
		}
		logrus.Infof("接管模式：session_id=%s secret_len=%d", *takeoverSessionID, len(*takeoverSecret))
	} else {
		loginBody, err = util.MarshalLoginReqJSON("", "", *token, "client", runtime.GOOS, util.LinkTransportWebSocket)
		if err != nil {
			logrus.Fatalf("构造登录请求失败: %v", err)
		}
	}
	if err := util.WriteLinkFrame(conn, util.LinkTypeLoginReq, loginBody); err != nil {
		logrus.Fatalf("发送登录请求失败: %v", err)
	}
	logrus.Info("已发送登录请求")

	typ, payload, err := util.ReadLinkFrame(conn)
	if err != nil {
		logrus.Fatalf("读取登录响应失败: %v", err)
	}
	if typ != util.LinkTypeLoginResp {
		logrus.Fatalf("期望登录响应类型 %d，收到 %d", util.LinkTypeLoginResp, typ)
	}
	loginResp, err := util.ParseLoginRespLinkPayload(payload)
	if err != nil {
		logrus.Fatalf("解析登录响应失败: %v", err)
	}
	if loginResp.Code != 0 {
		logrus.Fatalf("登录失败: %s", loginResp.Message)
	}
	logrus.Infof("登录成功: %s", loginResp.Message)
	if loginResp.SessionID != "" || loginResp.TakeoverSecret != "" {
		// primary 登录后 server 会下发 sessionID + takeoverSecret，留给后续 -takeover 使用。
		// 接管登录回写的是 same/同样的 sessionID + 新的 takeoverSecret（用于下一轮接管）。
		mode := "primary"
		if isTakeover {
			mode = "takeover"
		}
		logrus.Infof("[%s] 收到 LoginResp 接管凭证: session_id=%s takeover_secret_len=%d",
			mode, loginResp.SessionID, len(loginResp.TakeoverSecret))
	}

	typ, payload, err = util.ReadLinkFrame(conn)
	if err != nil {
		logrus.Fatalf("读取 ConvSaltLite 失败: %v", err)
	}
	if typ != util.LinkTypeConvSaltMsg {
		logrus.Fatalf("期望 ConvSaltLite 类型 %d，收到 %d", util.LinkTypeConvSaltMsg, typ)
	}
	lite, err := util.ParseConvSaltLiteLinkPayload(payload)
	if err != nil {
		logrus.Fatalf("解析 ConvSaltLite 失败: %v", err)
	}

	if len(lite.VirtualIPAssignments) > 0 {
		logrus.Info("=== 服务端下发的虚拟 IP 下发表 ===")
		for i, a := range lite.VirtualIPAssignments {
			logrus.Infof("  [%d] 虚拟IP: %s  (mask: %s, gateway: %s)", i+1, a.VirtualIP, a.Mask, a.Gateway)
		}
		logrus.Info("======================================")
	}
	if len(lite.DNSServersV4) > 0 {
		logrus.Infof("服务端下发 DNS(IPv4): %v", lite.DNSServersV4)
	}
	if len(lite.DNSServersV6) > 0 {
		logrus.Infof("服务端下发 DNS(IPv6): %v", lite.DNSServersV6)
	}

	if *simulateIcmp {
		runSimulateICMPLink(conn, lite) // conn 需支持 SetReadDeadline
		return
	}

	if *tunnelMode {
		tunIPCIDR := *tunIP
		if len(lite.VirtualIPAssignments) > 0 {
			a := &lite.VirtualIPAssignments[0]
			if a.VirtualIP != "" && a.Gateway != "" {
				if idx := strings.Index(a.Gateway, "/"); idx >= 0 {
					tunIPCIDR = a.VirtualIP + "/" + a.Gateway[idx+1:]
				} else {
					tunIPCIDR = a.VirtualIP + "/24"
				}
				logrus.Infof("使用服务端下发表: 虚拟 %s (网关 %s)", a.VirtualIP, a.Gateway)
			}
		}
		runTunnelLinkMode(conn, tunIPCIDR, lite.VirtualIPAssignments, util.ConvSaltEffectiveDNS(lite))
		return
	}

	// 非隧道：读链路帧直到断开
	for {
		t, p, err := util.ReadLinkFrame(conn)
		if err != nil {
			break
		}
		if t == util.LinkTypeClose {
			cm, _ := util.ParseCloseLinkPayload(p)
			if cm != nil {
				logrus.Infof("收到关闭: code=%d %s", cm.Code, cm.Reason)
			}
			break
		}
		if t == util.LinkTypeTakenOver {
			logTakenOver(p)
			break
		}
		if t == util.LinkTypePing {
			_ = util.WriteLinkFrame(conn, util.LinkTypePong, p)
			continue
		}
		if t == util.LinkTypePong {
			continue
		}
		logrus.WithFields(logrus.Fields{"type": t, "len": len(p)}).Info("收到链路帧")
	}
}

// logTakenOver 解析并打印 LinkTypeTakenOver 负载（不存在/格式错也只打日志，不当错误）。
// 收到该帧表示本链路被同一会话的新链路接管，server 紧接着会关闭本 conn，
// 上层应静默退出当前 read 循环（不视作异常断开）。
func logTakenOver(payload []byte) {
	msg, err := util.ParseTakenOverLinkPayload(payload)
	if err != nil {
		logrus.Warnf("收到 TakenOver 帧但解析失败: %v (raw=%d bytes)", err, len(payload))
		return
	}
	logrus.Infof("收到 TakenOver: new_session_id=%q new_transport=%q（本链路即将被服务端关闭）",
		msg.NewSessionID, msg.NewTransport)
}

// connWithReadDeadline 支持读超时（如 *net.TCPConn）
type connWithReadDeadline interface {
	io.ReadWriteCloser
	SetReadDeadline(t time.Time) error
}

// runSimulateICMPLink 经链路类型 5 发送 ICMP Echo Request，读回类型 5 的 Echo Reply
func runSimulateICMPLink(dataConn connWithReadDeadline, lite *util.ConvSaltLite) {
	if len(lite.VirtualIPAssignments) == 0 {
		logrus.Error("模拟 ICMP 需要虚拟 IP 下发表，当前为空")
		return
	}
	a := &lite.VirtualIPAssignments[0]
	srcIP := a.VirtualIP
	dstIP := a.Gateway
	if idx := strings.Index(dstIP, "/"); idx >= 0 {
		dstIP = dstIP[:idx]
	}
	if srcIP == "" || dstIP == "" {
		logrus.Error("虚拟 IP 或网关为空，无法模拟 ICMP")
		return
	}
	logrus.Infof("模拟 ICMP: 源 %s -> 目的(网关) %s", srcIP, dstIP)

	packet := buildICMPEchoRequestPacket(srcIP, dstIP, 1, 1, 56)
	if packet == nil {
		return
	}
	if err := util.WriteLinkFrame(dataConn, util.LinkTypeIPPacket, packet); err != nil {
		logrus.Errorf("发送 ICMP 包失败: %v", err)
		return
	}
	logrus.Info("已发送模拟 ICMP Echo Request，等待 Echo Reply ...")

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		_ = dataConn.SetReadDeadline(time.Now().Add(3 * time.Second))
		typ, buf, err := util.ReadLinkFrame(dataConn)
		if err != nil {
			logrus.Errorf("读取失败: %v", err)
			return
		}
		if typ == util.LinkTypeTakenOver {
			logTakenOver(buf)
			return
		}
		if typ != util.LinkTypeIPPacket || !util.ValidIPPacket(buf) {
			continue
		}
		if len(buf) < 28 || buf[0]>>4 != 4 || buf[9] != 1 {
			continue
		}
		if buf[20] == 0 {
			logrus.Info("收到 ICMP Echo Reply，隧道往返正常")
			return
		}
	}
	logrus.Error("超时未收到 ICMP Echo Reply")
}

// buildICMPEchoRequestPacket 构造 IPv4 + ICMP Echo Request 包。id、seq 为 ICMP 标识与序号，payloadSize 为 ICMP 负载字节数。
func buildICMPEchoRequestPacket(srcIP, dstIP string, id, seq uint16, payloadSize int) []byte {
	src := net.ParseIP(srcIP).To4()
	dst := net.ParseIP(dstIP).To4()
	if src == nil || dst == nil {
		logrus.Error("解析源/目的 IP 失败")
		return nil
	}
	icmpHdrLen := 8
	totalLen := 20 + icmpHdrLen + payloadSize
	if totalLen > 65535 {
		return nil
	}
	packet := make([]byte, totalLen)
	// IPv4 头
	packet[0] = 0x45
	packet[1] = 0
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(packet[4:6], 0)
	binary.BigEndian.PutUint16(packet[6:8], 0)
	packet[8] = 64
	packet[9] = 1 // ICMP
	// 10-11 checksum 稍后填
	copy(packet[12:16], src)
	copy(packet[16:20], dst)
	ipChecksum := ipv4Checksum(packet[0:20])
	binary.BigEndian.PutUint16(packet[10:12], ipChecksum)
	// ICMP Echo Request
	packet[20] = 8 // type
	packet[21] = 0 // code
	// 22-23 checksum 稍后填
	binary.BigEndian.PutUint16(packet[24:26], id)
	binary.BigEndian.PutUint16(packet[26:28], seq)
	for i := 28; i < len(packet); i++ {
		packet[i] = 0
	}
	icmpChecksum(packet[20:])
	return packet
}

func ipv4Checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	return ^uint16(sum)
}

func icmpChecksum(b []byte) {
	b[2] = 0
	b[3] = 0
	var sum uint32
	for i := 0; i < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	cs := ^uint16(sum)
	b[2] = byte(cs >> 8)
	b[3] = byte(cs & 0xff)
}

// runTunnelLinkMode TUN ↔ 同一条 TCP 连接，IPv4 包用链路类型 5 承载（与多 VIP 下按源地址选路一致）
func runTunnelLinkMode(dataConn io.ReadWriteCloser, tunIPCIDR string, assignments []util.VirtualIPAssignment, dnsServers []string) {
	vipToFirst := make(map[string]struct{})
	for _, a := range assignments {
		if a.VirtualIP != "" {
			vipToFirst[a.VirtualIP] = struct{}{}
		}
	}

	config := water.Config{DeviceType: water.TUN}
	ifce, err := water.New(config)
	if err != nil {
		logrus.Warnf("创建 TUN 失败: %v", err)
		return
	}
	defer ifce.Close()
	name := ifce.Name()
	logrus.Infof("已创建 TUN 设备: %s", name)

	if err := setTUNIP(name, tunIPCIDR); err != nil {
		logrus.Warnf("配置 TUN IP 失败: %v", err)
		return
	}
	dnsNeedsRevert := false
	if len(dnsServers) > 0 {
		rev, err := applyTUNDNS(name, dnsServers)
		if err != nil {
			logrus.Warnf("配置 TUN DNS 失败: %v", err)
		}
		dnsNeedsRevert = rev
	}
	defer func() {
		if dnsNeedsRevert {
			revertTUNDNS(name)
		}
	}()
	for i := 1; i < len(assignments); i++ {
		a := &assignments[i]
		if a.VirtualIP == "" {
			continue
		}
		cidr := vipCIDR(a)
		if err := addTUNIP(name, cidr); err != nil {
			logrus.Warnf("TUN 添加 VIP %s 失败: %v", a.VirtualIP, err)
		} else {
			logrus.Infof("TUN %s 已添加 VIP %s", name, cidr)
		}
	}
	logrus.Infof("TUN %s 已配置，开始 TUN↔链路类型5 转发", name)

	const maxPacket = 65535
	var wrMu sync.Mutex
	done := make(chan struct{})
	var once sync.Once
	closeDone := func() { once.Do(func() { close(done) }) }

	go func() {
		defer closeDone()
		buf := make([]byte, maxPacket)
		for {
			n, err := ifce.Read(buf)
			if err != nil {
				return
			}
			if n < 20 {
				continue
			}
			if buf[0]>>4 == 4 {
				srcIP := net.IP(buf[12:16]).String()
				if len(vipToFirst) > 0 {
					if _, ok := vipToFirst[srcIP]; !ok {
						logrus.Tracef("TUN 包源 IP %s 非本机 VIP，跳过", srcIP)
						continue
					}
				}
			}
			payload := make([]byte, n)
			copy(payload, buf[:n])
			wrMu.Lock()
			err = util.WriteLinkFrame(dataConn, util.LinkTypeIPPacket, payload)
			wrMu.Unlock()
			if err != nil {
				return
			}
		}
	}()

	go func() {
		defer closeDone()
		for {
			typ, payload, err := util.ReadLinkFrame(dataConn)
			if err != nil {
				return
			}
			switch typ {
			case util.LinkTypeIPPacket:
				if util.ValidIPPacket(payload) {
					_, _ = ifce.Write(payload)
				}
			case util.LinkTypeClose:
				return
			case util.LinkTypeTakenOver:
				logTakenOver(payload)
				return
			case util.LinkTypePing:
				wrMu.Lock()
				err = util.WriteLinkFrame(dataConn, util.LinkTypePong, payload)
				wrMu.Unlock()
				if err != nil {
					return
				}
			case util.LinkTypePong:
				// 保活应答，忽略
			default:
			}
		}
	}()

	<-done
	logrus.Info("隧道已关闭")
}

// vipCIDR 从 VirtualIPAssignment 得到 VirtualIP/CIDR 字符串（如 10.0.0.2/24）
func vipCIDR(a *util.VirtualIPAssignment) string {
	if a.Gateway != "" {
		if idx := strings.Index(a.Gateway, "/"); idx >= 0 {
			return a.VirtualIP + "/" + a.Gateway[idx+1:]
		}
	}
	return a.VirtualIP + "/24"
}

func setTUNIP(ifName, tunIPCIDR string) error {
	switch runtime.GOOS {
	case "linux":
		if out, err := exec.Command("ip", "addr", "add", tunIPCIDR, "dev", ifName).CombinedOutput(); err != nil {
			return fmt.Errorf("ip addr add: %w (%s)", err, string(out))
		}
		if out, err := exec.Command("ip", "link", "set", "dev", ifName, "up").CombinedOutput(); err != nil {
			return fmt.Errorf("ip link set up: %w (%s)", err, string(out))
		}
		return nil
	case "darwin":
		// 例: ifconfig utun3 inet 10.0.0.2 10.0.0.1 netmask 255.255.255.0 up
		// 从 10.0.0.2/24 解析出 IP 和网关（网关取网段 .1）
		ip, _, err := net.ParseCIDR(tunIPCIDR)
		if err != nil {
			return err
		}
		gw := make(net.IP, len(ip))
		copy(gw, ip)
		gw[len(gw)-1] = 1
		cmd := exec.Command("ifconfig", ifName, "inet", ip.String(), gw.String(), "netmask", "255.255.255.0", "up")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("ifconfig: %w (%s)", err, string(out))
		}
		return nil
	default:
		return fmt.Errorf("未支持的 OS: %s", runtime.GOOS)
	}
}

// applyTUNDNS 将 systemd-resolved 下该接口的 DNS 设为 servers（Linux）。
// 第二个返回值表示退出隧道前是否应调用 revertTUNDNS（仅 Linux resolvectl 成功时为 true）。
func applyTUNDNS(ifName string, servers []string) (needsRevert bool, err error) {
	if len(servers) == 0 {
		return false, nil
	}
	switch runtime.GOOS {
	case "linux":
		resolvectl, err := exec.LookPath("resolvectl")
		if err != nil {
			return false, fmt.Errorf("未找到 resolvectl（需 systemd-resolved 方可自动写入 TUN DNS）: %w", err)
		}
		args := append([]string{"dns", ifName}, servers...)
		out, err := exec.Command(resolvectl, args...).CombinedOutput()
		if err != nil {
			return false, fmt.Errorf("resolvectl: %w (%s)", err, string(out))
		}
		logrus.Infof("已通过 resolvectl 为 %s 设置 DNS: %v", ifName, servers)
		return true, nil
	case "darwin":
		logrus.Infof("服务端下发 DNS %v：macOS 请在本机为接口 %s 配置解析或使用系统 VPN 扩展", servers, ifName)
		return false, nil
	default:
		logrus.Infof("服务端下发 DNS %v：当前 OS 未自动写入，请手动配置", servers)
		return false, nil
	}
}

func revertTUNDNS(ifName string) {
	if runtime.GOOS != "linux" {
		return
	}
	resolvectl, err := exec.LookPath("resolvectl")
	if err != nil {
		return
	}
	if out, err := exec.Command(resolvectl, "revert", ifName).CombinedOutput(); err != nil {
		logrus.Debugf("resolvectl revert %s: %v %s", ifName, err, string(out))
	}
}

// addTUNIP 在已创建的 TUN 上增加一个 IP 地址（用于多 VIP）
func addTUNIP(ifName, vipCIDR string) error {
	switch runtime.GOOS {
	case "linux":
		if out, err := exec.Command("ip", "addr", "add", vipCIDR, "dev", ifName).CombinedOutput(); err != nil {
			return fmt.Errorf("ip addr add: %w (%s)", err, string(out))
		}
		return nil
	case "darwin":
		ip, ipNet, err := net.ParseCIDR(vipCIDR)
		if err != nil {
			return err
		}
		if ip.To4() == nil {
			return fmt.Errorf("仅支持 IPv4")
		}
		mask := ipNet.Mask
		var maskStr string
		if len(mask) == 4 {
			maskStr = fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
		} else {
			maskStr = "255.255.255.0"
		}
		cmd := exec.Command("ifconfig", ifName, "inet", ip.String(), "netmask", maskStr, "alias")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("ifconfig alias: %w (%s)", err, string(out))
		}
		return nil
	default:
		return fmt.Errorf("未支持的 OS: %s", runtime.GOOS)
	}
}
