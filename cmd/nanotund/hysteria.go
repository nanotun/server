package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	hyserver "github.com/apernet/hysteria/core/v2/server"
	hyauth "github.com/apernet/hysteria/extras/v2/auth"
	hyobfs "github.com/apernet/hysteria/extras/v2/obfs"
	"github.com/sirupsen/logrus"

	"github.com/nanotun/server/config"
	"github.com/nanotun/server/util"
)

// vpnLocalOutbound 忽略 hy2 客户端 TCP 请求中的目标地址，每流 Dial 本机 VPN WebSocket（防止 hy2 被用作任意 TCP 开放代理）。
// 启用全局 [smux] 时由 vpnSmuxStreamOutbound 替代，经环回 smux 多流而非每流 Dial。
type vpnLocalOutbound struct {
	wsURL     string
	timeout   time.Duration
	tlsClient *tls.Config // wss 环回；ws 时为 nil
}

func (o *vpnLocalOutbound) TCP(_ string) (net.Conn, error) {
	d := o.timeout
	if d <= 0 {
		d = 15 * time.Second
	}
	conn, err := util.DialVPNWebSocket(o.wsURL, d, o.tlsClient)
	if err != nil {
		return nil, err
	}
	enableTCPKeepAlive(conn)
	return conn, nil
}

func (o *vpnLocalOutbound) UDP(string) (hyserver.UDPConn, error) {
	return nil, fmt.Errorf("udp relay disabled")
}

// CheckUDP:hysteria v2.9 起 Outbound 接口新增的 UDP 准入钩子(ACL 用)。本 outbound 只做 VPN TCP 环回,
// UDP 一律拒(与 UDP() 返回 disabled 一致);服务端侧 DisableUDP 已兜底,这里返回错误使语义闭合。
func (o *vpnLocalOutbound) CheckUDP(string) error {
	return fmt.Errorf("udp relay disabled")
}

// vpnSmuxStreamOutbound 经 loopbackSmuxPool 在单条环回 WebSocket 上 OpenStream，与 REALITY 共用 smux 会话。
type vpnSmuxStreamOutbound struct {
	pool *loopbackSmuxPool
}

func (o *vpnSmuxStreamOutbound) TCP(_ string) (net.Conn, error) {
	if o.pool == nil {
		return nil, fmt.Errorf("smux pool 未初始化")
	}
	st, err := o.pool.OpenStream()
	if err != nil {
		return nil, err
	}
	// M1:hy2 共享 smux 池无法把某条 stream 关联回具体客户端(hysteria Outbound 接口不透出客户端
	// 地址),写一个 LOCAL(无源)PROXY v2 头 —— 让服务端「每条 loopback stream 先读一个头」的约定
	// 成立(否则会把 hy2 首个 VPN 帧误当 PROXY 头解析)。hy2 会话据此回退环回地址计,与既有行为一致。
	if werr := writeLoopbackProxyHeaderLocal(st); werr != nil {
		_ = st.Close()
		return nil, werr
	}
	return st, nil
}

func (o *vpnSmuxStreamOutbound) UDP(string) (hyserver.UDPConn, error) {
	return nil, fmt.Errorf("udp relay disabled")
}

// CheckUDP:同 vpnLocalOutbound —— smux 多路复用出口只承载 VPN TCP,UDP 一律拒。
func (o *vpnSmuxStreamOutbound) CheckUDP(string) error {
	return fmt.Errorf("udp relay disabled")
}

// hysteriaUDPProxyConn 与 hysteria core defaultUDPConn 行为一致（全锥 UDP），供启用 udp_relay 时使用。
type hysteriaUDPProxyConn struct {
	*net.UDPConn
}

func (c *hysteriaUDPProxyConn) ReadFrom(b []byte) (int, string, error) {
	n, addr, err := c.UDPConn.ReadFrom(b)
	if addr != nil {
		return n, addr.String(), err
	}
	return n, "", err
}

func (c *hysteriaUDPProxyConn) WriteTo(b []byte, addr string) (int, error) {
	uAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return 0, err
	}
	return c.UDPConn.WriteTo(b, uAddr)
}

// vpnHybridOutbound：TCP 固定环回 VPN；UDP 走 hysteria 默认全锥行为（仅当 udp_relay_enabled=true）。
type vpnHybridOutbound struct {
	tcp hyserver.Outbound
}

func (o *vpnHybridOutbound) TCP(req string) (net.Conn, error) {
	return o.tcp.TCP(req)
}

func (o *vpnHybridOutbound) UDP(reqAddr string) (hyserver.UDPConn, error) {
	_ = reqAddr
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	return &hysteriaUDPProxyConn{UDPConn: conn}, nil
}

// CheckUDP:仅在 udp_relay_enabled=true 时启用本 outbound,行为对齐 hysteria defaultOutbound 的全锥放行(nil)。
// 目的地准入不在此层做(与升级前一致,不改变现网语义);运维若要限制 UDP 目的应关掉 udp_relay。
func (o *vpnHybridOutbound) CheckUDP(string) error {
	return nil
}

// validateHysteriaUserConfig 现委托到 config 包的共享实现(e_config_lint):启动期与
// `nanotun-admin config lint` 共用同一套 hy2 调优约束,避免两处规则漂移。
func validateHysteriaUserConfig(hc *config.HysteriaConfig) error {
	return hc.ValidateTuning()
}

func buildHysteriaServerConfig(hc *config.HysteriaConfig, cert tls.Certificate, tcpOut hyserver.Outbound) (*hyserver.Config, error) {
	tlsCfg := hyserver.TLSConfig{Certificates: []tls.Certificate{cert}}
	if caPath := hc.TLSClientCAFile; caPath != "" {
		pem, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("hysteria 读取 tls_client_ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("hysteria: tls_client_ca_file 中无有效 PEM 证书")
		}
		tlsCfg.ClientCAs = pool
	}

	quicCfg := hyserver.QUICConfig{}
	if hc.QUICInitialStreamRecvWindow != 0 {
		quicCfg.InitialStreamReceiveWindow = hc.QUICInitialStreamRecvWindow
	}
	if hc.QUICMaxStreamRecvWindow != 0 {
		quicCfg.MaxStreamReceiveWindow = hc.QUICMaxStreamRecvWindow
	}
	if hc.QUICInitialConnRecvWindow != 0 {
		quicCfg.InitialConnectionReceiveWindow = hc.QUICInitialConnRecvWindow
	}
	if hc.QUICMaxConnRecvWindow != 0 {
		quicCfg.MaxConnectionReceiveWindow = hc.QUICMaxConnRecvWindow
	}
	if hc.QUICMaxIdleTimeoutSec != 0 {
		quicCfg.MaxIdleTimeout = time.Duration(hc.QUICMaxIdleTimeoutSec) * time.Second
	}
	if hc.QUICMaxIncomingStreams != 0 {
		quicCfg.MaxIncomingStreams = hc.QUICMaxIncomingStreams
	}
	quicCfg.DisablePathMTUDiscovery = hc.QUICDisablePathMTUDiscovery

	var ob hyserver.Outbound = tcpOut
	if hc.UDPRelayEnabled {
		ob = &vpnHybridOutbound{tcp: tcpOut}
		// I4: 启动期警告 —— nanotun 当前定位是「面向 VPN 客户端的 hy2 入口」,
		// 应当只承担 hy2-tunnel 流量。开启 UDPRelayEnabled 会把 hy2 作为通用
		// SOCKS5 UDP 代理使用,任何 hy2 客户端都能借此从本机发出任意 UDP 流量
		// (DNS amplification / 内网横移 / 等)。仅在确认需要纯代理用途时才开启。
		logrus.Warn("[hy2] config.udp_relay_enabled=true,nanotun 当前作为通用 UDP 代理使用;若仅作 VPN 入口请关闭以减小攻击面")
	}

	out := &hyserver.Config{
		TLSConfig:             tlsCfg,
		QUICConfig:            quicCfg,
		Authenticator:         &hyauth.PasswordAuthenticator{Password: hc.Password},
		Outbound:              ob,
		DisableUDP:            !hc.UDPRelayEnabled,
		IgnoreClientBandwidth: hc.IgnoreClientBandwidth,
		BandwidthConfig: hyserver.BandwidthConfig{
			MaxTx: hc.BandwidthMaxTxBps,
			MaxRx: hc.BandwidthMaxRxBps,
		},
	}
	if hc.UDPRelayEnabled && hc.UDPIdleTimeoutSec != 0 {
		out.UDPIdleTimeout = time.Duration(hc.UDPIdleTimeoutSec) * time.Second
	}
	if dir := hc.MasqueradeDir; dir != "" {
		out.MasqHandler = http.FileServer(http.Dir(dir))
	}
	return out, nil
}

func udpPortFromPacketConn(c net.PacketConn) (int, error) {
	addr := c.LocalAddr()
	u, ok := addr.(*net.UDPAddr)
	if !ok || u == nil {
		return 0, fmt.Errorf("hysteria: 本地地址非 UDP: %T", addr)
	}
	if u.Port < 1 || u.Port > 65535 {
		return 0, fmt.Errorf("hysteria: 无效 UDP 端口 %d", u.Port)
	}
	return u.Port, nil
}

// startEmbeddedHysteria 当 password、tls_cert_file、tls_key_file 均配置时启动 Hysteria 2；否则返回 nil, 0, nil。
// smuxPool 非空时 hy2 的 TCP 出口经 smux OpenStream；否则每流 dial 环回 VPN WebSocket（loopbackWSURL）。
// 第二返回值为实际监听 UDP 端口（用于 node_login 上报；listen_addr 为 :0 时必用此值）。
// 第三返回值为端口跳跃 iptables 清理函数（无则 nil）；进程退出前应调用。
func startEmbeddedHysteria(cfg *config.Config, vpnListenAddr string, loopbackWSURL string, smuxPool *loopbackSmuxPool, loopbackWSTLS *tls.Config) (hyserver.Server, int, func(), error) {
	hc := &cfg.Hysteria
	if !hc.HysteriaActive() {
		return nil, 0, nil, nil
	}
	if err := validateHysteriaUserConfig(hc); err != nil {
		return nil, 0, nil, err
	}
	cert, err := util.LoadAndCheckTLSKeyPair(hc.TLSCertFile, hc.TLSKeyFile, "hy2")
	if err != nil {
		return nil, 0, nil, fmt.Errorf("hysteria TLS 加载证书: %w", err)
	}
	udpAddr := hc.ListenAddr
	if udpAddr == "" {
		udpAddr = ":443"
	}
	udpHost, portUnion, err := util.SplitUDPListenAddr(udpAddr)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("hysteria listen_addr: %w", err)
	}
	primaryPort, err := util.PrimaryPortFromUDPListenAddr(udpAddr)
	if err != nil {
		return nil, 0, nil, err
	}
	listenPrimary := util.FormatUDPListenAddr(udpHost, primaryPort)
	packetConn, err := net.ListenPacket("udp", listenPrimary)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("hysteria UDP 监听 %s: %w", listenPrimary, err)
	}
	var hopCleanup func()
	if util.UDPPortUnionNeedsHop(portUnion) {
		cleanup, hopErr := setupHy2UDPPortHopRedirect(primaryPort, portUnion, hc.PortHopIface)
		if hopErr != nil {
			_ = packetConn.Close()
			return nil, 0, nil, fmt.Errorf("hysteria 端口跳跃: %w", hopErr)
		}
		hopCleanup = cleanup
	}
	udpPortNum, err := udpPortFromPacketConn(packetConn)
	if err != nil {
		_ = packetConn.Close()
		if hopCleanup != nil {
			hopCleanup()
		}
		return nil, 0, nil, err
	}
	if obfsPW := strings.TrimSpace(hc.ObfsSalamanderPassword); obfsPW != "" {
		// hysteria v2.9 起将 NewSalamanderObfuscator/WrapPacketConn 私有化,合并为一个公开助手
		// WrapPacketConnSalamander(conn, psk):内部仍是「建 Salamander 混淆器 → 包裹 PacketConn」两步,
		// 行为与升级前逐字节一致(每包 XOR BLAKE2b(PSK||salt)、前置 8 字节 salt)。
		wrapped, errO := hyobfs.WrapPacketConnSalamander(packetConn, []byte(obfsPW))
		if errO != nil {
			_ = packetConn.Close()
			if hopCleanup != nil {
				hopCleanup()
			}
			return nil, 0, nil, fmt.Errorf("hysteria Salamander obfs: %w", errO)
		}
		packetConn = wrapped
	}
	dialTimeout := time.Duration(hc.ForwardDialTimeoutSec) * time.Second
	if hc.ForwardDialTimeoutSec == 0 {
		dialTimeout = 15 * time.Second
	}
	var tcpOb hyserver.Outbound
	if smuxPool != nil {
		tcpOb = &vpnSmuxStreamOutbound{pool: smuxPool}
	} else {
		tcpOb = &vpnLocalOutbound{wsURL: loopbackWSURL, timeout: dialTimeout, tlsClient: loopbackWSTLS}
	}
	hyCfg, err := buildHysteriaServerConfig(hc, cert, tcpOb)
	if err != nil {
		_ = packetConn.Close()
		if hopCleanup != nil {
			hopCleanup()
		}
		return nil, 0, nil, err
	}
	hyCfg.Conn = packetConn
	srv, err := hyserver.NewServer(hyCfg)
	if err != nil {
		_ = packetConn.Close()
		if hopCleanup != nil {
			hopCleanup()
		}
		return nil, 0, nil, err
	}
	udpLog := packetConn.LocalAddr().String()
	if util.UDPPortUnionNeedsHop(portUnion) {
		logrus.Infof("Hysteria 2：UDP 主端口 %s，客户端端口并集 %q（port hopping）", udpLog, portUnion)
	}
	if smuxPool != nil {
		if strings.TrimSpace(hc.ObfsSalamanderPassword) != "" {
			logrus.Infof("Hysteria 2：UDP %s（Salamander obfs），认证后 TCP 经 smux 多路复用至 %s", udpLog, loopbackWSURL)
		} else {
			logrus.Infof("Hysteria 2：UDP %s，认证后 TCP 经 smux 多路复用至 %s", udpLog, loopbackWSURL)
		}
	} else if strings.TrimSpace(hc.ObfsSalamanderPassword) != "" {
		logrus.Infof("Hysteria 2：UDP %s（Salamander obfs），认证后 TCP 转至 WebSocket %s（每流一条连接）", udpLog, loopbackWSURL)
	} else {
		logrus.Infof("Hysteria 2：UDP %s，认证后 TCP 转至 WebSocket %s（每流一条连接）", udpLog, loopbackWSURL)
	}
	return srv, udpPortNum, hopCleanup, nil
}
