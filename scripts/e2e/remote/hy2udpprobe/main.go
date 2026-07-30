// hy2udpprobe 以一个**合法的 hy2 客户端**身份连上 nanotun 的 hy2 入口,然后尝试借它中转
// 一个真实的 UDP 包(向公网 DNS 发查询并等应答)。
//
// 它存在的理由:hysteria.udp_relay_enabled 是个纯安全开关 —— 关着时服务端设 DisableUDP,
// hy2 只承担 nanotun 自己的隧道流量;开着时任何**通过认证的** hy2 客户端都能把服务器当成
// 通用 UDP 代理(DNS 放大、内网横移),启动期那条 WARN 就是为这个打的。这个开关此前没有任何
// 自动化验证,而它一旦被误开,从外部看不出任何异样。
//
// 为什么要自己写而不是装 hysteria 官方客户端:hysteria 的客户端库本来就是本仓库的依赖,
// 用它就不必在被测机器上装第三方软件;而且 nanotun 的 hy2 入口开了 mTLS(RequireAndVerify)
// 与 salamander 混淆,通用客户端还得额外配这两样才连得上 —— 这里正好一并处理。
//
// 输出恒为单行 RESULT=<结论> [reason=...],退出码恒 0(除用法错误),交给 e2e 脚本去判定:
//
//	RESULT=udp_disabled          握手成功,但服务端不给 UDP 能力 → 开关是关的(期望值)
//	RESULT=udp_relayed           握手成功且真的中转成功、收到了 DNS 应答 → 开关是开的
//	RESULT=udp_enabled_no_reply  服务端给了 UDP 能力但没等到应答(网络问题?)
//	RESULT=handshake_failed      连不上 / 证书不对 → 脚手架问题,不是产品结论
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/extras/v2/obfs"
)

// obfsConnFactory 建底层 UDP socket 并按需套上 salamander 混淆。
// 服务端配了 obfs_salamander_password 时不套就完全握不上手(包会被当成噪声丢掉)。
type obfsConnFactory struct{ psk []byte }

func (f *obfsConnFactory) New(_ net.Addr) (net.PacketConn, error) {
	pc, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	if len(f.psk) == 0 {
		return pc, nil
	}
	return obfs.WrapPacketConnSalamander(pc, f.psk)
}

// dnsQuery 手搓一个 example.com 的 A 查询。用固定事务 ID 便于校验应答确实是这次查询的回音。
func dnsQuery() []byte {
	q := []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // flags: RD
		0x00, 0x01, // QDCOUNT
		0x00, 0x00, // ANCOUNT
		0x00, 0x00, // NSCOUNT
		0x00, 0x00, // ARCOUNT
	}
	for _, label := range []string{"example", "com"} {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0x00)       // 根标签
	q = append(q, 0x00, 0x01) // QTYPE=A
	q = append(q, 0x00, 0x01) // QCLASS=IN
	return q
}

// looksLikeOurDNSReply 校验应答是这次查询的回音:事务 ID 相同且 QR 位已置。
// 不校验的话,任何一坨字节都会被当成「中转成功」。
func looksLikeOurDNSReply(b []byte) bool {
	return len(b) >= 12 && b[0] == 0x12 && b[1] == 0x34 && b[2]&0x80 != 0
}

func result(verdict, reason string) {
	if reason == "" {
		fmt.Printf("RESULT=%s\n", verdict)
	} else {
		fmt.Printf("RESULT=%s reason=%s\n", verdict, reason)
	}
	os.Exit(0)
}

func main() {
	addr := flag.String("addr", "", "hy2 服务端 host:port")
	password := flag.String("password", "", "hy2 认证口令")
	obfsPSK := flag.String("obfs", "", "salamander 口令(留空表示不混淆)")
	certFile := flag.String("cert", "", "客户端证书 PEM(mTLS 必需)")
	keyFile := flag.String("key", "", "客户端私钥 PEM")
	sni := flag.String("sni", "localhost", "TLS SNI")
	target := flag.String("target", "8.8.8.8:53", "要中转到的 UDP 目标")
	timeout := flag.Duration("timeout", 8*time.Second, "等应答的时长")
	flag.Parse()

	if *addr == "" || *password == "" {
		fmt.Fprintln(os.Stderr, "用法: hy2udpprobe -addr host:port -password xxx [-obfs xxx -cert c.pem -key k.pem]")
		os.Exit(2)
	}

	udpAddr, err := net.ResolveUDPAddr("udp", *addr)
	if err != nil {
		result("handshake_failed", "解析地址失败:"+err.Error())
	}

	tlsCfg := client.TLSConfig{
		ServerName: *sni,
		// 测试环境是自签证书,校验服务端身份不是这个探针的职责。
		InsecureSkipVerify: true,
	}
	if *certFile != "" {
		cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			result("handshake_failed", "加载客户端证书失败:"+err.Error())
		}
		tlsCfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &cert, nil
		}
	}

	c, _, err := client.NewClient(&client.Config{
		ConnFactory: &obfsConnFactory{psk: []byte(*obfsPSK)},
		ServerAddr:  udpAddr,
		Auth:        *password,
		TLSConfig:   tlsCfg,
	})
	if err != nil {
		result("handshake_failed", err.Error())
	}
	defer func() { _ = c.Close() }()

	// 握手已经成功 —— 从这里往下的结论都是关于「服务端给不给 UDP 能力」的。
	uc, err := c.UDP()
	if err != nil {
		result("udp_disabled", err.Error())
	}
	defer func() { _ = uc.Close() }()

	if err := uc.Send(dnsQuery(), *target); err != nil {
		// 能拿到 UDP 会话却发不出去:也算没被拦住(能力是给了的),但要如实区分。
		result("udp_enabled_no_reply", "发送失败:"+err.Error())
	}

	type reply struct {
		data []byte
		err  error
	}
	ch := make(chan reply, 1)
	go func() {
		b, _, err := uc.Receive()
		ch <- reply{data: b, err: err}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			result("udp_enabled_no_reply", "接收失败:"+r.err.Error())
		}
		if !looksLikeOurDNSReply(r.data) {
			result("udp_enabled_no_reply", fmt.Sprintf("收到 %d 字节但不是本次查询的应答", len(r.data)))
		}
		result("udp_relayed", fmt.Sprintf("收到 %d 字节 DNS 应答", len(r.data)))
	case <-time.After(*timeout):
		result("udp_enabled_no_reply", "等应答超时")
	}
}
