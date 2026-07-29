package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	mrand "math/rand"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nanotun/server/config"
)

func writeTestHy2ServerTLS(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "hy2-test"},
		NotBefore:    time.Now().UTC().Add(-time.Hour),
		NotAfter:     time.Now().UTC().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certFile = filepath.Join(dir, "hy2-test.crt")
	keyFile = filepath.Join(dir, "hy2-test.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func testHysteriaConfig(t *testing.T, listenAddr, password, certFile, keyFile string) config.Config {
	t.Helper()
	return config.Config{
		Hysteria: config.HysteriaConfig{
			ListenAddr:            listenAddr,
			TLSCertFile:           certFile,
			TLSKeyFile:            keyFile,
			Password:              password,
			ReportTLSInsecureHint: true,
			PortHopIntervalSec:    5,
		},
	}
}

// pickFreeUDPPort 挑一个当下能绑的 UDP 端口交给被测代码。
//
// 与 freePort 同一个理由:不让内核用 `:0` 挑,否则拿到的号落在临时端口区间,而「先绑再关、把号交给
// 被测代码稍后重绑」的中间窗口里,同一进程的任何外发 socket 都可能被分到它 —— 失败会报成
// bind: address already in use,看起来像被测代码的问题。
func pickFreeUDPPort(t *testing.T) int {
	t.Helper()
	for i := 0; i < 50; i++ {
		// 留 4 个号的余量:端口跳跃那组用例要 port..port+3 一整段。
		port := 20000 + mrand.Intn(9990)
		pc, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			continue
		}
		_ = pc.Close()
		return port
	}
	t.Fatal("50 次都没挑到能绑的 UDP 端口")
	return 0
}
