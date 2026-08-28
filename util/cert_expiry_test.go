package util

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// LoadAndCheckTLSKeyPair 是启动期的证书闸口。它 fail-closed 的每一条都对应一次
// 真实事故:过期证书让所有客户端在握手期集体掉线、未生效证书让人以为是网络问题、
// 解析不了的 leaf 把错误推迟到握手期才炸。

// writeKeyPair 生成一份自签证书,notBefore/notAfter 由调用方指定。
func writeKeyPair(t *testing.T, dir string, notBefore, notAfter time.Time) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "cert-test"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

func TestLoadAndCheckTLSKeyPair_RefusesCertsThatWouldFailAtHandshakeTime(t *testing.T) {
	now := time.Now()

	t.Run("有效证书", func(t *testing.T) {
		c, k := writeKeyPair(t, t.TempDir(), now.Add(-time.Hour), now.Add(365*24*time.Hour))
		cert, err := LoadAndCheckTLSKeyPair(c, k, "vpn-wss")
		if err != nil {
			t.Fatalf("err=%v", err)
		}
		if len(cert.Certificate) == 0 {
			t.Fatal("返回的 cert 是空的")
		}
	})

	t.Run("快过期只警告不拦", func(t *testing.T) {
		// 续签窗口内还能跑 —— 这里 fail 掉的话,运维一觉醒来服务起不来了。
		c, k := writeKeyPair(t, t.TempDir(), now.Add(-time.Hour), now.Add(CertExpiryWarnWindow-time.Hour))
		if _, err := LoadAndCheckTLSKeyPair(c, k, "hy2"); err != nil {
			t.Fatalf("快过期不该拦: %v", err)
		}
	})

	t.Run("已过期", func(t *testing.T) {
		c, k := writeKeyPair(t, t.TempDir(), now.Add(-48*time.Hour), now.Add(-time.Hour))
		_, err := LoadAndCheckTLSKeyPair(c, k, "hy2")
		if err == nil {
			t.Fatal("过期证书应在启动期就被拒,而不是等所有客户端握手集体失败")
		}
		if !strings.Contains(err.Error(), "has expired") {
			t.Fatalf("错误里要点明是过期: %v", err)
		}
	})

	t.Run("尚未生效", func(t *testing.T) {
		c, k := writeKeyPair(t, t.TempDir(), now.Add(24*time.Hour), now.Add(48*time.Hour))
		_, err := LoadAndCheckTLSKeyPair(c, k, "vpn-wss")
		if err == nil {
			t.Fatal("未生效证书应被拒")
		}
		if !strings.Contains(err.Error(), "is not valid yet") {
			t.Fatalf("错误里要点明是未生效: %v", err)
		}
	})

	t.Run("小幅时钟漂移放行", func(t *testing.T) {
		// 签发端时钟比本机快一点点是常态,这种也拦就没法部署了。
		c, k := writeKeyPair(t, t.TempDir(), now.Add(time.Minute), now.Add(24*time.Hour))
		if _, err := LoadAndCheckTLSKeyPair(c, k, "hy2"); err != nil {
			t.Fatalf("1 分钟的漂移在 %s 容忍范围内,不该拦: %v", tlsNotBeforeSkew, err)
		}
	})

	t.Run("文件不存在", func(t *testing.T) {
		dir := t.TempDir()
		_, err := LoadAndCheckTLSKeyPair(filepath.Join(dir, "无"), filepath.Join(dir, "也无"), "hy2")
		if err == nil {
			t.Fatal("应报错")
		}
		if !strings.Contains(err.Error(), "hy2") {
			t.Fatalf("错误里要带 role,不然多份证书时不知道是哪份: %v", err)
		}
	})

	t.Run("cert 是垃圾", func(t *testing.T) {
		dir := t.TempDir()
		_, k := writeKeyPair(t, dir, now.Add(-time.Hour), now.Add(24*time.Hour))
		bad := filepath.Join(dir, "bad.pem")
		if err := os.WriteFile(bad, []byte("这不是 PEM"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, err := LoadAndCheckTLSKeyPair(bad, k, "hy2"); err == nil {
			t.Fatal("应报错")
		}
	})

	t.Run("cert 和 key 不配对", func(t *testing.T) {
		dirA, dirB := t.TempDir(), t.TempDir()
		c, _ := writeKeyPair(t, dirA, now.Add(-time.Hour), now.Add(24*time.Hour))
		_, k := writeKeyPair(t, dirB, now.Add(-time.Hour), now.Add(24*time.Hour))
		if _, err := LoadAndCheckTLSKeyPair(c, k, "hy2"); err == nil {
			t.Fatal("cert/key 不匹配应在启动期就报出来")
		}
	})
}

// 私钥被 group/others 读到是真实风险,但直接 Fatal 会让一堆默认 0644 的容器镜像
// 部署不下去 —— 所以是 Warn 而非拒绝。这条测试锁的就是「只警告不拒绝」。
func TestCheckKeyFilePerm_WarnsButNeverBlocksStartup(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "plan9" {
		t.Skip("非 Unix 不做权限校验")
	}
	now := time.Now()
	dir := t.TempDir()
	c, k := writeKeyPair(t, dir, now.Add(-time.Hour), now.Add(24*time.Hour))

	if err := os.Chmod(k, 0o644); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	if _, err := LoadAndCheckTLSKeyPair(c, k, "hy2"); err != nil {
		t.Fatalf("权限过宽只该警告,不该拦住启动: %v", err)
	}

	// stat 不到时静默返回,真正的 IO 错误留给 LoadX509KeyPair 报。
	checkKeyFilePerm(filepath.Join(dir, "根本不存在"), "hy2")
	// 0600 是标准答案,不该有任何动静。
	if err := os.Chmod(k, 0o600); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	checkKeyFilePerm(k, "hy2")
}

func TestNewServerTLSConfig_HasSafeDefaultsAndHonoursOverrides(t *testing.T) {
	now := time.Now()
	c, k := writeKeyPair(t, t.TempDir(), now.Add(-time.Hour), now.Add(24*time.Hour))
	cert, err := LoadAndCheckTLSKeyPair(c, k, "vpn-wss")
	if err != nil {
		t.Fatalf("LoadAndCheckTLSKeyPair: %v", err)
	}
	certs := []tls.Certificate{cert}

	t.Run("零值 opts 的默认值", func(t *testing.T) {
		cfg := NewServerTLSConfig(ServerTLSOptions{Certificates: certs})
		if cfg.MinVersion != tls.VersionTLS12 {
			t.Fatalf("MinVersion=%x,TLS 1.0/1.1 早该关掉了", cfg.MinVersion)
		}
		if !cfg.SessionTicketsDisabled {
			t.Fatal("session ticket 默认必须关 —— 开着会削弱前向保密")
		}
		if len(cfg.CipherSuites) == 0 {
			t.Fatal("TLS 1.2 的 cipher 白名单是空的,等于放任 Go 的默认集合")
		}
		for _, s := range cfg.CipherSuites {
			name := tls.CipherSuiteName(s)
			if strings.Contains(name, "_CBC_") || strings.Contains(name, "RC4") || strings.Contains(name, "3DES") {
				t.Fatalf("白名单里混进了非 AEAD 套件: %s", name)
			}
			if !strings.HasPrefix(name, "TLS_ECDHE_") {
				t.Fatalf("%s 不是 ECDHE,没有前向保密", name)
			}
		}
	})

	t.Run("显式覆盖", func(t *testing.T) {
		pool := x509.NewCertPool()
		cfg := NewServerTLSConfig(ServerTLSOptions{
			Certificates:          certs,
			OverrideMinVersion:    tls.VersionTLS13,
			OverrideCipherSuites:  []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			NextProtos:            []string{"h2", "http/1.1"},
			SessionTicketsEnabled: true,
			ClientCAs:             pool,
			ClientAuth:            tls.RequireAndVerifyClientCert,
		})
		if cfg.MinVersion != tls.VersionTLS13 {
			t.Fatalf("MinVersion=%x", cfg.MinVersion)
		}
		if len(cfg.CipherSuites) != 1 {
			t.Fatalf("cipher 覆盖没生效: %v", cfg.CipherSuites)
		}
		if cfg.SessionTicketsDisabled {
			t.Fatal("显式开了 ticket 却还是关的")
		}
		if cfg.ClientCAs != pool || cfg.ClientAuth != tls.RequireAndVerifyClientCert {
			t.Fatal("mTLS 相关字段没透传 —— 客户端证书校验会静默失效")
		}
		if strings.Join(cfg.NextProtos, ",") != "h2,http/1.1" {
			t.Fatalf("NextProtos=%v", cfg.NextProtos)
		}
	})

	t.Run("没证书直接 panic", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("空证书应当在启动期 panic,而不是握手到一半才报错")
			}
		}()
		_ = NewServerTLSConfig(ServerTLSOptions{})
	})
}
