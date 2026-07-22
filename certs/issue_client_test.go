package certs

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var osReadFile = os.ReadFile

// TestIssueClientCert_ValidDaysBounds 验证 validDays 上下界:≤0 拒;超上限(防 time.Duration 溢出)拒;
// 上限值本身与典型 90 天放行。
func TestIssueClientCert_ValidDaysBounds(t *testing.T) {
	dir := t.TempDir()
	caCertPath := filepath.Join(dir, "ca.pem")
	caKeyPath := filepath.Join(dir, "ca-key.pem")
	if err := GenerateTestCA(caCertPath, caKeyPath); err != nil {
		t.Fatal(err)
	}
	caCertPEM, _ := os.ReadFile(caCertPath)
	caKeyPEM, _ := os.ReadFile(caKeyPath)

	bad := []int{0, -1, maxClientCertValidDays + 1, 1 << 30}
	for _, d := range bad {
		if _, err := IssueClientCert(string(caCertPEM), string(caKeyPEM), "cn", d); err == nil {
			t.Errorf("validDays=%d 应被拒绝", d)
		}
	}
	for _, d := range []int{1, 90, maxClientCertValidDays} {
		issued, err := IssueClientCert(string(caCertPEM), string(caKeyPEM), "cn", d)
		if err != nil || issued == nil {
			t.Errorf("validDays=%d 应放行,got err=%v", d, err)
			continue
		}
		// NotAfter 必须落在未来(未因溢出跑到过去)。
		cert, err := parseCertificatePEM(issued.CertPEM)
		if err != nil {
			t.Fatal(err)
		}
		if !cert.NotAfter.After(cert.NotBefore) {
			t.Errorf("validDays=%d: NotAfter(%v) 不晚于 NotBefore(%v)", d, cert.NotAfter, cert.NotBefore)
		}
	}
}

func TestIssueClientCert_DevCA(t *testing.T) {
	dir := t.TempDir()
	caCertPath := filepath.Join(dir, "ca.pem")
	caKeyPath := filepath.Join(dir, "ca-key.pem")
	if err := GenerateTestCA(caCertPath, caKeyPath); err != nil {
		t.Fatal(err)
	}

	issued, err := IssueClientCertFromFiles(caCertPath, caKeyPath, "vpnport-test-user", 90)
	if err != nil {
		t.Fatal(err)
	}
	if issued.CertPEM == "" || issued.KeyPEM == "" {
		t.Fatal("empty pem")
	}

	clientCert, err := parseCertificatePEM(issued.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	if clientCert.Subject.CommonName != "vpnport-test-user" {
		t.Fatalf("cn=%q", clientCert.Subject.CommonName)
	}
	if clientCert.IsCA {
		t.Fatal("client cert must not be CA")
	}
	// 自切 Ed25519：cert/key 公钥须匹配，PEM 头是 PKCS8 "PRIVATE KEY"。
	key, err := parsePrivateKeyPEM(issued.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	edPriv, ok := key.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("expected ed25519 private key, got %T", key)
	}
	certPub, ok := clientCert.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("expected ed25519 cert public key, got %T", clientCert.PublicKey)
	}
	if !edPriv.Public().(ed25519.PublicKey).Equal(certPub) {
		t.Fatal("cert/key public key mismatch")
	}
	if !strings.Contains(issued.KeyPEM, "-----BEGIN PRIVATE KEY-----") {
		t.Fatalf("expected PKCS8 PEM header, got: %s", issued.KeyPEM[:40])
	}
}

// TestIssuedClientCert_LoadsAsTLSCert：crypto/tls 能加载 PEM 对（服务端 mTLS 路径）。
func TestIssuedClientCert_LoadsAsTLSCert(t *testing.T) {
	dir := t.TempDir()
	if err := GenerateTestCA(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca-key.pem")); err != nil {
		t.Fatal(err)
	}
	issued, err := IssueClientCertFromFiles(
		filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca-key.pem"),
		"cn", 30)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tls.X509KeyPair([]byte(issued.CertPEM), []byte(issued.KeyPEM)); err != nil {
		t.Fatalf("tls.X509KeyPair: %v", err)
	}
}

// TestIssuedClientCert_VerifiedByCA：用 CA 校验签发的客户端证书（服务端 mTLS 实际行为）。
func TestIssuedClientCert_VerifiedByCA(t *testing.T) {
	dir := t.TempDir()
	caCertPath := filepath.Join(dir, "ca.pem")
	caKeyPath := filepath.Join(dir, "ca-key.pem")
	if err := GenerateTestCA(caCertPath, caKeyPath); err != nil {
		t.Fatal(err)
	}
	issued, err := IssueClientCertFromFiles(caCertPath, caKeyPath, "cn", 30)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := parseCertificatePEM(readFile(t, caCertPath))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	clientCert, err := parseCertificatePEM(issued.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clientCert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("client cert not verified by CA: %v", err)
	}
}

// TestIssuedClientCert_SizeBudget：cert+key 合计 < 1500 B（QR 友好）。
// 用来防止以后被改回 RSA-2048（合计 ~3 KB，单节点 mTLS 就爆 QR）。
func TestIssuedClientCert_SizeBudget(t *testing.T) {
	dir := t.TempDir()
	if err := GenerateTestCA(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca-key.pem")); err != nil {
		t.Fatal(err)
	}
	issued, err := IssueClientCertFromFiles(
		filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca-key.pem"),
		"size-budget", 90)
	if err != nil {
		t.Fatal(err)
	}
	total := len(issued.CertPEM) + len(issued.KeyPEM)
	t.Logf("[client mTLS size] cert=%d B  key=%d B  total=%d B",
		len(issued.CertPEM), len(issued.KeyPEM), total)
	if total > 1500 {
		t.Fatalf("client cert+key %d B > 1500 B budget (regression)", total)
	}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := osReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestClientCAKeyPath(t *testing.T) {
	if got := ClientCAKeyPath("certs/dev-client-ca.pem"); got != "certs/dev-client-ca-key.pem" {
		t.Fatalf("got %q", got)
	}
}
