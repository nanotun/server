// Package certs 提供自托管部署用的客户端 mTLS 证书签发（profile 导出时临场生成）。
package certs

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"
)

// IssuedClientCert 为 PEM 编码的客户端证书与私钥（供 profile.hy2 下发）。
type IssuedClientCert struct {
	CertPEM string
	KeyPEM  string
}

// ClientCAKeyPath 由 `tls_client_ca_file` 路径推导 CA 私钥路径（与 server/certs/README 一致）。
func ClientCAKeyPath(caCertPath string) string {
	s := strings.TrimSpace(caCertPath)
	if strings.HasSuffix(s, ".pem") {
		return strings.TrimSuffix(s, ".pem") + "-key.pem"
	}
	return s + "-key.pem"
}

// IssueClientCert 用 PEM 格式的 CA 证书/私钥为 `commonName` 签发短期客户端证书（**Ed25519**）。
//
// 选 Ed25519：cert PEM ~520 B、key PEM ~120 B，相比 RSA-2048 体积约 1/5；TLS 1.3 (RFC 8446)
// 强制要求实现 Ed25519 签名验证，crypto/tls 与 rustls/ring 都原生支持，profile 装得进 QR。
// CA 算法不强制 Ed25519：现有 RSA-2048 CA 可继续给 Ed25519 客户端证书签名，X.509 标准允许混合。
//
// validDays 须 > 0；典型自托管 profile 导出用 90 天，到期后重新 `profile show` 即可。
func IssueClientCert(caCertPEM, caKeyPEM, commonName string, validDays int) (*IssuedClientCert, error) {
	commonName = strings.TrimSpace(commonName)
	if commonName == "" {
		return nil, errors.New("commonName 不能为空")
	}
	if validDays <= 0 {
		return nil, fmt.Errorf("validDays 须 > 0，得到 %d", validDays)
	}

	caCert, err := parseCertificatePEM(caCertPEM)
	if err != nil {
		return nil, fmt.Errorf("解析 CA 证书: %w", err)
	}
	if !caCert.IsCA {
		return nil, errors.New("CA 证书缺少 CA:TRUE（basicConstraints）")
	}

	caKey, err := parsePrivateKeyPEM(caKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("解析 CA 私钥: %w", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("生成客户端 Ed25519 密钥: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"nanotun-client"},
		},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(time.Duration(validDays) * 24 * time.Hour),
		// Ed25519 只能签名，去掉 KeyEncipherment（TLS 1.3 客户端认证只需 DigitalSignature）。
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, pub, caKey)
	if err != nil {
		return nil, fmt.Errorf("签发客户端证书: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("编码客户端私钥 (PKCS8): %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return &IssuedClientCert{
		CertPEM: string(certPEM),
		KeyPEM:  string(keyPEM),
	}, nil
}

// IssueClientCertFromFiles 从 CA 证书/私钥文件签发客户端证书。
func IssueClientCertFromFiles(caCertPath, caKeyPath, commonName string, validDays int) (*IssuedClientCert, error) {
	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("读取 CA 证书 %q: %w", caCertPath, err)
	}
	caKeyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		return nil, fmt.Errorf("读取 CA 私钥 %q: %w", caKeyPath, err)
	}
	return IssueClientCert(string(caCertPEM), string(caKeyPEM), commonName, validDays)
}

func parseCertificatePEM(pemData string) (*x509.Certificate, error) {
	var cert *x509.Certificate
	rest := []byte(pemData)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		cert = c
	}
	if cert == nil {
		return nil, errors.New("PEM 中无 CERTIFICATE 块")
	}
	return cert, nil
}

// GenerateTestCA 写入自签测试用客户端 CA（仅单测 / profile 测试 fixture）。
func GenerateTestCA(certPath, keyPath string) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "nanotun-test-client-ca"},
		NotBefore:             time.Now().UTC().Add(-time.Hour),
		NotAfter:              time.Now().UTC().Add(3650 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return err
	}
	return os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600)
}

func parsePrivateKeyPEM(pemData string) (interface{}, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("PEM 中无私钥块")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("不支持的私钥类型 %q", block.Type)
	}
}
