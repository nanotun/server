// Package certs 提供自托管部署用的客户端 mTLS 证书签发（profile 导出时临场生成）。
package certs

import (
	"crypto"
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

// maxClientCertValidDays 客户端 mTLS 证书有效期上限(天)。10 年:覆盖任何合理自托管用法,
// 又远离 time.Duration(int64 ns ≈ 292 年)的溢出边界(见 IssueClientCert 的 NotAfter 计算)。
const maxClientCertValidDays = 3650

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
	// 上限防溢出:NotAfter 用 time.Duration(validDays)*24h,而 time.Duration 是 int64 纳秒
	// (上限 ~106751 天 ≈ 292 年)。--hy2-client-cert-days 是无符号 flag,运维误传超大值会让
	// 乘法溢出成负 / 小 duration → NotAfter 落到过去,签出「刚签发即过期」的废证。10 年上限既覆盖
	// 一切合理用法,又远离溢出边界。
	if validDays > maxClientCertValidDays {
		return nil, fmt.Errorf("validDays 过大(%d)，上限 %d 天", validDays, maxClientCertValidDays)
	}

	caCert, err := parseCertificatePEM(caCertPEM)
	if err != nil {
		return nil, fmt.Errorf("解析 CA 证书: %w", err)
	}
	if !caCert.IsCA {
		return nil, errors.New("CA 证书缺少 CA:TRUE（basicConstraints）")
	}
	// 第四轮深扫 MED:若 CA 证书带了 KeyUsage 扩展,必须包含 keyCertSign;否则它根本没被授权签发证书,用它签出的
	// 客户端证书会被严格校验方(RFC 5280)拒绝(建链失败),等到运维部署时才发现。KeyUsage==0 = 未声明该扩展,
	// 按 X.509 惯例视为不限,放行(与既有仅 IsCA 的宽松度一致)。
	if caCert.KeyUsage != 0 && caCert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("CA 证书 KeyUsage 缺少 keyCertSign（无签发证书权限）")
	}
	// 拒绝**已过期 / 尚未生效**的 CA:用它签出的客户端证书链在校验时必然失败(签发者证书本身无效)。及早报错
	// 好过让运维拿到一张「客户端一连就被拒」的 profile。
	now := time.Now().UTC()
	if now.After(caCert.NotAfter) {
		return nil, fmt.Errorf("CA 证书已过期(NotAfter=%s)", caCert.NotAfter.Format(time.RFC3339))
	}
	if now.Before(caCert.NotBefore) {
		return nil, fmt.Errorf("CA 证书尚未生效(NotBefore=%s)", caCert.NotBefore.Format(time.RFC3339))
	}

	caKey, err := parsePrivateKeyPEM(caKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("解析 CA 私钥: %w", err)
	}

	// 第十六轮深扫 LOW:校验 CA 私钥与 CA 证书**成对**(私钥公钥 == 证书公钥)。此前证书与私钥各自独立解析,
	// 若运维把 cert 与 key 文件配错(换过其一 / bundle 顺序问题),x509.CreateCertificate 会**照签不误**——用错误
	// 私钥签出的叶子证书,其签名无法被 caCert 公钥验证 → 客户端建链失败,却要到部署连不上时才暴露。这里在签名前
	// 就地比对公钥,配错立即 fail-fast,报「密钥对错配」而非签出一张废证。stdlib 各类公钥都实现 Equal(crypto.PublicKey)。
	signer, ok := caKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("CA 私钥不支持签名(非 crypto.Signer)")
	}
	if eq, ok := signer.Public().(interface{ Equal(crypto.PublicKey) bool }); !ok || !eq.Equal(caCert.PublicKey) {
		return nil, errors.New("CA 私钥与 CA 证书不匹配(公钥不一致,请核对 cert 与 key 文件是否配对)")
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("生成客户端 Ed25519 密钥: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	notAfter := now.Add(time.Duration(validDays) * 24 * time.Hour)
	// 把叶子证书有效期**夹到 CA 有效期以内**(第四轮深扫 MED):若签出的客户端证书 NotAfter 超过 CA 的 NotAfter,
	// CA 过期后这张仍「未过期」的客户端证书也会因链上 CA 失效而被拒——徒增困惑。夹住后二者同进退,语义清晰。
	if notAfter.After(caCert.NotAfter) {
		notAfter = caCert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"nanotun-client"},
		},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  notAfter,
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
		// 用**第一个** CERTIFICATE 块作签发者。CA bundle 约定首证 = 与 key 文件配对的签发 CA;
		// 此前循环到最后一块并覆盖,若 bundle 排成 [签发CA, 根CA],会误取根 CA 当 parent,签出的
		// 客户端证书 Issuer 与实际签名密钥(key 文件对应的证书)不符 → 客户端建链 / 校验失败。
		return x509.ParseCertificate(block.Bytes)
	}
	return nil, errors.New("PEM 中无 CERTIFICATE 块")
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
