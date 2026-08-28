package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 这些闸口全是 fail-fast:签出一张废证的代价不是在这里报错,而是运维把 profile
// 发下去、用户连不上、再花半天查为什么。每一条都对应一种「看起来签成功了、
// 实际上建链必失败」的配错。

// caPair 造一份自签 CA(RSA),可指定有效期与 KeyUsage。
func caPair(t *testing.T, notBefore, notAfter time.Time, ku x509.KeyUsage, isCA bool) (certPEM, keyPEM string) {
	t.Helper()
	dir := t.TempDir()
	c, k := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca-key.pem")
	if err := GenerateTestCA(c, k); err != nil {
		t.Fatalf("GenerateTestCA: %v", err)
	}
	kb, err := os.ReadFile(k)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	key, err := parsePrivateKeyPEM(string(kb))
	if err != nil {
		t.Fatalf("parsePrivateKeyPEM: %v", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		t.Fatalf("类型 %T", key)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "custom-ca"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              ku,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(kb)
}

// goodCA 返回一份可用的 CA。
func goodCA(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	dir := t.TempDir()
	c, k := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca-key.pem")
	if err := GenerateTestCA(c, k); err != nil {
		t.Fatalf("GenerateTestCA: %v", err)
	}
	cb, err := os.ReadFile(c)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	kb, err := os.ReadFile(k)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	return string(cb), string(kb)
}

func TestClientCAKeyPath_DerivesTheSiblingKeyPath(t *testing.T) {
	cases := map[string]string{
		"/etc/nanotun/client-ca.pem": "/etc/nanotun/client-ca-key.pem",
		"  /etc/ca.pem  ":            "/etc/ca-key.pem",
		"/etc/ca.crt":                "/etc/ca.crt-key.pem",
		"ca":                         "ca-key.pem",
		"":                           "-key.pem",
	}
	for in, want := range cases {
		if got := ClientCAKeyPath(in); got != want {
			t.Errorf("ClientCAKeyPath(%q)=%q,期望 %q", in, got, want)
		}
	}
}

func TestIssueClientCert_RejectsInputsThatWouldProduceAnUnusableCert(t *testing.T) {
	caCert, caKey := goodCA(t)

	t.Run("正常签发", func(t *testing.T) {
		out, err := IssueClientCert(caCert, caKey, "  alice  ", 90)
		if err != nil {
			t.Fatalf("err=%v", err)
		}
		leaf, err := parseCertificatePEM(out.CertPEM)
		if err != nil {
			t.Fatalf("签出来的证书自己都解不了: %v", err)
		}
		if leaf.Subject.CommonName != "alice" {
			t.Fatalf("CN=%q,前后空白应被裁掉", leaf.Subject.CommonName)
		}
		if leaf.IsCA {
			t.Fatal("客户端证书不该是 CA —— 拿到它就能再签发下级证书")
		}
		// TLS 1.3 客户端认证只需要这两项;缺 ClientAuth 会被服务端直接拒。
		if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
			t.Fatalf("ExtKeyUsage=%v", leaf.ExtKeyUsage)
		}
		if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			t.Fatal("缺 DigitalSignature,Ed25519 客户端认证签不了名")
		}
		if _, err := parsePrivateKeyPEM(out.KeyPEM); err != nil {
			t.Fatalf("私钥 PEM 解不出来: %v", err)
		}
		// 签名真的能被 CA 公钥验过 —— 否则就是一张漂亮的废证。
		ca, _ := parseCertificatePEM(caCert)
		if err := leaf.CheckSignatureFrom(ca); err != nil {
			t.Fatalf("叶子证书的签名验不过 CA: %v", err)
		}
	})

	t.Run("CN 为空", func(t *testing.T) {
		for _, cn := range []string{"", "   ", "\t\n"} {
			if _, err := IssueClientCert(caCert, caKey, cn, 90); err == nil {
				t.Fatalf("CN=%q 应被拒", cn)
			}
		}
	})

	t.Run("有效期非法", func(t *testing.T) {
		for _, d := range []int{0, -1, -365} {
			if _, err := IssueClientCert(caCert, caKey, "alice", d); err == nil {
				t.Fatalf("validDays=%d 应被拒", d)
			}
		}
		// 超大值会让 time.Duration 的纳秒乘法溢出成负数 → NotAfter 落到过去,
		// 签出「刚签发即过期」的废证。
		for _, d := range []int{maxClientCertValidDays + 1, 1 << 30} {
			_, err := IssueClientCert(caCert, caKey, "alice", d)
			if err == nil {
				t.Fatalf("validDays=%d 应被拒", d)
			}
			if !strings.Contains(err.Error(), "limit") {
				t.Fatalf("错误里应点明上限: %v", err)
			}
		}
		// 上限本身是合法的。
		if _, err := IssueClientCert(caCert, caKey, "alice", maxClientCertValidDays); err != nil {
			t.Fatalf("正好等于上限应通过: %v", err)
		}
	})

	t.Run("CA 证书是垃圾", func(t *testing.T) {
		for _, bad := range []string{"", "不是 PEM", "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n"} {
			if _, err := IssueClientCert(bad, caKey, "alice", 90); err == nil {
				t.Fatalf("%q 应被拒", bad[:min(20, len(bad))])
			}
		}
	})

	t.Run("CA 私钥是垃圾", func(t *testing.T) {
		for _, bad := range []string{"", "不是 PEM",
			"-----BEGIN EC PARAMETERS-----\nZm9v\n-----END EC PARAMETERS-----\n"} {
			if _, err := IssueClientCert(caCert, bad, "alice", 90); err == nil {
				t.Fatal("应被拒")
			}
		}
	})

	// 下面三条都是「证书本身能解析、但用它签出来的东西一定建不了链」。
	t.Run("CA 没有 CA:TRUE", func(t *testing.T) {
		c, k := caPair(t, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour),
			x509.KeyUsageCertSign, false)
		if _, err := IssueClientCert(c, k, "alice", 90); err == nil {
			t.Fatal("非 CA 证书不该被拿来签发")
		}
	})

	t.Run("CA 的 KeyUsage 里没有 keyCertSign", func(t *testing.T) {
		c, k := caPair(t, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour),
			x509.KeyUsageDigitalSignature, true)
		_, err := IssueClientCert(c, k, "alice", 90)
		if err == nil {
			t.Fatal("没有签发权限的 CA,签出来的证书会被严格校验方拒")
		}
		if !strings.Contains(err.Error(), "keyCertSign") {
			t.Fatalf("错误里应点名是哪个扩展: %v", err)
		}
	})

	t.Run("CA 已过期 / 尚未生效", func(t *testing.T) {
		expired, ek := caPair(t, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour),
			x509.KeyUsageCertSign, true)
		if _, err := IssueClientCert(expired, ek, "alice", 90); err == nil {
			t.Fatal("过期 CA 应被拒")
		}
		future, fk := caPair(t, time.Now().Add(24*time.Hour), time.Now().Add(48*time.Hour),
			x509.KeyUsageCertSign, true)
		if _, err := IssueClientCert(future, fk, "alice", 90); err == nil {
			t.Fatal("未生效 CA 应被拒")
		}
	})

	// cert 和 key 配错是运维最容易犯的错(换过其中一个文件)。x509 会照签不误,
	// 签出来的东西谁都验不过。
	t.Run("cert 与 key 不配对", func(t *testing.T) {
		_, otherKey := goodCA(t)
		_, err := IssueClientCert(caCert, otherKey, "alice", 90)
		if err == nil {
			t.Fatal("配错的 cert/key 应当就地报错,而不是签出一张验不过的证书")
		}
		if !strings.Contains(err.Error(), "does not match") {
			t.Fatalf("错误要说清是配对问题: %v", err)
		}
	})

	// 叶子证书的有效期要夹在 CA 之内:超出去的话,CA 一过期,这张「还没到期」
	// 的客户端证书也会因为链上失效被拒,徒增困惑。
	t.Run("叶子有效期夹在 CA 之内", func(t *testing.T) {
		caEnd := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
		c, k := caPair(t, time.Now().Add(-time.Hour), caEnd, x509.KeyUsageCertSign, true)
		out, err := IssueClientCert(c, k, "alice", 3650)
		if err != nil {
			t.Fatalf("err=%v", err)
		}
		leaf, err := parseCertificatePEM(out.CertPEM)
		if err != nil {
			t.Fatalf("parseCertificatePEM: %v", err)
		}
		if leaf.NotAfter.After(caEnd) {
			t.Fatalf("叶子 NotAfter=%s 超过了 CA 的 %s", leaf.NotAfter, caEnd)
		}
	})
}

func TestIssueClientCertFromFiles_ReportsWhichFileItCouldNotRead(t *testing.T) {
	dir := t.TempDir()
	c, k := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca-key.pem")
	if err := GenerateTestCA(c, k); err != nil {
		t.Fatalf("GenerateTestCA: %v", err)
	}

	if _, err := IssueClientCertFromFiles(c, k, "alice", 90); err != nil {
		t.Fatalf("正常路径 err=%v", err)
	}

	missing := filepath.Join(dir, "没有这个文件")
	err := IssueClientCertFromFilesErr(t, missing, k)
	if !strings.Contains(err.Error(), "CA certificate") || !strings.Contains(err.Error(), missing) {
		t.Fatalf("错误要点名是哪个文件读不到: %v", err)
	}
	err = IssueClientCertFromFilesErr(t, c, missing)
	if !strings.Contains(err.Error(), "CA private key") {
		t.Fatalf("读不到私钥时应说是私钥: %v", err)
	}
}

func IssueClientCertFromFilesErr(t *testing.T, certPath, keyPath string) error {
	t.Helper()
	_, err := IssueClientCertFromFiles(certPath, keyPath, "alice", 90)
	if err == nil {
		t.Fatal("应报错")
	}
	return err
}

// CA bundle 排成 [签发CA, 根CA] 是常见写法。取错块的话,签出的证书 Issuer 跟
// 实际签名密钥对不上 —— 客户端建链失败,而这边一切"正常"。
func TestParseCertificatePEM_TakesTheFirstCertificateBlockInABundle(t *testing.T) {
	first, key := goodCA(t)
	second, _ := goodCA(t)

	t.Run("bundle 取第一块", func(t *testing.T) {
		got, err := parseCertificatePEM(first + second)
		if err != nil {
			t.Fatalf("err=%v", err)
		}
		want, _ := parseCertificatePEM(first)
		if got.SerialNumber.Cmp(want.SerialNumber) != 0 {
			t.Fatal("取到了 bundle 里的第二块 —— 签出的证书 Issuer 会跟签名密钥对不上")
		}
		// 用整个 bundle 去签,结果必须仍能被第一块验过。
		out, err := IssueClientCert(first+second, key, "alice", 30)
		if err != nil {
			t.Fatalf("IssueClientCert: %v", err)
		}
		leaf, _ := parseCertificatePEM(out.CertPEM)
		if err := leaf.CheckSignatureFrom(want); err != nil {
			t.Fatalf("验不过第一块 CA: %v", err)
		}
	})

	t.Run("跳过非 CERTIFICATE 块", func(t *testing.T) {
		prefixed := "-----BEGIN RSA PRIVATE KEY-----\nZm9v\n-----END RSA PRIVATE KEY-----\n" + first
		if _, err := parseCertificatePEM(prefixed); err != nil {
			t.Fatalf("私钥块在前面时应跳过它继续找证书: %v", err)
		}
	})

	t.Run("没有 CERTIFICATE 块", func(t *testing.T) {
		for _, bad := range []string{"", "什么都不是",
			"-----BEGIN RSA PRIVATE KEY-----\nZm9v\n-----END RSA PRIVATE KEY-----\n"} {
			if _, err := parseCertificatePEM(bad); err == nil {
				t.Fatal("应报错")
			}
		}
	})
}

func TestParsePrivateKeyPEM_AcceptsPKCS1AndPKCS8AndNothingElse(t *testing.T) {
	_, rsaKeyPEM := goodCA(t)
	if _, err := parsePrivateKeyPEM(rsaKeyPEM); err != nil {
		t.Fatalf("PKCS1 RSA: %v", err)
	}

	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(ec)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	pkcs8 := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if _, err := parsePrivateKeyPEM(pkcs8); err != nil {
		t.Fatalf("PKCS8: %v", err)
	}

	for _, bad := range []string{
		"",
		"不是 PEM",
		"-----BEGIN EC PRIVATE KEY-----\nZm9v\n-----END EC PRIVATE KEY-----\n", // 不支持的类型
		"-----BEGIN PRIVATE KEY-----\nZm9v\n-----END PRIVATE KEY-----\n",       // 类型对但内容坏
	} {
		if _, err := parsePrivateKeyPEM(bad); err == nil {
			t.Fatalf("%q 应被拒", bad)
		}
	}
}

func TestGenerateTestCA_WritesAPairThatCanImmediatelySign(t *testing.T) {
	dir := t.TempDir()
	c, k := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca-key.pem")
	if err := GenerateTestCA(c, k); err != nil {
		t.Fatalf("GenerateTestCA: %v", err)
	}
	if _, err := IssueClientCertFromFiles(c, k, "alice", 90); err != nil {
		t.Fatalf("刚生成的 CA 就签不了证: %v", err)
	}

	st, err := os.Stat(k)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Fatalf("CA 私钥权限 0o%o —— 不能给 group/others 看到", perm)
	}

	t.Run("路径写不了时报错", func(t *testing.T) {
		bad := filepath.Join(dir, "没有这个目录", "ca.pem")
		if err := GenerateTestCA(bad, k); err == nil {
			t.Fatal("应报错")
		}
		if err := GenerateTestCA(c, filepath.Join(dir, "没有这个目录", "k.pem")); err == nil {
			t.Fatal("私钥写不下去也该报错")
		}
	})
}
