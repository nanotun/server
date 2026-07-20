package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureTLSCert_Generate(t *testing.T) {
	dir := t.TempDir()
	cert, key, err := ensureTLSCert(dir, []string{"admin.example.com", "10.0.0.1"})
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if cert != filepath.Join(dir, "cert.pem") || key != filepath.Join(dir, "key.pem") {
		t.Fatalf("paths wrong: %s %s", cert, key)
	}

	// 文件存在 + 模式 0600
	st, err := os.Stat(cert)
	if err != nil {
		t.Fatal(err)
	}
	if mode := st.Mode().Perm(); mode != 0o600 {
		t.Errorf("cert mode = %o, want 0600", mode)
	}
	st, _ = os.Stat(key)
	if mode := st.Mode().Perm(); mode != 0o600 {
		t.Errorf("key mode = %o, want 0600", mode)
	}

	// 解码证书,确认 SAN 含我们传入的额外条目
	pemBytes, _ := os.ReadFile(cert)
	block, _ := pem.Decode(pemBytes)
	x, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	hasDNS := false
	for _, d := range x.DNSNames {
		if d == "admin.example.com" {
			hasDNS = true
		}
	}
	if !hasDNS {
		t.Errorf("DNSNames missing admin.example.com: %v", x.DNSNames)
	}
	hasIP := false
	for _, ip := range x.IPAddresses {
		if ip.String() == "10.0.0.1" {
			hasIP = true
		}
	}
	if !hasIP {
		t.Errorf("IPAddresses missing 10.0.0.1: %v", x.IPAddresses)
	}

	// 第二次调用应该复用,不再重写文件
	st1, _ := os.Stat(cert)
	cert2, _, err := ensureTLSCert(dir, []string{"foo.bar"})
	if err != nil {
		t.Fatalf("re-ensure: %v", err)
	}
	st2, _ := os.Stat(cert2)
	if !st1.ModTime().Equal(st2.ModTime()) {
		t.Errorf("cert should not be rewritten on re-ensure")
	}

	// 用 tls.LoadX509KeyPair 反向验证一对
	if _, err := tls.LoadX509KeyPair(cert, key); err != nil {
		t.Errorf("LoadX509KeyPair: %v", err)
	}
}

func TestEnsureTLSCert_HalfMissingRejected(t *testing.T) {
	dir := t.TempDir()
	// 故意只放一个 cert.pem
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), []byte("dummy"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := ensureTLSCert(dir, nil)
	if err == nil {
		t.Fatal("半残证书目录应被拒绝")
	}
}
