package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// M2:本地 self-signed 证书自动生成。
//
// 启动顺序:
//   1) Validate(c.CertDir) → 必须能写;
//   2) 若 cert.pem + key.pem 都存在 → 读出来作为 TLS 起服务;
//   3) 否则生成一对 P-256 ECDSA 证书(10 年),SAN 包含
//      ["localhost", "127.0.0.1", "::1", hostname, 公网 IP(若能拿到)] ∪ ExtraSANs;
//   4) 落盘 cert.pem 0600 + key.pem 0600(目录 0700)。
//
// 生产环境推荐前置 nginx/caddy + Let's Encrypt,把本进程绑 127.0.0.1:7443,
// 让反向代理处理 TLS。本函数提供的 self-signed 适合 dev + 内网。

const (
	certFileName = "cert.pem"
	keyFileName  = "key.pem"

	certFileMode os.FileMode = 0o600
	keyFileMode  os.FileMode = 0o600
	certDirMode  os.FileMode = 0o700

	certValidYears = 10
)

// ensureTLSCert 返回 cert / key 的绝对路径,需要时自动生成。
func ensureTLSCert(certDir string, extraSANs []string) (certPath, keyPath string, err error) {
	if strings.TrimSpace(certDir) == "" {
		return "", "", errors.New("cert dir cannot be empty")
	}
	if err := os.MkdirAll(certDir, certDirMode); err != nil {
		return "", "", fmt.Errorf("mkdir cert dir %s: %w", certDir, err)
	}
	_ = os.Chmod(certDir, certDirMode)

	certPath = filepath.Join(certDir, certFileName)
	keyPath = filepath.Join(certDir, keyFileName)

	cExists := fileExists(certPath)
	kExists := fileExists(keyPath)
	if cExists && kExists {
		logrus.WithFields(logrus.Fields{
			"cert": certPath, "key": keyPath,
		}).Info("[tls] 复用已存在的证书")
		_ = os.Chmod(certPath, certFileMode)
		_ = os.Chmod(keyPath, keyFileMode)
		return certPath, keyPath, nil
	}
	// 半残:只剩一个文件,拒绝起来,提示运维清理。
	// 否则可能 cert 是别的 hostname / key 不匹配,排查超烦。
	if cExists != kExists {
		return "", "", fmt.Errorf("cert dir %s is half-populated (only one of %s/%s present); please clean it up and retry",
			certDir, certFileName, keyFileName)
	}

	logrus.WithField("cert_dir", certDir).Info("[tls] 未发现证书,自动生成 self-signed(10 年有效)")

	sans := collectSANs(extraSANs)
	if err := generateSelfSignedCert(certPath, keyPath, sans); err != nil {
		return "", "", err
	}
	logrus.WithField("sans", sans).Warn("[tls] 已生成自签证书。生产环境请前置 nginx/caddy + 正式证书")
	return certPath, keyPath, nil
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir() && st.Size() > 0
}

// collectSANs 推导一个尽可能"覆盖管理员可能用到的访问方式"的 SAN 集合。
// 实在拿不到也至少有 localhost + 127.0.0.1 + ::1 兜底。
func collectSANs(extra []string) []string {
	seen := map[string]struct{}{}
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		seen[s] = struct{}{}
	}
	add("localhost")
	add("127.0.0.1")
	add("::1")
	if h, err := os.Hostname(); err == nil && h != "" {
		add(h)
	}
	// 枚举本机所有非 loopback / 非 link-local 的 IP 进 SAN。M2 用 self-signed 时,
	// 管理员往往用 IP 直连(domain 未必配),这里覆盖到能减少 NET::ERR_CERT_COMMON_NAME_INVALID。
	if ifaces, err := net.Interfaces(); err == nil {
		for _, ifc := range ifaces {
			if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, _ := ifc.Addrs()
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok {
					ip := ipn.IP
					if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
						continue
					}
					add(ip.String())
				}
			}
		}
	}
	for _, s := range extra {
		add(s)
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	return out
}

func generateSelfSignedCert(certPath, keyPath string, sans []string) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate ecdsa key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("rand serial: %w", err)
	}
	notBefore := time.Now().Add(-1 * time.Hour) // 兜底时钟漂移
	notAfter := notBefore.AddDate(certValidYears, 0, 0)

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "nanotun-web self-signed",
			Organization: []string{"nanotun"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},

		BasicConstraintsValid: true,
		// IsCA=false:这是一张**叶子/终端实体**服务器证书,绝不能当 CA。此前设 true 是为了"让管理员把它
		// 当 root CA 装进信任库",但那样一来,落在本机(0600)的这把私钥就能为**任意**域名签出被该信任库
		// 接受的证书 —— web 主机一旦被攻陷,攻击者即可用它 MITM 任何站点。需要信任时,现代浏览器 / 系统可
		// 直接把这张叶子证书作为例外 / 终端实体导入,无需赋予其 CA 签发能力。
		IsCA: false,
	}
	for _, s := range sans {
		if ip := net.ParseIP(s); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, s)
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	if err := writePEMFile(certPath, "CERTIFICATE", derBytes, certFileMode); err != nil {
		return err
	}

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		_ = os.Remove(certPath)
		return fmt.Errorf("marshal ec private key: %w", err)
	}
	if err := writePEMFile(keyPath, "EC PRIVATE KEY", keyDER, keyFileMode); err != nil {
		_ = os.Remove(certPath)
		return err
	}
	return nil
}

// writePEMFile 把 der 以 PEM 落盘到 path,经「随机名临时文件 → fchmod → fsync → 原子 rename」写入。
//
// 第四轮深扫 HIGH 加固:此前用**可预测**临时名 path+".tmp" 且 O_CREATE|O_TRUNC(无 O_EXCL)。writePEMFile 落的是
// **EC 私钥**(key.pem)与自签证书。若 CertDir 他人可写、或攻击者预置 <path>.tmp 为符号链接,OpenFile 会**跟随**它
// 把私钥写到链接目标(泄密 / 覆写受害文件);且既有 <path>.tmp 为 0644 时会**保留**该松权限(mode 只在创建时生效),
// rename 后再 Chmod 仍留一个世界可读窗口。改用 os.CreateTemp(内部 O_CREATE|O_EXCL + 随机后缀,0600)+ 显式 fchmod +
// fsync + 原子 rename —— 与 nanotun-admin 的 writeFileTight / copyFileAtomic 同姿态,消除符号链接跟随与权限保留窗口。
func writePEMFile(path, blockType string, der []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp in %s: %w", dir, err)
	}
	tmp := f.Name()
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("encode pem %s: %w", path, err)
	}
	// CreateTemp 已是 0600;显式 fchmod 到目标 mode,确保 rename 前即为既定权限(密钥无宽权限窗口)。
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("chmod %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("fsync %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename %s: %w", path, err)
	}
	return nil
}
