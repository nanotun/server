package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
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
//   3) 否则生成一对 P-256 ECDSA 证书(100 年,见 certValidYears),SAN 包含
//      ["localhost", "127.0.0.1", "::1", hostname, 公网 IP(若能拿到)] ∪ ExtraSANs;
//   4) 落盘 cert.pem 0600 + key.pem 0600(目录 0700)。
//
// 生产环境推荐前置 nginx/caddy + Let's Encrypt,把本进程绑 127.0.0.1:7443,
// 让反向代理处理 TLS。本函数提供的 self-signed 适合 dev + 内网。

// certRand 是自签证书生成过程用的随机源,写成变量只为可测性,生产恒为 rand.Reader。
//
// 密钥生成 / 序列号 / 签名这三步都取随机数,任一步失败都必须「一个文件都不留」——
// 半个证书目录会让下次启动撞上「半残目录」而拒绝起服务(见 ensureTLSCert),
// 更糟的是留下一把无对应证书的私钥。真实的 crypto/rand 故障没法在测试里制造,
// 没有这个接缝就无法验证这条不变量。
var certRand io.Reader = rand.Reader

const (
	certFileName = "cert.pem"
	keyFileName  = "key.pem"

	certFileMode os.FileMode = 0o600
	keyFileMode  os.FileMode = 0o600
	certDirMode  os.FileMode = 0o700

	// certValidYears 与装机脚本签的那几张对齐(一百年,见 scripts/ensure-server-assets.sh
	// 的 SELF_SIGNED_DAYS)。
	//
	// 这张证书没有任何续期机制:ensureTLSCert 只在两个文件都不在时才重签,而重签会换掉
	// 身份 —— 浏览器那边此前手工点过的例外、或导进信任库的那份,全部作废,得挨个重来一遍。
	// 十年是个会到的日子,到那天 TLS 直接连不上,而症状(浏览器报证书无效)离原因(装机
	// 脚本十年前定的默认值)隔得足够远,没人会往这儿想。
	//
	// 长有效期不影响浏览器接受度:Apple / Chrome 那条 398 天上限只管**公共信任根**签出
	// 的证书,手工加信任的自签叶子不在其列。
	certValidYears = 100
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
		// 两个文件都在,还得真读一遍 —— 存在不等于能用。
		//
		// 不读的话,坏证书要拖到 http.ServeTLS 真去加载时才炸,而在那之前已经打了一句
		// 「TLS 服务就绪,等待请求」:日志上先宣布就绪、再猝死,人第一反应是去查端口和
		// 防火墙。最后拿到的是 Go 标准库的原话「tls: failed to find any PEM data in
		// certificate input」—— 不说是哪个文件,也不说怎么办。
		//
		// 而写了一半的证书恰恰是断电 / 磁盘写满最常见的残留(0 字节反倒少见),
		// 也就是说更可能出现的那种坏法,原先给的提示反而更差。
		if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
			return "", "", fmt.Errorf("证书目录 %s 里的证书用不了(%s;%s):%w。多半是写到一半断电或磁盘写满留下的残件 —— 两个一起删掉再重启本服务,会自动重新签发自签证书(浏览器会因此提示一次新证书):rm -f %s %s",
				certDir, describeCertFile(certPath), describeCertFile(keyPath), err, certPath, keyPath)
		}
		logrus.WithFields(logrus.Fields{
			"cert": certPath, "key": keyPath,
		}).Info("[tls] 复用已存在的证书")
		_ = os.Chmod(certPath, certFileMode)
		_ = os.Chmod(keyPath, keyFileMode)
		return certPath, keyPath, nil
	}
	// 半残:两个文件只有一个可用,拒绝起来,提示运维清理。
	// 否则可能 cert 是别的 hostname / key 不匹配,排查超烦。
	//
	// 报错必须点名是哪个文件、什么状态。原先一律说成「only one of cert.pem/key.pem
	// present」,可 fileExists 把「不存在」和「存在但 0 字节」判成同一种 —— 于是磁盘
	// 写满或装到一半断电留下的空文件,报出来是「只有一个文件在」。运维 ls 一看两个
	// 明明都在,第一反应是这条报错不可信,转头去别的地方找原因,而修法其实就在眼前。
	//
	// 给的办法必须是**两个一起删**。说「把不完整的那个删掉」是不成立的:删完剩下的那个
	// 依旧只有一半,这里照样拦下,人照做一遍发现服务还是起不来,于是连带怀疑上面那句
	// 状态描述也是错的。自动重签只在两个都不在时才发生 —— 证书和私钥必须是配对生成的,
	// 单独补一个必然对不上。
	if cExists != kExists {
		return "", "", fmt.Errorf("证书目录 %s 不完整:%s;%s。证书和私钥必须成对,单补一个对不上 —— 两个一起删掉再重启本服务,会自动重新签发自签证书(浏览器会因此提示一次新证书):rm -f %s %s",
			certDir, describeCertFile(certPath), describeCertFile(keyPath), certPath, keyPath)
	}

	// 年数从常量取,别写死在文案里:上次把有效期从 10 年改成 100 年时,这句话是全仓
	// 唯一漏掉的地方,而日志正是运维用来确认「到底签了多久」的东西。
	logrus.WithField("cert_dir", certDir).Infof("[tls] 未发现证书,自动生成 self-signed(%d 年有效)", certValidYears)

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

// describeCertFile 说清楚一个证书文件眼下是什么状态,专门把「不存在」和「在但是空的」
// 分开 —— 这两种在 fileExists 里是同一个答案,而对着屏幕排障的人看到的完全是两回事。
func describeCertFile(p string) string {
	name := filepath.Base(p)
	st, err := os.Stat(p)
	switch {
	case err != nil:
		return name + " 不存在"
	case st.IsDir():
		return name + " 是个目录"
	case st.Size() == 0:
		return name + " 在,但是 0 字节"
	default:
		// 只报字节数,不下「正常」这种判断 —— 调用方之一恰恰是「读出来发现用不了」,
		// 那句话里再说文件正常就是自相矛盾:同一行里既说证书用不了,又说它正常。
		return fmt.Sprintf("%s %d 字节", name, st.Size())
	}
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
	priv, err := ecdsa.GenerateKey(elliptic.P256(), certRand)
	if err != nil {
		return fmt.Errorf("generate ecdsa key: %w", err)
	}
	serial, err := rand.Int(certRand, new(big.Int).Lsh(big.NewInt(1), 128))
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

	derBytes, err := x509.CreateCertificate(certRand, tmpl, tmpl, &priv.PublicKey, priv)
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
