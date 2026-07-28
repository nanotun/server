package main

// tls_cert_guards_test.go(第二十轮)—— 自签证书生成的失败侧。
//
// tls_cert_test.go 覆盖了「生成成功 + 复用 + 半残目录被拒」。这里补的是出错时的
// 落盘状态,它比错误码本身重要得多:
//
//   - 任何一步失败都不能留下半成品。留下一把没有对应证书的私钥,下次启动会撞上
//     「半残目录」直接拒绝起服务;更糟的是那把私钥就此躺在盘上无人知晓;
//   - 目录建不出来 / 参数为空要如实报错,不能悄悄用别的路径;
//   - SAN 集合里的空白项要被丢掉(空 DNS 名会让部分客户端直接判证书非法)。

import (
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// failingReader 在读了 okReads 次之后开始报错,用来把「随机数在第几步失效」
// 逐个走一遍:密钥生成、序列号、签名都取随机数,失败点不同、清理责任相同。
type failingReader struct {
	okReads int
	n       int
}

func (f *failingReader) Read(p []byte) (int, error) {
	if f.n >= f.okReads {
		return 0, errors.New("随机数源坏了")
	}
	f.n++
	for i := range p {
		// 固定填充:不需要真随机,只要能让前几步顺利走过去。
		p[i] = byte(i + 1)
	}
	return len(p), nil
}

// stubCertRand 替换证书生成用的随机源。
func stubCertRand(t *testing.T, okReads int) {
	t.Helper()
	orig := certRand
	certRand = &failingReader{okReads: okReads}
	t.Cleanup(func() { certRand = orig })
}

func TestEnsureTLSCert_RejectsEmptyDir(t *testing.T) {
	for _, dir := range []string{"", "   "} {
		cert, key, err := ensureTLSCert(dir, nil)
		if err == nil {
			t.Fatalf("certDir=%q 竟被接受,cert=%q key=%q", dir, cert, key)
		}
	}
}

// 目录建不出来(路径上有个普通文件挡着)要报错,不能退回某个默认目录 ——
// 那会让证书落到管理员没预期的地方,而下次配置改回来又变成"证书不见了"。
func TestEnsureTLSCert_MkdirFailureIsReported(t *testing.T) {
	base := t.TempDir()
	blocker := filepath.Join(base, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("造挡路的文件: %v", err)
	}
	if _, _, err := ensureTLSCert(filepath.Join(blocker, "certs"), nil); err == nil {
		t.Fatal("路径被普通文件挡住却报成功")
	}
}

// 随机数源在任意一步失效:必须报错,且目录里一个文件都不留。
func TestGenerateSelfSignedCert_RandFailureLeavesNothingBehind(t *testing.T) {
	// 0 次成功读 → 密钥生成就失败;之后逐步放宽,依次落到序列号、签名。
	for _, okReads := range []int{0, 1, 2, 3, 4, 5} {
		dir := t.TempDir()
		stubCertRand(t, okReads)
		certPath := filepath.Join(dir, certFileName)
		keyPath := filepath.Join(dir, keyFileName)

		err := generateSelfSignedCert(certPath, keyPath, []string{"localhost"})
		if err == nil {
			// 放宽到某个点后随机数够用了,证书能正常生成 —— 那就该是一对完整文件。
			if !fileExists(certPath) || !fileExists(keyPath) {
				t.Fatalf("okReads=%d: 报成功却没有完整的证书对", okReads)
			}
			continue
		}
		entries, rerr := os.ReadDir(dir)
		if rerr != nil {
			t.Fatalf("读目录: %v", rerr)
		}
		if len(entries) != 0 {
			names := make([]string, 0, len(entries))
			for _, e := range entries {
				names = append(names, e.Name())
			}
			t.Fatalf("okReads=%d 生成失败却留下了 %v —— 半残目录会让下次启动直接拒绝起服务",
				okReads, names)
		}
	}
}

// budgetReader 供应真随机,但总量封顶:超出预算的那次读直接报错。
//
// 上面那个按「读次数」封顶的 reader 卡不到中间那些步骤 —— 椭圆曲线密钥生成
// 内部会重试取数,前几次读全被它吃掉。按字节预算才能把失败点精确落在
// 「密钥已生成、序列号还没取到」这一刻。
type budgetReader struct {
	left int
}

func (b *budgetReader) Read(p []byte) (int, error) {
	if len(p) > b.left {
		b.left = 0
		return 0, errors.New("随机数预算用尽")
	}
	b.left -= len(p)
	return rand.Read(p)
}

// 序列号取不到随机数时必须失败,而且不留下半个文件。
//
// 为什么不能兜底成一个固定序列号:同一台机器每次重签都会产出**序列号相同、
// 公钥不同**的证书。浏览器与 keychain 用 (issuer, serial) 做缓存键,会认定
// 新证书是旧证书的重复而拒绝加载,症状是"重装证书后浏览器还在报旧指纹",
// 且管理员几乎不可能猜到原因。
func TestGenerateSelfSignedCert_SerialRandFailureLeavesNothingBehind(t *testing.T) {
	// P256 密钥生成消耗 40 字节上下(内部还有一次可选的 1 字节读),序列号再要
	// 16 字节。给 40-56 字节的预算就能把失败点扫过「序列号」这一步。
	sawSerialFailure := false
	for budget := 40; budget <= 56; budget++ {
		dir := t.TempDir()
		orig := certRand
		certRand = &budgetReader{left: budget}
		certPath := filepath.Join(dir, certFileName)
		keyPath := filepath.Join(dir, keyFileName)
		err := generateSelfSignedCert(certPath, keyPath, []string{"localhost"})
		certRand = orig

		if err != nil && strings.Contains(err.Error(), "rand serial") {
			sawSerialFailure = true
		}
		if err == nil {
			continue
		}
		entries, rerr := os.ReadDir(dir)
		if rerr != nil {
			t.Fatalf("读目录: %v", rerr)
		}
		if len(entries) != 0 {
			t.Fatalf("budget=%d 失败却留下了文件 —— 半残目录会让下次启动拒绝起服务", budget)
		}
	}
	if !sawSerialFailure {
		t.Fatal("扫了一遍字节预算都没能让序列号那一步失败 —— 这条分支没被真正验证")
	}
}

// 证书写不进去时,ensureTLSCert 必须把错误往上抛(而不是返回一对指向不存在
// 文件的路径,让调用方在 TLS 握手时才炸)。
func TestEnsureTLSCert_CertWriteFailureIsReported(t *testing.T) {
	dir := t.TempDir()
	// cert.pem 是个目录:fileExists 视为不存在(于是走生成),但最后一步
	// rename 到它上面必然失败。
	if err := os.Mkdir(filepath.Join(dir, certFileName), 0o700); err != nil {
		t.Fatalf("造占位目录: %v", err)
	}
	if _, _, err := ensureTLSCert(dir, nil); err == nil {
		t.Fatal("证书写不进去却报成功")
	}
}

// 私钥写不进去时,已经落盘的证书必须被删掉:剩一个 cert.pem 会让下次启动
// 撞上「半残目录」而拒绝起服务,管理员却看不出是哪一步失败的。
func TestGenerateSelfSignedCert_KeyWriteFailureRemovesTheCert(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, certFileName)
	keyPath := filepath.Join(dir, keyFileName)
	if err := os.Mkdir(keyPath, 0o700); err != nil {
		t.Fatalf("造占位目录: %v", err)
	}

	if err := generateSelfSignedCert(certPath, keyPath, []string{"localhost"}); err == nil {
		t.Fatal("私钥写不进去却报成功")
	}
	if fileExists(certPath) {
		t.Fatal("私钥失败了却把证书留在盘上")
	}
}

// SAN 里的空白项必须被丢掉:空 DNS 名会让一部分客户端直接判整张证书非法。
func TestCollectSANs_DropsBlanksAndDedupes(t *testing.T) {
	got := collectSANs([]string{"", "   ", "admin.example.com", "admin.example.com", " 10.0.0.1 "})
	seen := map[string]int{}
	for _, s := range got {
		if s == "" {
			t.Fatal("SAN 里混进了空串")
		}
		seen[s]++
	}
	for s, n := range seen {
		if n > 1 {
			t.Fatalf("SAN %q 重复了 %d 次", s, n)
		}
	}
	for _, want := range []string{"localhost", "127.0.0.1", "::1", "admin.example.com", "10.0.0.1"} {
		if seen[want] == 0 {
			t.Errorf("SAN 里缺 %q(实际 %v)", want, got)
		}
	}
}
