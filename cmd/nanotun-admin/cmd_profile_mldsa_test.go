package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// mldsa65PubKeyBytes 是 ML-DSA-65 公钥的固定长度,用来锚定「导出的确实是一把完整公钥」。
const mldsa65PubKeyBytes = 1952

// writeFixtureConfigWithPQ 写一份启用 ML-DSA-65 叶证书扩展的 reality 配置。
// seedB64 为空则不写该字段(对照组)。
func writeFixtureConfigWithPQ(t *testing.T, dir, name, seedB64 string) string {
	t.Helper()
	seedLine := ""
	if seedB64 != "" {
		seedLine = "mldsa65_seed_base64 = \"" + seedB64 + "\"\n"
	}
	body := `
[server]
listen_addr = ":8080"

[reality]
listen_addr = ":8443"
dest = "www.microsoft.com:443"
private_key = "` + realityPrivateKeyB64 + `"
server_names = ["www.microsoft.com"]
short_ids = ["abcd1234"]
` + seedLine
	path := filepath.Join(dir, "config-"+name+".toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// testMldsaSeed 返回一个非平凡的 32 字节 seed 及其 Base64。
func testMldsaSeed() ([32]byte, string) {
	var seed [32]byte
	copy(seed[:], bytes.Repeat([]byte{0x2a}, 32))
	return seed, base64.StdEncoding.EncodeToString(seed[:])
}

// TestProfileShow_ExportsMldsa65VerifyWhenPQEnabled 守住 PQ 验签的下发链路。
//
// 服务端配了 mldsa65_seed_base64 就会用 seed 派生的私钥去签 REALITY 叶证书扩展,
// 客户端要用**对应公钥**(profile 的 mldsa65_verify)才能验。这把公钥由机密 seed
// 派生,除 profile 外没有别的下发通道 —— 一旦不导出,rust_reality 拿到空值会直接
// 跳过扩展校验:服务端签了、客户端不验,抗量子那层白开,且两边都不报错。
// 这是最难自己发现的一类缺陷,所以这里不只断言「非空」,还要求它精确等于 seed 派生值。
func TestProfileShow_ExportsMldsa65VerifyWhenPQEnabled(t *testing.T) {
	dir := t.TempDir()
	seed, seedB64 := testMldsaSeed()
	cfg := writeFixtureConfigWithPQ(t, dir, "pq", seedB64)
	db := filepath.Join(dir, "pq.db")
	if c, _, e := runCLI(t, db, "", "user", "create", "pquser", "--psk", "p"); c != 0 {
		t.Fatalf("create pquser: %s", e)
	}
	c, stdout, stderr := runCLI(t, db, "",
		"profile", "show", "pquser", "--host", "exit.example.com", "--config", cfg)
	if c != 0 {
		t.Fatalf("profile show: code=%d stderr=%s", c, stderr)
	}
	p := parseProfileJSON(t, stdout)
	if p.Reality == nil {
		t.Fatal("profile 缺 reality 段")
	}
	got := p.Reality.Mldsa65Verify
	if got == "" {
		t.Fatal("配了 mldsa65_seed_base64 却没导出 mldsa65_verify:" +
			"客户端会静默跳过 PQ 验签")
	}

	vk, _ := mldsa65.NewKeyFromSeed(&seed)
	if want := base64.StdEncoding.EncodeToString(vk.Bytes()); got != want {
		t.Fatalf("mldsa65_verify 不是该 seed 派生的公钥\n got=%.40s...\nwant=%.40s...", got, want)
	}
	raw, err := base64.StdEncoding.DecodeString(got)
	if err != nil {
		t.Fatalf("mldsa65_verify 不是合法 Base64: %v", err)
	}
	if len(raw) != mldsa65PubKeyBytes {
		t.Fatalf("公钥长度 %d, 期望 %d", len(raw), mldsa65PubKeyBytes)
	}
}

// TestProfileShow_OmitsMldsa65VerifyWhenPQDisabled 对照组:没配 seed 就不该凭空多出
// 2.6 KB 的字段 —— 它会白白吃掉二维码预算。
func TestProfileShow_OmitsMldsa65VerifyWhenPQDisabled(t *testing.T) {
	dir := t.TempDir()
	cfg := writeFixtureConfigWithPQ(t, dir, "nopq", "")
	db := filepath.Join(dir, "nopq.db")
	if c, _, e := runCLI(t, db, "", "user", "create", "plainuser", "--psk", "p"); c != 0 {
		t.Fatalf("create plainuser: %s", e)
	}
	c, stdout, stderr := runCLI(t, db, "",
		"profile", "show", "plainuser", "--host", "exit.example.com", "--config", cfg)
	if c != 0 {
		t.Fatalf("profile show: code=%d stderr=%s", c, stderr)
	}
	if strings.Contains(stdout, "mldsa65_verify") {
		t.Fatalf("未配 seed 不应出现 mldsa65_verify:\n%s", stdout)
	}
	p := parseProfileJSON(t, stdout)
	if p.Reality != nil && p.Reality.Mldsa65Verify != "" {
		t.Fatalf("mldsa65_verify 应为空, 实际 %q", p.Reality.Mldsa65Verify)
	}
}

// TestProfileQRCapacity_PQProfileNoLongerFitsQR 把「开 PQ 就用不了二维码」这个取舍
// 钉成显式事实,而不是让管理员扫码失败才发现。
//
// 公钥固定 1952 字节,Base64 后 2604 字符,经 profile URL 的 base64url 再放大 4/3,
// 单入口 profile 会从约 2 KB 涨到约 5.5 KB —— 远超 qrLowMaxURLBytes。开 PQ 的部署
// 只能走文件/复制粘贴分发,与多入口同类取舍。
func TestProfileQRCapacity_PQProfileNoLongerFitsQR(t *testing.T) {
	dir := t.TempDir()
	_, seedB64 := testMldsaSeed()
	db := filepath.Join(dir, "pqqr.db")
	if c, _, e := runCLI(t, db, "", "user", "create", "pqqr", "--psk", "p"); c != 0 {
		t.Fatalf("create pqqr: %s", e)
	}
	show := func(cfg string) int {
		c, stdout, stderr := runCLI(t, db, "",
			"profile", "show", "pqqr", "--host", "exit.example.com", "--config", cfg)
		if c != 0 {
			t.Fatalf("profile show: code=%d stderr=%s", c, stderr)
		}
		p := parseProfileJSON(t, stdout)
		url, err := profileToURL(&p)
		if err != nil {
			t.Fatalf("profileToURL: %v", err)
		}
		return len(url)
	}
	plain := show(writeFixtureConfigWithPQ(t, dir, "qr-nopq", ""))
	pq := show(writeFixtureConfigWithPQ(t, dir, "qr-pq", seedB64))
	t.Logf("PQ 开销: %d 字节 (无 PQ %d → 有 PQ %d), 二维码上限 %d",
		pq-plain, plain, pq, qrLowMaxURLBytes)

	if plain > qrLowMaxURLBytes {
		t.Fatalf("不开 PQ 的单入口 profile 就已经超二维码上限(%d > %d)", plain, qrLowMaxURLBytes)
	}
	if pq <= qrLowMaxURLBytes {
		t.Fatalf("开 PQ 后 profile 仅 %d 字节仍能进二维码(上限 %d)——"+
			"公钥编码方式可能变了, 本测试与相关文档需要更新", pq, qrLowMaxURLBytes)
	}
}
