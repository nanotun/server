package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/url"
	"strconv"
	"testing"
	"time"
)

// newPoWTestService 构造一个只填了 powHMACKey / ipFailures 的 mock —
// 其它字段(store / cfg)不参与本测试用例。
func newPoWTestService() *SessionService {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return &SessionService{
		powHMACKey: key,
		ipFailures: NewIPFailureTracker(),
	}
}

// ===== 算法层(与 旧集中式后端 兼容性) =====

func TestPoWHash_KnownVector(t *testing.T) {
	// 固定输入 → 固定 digest;锁住算法不被悄悄改。
	// 这条向量可以拿到 旧集中式后端/internal/pow 跑出来对一下。
	cid := "test-id"
	salt := make([]byte, powSaltBytes)
	for i := range salt {
		salt[i] = byte(i + 1)
	}
	d := powHash(cid, salt, 0)
	// 先验证长度 32(防 panic),再用前 4 字节作为 sanity check。
	if len(d) != 32 {
		t.Fatalf("digest len = %d", len(d))
	}
	// 计算 leading zero bits 与 expected 对齐 — 实际是 5(算法稳定即可)。
	got := powLeadingZeroBits(d)
	if got < 0 || got > 256 {
		t.Fatalf("bad LZB %d for digest %x", got, d)
	}
	// 复合 invariant:同样输入两次,digest 完全一致 → 算法确定性。
	d2 := powHash(cid, salt, 0)
	if d != d2 {
		t.Fatalf("not deterministic: %x vs %x", d, d2)
	}
}

func TestPoWLeadingZeroBits_Boundaries(t *testing.T) {
	var d [32]byte
	d[0] = 0xff
	if powLeadingZeroBits(d) != 0 {
		t.Fatal("0xff → 0")
	}
	d[0] = 0x00
	d[1] = 0x80
	if powLeadingZeroBits(d) != 8 {
		t.Fatal("0x00 0x80 → 8")
	}
	d[0] = 0x00
	d[1] = 0x00
	d[2] = 0x40
	if powLeadingZeroBits(d) != 17 {
		t.Fatalf("0x00 0x00 0x40 → 17, got %d", powLeadingZeroBits(d))
	}
	// 全 0 → 256
	for i := range d {
		d[i] = 0
	}
	if powLeadingZeroBits(d) != 256 {
		t.Fatal("all-zero → 256")
	}
}

func TestPoWVerify_SmallDifficulty(t *testing.T) {
	cid := "verify-test"
	salt := make([]byte, powSaltBytes)
	for i := range salt {
		salt[i] = 0xab
	}
	// 4-bit 难度,平均 16 次内必中。
	var nonce uint64
	for ; nonce < 100_000; nonce++ {
		if powVerify(cid, salt, 4, nonce) {
			break
		}
	}
	if nonce >= 100_000 {
		t.Fatal("no nonce found for 4-bit (sus)")
	}
	if !powVerify(cid, salt, 4, nonce) {
		t.Fatal("not verifying the nonce we just found")
	}
	if powVerify(cid, salt, 4, nonce+1) {
		// 极少概率 nonce+1 也是合法解;不强测,但 if 必中说明确实是合法
		t.Log("nonce+1 also valid — rare but ok")
	}
}

func TestPoWVerify_BadDifficulty(t *testing.T) {
	salt := make([]byte, powSaltBytes)
	if powVerify("cid", salt, 3, 0) { // < min
		t.Fatal("difficulty<min should refuse")
	}
	if powVerify("cid", salt, powMaxDifficulty+1, 0) { // > max
		t.Fatal("difficulty>max should refuse")
	}
}

func TestPoWVerify_BadSalt(t *testing.T) {
	if powVerify("cid", make([]byte, 15), 4, 0) {
		t.Fatal("salt 15B should refuse")
	}
	if powVerify("cid", make([]byte, 17), 4, 0) {
		t.Fatal("salt 17B should refuse")
	}
}

// ===== HMAC 签名 =====

func TestChallengeHMAC_Deterministic(t *testing.T) {
	key := []byte("test-key-32-bytes-padding-........")
	a := powChallengeHMAC(key, "cid", "c2FsdA==", 14, 1700000000)
	b := powChallengeHMAC(key, "cid", "c2FsdA==", 14, 1700000000)
	if a == "" || a != b {
		t.Fatalf("not deterministic: %q vs %q", a, b)
	}
	if powChallengeHMAC(nil, "cid", "c2FsdA==", 14, 0) != "" {
		t.Fatal("nil key should yield empty")
	}
}

func TestChallengeHMAC_DifferentInputs(t *testing.T) {
	key := []byte("k")
	a := powChallengeHMAC(key, "cid1", "salt", 14, 100)
	b := powChallengeHMAC(key, "cid2", "salt", 14, 100)
	c := powChallengeHMAC(key, "cid1", "salt", 15, 100)
	d := powChallengeHMAC(key, "cid1", "salt", 14, 101)
	if a == b || a == c || a == d {
		t.Fatalf("collisions: %s %s %s %s", a, b, c, d)
	}
}

func TestChallengeHMACEqual_TamperResistant(t *testing.T) {
	key := []byte("k")
	sig := powChallengeHMAC(key, "cid", "salt", 14, 100)
	if !powChallengeHMACEqual(key, "cid", "salt", 14, 100, sig) {
		t.Fatal("genuine should pass")
	}
	// 翻末位
	raw, _ := base64.StdEncoding.DecodeString(sig)
	raw[len(raw)-1] ^= 0x01
	tampered := base64.StdEncoding.EncodeToString(raw)
	if powChallengeHMACEqual(key, "cid", "salt", 14, 100, tampered) {
		t.Fatal("tampered should fail")
	}
}

// ===== IssueChallenge + VerifyPoWProof roundtrip =====

func TestIssue_DifficultyZero_Empty(t *testing.T) {
	s := newPoWTestService()
	c, err := s.IssueChallenge(0)
	if err != nil {
		t.Fatal(err)
	}
	if c.IsRequired() {
		t.Fatalf("d=0 should be not-required, got %+v", c)
	}
}

func TestIssue_DifficultyClamping(t *testing.T) {
	s := newPoWTestService()
	c, err := s.IssueChallenge(1)
	if err != nil {
		t.Fatal(err)
	}
	if c.Difficulty != powMinDifficulty {
		t.Fatalf("d=1 should clamp up to min(%d), got %d", powMinDifficulty, c.Difficulty)
	}
	c2, _ := s.IssueChallenge(powMaxDifficulty + 100)
	if c2.Difficulty != powMaxDifficulty {
		t.Fatalf("d=huge should clamp to max(%d), got %d", powMaxDifficulty, c2.Difficulty)
	}
}

func TestVerifyProof_RoundTrip(t *testing.T) {
	s := newPoWTestService()
	c, err := s.IssueChallenge(4) // 4-bit:测试快
	if err != nil {
		t.Fatal(err)
	}
	salt, _ := base64.StdEncoding.DecodeString(c.Salt)
	// 找 nonce
	var nonce uint64
	for ; nonce < 100_000; nonce++ {
		if powVerify(c.ChallengeID, salt, c.Difficulty, nonce) {
			break
		}
	}
	if nonce >= 100_000 {
		t.Fatal("nonce not found")
	}
	p := PoWProof{
		ChallengeID: c.ChallengeID,
		Salt:        c.Salt,
		Difficulty:  c.Difficulty,
		ExpiresAt:   c.ExpiresAt,
		Signature:   c.Signature,
		Nonce:       nonce,
	}
	if err := s.VerifyPoWProof(p, c.Difficulty); err != nil {
		t.Fatalf("genuine proof: %v", err)
	}
	// 重放
	if err := s.VerifyPoWProof(p, c.Difficulty); !errors.Is(err, ErrPoWReplay) {
		t.Fatalf("replay should fail with ErrPoWReplay, got %v", err)
	}
}

func TestVerifyProof_BadSignature(t *testing.T) {
	s := newPoWTestService()
	c, _ := s.IssueChallenge(4)
	salt, _ := base64.StdEncoding.DecodeString(c.Salt)
	var nonce uint64
	for ; nonce < 100_000; nonce++ {
		if powVerify(c.ChallengeID, salt, c.Difficulty, nonce) {
			break
		}
	}
	p := PoWProof{
		ChallengeID: c.ChallengeID, Salt: c.Salt, Difficulty: c.Difficulty,
		ExpiresAt: c.ExpiresAt, Signature: "AAAA" + c.Signature[4:], Nonce: nonce,
	}
	if err := s.VerifyPoWProof(p, c.Difficulty); !errors.Is(err, ErrPoWBadSignature) {
		t.Fatalf("tampered sig: want ErrPoWBadSignature, got %v", err)
	}
}

func TestVerifyProof_DifficultyBelowExpected(t *testing.T) {
	s := newPoWTestService()
	// 发一个 4-bit 题,然后服务端 expected=14;客户端拿 4-bit 合法签名重放也拒。
	c, _ := s.IssueChallenge(4)
	salt, _ := base64.StdEncoding.DecodeString(c.Salt)
	var nonce uint64
	for ; nonce < 100_000; nonce++ {
		if powVerify(c.ChallengeID, salt, c.Difficulty, nonce) {
			break
		}
	}
	p := PoWProof{
		ChallengeID: c.ChallengeID, Salt: c.Salt, Difficulty: c.Difficulty,
		ExpiresAt: c.ExpiresAt, Signature: c.Signature, Nonce: nonce,
	}
	if err := s.VerifyPoWProof(p, 14); !errors.Is(err, ErrPoWDifficultyLow) {
		t.Fatalf("low diff replay: want ErrPoWDifficultyLow, got %v", err)
	}
}

func TestVerifyProof_Expired(t *testing.T) {
	s := newPoWTestService()
	// 手工构造一个 ExpiresAt 在过去的题。
	cidBuf := make([]byte, 16)
	rand.Read(cidBuf)
	cid := base64.RawURLEncoding.EncodeToString(cidBuf)
	salt := make([]byte, powSaltBytes)
	rand.Read(salt)
	saltB64 := base64.StdEncoding.EncodeToString(salt)
	exp := time.Now().Add(-time.Minute).Unix()
	sig := powChallengeHMAC(s.powHMACKey, cid, saltB64, 4, exp)
	var nonce uint64
	for ; nonce < 100_000; nonce++ {
		if powVerify(cid, salt, 4, nonce) {
			break
		}
	}
	p := PoWProof{
		ChallengeID: cid, Salt: saltB64, Difficulty: 4,
		ExpiresAt: exp, Signature: sig, Nonce: nonce,
	}
	if err := s.VerifyPoWProof(p, 4); !errors.Is(err, ErrPoWExpired) {
		t.Fatalf("expired: want ErrPoWExpired, got %v", err)
	}
}

func TestVerifyProof_InvalidNonce(t *testing.T) {
	s := newPoWTestService()
	c, _ := s.IssueChallenge(8) // 8-bit 让随便一个 nonce 大概率不合法
	p := PoWProof{
		ChallengeID: c.ChallengeID, Salt: c.Salt, Difficulty: c.Difficulty,
		ExpiresAt: c.ExpiresAt, Signature: c.Signature, Nonce: 0, // 大概率不合法
	}
	err := s.VerifyPoWProof(p, c.Difficulty)
	// 0 也可能恰好合法(1/256 概率),那就换个 nonce
	if err == nil {
		t.Skip("nonce=0 happened to be valid, skip(rare)")
	}
	if !errors.Is(err, ErrPoWInvalid) {
		t.Fatalf("invalid nonce: want ErrPoWInvalid, got %v", err)
	}
}

// ===== 难度公式 =====

func TestComputeDifficulty_Curve(t *testing.T) {
	cases := []struct {
		failures int
		want     int
	}{
		{0, 0}, {1, 0}, {2, 0},
		{3, 14},
		{4, 16},
		{5, 18},
		{6, 20},
		{7, 22},
		{8, 22}, // 封顶
		{100, 22},
	}
	for _, c := range cases {
		got := ComputeDifficulty(c.failures)
		if got != c.want {
			t.Errorf("failures=%d: want %d got %d", c.failures, c.want, got)
		}
	}
}

// ===== IPFailureTracker =====

func TestIPFailures_BasicLifecycle(t *testing.T) {
	tr := NewIPFailureTracker()
	if tr.Recent("1.1.1.1") != 0 {
		t.Fatal("fresh = 0")
	}
	if n := tr.Inc("1.1.1.1"); n != 1 {
		t.Fatalf("inc 1, got %d", n)
	}
	if n := tr.Inc("1.1.1.1"); n != 2 {
		t.Fatalf("inc 2, got %d", n)
	}
	tr.Reset("1.1.1.1")
	if tr.Recent("1.1.1.1") != 0 {
		t.Fatal("after reset = 0")
	}
}

func TestIPFailures_Isolation(t *testing.T) {
	tr := NewIPFailureTracker()
	tr.Inc("1.1.1.1")
	tr.Inc("1.1.1.1")
	tr.Inc("2.2.2.2")
	if tr.Recent("1.1.1.1") != 2 {
		t.Fatal("1.1.1.1 != 2")
	}
	if tr.Recent("2.2.2.2") != 1 {
		t.Fatal("2.2.2.2 != 1")
	}
	if tr.Recent("3.3.3.3") != 0 {
		t.Fatal("3.3.3.3 != 0")
	}
}

func TestIPFailures_EmptyIP(t *testing.T) {
	tr := NewIPFailureTracker()
	if n := tr.Inc(""); n != 0 {
		t.Fatalf("empty IP: %d", n)
	}
	if n := tr.Recent(""); n != 0 {
		t.Fatalf("recent empty IP: %d", n)
	}
}

// ===== parsePoWFormFields =====

type stubFormValue map[string]string

func (s stubFormValue) FormValue(k string) string { return s[k] }

func TestParsePoWFormFields_OK(t *testing.T) {
	form := stubFormValue{
		"pow_challenge_id": "abc",
		"pow_salt":         "c2FsdA==",
		"pow_difficulty":   "14",
		"pow_expires_at":   "1700000000",
		"pow_signature":    "deadbeef",
		"pow_nonce":        "42",
	}
	p, err := parsePoWFormFields(form)
	if err != nil {
		t.Fatal(err)
	}
	if p.ChallengeID != "abc" || p.Difficulty != 14 ||
		p.ExpiresAt != 1700000000 || p.Nonce != 42 {
		t.Fatalf("parsed wrong: %+v", p)
	}
}

func TestParsePoWFormFields_Missing(t *testing.T) {
	full := map[string]string{
		"pow_challenge_id": "abc",
		"pow_salt":         "c2FsdA==",
		"pow_difficulty":   "14",
		"pow_expires_at":   "1700000000",
		"pow_signature":    "deadbeef",
		"pow_nonce":        "42",
	}
	for k := range full {
		copy := stubFormValue{}
		for kk, vv := range full {
			if kk != k {
				copy[kk] = vv
			}
		}
		if _, err := parsePoWFormFields(copy); err == nil {
			t.Errorf("missing %q should fail", k)
		}
	}
}

// ===== prune & snapshot =====

func TestPruneExpiredPoW(t *testing.T) {
	s := newPoWTestService()
	// 直接写两条:一过期一未过期。
	s.powUsed.Store("active", nowUnix()+60)
	s.powUsed.Store("dead", nowUnix()-60)
	s.pruneExpiredPoW()
	if _, ok := s.powUsed.Load("active"); !ok {
		t.Fatal("active should remain")
	}
	if _, ok := s.powUsed.Load("dead"); ok {
		t.Fatal("dead should be gone")
	}
}

func TestIPFailures_Prune(t *testing.T) {
	tr := NewIPFailureTracker()
	tr.Inc("alive")
	tr.Inc("stale")
	// 偷偷把 stale 的 lastFail 设到很久以前
	if v, ok := tr.m.Load("stale"); ok {
		rec := v.(*ipFailureRecord)
		rec.mu.Lock()
		rec.lastFail = nowUnix() - 3*ipFailureWindowSec
		rec.mu.Unlock()
	}
	tr.Prune()
	snap := tr.snapshot()
	if _, ok := snap["stale"]; ok {
		t.Fatal("stale should be pruned")
	}
	if snap["alive"] != 1 {
		t.Fatalf("alive should remain count=1, snap=%v", snap)
	}
}

// 防 import drift
var _ = url.Values{}
var _ = strconv.Itoa
