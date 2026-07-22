package auth

import (
	"encoding/base64"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nanotun/server/store"
)

func TestHashAndVerifyRoundTrip(t *testing.T) {
	encoded, err := HashPSK("super-secret")
	if err != nil {
		t.Fatalf("HashPSK: %v", err)
	}
	if !strings.HasPrefix(encoded, "argon2id$v=") {
		t.Fatalf("encoded prefix mismatch: %q", encoded)
	}

	ok, err := VerifyPSK("super-secret", encoded)
	if err != nil {
		t.Fatalf("VerifyPSK: %v", err)
	}
	if !ok {
		t.Fatalf("expected match for correct password")
	}

	ok, err = VerifyPSK("wrong", encoded)
	if err != nil {
		t.Fatalf("VerifyPSK wrong: %v", err)
	}
	if ok {
		t.Fatalf("expected mismatch for wrong password")
	}
}

func TestHashUniqueSalt(t *testing.T) {
	a, err := HashPSK("same-pass")
	if err != nil {
		t.Fatal(err)
	}
	b, err := HashPSK("same-pass")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatalf("two hashes of the same password should differ (random salt), got %q", a)
	}
}

func TestVerifyEmptyAndMalformed(t *testing.T) {
	if _, err := HashPSK(""); err == nil {
		t.Fatalf("HashPSK should reject empty string")
	}
	if _, err := VerifyPSK("x", "not-an-argon2-string"); err == nil {
		t.Fatalf("VerifyPSK should reject malformed encoding")
	}
}

// 防御「空 hash → ConstantTimeCompare(empty, empty)=1」verify bypass：DecodePSK
// 看到 hash/salt 太短就直接报错，任何 plaintext 都不应该返回 true。
func TestVerifyPSK_RejectsShortHashSalt(t *testing.T) {
	// 合法 hash 长度 32 字节(base64-encoded 43 chars) 才能通过；这里塞个空 hash。
	bad := []string{
		"argon2id$v=19$m=65536,t=2,p=4$" + // header
			"AAAAAAAAAAAAAAAAAAAAAA$" + // 16 字节合法盐
			"", // 空 hash
		"argon2id$v=19$m=65536,t=2,p=4$" +
			"AA$" + // 1 字节短盐
			"AAAAAAAAAAAAAAAAAAAAAA", // 16 字节 hash, OK
	}
	for i, enc := range bad {
		ok, err := VerifyPSK("any-pass", enc)
		if err == nil {
			t.Fatalf("case %d: expected error, got ok=%v", i, ok)
		}
		if ok {
			t.Fatalf("case %d: must NOT verify true on short hash/salt", i)
		}
	}
}

// 防御「m=4GB 让 verify OOM」：DecodePSK 拒绝畸高的 argon 参数。
func TestVerifyPSK_RejectsOversizedArgonParams(t *testing.T) {
	bad := []string{
		// m 太大：写 8 GiB
		"argon2id$v=19$m=8388608,t=2,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		// t 太大：1000 轮
		"argon2id$v=19$m=65536,t=1000,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		// p 太大：128 线程
		"argon2id$v=19$m=65536,t=2,p=128$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		// 整数回绕绕过尝试：m=2^32+65536，回绕到 uint32 后 == 65536（看似正常）——必须在转 uint32 前按 int 域拒掉。
		"argon2id$v=19$m=4295032832,t=2,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		// t=2^32+2，回绕到 uint32 后 == 2；p=256 回绕到 uint8 后 == 0（后者原本被 ==0 兜底，前者不会）。
		"argon2id$v=19$m=65536,t=4294967298,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		// p=257，回绕到 uint8 后 == 1（看似正常）——必须在转 uint8 前按 int 域拒掉。
		"argon2id$v=19$m=65536,t=2,p=257$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
	for i, enc := range bad {
		if _, err := VerifyPSK("any-pass", enc); err == nil {
			t.Fatalf("case %d: expected error for oversized argon params", i)
		}
	}
}

// 防御「超长 hash/salt 让 argon2 keyLen 巨大 → OOM」：DecodePSK / VerifyPSK 拒绝畸长的 hash/salt 段。
func TestVerifyPSK_RejectsOversizedHashSalt(t *testing.T) {
	bigB64 := base64.RawStdEncoding.EncodeToString(make([]byte, 4096)) // 远超 maxHashBytes/maxSaltBytes(1024)
	// 超长 hash 段(salt 合法)。
	encLongHash := "argon2id$v=19$m=65536,t=2,p=4$AAAAAAAAAAAAAAAAAAAAAA$" + bigB64
	if _, err := VerifyPSK("x", encLongHash); err == nil {
		t.Fatal("expected error for oversized hash")
	}
	// 超长 salt 段(hash 合法 32B)。
	encLongSalt := "argon2id$v=19$m=65536,t=2,p=4$" + bigB64 + "$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if _, err := VerifyPSK("x", encLongSalt); err == nil {
		t.Fatal("expected error for oversized salt")
	}
}

func TestVerifierVerifyLogin(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "psk.db")
	st, err := store.Open(ctx, path, store.Options{})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	hash, err := HashPSK("hello-world")
	if err != nil {
		t.Fatal(err)
	}
	u, err := st.CreateUser(ctx, store.NewUser{Username: "alice", PSKHash: hash})
	if err != nil {
		t.Fatal(err)
	}

	v := NewVerifier(st)

	got, err := v.VerifyLogin(ctx, "alice", "hello-world")
	if err != nil {
		t.Fatalf("VerifyLogin success path: %v", err)
	}
	if got.ID != u.ID {
		t.Fatalf("VerifyLogin returned id=%d want %d", got.ID, u.ID)
	}

	_, err = v.VerifyLogin(ctx, "alice", "wrong")
	if !errors.Is(err, ErrBadPSK) {
		t.Fatalf("wrong psk err = %v, want ErrBadPSK", err)
	}

	_, err = v.VerifyLogin(ctx, "ghost", "x")
	if !errors.Is(err, ErrUnknownUser) {
		t.Fatalf("unknown user err = %v, want ErrUnknownUser", err)
	}

	if err := st.DisableUser(ctx, u.ID); err != nil {
		t.Fatalf("DisableUser: %v", err)
	}
	_, err = v.VerifyLogin(ctx, "alice", "hello-world")
	if !errors.Is(err, ErrUserDisabled) {
		t.Fatalf("disabled user err = %v, want ErrUserDisabled", err)
	}
}

// 时序防护：用户名不存在 / 已禁用的两条分支应当跟「用户名存在但密码错」一样耗时，
// 不让 attacker 通过响应时间枚举用户名。
//
// 测试不卡死绝对阈值（CI 抖动太大），改成「decoy 分支耗时至少 >= 真实 verify 的一半」。
// 真实 verify 约 60ms (argon2id 64MB),decoy 分支应 >= 30ms,而朴素的 "user not found"
// 直接返回应该 < 1ms。差距足够明显,即便 CI 慢也能稳定区分。
func TestVerifyLogin_UnknownUserStillHashes(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "psk.db")
	st, err := store.Open(ctx, path, store.Options{})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	hash, _ := HashPSK("p")
	if _, err := st.CreateUser(ctx, store.NewUser{Username: "real", PSKHash: hash}); err != nil {
		t.Fatal(err)
	}
	v := NewVerifier(st)

	// 预热 decoyHash + sqlite 缓存,避免首次冷启动 IO 干扰测量。
	_, _ = v.VerifyLogin(ctx, "ghost", "anything")
	_, _ = v.VerifyLogin(ctx, "real", "wrong")

	measure := func(user, pass string) time.Duration {
		// 跑 3 次取中位数，去抖动。
		durs := make([]time.Duration, 3)
		for i := range durs {
			start := time.Now()
			_, _ = v.VerifyLogin(ctx, user, pass)
			durs[i] = time.Since(start)
		}
		if durs[0] > durs[1] {
			durs[0], durs[1] = durs[1], durs[0]
		}
		if durs[1] > durs[2] {
			durs[1], durs[2] = durs[2], durs[1]
		}
		if durs[0] > durs[1] {
			durs[0], durs[1] = durs[1], durs[0]
		}
		return durs[1]
	}
	realDur := measure("real", "wrong")
	ghostDur := measure("ghost", "anything")

	if ghostDur*2 < realDur {
		t.Fatalf("decoy path too fast (ghost=%v, real=%v) — username enumeration possible",
			ghostDur, realDur)
	}
}
