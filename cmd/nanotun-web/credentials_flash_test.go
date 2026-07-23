package main

// credentials_flash_test.go(2026-05-26 / P2#5):
//
// 覆盖 credentials_flash.go 的核心 PRG 语义 — 这套机制是「user create / reset-psk
// 路径下 PSK 仅展示一次」承诺的根基。直接对 credentialsFlashStore 跑单测就够了:
// 把全套 HTTP / CSRF / session middleware 装进单测会 4-5 倍代码量,而我们要测的
// 行为(stash → 一次性 pop → 第二次拿不到 → kind mismatch reject → 过期清理)
// 与 HTTP 层无关,提到 unit 层最稳。
//
// 实际 handler 测试由 TestResetPSK_PRGToken 风格的 HTTP 层覆盖留待未来,
// 与「需要构造完整 admin session」绑定;本文件先 lock 住数据结构契约。

import (
	"testing"
	"time"
)

func newTestCredFlash(t *testing.T) (*credentialsFlashStore, chan struct{}) {
	t.Helper()
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	return newCredentialsFlashStore(stop), stop
}

func TestCredFlash_StashPop_Roundtrip(t *testing.T) {
	s, _ := newTestCredFlash(t)
	in := credentialsFlashPayload{
		Kind:        credentialsFlashKindUserCreated,
		UserID:      42,
		Username:    "alice",
		PSK:         "alpha-bravo",
		CredID:      "0d4b1c4e-3a2f-4f7e-9c8d-12345678abcd",
		CredCreated: "2026-05-26 12:00:00",
		CredURL:     "nanotun-cred://v1?d=stub",
		CredQRImage: "data:image/png;base64,stub",
	}
	tok, err := s.Stash(in, 100)
	if err != nil {
		t.Fatalf("Stash: %v", err)
	}
	if tok == "" {
		t.Fatalf("token 不应为空")
	}
	if s.Len() != 1 {
		t.Fatalf("Len=%d want 1", s.Len())
	}
	out, err := s.Pop(tok, credentialsFlashKindUserCreated, 100)
	if err != nil {
		t.Fatalf("Pop: %v", err)
	}
	if out != in {
		t.Fatalf("payload 漂移:got=%+v want=%+v", out, in)
	}
	if s.Len() != 0 {
		t.Fatalf("Pop 后 Len 仍 %d,one-shot 失效", s.Len())
	}
}

func TestCredFlash_OneShot(t *testing.T) {
	s, _ := newTestCredFlash(t)
	tok, err := s.Stash(credentialsFlashPayload{
		Kind:   credentialsFlashKindUserResetPSK,
		UserID: 7,
	}, 100)
	if err != nil {
		t.Fatalf("Stash: %v", err)
	}
	if _, err := s.Pop(tok, credentialsFlashKindUserResetPSK, 100); err != nil {
		t.Fatalf("first Pop: %v", err)
	}
	// 第二次 Pop 必须 missing(一次性消费)。这是「刷新页面就再也看不到 PSK」
	// 承诺的关键 — 凭证不能在 admin 浏览器后退 / 刷新时反复出现。
	if _, err := s.Pop(tok, credentialsFlashKindUserResetPSK, 100); err != errCredentialsFlashMissing {
		t.Fatalf("第二次 Pop 应 missing,got %v", err)
	}
}

// TestCredFlash_AdminBinding 锁定 d_flash_bind:token 只能被创建它的 admin 取出。
func TestCredFlash_AdminBinding(t *testing.T) {
	s, _ := newTestCredFlash(t)
	tok, err := s.Stash(credentialsFlashPayload{Kind: credentialsFlashKindUserCreated, UserID: 3}, 100)
	if err != nil {
		t.Fatalf("Stash: %v", err)
	}
	// 另一个 admin(id=200)拿同一 token → missing,且 entry 被消费(阻断继续试探)。
	if _, err := s.Pop(tok, credentialsFlashKindUserCreated, 200); err != errCredentialsFlashMissing {
		t.Fatalf("跨 admin Pop 应 missing,got %v", err)
	}
	if s.Len() != 0 {
		t.Fatalf("跨 admin Pop 应立即消费 entry,Len=%d", s.Len())
	}
	// 原始 admin 再取也拿不到(已被上一步删除)——符合「试一次即废」。
	if _, err := s.Pop(tok, credentialsFlashKindUserCreated, 100); err != errCredentialsFlashMissing {
		t.Fatalf("被跨 admin 触碰后原 admin 再取也应 missing,got %v", err)
	}
}

func TestCredFlash_KindMismatchRejected(t *testing.T) {
	s, _ := newTestCredFlash(t)
	tok, _ := s.Stash(credentialsFlashPayload{Kind: credentialsFlashKindUserCreated, UserID: 1}, 100)
	// 用错 kind 取 token —— 譬如把 user_created 的 token 拼到 reset-psk-result
	// URL 上。**第三轮深扫 P2 收紧**:每个 POST handler 写入时 kind 固定,
	// redirect URL 与 GET path 一对一,kind 不匹配 = referrer 泄漏后的枚举攻击,
	// store 必须 reject **且立刻删 entry**,后续合法 kind 也再取不到(等同已消费)。
	if _, err := s.Pop(tok, credentialsFlashKindUserResetPSK, 100); err != errCredentialsFlashMissing {
		t.Fatalf("kind 错配应 missing,got %v", err)
	}
	if s.Len() != 0 {
		t.Fatalf("kind 错配应立即消费 entry(安全收紧),Len=%d", s.Len())
	}
	if _, err := s.Pop(tok, credentialsFlashKindUserCreated, 100); err != errCredentialsFlashMissing {
		t.Fatalf("kind 错配后正确 kind 再取也应 missing,got %v", err)
	}
}

func TestCredFlash_EmptyTokenMissing(t *testing.T) {
	s, _ := newTestCredFlash(t)
	if _, err := s.Pop("", credentialsFlashKindUserCreated, 100); err != errCredentialsFlashMissing {
		t.Fatalf("空 token 应 missing,got %v", err)
	}
}

func TestCredFlash_ExpiredEntryPruned(t *testing.T) {
	s, _ := newTestCredFlash(t)
	tok, err := s.Stash(credentialsFlashPayload{Kind: credentialsFlashKindUserCreated, UserID: 5}, 100)
	if err != nil {
		t.Fatalf("Stash: %v", err)
	}
	// 把内部 entry expires 改成「已过期」;直接 Pop 应当 missing。
	s.mu.Lock()
	entry := s.entries[tok]
	entry.expires = time.Now().Add(-time.Minute)
	s.entries[tok] = entry
	s.mu.Unlock()

	if _, err := s.Pop(tok, credentialsFlashKindUserCreated, 100); err != errCredentialsFlashMissing {
		t.Fatalf("过期 token 应 missing,got %v", err)
	}
	if s.Len() != 0 {
		t.Fatalf("过期 Pop 应顺手 prune,Len=%d", s.Len())
	}
}

func TestCredFlash_GCPrunesExpired(t *testing.T) {
	s, _ := newTestCredFlash(t)
	tok, _ := s.Stash(credentialsFlashPayload{Kind: credentialsFlashKindUserCreated, UserID: 9}, 100)
	s.mu.Lock()
	entry := s.entries[tok]
	entry.expires = time.Now().Add(-2 * time.Minute)
	s.entries[tok] = entry
	s.mu.Unlock()
	// 直接调 prune,不等 ticker。
	s.prune(time.Now())
	if s.Len() != 0 {
		t.Fatalf("prune 应清掉过期 entry,Len=%d", s.Len())
	}
}
