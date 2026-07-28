package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// VerifyPSKLimited 存在的唯一理由是给 argon2 加一个全进程的并发天花板:每次 verify
// 要 ~64MB,web 后台的恢复码路径一次最多验 10 条,不封顶就能把宿主内存打爆。
// 它同时还要把「排不上队」和「密码错」分成两种结果 —— 混在一起的话,打满信号量
// 就能把合法管理员刷进账号锁定。

func mustHash(t *testing.T, plaintext string) string {
	t.Helper()
	h, err := HashPSK(plaintext)
	if err != nil {
		t.Fatalf("HashPSK: %v", err)
	}
	return h
}

func TestVerifyPSKLimited_BehavesLikeVerifyPSKWhenThereIsCapacity(t *testing.T) {
	enc := mustHash(t, "correct horse")

	ok, err := VerifyPSKLimited(t.Context(), "correct horse", enc)
	if err != nil || !ok {
		t.Fatalf("正确口令应通过,got (%v,%v)", ok, err)
	}

	ok, err = VerifyPSKLimited(t.Context(), "wrong horse", enc)
	if err != nil {
		t.Fatalf("密码错不是 error,是 (false,nil): %v", err)
	}
	if ok {
		t.Fatal("错口令通过了")
	}

	// 存储的 hash 畸形是 error,调用方要能跟「密码错」分开处理(前者该告警,后者只是日常)。
	if _, err := VerifyPSKLimited(t.Context(), "x", "这不是 PHC 串"); err == nil {
		t.Fatal("畸形 encoding 应返回 error")
	}
}

// 排不上队时必须是 ErrVerifyUnavailable,而不是「验证失败」。
func TestVerifyPSKLimited_QueueTimeoutIsNotAFailedPassword(t *testing.T) {
	enc := mustHash(t, "pw")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ok, err := VerifyPSKLimited(ctx, "pw", enc)
	if ok {
		t.Fatal("ctx 已取消,不该报验证通过")
	}
	if !errors.Is(err, ErrVerifyUnavailable) {
		t.Fatalf("err=%v —— 必须是 ErrVerifyUnavailable,否则打满信号量就能把管理员刷进锁定", err)
	}
	if !strings.Contains(err.Error(), "argon2") {
		t.Fatalf("错误里应说明是 argon2 容量/ctx 的问题: %v", err)
	}

	t.Run("超时同理", func(t *testing.T) {
		tctx, tcancel := context.WithTimeout(context.Background(), time.Nanosecond)
		defer tcancel()
		time.Sleep(time.Millisecond)
		if _, err := VerifyPSKLimited(tctx, "pw", enc); !errors.Is(err, ErrVerifyUnavailable) {
			t.Fatalf("err=%v", err)
		}
	})
}

// 存储 hash 畸形时 DecodePSK 在跑 argon2 **之前**就返回,响应明显偏快 ——
// 攻击者据此能问出「这个账号的 hash 坏了」。decoy 就是补上这段耗时。
func TestVerifyPSKLimitedOrDecoy_BurnsEquivalentTimeWhenTheStoredHashIsGarbage(t *testing.T) {
	good := mustHash(t, "pw")
	decoy := mustHash(t, "decoy-plaintext")

	t.Run("正常 hash 走真实 verify", func(t *testing.T) {
		ok, err := VerifyPSKLimitedOrDecoy(t.Context(), "pw", good, decoy)
		if err != nil || !ok {
			t.Fatalf("got (%v,%v)", ok, err)
		}
		ok, err = VerifyPSKLimitedOrDecoy(t.Context(), "nope", good, decoy)
		if err != nil || ok {
			t.Fatalf("错口令应是 (false,nil),got (%v,%v)", ok, err)
		}
	})

	t.Run("畸形 hash 报错但耗时跟正常路径同量级", func(t *testing.T) {
		start := time.Now()
		ok, err := VerifyPSKLimitedOrDecoy(t.Context(), "pw", "损坏的$hash", decoy)
		badDur := time.Since(start)
		if ok {
			t.Fatal("畸形 hash 不该报通过")
		}
		if err == nil {
			t.Fatal("畸形 hash 要返回 error,调用方据此告警")
		}

		start = time.Now()
		_, _ = VerifyPSKLimitedOrDecoy(t.Context(), "nope", good, decoy)
		normalDur := time.Since(start)

		// 只要 decoy 真跑了,两条路径都各跑一次 argon2,数量级就对得上。
		// 阈值放宽到 1/4,避免 CI 抖动误报;真漏跑 decoy 的话差距是几百倍。
		if badDur < normalDur/4 {
			t.Fatalf("畸形路径 %v vs 正常路径 %v —— 快这么多说明 decoy 没跑,时序泄漏「此账号 hash 异常」",
				badDur, normalDur)
		}
	})

	t.Run("排不上队时不跑 decoy 直接报不可用", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		start := time.Now()
		ok, err := VerifyPSKLimitedOrDecoy(ctx, "pw", "损坏的$hash", decoy)
		if ok {
			t.Fatal("不该报通过")
		}
		if !errors.Is(err, ErrVerifyUnavailable) {
			t.Fatalf("err=%v", err)
		}
		// 整体已经超时了,时序本身没有意义,再烧一次 argon2 只是浪费。
		if d := time.Since(start); d > time.Second {
			t.Fatalf("Acquire 失败时还是跑了 argon2(耗时 %v)", d)
		}
	})

	t.Run("decoy 本身也畸形不会崩", func(t *testing.T) {
		if _, err := VerifyPSKLimitedOrDecoy(t.Context(), "pw", "坏的", "也是坏的"); err == nil {
			t.Fatal("应返回真实 verify 的 error")
		}
	})
}
