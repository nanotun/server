package main

import (
	"fmt"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// newPoWTestLimiter 造一个与生产同参的桶,供直接塞表的用例用。
func newPoWTestLimiter() *rate.Limiter {
	return rate.NewLimiter(powIPRLRate, powIPRLBurst)
}

// PoW 出题限速表本身是一个内存表,而它的键来自**未认证的**对端地址。
//
// 所以这张表有两种反向的失效方式:限得太松 —— 单 IP 可以无限灌出题请求,把 ip_failures 列表
// 撑爆(那张表比出题贵得多);限得太死 —— 表满之后新 IP 一律拒,而真正的攻击者早就在表里了,
// 被拒的全是后来的正常用户。代码的选择是「表满先清陈旧项,清完还满才拒」,这个顺序必须在。

// TestPoWLimiter_LimitsPerIPWithoutStarvingOthers 一个 IP 超频不该牵连别人。
func TestPoWLimiter_LimitsPerIPWithoutStarvingOthers(t *testing.T) {
	l := &powIPLimiter{limits: make(map[string]*powIPEntry)}

	// burst 之内连着来都放行,超出即拒。
	for i := 0; i < powIPRLBurst; i++ {
		if ok, _ := l.AllowChallenge("203.0.113.7:5000"); !ok {
			t.Fatalf("第 %d 次就被拒了,burst 是 %d —— NAT 后多设备同时登录会被误伤", i+1, powIPRLBurst)
		}
	}
	if ok, _ := l.AllowChallenge("203.0.113.7:5001"); ok {
		t.Error("超出 burst 仍放行 —— 单 IP 可以无限灌出题请求")
	}
	// 同一 IP 的不同源端口算同一个主体(否则攻击者换端口就绕过)。
	if _, host := l.AllowChallenge("203.0.113.7:65000"); host != "203.0.113.7" {
		t.Errorf("host = %q,应按 IP 归并而不是按 IP:port", host)
	}
	// 邻居不受影响。
	if ok, _ := l.AllowChallenge("198.51.100.9:5000"); !ok {
		t.Error("另一个 IP 被牵连拒了 —— 一台超频的机器不该拖垮同网段其他用户")
	}
	// 取不出端口的地址(裸 IP / unix pipe)也要能当键用,不能因为解析失败就整条放行或整条拒。
	if ok, host := l.AllowChallenge("pipe"); !ok || host != "pipe" {
		t.Errorf("裸地址应原样当键用, ok=%v host=%q", ok, host)
	}
}

// TestPoWLimiter_SweepsStaleEntriesBeforeRefusingNewIPs 表满时先清陈旧项再说。
//
// 这张表的键是未认证的对端 IP,一次扫段就能塞满。若「满了就拒新 IP」,攻击者只要把表填满,
// 之后所有**新**用户都进不来 —— 而他自己已经在表里,照常出题。所以必须先清掉不活跃的条目;
// 清完仍满才是真的容量到顶,那时拒新 IP 是唯一选择(否则内存无上限)。
func TestPoWLimiter_SweepsStaleEntriesBeforeRefusingNewIPs(t *testing.T) {
	l := &powIPLimiter{limits: make(map[string]*powIPEntry)}

	// 填满,且全部标成「很久没见过」。
	stale := time.Now().Add(-2 * powIPRLGCTTL)
	for i := 0; i < powIPRLMaxEntries; i++ {
		l.limits[fmt.Sprintf("10.%d.%d.%d", i/65536%256, i/256%256, i%256)] = &powIPEntry{
			lim:      newPoWTestLimiter(),
			lastSeen: stale,
		}
	}
	if got := l.CountForTest(); got != powIPRLMaxEntries {
		t.Fatalf("准备阶段表里 %d 条, want %d", got, powIPRLMaxEntries)
	}

	if ok, _ := l.AllowChallenge("203.0.113.200:5000"); !ok {
		t.Fatal("表满但全是陈旧项时拒了新 IP —— 攻击者填满表就能把所有后来的用户挡在门外")
	}
	if got := l.CountForTest(); got >= powIPRLMaxEntries {
		t.Errorf("清完仍有 %d 条 —— 陈旧项没被回收,表会一直卡在容量上", got)
	}

	// 反向:全是活跃项时,容量到顶就必须拒(内存无上限比拒新 IP 更糟)。
	l2 := &powIPLimiter{limits: make(map[string]*powIPEntry)}
	fresh := time.Now()
	for i := 0; i < powIPRLMaxEntries; i++ {
		l2.limits[fmt.Sprintf("172.%d.%d.%d", i/65536%256, i/256%256, i%256)] = &powIPEntry{
			lim:      newPoWTestLimiter(),
			lastSeen: fresh,
		}
	}
	if ok, _ := l2.AllowChallenge("203.0.113.201:5000"); ok {
		t.Error("表全是活跃项、已到容量上限,仍收新 IP —— 这张表的内存就没有上界了")
	}
	if l2.capExceeded == 0 {
		t.Error("拒了却没记 capExceeded —— 这个数是判断『是否遭遇扫段』的唯一信号")
	}
}
