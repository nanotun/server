package main

import (
	"testing"
	"time"

	"github.com/xtaci/smux"
)

// 第二十五轮修的那条 MED 的回归测试:承载断了、但 smux 还没把会话标记为死的那半分钟窗口。
//
// smux 的死亡判定分两套:die(Close / keepalive 超时,IsClosed() 变 true)和 socket 读写错误
// (只记在 chSocketReadError/chSocketWriteError 上,**不动** die)。承载被掐断时先到的是后者:
// 于是 IsClosed() 恒 false、clearOnClose 也还没醒,而 OpenStream 每次都报 socket 错误。
// 池子若只看 IsClosed(),就会一直往这具尸体上开流 —— 每条新 hy2 / REALITY 流连续失败长达
// keepalive 超时(默认 30s),而重拨一条环回只要几毫秒。
func TestLoopbackSmuxPool_DropsAZombieSessionInsteadOfWaitingForKeepalive(t *testing.T) {
	es := startLoopbackWSEcho(t, true)
	pool := smuxPoolForEcho(es, smux.DefaultConfig())

	first, err := pool.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	if err := tryEcho(first, "before"); err != nil {
		t.Fatalf("前置条件:第一条流应能通: %v", err)
	}
	zombie := poolCurrentSession(pool)
	if zombie == nil {
		t.Fatal("池里应有一条会话")
	}

	// 掐断承载(环回那侧重启 / 连接被中断)。注意不要在旧 stream 上再做 I/O ——
	// 那会走 poolStream.noteIOError → retireSession,把本用例要验的那条路绕过去。
	es.killCarriers()

	// 等到会话进入「自称活着、开流却失败」的僵尸态。这是本用例的前置条件:
	// 如果 smux 直接把它标成 closed,那要验的窗口就不存在了。
	deadline := time.Now().Add(5 * time.Second)
	for {
		if zombie.IsClosed() {
			t.Skip("这次 smux 直接把会话标成 closed 了,僵尸窗口未出现(本用例只针对该窗口)")
		}
		if st, oerr := zombie.OpenStream(); oerr != nil {
			break // 僵尸态达成:IsClosed()==false 但开流失败
		} else {
			_ = st.Close()
		}
		if time.Now().After(deadline) {
			t.Fatal("承载已掐断,会话却仍能开流 —— 无法构造僵尸态")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// 关键断言:此时要一条新流,池子必须当场摘掉尸体并重拨,而不是把这次失败原样报给调用方。
	next, err := pool.OpenStream()
	if err != nil {
		t.Fatalf("僵尸会话应被摘掉并重建承载,却把失败原样报了出来: %v", err)
	}
	defer func() { _ = next.Close() }()
	if got := poolCurrentSession(pool); got == zombie {
		t.Fatal("池里还握着那条僵尸会话 —— 后续每条新流都会开在上面,连续失败到 keepalive 超时")
	}
	if err := tryEcho(next, "after"); err != nil {
		t.Fatalf("重建后的流应能通: %v", err)
	}
	if got := es.upgrades.Load(); got != 2 {
		t.Fatalf("应重建 1 条承载(共 2),实际 %d 条", got)
	}
}
