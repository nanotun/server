package main

// N38 窗口对限速的影响 —— 由并发压测(login_storm_scale_test.go)顺藤摸出来的。
//
// 登录路径的顺序是:
//
//	① connIDMap[connIDStr] = c        ← 连接对 /rate/refresh 可见(server.go:2949)
//	② 从 DB 读限速配置并算出 limiter   ← (server.go:3265-3283)
//	③ c.rlConn.Store(rwc)             ← 数据面就绪(server.go:3293)
//
// ①→③ 之间 /rate/refresh 若扫到这条连接,safeRLConn() 拿到 nil,applyConnRateLimit
// 直接 return false 跳过(control_socket.go:935-938),既不重试也不报错。
//
// 于是这条交错会让限速**永久失效**:
//
//	登录①  →  登录②读到旧值  →  管理员写新值 + 推 refresh  →  refresh 跳过本连接
//	                                                        →  登录③按旧值装上 limiter
//
// 管理员看到的是「限速已下发」,连接却一直跑在旧速率上,直到它自己重连。
// 这与之前修过的限速跨层覆盖(freshUserBW/freshDeviceRates)属于同一族问题:
// 都是「拿到了一份已经过期的快照,且没人再回头纠正」。

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/nanotun/server/store"
)

// TestLoginRateWindow_RefreshInWindowIsNotLost 是这个窗口的**确定性**回归测试。
//
// 用 loginRateWindowHookForTest 把登录**精确地**停在窗口正中间(已进 connIDMap、
// rlConn 尚未就绪),在那一刻完整地做一遍管理员的动作:改库 + 推 refresh。
// refresh 必然扫到这条连接、必然因为 rlConn==nil 而跳过 —— 然后放行登录。
//
// 期望:登录走完之后,这条连接的限速是**新值**。
// 若为旧值,说明两头都不管:refresh 跳过了它,它自己又用认证阶段的旧快照装 limiter。
func TestLoginRateWindow_RefreshInWindowIsNotLost(t *testing.T) {
	env := newStormEnv(t, 1)
	ctx := context.Background()

	const targetDownBPS = 2_000_000
	u := env.users[0]

	if err := env.st.SetRateDefaults(ctx, store.RateDefaults{}); err != nil {
		t.Fatalf("SetRateDefaults(清零): %v", err)
	}

	refresh := controlHandleRateRefresh(env.gw)

	var once sync.Once
	loginRateWindowHookForTest = func() {
		// 只在第一条连接上动手,避免 refresh 自身触发的其它登录递归进来。
		once.Do(func() {
			// 管理员的真实动作顺序:先落库,再推刷新。
			if err := env.st.SetUserBandwidth(ctx, u.id, 0, targetDownBPS); err != nil {
				t.Errorf("SetUserBandwidth: %v", err)
				return
			}
			rec := httptest.NewRecorder()
			body, _ := json.Marshal(map[string]any{})
			refresh(rec, httptest.NewRequest(http.MethodPost, "/rate/refresh", bytes.NewReader(body)))
		})
	}
	t.Cleanup(func() { loginRateWindowHookForTest = nil })

	s, err := stormLogin(env.gw, 1, u.name, u.psk, stormUUID(800001), "window-victim")
	if err != nil {
		t.Fatalf("登录失败: %v", err)
	}
	defer func() { _ = s.conn.Close() }()

	if hits := safeRLConnNilCount.Load(); hits == 0 {
		t.Fatal("窗口没被撞到(race_window_total=0),这个测试没测到该测的东西")
	}

	stale, checked := collectStaleRateConns(t, targetDownBPS)
	if checked == 0 {
		t.Fatal("一条连接都没查到,这个断言什么也没验证")
	}
	if len(stale) > 0 {
		t.Errorf("连接在窗口期错过了限速刷新,事后无人纠正:%v(期望下行 %d)\n"+
			"refresh 扫到它时 rlConn 还是 nil,applyConnRateLimit 直接 return false;"+
			"而它自己装 limiter 用的是认证阶段的旧快照 —— 这条会话会一直不受限,直到重连。",
			stale, targetDownBPS)
	}
}

// TestTakeoverRateWindow_RefreshInWindowIsNotLost 是 takeover(客户端热切换链路)侧的同款回归。
//
// 这条路径的窗口形状与主登录不同,更隐蔽:newConn 是在 rlConn.Store **之后**才进
// connIDMap 的,所以窗口期的 /rate/refresh **根本看不见它** —— 刷新只会作用在即将被
// 丢弃的 oldConn 上,newConn 却装着接管前那份旧快照。因为连接压根没被扫到,
// race_window_total 也不会 +1,靠指标发现不了。
func TestTakeoverRateWindow_RefreshInWindowIsNotLost(t *testing.T) {
	env := newStormEnv(t, 1)
	ctx := context.Background()

	const targetDownBPS = 3_000_000
	u := env.users[0]

	if err := env.st.SetRateDefaults(ctx, store.RateDefaults{}); err != nil {
		t.Fatalf("SetRateDefaults(清零): %v", err)
	}

	// 先建一条普通会话,拿到 session_id + takeover_secret。
	first, err := stormLogin(env.gw, 1, u.name, u.psk, stormUUID(810001), "takeover-base")
	if err != nil {
		t.Fatalf("首次登录失败: %v", err)
	}
	defer func() { _ = first.conn.Close() }()
	if first.sessionID == "" || first.takeoverSecret == "" {
		t.Fatalf("LoginResp 没给出 session_id / takeover_secret,无法发起接管")
	}

	refresh := controlHandleRateRefresh(env.gw)
	var once sync.Once
	takeoverRateWindowHookForTest = func() {
		once.Do(func() {
			if err := env.st.SetUserBandwidth(ctx, u.id, 0, targetDownBPS); err != nil {
				t.Errorf("SetUserBandwidth: %v", err)
				return
			}
			rec := httptest.NewRecorder()
			body, _ := json.Marshal(map[string]any{})
			refresh(rec, httptest.NewRequest(http.MethodPost, "/rate/refresh", bytes.NewReader(body)))
		})
	}
	t.Cleanup(func() { takeoverRateWindowHookForTest = nil })

	second, err := stormTakeover(env.gw, 2, u.name, u.psk, first)
	if err != nil {
		t.Fatalf("接管失败: %v", err)
	}
	defer func() { _ = second.conn.Close() }()

	// 确认接管**真的生效**了,而不是中途回滚。
	// 服务端在下发 ConvSaltLite 失败时会静默回滚整个接管(老连接原封不动),
	// 此时后面所有断言都会变成假绿 —— secret 轮换是接管成功的可靠标志。
	if second.takeoverSecret == "" || second.takeoverSecret == first.takeoverSecret {
		t.Fatalf("接管似乎被回滚了:secret 未轮换(old=%q new=%q)", first.takeoverSecret, second.takeoverSecret)
	}
	// 等老连接退场,只剩接管后的新连接,避免把 oldConn 的限速算进来。
	if !waitFor(10*time.Second, func() bool { return liveConnCount() == 1 }) {
		t.Logf("注意:接管后在线连接数为 %d(期望 1),老连接可能还在清理", liveConnCount())
	}

	stale, checked := collectStaleRateConns(t, targetDownBPS)
	if checked == 0 {
		t.Fatal("一条连接都没查到,这个断言什么也没验证")
	}
	t.Logf("接管后检查了 %d 条连接", checked)
	if len(stale) > 0 {
		t.Errorf("接管出来的连接错过了限速刷新:%v(期望下行 %d)\n"+
			"刷新发生时 newConn 还没进 connIDMap、压根没被扫到,而它装的是接管前的旧快照 —— "+
			"客户端只要换一次链路(Wi-Fi 切蜂窝)就能把刚下发的限速甩掉。",
			stale, targetDownBPS)
	}
}

// TestLoginRateWindow_RefreshDuringLoginIsNotLost 是上面那条的并发版本:
// 不注入钩子,靠真实的登录风暴自然撞窗口。撞不撞得到取决于机器时序,
// 因此它的价值在于**接近真实**,确定性由上面那条保证。
//
// 打的是 **user 级带宽** 这个旋钮,不是全局默认限速 —— 两者的窗口宽度差好几个量级:
//
//   - 全局默认(rate_defaults)是在 ③ 前几微秒才读 DB 的(server.go:3265),
//     要撞上得让管理员的「写库 + 扫到本连接」整个动作挤进那几微秒,基本撞不到;
//   - user / device 级限速则是在**认证阶段**就快照到 Connection 上的
//     (server.go:2936-2941,authResult),而认证远早于 ①。于是整个
//     「认证 → 建连 → supersede 等清理(最长 5s)→ 分配 vIP → 写 lease → ③」
//     都在窗口里,宽到秒级。
//
// 做法:一边持续登录,一边把 user 带宽调小并推 refresh。收工后逐条查活连接实际
// 装的下行限速 —— 只要有一条还停在「不限速」,就说明它在窗口里被 refresh 跳过、
// 事后也没有任何路径回头纠正。
func TestLoginRateWindow_RefreshDuringLoginIsNotLost(t *testing.T) {
	env := newStormEnv(t, 2)
	ctx := context.Background()

	const targetDownBPS = 1_000_000

	// 起点:不限速。这样「漏网」的连接会明显地停在 0 上。
	if err := env.st.SetRateDefaults(ctx, store.RateDefaults{}); err != nil {
		t.Fatalf("SetRateDefaults(清零): %v", err)
	}

	refresh := controlHandleRateRefresh(env.gw)
	pushRefresh := func() {
		rec := httptest.NewRecorder()
		body, _ := json.Marshal(map[string]any{})
		refresh(rec, httptest.NewRequest(http.MethodPost, "/rate/refresh", bytes.NewReader(body)))
	}

	// 规模是这里的关键放大器,不是为了「压得更狠」而堆数量:
	// 连接在 server.go:2949 就进了 connIDMap,却要到 3084 行才去抢 connectionsMu
	// —— 几百个并发登录会一起堵在这把锁上排队,每一个都顶着 rlConn==nil 待在窗口里
	// 几十上百毫秒。窗口于是从「几微秒」变成「肉眼可见」。
	n := stormN(200)
	sessions := make([]*stormSession, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			u := env.users[i%len(env.users)]
			<-start
			sessions[i], _ = stormLogin(env.gw, i, u.name, u.psk,
				stormUUID(700000+i), fmt.Sprintf("ratewin-%d", i))
		}(i)
	}
	close(start)

	// 等登录在锁上堆起来之后再压低 user 带宽 + 推 refresh。
	// 顺序与管理员的真实动作一致:`nanotun-admin user set-bandwidth` 先落库,再推刷新。
	go func() {
		time.Sleep(20 * time.Millisecond)
		for _, u := range env.users {
			_ = env.st.SetUserBandwidth(ctx, u.id, 0, targetDownBPS)
		}
		for i := 0; i < 200; i++ {
			pushRefresh()
			time.Sleep(time.Millisecond)
		}
	}()

	wg.Wait()
	defer closeAll(sessions)

	// 注意:这里**故意不再推一次 refresh**。
	// 补推一次会把所有被跳过的连接顺手修好,正好把要找的问题盖住 ——
	// 而现实中管理员只推一次,漏网的连接没有第二次机会。
	//
	// 也不存在「只是还没轮到」的良性解释:后台已经推了 60 次、覆盖到所有登录完成之后;
	// 且认证发生在改带宽之后的连接,快照本身就是新值,不会误报。
	t.Logf("窗口命中次数(race_window_total)= %d", safeRLConnNilCount.Load())

	stale, checked := collectStaleRateConns(t, targetDownBPS)
	if checked == 0 {
		t.Fatal("一条连接都没查到,这个断言什么也没验证")
	}
	if len(stale) > 0 {
		t.Errorf("有 %d/%d 条连接的下行限速仍停在旧值(应为 %d):%v\n"+
			"这些连接在「已进 connIDMap、rlConn 尚未就绪」的窗口里被 /rate/refresh 跳过 "+
			"(applyConnRateLimit 见 rl==nil 就 return false,不重试也不报错),"+
			"而它们自己装 limiter 用的是认证阶段的旧快照 —— 管理员看到限速已下发,这些会话却不受限。",
			len(stale), n, targetDownBPS, stale)
	}
}

// collectStaleRateConns 返回下行限速不等于 want 的连接摘要,以及实际检查过的连接数。
//
// 返回检查数是必要的:空集合天然「没有陈旧项」,若不核对就会把「一条都没查到」
// 误读成「全部正确」—— 这种假绿比漏测更糟。
func collectStaleRateConns(t *testing.T, want int64) ([]string, int) {
	t.Helper()
	connIDMapMu.RLock()
	conns := make([]*Connection, 0, len(connIDMap))
	for _, c := range connIDMap {
		conns = append(conns, c)
	}
	connIDMapMu.RUnlock()

	var stale []string
	checked := 0
	for _, c := range conns {
		rl := c.rlConn.Load()
		if rl == nil {
			// 登录还没走完的连接不算数(压测收工时不该有,但别把它误判成 bug)。
			continue
		}
		checked++
		_, down, _, _ := rl.snapshotLimits()
		if down != want {
			stale = append(stale, fmt.Sprintf("conn=%s down=%d", c.connIDStr, down))
		}
	}
	return stale, checked
}
