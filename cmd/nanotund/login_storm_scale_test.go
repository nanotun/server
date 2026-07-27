package main

// 规模 / 跨路径并发测试 —— login_storm_test.go 的姊妹文件。
//
// 单纯堆并发登录压不出什么:登录路径本身被 connectionsMu 串行化了,量再大也只是排队。
// 真正出过问题的是**不同代码路径同时碰同一份状态**:历史上的 rate limit 跨层覆盖、
// 端口转发回程被反欺骗闸误杀,都属于「A 路径读到了 B 路径写到一半的快照」这一类。
//
// 所以这里让登录/登出的 churn 与管理面操作(/status、/kick、/rate/refresh、ACL 重载)
// 同时跑,交给 -race 去抓。跑法:
//
//	go test ./cmd/nanotund/ -run Scale -race -count=1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// scaleChurn 在后台反复登录/登出,直到 stop 关闭。
//
// 返回的 wait 会等所有 goroutine 收工并关掉残留会话 —— 测试结束时必须调用,
// 否则后台 goroutine 会带着已关闭的 store 继续跑,报出一堆与被测行为无关的噪声。
func scaleChurn(env *stormEnv, workers int, stop <-chan struct{}) (wait func(), logins *atomic.Int64) {
	var wg sync.WaitGroup
	counter := &atomic.Int64{}
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				u := env.users[w%len(env.users)]
				s, err := stormLogin(env.gw, w, u.name, u.psk,
					stormUUID(100000+w*1000+i%50), fmt.Sprintf("churn-w%d", w))
				if err != nil {
					// churn 期间被 kick / 被 supersede 导致的登录失败是**预期内**的,
					// 这个 helper 只负责制造并发压力,正确性断言由各测试自己做。
					continue
				}
				counter.Add(1)
				time.Sleep(time.Millisecond)
				_ = s.conn.Close()
			}
		}(w)
	}
	return wg.Wait, counter
}

// ── /status 与 churn 并发 ───────────────────────────────────────────────────

// TestScale_StatusUnderLoginChurn 让 /status 在会话不断进出时反复全表扫描。
//
// /status 要遍历 connections / connIDMap 并读每条连接的 vIP、限速器、link 状态,
// 而这些字段正是登录路径在**分批写入**的 —— 连接先进 map、rlConn 稍后才 Store
// (conn_safe.go:38-55 记的就是这扇窗口)。这个测试专门去撞它。
func TestScale_StatusUnderLoginChurn(t *testing.T) {
	env := newStormEnv(t, 4)
	handler := controlHandleStatus(env.gw)

	stop := make(chan struct{})
	wait, logins := scaleChurn(env, 8, stop)

	var statusCalls int
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		rec := httptest.NewRecorder()
		handler(rec, httptest.NewRequest(http.MethodGet, "/status", nil))
		if rec.Code != http.StatusOK {
			close(stop)
			wait()
			t.Fatalf("/status 返回 %d,期望 200;body=%s", rec.Code, rec.Body.String())
		}
		// 解出来做基本自洽性检查:JSON 必须完整可解析。会话在扫描途中消失时
		// 若某个字段被写坏(比如 vIP 切片被并发改),这里会先炸。
		var st map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
			close(stop)
			wait()
			t.Fatalf("/status 输出不是合法 JSON: %v", err)
		}
		statusCalls++
	}
	close(stop)
	wait()

	// race_window_total 会是个不小的数,这是**正常**的:只要 /status 的轮询频率够高,
	// 撞上「连接已进 connIDMap、rlConn 尚未就绪」的登录中连接只是时间问题
	// (实测这里几千次扫描能撞出几百次)。conn_safe.go 早期注释里「生产预期严格 0」
	// 的说法就是被这个测试推翻的。
	//
	// 撞到本身无害 —— /status 把该连接的限速显示为未就绪即可。真正有害的是
	// /rate/refresh 撞到时会**跳过**该连接,那条已由 rateConfigGen 的登录尾部补刷兜住,
	// 回归测试见 login_rate_window_test.go。所以这里只记录数值,不设阈值。
	t.Logf("churn 期间完成 %d 次 /status 扫描、%d 次成功登录,撞到 rlConn 未就绪窗口 %d 次",
		statusCalls, logins.Load(), safeRLConnNilCount.Load())
	if statusCalls == 0 {
		t.Fatal("一次 /status 都没跑成")
	}
}

// ── 管理面操作与登录风暴并发 ───────────────────────────────────────────────

// TestScale_AdminOpsDuringLoginStorm 让 kick / 限速刷新 / ACL 重载与登录 churn 抢同一批状态。
//
// 这几条路径各自都持 connIDMapMu 或改 Connection 上的字段,而登录路径正在同时
// 往里塞新连接。跨路径干扰恰恰是这个仓库出过真问题的地方,所以让它们互相踩,
// 由 -race 判定;功能上只要求「服务端不崩、不死锁、状态最终收敛」。
func TestScale_AdminOpsDuringLoginStorm(t *testing.T) {
	env := newStormEnv(t, 4)

	stop := make(chan struct{})
	wait, logins := scaleChurn(env, 8, stop)

	kick := controlHandleKick(env.gw)
	rateRefresh := controlHandleRateRefresh(env.gw)
	status := controlHandleStatus(env.gw)

	var ops sync.WaitGroup
	// 1) 反复按 user 维度踢人。
	ops.Add(1)
	go func() {
		defer ops.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			for _, u := range env.users {
				body, _ := json.Marshal(map[string]string{"kind": "user", "id": u.name, "reason": "storm-test"})
				rec := httptest.NewRecorder()
				kick(rec, httptest.NewRequest(http.MethodPost, "/kick", bytes.NewReader(body)))
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	// 2) 反复刷限速(会重读 DB 并改活连接上的 limiter)。
	ops.Add(1)
	go func() {
		defer ops.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			rec := httptest.NewRecorder()
			body, _ := json.Marshal(map[string]any{"device_id": 1})
			rateRefresh(rec, httptest.NewRequest(http.MethodPost, "/rate/refresh", bytes.NewReader(body)))
			time.Sleep(5 * time.Millisecond)
		}
	}()
	// 3) 反复重建 ACL 快照(atomic 换指针,数据面在读)。
	ops.Add(1)
	go func() {
		defer ops.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			reloadACLSnapshotFromStore(env.st)
			time.Sleep(5 * time.Millisecond)
		}
	}()
	// 4) 持续扫 /status。
	ops.Add(1)
	go func() {
		defer ops.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			rec := httptest.NewRecorder()
			status(rec, httptest.NewRequest(http.MethodGet, "/status", nil))
			time.Sleep(2 * time.Millisecond)
		}
	}()

	time.Sleep(4 * time.Second)
	close(stop)
	ops.Wait()
	wait()

	t.Logf("混合压力期间成功登录 %d 次", logins.Load())

	// 压力撤掉后必须能收敛回零 —— 收敛不了就是有连接或 vIP 被漏在半路。
	if !waitFor(20*time.Second, func() bool { return liveConnCount() == 0 && usedVIPCount() == 0 }) {
		t.Errorf("压力结束后未收敛:仍有 %d 条连接、%d 个占用中的 vIP", liveConnCount(), usedVIPCount())
	}
}

// ── 大量在线会话下的 /status 开销 ──────────────────────────────────────────

// TestScale_StatusLatencyWithManySessions 量一下 /status 在会话数上去之后要多久。
//
// /status 是 O(N_conn) 全表扫描且要拿 connIDMapMu,而登录路径也要这把锁的写锁。
// 会话规模大时它会直接给登录加延迟 —— dashboard 每秒轮询一次的话尤其明显。
// 这里不设硬性门槛(不同机器差异大),只把数字打出来,便于回归时对比。
func TestScale_StatusLatencyWithManySessions(t *testing.T) {
	if testing.Short() {
		t.Skip("规模测试较慢,-short 下跳过")
	}
	env := newStormEnv(t, 4)
	n := stormN(150)

	sessions := make([]*stormSession, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			u := env.users[i%len(env.users)]
			s, err := stormLogin(env.gw, i, u.name, u.psk, stormUUID(500000+i), fmt.Sprintf("scale-%d", i))
			if err == nil {
				sessions[i] = s
			}
		}(i)
	}
	wg.Wait()
	defer closeAll(sessions)

	live := liveConnCount()
	if live == 0 {
		t.Fatal("一个会话都没建起来")
	}

	handler := controlHandleStatus(env.gw)
	const rounds = 20
	start := time.Now()
	for i := 0; i < rounds; i++ {
		rec := httptest.NewRecorder()
		handler(rec, httptest.NewRequest(http.MethodGet, "/status", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("/status 返回 %d", rec.Code)
		}
	}
	per := time.Since(start) / rounds

	t.Logf("在线会话 %d 条时,/status 单次耗时 %v(%d 次取平均)", live, per, rounds)

	// 只兜一条底线:单次扫描不该到秒级。真到了说明 status 路径上有 O(N²) 或锁内 IO。
	if per > time.Second {
		t.Errorf("/status 单次耗时 %v,在 %d 条会话下过慢,疑似锁内 IO 或 O(N^2)", per, live)
	}
}
