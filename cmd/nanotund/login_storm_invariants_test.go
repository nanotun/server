package main

// 并发登录下的几条**不变量**,都是「破了不会报错、只会静默算错」的那类。
//
// 与 login_storm_test.go 的区别:那边主要看「会不会崩 / 会不会泄漏」,这边看
// 「算出来的结果对不对」—— 会话上限有没有被突破、ACL 反查表跟在线会话是否一致。
// 这两样错了都不会有任何日志:超颇的会话照常收发,ACL 反查错了就是策略被绕过。

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// ── 会话上限 ────────────────────────────────────────────────────────────────

// TestLoginStorm_MaxSessionsNotExceeded 验证并发登录不会突破每用户会话上限。
//
// 驱逐逻辑(evictOldestSessionsLocked)是在 connIDMapMu 写锁内按 by-user 索引数数的,
// 数完再踢最老的几条。并发登录若在「数」和「踢」之间互相看不见对方,就会各自认为
// 「加上我刚好到上限」,最终稳定停在超颇状态 —— 而付费套餐的并发数限制正是靠它。
func TestLoginStorm_MaxSessionsNotExceeded(t *testing.T) {
	const maxSessions = 3
	env := newStormEnv(t, 1)
	u := env.users[0]

	if err := env.st.SetUserMaxSessions(t.Context(), u.id, maxSessions); err != nil {
		t.Fatalf("SetUserMaxSessions: %v", err)
	}

	n := stormN(24)
	sessions := make([]*stormSession, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			// 每个都用不同 device,避免走 supersede 那条路 —— 这里要测的是会话上限。
			sessions[i], _ = stormLogin(env.gw, i, u.name, u.psk,
				stormUUID(900000+i), fmt.Sprintf("cap-%d", i))
		}(i)
	}
	close(start)
	wg.Wait()
	// 收尾时等清理真正跑完再走。清理是异步的,测试函数返回后那些 goroutine 还在跑,
	// 会把 vIP 归属表之类的全局状态带进下一个测试(本文件的 vipOwner 测试就被这么污染过)。
	defer func() {
		closeAll(sessions)
		waitFor(15*time.Second, func() bool { return liveConnCount() == 0 })
	}()

	// 被驱逐的连接是异步清理的,等收敛。
	if !waitFor(15*time.Second, func() bool { return liveSessionsForUser(u.id) <= maxSessions }) {
		t.Errorf("%d 个并发登录后,用户 %s 仍有 %d 条活会话,上限是 %d —— 并发驱逐没数对,"+
			"超出的会话照常收发,套餐并发限制被突破且无任何日志。",
			n, u.name, liveSessionsForUser(u.id), maxSessions)
	} else {
		t.Logf("%d 个并发登录后收敛到 %d 条活会话(上限 %d)", n, liveSessionsForUser(u.id), maxSessions)
	}
}

// liveSessionsForUser 数某 user 名下未被踢/未被接管的活连接。
func liveSessionsForUser(userID int64) int {
	connIDMapMu.RLock()
	defer connIDMapMu.RUnlock()
	n := 0
	for _, c := range connByUser[fmt.Sprintf("u%d", userID)] {
		if c == nil || c.takenOver.Load() || c.superseded.Load() {
			continue
		}
		n++
	}
	return n
}

// ── vIP 归属反查表 ──────────────────────────────────────────────────────────

// TestLoginStorm_VIPOwnerTableStaysConsistent 验证 vIP→归属会话 的反查表在 churn 下不失真。
//
// 这张表(vipOwnerCur)是 copy-on-write 的,登录注册、清理注销,而 ACL 执法靠它把
// 数据包的源/目的 vIP 反查成 user 与会话。两类错法都很危险,且都不会报错:
//
//   - 表里残留已下线会话的 vIP → 地址被回收再分配给别人后,ACL 会按**前主人**的身份判定;
//   - 老会话的 cleanup 误删了新会话刚注册的映射 → 新会话查不到归属,策略按「未知」处理。
//
// 后者正是 unregisterVIPOwners 里 ownerConnID 守卫要防的那件事,这里用并发 churn 压它。
func TestLoginStorm_VIPOwnerTableStaysConsistent(t *testing.T) {
	env := newStormEnv(t, 3)
	rounds := 4
	perRound := stormN(16)

	for r := 0; r < rounds; r++ {
		sessions := make([]*stormSession, perRound)
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < perRound; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				u := env.users[i%len(env.users)]
				<-start
				sessions[i], _ = stormLogin(env.gw, i, u.name, u.psk,
					stormUUID(r*10000+950000+i), fmt.Sprintf("vipown-%d-%d", r, i))
			}(i)
		}
		close(start)
		wg.Wait()

		// 在线期间:每条活会话的每个 vIP 都必须能反查到**它自己**。
		assertVIPOwnersMatchLiveConns(t, r)

		// 关掉一半,留一半 —— 让「老会话 cleanup」与「活会话仍在表里」同时发生。
		for i := 0; i < perRound; i += 2 {
			if sessions[i] != nil {
				_ = sessions[i].conn.Close()
			}
		}
		if !waitFor(15*time.Second, func() bool { return liveConnCount() == perRound-((perRound+1)/2) }) {
			t.Logf("第 %d 轮:半数关闭后在线 %d 条", r, liveConnCount())
		}
		// 幸存者的映射不能被离场者的 cleanup 顺手删掉。
		assertVIPOwnersMatchLiveConns(t, r)

		closeAll(sessions)
		if !waitFor(15*time.Second, func() bool { return liveConnCount() == 0 }) {
			t.Fatalf("第 %d 轮:全部关闭后仍有 %d 条连接", r, liveConnCount())
		}
		// 全部离场后表必须清空,残留 = 地址复用时会按前主人的身份执法。
		if left := vipOwnerCount(); left != 0 {
			t.Errorf("第 %d 轮:所有会话都断开了,vIP 归属表里仍残留 %d 条 —— "+
				"这些地址被回收再分配后,ACL 会按前一个主人的身份判定。", r, left)
		}
	}
}

func vipOwnerCount() int {
	m := vipOwnerCur.Load()
	if m == nil {
		return 0
	}
	return len(*m)
}

// assertVIPOwnersMatchLiveConns 双向核对:活会话的 vIP 都在表里且归属正确,
// 且表里不含已经不在线的会话。
func assertVIPOwnersMatchLiveConns(t *testing.T, round int) {
	t.Helper()

	connectionsMu.Lock()
	live := make(map[uint32]*Connection, len(connections))
	for id, c := range connections {
		live[id] = c
	}
	connectionsMu.Unlock()

	// 方向一:活会话 → 表。
	expect := make(map[netip.Addr]uint32)
	for id, c := range live {
		ips := c.clientIPs.Load()
		if ips == nil {
			continue
		}
		for _, a := range *ips {
			addr, err := netip.ParseAddr(a.VirtualIP)
			if err != nil {
				continue
			}
			expect[addr] = id
			gotConn, ok := lookupVIPOwnerConn(addr)
			if !ok {
				t.Errorf("第 %d 轮:活会话 %d 的 vIP %s 在归属表里查不到 —— ACL 会把它当未知来源处理",
					round, id, a.VirtualIP)
				continue
			}
			if gotConn != id {
				t.Errorf("第 %d 轮:vIP %s 的归属是会话 %d,但它实际属于会话 %d —— ACL 会按别人的身份执法",
					round, a.VirtualIP, gotConn, id)
			}
		}
	}

	// 方向二:表 → 活会话(表里不该有已离场会话的残留)。
	m := vipOwnerCur.Load()
	if m == nil {
		return
	}
	for addr, e := range *m {
		if _, ok := live[e.ownerConnID]; !ok {
			t.Errorf("第 %d 轮:归属表里 %s 指向会话 %d,但该会话已不在线 —— 残留映射会让回收后的地址按前主人执法",
				round, addr, e.ownerConnID)
		}
	}
}

// ── 单 IP 登录风暴 ──────────────────────────────────────────────────────────

// TestLoginStorm_SingleSourceIPIsThrottled 验证反滥用闸门确实拦得住单点风暴。
//
// 其它压测都刻意给每个模拟客户端配了不同来源 IP,好让流量打到会话层 —— 那反过来
// 意味着「限速到底有没有生效」从没被验证过。这里全部走同一个 IP:PoW 出题是 per-IP
// 限速的(burst 10、平均 1/s),所以绝大多数请求应当在出题阶段就被挡下,
// 而不是一路放行到 argon2 去烧 CPU。
func TestLoginStorm_SingleSourceIPIsThrottled(t *testing.T) {
	env := newStormEnv(t, 1)
	u := env.users[0]
	n := stormN(60)

	var wg sync.WaitGroup
	ok := make([]bool, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			// 关键:srcIdx 全为同一个值 → 同一个来源 IP。
			s, err := stormLogin(env.gw, 0, u.name, u.psk,
				stormUUID(970000+i), fmt.Sprintf("single-ip-%d", i))
			if err == nil {
				ok[i] = true
				_ = s.conn.Close()
			}
		}(i)
	}
	close(start)
	wg.Wait()

	admitted := 0
	for _, v := range ok {
		if v {
			admitted++
		}
	}
	t.Logf("同一来源 IP 并发 %d 次登录,放行 %d 次", n, admitted)

	// PoW 出题 burst 是 10、平均 1/s。放行数应当远低于总数;
	// 全放行说明 per-IP 闸门在并发下失效,单机就能把 argon2 打满。
	if admitted >= n {
		t.Errorf("同一 IP 的 %d 次并发登录全部放行,per-IP PoW 限速(burst=10)在并发下没起作用 —— "+
			"单台机器即可把 argon2 容量占满,拖垮所有正常用户的登录。", n)
	}
	if admitted == 0 {
		t.Error("一次都没放行,闸门过严或测试环境有问题(burst=10 时应当放行少量)")
	}

	// 收尾:限速状态是全局的,不清会污染后续测试。
	globalPoWIPLimiter.ResetForTest()
	ResetGlobalPoWIssueLimiterForTest()
	_ = time.Now()
}
