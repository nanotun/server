package main

// ACL 规模测试:规则数上千之后,快照重建与判定还撑不撑得住。
//
// ACL 判定在数据面热路径上(每个包都要过),实现是「后台重建不可变快照 + 原子换指针,
// 热路径只读」。这套设计在规模上的风险点有两个:
//
//   - 重建是全量的(读 settings + ListACLPairs + 重新分桶),规则多了会变慢,
//     而每次 `acl add/del`、每次 setting 改动都会触发一次;
//   - 判定若退化成线性扫全部规则,包处理延迟会随规则数上升。
//
// 三机 e2e 只跑几条规则,这两条都摸不到。这里把规则数拉到千条级来量。

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/nanotun/server/store"
)

// createBulkUsers 批量造用户,返回其 id。
//
// 只为满足 acl_pairs 的外键约束,这些用户不会真去登录,所以 PSK 哈希算一次就够了 ——
// 每个都单独算的话,上千个用户光 argon2 就要好几秒。
func createBulkUsers(t *testing.T, env *stormEnv, n int, prefix string) []int64 {
	t.Helper()
	ctx := t.Context()
	hash := stormPSKHash("bulk")
	ids := make([]int64, 0, n)
	for i := 0; i < n; i++ {
		u, err := env.st.CreateUser(ctx, store.NewUser{
			Username: fmt.Sprintf("%s%d", prefix, i),
			PSKHash:  hash,
		})
		if err != nil {
			t.Fatalf("批量建用户 %s%d: %v", prefix, i, err)
		}
		ids = append(ids, u.ID)
	}
	return ids
}

// TestACLScale_SnapshotRebuildAndLookup 量千条规则下的重建耗时与判定耗时,并验证判定仍然正确。
func TestACLScale_SnapshotRebuildAndLookup(t *testing.T) {
	if testing.Short() {
		t.Skip("规模测试较慢,-short 下跳过")
	}
	env := newStormEnv(t, 2)
	ctx := context.Background()

	rules := envInt("NT_SCALE_ACL", 2000)

	// 默认拒绝,这样每条 allow 都必须被快照正确收录才放得行 —— 漏收就会被下面的断言抓到。
	if err := env.st.SettingsSet(ctx, "acl_default_action", "deny"); err != nil {
		t.Fatalf("设置 acl_default_action: %v", err)
	}

	// acl_pairs 对 users 有外键,所以得先有真实用户。
	ids := createBulkUsers(t, env, rules+1, "aclscale")
	for i := 0; i < rules; i++ {
		if _, err := env.st.AddACLPairBasic(ctx, ids[i], ids[i+1], "allow"); err != nil {
			t.Fatalf("插入第 %d 条 ACL: %v", i, err)
		}
	}

	t0 := time.Now()
	reloadACLSnapshotFromStore(env.st)
	rebuild := time.Since(t0)

	// 判定耗时:轮着打所有规则,避免只测到某一个桶。
	const probes = 20000
	t1 := time.Now()
	allowed := 0
	for i := 0; i < probes; i++ {
		j := i % rules
		if aclAllows(ids[j], ids[j+1]) {
			allowed++
		}
	}
	lookup := time.Since(t1) / probes

	t.Logf("%d 条 ACL 规则:快照重建 %v,单次判定 %v", rules, rebuild, lookup)

	// 正确性:每条 allow 都得放行,反向(未授权)都得拒绝。
	// 规模变大后判定还得是对的 —— 分桶写错时往往表现为「大部分对、少数错」。
	if allowed != probes {
		t.Errorf("%d 次判定里只有 %d 次放行,期望全部放行 —— 千条规则下快照漏收了部分规则",
			probes, allowed)
	}
	wrongDirection := 0
	for i := 0; i < rules; i++ {
		// 反向没有规则,默认拒绝下必须不通。
		if aclAllows(ids[i+1], ids[i]) {
			wrongDirection++
		}
	}
	if wrongDirection > 0 {
		t.Errorf("有 %d 条规则的**反方向**也被放行了。ACL 是有向的,反向放行等于策略被绕过。",
			wrongDirection)
	}

	// 兜底哨兵,不是性能目标:重建到秒级时,每次 `acl add` 都会卡住管理面,
	// 而重建期间数据面还在用老快照,策略生效被推迟。
	if rebuild > 2*time.Second {
		t.Errorf("%d 条规则的快照重建要 %v,过慢:每次 acl 增删都会触发一次全量重建。", rules, rebuild)
	}
}

// TestACLScale_ConcurrentReloadWhileEvaluating 让重建与判定同时跑。
//
// 快照是原子换指针的,判定方每次 Load 都该拿到一份**自洽**的快照:
// 要么全是旧规则,要么全是新规则,不该出现「读到重建到一半的表」。
// 这条测试的价值主要交给 -race 判定,功能上只要求判定结果始终是两个合法值之一。
func TestACLScale_ConcurrentReloadWhileEvaluating(t *testing.T) {
	env := newStormEnv(t, 2)
	ctx := context.Background()

	if err := env.st.SettingsSet(ctx, "acl_default_action", "deny"); err != nil {
		t.Fatalf("设置 acl_default_action: %v", err)
	}
	ids := createBulkUsers(t, env, 2, "aclrace")
	src, dst := ids[0], ids[1]
	if _, err := env.st.AddACLPairBasic(ctx, src, dst, "allow"); err != nil {
		t.Fatalf("插入 ACL: %v", err)
	}
	reloadACLSnapshotFromStore(env.st)

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// 重建方:反复全量重建。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			reloadACLSnapshotFromStore(env.st)
		}
	}()

	// 判定方:反复判定同一对。规则一直存在,结果**必须恒为放行**;
	// 若中途读到半成品快照,这里会看到 false。
	wg.Add(1)
	var denied int
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if !aclAllows(src, dst) {
				denied++
			}
		}
	}()

	time.Sleep(2 * time.Second)
	close(stop)
	wg.Wait()

	if denied > 0 {
		t.Errorf("并发重建期间有 %d 次判定把已存在的 allow 规则判成了拒绝 —— "+
			"说明判定方读到了重建中途的快照,数据面会在每次 acl 改动时瞬时误杀流量。", denied)
	}
}

// TestACLScale_ReloadUnderLoginChurn 让 ACL 重建与登录 churn 并发,交给 -race。
//
// 登录会往 vIP 归属表里写(ACL 反查用),ACL 重建会换判定快照,两者是不同的数据结构
// 但服务于同一次判定。让它们互相踩一下,确认没有隐藏的共享状态。
func TestACLScale_ReloadUnderLoginChurn(t *testing.T) {
	env := newStormEnv(t, 3)
	ctx := context.Background()

	ids := createBulkUsers(t, env, 201, "aclchurn")
	for i := 0; i < 200; i++ {
		if _, err := env.st.AddACLPairBasic(ctx, ids[i], ids[i+1], "allow"); err != nil {
			t.Fatalf("插入 ACL: %v", err)
		}
	}

	stop := make(chan struct{})
	wait, logins := scaleChurn(env, 6, stop)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			reloadACLSnapshotFromStore(env.st)
			// 顺带改一次 settings,触发快照里 default action 那部分重读。
			_ = env.st.SettingsSet(ctx, "acl_default_action", "allow")
			time.Sleep(2 * time.Millisecond)
		}
	}()

	time.Sleep(3 * time.Second)
	close(stop)
	wg.Wait()
	wait()

	t.Logf("ACL 反复重建期间成功登录 %d 次", logins.Load())
	if !waitFor(20*time.Second, func() bool { return liveConnCount() == 0 && usedVIPCount() == 0 }) {
		t.Errorf("压力结束后未收敛:仍有 %d 条连接、%d 个占用中的 vIP", liveConnCount(), usedVIPCount())
	}
}
