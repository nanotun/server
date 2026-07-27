package main

// 登录吞吐随「库里已有多少设备/租约」的变化 —— 容量规划用。
//
// 关注这一条的原因在 server.go 的登录热路径里:
//
//	connectionsMu.Lock()
//	  dbReservedVIPs(gw, ...)   ← 锁内查一次 SQLite,把别的设备的 lease 读成「已占用」集
//	  ... 分配 vIP ...
//	connectionsMu.Unlock()
//
// connectionsMu 是**全局**锁,所有登录都要排队过;而锁内那次查询的代价随 leases
// 表规模增长。两者相乘 = 登录吞吐随设备总数下降,且下降的是串行段,加核也救不回来。
//
// 这个测试不设硬性阈值(不同机器/磁盘差太多),它测的是**趋势**:在租约数放大一个
// 数量级之后,单次登录的平均耗时不应该跟着放大一个数量级。真放大了,说明扩容到
// 上万设备时登录会先撑不住,需要给这条路径加缓存或把查询挪出锁。

import (
	"fmt"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"
)

// TestScale_LoginThroughputVsLeaseCount 对比「空库」与「预置大量租约」两种情况下的登录耗时。
func TestScale_LoginThroughputVsLeaseCount(t *testing.T) {
	if testing.Short() {
		t.Skip("容量测试较慢,-short 下跳过")
	}
	if raceDetectorEnabled {
		// 竞态检测器给 map / SQLite 访问都加了插桩,拖慢的幅度还与访问次数相关 ——
		// 恰好把这里要量的「随规模增长」那部分成倍放大(实测比值从 3x 变成 11x)。
		// 正确性靠其它测试保证,这条只在不开 -race 时量数。
		t.Skip("耗时测量在 -race 下失真,跳过")
	}

	batch := stormN(40)
	// NT_SCALE_LEASES 可调预置租约数,用来手工探增长曲线(默认 4000 够跑得快又看得出差别)。
	preload := envInt("NT_SCALE_LEASES", 4000)

	baseline := measureLoginBatch(t, 0, batch)
	loaded := measureLoginBatch(t, preload, batch)

	t.Logf("空库时单次登录平均 %v;库里已有 %d 条租约时 %v(放大 %.2fx)",
		baseline, preload, loaded, float64(loaded)/float64(baseline))

	// 只兜住「灾难性劣化」:锁内查询若退化成全表扫且没走索引,这里会是几十倍。
	// 5x 是留了充分余量的哨兵,不是性能目标。
	if baseline > 0 && loaded > baseline*5 {
		t.Errorf("租约数从 0 涨到 %d 后,单次登录耗时从 %v 涨到 %v(>5x)。"+
			"登录热路径在 connectionsMu 锁内查 leases(dbReservedVIPs),"+
			"这条串行段会随设备总数变慢 —— 上万设备规模需要先给它加缓存或挪出锁。",
			preload, baseline, loaded)
	}
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return def
}

// measureLoginBatch 预置 preload 条租约后,并发登录 batch 次,返回单次平均耗时。
func measureLoginBatch(t *testing.T, preload, batch int) time.Duration {
	t.Helper()
	env := newStormEnv(t, 2)

	// 预置租约:直接写库,模拟「服务器上已经有这么多台设备注册过」。
	if preload > 0 {
		ctx := t.Context()
		u := env.users[0]
		for i := 0; i < preload; i++ {
			dev, err := env.st.UpsertDevice(ctx, u.id, stormUUID(2000000+i), fmt.Sprintf("preload-%d", i), "linux")
			if err != nil {
				t.Fatalf("预置 device %d: %v", i, err)
			}
			// 10.90.x.y,避开 batch 登录会用到的低位地址段。
			vip := fmt.Sprintf("10.90.%d.%d", 100+i/250, i%250+1)
			if _, err := env.st.UpsertLease(ctx, dev.ID, vip, "", false); err != nil {
				t.Fatalf("预置 lease %d: %v", i, err)
			}
		}
	}

	sessions := make([]*stormSession, batch)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < batch; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			u := env.users[i%len(env.users)]
			<-start
			sessions[i], _ = stormLogin(env.gw, i, u.name, u.psk,
				stormUUID(3000000+i), fmt.Sprintf("bench-%d", i))
		}(i)
	}

	t0 := time.Now()
	close(start)
	wg.Wait()
	elapsed := time.Since(t0)
	defer closeAll(sessions)

	ok := 0
	for _, s := range sessions {
		if s != nil {
			ok++
		}
	}
	if ok == 0 {
		t.Fatalf("preload=%d 时一个都没登录成功", preload)
	}
	return elapsed / time.Duration(ok)
}
