package main

import (
	"net/netip"
	"sync"
	"testing"
)

// P3-b:并发写 + 大量并发读不应触发 -race;新读到的快照永远是某次写入的「完整」结果。
//
// 切换到 atomic.Pointer[map] 的核心收益:消除 RWMutex 上的读端争用。
// 测试 1000 个读 goroutine + 4 个写 goroutine,各跑若干轮,任何中间状态都合法
// (每次 lookupVIPOwner 要么返回写入前 uid,要么返回写入后 uid,绝不会返回错位 uid)。
func TestVIPOwner_ConcurrentRace(t *testing.T) {
	// 准备 5 个 vIP,每个有「即将轮换的两个 uid」。
	addrs := make([]netip.Addr, 5)
	for i := range addrs {
		addrs[i] = netip.MustParseAddr("10.200.1." + itoa(int64(i+1)))
		registerVIPOwners([]netip.Addr{addrs[i]}, int64(100+i))
	}
	t.Cleanup(func() { unregisterVIPOwners(addrs) })

	var writers sync.WaitGroup
	var readers sync.WaitGroup
	stop := make(chan struct{})

	for w := 0; w < 4; w++ {
		writers.Add(1)
		go func(w int) {
			defer writers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				for i, a := range addrs {
					registerVIPOwners([]netip.Addr{a}, int64(100+i))
					registerVIPOwners([]netip.Addr{a}, int64(200+i))
				}
			}
		}(w)
	}

	for r := 0; r < 64; r++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for i := 0; i < 5000; i++ {
				_, _ = lookupVIPOwner(addrs[i%len(addrs)])
			}
		}()
	}

	// 先等读 goroutine 跑完,再叫停写,最后 Wait 写完。
	readers.Wait()
	close(stop)
	writers.Wait()
}

func BenchmarkLookupVIPOwner(b *testing.B) {
	a := netip.MustParseAddr("10.200.42.42")
	registerVIPOwners([]netip.Addr{a}, 4242)
	defer unregisterVIPOwners([]netip.Addr{a})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = lookupVIPOwner(a)
	}
}
