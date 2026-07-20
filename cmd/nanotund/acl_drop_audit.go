package main

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nanotun/server/store"
)

// P2#13 ACL drop 聚合 audit
//
// 背景:aclDropPacketDirected / exitDeniedForPacket 命中 drop 时,只递增了
// atomic 计数器,运维查 audit_logs 看不到「u3 → u5 tcp:22 1234 包被 drop」
// 这种 actionable 信息;不区分用户 + 不区分原因,排查时只能拼日志靠猜。
//
// 但 per-packet 写一行 audit 一秒能写到几千几万行,撑爆 audit_logs(P2-16 audit-gc
// 也来不及 prune)。妥协:
//
//   • 进程内一个 sync.Map[bucketKey] → counters,bucketKey = (srcUserID, dstUserID,
//     proto, dstPort, kind);
//   • 每 60s flush 一次:把每个非零 bucket 写一条 audit_logs(action=acl.drop.agg),
//     然后清零;
//   • 每 bucket 单条 audit detail 例:
//       "src=1 dst=2 proto=tcp port=22 kind=user count=842 first=...,last=..."
//
// 这样:
//   • 长期审计有据可查;
//   • 不阻塞数据面(原子 +1);
//   • DB 写入量从 packet/sec 量级降到 bucket数/分钟,通常一台 nanotun 不超过几十 bucket。

// AclDropBucketKey 聚合维度。
type aclDropBucketKey struct {
	srcUserID int64
	dstUserID int64
	proto     string
	dstPort   uint16
	kind      string // "user" / "exit_acl" / "exit_gate"
}

type aclDropBucket struct {
	count     atomic.Uint64
	firstAtNS atomic.Int64
	lastAtNS  atomic.Int64
}

var aclDropAggBuckets sync.Map // aclDropBucketKey → *aclDropBucket

// recordACLDrop 在数据面 drop 路径上调用(无锁、纳秒级)。
//
// 参数语义见 aclDropBucketKey.kind:
//   - "user":aclDropPacketDirected 命中 user-kind 规则的 deny / 默认 deny
//   - "exit_acl":aclDropPacketDirected 命中 exit-kind 规则
//   - "exit_gate":exitDeniedForPacket(P0-4 user.exit_allowed=false fast-path)
func recordACLDrop(kind string, srcUserID, dstUserID int64, proto string, dstPort uint16) {
	key := aclDropBucketKey{
		srcUserID: srcUserID,
		dstUserID: dstUserID,
		proto:     proto,
		dstPort:   dstPort,
		kind:      kind,
	}
	v, ok := aclDropAggBuckets.Load(key)
	if !ok {
		// 双查:防止两个 goroutine 同时 Store。
		v, _ = aclDropAggBuckets.LoadOrStore(key, &aclDropBucket{})
	}
	b := v.(*aclDropBucket)
	now := time.Now().UnixNano()
	if b.count.Add(1) == 1 {
		b.firstAtNS.Store(now)
	}
	b.lastAtNS.Store(now)
}

const (
	aclDropAuditFlushInterval = 60 * time.Second
)

// startACLDropAuditFlusher 起一条 goroutine 定时 flush 聚合 bucket 到 audit_logs。
// gw / gw.store 为 nil 时 no-op。
func startACLDropAuditFlusher(gw *gatewayState, interval time.Duration) func() {
	if gw == nil || gw.store == nil {
		return func() {}
	}
	if interval <= 0 {
		interval = aclDropAuditFlushInterval
	}
	go safeGlobalGoroutine("aclDropAuditFlush", globalContextCancel, func() {
		runACLDropAuditFlushLoop(globalContext, gw.store, interval)
	})
	return func() {}
}

func runACLDropAuditFlushLoop(ctx context.Context, st *store.Store, interval time.Duration) {
	if ctx == nil {
		ctx = context.Background()
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			// 退出前最后 flush 一次,避免短跑测试看不到统计。
			flushACLDropAggregates(ctx, st)
			return
		case <-t.C:
			flushACLDropAggregates(ctx, st)
		}
	}
}

// flushACLDropAggregates 把当前 bucket 写 audit_logs 并清零。
//
// 实现细节:
//   - 单次 Range 拿到所有 key/value,delete 在 Range 内部安全(sync.Map 文档允许);
//   - 但 atomic count 在 delete 之前可能被并发 + 1,因此设计上接受「漏报一两个」 ——
//     下一轮再 flush 即可,统计粗粒度也够用。
//   - 把 bucket 按 (count desc, kind asc) 排序,日志摘要先打 top-N。
//   - H2(2026-05-22):flush 时 c==0 的 bucket 必须 Delete,否则 sync.Map 永远只增不
//     减 —— 一个客户端做 port scan 一次就能在 map 里塞 65k 个 (dstUserID, proto,
//     port, kind) tuple,长跑下 内存持续涨。Delete 之后 recordACLDrop 再命中
//     相同 key 会重新 LoadOrStore 创建,代价是稳态下每 60s flush 周期内首次命中
//     的 bucket 多走一次 mu lock,可接受。
func flushACLDropAggregates(ctx context.Context, st *store.Store) {
	type item struct {
		key   aclDropBucketKey
		count uint64
		first int64
		last  int64
	}
	var items []item
	aclDropAggBuckets.Range(func(k, v any) bool {
		key := k.(aclDropBucketKey)
		b := v.(*aclDropBucket)
		c := b.count.Swap(0)
		if c == 0 {
			// H2:本轮没流量的 bucket → 删除,防止 map 无界增长。
			// 删除后下次同 key 命中会重建,代价 = 一次 LoadOrStore,稳态可忽略。
			aclDropAggBuckets.Delete(key)
			return true
		}
		items = append(items, item{
			key:   key,
			count: c,
			first: b.firstAtNS.Swap(0),
			last:  b.lastAtNS.Swap(0),
		})
		return true
	})
	if len(items) == 0 {
		return
	}
	sort.Slice(items, func(i, j int) bool { return items[i].count > items[j].count })

	logrus.WithField("bucket_count", len(items)).Debug("[acl-drop-audit] flush 聚合")
	for _, it := range items {
		detail := fmt.Sprintf("src=%d dst=%d proto=%s port=%d kind=%s count=%d first=%d last=%d",
			it.key.srcUserID, it.key.dstUserID, it.key.proto, it.key.dstPort, it.key.kind,
			it.count, it.first, it.last)
		opCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		err := st.Audit(opCtx, "acl-runtime", "acl_drop_agg", aclDropAuditTarget(it.key), detail)
		cancel()
		if err != nil {
			logrus.WithError(err).Debug("[acl-drop-audit] 写 audit 失败,丢弃当批")
		}
	}
}

// aclDropAuditTarget 给 audit.target 选一段人类可读的字符串。
func aclDropAuditTarget(k aclDropBucketKey) string {
	dst := userIDFromStoreID(k.dstUserID)
	if k.kind == "exit_acl" || k.kind == "exit_gate" {
		dst = "<exit>"
	}
	src := userIDFromStoreID(k.srcUserID)
	if k.srcUserID == 0 {
		src = "<unknown>"
	}
	return src + "->" + dst
}
