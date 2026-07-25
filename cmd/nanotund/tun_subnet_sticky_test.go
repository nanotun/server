package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nanotun/server/store"
)

// 三候选池，对应部署里 `[tun] subnets` 的常见写法。
var stickyPoolV4 = []string{"10.200.0.0/16", "10.201.0.0/16", "10.202.0.0/16"}

// 上次用 10.202 → 只要它仍在可用集里就必须继续用它，而不是按轮转下标另选一个。
// 这是「重启换网段作废全部 lease + 静默跳过 fixed vIP」的根因回归（2026-07-25 双机实测）。
func TestChooseTUNSubnet_ReusesLastUsedSubnet(t *testing.T) {
	got, sticky := chooseTUNSubnet(stickyPoolV4, []string{"10.202.0.1/16", "fd00:200::1/64"}, true)
	if !sticky {
		t.Fatalf("应沿用上次网段,却走了轮转: got %s", got)
	}
	if got != "10.202.0.0/16" {
		t.Fatalf("got %s, want 10.202.0.0/16", got)
	}
}

// 可用集合的「组成」变化不该改变选择结果：上次那个仍在里面就还用它。
// 修复前正是这一点会翻车 —— 下标 1 在 [10.200,10.202] 里指 10.202、在三个都可用时指 10.201。
func TestChooseTUNSubnet_StableAcrossUsableSetChanges(t *testing.T) {
	prev := []string{"10.202.0.1/16"}
	for _, usable := range [][]string{
		stickyPoolV4,
		{"10.200.0.0/16", "10.202.0.0/16"},
		{"10.202.0.0/16"},
		{"10.202.0.0/16", "10.200.0.0/16"}, // 顺序变了也不影响
	} {
		got, sticky := chooseTUNSubnet(usable, prev, true)
		if !sticky || got != "10.202.0.0/16" {
			t.Fatalf("usable=%v: got %s sticky=%v, want 10.202.0.0/16 sticky=true", usable, got, sticky)
		}
	}
}

// 上次的网段这次不可用（本机新增冲突接口 / 运维改了 subnets）→ 回退轮转，且必须选中可用集里的成员。
func TestChooseTUNSubnet_FallsBackWhenPreviousUnavailable(t *testing.T) {
	usable := []string{"10.200.0.0/16", "10.201.0.0/16"}
	got, sticky := chooseTUNSubnet(usable, []string{"10.202.0.1/16"}, true)
	if sticky {
		t.Fatal("上次网段已不可用,不该报告 sticky")
	}
	if got != usable[0] && got != usable[1] {
		t.Fatalf("回退结果 %s 不在可用集 %v 内", got, usable)
	}
}

// 首次部署（无快照）→ 回退轮转，不报 sticky。
func TestChooseTUNSubnet_FreshDeployHasNoPreference(t *testing.T) {
	got, sticky := chooseTUNSubnet(stickyPoolV4, nil, true)
	if sticky {
		t.Fatal("无快照时不该报告 sticky")
	}
	if got == "" {
		t.Fatal("仍须选出一个网段")
	}
}

// 族隔离：v6 快照不得影响 v4 选择，反之亦然（同一次启动两族各挑一次）。
func TestPickStickySubnet_FamilyIsolation(t *testing.T) {
	prev := []string{"10.202.0.1/16", "fd00:202::1/64"}
	if i := pickStickySubnet(stickyPoolV4, prev, true); i != 2 {
		t.Fatalf("v4 选择 idx=%d, want 2(10.202)", i)
	}
	poolV6 := []string{"fd00:200::/64", "fd00:202::/64"}
	if i := pickStickySubnet(poolV6, prev, false); i != 1 {
		t.Fatalf("v6 选择 idx=%d, want 1(fd00:202)", i)
	}
	// v4 快照对 v6 池无匹配 → -1。
	if i := pickStickySubnet(poolV6, []string{"10.202.0.1/16"}, false); i != -1 {
		t.Fatalf("跨族不该匹配, got idx=%d", i)
	}
}

// 掩码变了等于地址池变了，不能当同一个网段沿用。
func TestPickStickySubnet_PrefixLenMustMatch(t *testing.T) {
	if i := pickStickySubnet([]string{"10.202.0.0/24"}, []string{"10.202.0.1/16"}, true); i != -1 {
		t.Fatalf("掩码不同不该沿用, got idx=%d", i)
	}
}

// 垃圾输入（无法解析的快照 / 候选）只能被跳过，不能 panic 或误匹配。
func TestPickStickySubnet_IgnoresGarbage(t *testing.T) {
	if i := pickStickySubnet([]string{"not-a-cidr", "10.202.0.0/16"}, []string{"garbage", "10.202.0.1/16"}, true); i != 1 {
		t.Fatalf("应跳过垃圾项并命中 idx=1, got %d", i)
	}
	if i := pickStickySubnet(nil, []string{"10.202.0.1/16"}, true); i != -1 {
		t.Fatalf("空候选集应回 -1, got %d", i)
	}
}

// 只读探测：库不存在 / 无 mesh_cidrs → nil（按无偏好处理，绝不阻断启动）；写过则读回。
func TestReadPersistedMeshGateways(t *testing.T) {
	if got := readPersistedMeshGateways(""); got != nil {
		t.Fatalf("空路径应回 nil, got %v", got)
	}
	missing := filepath.Join(t.TempDir(), "nope.db")
	if got := readPersistedMeshGateways(missing); got != nil {
		t.Fatalf("库不存在应回 nil, got %v", got)
	}
	if _, err := os.Stat(missing); err == nil {
		t.Fatal("只读探测不得创建库文件")
	}

	ctx := t.Context()
	dbPath := filepath.Join(t.TempDir(), "sticky.db")
	st, err := store.Open(ctx, dbPath, store.Options{})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	// 迁移完但没写过 mesh_cidrs → nil。
	if got := readPersistedMeshGateways(dbPath); got != nil {
		t.Fatalf("未设置 mesh_cidrs 应回 nil, got %v", got)
	}
	want := []string{"10.202.0.1/16", "fd00:200::1/64"}
	if err := st.SetMeshCIDRs(ctx, want); err != nil {
		t.Fatalf("SetMeshCIDRs: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	got := readPersistedMeshGateways(dbPath)
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("readPersistedMeshGateways = %v, want %v", got, want)
	}
	// 端到端：读回的快照能直接驱动 sticky 选择。
	if sub, sticky := chooseTUNSubnet(stickyPoolV4, got, true); !sticky || sub != "10.202.0.0/16" {
		t.Fatalf("落库快照未生效: got %s sticky=%v", sub, sticky)
	}
}
