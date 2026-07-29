package main

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/nanotun/server/config"
)

// SIGHUP 热重载的失败面。
//
// 这里每一条都是同一种形状:**运维收到「已生效」,而实际没生效**。SIGHUP 没有返回值,唯一的
// 反馈就是日志和 applied/deferred 两个列表,所以「把失败记成 applied」是这条路径上最坏的 bug ——
// 它比崩溃更糟,因为崩溃至少会被发现。
//
// 第二十三轮在跳板机防火墙这条路上修过两处(一处 HIGH、一处 MED),但两处都没有回归测试。
// 本文件先把它们钉住。

func reloadStateWithFW(t *testing.T, cur *config.Config) *reloadState {
	t.Helper()
	return &reloadState{configPath: "fake.toml", cfg: cur, jumpFW: newJumpHostFirewall(true, 8080)}
}

// 第二十三轮 HIGH 的回归:刷规则失败时不许记成已应用,而且**内存里的旧名单不能被改**。
//
// 旧名单一旦被改,下一次同样的 SIGHUP 会因为「集合相等」整段跳过 —— 于是受保护端口敞开着,
// 运维手里是一份「已热更新」的成功回报,而且再 reload 多少次都不会重试,一直维持到重启。
func TestApplyConfigReload_AFailedFirewallApplyIsNeitherAppliedNorForgotten(t *testing.T) {
	f := installFakeIPT(t)
	f.failOn("ipset flush", errors.New("ipset 不可用")) // Replace 走回滚并回错
	cur := newReloadCfg()
	rs := reloadStateWithFW(t, &cur)
	newList := []string{"10.0.0.1", "203.0.113.9"}
	loader := func(string) (config.Config, error) {
		nc := newReloadCfg()
		nc.Server.JumpHostAllowedIPs = newList
		return nc, nil
	}

	applied, deferred := applyConfigReload(rs, loader)
	if slices.Contains(applied, "server.jump_host_allowed_ips") {
		t.Fatal("刷规则失败却记成了已应用 —— 运维据此认为受保护端口已限制到名单内,实际对全网敞开")
	}
	if !slices.ContainsFunc(deferred, func(s string) bool {
		return strings.Contains(s, "jump_host_allowed_ips") && strings.Contains(s, "应用失败")
	}) {
		t.Fatalf("deferred 里应说明是应用失败: %v", deferred)
	}
	if got := cur.Server.JumpHostAllowedIPs; !slices.Equal(got, []string{"10.0.0.1", "10.0.0.2"}) {
		t.Fatalf("失败时内存名单被改成了 %v —— 下一次相同的 SIGHUP 会因「集合相等」整段跳过,再也不重试", got)
	}

	// 第二次同样的 SIGHUP 必须仍然尝试(而不是认为没变化就跳过)。
	_, deferred2 := applyConfigReload(rs, loader)
	if !slices.ContainsFunc(deferred2, func(s string) bool {
		return strings.Contains(s, "jump_host_allowed_ips")
	}) {
		t.Fatalf("第二次 reload 应当继续重试并继续报 deferred,实际 %v", deferred2)
	}
}

// 第二十三轮 MED 的回归:SIGHUP 必须自己重跑 ValidateJumpHostFirewall。
//
// SIGHUP 走的 loadConfig 只做 Validate(),不含这条启动期校验。于是把名单改成一堆非法项
// (误写 CIDR / 主机名 / 拼错)之后 reload,runtime 的 sanitize 会把它们全丢掉,只剩
// ensureLoopbackIPv4Allowlist 补的 127.0.0.1 —— 真正的跳板机在受保护端口上被静默挡死。
// 同一份配置冷启动会直接 Fatal,热更新却悄悄生效,两边口径必须一致。
func TestApplyConfigReload_AnInvalidAllowlistIsRefusedNotSilentlySanitized(t *testing.T) {
	f := installFakeIPT(t)
	cur := newReloadCfg()
	rs := reloadStateWithFW(t, &cur)
	loader := func(string) (config.Config, error) {
		nc := newReloadCfg()
		// 三种最常见的手误:CIDR、主机名、拼错的地址。runtime 会把它们全部静默丢弃。
		nc.Server.JumpHostAllowedIPs = []string{"10.0.0.0/24", "jump.example.com", "10.0.0.300"}
		return nc, nil
	}

	applied, deferred := applyConfigReload(rs, loader)
	if slices.Contains(applied, "server.jump_host_allowed_ips") {
		t.Fatal("一份全是非法条目的名单被当成热更新成功了")
	}
	if !slices.ContainsFunc(deferred, func(s string) bool {
		return strings.Contains(s, "jump_host_allowed_ips") && strings.Contains(s, "校验未通过")
	}) {
		t.Fatalf("deferred 里应说明是校验未通过: %v", deferred)
	}
	if got := cur.Server.JumpHostAllowedIPs; !slices.Equal(got, []string{"10.0.0.1", "10.0.0.2"}) {
		t.Fatalf("校验没过却动了现役名单: %v", got)
	}
	// 关键:根本不该去刷 ipset。刷了就意味着 sanitize 之后的「只剩 127.0.0.1」已经落到内核,
	// 跳板机此刻已经进不来了。
	for _, cmd := range f.log() {
		if strings.Contains(cmd, "ipset add") || strings.Contains(cmd, "ipset flush") {
			t.Fatalf("校验未通过却已经动了 ipset: %q", cmd)
		}
	}
}

// 没起 jumpFW 时改名单只能提示重启,不能装作改成了。
func TestApplyConfigReload_WithoutAFirewallTheListChangeIsDeferred(t *testing.T) {
	cur := newReloadCfg()
	rs := &reloadState{configPath: "fake.toml", cfg: &cur, jumpFW: nil}
	applied, deferred := applyConfigReload(rs, func(string) (config.Config, error) {
		nc := newReloadCfg()
		nc.Server.JumpHostAllowedIPs = []string{"10.0.0.7"}
		return nc, nil
	})
	if slices.Contains(applied, "server.jump_host_allowed_ips") {
		t.Fatal("jumpFW 没启用时不该记成已应用")
	}
	if !slices.ContainsFunc(deferred, func(s string) bool {
		return strings.Contains(s, "jumpFW 未启用")
	}) {
		t.Fatalf("应提示需要重启: %v", deferred)
	}
}

// ACL 快照刷不动时要如实报,不能默认「reload 一定成功」。
//
// 这条与控制面的 /reload 是同一个诉求:执法用的是内存快照,刷不动就意味着新规则没有约束力,
// 而 SIGHUP 的唯一反馈就是这两个列表。
func TestApplyConfigReload_AFailedACLRefreshIsReportedAsDeferred(t *testing.T) {
	st := newACLReloadStore(t)
	if _, err := reloadACLSnapshotFromStore(st); err != nil {
		t.Fatalf("先装一份好快照: %v", err)
	}
	if _, err := st.DB().ExecContext(t.Context(),
		`ALTER TABLE acl_pairs RENAME TO acl_pairs_gone`); err != nil {
		t.Fatalf("藏掉 acl_pairs: %v", err)
	}

	cur := newReloadCfg()
	rs := &reloadState{configPath: "fake.toml", cfg: &cur,
		jumpFW: newJumpHostFirewall(false, 8080), store: st}

	applied, deferred := applyConfigReload(rs, func(string) (config.Config, error) {
		return newReloadCfg(), nil
	})
	if slices.Contains(applied, "acl_rules") {
		t.Fatal("ACL 快照刷失败却记成了已应用")
	}
	if !slices.Contains(deferred, "acl_rules(load_error)") {
		t.Fatalf("应在 deferred 里报 acl_rules 刷新失败: %v", deferred)
	}
}

// store 正常时 ACL 每次 SIGHUP 都要刷一遍(它没有 diff 概念,是无条件重拉)。
func TestApplyConfigReload_ACLIsRefreshedOnEverySIGHUP(t *testing.T) {
	st := newACLReloadStore(t)
	cur := newReloadCfg()
	rs := &reloadState{configPath: "fake.toml", cfg: &cur,
		jumpFW: newJumpHostFirewall(false, 8080), store: st}
	loader := func(string) (config.Config, error) { return newReloadCfg(), nil }

	for i := 0; i < 2; i++ {
		applied, _ := applyConfigReload(rs, loader)
		if !slices.Contains(applied, "acl_rules") {
			t.Fatalf("第 %d 次 SIGHUP 没刷 ACL: %v", i+1, applied)
		}
	}
}

// per-IP 登录限速改完要立刻生效,而不是等到重启。
func TestApplyConfigReload_LoginRateLimitTakesEffectAtOnce(t *testing.T) {
	prev := globalLoginIPLimiter.ratePerMin.Load()
	t.Cleanup(func() { globalLoginIPLimiter.SetRatePerMin(int(prev)) })

	cur := newReloadCfg()
	cur.Server.LoginRateLimitPerMin = 0
	rs := &reloadState{configPath: "fake.toml", cfg: &cur, jumpFW: newJumpHostFirewall(false, 8080)}

	applied, _ := applyConfigReload(rs, func(string) (config.Config, error) {
		nc := newReloadCfg()
		nc.Server.LoginRateLimitPerMin = 1
		return nc, nil
	})
	if !slices.Contains(applied, "server.login_rate_limit_per_min") {
		t.Fatalf("应记为已热更: %v", applied)
	}
	if got := globalLoginIPLimiter.ratePerMin.Load(); got != 1 {
		t.Fatalf("限速器没换成新速率,实际 %d —— 配置说改了但拦不住", got)
	}
	if cur.Server.LoginRateLimitPerMin != 1 {
		t.Fatal("内存配置没同步,下一次 reload 会以为没变过")
	}
}

// 传进来的东西不全时安静退出:SIGHUP 处理器崩了会连带整个进程。
func TestApplyConfigReload_IncompleteStateIsANoOp(t *testing.T) {
	called := false
	loader := func(string) (config.Config, error) { called = true; return config.Config{}, nil }

	if a, d := applyConfigReload(nil, loader); a != nil || d != nil {
		t.Fatal("nil state 应返回空")
	}
	if a, d := applyConfigReload(&reloadState{configPath: "x"}, loader); a != nil || d != nil {
		t.Fatal("没有当前配置时应返回空")
	}
	if called {
		t.Fatal("状态不全时不该去读配置文件")
	}
}

// 读不到新配置时保留旧值,并且什么都不许标成已应用。
func TestApplyConfigReload_ALoaderErrorChangesNothing(t *testing.T) {
	cur := newReloadCfg()
	rs := reloadStateWithFW(t, &cur)
	applied, deferred := applyConfigReload(rs, func(string) (config.Config, error) {
		return config.Config{}, errors.New("配置文件被改坏了")
	})
	if applied != nil || deferred != nil {
		t.Fatalf("加载失败时两个列表都该是空的: applied=%v deferred=%v", applied, deferred)
	}
	if cur.Log.Level != "info" || len(cur.Server.JumpHostAllowedIPs) != 2 {
		t.Fatalf("加载失败却动了现役配置: %+v", cur.Server)
	}
}
