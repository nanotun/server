package main

import (
	"errors"
	"slices"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/nanotun/server/config"
)

func newReloadCfg() config.Config {
	c := config.Config{}
	c.Log.Level = "info"
	c.Server.ListenAddr = ":8080"
	c.Server.JumpHostFirewall = true
	c.Server.JumpHostAllowedIPs = []string{"10.0.0.1", "10.0.0.2"}
	return c
}

// G6 单测 a:log.level 热更新成功,old 字段被覆盖,deferred 为空。
func TestApplyConfigReload_LogLevel(t *testing.T) {
	cur := newReloadCfg()
	rs := &reloadState{configPath: "fake.toml", cfg: &cur, jumpFW: newJumpHostFirewall(false, 8080)}

	prevLvl := logrus.GetLevel()
	defer logrus.SetLevel(prevLvl)

	loader := func(path string) (config.Config, error) {
		nc := newReloadCfg()
		nc.Log.Level = "debug"
		return nc, nil
	}
	applied, deferred := applyConfigReload(rs, loader)
	if !slices.Contains(applied, "log.level") {
		t.Fatalf("expected log.level in applied, got %v", applied)
	}
	if logrus.GetLevel() != logrus.DebugLevel {
		t.Fatalf("logrus level: got %v, want debug", logrus.GetLevel())
	}
	if cur.Log.Level != "debug" {
		t.Fatalf("cur.Log.Level not updated: %q", cur.Log.Level)
	}
	if len(deferred) != 0 {
		t.Fatalf("expected no deferred, got %v", deferred)
	}
}

// G6 单测 b:log.level 设成无效字符串 —— 保留旧值,不更新内部状态。
func TestApplyConfigReload_LogLevelInvalid_KeepsOld(t *testing.T) {
	cur := newReloadCfg()
	rs := &reloadState{configPath: "fake.toml", cfg: &cur, jumpFW: newJumpHostFirewall(false, 8080)}

	prevLvl := logrus.GetLevel()
	logrus.SetLevel(logrus.InfoLevel)
	defer logrus.SetLevel(prevLvl)

	loader := func(path string) (config.Config, error) {
		nc := newReloadCfg()
		nc.Log.Level = "notalevel"
		return nc, nil
	}
	applied, _ := applyConfigReload(rs, loader)
	if slices.Contains(applied, "log.level") {
		t.Fatalf("invalid log.level 不应当作 applied,got %v", applied)
	}
	if cur.Log.Level != "info" {
		t.Fatalf("cur.Log.Level 应保留 info,got %q", cur.Log.Level)
	}
	if logrus.GetLevel() != logrus.InfoLevel {
		t.Fatalf("logrus level 不应被 corrupt,got %v", logrus.GetLevel())
	}
}

// G6 单测 c:jump_host_allowed_ips 内容变了 → Replace 被调用,cfg 同步;
// 顺序变内容不变(集合相等)不应触发 Replace。
func TestApplyConfigReload_JumpHostAllowedIPs(t *testing.T) {
	cur := newReloadCfg()
	rs := &reloadState{configPath: "fake.toml", cfg: &cur, jumpFW: newJumpHostFirewall(true, 8080)}

	loader1 := func(path string) (config.Config, error) {
		nc := newReloadCfg()
		nc.Server.JumpHostAllowedIPs = []string{"10.0.0.2", "10.0.0.1"} // 顺序倒
		return nc, nil
	}
	applied, _ := applyConfigReload(rs, loader1)
	if slices.Contains(applied, "server.jump_host_allowed_ips") {
		t.Fatalf("集合相等(只换顺序)不应触发 Replace,got applied=%v", applied)
	}

	loader2 := func(path string) (config.Config, error) {
		nc := newReloadCfg()
		nc.Server.JumpHostAllowedIPs = []string{"10.0.0.1", "10.0.0.3"}
		return nc, nil
	}
	applied2, _ := applyConfigReload(rs, loader2)
	if !slices.Contains(applied2, "server.jump_host_allowed_ips") {
		t.Fatalf("内容变了应当 applied,got %v", applied2)
	}
	if len(cur.Server.JumpHostAllowedIPs) != 2 || cur.Server.JumpHostAllowedIPs[1] != "10.0.0.3" {
		t.Fatalf("cur 未同步新名单,got %v", cur.Server.JumpHostAllowedIPs)
	}
}

// G6 单测 d:jump_host_firewall=false 时改 IP 列表应当 deferred(开关切换需重启)。
func TestApplyConfigReload_JumpHostAllowedIPs_FirewallOffDeferred(t *testing.T) {
	cur := newReloadCfg()
	rs := &reloadState{configPath: "fake.toml", cfg: &cur, jumpFW: newJumpHostFirewall(true, 8080)}

	loader := func(path string) (config.Config, error) {
		nc := newReloadCfg()
		nc.Server.JumpHostFirewall = false
		nc.Server.JumpHostAllowedIPs = []string{"10.0.0.99"}
		return nc, nil
	}
	applied, deferred := applyConfigReload(rs, loader)
	if slices.Contains(applied, "server.jump_host_allowed_ips") {
		t.Fatalf("关闭 firewall 时不应 applied,got %v", applied)
	}
	if !slices.Contains(deferred, "server.jump_host_firewall(开关切换需重启)") {
		t.Fatalf("应该在 deferred 列出 jump_host_firewall 开关切换提示,got %v", deferred)
	}
}

// G6 单测 e:非热更新字段(listen_addr / tls / db)变了 → 全部进 deferred。
func TestApplyConfigReload_DeferredFields(t *testing.T) {
	cur := newReloadCfg()
	cur.Server.TLSCertFile = "/old/cert.pem"
	cur.Server.TLSKeyFile = "/old/key.pem"
	cur.Store.DBPath = "/var/lib/old.db"
	rs := &reloadState{configPath: "fake.toml", cfg: &cur, jumpFW: newJumpHostFirewall(false, 8080)}

	loader := func(path string) (config.Config, error) {
		nc := newReloadCfg()
		nc.Server.ListenAddr = ":9090"
		nc.Server.TLSCertFile = "/new/cert.pem"
		nc.Server.TLSKeyFile = "/new/key.pem"
		nc.Server.JumpHostFirewall = false
		nc.Hysteria.Password = "newpassword123456"
		nc.Hysteria.ListenAddr = ":444"
		nc.Reality.ListenAddr = ":9443"
		nc.Store.DBPath = "/var/lib/new.db"
		return nc, nil
	}
	_, deferred := applyConfigReload(rs, loader)

	wantContains := []string{
		"server.listen_addr",
		"server.tls_cert_file/tls_key_file",
		"server.jump_host_firewall",
		"hysteria.password",
		"hysteria.listen_addr",
		"reality.listen_addr",
		"store.db_path",
	}
	for _, w := range wantContains {
		if !slices.Contains(deferred, w) {
			t.Errorf("deferred 缺 %q,got %v", w, deferred)
		}
	}
	if cur.Server.ListenAddr != ":8080" {
		t.Errorf("cur.Server.ListenAddr 不应被改,got %q", cur.Server.ListenAddr)
	}
}

// G6 单测 f:loader 返回 error → 不更新任何状态,applied / deferred 都为 nil。
func TestApplyConfigReload_LoaderError_KeepsOldCfg(t *testing.T) {
	cur := newReloadCfg()
	rs := &reloadState{configPath: "missing.toml", cfg: &cur, jumpFW: newJumpHostFirewall(true, 8080)}

	loader := func(path string) (config.Config, error) {
		return config.Config{}, errors.New("simulated read failure")
	}
	applied, deferred := applyConfigReload(rs, loader)
	if len(applied) != 0 || len(deferred) != 0 {
		t.Fatalf("loader error 路径应早退,got applied=%v deferred=%v", applied, deferred)
	}
	if cur.Log.Level != "info" {
		t.Fatalf("cur 不应被改,got log.level=%q", cur.Log.Level)
	}
}

// P2#15:max_sessions_per_user 应加入白名单,reload 后立即生效(对未来登录)。
func TestApplyConfigReload_MaxSessionsPerUser_HotReload(t *testing.T) {
	cur := newReloadCfg()
	cur.Server.MaxSessionsPerUser = 5
	rs := &reloadState{configPath: "fake.toml", cfg: &cur, jumpFW: newJumpHostFirewall(false, 8080)}

	loader := func(path string) (config.Config, error) {
		nc := newReloadCfg()
		nc.Server.MaxSessionsPerUser = 12
		return nc, nil
	}
	applied, deferred := applyConfigReload(rs, loader)
	if !slices.Contains(applied, "server.max_sessions_per_user") {
		t.Fatalf("max_sessions_per_user 应在 applied 内,got applied=%v deferred=%v", applied, deferred)
	}
	if slices.Contains(deferred, "server.max_sessions_per_user") {
		t.Fatalf("max_sessions_per_user 不该再进 deferred,got %v", deferred)
	}
	if cur.Server.MaxSessionsPerUser != 12 {
		t.Fatalf("cur.Server.MaxSessionsPerUser 未热更,got %d", cur.Server.MaxSessionsPerUser)
	}
}

// P2#15:rate_limit_by_platform 字典替换应进 applied,且 cur 被换成新 map。
func TestApplyConfigReload_RateLimitByPlatform_HotReload(t *testing.T) {
	cur := newReloadCfg()
	cur.Server.RateLimitByPlatform = map[string]config.LinkRateLimitPlatform{
		"linux": {UploadRate: 100, DownloadRate: 200},
	}
	rs := &reloadState{configPath: "fake.toml", cfg: &cur, jumpFW: newJumpHostFirewall(false, 8080)}

	loader := func(path string) (config.Config, error) {
		nc := newReloadCfg()
		nc.Server.RateLimitByPlatform = map[string]config.LinkRateLimitPlatform{
			"linux":   {UploadRate: 500, DownloadRate: 200},
			"android": {UploadRate: 50, DownloadRate: 0},
		}
		return nc, nil
	}
	applied, _ := applyConfigReload(rs, loader)
	if !slices.Contains(applied, "server.rate_limit_by_platform") {
		t.Fatalf("rate_limit_by_platform 应在 applied,got %v", applied)
	}
	if cur.Server.RateLimitByPlatform["linux"].UploadRate != 500 {
		t.Fatalf("rate_limit linux 未热更,got %+v", cur.Server.RateLimitByPlatform["linux"])
	}
	if _, ok := cur.Server.RateLimitByPlatform["android"]; !ok {
		t.Fatal("新加 android key 应当存在")
	}

	// 二次 reload 同配置 → 应该不再标 applied。
	applied2, _ := applyConfigReload(rs, loader)
	if slices.Contains(applied2, "server.rate_limit_by_platform") {
		t.Fatalf("等价配置二次 reload 不应再 applied,got %v", applied2)
	}
}

// P2#15:user_invalidate_interval_sec / lease_gc_* / data_plane_ping_* 必须落
// deferred,且不更新 cur(防止"以为生效了实际没有")。
func TestApplyConfigReload_KnownNonHotFieldsDeferred(t *testing.T) {
	cur := newReloadCfg()
	cur.Server.UserInvalidateIntervalSec = 10
	cur.Server.LeaseGCIdleDays = 30
	cur.Server.LeaseGCIntervalHours = 24
	cur.Server.DataPlanePingMissThreshold = 3
	cur.Server.ControlSocketPath = "/run/old.sock"
	rs := &reloadState{configPath: "fake.toml", cfg: &cur, jumpFW: newJumpHostFirewall(false, 8080)}

	loader := func(path string) (config.Config, error) {
		nc := newReloadCfg()
		nc.Server.UserInvalidateIntervalSec = 30
		nc.Server.LeaseGCIdleDays = 90
		nc.Server.LeaseGCIntervalHours = 48
		nc.Server.DataPlanePingMissThreshold = 5
		nc.Server.ControlSocketPath = "/run/new.sock"
		return nc, nil
	}
	_, deferred := applyConfigReload(rs, loader)

	for _, w := range []string{
		"server.user_invalidate_interval_sec",
		"server.lease_gc_idle_days",
		"server.lease_gc_interval_hours",
		"server.data_plane_ping_miss_threshold",
		"server.control_socket_path",
	} {
		if !slices.Contains(deferred, w) {
			t.Errorf("deferred 缺 %q,got %v", w, deferred)
		}
	}
	// cur 不应被改 —— 让运维「真实生效值」永远等同于上次启动时塞 loop 的值。
	if cur.Server.UserInvalidateIntervalSec != 10 {
		t.Errorf("cur.UserInvalidateIntervalSec 不应被改,got %d", cur.Server.UserInvalidateIntervalSec)
	}
	if cur.Server.LeaseGCIdleDays != 30 {
		t.Errorf("cur.LeaseGCIdleDays 不应被改,got %d", cur.Server.LeaseGCIdleDays)
	}
}

// Round-4 deep scan:[server.pow] 段所有字段都不可热更。
// PoWService 启动时构造,hmac_key/公式参数全锁死,reload 改了必须 ERROR 提示并落
// deferred,防止运维"以为改了生效"踩坑。
func TestApplyConfigReload_PoWFieldsDeferred(t *testing.T) {
	cur := newReloadCfg()
	cur.Server.Pow.FailuresEnable = 0
	cur.Server.Pow.BaseDifficulty = 8
	cur.Server.Pow.RampDifficulty = 14
	cur.Server.Pow.StepPerFailure = 2
	cur.Server.Pow.AdaptiveCeiling = 22
	cur.Server.Pow.TTLSec = 300
	rs := &reloadState{configPath: "fake.toml", cfg: &cur, jumpFW: newJumpHostFirewall(false, 8080)}

	loader := func(path string) (config.Config, error) {
		nc := newReloadCfg()
		nc.Server.Pow.FailuresEnable = 3
		nc.Server.Pow.BaseDifficulty = 10
		nc.Server.Pow.RampDifficulty = 16
		nc.Server.Pow.StepPerFailure = 3
		nc.Server.Pow.AdaptiveCeiling = 20
		nc.Server.Pow.TTLSec = 600
		return nc, nil
	}
	_, deferred := applyConfigReload(rs, loader)

	for _, w := range []string{
		"server.pow.failures_enable",
		"server.pow.base_difficulty",
		"server.pow.ramp_difficulty",
		"server.pow.step_per_failure",
		"server.pow.adaptive_ceiling",
		"server.pow.ttl_sec",
	} {
		if !slices.Contains(deferred, w) {
			t.Errorf("deferred 缺 %q,got %v", w, deferred)
		}
	}
	// cur 的 PoW 字段不应被改 —— 真实运行中的 PoWService 仍用启动时的值。
	if cur.Server.Pow.BaseDifficulty != 8 {
		t.Errorf("cur.Pow.BaseDifficulty 不应被改,got %d", cur.Server.Pow.BaseDifficulty)
	}
	if cur.Server.Pow.TTLSec != 300 {
		t.Errorf("cur.Pow.TTLSec 不应被改,got %d", cur.Server.Pow.TTLSec)
	}
}

// G6 单测 g:同样的配置 reload → no-op。
func TestApplyConfigReload_NoChange(t *testing.T) {
	cur := newReloadCfg()
	rs := &reloadState{configPath: "fake.toml", cfg: &cur, jumpFW: newJumpHostFirewall(true, 8080)}

	loader := func(path string) (config.Config, error) {
		return newReloadCfg(), nil
	}
	applied, deferred := applyConfigReload(rs, loader)
	if len(applied) != 0 {
		t.Fatalf("unchanged reload 不应有 applied,got %v", applied)
	}
	if len(deferred) != 0 {
		t.Fatalf("unchanged reload 不应有 deferred,got %v", deferred)
	}
}
