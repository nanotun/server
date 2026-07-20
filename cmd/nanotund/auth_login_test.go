package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/nanotun/server/auth"
	"github.com/nanotun/server/config"
	"github.com/nanotun/server/store"
	"github.com/nanotun/server/util"
)

// newPSKGateway 拼一个 PSK 模式的 gatewayState 给测试用，不需要监听网络。
func newPSKGateway(t *testing.T) (*gatewayState, *store.Store) {
	t.Helper()
	ctx := t.Context()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "psk.db"), store.Options{})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	cfg := &config.Config{}
	gw := &gatewayState{
		cfg:          cfg,
		store:        st,
		authVerifier: auth.NewVerifier(st),
	}
	return gw, st
}

func TestAuthenticateLogin_PSKSuccess(t *testing.T) {
	gw, st := newPSKGateway(t)
	ctx := t.Context()

	hash, err := auth.HashPSK("super-secret")
	if err != nil {
		t.Fatal(err)
	}
	u, err := st.CreateUser(ctx, store.NewUser{Username: "alice", PSKHash: hash})
	if err != nil {
		t.Fatal(err)
	}

	// 用合法的 RFC 4122 v4 UUID;authenticatePSK 现在会拒绝非 v4 串。
	const deviceUUID = "11111111-2222-4333-8444-555555555555"
	req := &util.LoginReq{
		Name:       "alice",
		Token:      "super-secret",
		Platform:   "darwin",
		DeviceUUID: deviceUUID,
		DeviceName: "alice-mac",
	}
	res, authErr := authenticateLogin(gw, req, "conn-1")
	if authErr != nil {
		t.Fatalf("authenticateLogin err = %+v", authErr)
	}
	if res.UserID != "u"+itoa(u.ID) {
		t.Fatalf("UserID = %q, want u%d", res.UserID, u.ID)
	}
	if res.User == nil || res.Device == nil {
		t.Fatalf("expected User and Device populated, got %+v", res)
	}
	if res.Device.DeviceUUID != deviceUUID {
		t.Fatalf("device uuid = %q, want %q", res.Device.DeviceUUID, deviceUUID)
	}
}

// 平台白名单(2026-07-18):user.AllowedPlatforms 非空时,只有其中列出的平台能登录,
// 不命中(含上报空平台)→ CodePlatformNotAllowed(910)。空白名单 = 不限,任何平台
// (含空)放行 —— 老 user / 默认新建 user 走这条。
func TestAuthenticateLogin_PlatformAllowlist(t *testing.T) {
	gw, st := newPSKGateway(t)
	ctx := t.Context()

	hash, _ := auth.HashPSK("p")
	// 设了白名单:只允许 macos / ios。
	if _, err := st.CreateUser(ctx, store.NewUser{
		Username: "restricted", PSKHash: hash, AllowedPlatforms: "macos,ios",
	}); err != nil {
		t.Fatal(err)
	}
	// 不设白名单(默认新建):不限。
	if _, err := st.CreateUser(ctx, store.NewUser{Username: "open", PSKHash: hash}); err != nil {
		t.Fatal(err)
	}

	// 白名单外平台 → 拒 910。
	if _, authErr := authenticateLogin(gw, &util.LoginReq{
		Name: "restricted", Token: "p", Platform: "router",
	}, "c1"); authErr == nil || authErr.code != util.CodePlatformNotAllowed {
		t.Fatalf("router 应被拒 910, got %+v", authErr)
	}
	// 白名单内平台 → 放行(大小写不敏感)。
	if _, authErr := authenticateLogin(gw, &util.LoginReq{
		Name: "restricted", Token: "p", Platform: "MacOS",
	}, "c2"); authErr != nil {
		t.Fatalf("macos 应放行, got %+v", authErr)
	}
	// 已设白名单但上报空平台 → 拒(无法证明合规)。
	if _, authErr := authenticateLogin(gw, &util.LoginReq{
		Name: "restricted", Token: "p", Platform: "",
	}, "c3"); authErr == nil || authErr.code != util.CodePlatformNotAllowed {
		t.Fatalf("空平台在有白名单时应被拒 910, got %+v", authErr)
	}
	// 未设白名单 → 任何平台(含空)放行。
	for _, p := range []string{"router", "windows", ""} {
		if _, authErr := authenticateLogin(gw, &util.LoginReq{
			Name: "open", Token: "p", Platform: p,
		}, "c-open"); authErr != nil {
			t.Fatalf("open 用户 platform=%q 应放行, got %+v", p, authErr)
		}
	}
}

// 客户端送来非 v4 形态的 device_uuid（老 bug / 恶意伪造）时，authenticatePSK 应当
// 按「未提供」降级：登录继续，Device 为 nil，不污染 devices 表。
func TestAuthenticateLogin_PSKInvalidDeviceUUIDDegrades(t *testing.T) {
	gw, st := newPSKGateway(t)
	ctx := t.Context()

	hash, _ := auth.HashPSK("p")
	if _, err := st.CreateUser(ctx, store.NewUser{Username: "u", PSKHash: hash}); err != nil {
		t.Fatal(err)
	}

	bad := []string{
		"uuid-1",                               // 短串
		"garbage-not-a-uuid",                   // 格式错
		"11111111-2222-1333-8444-555555555555", // version=1
		"11111111-2222-4333-7444-555555555555", // variant=7
	}
	for _, b := range bad {
		res, authErr := authenticateLogin(gw, &util.LoginReq{
			Name: "u", Token: "p", DeviceUUID: b,
		}, "c")
		if authErr != nil {
			t.Fatalf("invalid uuid %q should NOT fail login: %+v", b, authErr)
		}
		if res.Device != nil {
			t.Fatalf("invalid uuid %q should degrade to Device=nil, got %+v", b, res.Device)
		}
	}

	// 没有任何脏 device 行留在 DB 里。
	devs, err := st.ListDevicesByUser(ctx, 1)
	if err != nil {
		t.Fatalf("ListDevicesByUser: %v", err)
	}
	if len(devs) != 0 {
		t.Fatalf("expected no devices, got %d: %+v", len(devs), devs)
	}
}

// 大小写不同的 device_uuid 应归一到同一 device 行（避免 fixed VIP 因大小写失配）。
func TestAuthenticateLogin_PSKDeviceUUIDCaseInsensitive(t *testing.T) {
	gw, st := newPSKGateway(t)
	ctx := t.Context()

	hash, _ := auth.HashPSK("p")
	if _, err := st.CreateUser(ctx, store.NewUser{Username: "u", PSKHash: hash}); err != nil {
		t.Fatal(err)
	}

	const upper = "AAAAAAAA-BBBB-4CCC-9DDD-EEEEEEEEEEEE"
	const lower = "aaaaaaaa-bbbb-4ccc-9ddd-eeeeeeeeeeee"

	res1, _ := authenticateLogin(gw, &util.LoginReq{Name: "u", Token: "p", DeviceUUID: upper}, "c1")
	if res1.Device == nil {
		t.Fatalf("upper case uuid should still produce a device row")
	}
	if res1.Device.DeviceUUID != lower {
		t.Fatalf("device uuid should be normalized lower, got %q", res1.Device.DeviceUUID)
	}

	res2, _ := authenticateLogin(gw, &util.LoginReq{Name: "u", Token: "p", DeviceUUID: lower}, "c2")
	if res2.Device == nil || res2.Device.ID != res1.Device.ID {
		t.Fatalf("upper / lower should land on the same device row; got id %v vs %v", res2.Device, res1.Device)
	}

	devs, _ := st.ListDevicesByUser(ctx, 1)
	if len(devs) != 1 {
		t.Fatalf("expected exactly 1 device after case-different upserts, got %d", len(devs))
	}
}

// 2026-07-18 GL-MT3000 事故回归门：合法 device_uuid + UpsertDevice 失败(部署重启窗口
// DB 不可写)时,登录必须被**拒绝**(CodeServerError,客户端会退避重连),而不是旧行为
// 「降级匿名继续」—— 匿名会话丢固定 vIP、出口路由声明被拒,且客户端隧道是通的,
// 不会主动重连,故障静默持续到人工干预。
//
// 用 ReadOnly store 模拟「读得到用户(VerifyLogin 只读)、写不进 device」的窗口状态。
func TestAuthenticateLogin_UpsertFailRejectsLogin(t *testing.T) {
	ctx := t.Context()
	dbPath := filepath.Join(t.TempDir(), "psk_ro.db")

	rw, err := store.Open(ctx, dbPath, store.Options{})
	if err != nil {
		t.Fatalf("store.Open RW: %v", err)
	}
	if err := rw.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	hash, _ := auth.HashPSK("p")
	if _, err := rw.CreateUser(ctx, store.NewUser{Username: "u", PSKHash: hash}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := rw.Close(); err != nil {
		t.Fatalf("Close RW: %v", err)
	}

	ro, err := store.Open(ctx, dbPath, store.Options{ReadOnly: true})
	if err != nil {
		t.Fatalf("store.Open RO: %v", err)
	}
	t.Cleanup(func() { _ = ro.Close() })
	gw := &gatewayState{cfg: &config.Config{}, store: ro, authVerifier: auth.NewVerifier(ro)}

	_, authErr := authenticateLogin(gw, &util.LoginReq{
		Name: "u", Token: "p",
		DeviceUUID: "11111111-2222-4333-8444-555555555555",
	}, "c")
	if authErr == nil {
		t.Fatal("upsert 失败的登录应被拒绝,不能降级匿名继续")
	}
	if authErr.code != util.CodeServerError {
		t.Fatalf("code = %d, want %d (CodeServerError,客户端可重试)", authErr.code, util.CodeServerError)
	}

	// 对照:没上报 device_uuid 的匿名登录不碰 devices 表,RO store 下应照常成功。
	res, authErr := authenticateLogin(gw, &util.LoginReq{Name: "u", Token: "p"}, "c2")
	if authErr != nil {
		t.Fatalf("匿名登录不应受 upsert 拒绝逻辑影响: %+v", authErr)
	}
	if res.Device != nil {
		t.Fatalf("匿名登录 Device 应为 nil, got %+v", res.Device)
	}
}

// upsertLoginDevice 的原地重试必须用**独立** ctx:生产事故里首次失败的典型原因就是
// 登录 ctx 预算耗尽(context deadline exceeded),若重试继承原 ctx 则必然立刻再失败,
// 重试形同虚设。这里用「已取消的 ctx」触发首次失败,断言重试仍能成功。
func TestUpsertLoginDevice_RetryUsesFreshContext(t *testing.T) {
	gw, st := newPSKGateway(t)
	ctx := t.Context()

	u, err := st.CreateUser(ctx, store.NewUser{Username: "u", PSKHash: "h"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	deadCtx, cancel := context.WithCancel(context.Background())
	cancel() // 模拟登录 ctx 预算被 argon2 verify / DB busy 耗尽

	const uuid = "aaaaaaaa-bbbb-4ccc-9ddd-eeeeeeeeeeee"
	dev, err := upsertLoginDevice(deadCtx, gw, u.ID, uuid, "dev", "linux")
	if err != nil {
		t.Fatalf("首次 ctx 已死但重试走独立 ctx,应当成功: %v", err)
	}
	if dev == nil || dev.DeviceUUID != uuid {
		t.Fatalf("dev = %+v, want uuid %q", dev, uuid)
	}
}

func TestAuthenticateLogin_PSKBadCred(t *testing.T) {
	gw, st := newPSKGateway(t)
	ctx := t.Context()

	hash, _ := auth.HashPSK("right-pass")
	if _, err := st.CreateUser(ctx, store.NewUser{Username: "u1", PSKHash: hash}); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name     string
		req      *util.LoginReq
		wantCode int
	}{
		{"unknown user", &util.LoginReq{Name: "ghost", Token: "x"}, util.CodeUserNotFound},
		{"bad psk", &util.LoginReq{Name: "u1", Token: "wrong"}, util.CodeTokenInvalid},
		{"empty fields", &util.LoginReq{Name: "", Token: ""}, util.CodeTokenInvalid},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, authErr := authenticateLogin(gw, c.req, "conn-x")
			if authErr == nil {
				t.Fatalf("expected error")
			}
			if authErr.code != c.wantCode {
				t.Fatalf("code = %d, want %d", authErr.code, c.wantCode)
			}
		})
	}
}

// PSK 模式下若 store / authVerifier 未初始化(配置漂移 / 测试场景兜底),
// authenticateLogin 应当返回 CodeServerError 而不是 panic。
func TestAuthenticateLogin_NoStore(t *testing.T) {
	gw := &gatewayState{cfg: &config.Config{}}
	_, authErr := authenticateLogin(gw, &util.LoginReq{Name: "x", Token: "y"}, "c")
	if authErr == nil {
		t.Fatalf("expected error when store is nil")
	}
	if authErr.code != util.CodeServerError {
		t.Fatalf("code = %d, want %d", authErr.code, util.CodeServerError)
	}
}

func TestAuthenticateLogin_PSKNoDevice(t *testing.T) {
	// 客户端没上报 device_uuid 时仍可登录，仅 device 为 nil。
	gw, st := newPSKGateway(t)
	ctx := t.Context()

	hash, _ := auth.HashPSK("p")
	if _, err := st.CreateUser(ctx, store.NewUser{Username: "u", PSKHash: hash}); err != nil {
		t.Fatal(err)
	}

	res, authErr := authenticateLogin(gw, &util.LoginReq{Name: "u", Token: "p"}, "c")
	if authErr != nil {
		t.Fatalf("authenticateLogin: %+v", authErr)
	}
	if res.Device != nil {
		t.Fatalf("expected nil device when device_uuid empty, got %+v", res.Device)
	}
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	out := []byte{}
	for n > 0 {
		out = append([]byte{byte('0' + n%10)}, out...)
		n /= 10
	}
	return string(out)
}

// K2 单测：auditActionForLoginCode 把已知 code 映射成细分 action;未知 code 走兜底。
// 测点是「2026-05-21 事故里那条 code=403」必须走 login.fail.user_not_found,
// 这样 `nanotun-admin audit list --action login.fail.user_not_found` 才能命中。
func TestAuditActionForLoginCode(t *testing.T) {
	cases := []struct {
		code int
		want string
	}{
		{util.CodeOK, "login.success"},
		{util.CodeUserNotFound, "login.fail.user_not_found"},
		{util.CodeTokenInvalid, "login.fail.bad_psk"},
		{util.CodeUserBlacklisted, "login.fail.user_disabled"},
		{util.CodeServerError, "login.fail.server_error"},
		{999, "login.fail"},
	}
	for _, c := range cases {
		if got := auditActionForLoginCode(c.code); got != c.want {
			t.Errorf("code=%d: got %q, want %q", c.code, got, c.want)
		}
	}
}

// K2 单测：user_not_found 速率聚合
//
//   - 60s 窗口内 < 阈值 → 不触发 ERROR
//   - 60s 窗口内 ≥ 阈值 → 在下一次跨窗口调用时触发 1 次 ERROR
//   - 触发后 counter 清零,下一窗口重新积累
//
// 用 fake clock 让窗口在不真等 60s 的情况下推进。
func TestNoteLoginUserNotFound_RateThreshold(t *testing.T) {
	loginUserNotFoundBucket = rateBucket{}

	base := time.Unix(1_700_000_000, 0)
	now := base
	nowFn := func() time.Time { return now }

	for i := 0; i < 5; i++ {
		if triggered := noteLoginUserNotFound(nowFn); triggered {
			t.Fatalf("under threshold should not trigger (i=%d)", i)
		}
	}
	now = base.Add(61 * time.Second)
	if triggered := noteLoginUserNotFound(nowFn); triggered {
		t.Fatal("5 hits / window 应低于阈值,不应触发")
	}

	for i := 0; i < userNotFoundWarnThreshold; i++ {
		if triggered := noteLoginUserNotFound(nowFn); triggered {
			t.Fatalf("窗口内不应触发(只在跨窗口结算时打 ERROR), i=%d", i)
		}
	}
	now = base.Add(122 * time.Second)
	if triggered := noteLoginUserNotFound(nowFn); !triggered {
		t.Fatal("应该触发:上一窗口累计 ≥ 阈值")
	}

	now = base.Add(183 * time.Second)
	if triggered := noteLoginUserNotFound(nowFn); triggered {
		t.Fatal("新窗口仅 1 次,counter 清零后不应再触发")
	}
}
