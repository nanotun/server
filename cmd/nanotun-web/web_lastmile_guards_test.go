package main

// web_lastmile_guards_test.go(第二十轮最后一寸)—— 剩下这些分支各只有一两条语句,
// 但都在「熵源坏了」「同一族地址撞了」「列表比屏幕长」这类边界上。
//
// 它们的共同点是:出错时**不会有异常抛到面前**,只会给出一个看起来合理的结果 ——
// 一枚可预测的 2FA 密钥、一批默默没落库的恢复码、一台被抢了 vIP 的出口、一张
// 只列了 5 台设备却写着"全部"的仪表盘。所以这一寸必须钉死。

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nanotun/server/store"
	"github.com/nanotun/server/util"
)

// =========================================================================
// /me/totp/*:熵源坏了的时候,绝不能给出一个"能用"的密钥或恢复码
// =========================================================================

// 熵源故障时 2FA 必须开不起来。若此处兜底成一个可预测的 secret,用户会以为
// 自己开了 2FA —— 而任何知道这套兜底的人都能算出他的动态码。
func TestMeTOTPSetup_SecretGenerationFailureRefusesToEnroll(t *testing.T) {
	s, admin := meGuardEnv(t)
	req := mePost(t, s, admin, "/me/totp/setup", url.Values{"password": {mePassword}}, "")
	stubRandRead(t, 1) // 请求已构造完(CSRF 已签发),此后所有取随机数都失败

	w := httptest.NewRecorder()
	s.handleMeTOTPSetup(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
	}
	cur, err := s.store.GetWebAdmin(t.Context(), admin.ID)
	if err != nil {
		t.Fatalf("GetWebAdmin: %v", err)
	}
	if cur.TOTPSecret != "" {
		t.Fatalf("熵源坏了却把 secret=%q 写进了库", cur.TOTPSecret)
	}
}

// 恢复码生成失败时,2FA 不能被启用。启用了但没有恢复码,等于用户一换手机
// 就彻底进不来 —— 这是这套后台里最难自救的一种锁死。
func TestMeTOTPEnable_RecoveryGenerationFailureLeaves2FAOff(t *testing.T) {
	s, admin := meGuardEnv(t)
	secret := meBeginEnroll(t, s, admin)
	req := mePost(t, s, admin, "/me/totp/enable",
		url.Values{"code": {totpCodeFor(t, secret)}}, "")
	stubRandRead(t, 1)

	w := httptest.NewRecorder()
	s.handleMeTOTPEnable(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
	}
	cur, err := s.store.GetWebAdmin(t.Context(), admin.ID)
	if err != nil {
		t.Fatalf("GetWebAdmin: %v", err)
	}
	if cur.TOTPEnabled {
		t.Fatal("恢复码没生成出来,2FA 却被启用了 —— 换手机即锁死")
	}
}

// 恢复码明文只在这一次 POST 之后的 GET 里露一面。存不进 flash 就必须报错:
// 若退化成"启用成功但不展示",用户手上没有任何一张可用的应急码,而库里已经
// 是启用状态了。
func TestMeTOTPEnable_StashFailureIsLoudNotSilent(t *testing.T) {
	s, admin := meGuardEnv(t)
	secret := meBeginEnroll(t, s, admin)
	req := mePost(t, s, admin, "/me/totp/enable",
		url.Values{"code": {totpCodeFor(t, secret)}}, "")

	orig := flashGenerateToken
	flashGenerateToken = func() (string, error) { return "", errors.New("injected: no entropy") }
	t.Cleanup(func() { flashGenerateToken = orig })

	w := httptest.NewRecorder()
	s.handleMeTOTPEnable(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
	}
	// 这次失败要进审计:管理员事后必须能看出"启用过一次但没拿到码"。
	if !auditHasAction(t, s, "totp_enable_stash_failed") {
		t.Error("恢复码没能展示,审计里却没留下痕迹")
	}
}

// 重新生成恢复码时熵源坏了:旧码必须仍然有效(不能先作废再生成)。
func TestMeTOTPRegen_GenerationFailureKeepsOldCodesUsable(t *testing.T) {
	s, admin := meGuardEnv(t)
	secret, oldCodes := enrollTOTP(t, s, admin, mePassword)
	req := mePost(t, s, admin, "/me/totp/regen-codes",
		url.Values{"code": {totpCodeForStep(t, secret, 1)}}, "")
	stubRandRead(t, 1)

	w := httptest.NewRecorder()
	s.handleMeTOTPRegen(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
	}
	// 旧码还能用 —— 否则这次失败就把用户的应急入口一并烧掉了。
	if n, err := s.store.CountUnusedRecoveryCodes(t.Context(), admin.ID); err != nil {
		t.Fatalf("CountUnusedRecoveryCodes: %v", err)
	} else if int(n) != len(oldCodes) {
		t.Fatalf("剩 %d 条恢复码,期望旧的 %d 条都还在", n, len(oldCodes))
	}
}

// =========================================================================
// /routes:v6 也是一等公民
// =========================================================================

// 待批出口列表要分别标出 v4 / v6 两族。只认 v4 的话,一台只自荐了 ::/0 的设备
// 会显示成"没有任何待批路由",管理员在 UI 上无从批准。
func TestRouteList_PendingExitTracksBothFamilies(t *testing.T) {
	s := newRoutesGuardServer(t)
	d := routeDevice(t, s, "dualstack", "linux", "")
	for _, cidr := range []string{util.ExitDefaultRouteV4, util.ExitDefaultRouteV6} {
		mustAdvertiseRoute(t, s, d.ID, cidr)
	}

	w := httptest.NewRecorder()
	s.handleRouteList(w, adminGetReq("/routes"))
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d body=%q", w.Code, trimForLog(w.Body.String()))
	}
	body := w.Body.String()
	if !strings.Contains(body, "dualstack-box") {
		t.Fatal("待批出口卡里没有这台设备")
	}
	// 模板用 v4 / v6 两枚 pill 标注自荐了哪些族。
	for _, pill := range []string{`>v4<`, `>v6<`} {
		if !strings.Contains(body, pill) {
			t.Errorf("待批出口卡里没有 %s 标记 —— 管理员看不出这台自荐了哪一族", pill)
		}
	}
}

// 指定出口时,v6 的固定 vIP 冲突同样要拦住。只查 v4 的话,两台出口会被焊上
// 同一个 v6 地址,客户端路由表随后打起来(症状是间歇性丢包,极难归因)。
func TestExitDesignate_V6VIPConflictDegradesInsteadOfStealing(t *testing.T) {
	s := newRoutesGuardServer(t)
	// 先来一台把 v6 焊死的设备。
	holder := routeDevice(t, s, "holder", "linux", "")
	const sharedV6 = "fd00:42::2"
	if err := s.store.SetDeviceFixedVIP(t.Context(), holder.ID, "", sharedV6, false); err != nil {
		t.Fatalf("给 holder 钉 v6: %v", err)
	}
	// 候选设备的 lease 恰好拿到同一个 v6(v4 侧已固定,不参与冲突判定)。
	cand := routeDevice(t, s, "cand", "linux", "")
	if err := s.store.SetDeviceFixedVIP(t.Context(), cand.ID, "10.66.0.9", "", false); err != nil {
		t.Fatalf("给 cand 钉 v4: %v", err)
	}
	// lease 直接落库:store 层的 UpsertLease 本身就会拒掉这种撞车,而我们要测的
	// 恰恰是「库里已经有一条撞车 lease」时 designate 的表现(旧数据 / 并发留下的)。
	if _, err := s.store.UpsertLease(t.Context(), cand.ID, "10.66.0.9", "", false); err != nil {
		t.Fatalf("UpsertLease: %v", err)
	}
	if _, err := s.store.DB().ExecContext(t.Context(),
		`UPDATE leases SET vip_v6 = ? WHERE device_id = ?`, sharedV6, cand.ID); err != nil {
		t.Fatalf("直接改 lease 的 v6: %v", err)
	}

	w := httptest.NewRecorder()
	s.handleExitAction(w, exitActionReq(t, "designate",
		url.Values{"device_id": {itoa(cand.ID)}}))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("code=%d body=%q, 期望 303(出口照批、vIP 降级)", w.Code, trimForLog(w.Body.String()))
	}
	// 出口路由要批下来。
	if got := routeStatusOrEmpty(t, s, cand.ID, util.ExitDefaultRouteV4); got != store.RouteStatusApproved {
		t.Errorf("v4 默认路由 status=%q, 期望 approved", got)
	}
	// 但那个 v6 绝不能被抢走。
	after, err := s.store.GetDevice(t.Context(), cand.ID)
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if after.FixedVIPv6 == sharedV6 {
		t.Fatalf("v6 冲突没拦住,%s 被从 holder 那里抢过来了", sharedV6)
	}
	holderAfter, err := s.store.GetDevice(t.Context(), holder.ID)
	if err != nil {
		t.Fatalf("GetDevice(holder): %v", err)
	}
	if holderAfter.FixedVIPv6 != sharedV6 {
		t.Fatalf("holder 的 v6 变成了 %q —— 原主人的地址被动了", holderAfter.FixedVIPv6)
	}
}

// =========================================================================
// 其余零散边界
// =========================================================================

// 仪表盘只放得下 5 条会话。不截断的话,一台跑着几千会话的服务器会把整页
// HTML 撑到几 MB,首页直接打不开 —— 而首页恰恰是出事时第一个要打开的页面。
func TestDashboard_TrimsSessionListToWhatFitsOnThePage(t *testing.T) {
	s := newMeTestServer(t)
	var rows []string
	for i := 0; i < 9; i++ {
		rows = append(rows, `{"conn_id":"sess-`+itoa(int64(i))+`","user_id":"u1"}`)
	}
	routes := controlOK()
	body := `{"ok":true,"sessions":[` + strings.Join(rows, ",") + `],"sessions_total":9}`
	routes["/status"] = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}
	s.control = newFakeControl(t, routes).client

	w := httptest.NewRecorder()
	s.handleDashboard(w, adminGetReq("/"))
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d body=%q", w.Code, trimForLog(w.Body.String()))
	}
	page := w.Body.String()
	if !strings.Contains(page, "sess-0") {
		t.Fatal("最近会话一条都没渲染出来")
	}
	if strings.Contains(page, "sess-8") {
		t.Fatal("9 条会话全渲染了 —— 首页会被大集群撑爆")
	}
	// 总数仍要报 9:截断的是列表,不是事实。
	if !strings.Contains(page, "9") {
		t.Error("页面上看不到会话总数 9")
	}
}

// 同一个用户的多条会话只查一次库。缓存没生效时,一页 200 条会话就是 200 次
// GetUser —— 会话列表是每 2 秒自动刷新的页面,这类放大很快就压到库上。
// 这里只能从结果侧断言:两行都要带上用户名(第二行走的是缓存分支)。
func TestSessionsView_SameUserAcrossSessionsGetsAName(t *testing.T) {
	s := newMeTestServer(t)
	u := newPRGTestUser(t, s, "repeat-user")
	uid := "u" + itoa(u.ID)
	routes := controlOK()
	routes["/status"] = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"sessions":[` +
			`{"conn_id":"c1","user_id":"` + uid + `"},` +
			`{"conn_id":"c2","user_id":"` + uid + `"}` +
			`]}`))
	}
	s.control = newFakeControl(t, routes).client

	views, err := s.collectSessionsForView(t.Context())
	if err != nil {
		t.Fatalf("collectSessionsForView: %v", err)
	}
	if len(views) != 2 {
		t.Fatalf("拿到 %d 行会话,期望 2", len(views))
	}
	for i, v := range views {
		if v.Username != "repeat-user" {
			t.Errorf("第 %d 行 username=%q, 期望 repeat-user(同一用户的第二行也要有名字)", i, v.Username)
		}
		if v.StoreUserID != u.ID {
			t.Errorf("第 %d 行 StoreUserID=%d, 期望 %d", i, v.StoreUserID, u.ID)
		}
	}
}

// 采样宿主机指标出的**非** unsupported 错误(/proc 读不动、cgroup 布局意外),
// 要回错误横幅 + 服务端日志,而不是静默给一份空指标 —— 空指标在前端看起来
// 就是"负载 0",与真实的高负载完全相反。
func TestSysmonData_HostSampleFailureSurfacesAsBanner(t *testing.T) {
	s, _ := pfServer(t)
	orig := sysmonSample
	sysmonSample = func() (*SysmonSnapshot, error) {
		return nil, errors.New("injected: /proc/stat 读不动")
	}
	t.Cleanup(func() { sysmonSample = orig })

	w := httptest.NewRecorder()
	s.handleSysmonData(w, adminGetReq("/sysmon/data"))
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d, 期望 200(带错误字段的 JSON)", w.Code)
	}
	if !strings.Contains(w.Body.String(), "host_error") {
		t.Fatalf("响应里没有 host_error,前端会把它当成一切正常: %s", trimForLog(w.Body.String()))
	}
}

// 采样成功时那份快照必须真的进到响应里。丢掉的话前端拿到一份"没有 host 字段"
// 的 JSON,画出来与"采样失败"无从区分 —— 监控页从此永远是空的。
func TestSysmonData_SuccessfulSampleReachesTheResponse(t *testing.T) {
	s, _ := pfServer(t)
	orig := sysmonSample
	sysmonSample = func() (*SysmonSnapshot, error) {
		return &SysmonSnapshot{CPUCores: 42, MemTotalBytes: 1 << 30}, nil
	}
	t.Cleanup(func() { sysmonSample = orig })

	w := httptest.NewRecorder()
	s.handleSysmonData(w, adminGetReq("/sysmon/data"))
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, `"cpu_cores":42`) {
		t.Fatalf("采到的指标没进响应: %s", trimForLog(body))
	}
	if strings.Contains(body, "host_error") {
		t.Fatalf("采样成功却带了错误字段: %s", trimForLog(body))
	}
}

// 图形验证码:题面画得出来但 nonce 取不到随机数时必须整体失败。
// 若退化成固定 nonce,同一个 cookie 就能被反复重放,验证码等于不存在。
func TestIssueCaptcha_NonceFailureRefusesToIssue(t *testing.T) {
	s := newMeTestServer(t)
	stubRandRead(t, 2) // 第 1 次(题面数字)放过,第 2 次(nonce)失败

	w := httptest.NewRecorder()
	if _, err := s.sess.IssueCaptcha(w); err == nil {
		t.Fatal("nonce 取不到随机数却发出了验证码")
	}
	if sc := w.Header().Get("Set-Cookie"); sc != "" {
		t.Fatalf("失败路径还是种下了 cookie: %q", sc)
	}
}

// PoW 题面的 salt 取不到随机数时要整体失败。固定 salt 意味着答案可以跨题复用,
// 攻击者一次算好就能无限次绕过 —— PoW 的全部意义就在于每题都要重新算。
func TestIssueChallenge_SaltFailureRefusesToIssue(t *testing.T) {
	s := newMeTestServer(t)
	stubRandRead(t, 2) // challenge_id 拿到了,salt 拿不到
	if ch, err := s.sess.IssueChallenge(powMinDifficulty); err == nil {
		t.Fatalf("salt 取不到随机数却发了题: %+v", ch)
	}
}

// 主机名探测的三级兜底都要走通,且任何一级都不能给出空串 —— 这个名字会进
// 自签证书的 SAN 与页面标题,空串会产出一张谁也验不过的证书。
func TestNetHostname_FallsBackThroughEveryLevel(t *testing.T) {
	stubHostnameSources := func(t *testing.T, addrs []string, addrErr error, host string, hostErr error) {
		t.Helper()
		origLookup, origHost := lookupAddrOS, hostnameOS
		lookupAddrOS = func(string) ([]string, error) { return addrs, addrErr }
		hostnameOS = func() (string, error) { return host, hostErr }
		t.Cleanup(func() { lookupAddrOS, hostnameOS = origLookup, origHost })
	}

	t.Run("反查拿到名字就用它", func(t *testing.T) {
		// "localhost" 与空项都要被跳过:它们不是可用的主机标识。
		stubHostnameSources(t, []string{"localhost.", "", "vpn.example.com."}, nil, "ignored", nil)
		got, err := netHostnameOrLocal()
		if err != nil || got != "vpn.example.com" {
			t.Fatalf("= (%q, %v), 期望 vpn.example.com", got, err)
		}
	})

	t.Run("反查失败退到 os.Hostname", func(t *testing.T) {
		stubHostnameSources(t, nil, errors.New("injected: 没有 DNS"), "box-1", nil)
		if _, err := netLookupSelf(); err == nil {
			t.Fatal("反查失败却说自己成功了")
		}
		got, err := netHostnameOrLocal()
		if err != nil || got != "box-1" {
			t.Fatalf("= (%q, %v), 期望 box-1", got, err)
		}
	})

	t.Run("两级都拿不到就兜底 localhost", func(t *testing.T) {
		stubHostnameSources(t, nil, errors.New("injected: 没有 DNS"), "", errors.New("injected: 没有 hostname"))
		got, err := netHostnameOrLocal()
		if err != nil {
			t.Fatalf("兜底路径不该报错: %v", err)
		}
		if got != "localhost" {
			t.Fatalf("= %q, 期望 localhost(绝不能是空串)", got)
		}
	})
}

// =========================================================================
// 本文件的小工具
// =========================================================================

const mePassword = "pw-me-guard-12345"

// meGuardEnv 造一个带 admin 的服务器,密码为 mePassword。
func meGuardEnv(t *testing.T) (*Server, *store.WebAdmin) {
	t.Helper()
	s := newMeTestServer(t)
	return s, createTestAdmin(t, s, "me-guard", mePassword)
}

// meBeginEnroll 只走到 setup(库里有 secret、还没 enable),返回该 secret。
func meBeginEnroll(t *testing.T, s *Server, admin *store.WebAdmin) string {
	t.Helper()
	w := httptest.NewRecorder()
	s.handleMeTOTPSetup(w, mePost(t, s, admin, "/me/totp/setup",
		url.Values{"password": {mePassword}}, ""))
	if w.Code != http.StatusOK {
		t.Fatalf("setup code=%d body=%q", w.Code, trimForLog(w.Body.String()))
	}
	cur, err := s.store.GetWebAdmin(t.Context(), admin.ID)
	if err != nil {
		t.Fatalf("GetWebAdmin: %v", err)
	}
	if cur.TOTPSecret == "" {
		t.Fatal("setup 之后库里没有 secret")
	}
	return cur.TOTPSecret
}

// auditHasAction 查审计表里有没有某个 action。
func auditHasAction(t *testing.T, s *Server, action string) bool {
	t.Helper()
	logs, err := s.store.QueryAudit(t.Context(), 0, time.Now().Add(time.Hour).Unix(), 200)
	if err != nil {
		t.Fatalf("QueryAudit: %v", err)
	}
	for _, l := range logs {
		if l.Action == action {
			return true
		}
	}
	return false
}
