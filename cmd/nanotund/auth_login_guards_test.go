package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nanotun/server/auth"
	"github.com/nanotun/server/config"
	"github.com/nanotun/server/store"
	"github.com/nanotun/server/util"
)

// 登录准入的两张映射表,以及 PSK 校验失败时的分档。
//
// 这两张表看着像文案,实际是运维的唯一抓手。auth_login.go 顶部记着 2026-05-21 那次事故:
// 安装脚本换了 DB 路径没迁用户,所有客户端登录都返回 403,而 audit_logs 里只有一行扁平的
// `action=login.fail`,既不能按子类聚合也不在 ERROR 级别 —— 等用户感知已经 11 小时。修法
// 就是「每个失败原因一个独立 action 名,全部挂在 login.fail. 前缀下」。所以这张表要钉的不是
// 字符串本身,而是三条结构性要求:每个码有自己的名字、名字互不重复、成功不许落进失败前缀。
// 少了任一条,`audit list --action-prefix login.fail` 这类报表就会静默给出错的数。

// loginCodeExpectations 覆盖 util/login_codes.go 里的**全部**登录结果码。
// 新增码时这里会因为下面那条「全码都得有专属文案」的断言而失败 —— 那是故意的。
var loginCodeExpectations = []struct {
	code    int
	message string
	action  string
}{
	{util.CodeOK, "ok", "login.success"},
	{util.CodeTokenInvalid, "用户名或密钥错误", "login.fail.bad_psk"},
	{util.CodeTokenExpired, "登录凭据已过期,请重新登录", "login.fail.token_expired"},
	{util.CodeUserNotFound, "用户不存在", "login.fail.user_not_found"},
	{util.CodeUserBlacklisted, "用户已被禁用", "login.fail.user_disabled"},
	{util.CodeVPNExpired, "服务已到期", "login.fail.vpn_expired"},
	{util.CodeSessionLimit, "已达最大会话数,请先在其它设备断开", "login.fail.session_limit"},
	{util.CodeKickByAdmin, "已被管理员踢下线", "login.fail.kick_by_admin"},
	{util.CodeNodeLoginInvalid, "节点信息无效", "login.fail.node_invalid"},
	{util.CodeDuplicateJWT, "同账号已在其它链路登录", "login.fail.duplicate_jwt"},
	{util.CodePowFailed, "登录请求过于频繁,请稍后再试", "login.fail.pow"},
	{util.CodePlatformNotAllowed, "此账号不支持在当前平台使用", "login.fail.platform_denied"},
	{util.CodeServerError, "服务器内部错误,请稍后再试", "login.fail.server_error"},
}

func TestLoginCodeTable_EveryOutcomeHasItsOwnMessageAndAction(t *testing.T) {
	for _, tc := range loginCodeExpectations {
		if got := clientLoginMessageForCode(tc.code); got != tc.message {
			t.Errorf("code=%d 的客户端文案: got %q want %q", tc.code, got, tc.message)
		}
		if got := auditActionForLoginCode(tc.code); got != tc.action {
			t.Errorf("code=%d 的 audit action: got %q want %q", tc.code, got, tc.action)
		}
	}

	// 未知码走兜底,且不能是空串 —— 空 action 会让那条审计记录从所有按 action 过滤的
	// 报表里消失。
	for _, unknown := range []int{-1, 1, 418, 999} {
		if got := clientLoginMessageForCode(unknown); got != "认证失败" {
			t.Errorf("未知码 %d 应回兜底文案,got %q", unknown, got)
		}
		if got := auditActionForLoginCode(unknown); got != "login.fail" {
			t.Errorf("未知码 %d 应回兜底 action,got %q", unknown, got)
		}
	}

	// ① 每个码要有**自己的** action。重复(复制粘贴漏改)不会报错,只会让两类失败在报表里
	//    并成一类 —— 那正是 2026-05-21 排查不下去的原因。
	seen := map[string]int{}
	for _, tc := range loginCodeExpectations {
		a := auditActionForLoginCode(tc.code)
		if prev, dup := seen[a]; dup {
			t.Errorf("code=%d 与 code=%d 共用 action %q —— 两类失败会在按 action 的报表里并成一类",
				tc.code, prev, a)
		}
		seen[a] = tc.code
	}

	// ② 失败一律挂在 login.fail. 前缀下,成功一律不许。运维用 --action-prefix login.fail
	//    一次性抓全部失败子类;成功若落进这个前缀,失败率报表会把成功也算成失败。
	for _, tc := range loginCodeExpectations {
		a := auditActionForLoginCode(tc.code)
		isFail := tc.code != util.CodeOK
		hasFailPrefix := strings.HasPrefix(a, "login.fail")
		if isFail && !hasFailPrefix {
			t.Errorf("code=%d 的 action %q 不在 login.fail 前缀下,prefix 聚合会漏掉它", tc.code, a)
		}
		if !isFail && hasFailPrefix {
			t.Errorf("成功的 action 是 %q —— 落在失败前缀下会污染失败率报表", a)
		}
	}
	// 兜底的 action 也必须在这个前缀下,否则「没见过的码」正是最该被看到的那一类,却漏掉了。
	if !strings.HasPrefix(auditActionForLoginCode(4242), "login.fail") {
		t.Error("兜底 action 也要在 login.fail 前缀下")
	}

	// ③ 客户端文案里不许出现内部细节。这两张表是「把内部错误链收敛成固定白名单」的地方,
	//    带上 SQL / Go 类型名就等于把库结构和依赖版本抖给任何一个能尝试登录的人。
	for _, tc := range loginCodeExpectations {
		m := clientLoginMessageForCode(tc.code)
		for _, leak := range []string{"sql", "SQL", "constraint", "store:", "auth:", "%!"} {
			if strings.Contains(m, leak) {
				t.Errorf("code=%d 的对外文案含内部细节 %q: %q", tc.code, leak, m)
			}
		}
	}
}

// TestAuthenticatePSK_EachFailureLandsInItsOwnBucket 钉住 PSK 校验的失败分档。
//
// 分档错了有两种坏法,方向相反:把「用户不存在」报成 500,运维会去查服务器而不是查用户表
// (2026-05-21 就是这个方向的近亲);反过来把内部错误(库读不动)报成 401「用户名或密钥错误」,
// 用户会一直重输密码,而真正的故障 —— 数据库 —— 没有任何人看见。
func TestAuthenticatePSK_EachFailureLandsInItsOwnBucket(t *testing.T) {
	t.Run("PSK 模式没初始化", func(t *testing.T) {
		_, st := newPSKGateway(t)
		for name, gw := range map[string]*gatewayState{
			"gw 为空":             nil,
			"没有 verifier":       {cfg: &config.Config{}, store: st},
			"没有 store":          {cfg: &config.Config{}, authVerifier: auth.NewVerifier(st)},
			"verifier/store 全无": {cfg: &config.Config{}},
		} {
			_, aerr := authenticateLogin(gw, &util.LoginReq{Name: "u", Token: "t"}, "sid")
			if aerr == nil {
				t.Fatalf("%s:应当拒绝", name)
			}
			if aerr.code != util.CodeServerError {
				t.Errorf("%s:应报 500(配置/初始化问题),got %d —— 报成 401 会让用户以为是自己密码错",
					name, aerr.code)
			}
		}
	})

	t.Run("用户名或 PSK 缺失", func(t *testing.T) {
		gw, _ := newPSKGateway(t)
		for _, req := range []*util.LoginReq{
			{Name: "", Token: "t"},
			{Name: "u", Token: ""},
			{Name: "", Token: ""},
		} {
			_, aerr := authenticateLogin(gw, req, "sid")
			if aerr == nil || aerr.code != util.CodeTokenInvalid {
				t.Fatalf("缺字段应回 401,got %+v", aerr)
			}
		}
	})

	t.Run("用户不存在", func(t *testing.T) {
		gw, _ := newPSKGateway(t)
		_, aerr := authenticateLogin(gw, &util.LoginReq{Name: "nobody", Token: "x"}, "sid")
		if aerr == nil || aerr.code != util.CodeUserNotFound {
			t.Fatalf("应回 403,got %+v", aerr)
		}
	})

	t.Run("PSK 不对", func(t *testing.T) {
		gw, st := newPSKGateway(t)
		hash, err := auth.HashPSK("right-one")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.CreateUser(t.Context(), store.NewUser{Username: "alice", PSKHash: hash}); err != nil {
			t.Fatal(err)
		}
		_, aerr := authenticateLogin(gw, &util.LoginReq{Name: "alice", Token: "wrong-one"}, "sid")
		if aerr == nil || aerr.code != util.CodeTokenInvalid {
			t.Fatalf("应回 401,got %+v", aerr)
		}
	})

	t.Run("用户已禁用", func(t *testing.T) {
		gw, st := newPSKGateway(t)
		hash, err := auth.HashPSK("right-one")
		if err != nil {
			t.Fatal(err)
		}
		u, err := st.CreateUser(t.Context(), store.NewUser{Username: "bob", PSKHash: hash})
		if err != nil {
			t.Fatal(err)
		}
		if err := st.DisableUser(t.Context(), u.ID); err != nil {
			t.Fatalf("禁用用户: %v", err)
		}
		_, aerr := authenticateLogin(gw, &util.LoginReq{Name: "bob", Token: "right-one"}, "sid")
		if aerr == nil {
			t.Fatal("被禁用的用户不该登录成功")
		}
		if aerr.code != util.CodeUserBlacklisted {
			t.Fatalf("应回 404(已禁用)而不是 %d —— 报成密码错会让用户一直重试,"+
				"而管理员那边看不到「有人在用被停的号」", aerr.code)
		}
	})

	t.Run("库读不动时报服务器错误,不报密码错", func(t *testing.T) {
		gw, st := newPSKGateway(t)
		hash, err := auth.HashPSK("right-one")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.CreateUser(t.Context(), store.NewUser{Username: "carol", PSKHash: hash}); err != nil {
			t.Fatal(err)
		}
		// 把 users 表藏起来,制造一个真实的读失败(库损坏 / 迁移半途 / 手工改表都是这个形状)。
		if _, err := st.DB().ExecContext(t.Context(), `ALTER TABLE users RENAME TO users_gone`); err != nil {
			t.Fatalf("藏表: %v", err)
		}
		_, aerr := authenticateLogin(gw, &util.LoginReq{Name: "carol", Token: "right-one"}, "sid")
		if aerr == nil {
			t.Fatal("库读不动时不该放行")
		}
		if aerr.code != util.CodeServerError {
			t.Fatalf("库故障应回 500,got %d —— 报成 401 会把一次数据库事故伪装成"+
				"一群用户同时打错密码", aerr.code)
		}
		// 对外文案要收敛:内部 message 可以带原始错误,但客户端拿到的是白名单文案。
		if strings.Contains(clientLoginMessageForCode(aerr.code), "users_gone") {
			t.Error("对外文案泄漏了表名")
		}
	})
}

// TestTruncateForLog_KeepsLogsParseable 日志字段截断。
// 上游可能把 KB 级的 DB 错误链塞进来,一行 JSON 日志超过 shipper 的默认上限(常见 8KB)
// 就是整行被丢 —— 于是恰恰在出故障时失去日志。
func TestTruncateForLog_KeepsLogsParseable(t *testing.T) {
	if got := truncateForLog("whatever", 0); got != "" {
		t.Errorf("max<=0 应返回空串,got %q", got)
	}
	if got := truncateForLog("whatever", -3); got != "" {
		t.Errorf("负 max 同样返回空串,got %q", got)
	}
	if got := truncateForLog("short", 32); got != "short" {
		t.Errorf("没超长不该改动,got %q", got)
	}
	long := strings.Repeat("x", 100)
	got := truncateForLog(long, 10)
	if !strings.HasPrefix(got, strings.Repeat("x", 10)) {
		t.Errorf("应保留前 10 字节,got %q", got)
	}
	if !strings.HasSuffix(got, "...<truncated>") {
		t.Errorf("要留下被截断的痕迹,否则读日志的人以为错误就这么短: %q", got)
	}
}

// TestInitAuthBackend_DefaultsToTheBundledDBPath 没配 db_path 时的默认落点。
//
// 打不开库时回错那条已有用例(见 TestInitAuthBackend_OpensTheStoreAndHandsBackACleanup),
// 这里只补默认路径:它决定了「配置里什么都不写」的部署把数据写到哪。选错落点不会报错,
// 只会让下一次带 --db-path 的 nanotun-admin 对着另一个空库操作 —— 用户全不见了。
func TestInitAuthBackend_DefaultsToTheBundledDBPath(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir) // 默认路径是相对的 data/nanotun.db
	gw := &gatewayState{cfg: &config.Config{}}
	cleanup, err := initAuthBackend(t.Context(), gw)
	if err != nil {
		t.Fatalf("默认路径应可用: %v", err)
	}
	t.Cleanup(cleanup)
	if gw.store == nil || gw.authVerifier == nil {
		t.Fatal("成功时必须把 store 与 verifier 都挂上去 —— 少一个,后续每次登录都是 500")
	}
	if _, err := os.Stat(filepath.Join(dir, "data", "nanotun.db")); err != nil {
		t.Fatalf("默认库文件应建在 data/nanotun.db: %v", err)
	}
}
