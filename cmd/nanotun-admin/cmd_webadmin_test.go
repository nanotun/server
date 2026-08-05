package main

// cmd_webadmin_test.go —— `webadmin` 子命令。
//
// 这条命令存在的理由是抢在 /setup 那个「谁先打开谁是管理员」的窗口之前把后台账号定下来,
// 所以它坏起来的方式很特别:命令说「已创建」、库里也确实多了一行,但那个账号**登不进去**
// (哈希格式与 Web 那边对不上),或者角色错成 viewer 导致整个控制台被永久锁成只读。
// 两种都不会在这条命令自己的输出里露馅,只会在几天后有人第一次去登录时炸开。
//
// 所以断言重心是「建出来的东西 Web 那边认」和「首位一定是 admin」,其次才是拒绝面。

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/nanotun/server/auth"
)

func webadminDB(t *testing.T) string {
	t.Helper()
	db := filepath.Join(t.TempDir(), "cli.db")
	if code, _, errOut := runCLI(t, db, "", "init"); code != 0 {
		t.Fatalf("init: %s", errOut)
	}
	return db
}

// TestWebAdminCreate_ProducesAnAccountTheWebCanActuallyVerify 是这一族里唯一非做不可的断言:
// CLI 用 auth.HashPSK 生成哈希,Web 登录用 auth.VerifyPSK 校验。两边一旦漂开,建账号这一步
// 照样「成功」,只有在有人第一次登录时才发现密码永远不对 —— 而那时候已经没人记得是哪一步的锅。
func TestWebAdminCreate_ProducesAnAccountTheWebCanActuallyVerify(t *testing.T) {
	db := webadminDB(t)
	const pw = "Str0ng-Console-Pass"

	code, out, errOut := runCLI(t, db, pw, "webadmin", "create", "alice", "--password-stdin")
	if code != 0 {
		t.Fatalf("create: code=%d err=%s", code, errOut)
	}
	if !strings.Contains(out, "alice") {
		t.Fatalf("输出里没提到建了谁: %q", out)
	}

	st := openStoreForTest(t, db)
	defer st.Close()
	admin, err := st.GetWebAdminByUsername(t.Context(), "alice")
	if err != nil {
		t.Fatalf("建完却查不到: %v", err)
	}
	ok, err := auth.VerifyPSK(pw, admin.PasswordHash)
	if err != nil || !ok {
		t.Fatalf("库里的哈希验不过刚才那个密码(Web 登录就是这么验的): ok=%v err=%v", ok, err)
	}
	// 反面:别的密码不能验过 —— 防止哪天 HashPSK 退化成常量或空串还「测试全绿」。
	if ok, _ := auth.VerifyPSK(pw+"x", admin.PasswordHash); ok {
		t.Fatal("换个密码也验过了,哈希是假的")
	}
}

// TestWebAdminCreate_FirstOneIsAdminEvenIfYouAskForViewer:首位若成了 viewer,没人能提权、
// 也没人能再建 admin(表一非空 /setup 就永久关),整台机器的控制台被锁成只读。DAL 已有兜底,
// 这里钉住 CLI 这一侧不会把它绕过去。
func TestWebAdminCreate_FirstOneIsAdminEvenIfYouAskForViewer(t *testing.T) {
	db := webadminDB(t)
	code, _, errOut := runCLI(t, db, "Str0ng-Console-Pass", "webadmin", "create", "alice",
		"--role", "viewer", "--password-stdin")
	if code != 0 {
		t.Fatalf("create: %s", errOut)
	}
	st := openStoreForTest(t, db)
	defer st.Close()
	admin, err := st.GetWebAdminByUsername(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if admin.Role != "admin" {
		t.Fatalf("首位管理员的角色 = %q,应为 admin —— 控制台会被锁成只读", admin.Role)
	}
}

// TestWebAdminCreate_SecondOneHonoursTheRequestedRole:表非空之后 viewer 才有意义。
func TestWebAdminCreate_SecondOneHonoursTheRequestedRole(t *testing.T) {
	db := webadminDB(t)
	if code, _, e := runCLI(t, db, "Str0ng-Console-Pass", "webadmin", "create", "alice", "--password-stdin"); code != 0 {
		t.Fatalf("first: %s", e)
	}
	if code, _, e := runCLI(t, db, "Second-Console-Pass", "webadmin", "create", "bob",
		"--role", "viewer", "--password-stdin"); code != 0 {
		t.Fatalf("second: %s", e)
	}
	st := openStoreForTest(t, db)
	defer st.Close()
	bob, err := st.GetWebAdminByUsername(t.Context(), "bob")
	if err != nil {
		t.Fatal(err)
	}
	if bob.Role != "viewer" {
		t.Fatalf("第二个管理员的角色 = %q,应为 viewer", bob.Role)
	}
}

func TestWebAdminCreate_RejectsWhatTheWebWouldAlsoReject(t *testing.T) {
	cases := []struct {
		name     string
		user     string
		password string
		wantHint string
	}{
		{"密码太短", "alice", "short1!", "至少 12 位"},
		{"只有一类字符", "alice", "aaaaaaaaaaaaaaaa", "两类字符"},
		{"用户名太短", "ab", "Str0ng-Console-Pass", "至少 3 个字符"},
		{"密码带换行", "alice", "Str0ng-Pass\nHere", "换行"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := webadminDB(t)
			code, _, errOut := runCLI(t, db, tc.password, "webadmin", "create", tc.user, "--password-stdin")
			if code == 0 {
				t.Fatal("居然建成了")
			}
			if !strings.Contains(errOut, tc.wantHint) {
				t.Fatalf("报错没说到点子上(想看到 %q):%s", tc.wantHint, errOut)
			}
			// 拒绝之后库里不该留下半个账号。
			st := openStoreForTest(t, db)
			defer st.Close()
			if n, _ := st.CountWebAdmins(t.Context()); n != 0 {
				t.Fatalf("被拒之后库里还是多了 %d 个管理员", n)
			}
		})
	}
}

func TestWebAdminCreate_DuplicateNameIsCaseInsensitive(t *testing.T) {
	db := webadminDB(t)
	if code, _, e := runCLI(t, db, "Str0ng-Console-Pass", "webadmin", "create", "alice", "--password-stdin"); code != 0 {
		t.Fatalf("first: %s", e)
	}
	code, _, errOut := runCLI(t, db, "Another-Console-Pass", "webadmin", "create", "ALICE", "--password-stdin")
	if code == 0 {
		t.Fatal("大小写不同的同名账号建成了 —— 登录时两者会互相冒充")
	}
	if !strings.Contains(errOut, "已有同名") {
		t.Fatalf("报错没说清是重名:%s", errOut)
	}
}

// TestWebAdminCreate_NoPasswordNoTerminalSaysHowToGiveOne:装机脚本 / CI / cron 撞到这里时
// 屏幕上只有这一行,它必须把三条路都写出来,而不是一句「需要密码」。
func TestWebAdminCreate_NoPasswordNoTerminalSaysHowToGiveOne(t *testing.T) {
	db := webadminDB(t)
	t.Setenv(envWebAdminPassword, "")
	code, _, errOut := runCLI(t, db, "", "webadmin", "create", "alice")
	if code == 0 {
		t.Fatal("没给密码却建成了")
	}
	for _, want := range []string{"--password-stdin", envWebAdminPassword, "终端"} {
		if !strings.Contains(errOut, want) {
			t.Fatalf("报错里没提到 %q,人不知道下一步该怎么办:%s", want, errOut)
		}
	}
}

func TestWebAdminCreate_PasswordFromEnvironment(t *testing.T) {
	db := webadminDB(t)
	t.Setenv(envWebAdminPassword, "Env-Console-Pass-1")
	if code, _, e := runCLI(t, db, "", "webadmin", "create", "alice"); code != 0 {
		t.Fatalf("create: %s", e)
	}
	st := openStoreForTest(t, db)
	defer st.Close()
	admin, err := st.GetWebAdminByUsername(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := auth.VerifyPSK("Env-Console-Pass-1", admin.PasswordHash); !ok {
		t.Fatal("环境变量里的密码没被用上")
	}
}

// TestWebAdminCreate_StdinBeatsEnvironment:显式给了 --password-stdin 就该以管道为准,
// 不能被恰好存在的环境变量截胡 —— 否则一台设过 NANOTUN_WEB_ADMIN_PASSWORD 的机器上,
// 管道里喂的新密码会被静默丢掉,而命令照样报成功。
func TestWebAdminCreate_StdinBeatsEnvironment(t *testing.T) {
	db := webadminDB(t)
	t.Setenv(envWebAdminPassword, "Env-Console-Pass-1")
	if code, _, e := runCLI(t, db, "Pipe-Console-Pass-2", "webadmin", "create", "alice", "--password-stdin"); code != 0 {
		t.Fatalf("create: %s", e)
	}
	st := openStoreForTest(t, db)
	defer st.Close()
	admin, err := st.GetWebAdminByUsername(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := auth.VerifyPSK("Pipe-Console-Pass-2", admin.PasswordHash); !ok {
		t.Fatal("管道里的密码没被用上(被环境变量截胡了)")
	}
}

// TestWebAdminCreate_TrailingNewlineFromPipeIsNotPartOfThePassword:`echo pw | ...` 会带一个
// 换行。若把它当密码的一部分存下去,人在网页上输入同一串就永远登不进去 —— 而且换行不可见,
// 没人查得出来。反过来,密码里的空格是合法的,不能替人 trim。
func TestWebAdminCreate_TrailingNewlineFromPipeIsNotPartOfThePassword(t *testing.T) {
	db := webadminDB(t)
	if code, _, e := runCLI(t, db, "Str0ng-Console-Pass\n", "webadmin", "create", "alice", "--password-stdin"); code != 0 {
		t.Fatalf("create: %s", e)
	}
	st := openStoreForTest(t, db)
	defer st.Close()
	admin, err := st.GetWebAdminByUsername(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := auth.VerifyPSK("Str0ng-Console-Pass", admin.PasswordHash); !ok {
		t.Fatal("尾部换行被当成密码的一部分了")
	}
}

func TestWebAdminList_ShowsWhoHoldsTheConsole(t *testing.T) {
	db := webadminDB(t)
	if code, _, e := runCLI(t, db, "Str0ng-Console-Pass", "webadmin", "create", "alice", "--password-stdin"); code != 0 {
		t.Fatalf("create: %s", e)
	}
	code, out, errOut := runCLI(t, db, "", "webadmin", "list")
	if code != 0 {
		t.Fatalf("list: %s", errOut)
	}
	if !strings.Contains(out, "alice") || !strings.Contains(out, "admin") {
		t.Fatalf("列表里看不到刚建的管理员:%s", out)
	}
	// 哈希绝不能出现在任何输出里。
	if strings.Contains(out, "$argon2") {
		t.Fatalf("列表把密码哈希打出来了:%s", out)
	}
}

func TestWebAdminList_JSONOmitsThePasswordHash(t *testing.T) {
	db := webadminDB(t)
	if code, _, e := runCLI(t, db, "Str0ng-Console-Pass", "webadmin", "create", "alice", "--password-stdin"); code != 0 {
		t.Fatalf("create: %s", e)
	}
	code, out, errOut := runCLI(t, db, "", "--json", "webadmin", "list")
	if code != 0 {
		t.Fatalf("list --json: %s", errOut)
	}
	if strings.Contains(out, "argon2") || strings.Contains(out, "password") {
		t.Fatalf("JSON 里带了密码相关字段:%s", out)
	}
}
