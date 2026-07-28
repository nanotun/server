package main

// cmd_init_guards_test.go(第二十二轮)—— `init` 首部署向导的拒绝面。
//
// init 是唯一一条「被设计成会被反复执行」的命令(install.sh / Ansible / Terraform 都会重跑),
// 所以它出错的方式很特别:不是报错,而是**在重跑时静默改掉线上管理员凭证**。历史上第八、
// 十二、十四、十五轮各修过一次同一类漏洞(读 setting 失败被吞、轮换不确认、换个名字就多一个
// admin)。这一组把那几道闸口逐条钉住,顺带覆盖读写失败时「绝不谎报成功」。

import (
	"bufio"
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func newTestReader(s string) *bufio.Reader { return bufio.NewReader(strings.NewReader(s)) }

// relaxAppSettingsValue 把 app_settings.value 上的 NOT NULL 约束去掉,让测试能塞 NULL 进去。
// 塞 NULL 之后 SettingsGet 往 string 扫会失败 —— 这是模拟「真·读故障」(磁盘位翻转 / 库被外部
// 工具改坏)的唯一办法,与「这个 key 没设过」(ok=false,不是 error)是两回事。
func relaxAppSettingsValue(t *testing.T, db string) {
	t.Helper()
	st := openStoreForTest(t, db)
	defer st.Close()
	for _, stmt := range []string{
		`CREATE TABLE app_settings_relaxed (key TEXT PRIMARY KEY, value TEXT)`,
		`INSERT INTO app_settings_relaxed(key, value) SELECT key, value FROM app_settings`,
		`DROP TABLE app_settings`,
		`ALTER TABLE app_settings_relaxed RENAME TO app_settings`,
	} {
		if _, err := st.DB().ExecContext(t.Context(), stmt); err != nil {
			t.Fatalf("放宽 app_settings 约束(%s): %v", stmt, err)
		}
	}
}

// abortSettingWrite 只挡某一个 setting key 的写,别的写照常 —— 这样 migration 与
// 前面的建号都能正常跑完,失败精确落在被测的那一次 SettingsSet 上。
func abortSettingWrite(t *testing.T, db, key string) {
	t.Helper()
	st := openStoreForTest(t, db)
	defer st.Close()
	for _, op := range []string{"INSERT", "UPDATE"} {
		stmt := fmt.Sprintf(
			`CREATE TRIGGER t_block_setting_%s_%s BEFORE %s ON app_settings
			 WHEN NEW.key = '%s' BEGIN SELECT RAISE(ABORT, 'blocked by test'); END`,
			key, strings.ToLower(op), op, key)
		if _, err := st.DB().ExecContext(t.Context(), stmt); err != nil {
			t.Fatalf("装 %s 的 %s 触发器: %v", key, op, err)
		}
	}
}

// settingValue 用裸连接读一个 setting(触发器还挂着时不能走 openStoreForTest,
// 它会跑 Migrate)。key 不存在返回空串。
func settingValue(t *testing.T, db, key string) string {
	t.Helper()
	raw, err := sql.Open("sqlite", db)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	var v string
	switch err := raw.QueryRowContext(t.Context(),
		`SELECT value FROM app_settings WHERE key = ?`, key).Scan(&v); {
	case errors.Is(err, sql.ErrNoRows):
		return ""
	case err != nil:
		t.Fatalf("读 %s: %v", key, err)
	}
	return v
}

// initDirect 绕过 runCLI(它恒注入 --yes)直接调 cmdInit,用来测确认门。
func initDirect(t *testing.T, db, stdin string, args ...string) (error, string) {
	t.Helper()
	st := openStoreForTest(t, db)
	defer st.Close()
	out := &bytes.Buffer{}
	opts := &globalOpts{lang: langZH, stdout: out, stderr: &bytes.Buffer{}, stdin: strings.NewReader(stdin)}
	return cmdInit(t.Context(), st, opts, args), out.String()
}

func TestCmdInit_UsageGuards(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "init-usage.db")
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"未知 flag", []string{"init", "--bogus"}},
		{"多给位置参数", []string{"init", "admin"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := runCLI(t, db, "admin\n\n", tc.args...)
			if code != 2 {
				t.Fatalf("用法错误应 exit 2, got %d stderr=%q", code, stderr)
			}
		})
	}
	// 用法错误不许留下任何用户 —— 否则「参数打错」会变成「多了个管理员」。
	if n := countUsers(t, db); n != 0 {
		t.Fatalf("用法错误却建出了 %d 个用户", n)
	}
}

func countUsers(t *testing.T, db string) int {
	t.Helper()
	st := openStoreForTest(t, db)
	defer st.Close()
	n, err := st.CountUsers(t.Context())
	if err != nil {
		t.Fatalf("CountUsers: %v", err)
	}
	return n
}

// setup_completed 读失败时必须中止,绝不能当成「没装过」继续往下走 —— 那条路径的终点是
// 静默轮换线上 admin 的 PSK(第八轮修的就是这个被吞掉的 error)。
func TestCmdInit_SettingReadFailureAbortsInsteadOfRotating(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "init-setread.db")
	if c, _, e := runCLI(t, db, "admin\n\n", "init"); c != 0 {
		t.Fatalf("first init: %s", e)
	}
	hashBefore := userPSKHash(t, db, "admin")

	relaxAppSettingsValue(t, db)
	st := openStoreForTest(t, db)
	if _, err := st.DB().ExecContext(t.Context(),
		`UPDATE app_settings SET value = NULL WHERE key = 'setup_completed'`); err != nil {
		t.Fatalf("弄坏 setup_completed: %v", err)
	}
	_ = st.Close()

	code, stdout, stderr := runCLI(t, db, "admin\n\n", "init")
	if code == 0 {
		t.Fatalf("读不出 setup_completed 却成功了, stdout=%q", stdout)
	}
	if !strings.Contains(stderr, "setup_completed") {
		t.Errorf("报错没说是哪个 setting 读不出来: %q", stderr)
	}
	if got := userPSKHash(t, db, "admin"); got != hashBefore {
		t.Fatal("读 setting 失败却把线上 admin 的 PSK 换掉了 —— 第八轮那个漏洞回归了")
	}
}

func userPSKHash(t *testing.T, db, username string) string {
	t.Helper()
	st := openStoreForTest(t, db)
	defer st.Close()
	u, err := st.GetUserByUsername(t.Context(), username)
	if err != nil {
		t.Fatalf("GetUserByUsername(%s): %v", username, err)
	}
	return u.PSKHash
}

// users 表都读不出来时必须失败 —— 若 CountUsers 的 error 被吞成 0,init 会以为这是
// 首次部署,走无声创建首位 admin 的分支。
func TestCmdInit_CountUsersFailureIsLoud(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "init-count.db")
	aclExec(t, db, `ALTER TABLE users RENAME TO users_gone`)
	code, stdout, _ := runCLI(t, db, "admin\n\n", "init")
	if code == 0 {
		t.Fatalf("users 表读不出来却成功了, stdout=%q", stdout)
	}
}

// setup 已完成、却输入了一个**别的**用户名:这不是幂等重跑,而是「想加第二个管理员」。
// init 必须拒绝并指路 `user create`,不能顺手新建。
func TestCmdInit_SetupDoneButUnknownUsernameRefuses(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "init-othername.db")
	if c, _, e := runCLI(t, db, "admin\n\n", "init"); c != 0 {
		t.Fatalf("first init: %s", e)
	}

	code, _, stderr := runCLI(t, db, "eve\n", "init")
	if code == 0 {
		t.Fatal("setup 已完成还输新用户名,init 竟然成功了")
	}
	if !strings.Contains(stderr, "eve") {
		t.Errorf("报错没回显那个名字: %q", stderr)
	}
	if !strings.Contains(stderr, "user create") {
		t.Errorf("报错应指路 user create: %q", stderr)
	}
	if n := countUsers(t, db); n != 1 {
		t.Fatalf("被拒之后用户数变成了 %d", n)
	}
}

// 幂等重跑的 --json 形态:脚本靠 noop=true 判断「已就绪」,且绝不能把 PSK 带出来
// (那一次重跑并没有生成新 PSK,输出任何 psk 字段都是谎报)。
func TestCmdInit_NoopJSONShapeCarriesNoPSK(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "init-noopjson.db")
	if c, _, e := runCLI(t, db, "admin\n\n", "init"); c != 0 {
		t.Fatalf("first init: %s", e)
	}

	code, stdout, stderr := runCLI(t, db, "admin\n", "--json", "init")
	if code != 0 {
		t.Fatalf("noop init --json: code=%d stderr=%s", code, stderr)
	}
	for _, want := range []string{`"noop"`, "true", `"setup_complete"`, `"admin"`} {
		if !strings.Contains(stdout, want) {
			t.Errorf("noop JSON 缺 %s:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, `"psk"`) {
		t.Errorf("幂等重跑没生成新 PSK,不该输出 psk 字段:\n%s", stdout)
	}
}

// 首次部署的 --json 形态:必须带上明文 PSK(这是它唯一的明文出现机会)和 autogen 标记。
func TestCmdInit_FirstRunJSONCarriesPSK(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "init-firstjson.db")
	code, stdout, stderr := runCLI(t, db, "admin\n\n", "--json", "init")
	if code != 0 {
		t.Fatalf("init --json: code=%d stderr=%s", code, stderr)
	}
	for _, want := range []string{`"psk"`, `"psk_autogen"`, `"setup_complete"`} {
		if !strings.Contains(stdout, want) {
			t.Errorf("首装 JSON 缺 %s:\n%s", want, stdout)
		}
	}
}

// --reset-psk 的语义是「重置**已存在**用户的 PSK」。用户名打错(查不到)时不能静默新建 ——
// 那会在线上多出一个未预期的管理员账号(第八轮修的)。
func TestCmdInit_ResetPSKOnUnknownUserRefuses(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "init-resetnouser.db")
	if c, _, e := runCLI(t, db, "admin\n\n", "init"); c != 0 {
		t.Fatalf("first init: %s", e)
	}

	code, _, stderr := runCLI(t, db, "typo-admin\n\n", "init", "--reset-psk")
	if code == 0 {
		t.Fatal("--reset-psk 对不存在的用户竟然成功了(会凭空造管理员)")
	}
	if !strings.Contains(stderr, "typo-admin") {
		t.Errorf("报错没回显打错的名字: %q", stderr)
	}
	if n := countUsers(t, db); n != 1 {
		t.Fatalf("被拒之后用户数变成了 %d", n)
	}
}

// 轮换已存在管理员的 PSK 是破坏性操作(旧 PSK 立即作废),不带 --yes 必须先问。
// 第十四轮把确认条件从「仅 --reset-psk」放宽到「只要到达轮换分支」—— 因为
// setup_completed 可被 `setting set` 清掉,那之后不带 --reset-psk 的 init 也会轮换。
func TestCmdInit_RotationNeedsConfirmEvenWithoutResetFlag(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "init-rotconfirm.db")
	if c, _, e := runCLI(t, db, "admin\n\n", "init"); c != 0 {
		t.Fatalf("first init: %s", e)
	}
	// 清掉 setup_completed:此后 alreadySetup=false,不带 --reset-psk 也会落到轮换分支。
	if c, _, e := runCLI(t, db, "", "setting", "set", "setup_completed", "0"); c != 0 {
		t.Fatalf("clear setup_completed: %s", e)
	}
	before := userPSKHash(t, db, "admin")

	t.Run("答不", func(t *testing.T) {
		err, out := initDirect(t, db, "admin\n\nn\n")
		if err != nil {
			t.Fatalf("取消不该报错: %v", err)
		}
		if !strings.Contains(out, "已取消") {
			t.Errorf("没告诉用户已取消: %q", out)
		}
		if got := userPSKHash(t, db, "admin"); got != before {
			t.Fatal("答了不,PSK 却被换了")
		}
	})

	t.Run("EOF 按不处理", func(t *testing.T) {
		err, out := initDirect(t, db, "admin\n\n")
		if err != nil {
			t.Fatalf("EOF 不该报错: %v", err)
		}
		if !strings.Contains(out, "已取消") {
			t.Errorf("EOF 应按取消处理: %q", out)
		}
		if got := userPSKHash(t, db, "admin"); got != before {
			t.Fatal("读不到回答却换了 PSK")
		}
	})

	t.Run("答是才换", func(t *testing.T) {
		err, out := initDirect(t, db, "admin\n\ny\n")
		if err != nil {
			t.Fatalf("确认后应成功: %v", err)
		}
		if !strings.Contains(out, "PSK:") {
			t.Errorf("轮换后要打出新 PSK: %q", out)
		}
		if got := userPSKHash(t, db, "admin"); got == before {
			t.Fatal("答了是,PSK 却没换")
		}
	})
}

// 轮换 PSK 的写入被库拒绝时不能报成功:运维会拿着「新 PSK」去配客户端,而库里还是旧 hash。
func TestCmdInit_RotateWriteFailureIsLoud(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "init-rotfail.db")
	if c, _, e := runCLI(t, db, "admin\n\n", "init"); c != 0 {
		t.Fatalf("first init: %s", e)
	}
	before := userPSKHash(t, db, "admin")
	abortWritesOn(t, db, "users", "UPDATE")

	code, stdout, stderr := runCLI(t, db, "admin\n\n", "init", "--reset-psk")
	if code == 0 {
		t.Fatalf("轮换写失败却 exit 0, stdout=%q", stdout)
	}
	if strings.Contains(stdout, "PSK:") {
		t.Errorf("写失败却打出了新 PSK —— 运维会拿它去配客户端: %q", stdout)
	}
	if strings.TrimSpace(stderr) == "" {
		t.Error("失败却没说原因")
	}
	if got := userPSKHash(t, db, "admin"); got != before {
		t.Fatal("写被拒了 hash 却变了")
	}
}

// 首装时建 admin 的写入失败同样不能报成功 —— 否则脚本会以为部署完成,而库里没有管理员。
func TestCmdInit_CreateUserFailureIsLoud(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "init-createfail.db")
	abortWritesOn(t, db, "users", "INSERT")

	code, stdout, stderr := runCLI(t, db, "admin\n\n", "init")
	if code == 0 {
		t.Fatalf("建 admin 失败却 exit 0, stdout=%q", stdout)
	}
	if strings.Contains(stdout, "PSK:") {
		t.Errorf("建用户失败却打出了 PSK: %q", stdout)
	}
	if strings.TrimSpace(stderr) == "" {
		t.Error("失败却没说原因")
	}
	if n := countUsers(t, db); n != 0 {
		t.Fatalf("写被拒了却有 %d 个用户", n)
	}
}

// setup_completed 落库失败时必须报错。若这里谎报成功,下一次重跑会因为 setup_completed
// 仍不是 "1" 而再次落到轮换分支 —— 重复部署就成了「每跑一次换一次 admin PSK」。
func TestCmdInit_SetupFlagWriteFailureIsLoud(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "init-flagfail.db")
	// 只挡 setup_completed 这一个 key。整表挡 INSERT 会先把 migration 挡掉(init 是写
	// 路径,开库时就跑 Migrate),命令在到达被测那行之前就已经 exit 1 —— 用例照样"通过",
	// 但验的其实是 migration 失败。
	abortSettingWrite(t, db, "setup_completed")

	code, stdout, stderr := runCLI(t, db, "admin\n\n", "init")
	if code == 0 {
		t.Fatalf("写 setup_completed 失败却 exit 0, stdout=%q", stdout)
	}
	if strings.Contains(stdout, "下一步") {
		t.Errorf("写标记失败却打了「下一步」引导: %q", stdout)
	}
	if !strings.Contains(stderr, "setup_completed") && !strings.Contains(stderr, "blocked by test") {
		t.Errorf("报错没指向这次写:%q", stderr)
	}
	// 用户其实已经建出来了(写标记发生在建号之后),所以这条命令是**部分成功**的。
	// 正确的收敛是「报错 + 不留 setup_completed」,下次重跑会走轮换分支(带确认)。
	if v := settingValue(t, db, "setup_completed"); v == "1" {
		t.Error("写被挡下了却留下了 setup_completed=1")
	}
}

// promptString 的默认值与回车语义:直接回车取默认;有输入取输入;读不到东西(EOF)取默认。
// 这三条决定了非交互场景(install.sh 把 stdin 接 /dev/null)会拿到什么用户名 ——
// 判错就会建出一个名字不对的管理员。
func TestPromptString_DefaultsAndEOF(t *testing.T) {
	for _, tc := range []struct {
		name  string
		stdin string
		def   string
		want  string
	}{
		{"直接回车取默认", "\n", "admin", "admin"},
		{"有输入取输入", "wenhai\n", "admin", "wenhai"},
		{"EOF 取默认", "", "admin", "admin"},
		{"无默认值时 EOF 得空", "", "", ""},
		{"CRLF 要被剥掉", "wenhai\r\n", "admin", "wenhai"},
		{"末行无换行也算输入", "wenhai", "admin", "wenhai"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts, _ := newConfirmOpts(tc.stdin)
			r := newTestReader(tc.stdin)
			if got := promptString(r, opts, "用户名", tc.def); got != tc.want {
				t.Errorf("promptString(stdin=%q, def=%q)=%q want %q", tc.stdin, tc.def, got, tc.want)
			}
		})
	}
}
