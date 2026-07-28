package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nanotun/server/auth"
	"github.com/nanotun/server/store"
)

// 第二十二轮收尾:剩下的零散分支。
//
// 挑的都是「错了会让人看到一个貌似正常的结果」的那类,不追纯防御分支
// (crypto/rand 失败、json.Marshal 一个固定结构失败之类 —— 那些真发生时机器已经坏了)。

// =========================================================================
// 打开库:schema 检查本身失败
// =========================================================================

// 库文件在、app_settings 也在,但表结构对不上(迁移半途断电 / 被外部工具改过)。
// 这既不是「库不存在」也不是「没 init 过」,必须报第三种:schema 读不出来。
// 若混进「没 init 过」那一类,提示会让人去跑 init —— 而 init 对着这个坏库只会
// 让事情更糟。
func TestRunWithStore_SchemaProbeFailureIsItsOwnCase(t *testing.T) {
	db := filepath.Join(t.TempDir(), "halfmigrated.db")
	raw, err := sql.Open("sqlite", db)
	if err != nil {
		t.Fatal(err)
	}
	// app_settings 在,但少了 value 列 → 探测表存在这步过得去,读 schema_version 时炸。
	if _, err := raw.ExecContext(t.Context(), `CREATE TABLE app_settings (key TEXT PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	code, _, stderr := runCLI(t, db, "", "user", "list")
	if code != 1 {
		t.Fatalf("schema 读失败应 exit 1(区别于不存在/未初始化的 2), got %d stderr=%q", code, stderr)
	}
	if !strings.Contains(stderr, "schema") {
		t.Errorf("报错没说清是 schema 这步挂了: %q", stderr)
	}
	if strings.Contains(stderr, "not initialized") {
		t.Error("把「schema 坏了」当成「没 init 过」—— 提示会把人引去对着坏库跑 init")
	}
}

// =========================================================================
// user create / reset-psk
// =========================================================================

func TestCmdUserCreate_JSONCarriesThePSKExactlyOnce(t *testing.T) {
	// --json 是配号脚本用的:PSK 只在这一次输出里出现,拿不到就得重置。
	// 所以字段名和内容都得钉住。
	db := newInitializedDB(t, t.TempDir(), "uc.db")
	code, stdout, stderr := runCLI(t, db, "", "--json", "user", "create", "olivia")
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
	var got struct {
		ID       int64  `json:"id"`
		Username string `json:"username"`
		PSK      string `json:"psk"`
		Note     string `json:"note"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("--json 输出不可解析: %v (%q)", err, stdout)
	}
	if got.ID == 0 || got.Username != "olivia" {
		t.Errorf("字段不对: %+v", got)
	}
	if got.PSK == "" {
		t.Error("自动生成的 PSK 没出现在 --json 里 —— 脚本再也拿不到它了")
	}
	// 自动生成时必须带上「只显示这一次」的提示,不然运维不会去存。
	if got.Note == "" {
		t.Error("自动生成 PSK 却没给 note 提示")
	}

	// 落库的必须是 hash,不是明文。
	st := openStoreForTest(t, db)
	defer st.Close()
	u, err := st.GetUserByUsername(t.Context(), "olivia")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(u.PSKHash, got.PSK) {
		t.Error("库里存了明文 PSK")
	}
	if ok, verr := auth.VerifyPSK(got.PSK, u.PSKHash); verr != nil || !ok {
		t.Errorf("输出的 PSK 与库里的 hash 对不上(ok=%v err=%v)—— 客户端拿它登不上", ok, verr)
	}
}

// 0013 之前建的 user 没有 credential_id。首次 reset-psk 要顺手补一个,并在 audit 里
// 留痕 —— 否则事后看不出这个 UUID 是什么时候冒出来的(客户端按 UUID 索引本地条目)。
func TestCmdUserResetPSK_BackfillIsAudited(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "urp.db")
	if c, _, e := runCLI(t, db, "", "user", "create", "peggy", "--psk", "psk-peggy-1234"); c != 0 {
		t.Fatalf("建用户: %s", e)
	}
	// 做成 0013 之前的老 row。
	aclExec(t, db, `UPDATE users SET credential_id = '' WHERE username = 'peggy'`)

	code, _, stderr := runCLI(t, db, "", "user", "reset-psk", "peggy")
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}

	st := openStoreForTest(t, db)
	defer st.Close()
	u, err := st.GetUserByUsername(t.Context(), "peggy")
	if err != nil {
		t.Fatal(err)
	}
	if u.CredentialID == "" {
		t.Fatal("credential_id 没补上 —— 客户端没法索引这条凭证")
	}
	logs, err := st.QueryAudit(t.Context(), 0, time.Now().Add(time.Hour).Unix(), 50)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, l := range logs {
		if l.Action == "user_reset_psk" && strings.Contains(l.Detail, "backfilled credential_id=") {
			found = true
		}
	}
	if !found {
		t.Error("补 credential_id 没写进 audit —— 事后无从解释这个 UUID 的来历")
	}
}

// =========================================================================
// credentials
// =========================================================================

// 两个 admin 同时给一个用户轮换 PSK 时,CAS 会让后到的那个失败。这条路必须给出
// 「另一个人刚刚换过,去拿新的」这种可操作提示,而不是把 store 层的 sentinel 原文
// 甩出来;同时要留 audit —— 否则「我明明换了却拿不到新 PSK」这种投诉查不了。
func TestResolveCredentialsPSK_LostCASRaceIsExplained(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "cred-race.db")
	if c, _, e := runCLI(t, db, "", "user", "create", "quentin", "--psk", "psk-quentin-12"); c != 0 {
		t.Fatalf("建用户: %s", e)
	}

	st := openStoreForTest(t, db)
	defer st.Close()
	u, err := st.GetUserByUsername(t.Context(), "quentin")
	if err != nil {
		t.Fatal(err)
	}
	// 模拟「另一个 admin 抢在前面换掉了」:手里这份 u 的 psk_hash 已经过期。
	otherHash, err := auth.HashPSK("someone-else-rotated-it")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().ExecContext(t.Context(),
		`UPDATE users SET psk_hash = ? WHERE id = ?`, otherHash, u.ID); err != nil {
		t.Fatal(err)
	}

	_, _, _, rerr := resolveCredentialsPSK(t.Context(), st, u, "", true)
	if rerr == nil {
		t.Fatal("CAS 输了却报成功 —— 会把一个从未落库的 PSK 交付给用户")
	}
	if !strings.Contains(rerr.Error(), u.Username) {
		t.Errorf("提示里没提是谁: %v", rerr)
	}
	if strings.Contains(rerr.Error(), "CAS") || strings.Contains(rerr.Error(), "snapshot") {
		t.Errorf("把实现层文案甩给运维了: %v", rerr)
	}

	logs, err := st.QueryAudit(t.Context(), 0, time.Now().Add(time.Hour).Unix(), 50)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, l := range logs {
		if l.Action == "user_reset_psk_raced" &&
			strings.Contains(l.Detail, "username="+u.Username) &&
			strings.Contains(l.Detail, "via=credentials_show") {
			found = true
		}
	}
	if !found {
		t.Error("撞车事件没写 audit —— 「我换了却拿不到新 PSK」的投诉就查不了")
	}
}

// --rotate-psk 一旦落库,旧 PSK 立刻作废。所以所有**确定性**的输出失败都必须在
// 落库前拦下:落库后才失败 = PSK 已换、明文从未交付,用户当场断连。
func TestPreflightCredentialsOutput_CatchesDeterministicFailuresBeforeRotating(t *testing.T) {
	dir := t.TempDir()
	plainOpts := &globalOpts{lang: langZH, stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}

	t.Run("qr-png 缺 --output", func(t *testing.T) {
		if err := preflightCredentialsOutput("qr-png", "", false, plainOpts); err == nil {
			t.Fatal("qr-png 不给输出路径却过了 preflight —— 落库后才报,PSK 已经废了")
		}
	})

	t.Run("--output 的目录不存在", func(t *testing.T) {
		bad := filepath.Join(dir, "no-such-dir", "c.png")
		if err := preflightCredentialsOutput("qr-png", bad, false, plainOpts); err == nil {
			t.Fatal("目录不存在却过了 preflight")
		}
	})

	t.Run("--output 已存在且没给 --force", func(t *testing.T) {
		exists := filepath.Join(dir, "taken.json")
		if err := os.WriteFile(exists, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := preflightCredentialsOutput("json", exists, false, plainOpts); err == nil {
			t.Fatal("会覆盖已有文件却过了 preflight")
		}
		// --force 是明示要覆盖,该放行。
		if err := preflightCredentialsOutput("json", exists, true, plainOpts); err != nil {
			t.Fatalf("--force 之下不该拦: %v", err)
		}
	})

	t.Run("--output 路径本身不合法", func(t *testing.T) {
		// 文件名超长:Lstat 给的不是 ENOENT,不能当成「目标不存在」放行 ——
		// 放行的话仍然是落库之后才写失败。
		tooLong := filepath.Join(dir, strings.Repeat("z", 300)+".json")
		err := preflightCredentialsOutput("json", tooLong, false, plainOpts)
		if err == nil {
			t.Fatal("路径不合法却过了 preflight")
		}
		if !strings.Contains(err.Error(), "--output") {
			t.Errorf("报错没指向 --output: %v", err)
		}
	})

	t.Run("纯终端 qr 不看 --output", func(t *testing.T) {
		// 非 --json 的 qr 只往 stdout 画,给了 --output 也只是被忽略(会 warn),
		// 因此 preflight 不该因为「那个文件已存在」把它拦下。
		exists := filepath.Join(dir, "ignored.png")
		if err := os.WriteFile(exists, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := preflightCredentialsOutput("qr", exists, false, plainOpts); err != nil {
			t.Fatalf("纯终端 qr 被 --output 拦下了: %v", err)
		}
	})

	t.Run("全局 --json 之下 format 被忽略", func(t *testing.T) {
		// --json 一律写 JSON,qr-png 那条「必须给 output」的规则不适用。
		jsonOpts := &globalOpts{lang: langZH, json: true, stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
		if err := preflightCredentialsOutput("qr-png", "", false, jsonOpts); err != nil {
			t.Fatalf("--json 之下不该要求 --output: %v", err)
		}
	})
}

// =========================================================================
// 语言归一
// =========================================================================

func TestNormalizeLang_AcceptsTheFormsPeopleActuallyType(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
		ok   bool
	}{
		{"en", "en", true},
		{"EN", "en", true},
		{" en ", "en", true},
		{"en-US", "en", true},
		{"zh", langZH, true},
		{"ZH", langZH, true},
		{"zh-CN", langZH, true},
		{"zh_TW", langZH, true},
		{"", "", false},
		{"klingon", "", false},
		{"e", "", false},
	} {
		got, ok := normalizeLang(tc.in)
		if ok != tc.ok {
			t.Errorf("normalizeLang(%q): ok=%v, 期望 %v", tc.in, ok, tc.ok)
			continue
		}
		if ok && got != tc.want {
			t.Errorf("normalizeLang(%q)=%q, 期望 %q", tc.in, got, tc.want)
		}
	}
}

// store 包里的 setting key 分类表被 CLI 直接引用。表空/漏项都会让 `setting set`
// 的三层闸门形同虚设,这里给个下限断言。
func TestSettingKeyTablesAreNotEmpty(t *testing.T) {
	if len(systemManagedSettingKeys) == 0 {
		t.Error("系统自管 key 表是空的 —— 手改证书/PSK 类 key 会畅通无阻")
	}
	if len(validatedSettingKeys) == 0 {
		t.Error("带校验的 key 表是空的 —— 所有值都会原样落库")
	}
	// 两张表不该有交集:同一个 key 既「硬拒」又「校验后放行」是自相矛盾的,
	// 实际行为取决于代码里先查哪张表。
	for k := range systemManagedSettingKeys {
		if _, dup := validatedSettingKeys[k]; dup {
			t.Errorf("%q 同时在「系统自管」和「带校验」两张表里", k)
		}
	}
	_ = store.MeshCIDRsKey
}
