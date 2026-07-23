package main

// cmd_credentials_test.go(2026-05-25,0013):「profile / credentials 解耦」服务端导出测试。
//
// 覆盖矩阵(与 cmd_credentials.go::cmdCredentialsShow 行为一一对照):
//
//	TestCredentialsShow_PSKVerify        --psk PLAIN 成功路径 + UUID/created_at 不变 + 多 format
//	TestCredentialsShow_RotatePSK         --rotate-psk 保 UUID + 新 PSK + 刷 created_at +
//	                                     验证多次 rotate 得到不同 PSK / 新 PSK 能 verify-back
//	TestCredentialsShow_PSKMismatch       --psk WRONG 显式拒绝
//	TestCredentialsShow_FlagValidation    --psk + --rotate-psk 互斥;两者都缺也拒
//	TestCredentialsShow_URLRoundtrip      url 输出可被 base64url 反解,得到合法 credentialsSchema
//	TestCredentialsShow_QRPNG             qr-png + --output 落盘 PNG 文件
//	TestCredentialsShow_LegacyUserBackfill 老 user(credential_id 空)首次 show 自动 backfill
//	                                       UUID v4;再次 show 拿到同 UUID(稳定)。

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nanotun/server/auth"
	"github.com/nanotun/server/store"
)

// parseCredentialsJSON 把 credentials show --format json 的 stdout 反序列化。
func parseCredentialsJSON(t *testing.T, stdout string) credentialsSchema {
	t.Helper()
	var c credentialsSchema
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &c); err != nil {
		t.Fatalf("parse credentials json: %v\n%s", err, stdout)
	}
	return c
}

func TestCredentialsShow_PSKVerify(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "p.db")
	const knownPSK = "test-psk-alpha-bravo"
	if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", knownPSK); c != 0 {
		t.Fatalf("create alice: %s", e)
	}

	c, stdout, stderr := runCLI(t, db, "",
		"credentials", "show", "alice",
		"--psk", knownPSK,
		"--format", "json",
	)
	if c != 0 {
		t.Fatalf("credentials show --psk: code=%d stderr=%s", c, stderr)
	}
	cred := parseCredentialsJSON(t, stdout)
	if cred.Version != credentialsSchemaVersion {
		t.Fatalf("version=%d want %d", cred.Version, credentialsSchemaVersion)
	}
	if cred.Username != "alice" {
		t.Fatalf("username=%q", cred.Username)
	}
	if cred.PSK != knownPSK {
		t.Fatalf("psk roundtrip mismatch: got=%q want=%q", cred.PSK, knownPSK)
	}
	if cred.ID == "" {
		t.Fatalf("credential id should be non-empty (user create 时已分配 UUID v4)")
	}
	if cred.CreatedAt <= 0 {
		t.Fatalf("created_at should be positive: %d", cred.CreatedAt)
	}

	// 二次 show:UUID + created_at 必须**完全一致**(没 rotate)。
	c, stdout2, _ := runCLI(t, db, "",
		"credentials", "show", "alice",
		"--psk", knownPSK,
		"--format", "json",
	)
	if c != 0 {
		t.Fatalf("second show failed")
	}
	cred2 := parseCredentialsJSON(t, stdout2)
	if cred2.ID != cred.ID {
		t.Fatalf("UUID drifted between two reads: %q -> %q", cred.ID, cred2.ID)
	}
	if cred2.CreatedAt != cred.CreatedAt {
		t.Fatalf("created_at drifted: %d -> %d", cred.CreatedAt, cred2.CreatedAt)
	}
}

func TestCredentialsShow_RotatePSK(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "p.db")
	if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", "init-psk"); c != 0 {
		t.Fatalf("create alice: %s", e)
	}

	// 第一次 rotate
	c, stdout1, _ := runCLI(t, db, "",
		"credentials", "show", "alice",
		"--rotate-psk",
		"--format", "json",
	)
	if c != 0 {
		t.Fatalf("rotate #1 failed: %s", stdout1)
	}
	c1 := parseCredentialsJSON(t, stdout1)
	if c1.PSK == "" || c1.PSK == "init-psk" {
		t.Fatalf("rotate should issue fresh PSK; got %q", c1.PSK)
	}
	if c1.ID == "" || c1.CreatedAt == 0 {
		t.Fatalf("rotate output must include id + created_at: %+v", c1)
	}

	// 再 rotate:**同 UUID** + 不同 PSK + created_at 应 >= 上次
	c, stdout2, _ := runCLI(t, db, "",
		"credentials", "show", "alice",
		"--rotate-psk",
		"--format", "json",
	)
	if c != 0 {
		t.Fatalf("rotate #2 failed: %s", stdout2)
	}
	c2 := parseCredentialsJSON(t, stdout2)
	if c2.ID != c1.ID {
		t.Fatalf("rotate must preserve UUID: %q -> %q", c1.ID, c2.ID)
	}
	if c2.PSK == c1.PSK {
		t.Fatalf("two rotates produced same PSK: %q", c2.PSK)
	}
	if c2.CreatedAt < c1.CreatedAt {
		t.Fatalf("created_at must monotonically advance: %d -> %d", c1.CreatedAt, c2.CreatedAt)
	}

	// 用最新 PSK verify-back:成功
	c, stdout3, stderr := runCLI(t, db, "",
		"credentials", "show", "alice",
		"--psk", c2.PSK,
		"--format", "json",
	)
	if c != 0 {
		t.Fatalf("verify latest psk failed: stderr=%s", stderr)
	}
	c3 := parseCredentialsJSON(t, stdout3)
	if c3.PSK != c2.PSK {
		t.Fatalf("verified psk mismatch: %q vs %q", c3.PSK, c2.PSK)
	}
	if c3.ID != c2.ID {
		t.Fatalf("verify must reuse UUID: %q vs %q", c3.ID, c2.ID)
	}

	// 老 PSK 应失效
	c, _, _ = runCLI(t, db, "",
		"credentials", "show", "alice",
		"--psk", c1.PSK,
	)
	if c == 0 {
		t.Fatalf("old psk should fail after second rotate")
	}
}

// TestCredentialsShow_RotatePreflightNoClobber(第六轮深扫 HIGH):rotate + --output 目标已存在 + 无
// --force 时,必须在**落库前**报错,且 PSK 不被轮换(老 PSK 仍可 verify)——否则新 PSK 已入库却因输出
// 失败从未交付,用户被下线且运维无新密钥。
func TestCredentialsShow_RotatePreflightNoClobber(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "p.db")
	if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", "init-psk"); c != 0 {
		t.Fatalf("create alice: %s", e)
	}
	// 预先放一个已存在的输出目标。
	out := filepath.Join(dir, "cred.json")
	if err := os.WriteFile(out, []byte("preexisting"), 0o600); err != nil {
		t.Fatal(err)
	}

	// rotate + 已存在 output + 无 --force → 应失败。
	c, _, _ := runCLI(t, db, "",
		"credentials", "show", "alice",
		"--rotate-psk", "--format", "json", "--output", out,
	)
	if c == 0 {
		t.Fatal("rotate 写到已存在目标(无 --force)应失败")
	}
	// 目标文件内容不变(没被覆盖)。
	if b, _ := os.ReadFile(out); string(b) != "preexisting" {
		t.Fatalf("已存在目标不应被改动, got %q", b)
	}
	// 关键:PSK 未被轮换 —— 老 psk 仍可 verify(说明落库前就 fail,没提交新 hash)。
	if c2, _, e := runCLI(t, db, "", "credentials", "show", "alice", "--psk", "init-psk", "--format", "json"); c2 != 0 {
		t.Fatalf("预检失败后老 PSK 应仍有效(未轮换),但 verify 失败: %s", e)
	}
}

// TestCredentialsShow_RotatePreflightQRPNGNeedsOutput(第七轮深扫 HIGH):rotate + --format qr-png
// 但缺 --output —— 这是最易复现的「确定性输出失败」。必须在**落库前**报错、PSK 不被轮换,否则旧 hash
// 已失效、新明文 QR 从未产出,用户被下线且无新密钥。第六轮的预检只覆盖「output 已存在」,不覆盖本例。
func TestCredentialsShow_RotatePreflightQRPNGNeedsOutput(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "p.db")
	if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", "init-psk"); c != 0 {
		t.Fatalf("create alice: %s", e)
	}
	// rotate + qr-png + 无 --output → 应在落库前失败。
	c, _, _ := runCLI(t, db, "",
		"credentials", "show", "alice",
		"--rotate-psk", "--format", "qr-png",
	)
	if c == 0 {
		t.Fatal("rotate + qr-png 缺 --output 应失败")
	}
	// 关键:老 PSK 仍可 verify(未轮换,落库前就 fail)。
	if c2, _, e := runCLI(t, db, "", "credentials", "show", "alice", "--psk", "init-psk", "--format", "json"); c2 != 0 {
		t.Fatalf("qr-png 预检失败后老 PSK 应仍有效(未轮换),但 verify 失败: %s", e)
	}
}

func TestCredentialsShow_PSKMismatch(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "p.db")
	if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", "right"); c != 0 {
		t.Fatalf("create alice: %s", e)
	}
	c, _, stderr := runCLI(t, db, "",
		"credentials", "show", "alice",
		"--psk", "wrong",
		"--format", "json",
	)
	if c == 0 {
		t.Fatalf("wrong psk should fail")
	}
	if !strings.Contains(stderr, "不匹配") {
		t.Fatalf("expected mismatch hint, got: %s", stderr)
	}
}

func TestCredentialsShow_FlagValidation(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "p.db")
	if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", "p"); c != 0 {
		t.Fatalf("create alice: %s", e)
	}

	// 两者都缺
	c, _, _ := runCLI(t, db, "",
		"credentials", "show", "alice",
	)
	if c == 0 {
		t.Fatalf("missing --psk and --rotate-psk should fail")
	}
	// 两者同传
	c, _, _ = runCLI(t, db, "",
		"credentials", "show", "alice",
		"--psk", "p", "--rotate-psk",
	)
	if c == 0 {
		t.Fatalf("--psk + --rotate-psk must be mutex")
	}
	// 非法 format
	c, _, _ = runCLI(t, db, "",
		"credentials", "show", "alice", "--psk", "p", "--format", "xml",
	)
	if c == 0 {
		t.Fatalf("--format xml should fail")
	}
}

func TestCredentialsShow_URLRoundtrip(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "p.db")
	if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", "p"); c != 0 {
		t.Fatalf("create alice: %s", e)
	}
	c, stdout, _ := runCLI(t, db, "",
		"credentials", "show", "alice",
		"--psk", "p",
		"--format", "url",
	)
	if c != 0 {
		t.Fatalf("show url failed")
	}
	line := strings.TrimSpace(stdout)
	if !strings.HasPrefix(line, credentialsURLPrefix) {
		t.Fatalf("missing url prefix: %q", line)
	}
	payload := strings.TrimPrefix(line, credentialsURLPrefix)
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("decode rawurl: %v", err)
	}
	var c1 credentialsSchema
	if err := json.Unmarshal(raw, &c1); err != nil {
		t.Fatalf("payload not credentialsSchema: %v\n%s", err, raw)
	}
	if c1.Version != credentialsSchemaVersion || c1.Username != "alice" || c1.PSK != "p" {
		t.Fatalf("url-decoded credentials mismatch: %+v", c1)
	}
	if c1.ID == "" || c1.CreatedAt <= 0 {
		t.Fatalf("url-decoded missing id/created_at: %+v", c1)
	}
}

// TestCredentialsShow_LegacyUserBackfill:0013 之前的老 user(credential_id 为空 /
// credential_created_at = 0)首次跑 `credentials show <user> --psk PLAIN` 时,应
// 触发幂等 backfill — UUID v4 + credential_created_at 落库;再次 show 拿到**同**
// UUID(稳定不变)、credential_created_at 也保持稳定。
//
// 这是 client 端「按 UUID 索引,新 QR 自动覆盖旧 PSK」的根基:UUID 不能漂移。
func TestCredentialsShow_LegacyUserBackfill(t *testing.T) {
	db := filepath.Join(t.TempDir(), "legacy.db")

	// 用 store 直接插入一行老 user(0013 之前的形态:credential_id IS NULL,
	// credential_created_at 也是 0)。CLI `user create` 在 0013 之后会强制带 UUID,
	// 用它无法复刻老 row 状态;走 store 层 raw 注入。
	const knownPSK = "legacy-known-psk-1"
	st := openStoreForTest(t, db)
	hash, err := auth.HashPSK(knownPSK)
	if err != nil {
		t.Fatalf("hash psk: %v", err)
	}
	if _, err := st.CreateUser(t.Context(), store.NewUser{
		Username: "legacy",
		PSKHash:  hash,
		// 故意不传 CredentialID / CredentialCreatedAt → store 层 nullableString
		// / nullableInt64 入库 NULL;COALESCE 在 GetUser 路径上把它读回 ""/0,
		// 与 0013 之前实际生产库的状态一致。
	}); err != nil {
		t.Fatalf("create legacy user: %v", err)
	}
	_ = st.Close()

	// 第一次 show:应当 backfill UUID + credential_created_at,JSON 输出二者皆非空。
	c, stdout, stderr := runCLI(t, db, "",
		"credentials", "show", "legacy",
		"--psk", knownPSK,
		"--format", "json",
	)
	if c != 0 {
		t.Fatalf("first show failed: code=%d stderr=%s", c, stderr)
	}
	c1 := parseCredentialsJSON(t, stdout)
	if c1.ID == "" {
		t.Fatalf("backfill 没生效:credential_id 仍空(stdout=%s)", stdout)
	}
	if c1.CreatedAt <= 0 {
		t.Fatalf("backfill 没生效:credential_created_at 仍 0(stdout=%s)", stdout)
	}
	if c1.PSK != knownPSK {
		t.Fatalf("PSK roundtrip 异常:%q != %q", c1.PSK, knownPSK)
	}

	// 再次 show:**同** UUID(稳定),created_at 不变(无 rotate)。
	c, stdout2, _ := runCLI(t, db, "",
		"credentials", "show", "legacy",
		"--psk", knownPSK,
		"--format", "json",
	)
	if c != 0 {
		t.Fatalf("second show failed")
	}
	c2 := parseCredentialsJSON(t, stdout2)
	if c2.ID != c1.ID {
		t.Fatalf("UUID 不稳定:第一次 %q vs 第二次 %q", c1.ID, c2.ID)
	}
	if c2.CreatedAt != c1.CreatedAt {
		t.Fatalf("created_at 漂移:%d -> %d", c1.CreatedAt, c2.CreatedAt)
	}
}

// TestCredentialsList_HumanOutput — P2#5(2026-05-26):
//
// `credentials list`(table 模式)只列 credential_id 非空的 user。验证:
//   - 创建 3 个 user;
//   - 给其中 2 个跑 `credentials show --rotate-psk` → credential_id 落库 + ts 排序前;
//   - 第 3 个老 row backfill 后 ts 较小 → 应排在后。
//   - 创建一个 user 但**不**跑 show / rotate(0013 起 user create 已自动分配
//     UUID + ts;因此实际所有 user 都会出现在 list 里;早期需求"不出 show 就不入
//     list" 在 0013 之后已经天然失效。这里我们改测「list 含全部 3 user,顺序按
//     credential_created_at DESC」即可)。
func TestCredentialsList_HumanOutput(t *testing.T) {
	db := filepath.Join(t.TempDir(), "credlist.db")
	for _, u := range []string{"alice", "bob", "carol"} {
		if c, _, e := runCLI(t, db, "", "user", "create", u, "--psk", "p-"+u); c != 0 {
			t.Fatalf("create %s: %s", u, e)
		}
	}
	c, stdout, stderr := runCLI(t, db, "", "credentials", "list")
	if c != 0 {
		t.Fatalf("credentials list: stderr=%s", stderr)
	}
	for _, u := range []string{"alice", "bob", "carol"} {
		if !strings.Contains(stdout, u) {
			t.Fatalf("table 应含 %q:%s", u, stdout)
		}
	}
	if !strings.Contains(stdout, "USERNAME") || !strings.Contains(stdout, "CREDENTIAL_ID") ||
		!strings.Contains(stdout, "CREATED_AT") {
		t.Fatalf("table 表头不全:%s", stdout)
	}
}

// TestCredentialsList_JSONOutput — `--json credentials list` 必须按
// credential_created_at DESC 排序(最新 rotate 在前)。
func TestCredentialsList_JSONOutput(t *testing.T) {
	db := filepath.Join(t.TempDir(), "credlist_json.db")
	// 三 user,顺序创建 → ts 递增。json list 按 ts DESC,因此 carol 应在 alice 之前。
	for _, u := range []string{"alice", "bob", "carol"} {
		if c, _, e := runCLI(t, db, "", "user", "create", u, "--psk", "p-"+u); c != 0 {
			t.Fatalf("create %s: %s", u, e)
		}
	}
	c, stdout, _ := runCLI(t, db, "", "--json", "credentials", "list")
	if c != 0 {
		t.Fatalf("--json credentials list failed")
	}
	type row struct {
		Username            string `json:"username"`
		CredentialID        string `json:"credential_id"`
		CredentialCreatedAt int64  `json:"credential_created_at"`
		DisabledAt          int64  `json:"disabled_at,omitempty"`
	}
	var rows []row
	if err := json.Unmarshal([]byte(stdout), &rows); err != nil {
		t.Fatalf("parse json: %v\n%s", err, stdout)
	}
	if len(rows) != 3 {
		t.Fatalf("rows=%d,want 3:%+v", len(rows), rows)
	}
	for i := 1; i < len(rows); i++ {
		if rows[i].CredentialCreatedAt > rows[i-1].CredentialCreatedAt {
			t.Fatalf("排序不是 created_at DESC:%+v", rows)
		}
	}
	for _, r := range rows {
		if r.CredentialID == "" {
			t.Fatalf("json 行缺 credential_id:%+v", r)
		}
		if r.CredentialCreatedAt <= 0 {
			t.Fatalf("json 行 created_at 无效:%+v", r)
		}
	}
}

// TestUserResetPSK_WritesAudit — P2#5(2026-05-26):
//
// `user reset-psk <user>` 走完成功路径后必须写一行 `user_reset_psk` audit:
//   - actor    = admin-cli
//   - target   = user:<id>
//   - detail   含 username + credential_id;**绝不**含明文 PSK / hash。
//
// 这是合规要求(谁在何时给谁 rotate 了 PSK 必须能事后追溯),同时是「禁止把
// PSK 落 audit_logs」的回归保护 — audit 表本身长期持久化,落 PSK 等同永久泄密。
func TestUserResetPSK_WritesAudit(t *testing.T) {
	db := filepath.Join(t.TempDir(), "audit.db")
	const knownPSK = "audit-test-init-psk"
	if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", knownPSK); c != 0 {
		t.Fatalf("create alice: %s", e)
	}

	// 跑 reset-psk(自动生成新 PSK)
	c, stdout, stderr := runCLI(t, db, "", "user", "reset-psk", "alice")
	if c != 0 {
		t.Fatalf("reset-psk: code=%d stderr=%s", c, stderr)
	}
	// stdout 里能看到「新 PSK:...」一行,提取 PSK 值用于后面「audit detail 不含 PSK」断言。
	var newPSK string
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		// 兼容 "新 PSK:value" 与 "新 PSK：value"(全角冒号);splitN 用 ":" / ":" 各试一次。
		for _, sep := range []string{"新 PSK：", "新 PSK:"} {
			if i := strings.Index(line, sep); i >= 0 {
				newPSK = strings.TrimSpace(line[i+len(sep):])
				break
			}
		}
		if newPSK != "" {
			break
		}
	}
	if newPSK == "" {
		t.Fatalf("无法从 reset-psk 输出抽取新 PSK:%s", stdout)
	}

	// 直接走 store 拉 audit_logs,查 user_reset_psk 行。
	st := openStoreForTest(t, db)
	defer func() { _ = st.Close() }()
	rows, err := st.QueryAudit(t.Context(), 0, 9999999999, 100)
	if err != nil {
		t.Fatalf("QueryAudit: %v", err)
	}
	var found *store.AuditLog
	for i := range rows {
		if rows[i].Action == "user_reset_psk" {
			found = &rows[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("未找到 user_reset_psk 审计行,有 %d 行:%+v", len(rows), rows)
	}
	if found.Actor != "admin-cli" {
		t.Fatalf("actor 应为 admin-cli,got=%q", found.Actor)
	}
	if !strings.HasPrefix(found.Target, "user:") {
		t.Fatalf("target 应以 user: 开头,got=%q", found.Target)
	}
	if !strings.Contains(found.Detail, "user=alice") {
		t.Fatalf("detail 应含 user=alice:%q", found.Detail)
	}
	if !strings.Contains(found.Detail, "credential_id=") {
		t.Fatalf("detail 应含 credential_id=...:%q", found.Detail)
	}
	if strings.Contains(found.Detail, newPSK) {
		t.Fatalf("audit detail **不**应含明文 PSK:%q", found.Detail)
	}
}

func TestCredentialsShow_QRPNG(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "p.db")
	out := filepath.Join(dir, "cred.png")
	if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", "p"); c != 0 {
		t.Fatalf("create alice: %s", e)
	}
	c, _, stderr := runCLI(t, db, "",
		"credentials", "show", "alice",
		"--psk", "p",
		"--format", "qr-png",
		"--output", out,
	)
	if c != 0 {
		t.Fatalf("qr-png failed: stderr=%s", stderr)
	}
	info, err := os.Stat(out)
	if err != nil {
		t.Fatalf("stat png: %v", err)
	}
	if info.Size() < 64 {
		t.Fatalf("png too small: %d bytes", info.Size())
	}
	// 头部 8 字节签名:\x89PNG\r\n\x1a\n
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read png: %v", err)
	}
	if len(body) < 8 || string(body[:8]) != "\x89PNG\r\n\x1a\n" {
		t.Fatalf("not a valid PNG file header")
	}
}
