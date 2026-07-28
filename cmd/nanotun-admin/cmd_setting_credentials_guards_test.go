package main

// cmd_setting_credentials_guards_test.go(第二十二轮)—— setting 与 credentials 剩下的拒绝面。
//
// 两条命令各有一类特有的坏法:
//   - setting:改了库不等于生效。ACL 快照类和限速三件套都缓存在 server 内存里,
//     通知不到时必须明说,否则运维看着「已写入」而数据面照旧;
//   - credentials --rotate-psk:一旦落库,旧 PSK 立刻作废。所以任何**确定性**的
//     输出失败都必须发生在落库之前 —— 否则就是「PSK 已换、明文从未交付」,
//     用户当场断连而运维手里也没有新密钥。

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// failAfterWriter 在写满 okWrites 次之后开始报错,用来模拟 stdout 半途断掉
// (`nanotun-admin credentials show … | head -1` 就会给出 EPIPE)。
type failAfterWriter struct {
	okWrites int
	n        int
}

var errWriterBroken = errors.New("broken pipe (test)")

func (w *failAfterWriter) Write(p []byte) (int, error) {
	w.n++
	if w.n > w.okWrites {
		return 0, errWriterBroken
	}
	return len(p), nil
}

// setSettingValueNull 把某个 setting 的值改成 NULL,让 SettingsGet 往 string 扫时报错。
// 模拟「库被外部工具改坏」而不是「这个 key 没设过」。
func setSettingValueNull(t *testing.T, db, key string) {
	t.Helper()
	relaxAppSettingsValue(t, db)
	st := openStoreForTest(t, db)
	defer st.Close()
	if _, err := st.DB().ExecContext(t.Context(),
		`INSERT INTO app_settings(key, value) VALUES(?, NULL)
		 ON CONFLICT(key) DO UPDATE SET value = NULL`, key); err != nil {
		t.Fatalf("把 %s 置 NULL: %v", key, err)
	}
}

// =========================================================================
// setting
// =========================================================================

// setting rate / probe-dial-host 两个子命令的用法门(顶层 get/set/list 的门在
// cmd_setting_guards_test.go 里)。
func TestCmdSettingRateAndProbe_UsageGuards(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "set-usage.db")
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"rate 带位置参数", []string{"setting", "rate", "50"}},
		{"rate 未知 flag", []string{"setting", "rate", "--bogus"}},
		{"probe-dial-host 不给 host", []string{"setting", "probe-dial-host"}},
		{"probe-dial-host 给两个", []string{"setting", "probe-dial-host", "a.example", "b.example"}},
		{"probe-dial-host host 是空白", []string{"setting", "probe-dial-host", "   "}},
		{"probe-dial-host 未知 flag", []string{"setting", "probe-dial-host", "a.example", "--bogus"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := runCLI(t, db, "", tc.args...)
			if code != 2 {
				t.Fatalf("用法错误应 exit 2, got %d stderr=%q", code, stderr)
			}
		})
	}
}

// setting get:key 不存在与「读不出来」是两回事。前者提示未设置,后者必须当故障报 ——
// 若把读故障当成未设置,运维会照着「没设过」去重设一遍,可能覆盖掉真实值。
func TestCmdSettingGet_MissingVersusUnreadable(t *testing.T) {
	t.Run("key 未设置", func(t *testing.T) {
		db := newInitializedDB(t, t.TempDir(), "set-get-missing.db")
		code, _, stderr := runCLI(t, db, "", "setting", "get", "never_set_this")
		if code == 0 {
			t.Fatal("未设置的 key 却成功返回了值")
		}
		if !strings.Contains(stderr, "never_set_this") {
			t.Errorf("报错没回显 key: %q", stderr)
		}
	})

	t.Run("值读不出来", func(t *testing.T) {
		db := newInitializedDB(t, t.TempDir(), "set-get-bad.db")
		setSettingValueNull(t, db, "advertised_host")
		code, stdout, _ := runCLI(t, db, "", "setting", "get", "advertised_host")
		if code == 0 {
			t.Fatalf("值读不出来却 exit 0, stdout=%q", stdout)
		}
	})
}

// 落库失败时不能打「已写入」—— 那一行是运维唯一的确认信号。
func TestCmdSettingSet_WriteFailureIsLoud(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "set-wfail.db")
	abortWritesOn(t, db, "app_settings", "UPDATE")
	// 先确保这个 key 已存在,这样 upsert 走 UPDATE 分支被触发器拦住。
	if c, _, e := runCLI(t, db, "", "setting", "set", "mesh_enabled", "1"); c != 0 {
		t.Skipf("前置写入就失败了,跳过: %s", e)
	}

	code, stdout, stderr := runCLI(t, db, "", "setting", "set", "mesh_enabled", "0")
	if code == 0 {
		t.Fatalf("写失败却 exit 0, stdout=%q", stdout)
	}
	if strings.Contains(stdout, "已写入") {
		t.Errorf("写失败却打了「已写入」: %q", stdout)
	}
	if strings.TrimSpace(stderr) == "" {
		t.Error("失败却没说原因")
	}
}

// setting list 遇到扫不出来的行必须失败:缺行的设置表会让运维以为某项没配,
// 从而按默认值去推断系统行为。
func TestCmdSettingList_UnreadableRowFailsLoudly(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "set-list-bad.db")
	setSettingValueNull(t, db, "advertised_host")
	code, stdout, _ := runCLI(t, db, "", "setting", "list")
	if code == 0 {
		t.Fatalf("行扫不出来却 exit 0, stdout=%q", stdout)
	}
}

// setting rate 的「值没变」路径:必须仍推一次全量刷新,并在推不动时明说。
// 2026-07-26 三机实测过:库里显示限速、在线会话全速跑,而这条命令因为「值一致」
// 什么都不做 —— 运维就此卡死。推不动时若静默,同一个坑会原样回来。
func TestCmdSettingRate_NoChangeStillReappliesAndWarnsWhenUnreachable(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "set-rate-noop.db")

	// 全新库默认 0;显式传 --up-mibs 0 → 值一致但传了 flag。
	code, stdout, stderr := runCLI(t, db, "", "setting", "rate", "--up-mibs", "0")
	if code != 0 {
		t.Fatalf("setting rate: code=%d stderr=%s", code, stderr)
	}
	// 「传了 flag 但值一致」必须显式说明跳过了写库 —— 否则运维会误以为没生效而反复重跑。
	if !strings.Contains(stdout, "跳过") {
		t.Errorf("没说明值一致、跳过写库: %q", stdout)
	}
	// 没有 control socket → 推不动 → 必须在 stderr 说清楚。
	if strings.TrimSpace(stderr) == "" {
		t.Error("推不动刷新却一句提示都没有 —— 库与在线会话可能长期不一致")
	}

	// --no-refresh 则连推都不推,但仍要展示现值。
	code, stdout, _ = runCLI(t, db, "", "setting", "rate", "--up-mibs", "0", "--no-refresh")
	if code != 0 {
		t.Fatalf("--no-refresh: code=%d", code)
	}
	if strings.TrimSpace(stdout) == "" {
		t.Error("--no-refresh 之下什么都不打,运维无从确认")
	}

	// 一个 flag 都不给 = 纯展示,要给出「怎么改」的提示。
	code, stdout, _ = runCLI(t, db, "", "setting", "rate")
	if code != 0 {
		t.Fatalf("纯展示: code=%d", code)
	}
	if strings.TrimSpace(stdout) == "" {
		t.Error("纯展示什么都不打")
	}
}

// 限速默认值写失败时不能报「已更新」。
func TestCmdSettingRate_WriteFailureIsLoud(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "set-rate-wfail.db")
	abortWritesOn(t, db, "app_settings", "INSERT")

	code, stdout, _ := runCLI(t, db, "", "setting", "rate", "--up-mibs", "50")
	if code == 0 {
		t.Fatalf("写失败却 exit 0, stdout=%q", stdout)
	}
	if strings.Contains(stdout, "已更新") {
		t.Errorf("写失败却报了已更新: %q", stdout)
	}
}

// 现有限速值读不出来时,不能当成 0 继续往下算 —— 那会把「读故障」变成一次
// 「把限速悄悄改成别的值」的写入。
func TestCmdSettingRate_ReadFailureAborts(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "set-rate-rfail.db")
	setSettingValueNull(t, db, "rate_default_upload_bps")

	code, stdout, _ := runCLI(t, db, "", "setting", "rate", "--up-mibs", "50")
	if code == 0 {
		t.Fatalf("现值读不出来却照样改, stdout=%q", stdout)
	}
}

// probe-dial-host 只验证不落库。语法不合法要当场拒,且**绝不能**顺手把它写进设置。
func TestCmdSettingProbeDialHost_SyntaxAndLocalAddresses(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "set-probe.db")

	t.Run("语法不合法", func(t *testing.T) {
		code, stdout, _ := runCLI(t, db, "", "setting", "probe-dial-host", "http://vpn.example.com")
		if code == 0 {
			t.Fatal("带 scheme 的 host 通过了语法校验")
		}
		if strings.TrimSpace(stdout) == "" {
			t.Error("失败却没在 stdout 说清是哪一道没过")
		}
		// 只验证不落库。
		if c, _, _ := runCLI(t, db, "", "setting", "get", "server_dial_host"); c == 0 {
			t.Error("probe 顺手把 host 写进设置了 —— 它应该只验证")
		}
	})

	t.Run("字面 IP + --skip-icmp 直接放行", func(t *testing.T) {
		// 字面 IP 无需 DNS,--skip-icmp 之下没有任何网络动作 —— 因此这条不依赖环境。
		code, stdout, stderr := runCLI(t, db, "",
			"setting", "probe-dial-host", "203.0.113.10", "--skip-icmp")
		if code != 0 {
			t.Fatalf("字面 IP 应通过: code=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
		if strings.TrimSpace(stdout) == "" {
			t.Error("通过了却什么都不说")
		}
	})

	t.Run("解析不出记录", func(t *testing.T) {
		// .invalid 是 RFC 2606 保留的永不解析 TLD,不依赖具体网络环境。
		code, stdout, _ := runCLI(t, db, "",
			"setting", "probe-dial-host", "no-such-host.invalid", "--skip-icmp", "--timeout", "5s")
		if code == 0 {
			t.Fatal("解析不出来的域名却报通过 —— 运维会照着它去 set")
		}
		if strings.TrimSpace(stdout) == "" {
			t.Error("失败却没说是 DNS 这一步")
		}
	})
}

// =========================================================================
// credentials
// =========================================================================

func TestCmdCredentials_FlagGuards(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "cred-usage.db")
	seedACLUsers(t, db, "cu")

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"show 未知 flag", []string{"credentials", "show", "cu", "--bogus"}},
		{"show 不给用户名", []string{"credentials", "show"}},
		{"show 用户名是空白", []string{"credentials", "show", "   ", "--rotate-psk"}},
		{"--psk 与 --rotate-psk 互斥", []string{"credentials", "show", "cu", "--psk", "x", "--rotate-psk"}},
		{"两者都不给", []string{"credentials", "show", "cu"}},
		{"--format 非法", []string{"credentials", "show", "cu", "--rotate-psk", "--format", "pdf"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := runCLI(t, db, "", tc.args...)
			if code != 2 {
				t.Fatalf("用法错误应 exit 2, got %d stderr=%q", code, stderr)
			}
		})
	}
}

// wire 里的 host / server_id 读不出来时必须在**轮换之前**失败。若拖到轮换之后才报,
// 就是「PSK 已换、明文从未交付」:用户现有客户端立刻断连,而运维手里没有新密钥。
func TestCmdCredentialsShow_WireFieldReadFailuresHappenBeforeRotation(t *testing.T) {
	for _, key := range []string{"advertised_host", "server_id"} {
		t.Run(key+" 读不出来", func(t *testing.T) {
			db := newInitializedDB(t, t.TempDir(), "cred-"+key+".db")
			seedACLUsers(t, db, "cw")
			before := userPSKHash(t, db, "cw")
			setSettingValueNull(t, db, key)

			code, stdout, stderr := runCLI(t, db, "", "credentials", "show", "cw", "--rotate-psk")
			if code == 0 {
				t.Fatalf("%s 读不出来却成功了, stdout=%q", key, stdout)
			}
			if strings.TrimSpace(stderr) == "" {
				t.Error("失败却没说原因")
			}
			if got := userPSKHash(t, db, "cw"); got != before {
				t.Fatalf("%s 读失败发生在轮换之后 —— PSK 已换但明文从未交付", key)
			}
		})
	}
}

// 老库里 credential_id 为空的 user 首次 rotate 时会顺手 backfill 一个 UUID,
// 审计 detail 要留下痕迹,否则事后无法解释「这个 UUID 是哪来的」。
func TestCmdCredentialsShow_BackfillsCredentialIDAndAuditsIt(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "cred-backfill.db")
	seedACLUsers(t, db, "oldie")
	// 模拟 0013 之前的老 row:credential_id 为空。
	aclExec(t, db, `UPDATE users SET credential_id = '' WHERE username = 'oldie'`)

	code, stdout, stderr := runCLI(t, db, "", "credentials", "show", "oldie", "--rotate-psk")
	if code != 0 {
		t.Fatalf("rotate: code=%d stderr=%s", code, stderr)
	}
	if strings.TrimSpace(stdout) == "" {
		t.Fatal("没输出凭证")
	}

	_, audit, _ := runCLI(t, db, "", "audit", "list", "--action", "credentials_rotate_psk")
	if !strings.Contains(audit, "backfilled") {
		t.Errorf("backfill 没留下审计痕迹:\n%s", audit)
	}
}

// 轮换写库失败时:不能输出任何明文(运维会拿去配客户端),库里的 hash 也不能变。
func TestCmdCredentialsShow_RotateWriteFailureEmitsNothing(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "cred-rotfail.db")
	seedACLUsers(t, db, "cr")
	before := userPSKHash(t, db, "cr")
	abortWritesOn(t, db, "users", "UPDATE")

	code, stdout, stderr := runCLI(t, db, "", "credentials", "show", "cr", "--rotate-psk")
	if code == 0 {
		t.Fatalf("写失败却 exit 0, stdout=%q", stdout)
	}
	if strings.Contains(stdout, "nanotun-cred://") || strings.Contains(stdout, `"psk"`) {
		t.Errorf("写失败却输出了凭证: %q", stdout)
	}
	if strings.TrimSpace(stderr) == "" {
		t.Error("失败却没说原因")
	}
	if got := userPSKHash(t, db, "cr"); got != before {
		t.Fatal("写被拒了 hash 却变了")
	}
}

// --psk 读路径:库里的 hash 坏掉时不能当成「PSK 不匹配」—— 那会让运维以为自己记错了
// 密钥,进而去 rotate(把还能用的凭证换掉)。必须报成校验故障。
func TestCmdCredentialsShow_CorruptHashIsAFailureNotAMismatch(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "cred-badhash.db")
	seedACLUsers(t, db, "ch")
	aclExec(t, db, `UPDATE users SET psk_hash = 'not-a-valid-hash' WHERE username = 'ch'`)

	code, stdout, stderr := runCLI(t, db, "", "credentials", "show", "ch", "--psk", "whatever")
	if code == 0 {
		t.Fatalf("hash 坏掉却成功输出了凭证: %q", stdout)
	}
	if strings.TrimSpace(stderr) == "" {
		t.Error("失败却没说原因")
	}
}

// 只读路径下 credential_id 的 backfill 写失败也要报错,不能输出一份 id 为空的凭证 ——
// 客户端拿到空 id 无法与服务端对账。
func TestCmdCredentialsShow_ReadPathBackfillFailureIsLoud(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "cred-ensurefail.db")
	seedACLUsers(t, db, "ce")
	aclExec(t, db, `UPDATE users SET credential_id = '' WHERE username = 'ce'`)
	abortWritesOn(t, db, "users", "UPDATE")

	code, stdout, _ := runCLI(t, db, "", "credentials", "show", "ce", "--psk", "psk-ce-12345678")
	if code == 0 {
		t.Fatalf("backfill 写失败却输出了凭证: %q", stdout)
	}
}

// --format qr 是纯终端输出,给了 --output 也不会写文件 —— 必须明确告诉运维这一点,
// 否则他会以为文件已生成并把「不存在的文件」派给用户。
func TestCmdCredentialsShow_QRIgnoresOutputButSaysSo(t *testing.T) {
	dir := t.TempDir()
	db := newInitializedDB(t, dir, "cred-qr.db")
	seedACLUsers(t, db, "cq")
	out := filepath.Join(dir, "will-not-exist.txt")

	code, stdout, stderr := runCLI(t, db, "", "credentials", "show", "cq",
		"--psk", "psk-cq-12345678", "--format", "qr", "--output", out)
	if code != 0 {
		t.Fatalf("qr: code=%d stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr, out) {
		t.Errorf("没说清 --output 被忽略了: %q", stderr)
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("qr 格式竟然写出了文件 —— 与提示自相矛盾")
	}
	if strings.TrimSpace(stdout) == "" {
		t.Error("终端二维码没输出")
	}
}

// --output 指向不存在的目录时要报错。读路径(--psk)不走 rotate 前置检查,
// 失败点落在真正写盘那一步,同样不能谎报成功。
func TestCmdCredentialsShow_BadOutputDirOnReadPath(t *testing.T) {
	dir := t.TempDir()
	db := newInitializedDB(t, dir, "cred-badout.db")
	seedACLUsers(t, db, "cb")
	bad := filepath.Join(dir, "no-such-dir", "cred.json")

	for _, extra := range [][]string{
		{"--format", "url"},
		{"--format", "json"},
	} {
		args := append([]string{"credentials", "show", "cb", "--psk", "psk-cb-12345678", "--output", bad}, extra...)
		code, stdout, stderr := runCLI(t, db, "", args...)
		if code == 0 {
			t.Fatalf("%v: 目录不存在却报成功, stdout=%q", extra, stdout)
		}
		if strings.TrimSpace(stderr) == "" {
			t.Errorf("%v: 失败却没说原因", extra)
		}
	}

	// --json 全局开关走另一条写盘分支,同样要失败。
	code, _, stderr := runCLI(t, db, "", "--json", "credentials", "show", "cb",
		"--psk", "psk-cb-12345678", "--output", bad)
	if code == 0 {
		t.Fatal("--json 路径下目录不存在却报成功")
	}
	if strings.TrimSpace(stderr) == "" {
		t.Error("--json 路径失败却没说原因")
	}
}

// credentials list 读不出用户时必须失败 —— 一张空的凭证清单会让运维以为「谁都还没发过卡」。
func TestCmdCredentialsList_QueryFailureIsLoud(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "cred-listfail.db")
	aclExec(t, db, `ALTER TABLE users RENAME TO users_gone`)
	code, stdout, _ := runCLI(t, db, "", "credentials", "list")
	if code == 0 {
		t.Fatalf("查不到用户表却 exit 0, stdout=%q", stdout)
	}
}

// 输出写一半断掉(典型:管道给 head)时必须把错误传上去,而不是当成写完了。
// 这几条分支只能直接调 —— CLI 层的 stdout 在测试里是内存 buffer,永远不会失败。
func TestEmitCredentials_WriterFailuresPropagate(t *testing.T) {
	cred := &credentialsSchema{
		Version:   credentialsSchemaVersion,
		ID:        "11111111-2222-4333-8444-555555555555",
		Username:  "u",
		PSK:       "psk-value",
		CreatedAt: 1700000000,
		Host:      "vpn.example.com",
		ServerID:  "srv-1",
	}

	newOpts := func(w *failAfterWriter, jsonMode bool) *globalOpts {
		return &globalOpts{lang: langZH, stdout: w, stderr: &bytes.Buffer{},
			stdin: strings.NewReader(""), json: jsonMode}
	}

	t.Run("--json compact 写失败", func(t *testing.T) {
		opts := newOpts(&failAfterWriter{}, true)
		if err := emitCredentials(cred, "json", "", false, opts); !errors.Is(err, errWriterBroken) {
			t.Fatalf("err=%v, 期望透传写失败", err)
		}
	})

	t.Run("json pretty 写失败", func(t *testing.T) {
		opts := newOpts(&failAfterWriter{}, false)
		if err := emitCredentials(cred, "json", "", false, opts); !errors.Is(err, errWriterBroken) {
			t.Fatalf("err=%v", err)
		}
	})

	t.Run("url 写失败", func(t *testing.T) {
		opts := newOpts(&failAfterWriter{}, false)
		if err := emitCredentials(cred, "url", "", false, opts); !errors.Is(err, errWriterBroken) {
			t.Fatalf("err=%v", err)
		}
	})

	// both 会连写三段(JSON、分隔换行、URL)。三个断点都要能把错误带出来,
	// 否则会出现「只写了一半的凭证文件」而命令报成功。
	for okWrites := 0; okWrites <= 2; okWrites++ {
		t.Run(fmt.Sprintf("both 在第 %d 次写之后断掉", okWrites), func(t *testing.T) {
			opts := newOpts(&failAfterWriter{okWrites: okWrites}, false)
			if err := emitCredentials(cred, "both", "", false, opts); !errors.Is(err, errWriterBroken) {
				t.Fatalf("err=%v", err)
			}
		})
	}

	t.Run("format 不认识", func(t *testing.T) {
		// validFormat 会先拦住这种值,但 writeCredentials 的兜底分支仍须是「报错」
		// 而不是「静默写出空内容」—— 将来加新 format 时忘了同步这里就会被这条抓住。
		var buf bytes.Buffer
		if err := writeCredentials(&buf, cred, "yaml"); err == nil {
			t.Fatal("不认识的 format 却静默成功了")
		}
		if buf.Len() != 0 {
			t.Errorf("不认识的 format 还是写出了内容: %q", buf.String())
		}
	})
}
