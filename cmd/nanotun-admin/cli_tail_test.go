package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestCmdConfig_UsageIsPrintedOnBothTheHelpAndTheErrorPaths(t *testing.T) {
	db := filepath.Join(t.TempDir(), "cfg.db")

	c, out, _ := runCLI(t, db, "", "config", "help")
	if c != 0 {
		t.Fatalf("config help 的退出码 = %d,期望 0", c)
	}
	if !strings.Contains(out, "lint") {
		t.Fatalf("用法里应提到 lint 子命令: %q", out)
	}

	// 没给子命令 / 给了不认识的子命令,都要把用法打到 stderr 并 exit 2。
	for _, args := range [][]string{{"config"}, {"config", "自爆"}} {
		c, _, e := runCLI(t, db, "", args...)
		if c != 2 {
			t.Fatalf("%v 的退出码 = %d,期望 2", args, c)
		}
		if !strings.Contains(e, "lint") {
			t.Fatalf("%v 没把用法打到 stderr: %q", args, e)
		}
	}
}

// 全局 --json 下 credentials show 必须吐**单行** compact JSON:脚本一行行喂给 jq,
// pretty 打印会把一条记录拆成十几行。
func TestCredentialsShow_GlobalJSONEmitsOneCompactLine(t *testing.T) {
	db := filepath.Join(t.TempDir(), "cred.db")
	if c, _, e := runCLI(t, db, "", "user", "create", "creduser", "--psk", "pw"); c != 0 {
		t.Fatalf("user create: %s", e)
	}

	c, out, e := runCLI(t, db, "", "--json", "credentials", "show", "creduser", "--psk", "pw")
	if c != 0 {
		t.Fatalf("code=%d stderr=%s", c, e)
	}
	body := strings.TrimRight(out, "\n")
	if strings.Contains(body, "\n") {
		t.Fatalf("--json 应是单行 compact,实际有换行:\n%s", out)
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatalf("解析不了: %v(%q)", err, body)
	}
	if v["username"] != "creduser" {
		t.Fatalf("username 字段不对: %v", v["username"])
	}
	if !strings.HasSuffix(out, "\n") {
		t.Fatal("末尾要有换行,否则跟下一行输出粘在一起")
	}
}

// set-bandwidth 默认会顺手通知 nanotund 刷新限速。控制面不通时只能是警告 ——
// 库里已经改了,整条命令再报失败会让运维以为没生效而重复执行。
func TestUserSetBandwidth_PushesRateRefreshAndDegradesToAWarning(t *testing.T) {
	db := filepath.Join(t.TempDir(), "bwpush.db")
	if c, _, e := runCLI(t, db, "", "user", "create", "pushuser", "--psk", "p"); c != 0 {
		t.Fatalf("user create: %s", e)
	}
	st := openStoreForTest(t, db)
	u, err := st.GetUserByUsername(t.Context(), "pushuser")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	_ = st.Close()

	fc := newFakeControlSocket(t, map[string]http.HandlerFunc{
		"/users/rate/refresh": jsonHandler(`{"ok":true}`)})
	if c, _, e := runCLISock(t, db, fc.path, "user", "set-bandwidth", "pushuser", "--up-mibs", "3"); c != 0 {
		t.Fatalf("code=%d stderr=%s", c, e)
	}
	if !containsAny(fc.requests(), "user_id="+strconv.FormatInt(u.ID, 10)) {
		t.Fatalf("没通知控制面刷新该用户的限速,改动要等到下次登录才生效: %v", fc.requests())
	}

	t.Run("控制面不通只警告", func(t *testing.T) {
		c, _, e := runCLISock(t, db, "/tmp/绝对不存在的.sock",
			"user", "set-bandwidth", "pushuser", "--down-mibs", "7")
		if c != 0 {
			t.Fatalf("退出码 %d —— 库里已经写好了,不该报失败", c)
		}
		if e == "" {
			t.Fatal("至少要在 stderr 上警告一句「没通知到 nanotund」")
		}
		st2 := openStoreForTest(t, db)
		defer st2.Close()
		u2, _ := st2.GetUserByUsername(t.Context(), "pushuser")
		if u2.BandwidthDownBPS != 7*1024*1024 {
			t.Fatalf("下行 = %d,写库本身不该被控制面的失败影响", u2.BandwidthDownBPS)
		}
	})
}

// 顶层靠 isUsageErr 把退出码判成 2。usageErrorWrap 包了内层错误,得保证
// errors.Is/As 能穿过去 —— 否则「参数解析失败」会被报成普通执行失败(exit 1)。
func TestUsageErrorWrap_KeepsTheInnerErrorReachable(t *testing.T) {
	inner := errors.New("invalid syntax")
	err := usageErrorWrap("用法: nanotun-admin device delete <id>", inner)

	if !errors.Is(err, inner) {
		t.Fatal("errors.Is 穿不过去,内层原因在日志里就丢了")
	}
	if !isUsageErr(err) {
		t.Fatal("isUsageErr 没认出来 —— 退出码会从 2 变成 1")
	}
	if got := err.Error(); !strings.Contains(got, "device delete") || !strings.Contains(got, "invalid syntax") {
		t.Fatalf("文案应同时含用法和原因: %q", got)
	}

	bare := usageError("用法: 什么什么")
	if errors.Unwrap(bare) != nil {
		t.Fatal("没有内层错误时 Unwrap 应返回 nil")
	}
	if !isUsageErr(bare) {
		t.Fatal("裸 usageError 也该被认出来")
	}
	// 包在别人里面也要认得出:调用链上常有 fmt.Errorf("%w") 再包一层。
	if !isUsageErr(errors.Join(errors.New("外层"), err)) {
		t.Fatal("嵌在错误链里就认不出来了")
	}
}
