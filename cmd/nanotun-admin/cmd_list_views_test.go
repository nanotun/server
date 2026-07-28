package main

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// 列表类命令是运维最常敲的。它们此前只被"能跑起来"的冒烟测试扫过,过滤条件和
// --json 形态都没验过 —— 而过滤条件写反了会让人对着一张漏掉一半行的表做决策。

func TestDeviceList_FiltersByUserAndSpeaksJSON(t *testing.T) {
	db := filepath.Join(t.TempDir(), "devlist.db")
	seedDevice(t, db, "alice", "aaaaaaaa-0000-4000-8000-000000000001")
	seedDevice(t, db, "bob", "bbbbbbbb-0000-4000-8000-000000000002")

	t.Run("不带过滤 = 全量", func(t *testing.T) {
		c, out, e := runCLI(t, db, "", "device", "list")
		if c != 0 {
			t.Fatalf("code=%d stderr=%s", c, e)
		}
		if !strings.Contains(out, "aaaaaaaa") || !strings.Contains(out, "bbbbbbbb") {
			t.Fatalf("两台设备都该列出来: %q", out)
		}
	})

	t.Run("--user 只列该用户的", func(t *testing.T) {
		c, out, e := runCLI(t, db, "", "device", "list", "--user", "alice")
		if c != 0 {
			t.Fatalf("code=%d stderr=%s", c, e)
		}
		if !strings.Contains(out, "aaaaaaaa") {
			t.Fatalf("alice 的设备没列出来: %q", out)
		}
		if strings.Contains(out, "bbbbbbbb") {
			t.Fatalf("串到 bob 的设备了 —— 过滤形同虚设: %q", out)
		}
	})

	t.Run("--json 是数组", func(t *testing.T) {
		c, out, _ := runCLI(t, db, "", "--json", "device", "list")
		if c != 0 {
			t.Fatalf("code=%d", c)
		}
		var rows []map[string]any
		if err := json.Unmarshal([]byte(out), &rows); err != nil {
			t.Fatalf("--json 应吐数组: %v(%q)", err, out)
		}
		if len(rows) != 2 {
			t.Fatalf("应有 2 条,got %d", len(rows))
		}
	})

	t.Run("用户不存在 → exit 1", func(t *testing.T) {
		if c, _, _ := runCLI(t, db, "", "device", "list", "--user", "查无此人"); c != 1 {
			t.Fatalf("退出码应为 1")
		}
	})

	t.Run("不认识的 flag → exit 2", func(t *testing.T) {
		if c, _, _ := runCLI(t, db, "", "device", "list", "--everything"); c != 2 {
			t.Fatal("flag 解析失败属用法错")
		}
	})
}

// --effective 要把 device / app_settings / toml / user 四层限速取 min 后显示。
// 控制面拿不到 toml 那层时只警告、照常出表 —— server 没起时列表仍然可用。
func TestDeviceList_EffectiveTakesTheMinAcrossLayersAndDegradesGracefully(t *testing.T) {
	db := filepath.Join(t.TempDir(), "deveff.db")
	id := seedDevice(t, db, "effuser", "cccccccc-0000-4000-8000-000000000003")
	idStr := strconv.FormatInt(id, 10)

	// device 层 100 MiB/s,server 的 toml 层 1000 B/s —— 生效值必须取小的那个。
	if c, _, e := runCLI(t, db, "", "device", "set-rate", idStr,
		"--up-mibs", "100", "--down-mibs", "100", "--no-refresh"); c != 0 {
		t.Fatalf("set-rate: %s", e)
	}
	fc := newFakeControlSocket(t, map[string]http.HandlerFunc{
		"/status": jsonHandler(`{"rate_config":{"toml_up_bps":1000,"toml_down_bps":2000}}`)})

	c, out, e := runCLISock(t, db, fc.path, "device", "list", "--effective")
	if c != 0 {
		t.Fatalf("code=%d stderr=%s", c, e)
	}
	if strings.Contains(out, "100") && !strings.Contains(out, "1000") {
		t.Fatalf("看起来没叠加 toml 层:\n%s", out)
	}

	t.Run("控制面不通只警告", func(t *testing.T) {
		c, out, e := runCLISock(t, db, "/tmp/绝对不存在的.sock", "device", "list", "--effective")
		if c != 0 {
			t.Fatalf("退出码 %d —— server 没起时列表也该能看", c)
		}
		if e == "" {
			t.Fatal("拿不到 toml 层限速要在 stderr 说一声,不然表里的数会被当成真的生效值")
		}
		if !strings.Contains(out, "cccccccc") {
			t.Fatalf("表还是要出的: %q", out)
		}
	})
}

func TestRouteList_FiltersByDeviceStatusAndUser(t *testing.T) {
	db := filepath.Join(t.TempDir(), "routelist.db")
	idA := seedDevice(t, db, "ralice", "dddddddd-0000-4000-8000-000000000004")
	idB := seedDevice(t, db, "rbob", "eeeeeeee-0000-4000-8000-000000000005")

	st := openStoreForTest(t, db)
	for _, x := range []struct {
		dev  int64
		cidr string
	}{{idA, "192.168.10.0/24"}, {idA, "192.168.11.0/24"}, {idB, "192.168.20.0/24"}} {
		if _, err := st.UpsertAdvertisedRoute(t.Context(), x.dev, x.cidr); err != nil {
			t.Fatalf("UpsertAdvertisedRoute: %v", err)
		}
	}
	if err := st.SetRouteStatus(t.Context(), idA, "192.168.10.0/24", "approved", ""); err != nil {
		t.Fatalf("SetRouteStatus: %v", err)
	}
	_ = st.Close()

	t.Run("全量", func(t *testing.T) {
		_, out, _ := runCLI(t, db, "", "route", "list")
		for _, want := range []string{"192.168.10.0/24", "192.168.11.0/24", "192.168.20.0/24"} {
			if !strings.Contains(out, want) {
				t.Fatalf("缺 %s:\n%s", want, out)
			}
		}
	})

	t.Run("--device", func(t *testing.T) {
		_, out, _ := runCLI(t, db, "", "route", "list", "--device", strconv.FormatInt(idA, 10))
		if !strings.Contains(out, "192.168.10.0/24") {
			t.Fatalf("缺自己的路由:\n%s", out)
		}
		if strings.Contains(out, "192.168.20.0/24") {
			t.Fatalf("串到别的设备了:\n%s", out)
		}
	})

	t.Run("--status", func(t *testing.T) {
		_, out, _ := runCLI(t, db, "", "route", "list", "--status", "approved")
		if !strings.Contains(out, "192.168.10.0/24") {
			t.Fatalf("已批准的没列出来:\n%s", out)
		}
		if strings.Contains(out, "192.168.11.0/24") {
			t.Fatalf("pending 的混进 approved 结果里了 —— 会被当成已经放行:\n%s", out)
		}
	})

	t.Run("--user", func(t *testing.T) {
		_, out, _ := runCLI(t, db, "", "route", "list", "--user", "ralice")
		if !strings.Contains(out, "192.168.11.0/24") {
			t.Fatalf("缺 ralice 的路由:\n%s", out)
		}
		if strings.Contains(out, "192.168.20.0/24") {
			t.Fatalf("串到 rbob 的路由了:\n%s", out)
		}
	})

	t.Run("--json", func(t *testing.T) {
		_, out, _ := runCLI(t, db, "", "--json", "route", "list")
		var rows []map[string]any
		if err := json.Unmarshal([]byte(out), &rows); err != nil {
			t.Fatalf("--json 应吐数组: %v(%q)", err, out)
		}
		if len(rows) != 3 {
			t.Fatalf("应有 3 条,got %d", len(rows))
		}
	})

	t.Run("--user 查无此人 → exit 1", func(t *testing.T) {
		if c, _, _ := runCLI(t, db, "", "route", "list", "--user", "查无此人"); c != 1 {
			t.Fatal("退出码应为 1")
		}
	})
	t.Run("坏 flag → exit 2", func(t *testing.T) {
		if c, _, _ := runCLI(t, db, "", "route", "list", "--device", "abc"); c != 2 {
			t.Fatal("--device 不是数字属用法错")
		}
	})
}

func TestRouteDelete_ConfirmsFirstAndReportsMissingRowsPlainly(t *testing.T) {
	db := filepath.Join(t.TempDir(), "routedel.db")
	id := seedDevice(t, db, "rdel", "ffffffff-0000-4000-8000-000000000006")
	idStr := strconv.FormatInt(id, 10)

	st := openStoreForTest(t, db)
	if _, err := st.UpsertAdvertisedRoute(t.Context(), id, "10.9.0.0/24"); err != nil {
		t.Fatalf("UpsertAdvertisedRoute: %v", err)
	}
	_ = st.Close()

	routeExists := func() bool {
		st := openStoreForTest(t, db)
		defer st.Close()
		rows, err := st.ListRoutesByDevice(t.Context(), id)
		if err != nil {
			return false
		}
		for _, r := range rows {
			if r.CIDR == "10.9.0.0/24" {
				return true
			}
		}
		return false
	}

	t.Run("回答 n 就不删", func(t *testing.T) {
		if c, _, e := runCLIInteractive(t, db, "n\n", "route", "delete", idStr, "10.9.0.0/24"); c != 0 {
			t.Fatalf("code=%d stderr=%s", c, e)
		}
		if !routeExists() {
			t.Fatal("拒绝确认之后路由还是被删了")
		}
	})

	t.Run("确认后真删", func(t *testing.T) {
		if c, _, e := runCLIInteractive(t, db, "y\n", "route", "delete", idStr, "10.9.0.0/24"); c != 0 {
			t.Fatalf("code=%d stderr=%s", c, e)
		}
		if routeExists() {
			t.Fatal("路由还在")
		}
	})

	t.Run("删不存在的行给可读错误", func(t *testing.T) {
		c, _, e := runCLI(t, db, "", "route", "delete", idStr, "10.9.0.0/24")
		if c != 1 {
			t.Fatalf("退出码 %d,期望 1", c)
		}
		if !strings.Contains(e, "10.9.0.0/24") {
			t.Fatalf("错误里应点名是哪条路由: %q", e)
		}
	})

	t.Run("参数不全 → exit 2", func(t *testing.T) {
		for _, args := range [][]string{
			{"route", "delete"},
			{"route", "delete", idStr},
			{"route", "delete", "abc", "10.9.0.0/24"},
			{"route", "delete", idStr, "不是个网段"},
		} {
			if c, _, _ := runCLI(t, db, "", args...); c != 2 {
				t.Fatalf("%v 的退出码不是 2", args)
			}
		}
	})
}

func TestUserDelete_NeedsConfirmationAndTakesTheDevicesWithIt(t *testing.T) {
	db := filepath.Join(t.TempDir(), "userdel.db")
	seedDevice(t, db, "doomed", "99999999-0000-4000-8000-000000000007")

	userExists := func() bool {
		st := openStoreForTest(t, db)
		defer st.Close()
		_, err := st.GetUserByUsername(t.Context(), "doomed")
		return err == nil
	}

	t.Run("回答 n 就不删", func(t *testing.T) {
		c, out, e := runCLIInteractive(t, db, "n\n", "user", "delete", "doomed")
		if c != 0 {
			t.Fatalf("code=%d stderr=%s", c, e)
		}
		if out == "" {
			t.Fatal("取消了要说一声,不然运维不知道到底删没删")
		}
		if !userExists() {
			t.Fatal("拒绝确认之后账号还是被删了 —— 这是最高破坏性操作")
		}
	})

	t.Run("确认后真删", func(t *testing.T) {
		if c, _, e := runCLIInteractive(t, db, "y\n", "user", "delete", "doomed"); c != 0 {
			t.Fatalf("code=%d stderr=%s", c, e)
		}
		if userExists() {
			t.Fatal("账号还在")
		}
	})

	t.Run("再删一次报找不到", func(t *testing.T) {
		if c, _, _ := runCLI(t, db, "", "user", "delete", "doomed"); c != 1 {
			t.Fatal("退出码应为 1")
		}
	})

	t.Run("参数不对 → exit 2", func(t *testing.T) {
		if c, _, _ := runCLI(t, db, "", "user", "delete"); c != 2 {
			t.Fatal("缺用户名属用法错")
		}
		if c, _, _ := runCLI(t, db, "", "user", "delete", "a", "b"); c != 2 {
			t.Fatal("多给一个参数属用法错")
		}
	})
}

func TestLeaseList_ShowsWhatWasJustSet(t *testing.T) {
	db := filepath.Join(t.TempDir(), "leaselist.db")
	id := seedDevice(t, db, "llowner", "88888888-0000-4000-8000-000000000008")
	idStr := strconv.FormatInt(id, 10)
	if c, _, e := runCLI(t, db, "", "lease", "set", idStr, "--v4", "10.80.0.77"); c != 0 {
		t.Fatalf("lease set: %s", e)
	}

	c, out, e := runCLI(t, db, "", "lease", "list")
	if c != 0 {
		t.Fatalf("code=%d stderr=%s", c, e)
	}
	if !strings.Contains(out, "10.80.0.77") {
		t.Fatalf("刚设的租约没列出来:\n%s", out)
	}

	_, jout, _ := runCLI(t, db, "", "--json", "lease", "list")
	var rows []map[string]any
	if err := json.Unmarshal([]byte(jout), &rows); err != nil {
		t.Fatalf("--json 应吐数组: %v(%q)", err, jout)
	}
	if len(rows) != 1 {
		t.Fatalf("应有 1 条,got %d", len(rows))
	}
}

func TestAgeFromUnix_NeverShowsANegativeAge(t *testing.T) {
	if got := ageFromUnix(0); got != "-" {
		t.Fatalf("没有时间戳应显示 -,got %q", got)
	}
	if got := ageFromUnix(-5); got != "-" {
		t.Fatalf("负时间戳应显示 -,got %q", got)
	}
	// 时钟回拨 / 服务端时间超前时,"-3h" 这种输出会让人以为读错了列。
	if got := ageFromUnix(time.Now().Add(time.Hour).Unix()); got != "-" {
		t.Fatalf("未来的时间戳应显示 -,got %q", got)
	}
	got := ageFromUnix(time.Now().Add(-90 * time.Second).Unix())
	if !strings.Contains(got, "m") {
		t.Fatalf("90 秒前应显示成分钟级,got %q", got)
	}
}

func TestBurstBytesHuman_PicksTheUnitAndCallsZeroTheDefault(t *testing.T) {
	opts := &globalOpts{lang: "zh"}
	zero := burstBytesHuman(opts, 0)
	if zero == "" || strings.Contains(zero, "0") {
		t.Fatalf("0 表示「用默认 burst」,不该显示成 0 字节: %q", zero)
	}
	if burstBytesHuman(opts, -1) != zero {
		t.Fatal("负值同 0")
	}
	if got := burstBytesHuman(opts, 64*1024); got != "64 KiB" {
		t.Fatalf("got %q", got)
	}
	if got := burstBytesHuman(opts, 1024*1024); got != "1.00 MiB" {
		t.Fatalf("1 MiB 是 KiB/MiB 的分界点,got %q", got)
	}
	if got := burstBytesHuman(opts, 1024*1024-1); !strings.HasSuffix(got, "KiB") {
		t.Fatalf("刚好差一字节应还在 KiB 档,got %q", got)
	}
}
