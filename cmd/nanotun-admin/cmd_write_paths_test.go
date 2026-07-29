package main

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// 这一批是 CLI 侧「改状态」的子命令:改别名、删设备、改限速、回收租约、放租约、
// 改账号带宽。Web 侧同名操作都有测试,CLI 侧此前一条没有 —— 而两条路各自解析
// 参数、各自写库。

// runCLIInteractive 跟 runCLI 一样,但**不**带 --yes —— 用来测那些危险子命令的
// 二次确认。stdin 是喂给 confirm 的回答。
func runCLIInteractive(t *testing.T, dbPath, stdin string, args ...string) (int, string, string) {
	t.Helper()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	opts := &globalOpts{stdout: stdout, stderr: stderr, stdin: strings.NewReader(stdin)}
	full := append([]string{"--db-path", dbPath, "--lang", "zh"}, args...)
	rest, err := parseGlobalFlags(full, opts)
	if err != nil {
		t.Fatalf("parseGlobalFlags: %v", err)
	}
	return runRoot(rest, opts), stdout.String(), stderr.String()
}

func newConfirmOpts(stdin string) (*globalOpts, *bytes.Buffer) {
	out := &bytes.Buffer{}
	return &globalOpts{
		stdout: out,
		stderr: &bytes.Buffer{},
		stdin:  strings.NewReader(stdin),
		lang:   "zh",
	}, out
}

// seedDevice 建一个用户 + 一台设备,返回 device_id。
func seedDevice(t *testing.T, db, username, uuid string) int64 {
	t.Helper()
	if c, _, e := runCLI(t, db, "", "user", "create", username, "--psk", "p"); c != 0 {
		t.Fatalf("user create: %s", e)
	}
	if c, _, e := runCLI(t, db, "", "device", "create", username, "--uuid", uuid, "--name", "box"); c != 0 {
		t.Fatalf("device create: %s", e)
	}
	st := openStoreForTest(t, db)
	defer st.Close()
	u, err := st.GetUserByUsername(t.Context(), username)
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	d, err := st.GetDeviceByUUID(t.Context(), u.ID, uuid)
	if err != nil || d == nil {
		t.Fatalf("GetDeviceByUUID: %v", err)
	}
	return d.ID
}

func TestDeviceSetAlias_SetsAndClears(t *testing.T) {
	db := filepath.Join(t.TempDir(), "alias.db")
	id := seedDevice(t, db, "aliasowner", "11111111-1111-4111-8111-111111111111")
	idStr := strconv.FormatInt(id, 10)

	c, out, e := runCLI(t, db, "", "device", "set-alias", idStr, "  机房 A 的出口  ")
	if c != 0 {
		t.Fatalf("set-alias: code=%d stderr=%s", c, e)
	}
	if !strings.Contains(out, "机房 A 的出口") {
		t.Fatalf("输出里应回显新别名: %s", out)
	}

	st := openStoreForTest(t, db)
	d, err := st.GetDevice(t.Context(), id)
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	_ = st.Close()
	if d.Alias != "机房 A 的出口" {
		t.Fatalf("库里别名 = %q,前后空白应被裁掉", d.Alias)
	}

	// 空串 = 清除,回落到客户端上报的设备名。
	if c, _, e := runCLI(t, db, "", "device", "set-alias", idStr, ""); c != 0 {
		t.Fatalf("清除别名: code=%d stderr=%s", c, e)
	}
	st2 := openStoreForTest(t, db)
	d2, _ := st2.GetDevice(t.Context(), id)
	_ = st2.Close()
	if d2.Alias != "" {
		t.Fatalf("别名没清掉: %q", d2.Alias)
	}
}

func TestDeviceSetAlias_RejectsBadInput(t *testing.T) {
	db := filepath.Join(t.TempDir(), "alias-bad.db")
	seedDevice(t, db, "u", "22222222-2222-4222-8222-222222222222")

	cases := []struct {
		name string
		args []string
		want int
	}{
		{"缺参数", []string{"device", "set-alias"}, 2},
		{"只给 id", []string{"device", "set-alias", "1"}, 2},
		{"id 不是数字", []string{"device", "set-alias", "abc", "x"}, 2},
		{"设备不存在", []string{"device", "set-alias", "999999", "x"}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if c, _, _ := runCLI(t, db, "", tc.args...); c != tc.want {
				t.Fatalf("退出码 %d,期望 %d —— 脚本靠它区分「用法错」和「执行失败」", c, tc.want)
			}
		})
	}
}

func TestDeviceDelete_RemovesTheRow(t *testing.T) {
	db := filepath.Join(t.TempDir(), "devdel.db")
	id := seedDevice(t, db, "delowner", "33333333-3333-4333-8333-333333333333")
	idStr := strconv.FormatInt(id, 10)

	if c, _, e := runCLI(t, db, "", "device", "delete", idStr); c != 0 {
		t.Fatalf("device delete: code=%d stderr=%s", c, e)
	}
	st := openStoreForTest(t, db)
	_, err := st.GetDevice(t.Context(), id)
	_ = st.Close()
	if err == nil {
		t.Fatal("设备还在库里")
	}

	// 再删一次要给「找不到」而不是崩,脚本重跑是常态。
	if c, _, _ := runCLI(t, db, "", "device", "delete", idStr); c == 0 {
		t.Fatal("删一个不存在的设备不该报成功")
	}
	if c, _, _ := runCLI(t, db, "", "device", "delete"); c != 2 {
		t.Fatal("缺参数应是用法错(exit 2)")
	}
	if c, _, _ := runCLI(t, db, "", "device", "delete", "abc"); c != 2 {
		t.Fatal("id 不是数字应是用法错(exit 2)")
	}
}

func TestDeviceSetRate_AcceptsBothUnitsAndLeavesUntouchedSidesAlone(t *testing.T) {
	db := filepath.Join(t.TempDir(), "devrate.db")
	id := seedDevice(t, db, "rateowner", "44444444-4444-4444-8444-444444444444")
	idStr := strconv.FormatInt(id, 10)

	rates := func() (int64, int64) {
		st := openStoreForTest(t, db)
		defer st.Close()
		d, err := st.GetDevice(t.Context(), id)
		if err != nil {
			t.Fatalf("GetDevice: %v", err)
		}
		return d.RateUploadBPS, d.RateDownloadBPS
	}

	// MiB/s 换算成字节每秒。换算掉了 8 倍(bit/byte 混淆)是这类代码的经典错误。
	if c, _, e := runCLI(t, db, "", "device", "set-rate", idStr,
		"--up-mibs", "10", "--down-mibs", "20", "--no-refresh"); c != 0 {
		t.Fatalf("set-rate: code=%d stderr=%s", c, e)
	}
	up, down := rates()
	if up != 10*1024*1024 || down != 20*1024*1024 {
		t.Fatalf("up=%d down=%d,期望 %d / %d", up, down, 10*1024*1024, 20*1024*1024)
	}

	// 只改上行,下行必须保持不变 —— 顺手清零的话用户会突然被限死。
	if c, _, e := runCLI(t, db, "", "device", "set-rate", idStr, "--up-bps", "12345", "--no-refresh"); c != 0 {
		t.Fatalf("set-rate: code=%d stderr=%s", c, e)
	}
	up, down = rates()
	if up != 12345 {
		t.Fatalf("上行 = %d,期望 12345", up)
	}
	if down != 20*1024*1024 {
		t.Fatalf("只改了上行,下行却变成了 %d", down)
	}

	// 0 = 不限速,是个合法值。
	if c, _, e := runCLI(t, db, "", "device", "set-rate", idStr,
		"--up-bps", "0", "--down-bps", "0", "--no-refresh"); c != 0 {
		t.Fatalf("set-rate 0: code=%d stderr=%s", c, e)
	}
	if up, down = rates(); up != 0 || down != 0 {
		t.Fatalf("up=%d down=%d,期望都是 0", up, down)
	}
}

func TestDeviceSetRate_RejectsBadInput(t *testing.T) {
	db := filepath.Join(t.TempDir(), "devrate-bad.db")
	id := seedDevice(t, db, "u", "55555555-5555-4555-8555-555555555555")
	idStr := strconv.FormatInt(id, 10)

	cases := []struct {
		name string
		args []string
		want int
	}{
		{"缺 device_id", []string{"device", "set-rate", "--up-mibs", "1"}, 2},
		{"id 不是数字", []string{"device", "set-rate", "abc", "--up-mibs", "1"}, 2},
		{"设备不存在", []string{"device", "set-rate", "999999", "--up-mibs", "1"}, 1},
		{"两种单位同时给", []string{"device", "set-rate", idStr, "--up-mibs", "1", "--up-bps", "100"}, 1},
		{"速率不是数字", []string{"device", "set-rate", idStr, "--up-bps", "很快"}, 1},
		{"负数", []string{"device", "set-rate", idStr, "--up-bps", "-1"}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if c, _, _ := runCLI(t, db, "", tc.args...); c != tc.want {
				t.Fatalf("退出码 %d,期望 %d", c, tc.want)
			}
		})
	}
}

func TestUserSetBandwidth_MirrorsTheDeviceLevelSemantics(t *testing.T) {
	db := filepath.Join(t.TempDir(), "userbw.db")
	if c, _, e := runCLI(t, db, "", "user", "create", "bwuser", "--psk", "p"); c != 0 {
		t.Fatalf("user create: %s", e)
	}

	bw := func() (int64, int64) {
		st := openStoreForTest(t, db)
		defer st.Close()
		u, err := st.GetUserByUsername(t.Context(), "bwuser")
		if err != nil {
			t.Fatalf("GetUserByUsername: %v", err)
		}
		return u.BandwidthUpBPS, u.BandwidthDownBPS
	}

	if c, _, e := runCLI(t, db, "", "user", "set-bandwidth", "bwuser",
		"--up-mibs", "5", "--down-mibs", "50", "--no-refresh"); c != 0 {
		t.Fatalf("set-bandwidth: code=%d stderr=%s", c, e)
	}
	up, down := bw()
	if up != 5*1024*1024 || down != 50*1024*1024 {
		t.Fatalf("up=%d down=%d", up, down)
	}

	// 只动一侧。
	if c, _, e := runCLI(t, db, "", "user", "set-bandwidth", "bwuser", "--down-bps", "999", "--no-refresh"); c != 0 {
		t.Fatalf("set-bandwidth: code=%d stderr=%s", c, e)
	}
	if up, down = bw(); up != 5*1024*1024 || down != 999 {
		t.Fatalf("up=%d down=%d,上行不该被改动", up, down)
	}

	if c, _, _ := runCLI(t, db, "", "user", "set-bandwidth", "查无此人", "--up-mibs", "1", "--no-refresh"); c != 1 {
		t.Fatal("用户不存在应 exit 1")
	}
	if c, _, _ := runCLI(t, db, "", "user", "set-bandwidth", "--up-mibs", "1"); c != 2 {
		t.Fatal("缺用户名应是用法错(exit 2)")
	}
}

func TestLeaseRelease_FreesTheStickyAddress(t *testing.T) {
	db := filepath.Join(t.TempDir(), "leaserel.db")
	id := seedDevice(t, db, "leaseowner", "66666666-6666-4666-8666-666666666666")
	idStr := strconv.FormatInt(id, 10)

	// 没有租约时要明确说「没有」,不能报成功 —— 运维会以为已经放掉了。
	c, _, _ := runCLI(t, db, "", "lease", "release", idStr)
	if c == 0 {
		t.Fatal("设备根本没有租约,不该报成功")
	}

	if c, _, e := runCLI(t, db, "", "lease", "set", idStr, "--v4", "10.80.0.9"); c != 0 {
		t.Fatalf("lease set: code=%d stderr=%s", c, e)
	}
	if c, out, e := runCLI(t, db, "", "lease", "release", idStr); c != 0 {
		t.Fatalf("lease release: code=%d stderr=%s out=%s", c, e, out)
	}

	st := openStoreForTest(t, db)
	defer st.Close()
	if l, err := st.GetLeaseByDevice(t.Context(), id); err == nil && l != nil && l.VIPv4 != "" {
		t.Fatalf("租约还在: %+v", l)
	}

	if c, _, _ := runCLI(t, db, "", "lease", "release"); c != 2 {
		t.Fatal("缺 device_id 应是用法错(exit 2)")
	}
	if c, _, _ := runCLI(t, db, "", "lease", "release", "abc"); c != 2 {
		t.Fatal("id 不是数字应是用法错(exit 2)")
	}
}

// lease gc 是破坏性操作:批量删孤儿租约、释放粘性 vIP。--dry-run 必须只数不删,
// 不带 --yes 时必须先问一句。
func TestLeaseGc_DryRunCountsAndConfirmationGuardsTheRealRun(t *testing.T) {
	db := filepath.Join(t.TempDir(), "leasegc.db")
	id := seedDevice(t, db, "gcowner", "77777777-7777-4777-8777-777777777777")
	idStr := strconv.FormatInt(id, 10)
	if c, _, e := runCLI(t, db, "", "lease", "set", idStr, "--v4", "10.80.0.11"); c != 0 {
		t.Fatalf("lease set: %s", e)
	}

	leaseStillThere := func() bool {
		st := openStoreForTest(t, db)
		defer st.Close()
		l, err := st.GetLeaseByDevice(t.Context(), id)
		return err == nil && l != nil && l.VIPv4 != ""
	}

	t.Run("dry-run 不删任何东西", func(t *testing.T) {
		c, out, e := runCLI(t, db, "", "lease", "gc", "--idle", "1s", "--dry-run")
		if c != 0 {
			t.Fatalf("code=%d stderr=%s", c, e)
		}
		if out == "" {
			t.Fatal("dry-run 应当报出会删多少条,否则运维无从判断")
		}
		if !leaseStillThere() {
			t.Fatal("dry-run 把租约真删了")
		}
	})

	t.Run("拒绝确认就什么都不做", func(t *testing.T) {
		code, _, e := runCLIInteractive(t, db, "n\n", "lease", "gc", "--idle", "1s")
		if code != 0 {
			t.Fatalf("code=%d stderr=%s", code, e)
		}
		if !leaseStillThere() {
			t.Fatal("回答 n 之后租约还是被删了")
		}
	})

	t.Run("确认之后才真删", func(t *testing.T) {
		code, _, e := runCLIInteractive(t, db, "y\n", "lease", "gc", "--idle", "1s")
		if code != 0 {
			t.Fatalf("code=%d stderr=%s", code, e)
		}
	})

	t.Run("idle 必须为正", func(t *testing.T) {
		if c, _, _ := runCLI(t, db, "", "lease", "gc", "--idle", "0"); c != 2 {
			t.Fatal("--idle 0 会把所有租约都当孤儿,必须拒绝")
		}
		if c, _, _ := runCLI(t, db, "", "lease", "gc", "--idle", "-1h"); c != 2 {
			t.Fatal("负数同理")
		}
	})
}

// confirm 只认 y / yes,其它一律当成拒绝 —— 危险操作上默认应该是"不做"。
func TestConfirm_OnlyYesMeansYes(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"y\n", true},
		{"Y\n", true},
		{"yes\n", true},
		{"YES\n", true},
		{"  yes  \n", true},
		{"n\n", false},
		{"no\n", false},
		{"\n", false},
		{"yep\n", false},
		{"", false}, // 直接 EOF(比如 stdin 被关掉)
		{"随便什么\n", false},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%q", tc.in), func(t *testing.T) {
			opts, out := newConfirmOpts(tc.in)
			if got := confirm(opts, "真的要删吗"); got != tc.want {
				t.Fatalf("got %v want %v —— 危险操作上把「不确定」当成确认是不可接受的", got, tc.want)
			}
			if !strings.Contains(out.String(), "真的要删吗") {
				t.Fatalf("提示语没打出来: %q", out.String())
			}
			if !strings.Contains(out.String(), "[y/N]") {
				t.Fatal("提示里要标明默认是 N")
			}
		})
	}
}

func TestParsePortRange_RejectsEverythingThatIsNotLoDashHi(t *testing.T) {
	t.Run("合法", func(t *testing.T) {
		lo, hi, err := parsePortRange("80-443")
		if err != nil || lo != 80 || hi != 443 {
			t.Fatalf("got (%d,%d,%v)", lo, hi, err)
		}
		if lo, hi, err = parsePortRange("22-22"); err != nil || lo != 22 || hi != 22 {
			t.Fatalf("单点区间应合法,got (%d,%d,%v)", lo, hi, err)
		}
	})

	for _, bad := range []string{"", "80", "-443", "80-", "-", "a-b", "80-abc", "abc-443", "443-80"} {
		t.Run(fmt.Sprintf("%q", bad), func(t *testing.T) {
			if _, _, err := parsePortRange(bad); err == nil {
				t.Fatalf("%q 应被拒 —— 端口区间写错会让 ACL 规则覆盖面跟预期不符", bad)
			}
		})
	}
}

func TestMinPos64_IgnoresZeroAndNegativeBecauseTheyMeanUnlimited(t *testing.T) {
	cases := []struct {
		in   []int64
		want int64
	}{
		{nil, 0},
		{[]int64{0, 0}, 0},
		{[]int64{0, 100}, 100},
		{[]int64{100, 0}, 100},
		{[]int64{100, 50}, 50},
		{[]int64{-1, 50}, 50},
		{[]int64{-5, -3}, 0},
		{[]int64{300, 100, 200}, 100},
	}
	for _, tc := range cases {
		if got := minPos64(tc.in...); got != tc.want {
			t.Errorf("minPos64(%v)=%d want %d —— 0 在限速语义里是「不限」,不能被当成最小值",
				tc.in, got, tc.want)
		}
	}
}

func TestExitMark_RendersABooleanAsAColumnGlyph(t *testing.T) {
	if got := exitMark(true); got != "✓" {
		t.Fatalf("got %q", got)
	}
	if got := exitMark(false); got != "-" {
		t.Fatalf("got %q", got)
	}
}
