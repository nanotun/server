package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// --json 的键名是给脚本看的契约,一族命令内必须是同一套形状。
//
// 2026-07-30 统一之前,`acl allow/deny --json`、`lease set --json`、`device list --json` 打的是裸
// store 结构体(没有 json tag,于是键落成 Go 风格的 `ID`/`DstPortLo`/`DeviceUUID`),而同族的
// `acl list --json`、`lease list --json` 是手写的 snake_case。两套形状同时存在的后果不是报错:
// `device list --json | jq '.[].device_uuid'` 拿到的是 null,而 CI 里 null 往下传通常一路无声 ——
// 编排工具于是把一台刚建好的设备当成「没有 UUID」写进下游配置。
//
// 这道闸不检查具体键名(那些各自的用例已经在验),只钉住「同族两条命令的键集合一致」——
// 因为往回退化的方式几乎总是「新写的那条命令直接 printJSON 了 store 结构体」,而那一步的结果
// 恰好就是键集合整体错开。

// jsonKeysOf 取一段 JSON(对象或对象数组)的顶层键集合,排序后返回。
func jsonKeysOf(t *testing.T, raw string) []string {
	t.Helper()
	trimmed := strings.TrimSpace(raw)
	var obj map[string]any
	if strings.HasPrefix(trimmed, "[") {
		var arr []map[string]any
		if err := json.Unmarshal([]byte(trimmed), &arr); err != nil {
			t.Fatalf("解 JSON 数组: %v\n%s", err, raw)
		}
		if len(arr) == 0 {
			t.Fatalf("JSON 数组是空的,取不到键集合:\n%s", raw)
		}
		obj = arr[0]
	} else if err := json.Unmarshal([]byte(trimmed), &obj); err != nil {
		t.Fatalf("解 JSON 对象: %v\n%s", err, raw)
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// assertNoGoStyleKeys 顶层键里不许出现大写开头的 —— 那是「直接打了 store 结构体」的指纹。
func assertNoGoStyleKeys(t *testing.T, what, raw string) {
	t.Helper()
	for _, k := range jsonKeysOf(t, raw) {
		if k == "" {
			continue
		}
		if c := k[0]; c >= 'A' && c <= 'Z' {
			t.Errorf("%s 的 --json 里有 Go 风格的键 %q —— 说明打的是裸 store 结构体,"+
				"按同族 list 的键名写的脚本会读到 null:\n%s", what, k, raw)
		}
	}
}

// TestACLJSON_AddAndListAgreeOnTheirKeys acl add/deny 与 acl list 的 --json 形状必须一致。
func TestACLJSON_AddAndListAgreeOnTheirKeys(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "acl-shape.db")
	seedACLUsers(t, db, "ua", "ub")

	code, addOut, stderr := runCLI(t, db, "", "--json", "acl", "allow", "ua", "ub",
		"--proto", "udp", "--port", "53")
	if code != 0 {
		t.Fatalf("acl allow --json: code=%d stderr=%s", code, stderr)
	}
	code, listOut, stderr := runCLI(t, db, "", "--json", "acl", "list")
	if code != 0 {
		t.Fatalf("acl list --json: code=%d stderr=%s", code, stderr)
	}

	assertNoGoStyleKeys(t, "acl allow", addOut)
	assertSameKeys(t, "acl allow", addOut, "acl list", listOut)

	// 两端的用户名也要给:list 那侧是 JOIN 出来的,add 这侧原本就知道(命令行传的就是用户名)。
	// 只给 id 的话调用方为了打一行日志还得再查一次库。
	var v aclPairView
	if err := json.Unmarshal([]byte(addOut), &v); err != nil {
		t.Fatalf("解 acl allow 的 JSON: %v\n%s", err, addOut)
	}
	if v.SrcUsername != "ua" || v.DstUsername != "ub" {
		t.Errorf("acl allow --json 没带回两端用户名(src=%q dst=%q)—— 与 acl list 的同名字段对不上",
			v.SrcUsername, v.DstUsername)
	}
}

// TestACLJSON_WildcardEndsStayEmptyJustLikeInTheList 通配一端在 list 侧是空串,add 侧也必须是空。
//
// 这一条是防「把命令行原样的 `*` 当用户名填进 src_username」:调用方按用户名匹配时,一条
// `allow * ub` 会被当成有个真叫 `*` 的用户,而 list 那侧同一条规则是空 —— 同一条规则两种读法。
func TestACLJSON_WildcardEndsStayEmptyJustLikeInTheList(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "acl-shape-wild.db")
	seedACLUsers(t, db, "ua", "ub")

	code, addOut, stderr := runCLI(t, db, "", "--json", "acl", "allow", "*", "ub")
	if code != 0 {
		t.Fatalf("acl allow * ub --json: code=%d stderr=%s", code, stderr)
	}
	if strings.Contains(addOut, `"src_username"`) {
		t.Errorf("通配的一端被当成了叫 `*` 的用户名下发(acl list 那侧是空的):\n%s", addOut)
	}
}

// TestLeaseJSON_SetAndListAgreeOnTheirKeys lease set 与 lease list 的 --json 形状必须一致。
func TestLeaseJSON_SetAndListAgreeOnTheirKeys(t *testing.T) {
	db := filepath.Join(t.TempDir(), "lease-shape.db")
	id := seedDevice(t, db, "lshape", "aaaaaaaa-0009-4009-8009-000000000009")

	code, setOut, stderr := runCLI(t, db, "", "--json", "lease", "set", fmt.Sprint(id),
		"--v4", "100.64.0.21", "--v6", "fd00:200::21")
	if code != 0 {
		t.Fatalf("lease set --json: code=%d stderr=%s", code, stderr)
	}
	code, listOut, stderr := runCLI(t, db, "", "--json", "lease", "list")
	if code != 0 {
		t.Fatalf("lease list --json: code=%d stderr=%s", code, stderr)
	}

	assertNoGoStyleKeys(t, "lease set", setOut)
	assertSameKeys(t, "lease set", setOut, "lease list", listOut)

	var v leaseView
	if err := json.Unmarshal([]byte(setOut), &v); err != nil {
		t.Fatalf("解 lease set 的 JSON: %v\n%s", err, setOut)
	}
	// device_uuid / username 是 list 那侧 JOIN 出来的三列。set 侧漏掉的话,脚本「钉地址后立刻
	// 记一条审计」就得再查一次库,而它拿到的是 null —— 记下来的是一条没有主体的审计。
	if v.DeviceUUID == "" || v.Username != "lshape" || v.UserID == 0 {
		t.Errorf("lease set --json 缺设备/用户这几列(uuid=%q user=%q id=%d):\n%s",
			v.DeviceUUID, v.Username, v.UserID, setOut)
	}
}

// TestLeaseJSON_SetStillSucceedsWhenTheUsernameCannotBeLookedUp
// 补关联列这一步查不动库时,lease set 必须照样报成功。
//
// 租约在补这几列之前就已经落库了。为了一个纯展示字段把命令判成失败,调用方会去重试一个
// 其实已经成功的写操作 —— 而 UpsertManualLeasePreservingEmpty 只保留「命令行没传的那一族」,
// 重试时若参数拼得不完全一样(编排工具重试常常只带上次失败的那一个字段),第二次就会把
// 第一次写进去的另一族按 COALESCE 留下、却把 manual 标记改掉。总之:已经成功的写不该被重试。
func TestLeaseJSON_SetStillSucceedsWhenTheUsernameCannotBeLookedUp(t *testing.T) {
	db := filepath.Join(t.TempDir(), "lease-noname.db")
	id := seedDevice(t, db, "lnoname", "aaaaaaaa-0012-4012-8012-000000000012")
	// users 表没了 → GetUser 必失败,而 devices / leases 照常可读写。
	dropTable(t, db, "users")

	code, out, stderr := runCLI(t, db, "", "--json", "lease", "set", fmt.Sprint(id), "--v4", "100.64.0.22")
	if code != 0 {
		t.Fatalf("补展示字段查不动库,整条命令却失败了(code=%d stderr=%s)—— 租约其实已经落库,"+
			"调用方会去重试一个已经成功的写", code, stderr)
	}
	var v leaseView
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("解 lease set 的 JSON: %v\n%s", err, out)
	}
	if v.VIPv4 != "100.64.0.22" {
		t.Errorf("落库的地址没回给调用方(got %q):\n%s", v.VIPv4, out)
	}
	if v.Username != "" {
		t.Errorf("查不到用户名却填了 %q —— 那是个编出来的值", v.Username)
	}
}

// TestDeviceListJSON_HasNoGoStyleKeys device list 是这批里唯一没有「同族 list」可比的,单独钉键名。
//
// 挑这几个键是因为它们各自对应一类脚本用法:device_uuid 用来跟客户端上报的身份对齐、
// fixed_vip_v4 用来核对钉住的地址、rate_upload_bps 用来核对限速。三者的 Go 风格键名
// (DeviceUUID / FixedVIPv4 / RateUploadBPS)与 snake_case 差得远,不会被 json 的
// 大小写不敏感匹配蒙对。
func TestDeviceListJSON_HasNoGoStyleKeys(t *testing.T) {
	db := filepath.Join(t.TempDir(), "dev-shape.db")
	seedDevice(t, db, "dshape", "aaaaaaaa-0010-4010-8010-000000000010")

	code, out, stderr := runCLI(t, db, "", "--json", "device", "list")
	if code != 0 {
		t.Fatalf("device list --json: code=%d stderr=%s", code, stderr)
	}
	assertNoGoStyleKeys(t, "device list", out)

	got := jsonKeysOf(t, out)
	have := make(map[string]bool, len(got))
	for _, k := range got {
		have[k] = true
	}
	for _, want := range []string{
		"id", "user_id", "device_uuid", "device_name", "display_name",
		"rate_upload_bps", "rate_download_bps", "last_seen_at", "created_at",
	} {
		if !have[want] {
			t.Errorf("device list --json 缺键 %q(实际 %v)", want, got)
		}
	}
}

// TestDeviceListJSON_GivesBothTheAliasAndTheNameActuallyDisplayed
// 别名与展示名都要给,且展示名要按「设了别名用别名」回落。
//
// 只给 alias 的话调用方得自己重实现这个回落,而漏掉回落的脚本会在没设别名的设备上打出空名字 ——
// 一张「设备清单」里凭空少掉一列,而它自己不报错。
func TestDeviceListJSON_GivesBothTheAliasAndTheNameActuallyDisplayed(t *testing.T) {
	db := filepath.Join(t.TempDir(), "dev-alias-shape.db")
	const uuid = "aaaaaaaa-0011-4011-8011-000000000011"
	id := seedDevice(t, db, "ashape", uuid)

	// 未设别名:display_name 应回落到客户端上报名,alias 缺省省略。
	code, out, stderr := runCLI(t, db, "", "--json", "device", "list")
	if code != 0 {
		t.Fatalf("device list --json: code=%d stderr=%s", code, stderr)
	}
	var rows []deviceView
	if err := json.Unmarshal([]byte(out), &rows); err != nil || len(rows) != 1 {
		t.Fatalf("解 device list 的 JSON: %v\n%s", err, out)
	}
	if rows[0].DisplayName == "" {
		t.Error("没设别名时 display_name 是空的 —— 调用方照它打清单会少掉一整列名字")
	}

	if c, _, e := runCLI(t, db, "", "device", "set-alias", fmt.Sprint(id), "机房A-跳板"); c != 0 {
		t.Skipf("这套 CLI 没有 device set-alias,跳过别名那半边: %s", e)
	}
	code, out, stderr = runCLI(t, db, "", "--json", "device", "list")
	if code != 0 {
		t.Fatalf("device list --json: code=%d stderr=%s", code, stderr)
	}
	rows = nil
	if err := json.Unmarshal([]byte(out), &rows); err != nil || len(rows) != 1 {
		t.Fatalf("解 device list 的 JSON: %v\n%s", err, out)
	}
	if rows[0].Alias != "机房A-跳板" {
		t.Errorf("alias 没下发(got %q)", rows[0].Alias)
	}
	if rows[0].DisplayName != "机房A-跳板" {
		t.Errorf("设了别名,display_name 却还是 %q —— 与 web / exits-list 各处展示的名字不一致,"+
			"同一台设备在两个界面上是两个名字", rows[0].DisplayName)
	}
}

func assertSameKeys(t *testing.T, whatA, rawA, whatB, rawB string) {
	t.Helper()
	a, b := jsonKeysOf(t, rawA), jsonKeysOf(t, rawB)
	inB := make(map[string]bool, len(b))
	for _, k := range b {
		inB[k] = true
	}
	inA := make(map[string]bool, len(a))
	for _, k := range a {
		inA[k] = true
	}
	for _, k := range a {
		if !inB[k] {
			t.Errorf("%s 打了键 %q 而 %s 没有 —— 同族两套形状,脚本按哪一套写都会在另一条命令上读到 null\n%s=%v\n%s=%v",
				whatA, k, whatB, whatA, a, whatB, b)
		}
	}
	for _, k := range b {
		if !inA[k] {
			t.Errorf("%s 打了键 %q 而 %s 没有 —— 同上\n%s=%v\n%s=%v",
				whatB, k, whatA, whatA, a, whatB, b)
		}
	}
}
