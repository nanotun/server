package main

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nanotun/server/store"
)

// 本文件盯的是控制面两处「错了不出声」的地方:
//
//   - 启动期的 fail-closed。控制面**无鉴权**,kick / reload / rate-refresh 全靠「只有能读这个 socket 的
//     本地用户才是管理员」。任何一处权限没收紧却照样开门,就是本地提权,而且日志之外毫无迹象。
//   - kick 真的踢到人。三种形状(session / device / user)都回 200 + kicked 计数;算错目标时管理员
//     以为处置生效了,被踢的会话还在跑,或者踢错了别人。

func TestResolveControlSocketPath(t *testing.T) {
	cases := []struct {
		in       string
		wantPath string
		wantOff  bool
	}{
		{"off", "", true},
		{"OFF", "", true},
		{"  off  ", "", true},
		{"", defaultControlSocketPath, false},
		{"   ", defaultControlSocketPath, false},
		{"/tmp/x.sock", "/tmp/x.sock", false},
		{"offline.sock", "offline.sock", false}, // 前缀是 off 但不是 off
	}
	for _, tc := range cases {
		got, off := resolveControlSocketPath(tc.in)
		if off != tc.wantOff || got != tc.wantPath {
			t.Fatalf("resolveControlSocketPath(%q) = (%q,%v),want (%q,%v)",
				tc.in, got, off, tc.wantPath, tc.wantOff)
		}
	}
}

// 收不紧权限就必须关门:关掉监听、删掉那个文件,而不是留着一个别人能连的特权 socket。
func TestEnforceControlSocketPerm_FailsClosedAndTakesTheSocketDownWithIt(t *testing.T) {
	t.Run("chmod 失败", func(t *testing.T) {
		dir := mustTempSockDir(t)
		path := filepath.Join(dir, "live.sock")
		ln := mustUnixListen(t, path)

		// 这里要单独钉住第一道门:让随后的权限复核**看起来是通的**(替掉那次 Stat,回一个 0600 的
		// 文件),于是唯一能拦下这次启动的只有 chmod 自己的返回值。否则 chmod 失败总会被第二道门
		// 顺手拦住,「chmod 失败只 Warn 后继续」这种改动就测不出来了。
		tight := filepath.Join(dir, "tight")
		if err := os.WriteFile(tight, []byte("x"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		prev := controlSocketStatForPermCheck
		controlSocketStatForPermCheck = func(string) (os.FileInfo, error) { return os.Stat(tight) }
		t.Cleanup(func() { controlSocketStatForPermCheck = prev })

		// chmod 的目标不存在 → 必然失败,模拟「权限收不紧」。
		if err := enforceControlSocketPerm(ln, filepath.Join(dir, "gone.sock")); err == nil {
			t.Fatal("chmod 失败时必须报错并拒绝启动管理面 —— 收不紧权限就等于把无鉴权特权面开给所有本地用户")
		}
		assertListenerClosed(t, ln, path)
	})

	t.Run("chmod 报成功但权限没落到 0600", func(t *testing.T) {
		dir := mustTempSockDir(t)
		path := filepath.Join(dir, "c.sock")
		ln := mustUnixListen(t, path)

		// 个别 FS / overlay 上会这样:chmod 返回 nil,实际权限仍是人人可访问。
		loose := filepath.Join(dir, "loose")
		if err := os.WriteFile(loose, []byte("x"), 0o666); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if err := os.Chmod(loose, 0o666); err != nil {
			t.Fatalf("Chmod: %v", err)
		}
		prev := controlSocketStatForPermCheck
		controlSocketStatForPermCheck = func(string) (os.FileInfo, error) { return os.Stat(loose) }
		t.Cleanup(func() { controlSocketStatForPermCheck = prev })

		if err := enforceControlSocketPerm(ln, path); err == nil {
			t.Fatal("实测权限仍开放时必须拒绝启动 —— 这是无鉴权控制面的最后一道门")
		}
		assertListenerClosed(t, ln, path)
		if _, err := os.Stat(path); err == nil {
			t.Fatal("拒绝启动后那个 socket 文件必须删掉,否则它还挂在那里等人来连")
		}
	})

	t.Run("Stat 本身失败", func(t *testing.T) {
		dir := mustTempSockDir(t)
		path := filepath.Join(dir, "c.sock")
		ln := mustUnixListen(t, path)

		prev := controlSocketStatForPermCheck
		controlSocketStatForPermCheck = func(string) (os.FileInfo, error) {
			return nil, errors.New("stat 挂了")
		}
		t.Cleanup(func() { controlSocketStatForPermCheck = prev })

		if err := enforceControlSocketPerm(ln, path); err == nil {
			t.Fatal("复核不了权限时也必须拒绝(不能因为读不到就当它是安全的)")
		}
		assertListenerClosed(t, ln, path)
	})

	t.Run("权限正常时放行并确实收紧到 0600", func(t *testing.T) {
		dir := mustTempSockDir(t)
		path := filepath.Join(dir, "c.sock")
		ln := mustUnixListen(t, path)
		t.Cleanup(func() { _ = ln.Close() })

		if err := enforceControlSocketPerm(ln, path); err != nil {
			t.Fatalf("正常情况应放行: %v", err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("Stat: %v", err)
		}
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			t.Fatalf("socket 权限是 %v,group/other 位必须全 0", perm)
		}
	})
}

// unix socket 路径有 ~104 字节上限。超长时 Listen 会失败,此时不许留下半开的管理面。
func TestStartControlSocket_RefusesWhenTheSocketPathCannotBeListenedOn(t *testing.T) {
	dir := mustTempSockDir(t)
	// 逐级建目录把路径堆到超过 sun_path 上限;prepare 能过(只 mkdir + stat),Listen 会失败。
	long := dir
	for i := 0; i < 6; i++ {
		long = filepath.Join(long, strings.Repeat("d", 30))
	}
	path := filepath.Join(long, "c.sock")

	cleanup := startControlSocket(path, &gatewayState{})
	if cleanup == nil {
		t.Fatal("Listen 失败时也要返回可调用的 cleanup")
	}
	cleanup()

	if _, err := os.Stat(path); err == nil {
		t.Fatal("Listen 失败后不该留下 socket 文件")
	}
}

// cleanup 必须真的停服并把 socket 文件删掉,否则下次启动会 EADDRINUSE(表现成「管理面莫名不可用」)。
func TestStartControlSocket_CleanupStopsServingAndUnlinks(t *testing.T) {
	dir := mustTempSockDir(t)
	path := filepath.Join(dir, "c.sock")

	cleanup := startControlSocket(path, &gatewayState{})
	waitForSocket(t, path)
	c, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		t.Fatalf("管理面应可连接: %v", err)
	}
	_ = c.Close()

	cleanup()

	if _, err := os.Stat(path); err == nil {
		t.Fatal("cleanup 后 socket 文件必须删掉,否则下次 bind 会撞 address already in use")
	}
	if c, err := net.DialTimeout("unix", path, 500*time.Millisecond); err == nil {
		_ = c.Close()
		t.Fatal("cleanup 后仍能连上管理面")
	}

	// 同一路径必须能立刻再起一次(重启幂等)。
	cleanup2 := startControlSocket(path, &gatewayState{})
	defer cleanup2()
	waitForSocket(t, path)
}

// 残留的 socket 文件要能被清掉;清不掉(父目录不可写)必须报错而不是硬着头皮往下走。
func TestPrepareControlSocketPath_ReportsWhenAStaleSocketCannotBeRemoved(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root 无视目录权限,这条只在非 root 下有意义")
	}
	dir := mustTempSockDir(t)
	path := filepath.Join(dir, "c.sock")
	ln := mustUnixListen(t, path)
	// Go 的 UnixListener 默认关闭时顺手 unlink,得关掉这个行为才能造出「上次没退干净」的残留文件
	// (真实场景是进程被 SIGKILL,来不及走 cleanup)。
	if ul, ok := ln.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}
	_ = ln.Close()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("残留 socket 没造出来: %v", err)
	}

	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	err := prepareControlSocketPath(path)
	if err == nil {
		t.Fatal("残留 socket 删不掉时应报错(否则随后的 Listen 会以 EADDRINUSE 失败,原因还被藏住了)")
	}
	if !strings.Contains(err.Error(), "unlink stale socket") {
		t.Fatalf("错误应指明是清理残留失败: %v", err)
	}
}

// 父路径上挡着一个普通文件时,建目录会失败 —— 要如实报错。
func TestPrepareControlSocketPath_ReportsWhenTheParentCannotBeCreated(t *testing.T) {
	base := mustTempSockDir(t)
	blocker := filepath.Join(base, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	err := prepareControlSocketPath(filepath.Join(blocker, "sub", "c.sock"))
	if err == nil {
		t.Fatal("父路径上有普通文件时应报错")
	}
	if !strings.Contains(err.Error(), "mkdir") {
		t.Fatalf("错误应指明是建目录失败: %v", err)
	}
}

// kick 三种形状都必须**真的**踢到目标,且只踢目标。
//
// 既有用例验的是「参数不合法时拒绝」;这里验的是命中那一侧:算错目标不会报错,只会回 200 加一个
// 好看的 kicked 计数,管理员据此以为处置生效了。
func TestControlSocketKick_EachShapeHitsItsTargetAndSparesTheRest(t *testing.T) {
	ctx := t.Context()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "kick.db"), store.Options{})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer func() { _ = st.Close() }()
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	target, err := st.CreateUser(ctx, store.NewUser{Username: "victim", PSKHash: "h"})
	if err != nil {
		t.Fatalf("CreateUser(victim): %v", err)
	}
	bystanderUser, err := st.CreateUser(ctx, store.NewUser{Username: "bystander", PSKHash: "h"})
	if err != nil {
		t.Fatalf("CreateUser(bystander): %v", err)
	}
	gw := &gatewayState{store: st}
	sockPath, cleanup := startTestControlSocket(t, gw)
	defer cleanup()

	shapes := []struct {
		name string
		body map[string]any
	}{
		{"session", map[string]any{"kind": "session", "id": "conn-victim"}},
		{"device 数字 id", map[string]any{"kind": "device", "id": "77"}},
		// UUID 带十六进制字母,且**用大写发过来**:CLI / web 复制粘贴出来的大写 UUID 必须也能踢到。
		{"device UUID(大写也要认)", map[string]any{"kind": "device", "id": "0000ABCD-0000-4000-8000-0000000000AB"}},
		{"user 名字", map[string]any{"kind": "user", "id": "victim"}},
		{"user 数字 id", map[string]any{"kind": "user", "id": strconv.FormatInt(target.ID, 10)}},
	}
	for _, shape := range shapes {
		t.Run(shape.name, func(t *testing.T) {
			victim := &Connection{
				connIDStr:  "conn-victim",
				userID:     userIDFromStoreID(target.ID),
				deviceID:   77,
				deviceUUID: "0000abcd-0000-4000-8000-0000000000ab",
				linkConn:   newFakeLinkConn(),
				tunnelDone: make(chan struct{}),
				createdAt:  time.Now(),
			}
			bystander := &Connection{
				connIDStr:  "conn-bystander",
				userID:     userIDFromStoreID(bystanderUser.ID),
				deviceID:   88,
				deviceUUID: "00000000-0000-4000-8000-000000000088",
				linkConn:   newFakeLinkConn(),
				tunnelDone: make(chan struct{}),
				createdAt:  time.Now(),
			}
			installConn(t, victim)
			installConn(t, bystander)

			status, out := controlReq(t, sockPath, "POST", "/kick", shape.body)
			if status != http.StatusOK {
				t.Fatalf("status %d body=%s", status, out)
			}
			var resp struct {
				OK      bool     `json:"ok"`
				Kicked  int      `json:"kicked"`
				ConnIDs []string `json:"conn_ids"`
				Reason  string   `json:"reason"`
			}
			if err := json.Unmarshal(out, &resp); err != nil {
				t.Fatalf("解响应: %v body=%s", err, out)
			}
			if resp.Kicked != 1 {
				t.Fatalf("应踢掉 1 条,实际 kicked=%d body=%s", resp.Kicked, out)
			}
			if len(resp.ConnIDs) != 1 || resp.ConnIDs[0] != "conn-victim" {
				t.Fatalf("被踢的应当只是目标会话,实际 conn_ids=%v", resp.ConnIDs)
			}
			if resp.Reason != "kicked_by_admin" {
				t.Fatalf("未带 reason 时应回默认值,实际 %q", resp.Reason)
			}
			// 旁站会话必须还活着:踢错人比踢不掉更糟。
			select {
			case <-bystander.tunnelDone:
				t.Fatal("旁站会话被一起踢了")
			default:
			}
		})
	}
}

// gw 还没就绪时,改限速的两条 endpoint 必须回 503 而不是「看起来成功了」。
func TestControlSocketRateRefresh_ReportsUnavailableWithoutAGateway(t *testing.T) {
	for _, path := range []string{"/rate/refresh", "/users/rate/refresh"} {
		t.Run(path, func(t *testing.T) {
			sockPath, cleanup := startTestControlSocket(t, nil)
			defer cleanup()
			status, out := controlReq(t, sockPath, "POST", path, map[string]any{})
			if status != http.StatusServiceUnavailable {
				t.Fatalf("want 503, got %d body=%s", status, out)
			}
		})
	}
}

// device_id 给了个不是数字的值:必须 400。静默当成 0 会把「刷这一台」变成「刷全量」。
func TestControlSocketRateRefresh_RejectsAMalformedDeviceID(t *testing.T) {
	gw := &gatewayState{}
	sockPath, cleanup := startTestControlSocket(t, gw)
	defer cleanup()

	status, out := controlReq(t, sockPath, "POST", "/rate/refresh?device_id=abc", nil)
	if status != http.StatusBadRequest {
		t.Fatalf("want 400, got %d body=%s", status, out)
	}
}

// 没踢到就不许回报踢到了。
//
// 这是第二十二轮修过的那处:快照到的会话在放锁之后可能已被 takeover 顶掉或自行离场,此时
// kickConnForUserInvalidate 追不到活会话、如实回 false。计数若不看这个返回值,管理员就会收到
// 「已踢除 1 条」而实际一条都没踢掉 —— 处置看起来生效了,人还在线。
func TestControlSocketKick_DoesNotClaimAKickItDidNotMake(t *testing.T) {
	gw := &gatewayState{}
	sockPath, cleanup := startTestControlSocket(t, gw)
	defer cleanup()

	// 标记成已被接管,而会话表里那个 connIDStr 仍指向它自己 → 沿接管链追不到新持有者,
	// 也就是「没有活会话可踢」。
	c := &Connection{
		connIDStr:  "conn-ghost",
		userID:     "u1",
		linkConn:   newFakeLinkConn(),
		tunnelDone: make(chan struct{}),
		createdAt:  time.Now(),
	}
	c.takenOver.Store(true)
	installConn(t, c)

	status, out := controlReq(t, sockPath, "POST", "/kick", map[string]any{
		"kind": "session", "id": "conn-ghost",
	})
	if status != http.StatusOK {
		t.Fatalf("status %d body=%s", status, out)
	}
	var resp struct {
		Kicked  int      `json:"kicked"`
		ConnIDs []string `json:"conn_ids"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("解响应: %v body=%s", err, out)
	}
	if resp.Kicked != 0 || len(resp.ConnIDs) != 0 {
		t.Fatalf("没有活会话可踢时必须回报 0,实际 kicked=%d conn_ids=%v", resp.Kicked, resp.ConnIDs)
	}
}

// reload 失败必须回 500 并说明原因,而不是回一个「ok:true, acl_pairs:0」。
//
// 后者是最坏的形状:ACL 读不出来时快照按 fail-closed 保持原样(见 acl_reload_guards_test.go),
// 而管理员看到 ok 就以为新规则已经生效了 —— 实际执法用的还是旧快照,新加的 deny 一条没生效。
func TestControlSocketReload_SurfacesTheFailureInsteadOfReportingSuccess(t *testing.T) {
	st := newACLReloadStore(t)
	if _, err := reloadACLSnapshotFromStore(st); err != nil {
		t.Fatalf("先装一份好快照: %v", err)
	}
	// 把规则表藏起来,模拟坏迁移 / 手抠库之后 reload 读不到规则集。
	if _, err := st.DB().ExecContext(t.Context(),
		`ALTER TABLE acl_pairs RENAME TO acl_pairs_gone`); err != nil {
		t.Fatalf("藏掉 acl_pairs: %v", err)
	}

	gw := &gatewayState{store: st}
	sockPath, cleanup := startTestControlSocket(t, gw)
	defer cleanup()

	status, out := controlReq(t, sockPath, "POST", "/reload?what=acl", nil)
	if status != http.StatusInternalServerError {
		t.Fatalf("reload 失败时应回 500,实际 %d body=%s", status, out)
	}
	if !strings.Contains(string(out), "reload acl") {
		t.Fatalf("响应应说明是 reload acl 失败: %s", out)
	}
}

// 会话表里出现一条 nil 表项时,管理面不能崩。
//
// 崩的话整个 controlSocket goroutine 就没了(safeGlobalGoroutine 兜住进程,但管理面自此哑掉):
// reload / kick / rate-refresh 全部不可用,而 web 上只看到「请求超时」。
func TestControlSocket_ANilSessionEntryDoesNotTakeDownTheAdminPlane(t *testing.T) {
	gw := &gatewayState{}
	sockPath, cleanup := startTestControlSocket(t, gw)
	defer cleanup()

	connIDMapMu.Lock()
	connIDMap["nil-entry"] = nil
	connIDMapMu.Unlock()
	t.Cleanup(func() {
		connIDMapMu.Lock()
		delete(connIDMap, "nil-entry")
		connIDMapMu.Unlock()
	})

	for _, req := range []struct {
		method, path string
		body         any
	}{
		{"GET", "/status", nil},
		{"POST", "/rate/refresh", map[string]any{"device_id": 0}},
	} {
		status, out := controlReq(t, sockPath, req.method, req.path, req.body)
		// /status 在没有 tun 时按设计回 503(HTTP 码本身就是就绪信号),所以这里只要求
		// 「handler 完整跑完并给出合法 JSON」—— panic 的话响应会被截断甚至根本没有。
		if status == http.StatusInternalServerError {
			t.Fatalf("%s %s 因 nil 表项挂了: body=%s", req.method, req.path, out)
		}
		var probe map[string]any
		if err := json.Unmarshal(out, &probe); err != nil {
			t.Fatalf("%s %s 的响应不是完整 JSON(handler 中途崩了?): %v body=%s",
				req.method, req.path, err, out)
		}
		if _, ok := probe["ok"]; !ok {
			t.Fatalf("%s %s 的响应缺少 ok 字段: body=%s", req.method, req.path, out)
		}
	}
}

// 读不到当前值时,必须回落到调用方给的登录快照 —— 绝不能回落到 0。
//
// 这两个 helper 的返回值会进 effectiveLinkRates 取 min,而 0 在那里表示「这一层不限速」。
// 回落成 0 就等于把用户配额 / 设备限速悄悄拿掉:限速看起来「生效了」,实测吞吐却是满速。
func TestFreshRateLookups_FallBackToTheLoginSnapshotNotToUnlimited(t *testing.T) {
	ctx := t.Context()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "fresh.db"), store.Options{})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer func() { _ = st.Close() }()
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	withStore := &gatewayState{store: st}

	const snapUp, snapDown = int64(512_000), int64(1_024_000)
	cases := []struct {
		name string
		gw   *gatewayState
		id   int64
	}{
		{"没有 gateway", nil, 7},
		{"store 不可用", &gatewayState{}, 7},
		{"匿名 / 无 id", withStore, 0},
		{"库里那一行已经删了", withStore, 999999},
	}
	for _, tc := range cases {
		t.Run("user/"+tc.name, func(t *testing.T) {
			up, down := freshUserBW(ctx, tc.gw, tc.id, map[int64]rateSnap{}, snapUp, snapDown)
			if up != snapUp || down != snapDown {
				t.Fatalf("应回落到登录快照 (%d,%d),实际 (%d,%d) —— 0 在上层等于不限速",
					snapUp, snapDown, up, down)
			}
		})
		t.Run("device/"+tc.name, func(t *testing.T) {
			up, down := freshDeviceRates(ctx, tc.gw, tc.id, map[int64]rateSnap{}, snapUp, snapDown)
			if up != snapUp || down != snapDown {
				t.Fatalf("应回落到登录快照 (%d,%d),实际 (%d,%d)", snapUp, snapDown, up, down)
			}
		})
	}

	// 缓存命中时不再查库:一次全量刷有 N 条 conn,同一个 user/device 只该读一次。
	cache := map[int64]rateSnap{7: {up: 1, down: 2}}
	if up, down := freshUserBW(ctx, withStore, 7, cache, snapUp, snapDown); up != 1 || down != 2 {
		t.Fatalf("应返回缓存值 (1,2),实际 (%d,%d)", up, down)
	}
	devCache := map[int64]rateSnap{7: {up: 3, down: 4}}
	if up, down := freshDeviceRates(ctx, withStore, 7, devCache, snapUp, snapDown); up != 3 || down != 4 {
		t.Fatalf("应返回缓存值 (3,4),实际 (%d,%d)", up, down)
	}
}

// 已被接管 / 还没有数据面的连接不该被算成「刷到了」。
//
// 回报 refreshed 偏大本身不致命,但它是管理员判断「限速改动是否落地」的唯一依据:
// 把马上要 close 的 oldConn 也算进去,就会把「实际一条都没刷到」显示成「已刷 N 条」。
func TestApplyConnRateLimit_SkipsWhatItCannotActuallyChange(t *testing.T) {
	if applyConnRateLimit(nil, &gatewayState{}, 0, 0, storeRateDefaultsView{}, 0, 0, 0) {
		t.Fatal("nil conn 不该被算成刷到了")
	}

	// 这条要装上真的 rlConn:否则「没有数据面」那道门会先把它挡下,takenOver 这道门就没被验到。
	takenOver := &Connection{connIDStr: "c-taken", linkConn: newFakeLinkConn(), tunnelDone: make(chan struct{})}
	takenOver.rlConn.Store(newRateLimitedConn(nopReadWriteCloser{}, nil, nil, nil))
	takenOver.takenOver.Store(true)
	if applyConnRateLimit(takenOver, &gatewayState{}, 0, 0, storeRateDefaultsView{}, 0, 0, 0) {
		t.Fatal("已被接管的连接不该被算成刷到了(它的 rlConn 马上就会被关掉)")
	}

	noDataPlane := &Connection{connIDStr: "c-nodp", linkConn: newFakeLinkConn(), tunnelDone: make(chan struct{})}
	if applyConnRateLimit(noDataPlane, &gatewayState{}, 0, 0, storeRateDefaultsView{}, 0, 0, 0) {
		t.Fatal("还没建起数据面(rlConn 为 nil)的连接不该被算成刷到了")
	}
}

// 登录尾部补刷在参数不全时必须安静地什么都不做,不能 panic —— 它跑在登录路径上,崩了就是登录失败。
func TestReapplyRateAfterLogin_DoesNothingWhenThereIsNothingToApply(t *testing.T) {
	ctx := t.Context()
	reapplyRateAfterLogin(ctx, nil, &Connection{}, "ios")
	reapplyRateAfterLogin(ctx, &gatewayState{}, nil, "ios")
	// 有 conn 但还没有数据面:同样直接返回。
	reapplyRateAfterLogin(ctx, &gatewayState{}, &Connection{connIDStr: "c"}, "ios")
}

func mustTempSockDir(t *testing.T) string {
	t.Helper()
	// unix socket 路径有 ~104 字节上限,t.TempDir() 在 macOS 上就超了,所以落在 /tmp 下。
	dir, err := os.MkdirTemp("/tmp", "ctlg")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700); _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	return dir
}

func mustUnixListen(t *testing.T, path string) net.Listener {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("Listen(unix, %s): %v", path, err)
	}
	return ln
}

func assertListenerClosed(t *testing.T, ln net.Listener, path string) {
	t.Helper()
	if err := ln.Close(); err == nil {
		t.Fatal("拒绝启动时必须把监听关掉(重复 Close 应报错)")
	}
	if c, err := net.DialTimeout("unix", path, 300*time.Millisecond); err == nil {
		_ = c.Close()
		t.Fatal("拒绝启动后仍能连上那个 socket")
	}
}

func waitForSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("socket %s 没建起来", path)
}
