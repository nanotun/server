package main

import (
	"net/netip"
	"testing"
	"time"

	"github.com/nanotun/server/config"
	"github.com/nanotun/server/store"
)

// 第 46 轮的零散闸门。共同点是「不报错的坏」:每一处失守都不会有日志、不会有告警,
// 只会让某个功能安静地不再工作,或者让一条本该跳过的表项把整轮扫描带走。

// TestSameRateLimitMap_TellsApartTwoMapsWithTheSameKeys 热更 diff 必须看值,不能只看键。
//
// SIGHUP 的热更是「先 diff、不同才装」。这个 diff 若只比键集合,那么运维改一个平台的限速数值
// (键没变、值变了)就会被判成「没改动」——reload 返回成功、日志一切正常,而限速还是老的。
// 这类「改了配置没生效」的故障极难自证:运维只会反复怀疑自己写错了字段名。
func TestSameRateLimitMap_TellsApartTwoMapsWithTheSameKeys(t *testing.T) {
	base := map[string]config.LinkRateLimitPlatform{
		"ios": {UploadRate: 1_000_000, DownloadRate: 2_000_000},
	}
	for _, tc := range []struct {
		name string
		b    map[string]config.LinkRateLimitPlatform
		same bool
	}{
		{
			name: "逐字相同",
			b:    map[string]config.LinkRateLimitPlatform{"ios": {UploadRate: 1_000_000, DownloadRate: 2_000_000}},
			same: true,
		},
		{
			name: "键相同值不同",
			b:    map[string]config.LinkRateLimitPlatform{"ios": {UploadRate: 1_000_000, DownloadRate: 8_000_000}},
			same: false,
		},
		{
			name: "键改了名",
			b:    map[string]config.LinkRateLimitPlatform{"android": {UploadRate: 1_000_000, DownloadRate: 2_000_000}},
			same: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sameRateLimitMap(base, tc.b); got != tc.same {
				t.Fatalf("sameRateLimitMap = %v,期望 %v —— 判成「没改动」的话 reload 会静默丢掉这次限速变更", got, tc.same)
			}
		})
	}
	// 删空 section 与删掉整个 section 不该被区分,否则每次 reload 都白装一遍。
	if !sameRateLimitMap(nil, map[string]config.LinkRateLimitPlatform{}) {
		t.Error("nil 与 0 长度表应视作相同")
	}
}

// TestScanAndKickInvalidUsers_SkipsJunkEntriesAndStillHandlesTheRealOne
// by-user 索引里的坏表项(键不是数字 / 值是 nil)必须被跳过,而不能把整轮扫描带走。
//
// 这个扫描是「用户被禁用 / 改了 PSK / 平台白名单变了之后把在线会话踢下线」的唯一执行者,在一个
// goroutine 里按 ticker 跑。nil 表项会让它当场 panic —— safeGoroutine 兜住了进程,但这一轮剩下的
// 用户全部漏扫:被禁用的账号继续在线,而且下一 tick 还会撞上同一个坏表项,于是永久漏扫。
func TestScanAndKickInvalidUsers_SkipsJunkEntriesAndStillHandlesTheRealOne(t *testing.T) {
	gw := newTestGatewayForUserInvalidate(t)
	ctx := t.Context()

	user, err := gw.store.CreateUser(ctx, store.NewUser{Username: "doomed", PSKHash: "psk-doomed"})
	if err != nil {
		t.Fatal(err)
	}
	fake := newFakeLinkConn()
	c := &Connection{
		connIDStr:      "conn-doomed",
		userID:         userIDFromStoreID(user.ID),
		linkConn:       fake,
		pskHashAtLogin: "psk-doomed",
		tunnelDone:     make(chan struct{}),
		createdAt:      time.Now(),
	}
	installConn(t, c)

	// 坏表项一:键不是 "u<id>" 形状(空 userID 的会话就落在这里)。它背后是一条**活着的**会话:
	// 这个键解不出 user,于是查库查的是「不存在的 user」,而「查不到 user」的处置是按已删号全员踢
	// —— 于是一条好端端的会话被踢下线,理由是一个根本不存在的账号被删了。
	orphanConn := newFakeLinkConn()
	orphan := &Connection{
		connIDStr:  "conn-orphan",
		userID:     "",
		linkConn:   orphanConn,
		tunnelDone: make(chan struct{}),
		createdAt:  time.Now(),
	}
	// 坏表项二:值里有个 nil —— 取 c.pskHashAtLogin 时当场 panic。
	connIDMapMu.Lock()
	connByUser[""] = map[string]*Connection{orphan.connIDStr: orphan}
	connByUser["u999999"] = map[string]*Connection{"nil-one": nil}
	connIDMapMu.Unlock()
	t.Cleanup(func() {
		connIDMapMu.Lock()
		delete(connByUser, "")
		delete(connByUser, "u999999")
		connIDMapMu.Unlock()
	})

	if err := gw.store.DisableUser(ctx, user.ID); err != nil {
		t.Fatalf("DisableUser: %v", err)
	}
	scanAndKickInvalidUsers(ctx, gw)

	select {
	case <-fake.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("被禁用的用户没被踢下线 —— 坏表项把整轮扫描带走了,这一轮所有该踢的会话都留在线上")
	}
	select {
	case <-orphanConn.closed:
		t.Error("索引键解不出 user 的会话被踢下线了 —— 它对应的账号并不存在于「已删除」这个判定里," +
			"这条会话是被一个不存在的账号连坐的")
	default:
	}
}

// TestLookupVia6Site_AnswersBeforeTheTableIsEverBuilt 4via6 站点表还没建起来时查询必须答「没有」。
//
// 这张表由 /reload?what=routes 建,而 MagicDNS 在那之前就已经在应答了。启动后的那个窗口里若对一个
// 4via6 名字发查询,少了这道判空就是对 nil map 指针解引用 —— 直接 panic 在 DNS 处理 goroutine 上。
// safeGoroutine 能兜住进程,但那条查询已经丢了,而且窗口内每条 4via6 查询都会重演。
func TestLookupVia6Site_AnswersBeforeTheTableIsEverBuilt(t *testing.T) {
	prev := via6SiteTable.Load()
	via6SiteTable.Store(nil)
	t.Cleanup(func() { via6SiteTable.Store(prev) })

	dev, ok := lookupVia6Site(7)
	if ok || dev != 0 {
		t.Fatalf("站点表未就绪时应答「无此站点」,got (%d,%v)", dev, ok)
	}
}

// TestSnapshotSubnetRouteStats_ReportsHowManyRoutesAreLoaded /status 里的路由条数要跟着真实表走。
//
// 这个数字是运维排查「子网路由怎么不通」时看的第一眼。恒报 0 的话,他会去查审批状态、查客户端
// 宣告,而真正生效的表其实是满的 —— 排查方向从一开始就被带偏。
func TestSnapshotSubnetRouteStats_ReportsHowManyRoutesAreLoaded(t *testing.T) {
	prev := subnetRouteTable.Load()
	t.Cleanup(func() { subnetRouteTable.Store(prev) })

	subnetRouteTable.Store(nil)
	if got := snapshotSubnetRouteStats().Routes; got != 0 {
		t.Fatalf("表未就绪时应报 0 条,got %d", got)
	}

	tbl := []subnetRouteEntry{
		{prefix: netip.MustParsePrefix("192.168.30.0/24"), deviceID: 1},
		{prefix: netip.MustParsePrefix("192.168.31.0/24"), deviceID: 2},
	}
	subnetRouteTable.Store(&tbl)
	if got := snapshotSubnetRouteStats().Routes; got != 2 {
		t.Fatalf("装了 2 条路由,/status 报 %d 条 —— 运维会照着这个数字往错的方向查", got)
	}
}

// TestInitAuthBackend_RefusesToRunOnADatabaseItCannotMigrate 建不起表就必须启动失败。
//
// 打开一个 sqlite 库几乎不会失败 —— 真正会翻车的是建表:db_path 指到了别的系统的库(里面已经有个
// 叫 users 的对象、类型还不一样)、或者库是从更新的版本回滚下来的。这一步失败必须让启动整体失败:
// 若把这个库挂上 gw 继续跑,进程能起来、端口能监听,但每次登录都在查一张不存在(或形状不对)的表,
// 客户端只看到「服务器内部错误」,而日志里那行唯一的线索早已被启动日志刷走。
func TestInitAuthBackend_RefusesToRunOnADatabaseItCannotMigrate(t *testing.T) {
	dbPath := t.TempDir() + "/foreign.db"
	// 造一个「能打开但迁移必然失败」的库:先占住 users 这个名字,且占的是个 view。
	seed, err := store.Open(t.Context(), dbPath, store.Options{})
	if err != nil {
		t.Fatalf("造库: %v", err)
	}
	if _, err := seed.DB().ExecContext(t.Context(), `CREATE VIEW users AS SELECT 1 AS id`); err != nil {
		t.Fatalf("占住 users: %v", err)
	}
	if err := seed.Close(); err != nil {
		t.Fatalf("关库: %v", err)
	}

	gw := &gatewayState{cfg: &config.Config{}}
	gw.cfg.Store.DBPath = dbPath

	cleanup, err := initAuthBackend(t.Context(), gw)
	if err == nil {
		if cleanup != nil {
			cleanup()
		}
		t.Fatal("库建不起表却启动成功了 —— 进程会带着一个查不了的库对外服务,每次登录都是内部错误")
	}
	if cleanup != nil {
		t.Error("失败时不该返回 cleanup(调用方会以为库已经挂上了)")
	}
	if gw.store != nil {
		t.Error("失败时不能把这个库挂到 gw 上")
	}
}
