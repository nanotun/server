package store

// users_guards_test.go:users 表 DAL 的输入守卫、ErrNotFound / ErrDuplicate 归一、
// 以及「写失败必须让调用方看见」这三类断言。
//
// 为什么这些值得单独一个文件:users 行是整套鉴权的根 —— 用户名歧义会让两个账号在
// 登录界面长得一模一样;psk_hash 半途改坏会让人扫了 QR 登不上;删用户时孤儿转发没清
// 会被后来注册同 UUID 的人静默继承公网入口。这些都不是「返回值对不对」的问题,而是
// 「失败时库里剩下什么」的问题,所以下面每个用例都在断言错误之外再断言一次落库状态。

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// newClosedUserStore:建库、塞一个用户、然后关掉。用来验证「连接没了」时每个函数都报错,
// 而不是静默成功或被归一成 ErrNotFound(后者会让 CLI 显示「用户不存在」而不是「存储故障」)。
func newClosedUserStore(t *testing.T) (*Store, int64) {
	t.Helper()
	s := newTestStore(t)
	u := mustUser(t, s, "doomed-user")
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return s, u.ID
}

func countUsersRaw(t *testing.T, s *Store) int {
	t.Helper()
	var n int
	if err := s.db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		t.Fatalf("count users: %v", err)
	}
	return n
}

func TestCreateUser_RefusesRowsNobodyCouldTellApartLater(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	base := mustUser(t, s, "alice")
	before := countUsersRaw(t, s)

	cases := []struct {
		name    string
		in      NewUser
		because string
	}{
		{
			"用户名裁剪后为空", NewUser{Username: "   \t ", PSKHash: "h"},
			"空用户名登录时匹配不到任何人,却占着一行,列表里显示成空白账号",
		},
		{
			"psk_hash 为空", NewUser{Username: "nopsk", PSKHash: "  "},
			"空 hash 会让口令校验退化 —— 任何比对空串的路径都可能直接放行",
		},
		{
			"仅大小写不同的重名", NewUser{Username: "ALICE", PSKHash: "h"},
			"列上的 UNIQUE 是 BINARY,挡不住 Alice/alice;登录界面上两行长得一样,授权给谁全看运气",
		},
		{
			"用户名只差首尾空白", NewUser{Username: "  alice  ", PSKHash: "h"},
			"入库前要裁剪,裁剪后与既有 alice 同名,应当按重名拒绝",
		},
		{
			"上行带宽为负", NewUser{Username: "negup", PSKHash: "h", BandwidthUpBPS: -1},
			"负带宽被消费方按无符号解读会整型回绕成天文数字,等于绕过限速",
		},
		{
			"下行带宽为负", NewUser{Username: "negdown", PSKHash: "h", BandwidthDownBPS: -1},
			"同上",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.CreateUser(ctx, tc.in)
			if err == nil {
				t.Fatalf("应被拒绝却建成了 %+v。%s", got, tc.because)
			}
		})
	}

	if n := countUsersRaw(t, s); n != before {
		t.Fatalf("users 现在 %d 行,建号前 %d 行 —— 被拒的创建不该落库", n, before)
	}
	if got, err := s.GetUser(ctx, base.ID); err != nil || got.Username != "alice" {
		t.Fatalf("原有用户被污染了: %+v err=%v", got, err)
	}
}

func TestCreateUser_DuplicateCredentialIDIsNormalizedNotLeakedAsDriverError(t *testing.T) {
	// credential_id 上有 UNIQUE 索引(0013/0027)。UUID v4 撞车概率极低,但调用方
	// 只有拿到 ErrDuplicate 才知道「重新生成一个再试」;裸驱动错误只会被当成存储故障放弃。
	s := newTestStore(t)
	ctx := t.Context()
	const cred = "11111111-2222-3333-4444-555555555555"
	if _, err := s.CreateUser(ctx, NewUser{Username: "first", PSKHash: "h", CredentialID: cred}); err != nil {
		t.Fatalf("CreateUser first: %v", err)
	}
	_, err := s.CreateUser(ctx, NewUser{Username: "second", PSKHash: "h", CredentialID: cred})
	if !errors.Is(err, ErrDuplicate) {
		t.Fatalf("err=%v,想要 ErrDuplicate —— 调用方据此重新生成 UUID,不然只能整个放弃", err)
	}
	if n := countUsersRaw(t, s); n != 1 {
		t.Fatalf("users %d 行,重复 credential_id 的那次不该留下半行", n)
	}
}

func TestUserReads_SurfaceBrokenRowsInsteadOfSilentlyShorteningTheList(t *testing.T) {
	// 列表少一行比报错危险得多:管理员看不到某个账号,就以为它不存在 / 已清理,
	// 而这个账号照样能登录。所以扫描失败必须整体报错。
	s := newTestStore(t)
	ctx := t.Context()
	mustUser(t, s, "good")
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO users(username, psk_hash, is_admin, bandwidth_up_bps, bandwidth_down_bps,
		                   exit_allowed, role, created_at, credential_id)
		 VALUES('corrupt','h',0,0,0,0,'user','这不是时间戳','cred-x')`); err != nil {
		t.Fatalf("插损坏行: %v", err)
	}

	lists := map[string]func() ([]*User, error){
		"ListUsers":                func() ([]*User, error) { return s.ListUsers(ctx) },
		"ListUsersAll":             func() ([]*User, error) { return s.ListUsersAll(ctx) },
		"ListUsersWithCredentials": func() ([]*User, error) { return s.ListUsersWithCredentials(ctx) },
	}
	for name, run := range lists {
		t.Run(name, func(t *testing.T) {
			out, err := run()
			if err == nil {
				t.Fatalf("读到损坏行却返回了 %d 条和 nil —— 少的那行会被当成不存在", len(out))
			}
			if errors.Is(err, ErrNotFound) {
				t.Fatalf("损坏行被归一成 ErrNotFound: %v", err)
			}
		})
	}
	t.Run("GetUser 单行同理", func(t *testing.T) {
		var id int64
		if err := s.db.QueryRowContext(ctx, `SELECT id FROM users WHERE username='corrupt'`).Scan(&id); err != nil {
			t.Fatalf("取 id: %v", err)
		}
		if _, err := s.GetUser(ctx, id); err == nil {
			t.Fatal("损坏行被当成正常用户返回了")
		} else if errors.Is(err, ErrNotFound) {
			t.Fatalf("损坏行被归一成 ErrNotFound: %v —— 调用方会以为账号已删除", err)
		}
	})
}

func TestRotateUserPSK_RefusesInputsThatWouldStrandTheClient(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	u := mustUser(t, s, "rot")
	const ghost = int64(987654)

	t.Run("空 hash", func(t *testing.T) {
		if err := s.RotateUserPSK(ctx, u.ID, "  ", 100); err == nil {
			t.Fatal("空 psk_hash 应被拒 —— 落库后口令校验形同虚设")
		}
	})
	t.Run("非正的 created_at", func(t *testing.T) {
		for _, ts := range []int64{0, -1} {
			if err := s.RotateUserPSK(ctx, u.ID, "new", ts); !errors.Is(err, ErrInvalid) {
				t.Fatalf("created_at=%d err=%v,想要 ErrInvalid —— 0 会被 COALESCE 当成「没设过」,"+
					"客户端看不出 PSK 换过", ts, err)
			}
		}
	})
	t.Run("不存在的用户", func(t *testing.T) {
		if err := s.RotateUserPSK(ctx, ghost, "new", 100); !errors.Is(err, ErrNotFound) {
			t.Fatalf("err=%v,想要 ErrNotFound —— 静默成功会让 admin 拿着一张没人认的 QR", err)
		}
	})
	t.Run("CAS 版的入参守卫", func(t *testing.T) {
		if _, err := s.RotateUserPSKCAS(ctx, u.ID, "", "old", 100); err == nil {
			t.Fatal("空新 hash 应被拒")
		}
		if _, err := s.RotateUserPSKCAS(ctx, u.ID, "new", "   ", 100); err == nil {
			t.Fatal("空 expectedOldHash 应被拒 —— 没有 base 的 CAS 等于没有 CAS")
		}
		if _, err := s.RotateUserPSKCAS(ctx, u.ID, "new", "h", 0); !errors.Is(err, ErrInvalid) {
			t.Fatalf("err=%v,想要 ErrInvalid", err)
		}
	})
	t.Run("CAS 落空返回 wrote=false 而不是错误", func(t *testing.T) {
		wrote, err := s.RotateUserPSKCAS(ctx, u.ID, "new", "不是当前的hash", 100)
		if err != nil || wrote {
			t.Fatalf("wrote=%v err=%v,想要 (false, nil) —— 调用方靠重读区分「行没了」和「被人抢先」", wrote, err)
		}
		got, err := s.GetUser(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetUser: %v", err)
		}
		if got.PSKHash != "h" {
			t.Fatalf("CAS 没匹配上却把 hash 改成了 %q", got.PSKHash)
		}
	})

	// 入参都合法时必须真的改到,否则上面那些「应当被拒」的断言可以靠一个永远失败的实现骗过去。
	if err := s.RotateUserPSK(ctx, u.ID, "brand-new", 4242); err != nil {
		t.Fatalf("合法 rotate 失败: %v", err)
	}
	got, err := s.GetUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if got.PSKHash != "brand-new" || got.CredentialCreatedAt != 4242 {
		t.Fatalf("rotate 后 hash=%q ts=%d", got.PSKHash, got.CredentialCreatedAt)
	}
}

func TestBackfillUserCredentialID_IsIdempotentAndNormalizesCollisions(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	a := mustUser(t, s, "backfill-a")
	b := mustUser(t, s, "backfill-b")

	t.Run("入参守卫", func(t *testing.T) {
		if _, err := s.BackfillUserCredentialID(ctx, a.ID, "  ", 100); err == nil {
			t.Fatal("空 credential_id 应被拒")
		}
		if _, err := s.BackfillUserCredentialID(ctx, a.ID, "cred-a", 0); !errors.Is(err, ErrInvalid) {
			t.Fatal("created_at<=0 应被拒")
		}
	})

	wrote, err := s.BackfillUserCredentialID(ctx, a.ID, "cred-a", 100)
	if err != nil || !wrote {
		t.Fatalf("首次补齐 wrote=%v err=%v", wrote, err)
	}
	t.Run("再补一次不写也不报错", func(t *testing.T) {
		wrote, err := s.BackfillUserCredentialID(ctx, a.ID, "cred-a2", 200)
		if err != nil || wrote {
			t.Fatalf("wrote=%v err=%v,想要 (false, nil)", wrote, err)
		}
		got, err := s.GetUser(ctx, a.ID)
		if err != nil {
			t.Fatalf("GetUser: %v", err)
		}
		if got.CredentialID != "cred-a" {
			t.Fatalf("credential_id 被改成了 %q —— 客户端就是按它索引的,改了等于旧 QR 全部失联",
				got.CredentialID)
		}
	})
	t.Run("撞车归一成 ErrDuplicate", func(t *testing.T) {
		_, err := s.BackfillUserCredentialID(ctx, b.ID, "cred-a", 300)
		if !errors.Is(err, ErrDuplicate) {
			t.Fatalf("err=%v,想要 ErrDuplicate —— 调用方据此重生成 UUID 再试", err)
		}
	})
	t.Run("不存在的用户返回 wrote=false", func(t *testing.T) {
		wrote, err := s.BackfillUserCredentialID(ctx, 987654, "cred-ghost", 100)
		if err != nil || wrote {
			t.Fatalf("wrote=%v err=%v", wrote, err)
		}
	})
}

func TestUserMutators_TellApartBadInputMissingRowAndStorageFailure(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	u := mustUser(t, s, "mut")
	const ghost = int64(987654)

	t.Run("非法入参", func(t *testing.T) {
		bad := []struct {
			name string
			run  func() error
		}{
			{"带宽为负", func() error { return s.SetUserBandwidth(ctx, u.ID, -1, 0) }},
			{"下行带宽为负", func() error { return s.SetUserBandwidth(ctx, u.ID, 0, -5) }},
			{"max_sessions 小于 -1", func() error { return s.SetUserMaxSessions(ctx, u.ID, -2) }},
			{"max_sessions 超上限", func() error { return s.SetUserMaxSessions(ctx, u.ID, MaxSessionsCap+1) }},
		}
		for _, tc := range bad {
			t.Run(tc.name, func(t *testing.T) {
				if err := tc.run(); !errors.Is(err, ErrInvalid) {
					t.Fatalf("err=%v,想要 ErrInvalid", err)
				}
			})
		}
		got, err := s.GetUser(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetUser: %v", err)
		}
		if got.BandwidthUpBPS != 0 || got.BandwidthDownBPS != 0 || got.MaxSessions != 0 {
			t.Fatalf("被拒的写落库了: %+v", got)
		}
	})

	t.Run("行不存在", func(t *testing.T) {
		missing := map[string]func() error{
			"SetUserBandwidth":        func() error { return s.SetUserBandwidth(ctx, ghost, 1, 1) },
			"SetUserAllowedPlatforms": func() error { return s.SetUserAllowedPlatforms(ctx, ghost, "linux") },
			"SetUserMaxSessions":      func() error { return s.SetUserMaxSessions(ctx, ghost, 3) },
			"DisableUser":             func() error { return s.DisableUser(ctx, ghost) },
			"EnableUser":              func() error { return s.EnableUser(ctx, ghost) },
			"DeleteUser":              func() error { return s.DeleteUser(ctx, ghost) },
			"RotateUserPSK":           func() error { return s.RotateUserPSK(ctx, ghost, "h", 1) },
		}
		for name, run := range missing {
			t.Run(name, func(t *testing.T) {
				if err := run(); !errors.Is(err, ErrNotFound) {
					t.Fatalf("err=%v,想要 ErrNotFound —— 静默成功会让管理员以为改动生效了", err)
				}
			})
		}
	})

	t.Run("库关掉之后一律报错", func(t *testing.T) {
		dead, id := newClosedUserStore(t)
		ops := map[string]func() error{
			"CreateUser": func() error {
				_, err := dead.CreateUser(ctx, NewUser{Username: "x", PSKHash: "h"})
				return err
			},
			"GetUser":            func() error { _, err := dead.GetUser(ctx, id); return err },
			"GetUserByUsername":  func() error { _, err := dead.GetUserByUsername(ctx, "doomed-user"); return err },
			"ListUsers":          func() error { _, err := dead.ListUsers(ctx); return err },
			"ListUsersAll":       func() error { _, err := dead.ListUsersAll(ctx); return err },
			"ListUsersWithCreds": func() error { _, err := dead.ListUsersWithCredentials(ctx); return err },
			"CountUsers":         func() error { _, err := dead.CountUsers(ctx); return err },
			"RotateUserPSK":      func() error { return dead.RotateUserPSK(ctx, id, "h2", 100) },
			"RotateUserPSKCAS": func() error {
				_, err := dead.RotateUserPSKCAS(ctx, id, "h2", "h", 100)
				return err
			},
			"BackfillCredential": func() error {
				_, err := dead.BackfillUserCredentialID(ctx, id, "cred", 100)
				return err
			},
			"SetUserBandwidth":        func() error { return dead.SetUserBandwidth(ctx, id, 1, 1) },
			"SetUserAllowedPlatforms": func() error { return dead.SetUserAllowedPlatforms(ctx, id, "linux") },
			"SetUserMaxSessions":      func() error { return dead.SetUserMaxSessions(ctx, id, 3) },
			"DisableUser":             func() error { return dead.DisableUser(ctx, id) },
			"EnableUser":              func() error { return dead.EnableUser(ctx, id) },
			"DeleteUser":              func() error { return dead.DeleteUser(ctx, id) },
			"RotateAndEnsureCred": func() error {
				_, _, err := dead.RotateUserPSKAndEnsureCredential(ctx, &User{ID: id, PSKHash: "h"}, "h2")
				return err
			},
		}
		for name, run := range ops {
			t.Run(name, func(t *testing.T) {
				err := run()
				if err == nil {
					t.Fatal("库已关闭却报成功")
				}
				if errors.Is(err, ErrNotFound) {
					t.Fatalf("存储故障被归一成 ErrNotFound: %v —— CLI 会显示「用户不存在」,"+
						"管理员据此去重建账号,越修越乱", err)
				}
			})
		}
	})
}

func TestUserWrites_OnReadOnlyDatabaseFailLoudly(t *testing.T) {
	// 磁盘满 / 文件系统只读时,写路径的 UPDATE 会失败但 SELECT 仍然正常 ——
	// 这跟「库关了」不是一回事:调用方能读到行,更容易误以为写也生效了。
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "ro_users.db")
	rw, err := Open(ctx, path, Options{})
	if err != nil {
		t.Fatalf("Open rw: %v", err)
	}
	if err := rw.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	u, err := rw.CreateUser(ctx, NewUser{Username: "frozen", PSKHash: "h"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := rw.Close(); err != nil {
		t.Fatalf("Close rw: %v", err)
	}
	s, err := Open(ctx, path, Options{ReadOnly: true})
	if err != nil {
		t.Fatalf("Open ro: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	writes := map[string]func() error{
		"CreateUser": func() error {
			_, err := s.CreateUser(ctx, NewUser{Username: "new", PSKHash: "h"})
			return err
		},
		"RotateUserPSK":           func() error { return s.RotateUserPSK(ctx, u.ID, "h2", 100) },
		"SetUserBandwidth":        func() error { return s.SetUserBandwidth(ctx, u.ID, 1, 1) },
		"SetUserAllowedPlatforms": func() error { return s.SetUserAllowedPlatforms(ctx, u.ID, "linux") },
		"SetUserMaxSessions":      func() error { return s.SetUserMaxSessions(ctx, u.ID, 3) },
		"DisableUser":             func() error { return s.DisableUser(ctx, u.ID) },
		"DeleteUser":              func() error { return s.DeleteUser(ctx, u.ID) },
	}
	for name, run := range writes {
		t.Run(name, func(t *testing.T) {
			err := run()
			if err == nil {
				t.Fatal("只读库上写成功了?")
			}
			if errors.Is(err, ErrNotFound) {
				t.Fatalf("只读失败被归一成 ErrNotFound: %v", err)
			}
		})
	}
	// 读仍然要好使 —— 否则上面的断言可能只是「库整个坏了」。
	if got, err := s.GetUser(ctx, u.ID); err != nil || got.PSKHash != "h" {
		t.Fatalf("只读库上读也失败了 got=%+v err=%v", got, err)
	}
}

func TestDeleteUser_KeepsTheAccountWhenItsForwardsCannotBeReaped(t *testing.T) {
	// 端口转发表没有外键,删用户时得手动清掉指向它设备 UUID 的转发。
	// 若清理失败却照样把用户删掉,那些转发就成了孤儿:下一个注册同 UUID 的人
	// 会静默继承别人的公网入口。所以这一步失败必须整个事务回滚。
	s := newTestStore(t)
	ctx := t.Context()
	u := mustUser(t, s, "pf-owner")
	if _, err := s.UpsertDevice(ctx, u.ID, "uuid-user-pf", "d", "linux"); err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}
	if _, err := s.CreatePortForward(ctx, PortForward{
		PublicPort: 18099, Proto: "tcp", TargetDeviceUUID: "uuid-user-pf",
		TargetIP: "10.0.0.7", TargetPort: 80, Enabled: true,
	}); err != nil {
		t.Fatalf("CreatePortForward: %v", err)
	}
	abortOn(t, s, "port_forwards", "DELETE")

	if err := s.DeleteUser(ctx, u.ID); err == nil {
		t.Fatal("孤儿转发清不掉却报删除成功")
	}
	if _, err := s.GetUser(ctx, u.ID); err != nil {
		t.Fatalf("用户被删了但转发还在 —— 正是要防的孤儿状态: %v", err)
	}
}

func TestDeleteUser_SurfacesTheUserDeleteFailureItself(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	u := mustUser(t, s, "undeletable")
	abortOn(t, s, "users", "DELETE")

	err := s.DeleteUser(ctx, u.ID)
	if err == nil {
		t.Fatal("删用户失败却报成功")
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatalf("写失败被归一成 ErrNotFound: %v", err)
	}
	if _, err := s.GetUser(ctx, u.ID); err != nil {
		t.Fatalf("报了错却真删了: %v", err)
	}
}

func TestRotateAndEnsureCredential_IsAllOrNothing(t *testing.T) {
	// 这个高阶入口的全部价值就在于「PSK 和 credential_id 在同一个事务里」:
	// 半成功(PSK 换了、credential_id 还空)会让 admin 拿到一张生成不出来的 QR,
	// 而用户的旧 PSK 已经作废 —— 人被锁在门外,还看不出发生了什么。
	newUser := func(t *testing.T) (*Store, *User) {
		t.Helper()
		s := newTestStore(t)
		return s, mustUser(t, s, "rotator")
	}

	t.Run("入参守卫", func(t *testing.T) {
		s, u := newUser(t)
		ctx := t.Context()
		if _, _, err := s.RotateUserPSKAndEnsureCredential(ctx, nil, "h2"); err == nil {
			t.Fatal("nil user 应被拒")
		}
		if _, _, err := s.RotateUserPSKAndEnsureCredential(ctx, &User{ID: u.ID}, "h2"); err == nil {
			t.Fatal("snapshot 的 psk_hash 为空时应当报错 —— 没有 CAS base 就退回无守门的盲写," +
				"正是并发 rotate 双赢家那个 bug")
		}
		if _, _, err := s.RotateUserPSKAndEnsureCredential(ctx, u, ""); err == nil {
			t.Fatal("空新 hash 应被拒")
		}
	})

	t.Run("快照过期时返回 CAS sentinel 且不动库", func(t *testing.T) {
		s, u := newUser(t)
		ctx := t.Context()
		stale := *u
		if err := s.RotateUserPSK(ctx, u.ID, "别人先改的", 100); err != nil {
			t.Fatalf("先手 rotate: %v", err)
		}
		if _, _, err := s.RotateUserPSKAndEnsureCredential(ctx, &stale, "我的新hash"); !errors.Is(err, ErrPSKConcurrentRotation) {
			t.Fatalf("err=%v,想要 ErrPSKConcurrentRotation —— 调用方据此提示刷新,而不是展示过期 QR", err)
		}
		got, err := s.GetUser(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetUser: %v", err)
		}
		if got.PSKHash != "别人先改的" {
			t.Fatalf("输家把赢家的 hash 覆盖成了 %q", got.PSKHash)
		}
	})

	t.Run("正常路径补齐 credential_id 并保持稳定", func(t *testing.T) {
		s, u := newUser(t)
		ctx := t.Context()
		cred, ts, err := s.RotateUserPSKAndEnsureCredential(ctx, u, "h2")
		if err != nil {
			t.Fatalf("rotate: %v", err)
		}
		if cred == "" || ts <= 0 {
			t.Fatalf("cred=%q ts=%d,两者都该非空", cred, ts)
		}
		reloaded, err := s.GetUser(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetUser: %v", err)
		}
		again, ts2, err := s.RotateUserPSKAndEnsureCredential(ctx, reloaded, "h3")
		if err != nil {
			t.Fatalf("二次 rotate: %v", err)
		}
		if again != cred {
			t.Fatalf("credential_id 从 %q 变成了 %q —— 客户端按它索引,换了等于旧 QR 全部失联", cred, again)
		}
		if ts2 < ts {
			t.Fatalf("created_at 倒退了 %d → %d", ts, ts2)
		}
	})

	t.Run("CAS 写失败时整体回滚", func(t *testing.T) {
		s, u := newUser(t)
		abortOn(t, s, "users", "UPDATE OF psk_hash")
		if _, _, err := s.RotateUserPSKAndEnsureCredential(t.Context(), u, "h2"); err == nil {
			t.Fatal("写失败却报成功")
		}
	})

	t.Run("补 credential_id 失败时连 PSK 一起回滚", func(t *testing.T) {
		s, u := newUser(t)
		ctx := t.Context()
		abortOn(t, s, "users", "UPDATE OF credential_id")

		if _, _, err := s.RotateUserPSKAndEnsureCredential(ctx, u, "h2"); err == nil {
			t.Fatal("补 credential_id 失败却报成功")
		}
		got, err := s.GetUser(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetUser: %v", err)
		}
		if got.PSKHash != "h" {
			t.Fatalf("psk_hash 已变成 %q 但 credential_id=%q —— 正是要消除的半成功态:"+
				"旧 PSK 作废了,新 QR 却生成不出来", got.PSKHash, got.CredentialID)
		}
	})

	t.Run("事务内重读失败时也回滚", func(t *testing.T) {
		s, u := newUser(t)
		ctx := t.Context()
		if _, err := s.db.ExecContext(ctx,
			`ALTER TABLE users RENAME COLUMN credential_id TO credential_id_drifted`); err != nil {
			t.Fatalf("改列名: %v", err)
		}
		if _, _, err := s.RotateUserPSKAndEnsureCredential(ctx, u, "h2"); err == nil {
			t.Fatal("读不到 credential_id 却报成功")
		}
		var hash string
		if err := s.db.QueryRowContext(ctx, `SELECT psk_hash FROM users WHERE id=?`, u.ID).Scan(&hash); err != nil {
			t.Fatalf("读 psk_hash: %v", err)
		}
		if hash != "h" {
			t.Fatalf("psk_hash 已被改成 %q,事务没回滚", hash)
		}
	})
}

func TestEnsureUserCredentialID_AlwaysHandsBackAUsableTimestamp(t *testing.T) {
	// QR 上的 created_at 是客户端判断「这张比手里的新」的唯一依据。返回 0 会让
	// 新旧两张 QR 看起来一样新,客户端可能拒绝覆盖旧 PSK。所以每条分支都得兜到非零。
	s := newTestStore(t)
	ctx := t.Context()

	t.Run("nil user", func(t *testing.T) {
		if _, _, err := s.EnsureUserCredentialID(ctx, nil); err == nil {
			t.Fatal("nil user 应被拒")
		}
	})

	t.Run("已有凭证时原样返回", func(t *testing.T) {
		u := &User{ID: 1, CredentialID: "cred", CredentialCreatedAt: 77, CreatedAt: 55}
		id, ts, err := s.EnsureUserCredentialID(ctx, u)
		if err != nil || id != "cred" || ts != 77 {
			t.Fatalf("id=%q ts=%d err=%v", id, ts, err)
		}
	})
	t.Run("已有凭证但没有凭证时间时退回建号时间", func(t *testing.T) {
		u := &User{ID: 1, CredentialID: "cred", CreatedAt: 55}
		_, ts, err := s.EnsureUserCredentialID(ctx, u)
		if err != nil || ts != 55 {
			t.Fatalf("ts=%d err=%v,想要退回 created_at=55", ts, err)
		}
	})
	t.Run("两个时间都没有时退回当下", func(t *testing.T) {
		u := &User{ID: 1, CredentialID: "cred"}
		_, ts, err := s.EnsureUserCredentialID(ctx, u)
		if err != nil || ts <= 0 {
			t.Fatalf("ts=%d err=%v,不能返回 0 —— 客户端会认不出新旧", ts, err)
		}
	})

	t.Run("老用户首次补齐", func(t *testing.T) {
		u := mustUser(t, s, "legacy")
		id, ts, err := s.EnsureUserCredentialID(ctx, u)
		if err != nil {
			t.Fatalf("EnsureUserCredentialID: %v", err)
		}
		if id == "" || ts <= 0 {
			t.Fatalf("id=%q ts=%d", id, ts)
		}
		got, err := s.GetUser(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetUser: %v", err)
		}
		if got.CredentialID != id {
			t.Fatalf("返回 %q 但库里是 %q —— 两边对不上,QR 指向一个不存在的凭证", id, got.CredentialID)
		}
	})
	t.Run("老用户连 created_at 都是 0 时退回当下", func(t *testing.T) {
		u := mustUser(t, s, "legacy-nots")
		if _, err := s.db.ExecContext(ctx, `UPDATE users SET created_at=0 WHERE id=?`, u.ID); err != nil {
			t.Fatalf("清 created_at: %v", err)
		}
		reloaded, err := s.GetUser(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetUser: %v", err)
		}
		_, ts, err := s.EnsureUserCredentialID(ctx, reloaded)
		if err != nil || ts <= 0 {
			t.Fatalf("ts=%d err=%v", ts, err)
		}
	})
	t.Run("补齐写不进去时不能凭空发一个凭证", func(t *testing.T) {
		// 返回一个库里不存在的 credential_id,客户端拿去索引会永远对不上,
		// 而 admin 那头看不出任何异常。
		s := newTestStore(t)
		u := mustUser(t, s, "backfill-blocked")
		abortOn(t, s, "users", "UPDATE OF credential_id")

		id, ts, err := s.EnsureUserCredentialID(t.Context(), u)
		if err == nil {
			t.Fatalf("写失败却发回了 id=%q ts=%d", id, ts)
		}
	})

	t.Run("补齐落空且行已消失时报错", func(t *testing.T) {
		// wrote=false 说明 WHERE 没匹配上:要么行没了,要么别人抢先写了。
		// 行没了的分支必须报错 —— 返回一个库里根本不存在的 credential_id 更糟。
		u := &User{ID: 987654}
		if _, _, err := s.EnsureUserCredentialID(ctx, u); err == nil {
			t.Fatal("用户不存在却发回了一个凭证")
		}
	})
}

// 兜底:确认上面用到的注入手段本身是有效的 —— 触发器真的会让写失败,
// 否则那些「应当报错」的断言可能只是碰巧通过。
func TestAbortTriggerActuallyBitesOnUsers(t *testing.T) {
	s := newTestStore(t)
	u := mustUser(t, s, "canary")
	abortOn(t, s, "users", "UPDATE OF psk_hash")
	_, err := s.db.ExecContext(t.Context(), `UPDATE users SET psk_hash='x' WHERE id=?`, u.ID)
	if err == nil {
		t.Fatal("触发器没生效,依赖它的用例全部是假通过")
	}
	if !strings.Contains(fmt.Sprint(err), "注入的故障") {
		t.Fatalf("失败原因不是注入的那个: %v", err)
	}
}
