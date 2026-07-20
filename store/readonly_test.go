package store

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestReadOnlyRejectsWrites 校验:用 Options.ReadOnly=true 打开同一个已迁好的库,
// 任何 INSERT/UPDATE/DELETE 都会被 SQLite 用 SQLITE_READONLY 拒掉,即便先在
// 写连接上插了数据,也能从只读连接看见,但无法修改。
//
// 这是 admin CLI "只读子命令(list/show/get)" 安全模型的回归门:一旦哪天有人
// 给 list 路径里偷加了写 SQL,这个测试会直接挂。
func TestReadOnlyRejectsWrites(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "nanotun_ro.db")

	rw, err := Open(ctx, path, Options{})
	if err != nil {
		t.Fatalf("Open RW: %v", err)
	}
	if err := rw.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if _, err := rw.CreateUser(ctx, NewUser{Username: "alice", PSKHash: "h"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := rw.Close(); err != nil {
		t.Fatalf("Close RW: %v", err)
	}

	ro, err := Open(ctx, path, Options{ReadOnly: true})
	if err != nil {
		t.Fatalf("Open RO: %v", err)
	}
	defer ro.Close()

	users, err := ro.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers (RO): %v", err)
	}
	if len(users) != 1 || users[0].Username != "alice" {
		t.Fatalf("ListUsers (RO) = %+v, want [alice]", users)
	}

	if _, err := ro.CreateUser(ctx, NewUser{Username: "bob", PSKHash: "h"}); err == nil {
		t.Fatalf("CreateUser on RO store: want error, got nil")
	} else if !strings.Contains(strings.ToLower(err.Error()), "readonly") &&
		!strings.Contains(strings.ToLower(err.Error()), "read-only") &&
		!strings.Contains(strings.ToLower(err.Error()), "read only") {
		t.Fatalf("CreateUser on RO: want readonly error, got %v", err)
	}
}

// TestMaxOpenConnsParallelReads 校验 MaxOpenConns > 1 时多条只读连接能并行
// 拉取,且 connection-level pragma (query_only) 在每条连接上都生效。
//
// 这个测试的失败模式:如果哪天有人把 query_only PRAGMA 从 DSN 挪到 ExecContext,
// 只有池里第一条连接会拿到 query_only=1;第二条连接随机打到时,写 SQL 会通过,
// 然后这里就会 fail。
func TestMaxOpenConnsParallelReads(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "nanotun_pool.db")

	rw, err := Open(ctx, path, Options{})
	if err != nil {
		t.Fatalf("Open RW: %v", err)
	}
	if err := rw.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	for i := 0; i < 5; i++ {
		if _, err := rw.CreateUser(ctx, NewUser{Username: "u" + string(rune('a'+i)), PSKHash: "h"}); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
	}
	if err := rw.Close(); err != nil {
		t.Fatalf("Close RW: %v", err)
	}

	ro, err := Open(ctx, path, Options{ReadOnly: true, MaxOpenConns: 4})
	if err != nil {
		t.Fatalf("Open RO: %v", err)
	}
	defer ro.Close()

	// 触发多条 conn 同时被建出来,验证每条都拒写。
	errCh := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func() {
			if _, err := ro.ListUsers(ctx); err != nil {
				errCh <- err
				return
			}
			_, err := ro.DB().ExecContext(ctx, "INSERT INTO app_settings(key,value) VALUES('ro_probe','x')")
			errCh <- err
		}()
	}
	for i := 0; i < 8; i++ {
		err := <-errCh
		if err == nil {
			t.Fatalf("expected write on RO pool conn %d to fail, got nil", i)
		}
		low := strings.ToLower(err.Error())
		if !strings.Contains(low, "readonly") && !strings.Contains(low, "read-only") && !strings.Contains(low, "read only") {
			t.Fatalf("expected readonly error on conn %d, got %v", i, err)
		}
	}
}
