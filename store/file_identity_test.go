package store

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 回归:2026-07-26 实测发现 nanotun-web 在 restore 之后仍持有被 unlink 的旧 inode,
// 后台建用户返回 303 成功、PSK 都发出去了,数据却写进无人可读的孤儿文件且零报错。
// 掉包必须能被检出。
func TestCheckFileIdentity_DetectsSwap(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	path := filepath.Join(dir, "live.db")
	st, err := Open(ctx, path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := st.CheckFileIdentity(); err != nil {
		t.Fatalf("未动文件时不该报: %v", err)
	}

	// 模拟 restore:写临时文件再 rename 覆盖 —— 换的是 inode,不是原地改内容。
	other := filepath.Join(dir, "snapshot.db")
	st2, err := Open(ctx, other, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := st2.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	_ = st2.Close()
	if err := os.Rename(other, path); err != nil {
		t.Fatal(err)
	}

	err = st.CheckFileIdentity()
	if err == nil {
		t.Fatal("文件已被替换却没检出")
	}
	if !strings.Contains(err.Error(), "has been replaced") {
		t.Fatalf("错误信息应说明被替换,got %v", err)
	}
}

// 路径暂时消失(备份脚本挪走又挪回)不该误杀 —— 宁可漏报,真掉包下一轮还会被抓到。
func TestCheckFileIdentity_MissingPathIsNotASwap(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "live.db")
	st, err := Open(ctx, path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		_ = os.Remove(path + suffix)
	}
	if err := st.CheckFileIdentity(); err != nil {
		t.Fatalf("路径消失不该判为掉包: %v", err)
	}
}

// 内存库没有 inode 可比,检测必须整体跳过而不是恒报错。
func TestCheckFileIdentity_MemorySkips(t *testing.T) {
	st, err := Open(t.Context(), ":memory:", Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.CheckFileIdentity(); err != nil {
		t.Fatalf("内存库不该报: %v", err)
	}
	called := false
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	st.WatchFileIdentity(ctx, 10*time.Millisecond, func(error) { called = true })
	if called {
		t.Fatal("内存库不该触发 onSwapped")
	}
}

func TestWatchFileIdentity_FiresOnce(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	path := filepath.Join(dir, "live.db")
	st, err := Open(ctx, path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	got := make(chan error, 4)
	wctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	go st.WatchFileIdentity(wctx, 10*time.Millisecond, func(err error) { got <- err })

	other := filepath.Join(dir, "snap.db")
	st2, err := Open(ctx, other, Options{})
	if err != nil {
		t.Fatal(err)
	}
	_ = st2.Migrate(ctx)
	_ = st2.Close()
	if err := os.Rename(other, path); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-got:
		if err == nil {
			t.Fatal("onSwapped 收到 nil error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("掉包后 watcher 没触发")
	}
	// 只应回调一次然后退出。
	select {
	case <-got:
		t.Fatal("onSwapped 被重复调用")
	case <-time.After(100 * time.Millisecond):
	}
}
