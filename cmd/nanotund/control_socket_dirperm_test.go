package main

// control_socket_dirperm_test.go - 控制面 socket 父目录权限 fail-closed(e_ctrl_dir)。

import (
	"os"
	"path/filepath"
	"testing"
)

func TestControlSocketDirPermSafe(t *testing.T) {
	cases := []struct {
		name string
		mode os.FileMode
		want bool
	}{
		{"0700_owner_only", 0o700, true},
		{"0755_group_other_read_exec", 0o755, true},
		{"0770_group_write", 0o770, false},
		{"0777_world_write", 0o777, false},
		{"0757_other_write", 0o757, false},
		{"1777_sticky_world_write", 0o777 | os.ModeSticky, true},
		{"01770_sticky_group_write", 0o770 | os.ModeSticky, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := controlSocketDirPermSafe(c.mode); got != c.want {
				t.Fatalf("controlSocketDirPermSafe(%s)=%v want %v", c.mode, got, c.want)
			}
		})
	}
}

// prepareControlSocketPath 应在父目录 group/other 可写且无 sticky 时 fail-closed。
func TestPrepareControlSocketPath_RejectsWorldWritableParent(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "ctrldir")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	// 故意放成 0777(无 sticky)。
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	// 有些环境 umask 会影响,复核实际权限确为可写再断言。
	info, _ := os.Stat(dir)
	if info.Mode().Perm()&0o022 == 0 {
		t.Skipf("环境无法把目录设成 group/other 可写(perm=%s),跳过", info.Mode())
	}
	if err := prepareControlSocketPath(filepath.Join(dir, "c.sock")); err == nil {
		t.Fatal("父目录 0777 无 sticky 时应 fail-closed,却返回 nil")
	}
}

// 0700 父目录应通过。
func TestPrepareControlSocketPath_AcceptsTightParent(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "ctrldir")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if err := prepareControlSocketPath(filepath.Join(dir, "c.sock")); err != nil {
		t.Fatalf("0700 父目录应通过,got %v", err)
	}
}
