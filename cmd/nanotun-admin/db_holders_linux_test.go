//go:build linux

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 回归:restore 只探 nanotund 的 control socket,漏掉了共享同一个 SQLite 文件的
// nanotun-web —— 实测导致 web 后台在 restore 之后一直往被 unlink 的旧 inode 写,
// 建用户返回成功、PSK 也发了,数据却谁也读不到。这里验证「还有别人开着」能被扫出来。
func TestProcessesHoldingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "held.db")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := processesHoldingFile(path); len(got) != 0 {
		t.Fatalf("没人开着时应为空,got %v", got)
	}

	cmd := exec.Command("/bin/sh", "-c", "exec 3< \"$0\"; sleep 5", path)
	if err := cmd.Start(); err != nil {
		t.Skipf("无法起子进程: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	deadline := time.Now().Add(3 * time.Second)
	var got []string
	for time.Now().Before(deadline) {
		got = processesHoldingFile(path)
		if len(got) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(got) == 0 {
		t.Fatal("子进程开着该文件却没被扫出来")
	}
}

// 被 unlink 的持有者(上一次 restore 的遗留)才是最该报出来的那种,
// readlink 的 " (deleted)" 后缀不能让它漏网。
func TestProcessesHoldingFile_DeletedHolder(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gone.db")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", "-c", "exec 3< \"$0\"; sleep 5", path)
	if err := cmd.Start(); err != nil {
		t.Skipf("无法起子进程: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()
	time.Sleep(300 * time.Millisecond)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(3 * time.Second)
	var got []string
	for time.Now().Before(deadline) {
		got = processesHoldingFile(path)
		if len(got) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(got) == 0 {
		t.Fatal("持有已删除文件的进程没被扫出来")
	}
}

// restore 在检测到别的持有者时必须拒绝,且现库分毫不动。
func TestCmdRestore_RefusesWhenOtherProcessHoldsDB(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.db")
	dst := filepath.Join(dir, "dst.db")
	newNanotunDB(t, src, "fresh")
	newNanotunDB(t, dst, "keepme")

	cmd := exec.Command("/bin/sh", "-c", "exec 3< \"$0\"; sleep 5", dst)
	if err := cmd.Start(); err != nil {
		t.Skipf("无法起子进程: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && len(processesHoldingFile(dst)) == 0 {
		time.Sleep(50 * time.Millisecond)
	}

	out := &bytes.Buffer{}
	opts := &globalOpts{stdout: out, stderr: out, stdin: os.Stdin, dbPath: dst, yes: true,
		controlSocket: "/tmp/this-does-not-exist.sock"}
	if code := cmdRestore(opts, []string{src}); code == 0 {
		t.Fatalf("有其它进程开着时应拒绝,out=%s", out.String())
	}
	if !strings.Contains(out.String(), "sh") {
		t.Fatalf("提示里应点名持有者进程,out=%s", out.String())
	}
	if got := usersInDB(t, dst); len(got) != 1 || got[0] != "keepme" {
		t.Fatalf("现库必须分毫不动,got %v", got)
	}
}
