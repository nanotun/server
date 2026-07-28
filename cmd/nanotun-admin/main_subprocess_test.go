package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// main() 的函数体在测试进程里跑不到:它读 os.Args、直接 os.Exit。而它恰恰是
// 「退出码」这件事的唯一真源 —— 脚本(install-self-hosted.sh、备份 cron、编排工具)
// 全靠退出码判断该不该继续。这里编出真二进制跑一遍,把 0 / 2 三条主路径钉住。
//
// 与 nanotun-web 同款:设了 NANOTUN_SUBPROC_COVERDIR 就用 `go build -cover` 编,
// 子进程的语句计数落进 GOCOVERDIR,再由 scripts/coverage/merge-coverage.py 并进基线
// (见 docs/COVERAGE.md)。不设时就是普通冒烟测试。

const adminSubprocCoverDirEnv = "NANOTUN_SUBPROC_COVERDIR"

var (
	adminBinOnce sync.Once
	adminBinPath string
	adminBinErr  error
)

func buildAdminBinary(t *testing.T) string {
	t.Helper()
	adminBinOnce.Do(func() {
		dir, err := os.MkdirTemp("", "nanotun-admin-bin-*")
		if err != nil {
			adminBinErr = err
			return
		}
		bin := filepath.Join(dir, "nanotun-admin")
		args := []string{"build", "-o", bin}
		if os.Getenv(adminSubprocCoverDirEnv) != "" {
			args = append(args, "-cover", "-covermode=atomic",
				"-coverpkg=github.com/nanotun/server/...")
		}
		out, err := exec.Command("go", append(args, ".")...).CombinedOutput()
		if err != nil {
			adminBinErr = fmt.Errorf("go build: %v\n%s", err, out)
			return
		}
		adminBinPath = bin
	})
	if adminBinErr != nil {
		t.Fatalf("编 nanotun-admin: %v", adminBinErr)
	}
	return adminBinPath
}

// runAdminBinary 跑一次二进制,返回退出码与合并输出。
func runAdminBinary(t *testing.T, args ...string) (int, string) {
	t.Helper()
	// 先编再计时:见 nanotun-web 侧 runWebBinary 的同款说明 —— 60s 是给「跑一次 CLI」
	// 的预算,不该包含整轮只做一次的编译。开了 -cover 时在 1 核机器上编一次要 ~3 分钟,
	// 混在一起会让第一条子测试以 "context deadline exceeded" 假失败。
	bin := buildAdminBinary(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = os.Environ()
	if dir := os.Getenv(adminSubprocCoverDirEnv); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("建 GOCOVERDIR: %v", err)
		}
		cmd.Env = append(cmd.Env, "GOCOVERDIR="+dir)
	}
	// 宿主机常导出 NANOTUN_DB 指向真库;子进程必须与它无关。
	cmd.Env = append(cmd.Env, "NANOTUN_DB=", "NANOTUN_LANG=")
	out, err := cmd.CombinedOutput()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("跑二进制: %v\n%s", err, out)
	}
	return code, string(out)
}

func TestAdminBinary_ExitCodesForTheThreeEntryShapes(t *testing.T) {
	if testing.Short() {
		t.Skip("要编二进制,-short 下跳过")
	}

	t.Run("version → 0", func(t *testing.T) {
		code, out := runAdminBinary(t, "version")
		if code != 0 {
			t.Fatalf("exit=%d, 期望 0\n%s", code, out)
		}
		if !strings.Contains(out, "nanotun-admin") {
			t.Errorf("没打印版本: %q", out)
		}
	})

	t.Run("help → 0", func(t *testing.T) {
		code, out := runAdminBinary(t, "help")
		if code != 0 {
			t.Fatalf("exit=%d, 期望 0\n%s", code, out)
		}
		if !strings.Contains(out, "USAGE") {
			t.Errorf("没打印用法: %q", out)
		}
	})

	// 一个参数都不给要 exit 2 并打用法。此前若返回 0,`nanotun-admin` 打错命令的
	// 脚本会当成成功继续往下跑。
	t.Run("不给子命令 → 2", func(t *testing.T) {
		code, out := runAdminBinary(t)
		if code != 2 {
			t.Fatalf("exit=%d, 期望 2\n%s", code, out)
		}
		if !strings.Contains(out, "USAGE") {
			t.Errorf("没打印用法: %q", out)
		}
	})

	// 全局 flag 解析失败也要 exit 2,而且**不能**顺手把下一个 token 当成值吞掉。
	t.Run("全局 flag 缺值 → 2", func(t *testing.T) {
		code, out := runAdminBinary(t, "--db-path")
		if code != 2 {
			t.Fatalf("exit=%d, 期望 2\n%s", code, out)
		}
		if !strings.Contains(out, "--db-path") {
			t.Errorf("报错没回显是哪个 flag: %q", out)
		}
	})

	// 库不存在时只有 init 能建库,其余命令必须 exit 2 并指向 init ——
	// 这条是「敲错 --db-path 静默造空库」那个老坑的回归闸。
	t.Run("库不存在的只读命令 → 2 且不建库", func(t *testing.T) {
		dir := t.TempDir()
		missing := filepath.Join(dir, "nope.db")
		code, out := runAdminBinary(t, "--db-path", missing, "user", "list")
		if code != 2 {
			t.Fatalf("exit=%d, 期望 2\n%s", code, out)
		}
		if _, err := os.Stat(missing); err == nil {
			t.Error("顺手把库建出来了 —— 之后所有命令都会对着这个空库跑")
		}
	})

	t.Run("--lang 影响用法语言", func(t *testing.T) {
		_, zh := runAdminBinary(t, "--lang", "zh", "help")
		_, en := runAdminBinary(t, "--lang", "en", "help")
		if zh == en {
			t.Error("中英用法输出一模一样 —— --lang 没接到 printUsage 上")
		}
	})
}
