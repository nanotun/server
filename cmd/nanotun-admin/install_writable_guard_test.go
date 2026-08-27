package main

// install_writable_guard_test.go —— 落点写不进去时,得在动手之前拦住。
//
// install-self-hosted.sh 第 1 步原来是一串裸的 install。任何一次写失败都被 set -e 直接
// 带走,屏幕上最后一行是 coreutils 自己的英文;换成 uutils 版(有些发行版已经默认它)
// 更糟,吐的是一段 Rust 调试结构:`Os { code: 30, kind: ReadOnlyFilesystem, .. }`。
// 没有 FATAL、没有原因、也没有下一步 —— 而这是第 1 步,失败时 /usr/local/bin 里已经
// 装进去一半,人却看不出机器现在是什么状态、自己的服务还在不在。
// 实测:把 /usr/local/bin 挂成只读,得到的就是那段 Rust 结构体加一句 `install: Already exists`。
//
// 修法是在写第一个文件之前先探一遍:目录建得出来吗、真写得进去吗、放得下吗。
// 拦住比事后解释值钱 —— 检查不过就一个文件都没动,机器还是原样,修完重跑即可。
//
// 这个测试盯两件事:探测还在,而且仍然排在第一个 install 之前。挪到后面等于没有:
// 第一个 install 会先失败先退出,探测永远走不到。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallSelfHosted_ProbesTargetsBeforeWriting(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("../..", "scripts/install-self-hosted.sh"))
	if err != nil {
		t.Fatalf("读 install-self-hosted.sh: %v", err)
	}
	body := string(raw)

	iProbe := strings.Index(body, ".nanotun-write-test")
	iSpace := strings.Index(body, "所在分区空间不够")
	iFirstInstall := strings.Index(body, `install -m 0755 "$DEPLOY_DIR/nanotund"`)

	if iProbe < 0 {
		t.Error("第 1 步没有写入探测 —— 只读挂载 / 权限 / immutable 会让安装装到一半," +
			"而屏幕上只剩 install 自己的英文报错(uutils 版是一段 Rust 调试结构)")
	}
	if iSpace < 0 {
		t.Error("第 1 步没有空间检查 —— 空间不够时会留下半截 nanotund:" +
			"正在跑的服务靠已打开的旧文件还撑着,重启才起不来,那时离现在可能隔了很久")
	}
	if iFirstInstall < 0 {
		t.Fatal("找不到第一个 install 调用,这个测试的定位假设已经失效")
	}
	if iProbe > iFirstInstall || iSpace > iFirstInstall {
		t.Error("探测跑到了第一个 install 后面 —— install 会先失败先退出,探测等于没有")
	}

	// 只读挂载是这条修复最主要的目标场景,而 [ -w ] 判不出它:root 对目录的权限位永远够,
	// 拦住写入的是挂载选项,要等真正 write 才报出来。所以必须是「真写一个文件」。
	if !strings.Contains(body, `touch "$d/.nanotun-write-test"`) {
		t.Error("写入探测不是靠真写一个文件 —— 换成 [ -w ] 之类的判据会把只读挂载放过去")
	}
	for _, c := range []struct{ needle, why string }{
		{"只读挂载", "得点名这个最常见的成因,否则人只会去查权限"},
		{"immutable", "chattr +i 的目录同样写不进去,而它不体现在权限位上"},
		{"一个文件都还没动,机器仍是原样", "得让人知道现在是安全的,不必先去抢救机器"},
	} {
		if !strings.Contains(body, c.needle) {
			t.Errorf("找不到 %q —— %s", c.needle, c.why)
		}
	}
}
