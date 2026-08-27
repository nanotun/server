package main

// install_checksum_guard_test.go —— 校验失败时,得说清是哪一种失败。
//
// `sha256sum -c` 对三件完全不同的事给的是同一个非零退出码,而 install.sh 原来把它们
// 一律报成第三种:「下载的包与官方清单不符,可能是被中间人替换过」。
//
//   ① 取到的根本不是校验清单 —— 公司代理、酒店/机场登录门户、坏镜像对任何请求都回一页
//      HTML,状态码还是 200。这时候包压根没跟任何东西比对过,那句话是假的;而该做的事
//      (换条链路)也被藏住了。实测:清单换成 HTML,报的仍是「包与清单不符」。
//   ② 清单是真的,但里面没有本机架构这一条(发布时清单没覆盖全)。包很可能好端端的,
//      却被指成「可能被中间人替换过」—— 一句相当吓人、而且错的判断。实测同上。
//   ③ 清单里有这一条,哈希对不上。只有这一种才是「传输损坏或被人替换」。
//
// 修法是跑 -c 之前先看清单本身。这个测试盯着三条岔路别再并回一条 —— 并回去不会有任何
// 报错,只会让前两种人拿着一句假的诊断去查一件跟他无关的事。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstall_ChecksumFailuresAreDistinguished(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("../..", "scripts/install.sh"))
	if err != nil {
		t.Fatalf("读 install.sh: %v", err)
	}
	body := string(raw)

	for _, c := range []struct{ needle, why string }{
		{"不是一份校验清单", "①:清单不是清单时要单独说,并把矛头指向代理 / 门户 / 镜像"},
		{"它们对任何请求都回一页 HTML", "①:得点破「状态码 200 但内容是网页」这种最迷惑的形态"},
		{"没法核对下载的包", "②:清单里没有本机这一条时,说的应是「没核对成」而不是「不符」"},
		{"清单没覆盖全", "②:要说清这多半是发布方的疏漏,不是这台机器遇到了攻击"},
		{"本机算出来的是", "②:给出本地哈希,人才有办法去手动核对"},
		{"可能是传输损坏,也可能是被中间人替换过", "③:真对不上的那条原话要留着,它在这一种情形下是对的"},
	} {
		if !strings.Contains(body, c.needle) {
			t.Errorf("install.sh 里找不到 %q —— %s", c.needle, c.why)
		}
	}

	// 顺序也是这条修复的一部分:两道预检必须在 -c 之前。放到后面等于没修 ——
	// -c 先失败,先 die,预检永远走不到。
	iCheck := strings.Index(body, `"${SHA_CHECK[@]}" < SHA256SUMS`)
	iManifest := strings.Index(body, "不是一份校验清单")
	iEntry := strings.Index(body, "没法核对下载的包")
	if iCheck < 0 || iManifest < 0 || iEntry < 0 {
		t.Fatal("找不到校验那一段的关键行,这个测试的定位假设已经失效")
	}
	if iManifest > iCheck || iEntry > iCheck {
		t.Error("清单预检跑到了 sha256sum -c 后面 —— -c 会先失败先 die,预检等于没有")
	}

	// 区间写法({64})在老 mawk 上不认。真踩上的后果不是漏判而是全线中断:
	// 每一份正常清单都被判成「不是清单」,谁都装不上。
	if strings.Contains(body, "[0-9a-fA-F]{64}") {
		t.Error("清单格式判断用了 {64} 区间写法 —— 老 mawk 不认,会把每一份正常清单都判成非法;" +
			"用 length($1) == 64 代替")
	}
}
