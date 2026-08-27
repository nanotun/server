package main

// install_version_hint_guard_test.go —— 钉了一个不存在的版本时,第一条报错就得说对原因。
//
// 起因:NANOTUN_VERSION=v0.1.99(敲错版本号、或猜一个还没发的号)时,install.sh 取
// preflight.sh 拿到 404,而它一律解释成「该版本的 tag 上可能没有这个文件」,并建议
// NANOTUN_BRANCH=main 或 --skip-check。两条建议在「版本压根不存在」时都不可能奏效:
// 照着走会顺利跑完一整屏环境检查,打出「✓ 版本: v0.1.99」和「✓ 这台机器可以装 nanotun」,
// 二十秒后才在下载发布包时撞上真正的原因 —— 中间每一步都在替那个不存在的版本背书。
//
// 修法是失败时多探一次同 ref 下的 install.sh(任何真实 tag 上都有它),用状态码把
// 「ref 不存在(404)」「ref 在但缺文件(200)」「根本没连上(000)」分开。这个测试盯的是
// 这四条岔路一条都不能少 —— 少哪条,哪条对应的人就会被支去查一件跟他无关的事。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstall_VersionNotFoundHintIsDistinct(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("../..", "scripts/install.sh"))
	if err != nil {
		t.Fatalf("读 install.sh: %v", err)
	}
	body := string(raw)

	// 探针本身:没有它就无从分辨,只能退回「一律按老 tag 解释」那种猜法。
	if !strings.Contains(body, `dl_file_code "$RAW_BASE/install.sh"`) {
		t.Error("preflight.sh 取不到时没有再探一次同 ref 下的 install.sh —— " +
			"少了这一次探测,就分不出「版本不存在」和「tag 在但缺文件」,而两者的下一步是相反的")
	}

	for _, c := range []struct{ needle, why string }{
		{"这个版本不存在", "404:该 ref 下连 install.sh 都没有,就是版本号错了,得直说"},
		{"不设时脚本会自己解析 latest", "404:要告诉人怎么装最新版,否则他只能继续猜版本号"},
		{"但它里面没有 scripts/preflight.sh", "200:tag 确实在、只是缺文件,这才是 NANOTUN_BRANCH=main 管用的那种"},
		{"一个 HTTP 响应都没拿到", "000:网络断了,第一句就该说网络 —— 支人去核对版本号是浪费时间"},
		{"多半是限流", "其它状态码:429/403/5xx 该建议等一会儿重试,而不是改版本号"},
		{"自定义 NANOTUN_RAW_BASE(镜像)", "指了镜像时不能断言版本不存在:镜像缺 tag / 路径形状不对同样是 404"},
	} {
		if !strings.Contains(body, c.needle) {
			t.Errorf("install.sh 里找不到 %q —— %s", c.needle, c.why)
		}
	}

	// 内部哨兵值糊到用户脸上过一次(文案里冒出「探 install.sh 得到 mirror」),
	// 起因是拿 code=mirror 混进按状态码分岔的 case。镜像那支必须自己独立。
	if strings.Contains(body, "code=mirror") {
		t.Error("镜像那支又在往状态码变量里塞哨兵值 —— " +
			"它会顺着「探 install.sh 得到 ${code}」打进用户看到的文案里")
	}
}
