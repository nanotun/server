package main

// deploy_srv_guard_test.go —— e2e 的 SRV 上装的那套命令,必须和真实装机装的一致。
//
// scripts/e2e/deploy-srv.sh 把本地 HEAD 热替到测试服,而它的安装清单是**手工维护**的。
// 漏一个不会有任何提示:门禁照样跑,照样全绿 —— 只是绿的那台机器和用户真实装出来的机器
// 不是同一个形状。deploy-srv.sh 自己的注释早就写着这件事(tun-setup.sh 曾这么漏了很久),
// 但注释拦不住下一次。
//
// 2026-08-28 又漏了三个,而且其中一个正好落在最难看出来的地方:
//
//   · nanotun-ports.sh —— preflight.sh 与 uninstall.sh 都 source 它来读**实际**端口。
//     文件不在时两者静默回落到写死的 8443/443/7443。于是门禁里跑的是兜底分支,而
//     「改过端口的机器」那条真路径从来没被执行过 —— 偏偏那正是 nanotun-ports.sh
//     被造出来要解决的问题(见该文件头部记录的三种错法)。
//   · nanotun-set-suffix / nanotun-uninstall —— 真实装机会装成命令,SRV 上却没有。
//     想在门禁里按装好的名字敲它们,只能自己先推一份上去(magic-suffix-drill.sh 就是
//     这么做的),而「装机到底有没有把它装上」这件事在三机环境里等于没被覆盖。
//
// 所以把「两份清单一致」变成一条断言。判据取 install-self-hosted.sh —— 它是真实装机,
// 是这件事的真源;deploy-srv.sh 只是要长得像它。

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// 从脚本里抠出所有被装到 /usr/local/bin 下的命令名。
//
// 只认 `install ... /usr/local/bin/<名字>` 这种形状:两个脚本都用 install(1) 落盘,
// 而 install 的最后一个参数就是落点。
func installedCommands(t *testing.T, rel string) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("../..", rel))
	if err != nil {
		t.Fatalf("读 %s: %v", rel, err)
	}
	reNamed := regexp.MustCompile(`/usr/local/bin/([A-Za-z0-9._-]+)`)
	// 落点是**目录**的那种:`install a b c /usr/local/bin/`,装出来的名字是各源文件的
	// basename。deploy-srv.sh 的三个二进制就是这么一条带走的,少了这一支会把它们误报成缺失。
	reDir := regexp.MustCompile(`install\s+(.*?)\s+/usr/local/bin/?\s*$`)
	reSrc := regexp.MustCompile(`([A-Za-z0-9._-]+)"?\s*$`)
	out := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		s := strings.TrimSpace(line)
		// 注释里也会提到这些路径(解释为什么装、装成什么名),那不算「真的装了」。
		if strings.HasPrefix(s, "#") || !strings.Contains(s, "install ") {
			continue
		}
		if m := reDir.FindStringSubmatch(s); m != nil {
			for _, tok := range strings.Fields(m[1]) {
				if strings.HasPrefix(tok, "-") { // -m 0755 之类
					continue
				}
				if sm := reSrc.FindStringSubmatch(tok); sm != nil {
					out[sm[1]] = true
				}
			}
			continue
		}
		for _, m := range reNamed.FindAllStringSubmatch(s, -1) {
			out[m[1]] = true
		}
	}
	if len(out) == 0 {
		t.Fatalf("%s 里没解析出任何 /usr/local/bin 落点 —— 本测试的解析口径该跟着脚本改了", rel)
	}
	return out
}

func TestDeploySRV_InstallsWhatARealInstallInstalls(t *testing.T) {
	real := installedCommands(t, "scripts/install-self-hosted.sh")
	lab := installedCommands(t, "scripts/e2e/deploy-srv.sh")

	// 三个二进制由 deploy-srv 一条 install 带走,与真实装机一致,不必单列。
	var missing []string
	for name := range real {
		if !lab[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("deploy-srv.sh 没装这些,而真实装机会装:%v\n"+
			"  后果不是报错,是**静默地测了另一台机器**:门禁跑在一台缺了这些命令的 SRV 上,\n"+
			"  照样全绿。source 类的(nanotun-ports.sh)更隐蔽 —— 调用方会回落到写死的默认值,\n"+
			"  于是那条真路径在三机环境里从来没被执行过。\n"+
			"  在 scripts/e2e/deploy-srv.sh 的 install 清单里补上,或说明为什么 SRV 不需要它。",
			missing)
	}
}
