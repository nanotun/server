package main

// wizard_validation_guard_test.go —— 向导里两处「查了却不作数」的地方。
//
// 一、拨号地址探测失败之后
//     -y 下 DNS 探测不过是降级为告警继续的,这本身对(域名常常装完才解析过来)。可那句
//     告警出现在第 1 步,后面还有三四十行绿字,最后一屏摘要里那行
//     `Web 后台 https://<地址>:7443` 与一切正常时一模一样。于是域名敲错的人拿到的是
//     一台装得漂漂亮亮、而所有客户端配置和二维码都指向一个解析不到的名字的机器,
//     要等客户端连不上才回头找原因。修法:记住这次探测没过,收尾再说一遍。
//
//     更阴的是重跑那条路:地址与库里一致时原来一个字都不查,直接「✓ 保持不变」——
//     而重跑向导加用户是常规操作,于是第一次填错的地址从第二次起就被绿勾背书了。
//     修法:值没变也查一次 DNS(-skip-icmp,几十毫秒),查不过就不打勾。
//
// 二、MagicDNS 后缀
//     禁用 local 的理由是 mac/iOS 与 Avahi 把整个 .local 交给 mDNS 组播,可判据是精确
//     匹配,于是 lan.local / home.local 一路绿灯 —— 而想避开 lan 的人正好会写 lan.local,
//     等于从一个坑跳进更深的一个。另外正则只管字符集不管长度,80 字符的单标签也能过,
//     而 DNS 标签上限是 63:改是改成功了,客户端谁都解析不动。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetup_DialHostProbeFailureSurvivesToSummary(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("../..", "scripts/setup.sh"))
	if err != nil {
		t.Fatalf("读 setup.sh: %v", err)
	}
	body := string(raw)

	if !strings.Contains(body, "DIAL_PROBE_FAILED=1") {
		t.Error("探测失败没有被记下来 —— 那句警告会被后面几十行绿字刷走,而它决定的是客户端能不能连上")
	}
	if !strings.Contains(body, "上面生成的客户端配置和二维码全都指向它") {
		t.Error("收尾没有重申拨号地址不可达 —— 摘要里那行 Web 后台 URL 看着与一切正常时一模一样")
	}
	// 值没变那条路必须也查一次,否则填错的地址从第二次起就被绿勾背书。
	if !strings.Contains(body, `probe-dial-host -skip-icmp "$dial_host"`) {
		t.Error("「保持不变」那条路没有核实 DNS —— 打勾就得是真查过;" +
			"只查 DNS 不 ping(-skip-icmp),ICMP 在云上常年不通,拿它当判据只会天天误报")
	}

	// 收尾只对硬失败(DNS/语法)重申。ICMP 不通是云上的常态,再提一遍只会稀释真正要紧的那条。
	if !strings.Contains(body, `"${DIAL_PROBE_KIND:-}" = hard`) {
		t.Error("收尾没有区分硬失败和 ICMP 软失败 —— 对每台云主机都喊一遍等于没喊")
	}
}

func TestSetSuffix_RejectsDotLocalAndOverlongLabels(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("../..", "scripts/set-magic-suffix.sh"))
	if err != nil {
		t.Fatalf("读 set-magic-suffix.sh: %v", err)
	}
	body := string(raw)

	if !strings.Contains(body, "local|*.local)") {
		t.Error("只拦了 local 本身,没拦 .local 下的子域 —— lan.local / home.local 会一路绿灯装完," +
			"而它们在 mac/iOS 上永远解析不到(整个 .local 归 mDNS 组播)")
	}
	if !strings.Contains(body, "length($i) > 63") {
		t.Error("没有标签长度检查 —— 正则只管字符集,80 字符的单标签照样过," +
			"而 DNS 标签上限是 63:改成功了,客户端却谁都解析不动")
	}
}
