package main

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// store.* 这组文案在 CLI 和 Web 各存了一份,值必须逐字相同。
//
// 它们翻译的是**同一批** store 层校验错误(store.LocalizedError 的 LocaleKey),
// 而两个 main 包各自维护一张表。catalog_en.go 的头注释写着「值与 nanotun-web 的 catEN
// 保持一致」,但在这条守卫之前没有任何东西在执行那句话 —— 这一整天里同样形状的问题
// (「两边必须同步」只写在注释里)已经踩到过好几次。
//
// 漂了的后果不响也不崩:同一个输入,`nanotun-admin` 说一句、网页上说另一句。用户照着
// CLI 的提示去改,网页却给出不同的措辞和不同的修复建议,而两边都"看起来正常"。
//
// 只比 store.* 前缀:其余 key 是各自 UI 的文案(CLI 有命令行专属的,Web 有页面专属的),
// 本来就不该相同。
func TestStoreCatalogsMatchAcrossPackages(t *testing.T) {
	entry := regexp.MustCompile(`"(store\.[A-Za-z0-9_.]+)":\s*"((?:[^"\\]|\\.)*)"`)

	load := func(rel string) map[string]string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join("..", "..", rel))
		if err != nil {
			t.Fatalf("读不到 %s:%v", rel, err)
		}
		out := map[string]string{}
		for _, m := range entry.FindAllStringSubmatch(string(b), -1) {
			out[m[1]] = m[2]
		}
		if len(out) == 0 {
			t.Fatalf("%s 里一个 store.* key 都没解析出来 —— 若表的写法改了,请同步本守卫", rel)
		}
		return out
	}

	for _, c := range []struct{ lang, cli, web string }{
		{"en", "cmd/nanotun-admin/catalog_en.go", "cmd/nanotun-web/i18n_en.go"},
		{"zh", "cmd/nanotun-admin/catalog_zh.go", "cmd/nanotun-web/i18n_zh.go"},
	} {
		cli, web := load(c.cli), load(c.web)

		for k, v := range cli {
			wv, ok := web[k]
			if !ok {
				t.Errorf("[%s] %s 有 %q,而 %s 没有 —— 同一个 store 错误在网页上会退回 key 本身或另一种说法",
					c.lang, c.cli, k, c.web)
				continue
			}
			if wv != v {
				t.Errorf("[%s] %q 两边说法不同:\n  CLI: %s\n  Web: %s\n"+
					"  同一个输入,命令行和网页给出不同措辞(往往连修复建议都不同),而两边都看着正常。",
					c.lang, k, v, wv)
			}
		}
		for k := range web {
			if _, ok := cli[k]; !ok {
				t.Errorf("[%s] %s 有 %q,而 %s 没有", c.lang, c.web, k, c.cli)
			}
		}
	}
}
