package main

import (
	"regexp"
	"testing"
)

// verbRe 匹配 fmt 占位符(%d %s %q %v %x ... 以及 %[1]d 等带索引形式)。
// 与 nanotun-web 的 parity 测试同款,用于校验双语文案的参数数量一致。
var verbRe = regexp.MustCompile(`%[#+\-0-9.\[\]*]*[a-zA-Z%]`)

func countVerbs(s string) int {
	n := 0
	for _, m := range verbRe.FindAllString(s, -1) {
		if m == "%%" {
			continue
		}
		n++
	}
	return n
}

// TestCatalogParity 保证 catEN / catZH:
//   - key 集合完全一致(任一语言缺 key 会导致运行时回落,UI 漏翻);
//   - 每个 key 的 fmt 占位符数量一致(避免 Sprintf 参数错位)。
func TestCatalogParity(t *testing.T) {
	for k := range catEN {
		if _, ok := catZH[k]; !ok {
			t.Errorf("key %q in catEN but missing in catZH", k)
		}
	}
	for k := range catZH {
		if _, ok := catEN[k]; !ok {
			t.Errorf("key %q in catZH but missing in catEN", k)
		}
	}
	for k, en := range catEN {
		zh, ok := catZH[k]
		if !ok {
			continue
		}
		if ve, vz := countVerbs(en), countVerbs(zh); ve != vz {
			t.Errorf("key %q verb count mismatch: en=%d (%q) zh=%d (%q)", k, ve, en, vz, zh)
		}
	}
}
