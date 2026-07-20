package main

import (
	"sort"
	"testing"
)

// #6：parseStalePortForwardPorts 必须兼容 iptables -S 对 comment 的两种渲染（带引号 / 不带引号），
// 只取带本特性 comment 的 -A ACCEPT 规则的 --dport，忽略他人规则与非 -A 行，并去重。
func TestParseStalePortForwardPorts(t *testing.T) {
	dump := `-P INPUT DROP
-N ufw-before-input
-A INPUT -p tcp -m tcp --dport 2222 -m comment --comment nanotun_pf -j ACCEPT
-A INPUT -p tcp -m tcp --dport 8443 -m comment --comment "nanotun_pf" -j ACCEPT
-A INPUT -p tcp -m tcp --dport 80 -m comment --comment "some_other_rule" -j ACCEPT
-A INPUT -p tcp -m tcp --dport 53 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 2222 -m comment --comment nanotun_pf -j ACCEPT
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT`

	got := parseStalePortForwardPorts(dump)
	sort.Ints(got)
	want := []int{2222, 8443} // 不含他人 comment(80) / 无 comment(53)；2222 去重
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

// lineHasPortForwardComment：带引号 / 不带引号都应命中；他人 comment 不命中。
func TestLineHasPortForwardComment(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{`-A INPUT -p tcp --dport 2222 -m comment --comment nanotun_pf -j ACCEPT`, true},
		{`-A INPUT -p tcp --dport 8443 -m comment --comment "nanotun_pf" -j ACCEPT`, true},
		{`-A INPUT -p tcp --dport 80 -m comment --comment nanotun_pfx -j ACCEPT`, false}, // 前缀相同但非本 comment
		{`-A INPUT -p tcp --dport 80 -m comment --comment "other" -j ACCEPT`, false},
		{`-A INPUT -p tcp --dport 53 -j ACCEPT`, false},
	}
	for _, c := range cases {
		if got := lineHasPortForwardComment(c.line); got != c.want {
			t.Fatalf("lineHasPortForwardComment(%q) = %v, want %v", c.line, got, c.want)
		}
	}
}
