package main

import (
	"testing"
)

// C6_full 单测:parseJumpHostProtectedPorts 各种合法 + 非法输入。
func TestParseJumpHostProtectedPorts(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []jumpHostPortSpec
	}{
		{
			"single tcp",
			[]string{"tcp/8080"},
			[]jumpHostPortSpec{{Proto: "tcp", Port: 8080}},
		},
		{
			"single udp + range with dash",
			[]string{"udp/443", "udp/5000-5002"},
			[]jumpHostPortSpec{
				{Proto: "udp", Port: 443},
				{Proto: "udp", Port: 5000, EndPort: 5002},
			},
		},
		{
			"range with colon",
			[]string{"tcp/9000:9002"},
			[]jumpHostPortSpec{{Proto: "tcp", Port: 9000, EndPort: 9002}},
		},
		{
			"case insensitive proto",
			[]string{"TCP/8443"},
			[]jumpHostPortSpec{{Proto: "tcp", Port: 8443}},
		},
		{
			"skip invalid entries",
			[]string{"", "  ", "foo/80", "tcp/", "/8080", "tcp/0", "tcp/65536", "tcp/notanumber", "tcp/8080"},
			[]jumpHostPortSpec{{Proto: "tcp", Port: 8080}},
		},
		{
			"end-before-start kept literally - parser leaves order, constructor normalizes",
			[]string{"tcp/9000-8000"},
			[]jumpHostPortSpec{{Proto: "tcp", Port: 9000, EndPort: 8000}},
		},
		{
			"empty input → nil",
			nil,
			nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseJumpHostProtectedPorts(c.in)
			if len(got) != len(c.want) {
				t.Fatalf("len got=%d want=%d (got=%+v)", len(got), len(c.want), got)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("[%d] got=%+v want=%+v", i, got[i], c.want[i])
				}
			}
		})
	}
}

// C6_full 单测:newJumpHostFirewallWithSpecs 过滤掉非法 spec,EndPort<Port 自动 swap。
func TestNewJumpHostFirewallWithSpecs_Sanitizes(t *testing.T) {
	specs := []jumpHostPortSpec{
		{Proto: "tcp", Port: 8080},                  // 合法
		{Proto: "udp", Port: 5000, EndPort: 4999},   // EndPort<Port → swap
		{Proto: "icmp", Port: 80},                   // 非 tcp/udp → 丢
		{Proto: "tcp", Port: 0},                     // 端口 0 → 丢
		{Proto: "tcp", Port: 70000},                 // 端口超界 → 丢
		{Proto: "tcp", Port: 5000, EndPort: -1},     // EndPort 负 → 丢
		{Proto: "tcp", Port: 9000, EndPort: 100000}, // EndPort 超界 → 丢
	}
	f := newJumpHostFirewallWithSpecs(false, specs)
	if len(f.protectedPorts) != 2 {
		t.Fatalf("应只剩 2 个合法 spec,got %d: %+v", len(f.protectedPorts), f.protectedPorts)
	}
	if f.protectedPorts[0] != (jumpHostPortSpec{Proto: "tcp", Port: 8080}) {
		t.Errorf("[0] got %+v", f.protectedPorts[0])
	}
	// EndPort<Port 自动 swap:Port=4999, EndPort=5000
	if f.protectedPorts[1] != (jumpHostPortSpec{Proto: "udp", Port: 4999, EndPort: 5000}) {
		t.Errorf("[1] expected swapped to 4999-5000,got %+v", f.protectedPorts[1])
	}
}

// C6_full 单测:inputJumpRuleArgsFor 单端口 vs 端口段。
func TestInputJumpRuleArgsFor(t *testing.T) {
	f := newJumpHostFirewallWithSpecs(true, []jumpHostPortSpec{
		{Proto: "tcp", Port: 8080},
		{Proto: "udp", Port: 5000, EndPort: 5002},
	})

	single := f.inputJumpRuleArgsFor(f.protectedPorts[0])
	if got, want := single[1], "tcp"; got != want {
		t.Errorf("proto: got %q want %q", got, want)
	}
	if got, want := single[3], "8080"; got != want {
		t.Errorf("--dport: got %q want %q", got, want)
	}

	rng := f.inputJumpRuleArgsFor(f.protectedPorts[1])
	if got, want := rng[1], "udp"; got != want {
		t.Errorf("proto: got %q want %q", got, want)
	}
	if got, want := rng[3], "5000:5002"; got != want {
		t.Errorf("--dport range: got %q want %q", got, want)
	}
}

// C6_full 单测:describePortSpecs 日志友好格式。
func TestDescribePortSpecs(t *testing.T) {
	got := describePortSpecs([]jumpHostPortSpec{
		{Proto: "tcp", Port: 8080},
		{Proto: "tcp", Port: 8443},
		{Proto: "udp", Port: 443},
		{Proto: "udp", Port: 5000, EndPort: 5002},
	})
	want := "tcp/8080,tcp/8443,udp/443,udp/5000:5002"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
