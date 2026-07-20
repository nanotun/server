package main

import (
	"reflect"
	"strings"
	"testing"
)

// S7(2026-05-26):R6 加 --limit / --offset flag,R3 后续支持 --flag=VALUE 等价语法。
// 没回归测试容易在下次重构里 silently 破坏 unix CLI 习惯,本文件 table-driven 覆盖
// parseLimitOffsetArgs / buildStatusPath 的边界。

func TestParseLimitOffsetArgs(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantLimit  int
		wantOffset int
		wantRest   []string
		wantErrSub string // 非空则期望 err 含此子串
	}{
		// 基础:不传任何 flag → 全 0。
		{
			name:       "no flags",
			args:       []string{},
			wantLimit:  0,
			wantOffset: 0,
			wantRest:   []string{},
		},
		// 双 token 写法(原 R6 风格)。
		{
			name:       "two-token limit",
			args:       []string{"--limit", "10"},
			wantLimit:  10,
			wantOffset: 0,
			wantRest:   []string{},
		},
		{
			name:       "two-token both",
			args:       []string{"--limit", "10", "--offset", "20"},
			wantLimit:  10,
			wantOffset: 20,
			wantRest:   []string{},
		},
		// S3 加的 --flag=VALUE 单 token 写法。
		{
			name:       "eq-form limit",
			args:       []string{"--limit=10"},
			wantLimit:  10,
			wantOffset: 0,
			wantRest:   []string{},
		},
		{
			name:       "eq-form both",
			args:       []string{"--limit=10", "--offset=20"},
			wantLimit:  10,
			wantOffset: 20,
			wantRest:   []string{},
		},
		// 混合:两种风格可以一起用。
		{
			name:       "mixed two-token + eq",
			args:       []string{"--limit", "5", "--offset=15"},
			wantLimit:  5,
			wantOffset: 15,
			wantRest:   []string{},
		},
		// rest:非 flag args 透传。
		{
			name:       "rest passthrough",
			args:       []string{"sub", "--limit", "3", "more"},
			wantLimit:  3,
			wantOffset: 0,
			wantRest:   []string{"sub", "more"},
		},
		{
			name:       "rest with eq form",
			args:       []string{"--limit=3", "sub"},
			wantLimit:  3,
			wantOffset: 0,
			wantRest:   []string{"sub"},
		},
		// 错误:非数字。
		{
			name:       "non-numeric limit",
			args:       []string{"--limit", "abc"},
			wantErrSub: "--limit must be a non-negative integer",
		},
		{
			name:       "non-numeric limit eq",
			args:       []string{"--limit=abc"},
			wantErrSub: "--limit must be a non-negative integer",
		},
		{
			name:       "non-numeric offset",
			args:       []string{"--offset", "xyz"},
			wantErrSub: "--offset must be a non-negative integer",
		},
		// 错误:负数。
		{
			name:       "negative limit",
			args:       []string{"--limit", "-1"},
			wantErrSub: "--limit must be a non-negative integer",
		},
		// 错误:缺参数。
		{
			name:       "limit missing arg",
			args:       []string{"--limit"},
			wantErrSub: "--limit needs an argument",
		},
		{
			name:       "offset missing arg",
			args:       []string{"--offset"},
			wantErrSub: "--offset needs an argument",
		},
		// 0 是合法的(server 会按全量处理 / 显式不传)。
		{
			name:       "zero limit ok",
			args:       []string{"--limit", "0"},
			wantLimit:  0,
			wantOffset: 0,
			wantRest:   []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limit, offset, rest, err := parseLimitOffsetArgs(tt.args)
			if tt.wantErrSub != "" {
				if err == nil {
					t.Fatalf("want err containing %q, got nil", tt.wantErrSub)
				}
				if !strings.Contains(err.Error(), tt.wantErrSub) {
					t.Errorf("err = %q, want substring %q", err.Error(), tt.wantErrSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if limit != tt.wantLimit {
				t.Errorf("limit = %d, want %d", limit, tt.wantLimit)
			}
			if offset != tt.wantOffset {
				t.Errorf("offset = %d, want %d", offset, tt.wantOffset)
			}
			if !reflect.DeepEqual(rest, tt.wantRest) {
				t.Errorf("rest = %v, want %v", rest, tt.wantRest)
			}
		})
	}
}

// TestBuildStatusPath:验证 limit / offset 各种组合生成的 /status 路径。
// 覆盖 R6+Q2:offset > 0 但 limit == 0 时 server 会 400,helper 仍 honor 调用方传入,
// 让 server 透传错误 — 这是「显式失败优于客户端臆测」的 Q2 设计原则。
func TestBuildStatusPath(t *testing.T) {
	tests := []struct {
		name   string
		limit  int
		offset int
		want   string
	}{
		{"both zero (no args)", 0, 0, "/status"},
		{"limit only", 10, 0, "/status?limit=10"},
		{"both", 10, 20, "/status?limit=10&offset=20"},
		{"offset only (server will 400, helper still honors)", 0, 5, "/status?offset=5"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildStatusPath(tt.limit, tt.offset)
			if got != tt.want {
				t.Errorf("buildStatusPath(%d, %d) = %q, want %q", tt.limit, tt.offset, got, tt.want)
			}
		})
	}
}
