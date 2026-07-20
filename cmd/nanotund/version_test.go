package main

import (
	"strings"
	"testing"
)

// TestMergeFallbackVersion: 覆盖 fallback 的三条路径 ——
//  1. ldflags 全注入: 不动;
//  2. 无注入 + 有 vcs : 三者都被回填,且 serverVersion = dev-<sha>;
//  3. 无注入 + 无 vcs : 仅 serverVersion 落到 "dev",其它保持 "unknown"。
//
// 还测 dirty 后缀和 git_sha 单独有效的边界。
func TestMergeFallbackVersion(t *testing.T) {
	cases := []struct {
		name                   string
		inV, inSHA, inTS       string
		bi                     buildInfoSummary
		wantV, wantSHA, wantTS string
		wantVContains          string // 非空时做 substring 检查
	}{
		{
			name: "ldflags 已注入,buildInfo 不应覆盖",
			inV:  "v1.2.3", inSHA: "abc1234", inTS: "2026-05-23T10:00:00Z",
			bi:    buildInfoSummary{gitSHA: "ffffff0", vcsTime: "1999-01-01T00:00:00Z", dirty: true},
			wantV: "v1.2.3", wantSHA: "abc1234", wantTS: "2026-05-23T10:00:00Z",
		},
		{
			name: "无注入 + vcs 有信息: 全回填,版本=dev-<sha>",
			inV:  "unknown", inSHA: "unknown", inTS: "unknown",
			bi:    buildInfoSummary{gitSHA: "deadbee", vcsTime: "2026-05-23T12:00:00Z"},
			wantV: "dev-deadbee", wantSHA: "deadbee", wantTS: "2026-05-23T12:00:00Z",
		},
		{
			name: "无注入 + vcs dirty: 版本带 -dirty 后缀",
			inV:  "unknown", inSHA: "unknown", inTS: "unknown",
			bi:    buildInfoSummary{gitSHA: "cafe123", vcsTime: "2026-05-23T12:00:00Z", dirty: true},
			wantV: "dev-cafe123-dirty", wantSHA: "cafe123", wantTS: "2026-05-23T12:00:00Z",
			wantVContains: "dirty",
		},
		{
			name: "无注入 + 完全无 vcs: 版本=dev, sha/ts 保持 unknown",
			inV:  "unknown", inSHA: "unknown", inTS: "unknown",
			bi:    buildInfoSummary{},
			wantV: "dev", wantSHA: "unknown", wantTS: "unknown",
		},
		{
			name: "无注入 + 只有 dirty(无 sha,理论上 git 不会这样): 仍生成 dev-dirty",
			inV:  "unknown", inSHA: "unknown", inTS: "unknown",
			bi:    buildInfoSummary{dirty: true},
			wantV: "dev-dirty", wantSHA: "unknown", wantTS: "unknown",
		},
		{
			name: "ldflags 部分注入(只有 version): sha/ts 仍可被 buildInfo 回填",
			inV:  "v9.9.9", inSHA: "unknown", inTS: "unknown",
			bi:    buildInfoSummary{gitSHA: "1234567", vcsTime: "2026-05-23T13:00:00Z"},
			wantV: "v9.9.9", wantSHA: "1234567", wantTS: "2026-05-23T13:00:00Z",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotV, gotSHA, gotTS := mergeFallbackVersion(tc.inV, tc.inSHA, tc.inTS, tc.bi)
			if gotV != tc.wantV {
				t.Errorf("version: 期望 %q, 实际 %q", tc.wantV, gotV)
			}
			if gotSHA != tc.wantSHA {
				t.Errorf("sha: 期望 %q, 实际 %q", tc.wantSHA, gotSHA)
			}
			if gotTS != tc.wantTS {
				t.Errorf("ts: 期望 %q, 实际 %q", tc.wantTS, gotTS)
			}
			if tc.wantVContains != "" && !strings.Contains(gotV, tc.wantVContains) {
				t.Errorf("version %q 应包含 %q", gotV, tc.wantVContains)
			}
		})
	}
}

// TestBuildInfoShortSHA: vcs.revision 长 hash 必须被截到 7 字符,避免 dashboard 太长。
// 真实 buildInfo() 在 `go test` 下一般取不到 vcs.revision(test binary 不嵌 vcs);
// 若取到了,验证它满足 ≤7 字符即可,取不到就跳过。
func TestBuildInfoShortSHA(t *testing.T) {
	info, ok := buildInfo()
	if !ok || info.gitSHA == "" {
		t.Skip("test binary 未嵌 vcs.revision,跳过")
	}
	if len(info.gitSHA) > 7 {
		t.Errorf("gitSHA 期望 ≤7 字符,实际 %q(len=%d)", info.gitSHA, len(info.gitSHA))
	}
}
