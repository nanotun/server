package main

import (
	"os"
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

// TestFormatVersion: `nanotund --version` 的第一行必须是 "nanotund <版本>"。
//
// 钉住第一行是因为它是被解析的那一行:scripts/uninstall.sh 用 `| head -1` 取它来显示
// 「找到已安装的服务端」。往第一行加东西(git SHA、构建时间之类)不会有任何测试变红,
// 但会让那些取法拿到一串多余内容 —— 与 nanotun-admin / nanotun-web 的输出格式也就散了。
func TestFormatVersion(t *testing.T) {
	origV, origSHA, origTS := serverVersion, serverGitSHA, serverBuildTime
	t.Cleanup(func() { serverVersion, serverGitSHA, serverBuildTime = origV, origSHA, origTS })
	serverVersion, serverGitSHA, serverBuildTime = "v9.9.9", "abc1234", "2026-08-04T00:00:00Z"

	lines := strings.Split(formatVersion(), "\n")
	if lines[0] != "nanotund v9.9.9" {
		t.Errorf("第一行期望 %q, 实际 %q", "nanotund v9.9.9", lines[0])
	}
	// 另外两行是排查「跑的是哪次构建」时唯一的线索,掉了不该悄无声息。
	rest := strings.Join(lines[1:], "\n")
	for _, want := range []string{"abc1234", "2026-08-04T00:00:00Z"} {
		if !strings.Contains(rest, want) {
			t.Errorf("输出缺 %q:\n%s", want, formatVersion())
		}
	}
}

// TestClientOwnsTUN: 只有「客户端声称在用 + 网卡确实存在」两条都成立才算撞上。
//
// 两个方向都要钉住:
//   - 漏判(该拦没拦)= 服务端启动时删掉客户端的网卡,客户端从此每逢服务端重启就断线,
//     且那头看不出是谁干的;
//   - 误判(不该拦却拦了)= 客户端早就卸干净、只剩个残留的 tun_name 文件,却让一台
//     本可以正常起的服务端起不来。后者正是这里要查网卡是否真实存在的原因。
func TestClientOwnsTUN(t *testing.T) {
	const clientTUN = "nanotun0"
	stateOK := func() (string, error) { return clientTUN + "\n", nil } // 客户端写的带换行
	stateMissing := func() (string, error) { return "", os.ErrNotExist }
	exists := func(string) bool { return true }
	absent := func(string) bool { return false }

	cases := []struct {
		name        string
		deviceName  string
		readState   func() (string, error)
		ifaceExists func(string) bool
		want        bool
	}{
		{"配成客户端那块 + 网卡在 → 拦", clientTUN, stateOK, exists, true},
		{"默认 tun0,与客户端不撞 → 放行", "tun0", stateOK, exists, false},
		{"没有客户端(读不到状态文件)→ 放行", clientTUN, stateMissing, exists, false},
		{"状态文件是残留、网卡其实不在 → 放行", clientTUN, stateOK, absent, false},
		{"device_name 为空 → 放行(上游会回退到 tun0)", "", stateOK, exists, false},
		{"两边都带空白也应判等", "  " + clientTUN + "  ", stateOK, exists, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := clientOwnsTUN(tc.deviceName, tc.readState, tc.ifaceExists); got != tc.want {
				t.Errorf("clientOwnsTUN(%q) = %v, 期望 %v", tc.deviceName, got, tc.want)
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
