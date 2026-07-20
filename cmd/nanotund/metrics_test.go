package main

import (
	"bytes"
	"strings"
	"testing"
)

// J3:Prometheus 文本格式契约测试。
//
//   - 每个 metric 前必须有 # HELP / # TYPE 行(否则 prometheus scrape 会 reject);
//   - metric 名以 nanotun_ 开头(命名空间);
//   - counter 必须以 _total 结尾,gauge 不需要(prometheus 习惯);
//   - 至少有几个关键 metric 名;
//   - 不应 panic / 不应输出乱码字符。
func TestWritePrometheusMetrics_Format(t *testing.T) {
	// metrics 路径 gw==nil 时会触发 lazyPoWService() 把 fallback 实例化。
	// 测试结束清掉,避免污染后续测试的 ipFailures 累积。
	t.Cleanup(resetLazyPoWForTest)

	var buf bytes.Buffer
	writePrometheusMetrics(&buf, nil)
	out := buf.String()
	if out == "" {
		t.Fatal("metrics 输出为空")
	}

	// 关键 metric 必须存在。
	for _, name := range []string{
		"nanotun_build_info",
		"nanotun_uptime_seconds",
		"nanotun_tun_ready",
		"nanotun_active_sessions",
		"nanotun_acl_drops_total",
		"nanotun_lease_gc_total",
		"nanotun_user_invalidate_kicks_total",
		"nanotun_session_supersede_total",
		"nanotun_magic_dns_queries_total",
		"nanotun_magic_dns_inflight_drops_total",
		"nanotun_route_adv_total",
		// exit-node:出口选择(控制面)+ 转发(数据面)计数 + 字节计量。
		"nanotun_egress_select_total",
		"nanotun_exit_forward_total",
		"nanotun_exit_forward_bytes_total",
		"nanotun_login_ratelimit_entries",
		"nanotun_login_ratelimit_cap_exceeded_total",
		// V1(2026-05-26):VPN 业务字节计数(direction="up"/"down" 两条 line)。
		"nanotun_bytes_total",
		// P1-2(2026-05-24):PoW 防护监控。
		"nanotun_pow_challenges_issued_total",
		"nanotun_pow_verify_success_total",
		"nanotun_pow_verify_failed_total",
		"nanotun_pow_used_table_size",
		"nanotun_pow_ip_failures_tracked",
		"nanotun_pow_ratelimit_entries",
		"nanotun_pow_ratelimit_cap_exceeded_total",
		"nanotun_pow_global_limited_total",
	} {
		if !strings.Contains(out, name) {
			t.Errorf("缺少 metric %q", name)
		}
	}

	// 每个 metric 名都应当有配套的 # HELP / # TYPE 行。
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "nanotun_") {
			name := strings.Fields(line)[0]
			// 取掉 label 部分:metric{a="b"} → metric
			if i := strings.Index(name, "{"); i >= 0 {
				name = name[:i]
			}
			if !strings.Contains(out, "# HELP "+name+" ") {
				t.Errorf("metric %q 缺 # HELP", name)
			}
			if !strings.Contains(out, "# TYPE "+name+" ") {
				t.Errorf("metric %q 缺 # TYPE", name)
			}
		}
	}

	// counter 必须以 _total 结尾(prometheus 约定)。
	// 这里只检查 TYPE 行声明为 counter 的名字。
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "# TYPE ") && strings.HasSuffix(line, " counter") {
			parts := strings.Fields(line)
			if len(parts) != 4 {
				continue
			}
			name := parts[2]
			if !strings.HasSuffix(name, "_total") {
				t.Errorf("counter %q 应以 _total 结尾(prometheus 命名约定)", name)
			}
		}
	}
}
