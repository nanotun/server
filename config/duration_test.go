package config

import (
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"
)

// TestDuration_UnmarshalText 覆盖 config.Duration 的三种合法输入和典型错误形态。
//
// 这个测试存在的原因是 P0 现场事故的修复:pelletier/go-toml/v2 直接反序列化
// time.Duration 时拒绝 "30s" 字符串,导致一次部署后整个 nanotun 进程退不出
// Config 解析,业务中断。这里用单测把契约钉住,避免下次回归。
func TestDuration_UnmarshalText(t *testing.T) {
	type holder struct {
		D Duration `toml:"d"`
	}

	cases := []struct {
		name    string
		in      string
		want    time.Duration
		wantErr bool
	}{
		{"string_30s", `d = "30s"`, 30 * time.Second, false},
		{"string_5m", `d = "5m"`, 5 * time.Minute, false},
		{"string_1h30m", `d = "1h30m"`, 90 * time.Minute, false},
		{"int_nanos", `d = 30000000000`, 30 * time.Second, false},
		{"empty", ``, 0, false},
		{"invalid_string", `d = "not-a-duration"`, 0, true},
		// 深扫第八轮 MED 的回归钉子:正的亚毫秒裸整数(忘带单位)必须被拒,
		// 而不是静默当纳秒上线(会导致 ticker 30ns 空转刷屏)。
		{"bare_int_30_rejected", `d = 30`, 0, true},
		{"bare_int_999_rejected", `d = 999`, 0, true},
		// 边界:0 表示「禁用」,保留;1ms 及以上照常接受。
		{"bare_int_zero_ok", `d = 0`, 0, false},
		{"bare_int_1ms_ok", `d = 1000000`, time.Millisecond, false},
		// 深扫第十轮 MED:带单位但仍亚毫秒的字符串同样要拒(此前只拦裸整数)。
		{"string_30ns_rejected", `d = "30ns"`, 0, true},
		{"string_500us_rejected", `d = "500us"`, 0, true},
		{"string_1ms_ok", `d = "1ms"`, time.Millisecond, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var h holder
			err := toml.Unmarshal([]byte(tc.in), &h)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got nil (parsed=%v)", time.Duration(h.D))
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if time.Duration(h.D) != tc.want {
				t.Fatalf("got %v want %v", time.Duration(h.D), tc.want)
			}
		})
	}
}

// TestDuration_ServerConfig_DataPlanePing 用真实 ServerConfig 段确认 "30s"
// 在我们实际生产 schema 下也通过(防止字段重命名 / tag 写错的回归)。
func TestDuration_ServerConfig_DataPlanePing(t *testing.T) {
	const in = `
[server]
data_plane_ping_interval = "30s"
data_plane_ping_miss_threshold = 3
`
	var cfg Config
	if err := toml.Unmarshal([]byte(in), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := time.Duration(cfg.Server.DataPlanePingInterval); got != 30*time.Second {
		t.Fatalf("DataPlanePingInterval = %v, want 30s", got)
	}
	if cfg.Server.DataPlanePingMissThreshold != 3 {
		t.Fatalf("DataPlanePingMissThreshold = %d, want 3", cfg.Server.DataPlanePingMissThreshold)
	}
}
