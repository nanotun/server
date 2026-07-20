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
