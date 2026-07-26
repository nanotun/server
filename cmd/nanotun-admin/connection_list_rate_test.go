package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestConnectionList_ShowsEffectiveRate:UP_BPS / DOWN_BPS 列要展示数据面**当下生效**的 cap。
//
// 三机实测(2026-07-26):`setting rate --down-bps 150000` + `device set-rate 1 --down-bps 60000`
// 之后 A 的下行实测被限在 57 KB/s,而本表两列都是 "-"(= 不限速)—— 因为它读的是 bw_*_bps
// (users.bandwidth_*,本例为空),而不是 link_rate_*_bps。运维照着这张表会以为限速没生效。
func TestConnectionList_ShowsEffectiveRate(t *testing.T) {
	body := []byte(`{"ok":true,"conn_count":1,"server_version":"test","uptime":"1m","sessions":[
		{"conn_id":"abc","user_id":"u2","vips":["10.201.0.77"],"created_at":0,"exit_allowed":true,
		 "link_ready":true,"link_rate_down_bps":60000,"link_rate_up_bps":0}]}`)
	out := &bytes.Buffer{}
	opts := &globalOpts{stdout: out, stderr: &bytes.Buffer{}, lang: "zh"}
	if err := printConnectionList(opts, body); err != nil {
		t.Fatalf("print: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "60000") {
		t.Errorf("应展示生效下行 cap 60000,实际输出:\n%s", got)
	}
}

// TestConnectionList_UnknownRateBeforeLinkReady:limiter 还没建起来时 LinkRate* 恒为 0,
// 那个 0 不代表「不限速」,不能渲染成 "-"。
func TestConnectionList_UnknownRateBeforeLinkReady(t *testing.T) {
	body := []byte(`{"ok":true,"conn_count":1,"server_version":"test","uptime":"1m","sessions":[
		{"conn_id":"abc","user_id":"u2","vips":["10.201.0.77"],"created_at":0,"exit_allowed":true,
		 "link_ready":false}]}`)
	out := &bytes.Buffer{}
	opts := &globalOpts{stdout: out, stderr: &bytes.Buffer{}, lang: "zh"}
	if err := printConnectionList(opts, body); err != nil {
		t.Fatalf("print: %v", err)
	}
	if got := out.String(); !strings.Contains(got, "?") {
		t.Errorf("limiter 未就绪应显示未知,实际输出:\n%s", got)
	}
}
