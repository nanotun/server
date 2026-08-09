//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestHasIPv4DefaultRoute 钉死「GetWAN 失败该硬退还是该容忍」的那把分流刀。
//
// 背景:纯 IPv6 主机上 `ip route get 1.1.1.1` 必然 "Network is unreachable",GetWAN 返错。
// 以前这条路无条件 failTUN → 生产 Linux root 下 os.Exit(60) → systemd 拉起又崩,30 次
// 起步的崩溃循环,而 web 面照常监听,活活一个「起来了却没数据面」的伪可用。修复靠
// hasIPv4DefaultRoute 把两类情形分开:
//   - 有 v4 默认路由却探不到出口 = 真故障 → 必须判 true,让上层保持硬退;
//   - 没有 v4 默认路由 = 纯 v6 主机 → 必须判 false,让上层跳过 v4 NAT、数据面走 v6。
//
// 判反任意一边都危险:true 判成 false 会把真实的网卡/防火墙故障咽成一台流量黑洞;
// false 判成 true 会把纯 v6 机器重新按回崩溃循环。用 PATH 注入一个可控假 ip 三种都过一遍。
func TestHasIPv4DefaultRoute(t *testing.T) {
	writeFakeIP := func(t *testing.T, body string) {
		t.Helper()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "ip"), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatalf("写假 ip: %v", err)
		}
		t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	}

	t.Run("有_v4_默认路由→true", func(t *testing.T) {
		writeFakeIP(t, `case "$*" in
  *"-4 route show default"*) echo "default via 10.0.0.1 dev eth0 proto dhcp src 10.0.0.5 metric 100"; exit 0 ;;
esac
exit 0
`)
		if !hasIPv4DefaultRoute() {
			t.Fatal("有默认路由却判成没有 —— GetWAN 失败会被误当纯 v6 容忍,该硬退的真故障被咽掉")
		}
	})

	t.Run("无_v4_默认路由_纯v6→false", func(t *testing.T) {
		// 任何 ip 调用都成功但 stdout 为空:纯 v6 主机 `ip -4 route show default` 的实况。
		writeFakeIP(t, "exit 0\n")
		if hasIPv4DefaultRoute() {
			t.Fatal("纯 v6 主机(输出空)却判成有默认路由 —— 会走进 failTUN 硬退,回到崩溃循环")
		}
	})

	t.Run("命令失败→false_偏可用性", func(t *testing.T) {
		// 走到这里时 GetWAN 已经失败;真有 v4 WAN 的话 GetWAN 不会先失败,故此处偏可用性判 false。
		writeFakeIP(t, "echo 'fake ip: boom' >&2\nexit 2\n")
		if hasIPv4DefaultRoute() {
			t.Fatal("ip 命令失败应保守判 false")
		}
	})
}
