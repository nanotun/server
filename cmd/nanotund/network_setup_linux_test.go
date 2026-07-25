package main

import (
	"reflect"
	"testing"
)

// TestRedirectSysctlKeys_CoversAllAndDevice:内核对 send_redirects 取
// OR(conf/all, conf/<dev>),所以两个键必须都写。只写本设备时 all=1 仍会发重定向,
// 这个测试就是拦「顺手简化成只设本设备」的回归。
func TestRedirectSysctlKeys_CoversAllAndDevice(t *testing.T) {
	got := redirectSysctlKeys("tun0")
	want := []string{
		"net.ipv4.conf.all.send_redirects=0",
		"net.ipv4.conf.tun0.send_redirects=0",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("redirectSysctlKeys(tun0) = %v, want %v", got, want)
	}

	if got := redirectSysctlKeys("nanotun9"); got[1] != "net.ipv4.conf.nanotun9.send_redirects=0" {
		t.Errorf("device key not interpolated: %v", got)
	}
}

// TestConnlimitRuleArgs_ScopedToWANAndClientSource:并发连接上限只该管「客户端 → 公网」
// 这一段。丢掉 -o <wan> 会把 mesh 内部 tun→tun 也算进同一个 per-source 计数,某客户端
// 公网连接超标就连带把它的 peer 互访 / 子网路由 / 出口回程全打死(三机实测 2026-07-25:
// mesh TCP 握手永远收不到 SYN-ACK,ICMP 却通);丢掉 -s <subnet> 则会按出口回程的公网源 IP
// 误限(2026-07 CDN 卡死)。两个限定都是事故换来的,这里一起钉住。
func TestConnlimitRuleArgs_ScopedToWANAndClientSource(t *testing.T) {
	got := connlimitRuleArgs("tun0", "enp1s0", "10.201.0.0/16", "tcp", 40, "32")
	want := []string{
		"-i", "tun0", "-o", "enp1s0", "-s", "10.201.0.0/16", "-p", "tcp",
		"-m", "connlimit", "--connlimit-above", "40",
		"--connlimit-saddr", "--connlimit-mask", "32", "-j", "DROP",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("v4 规则 =\n  %v\nwant\n  %v", got, want)
	}

	v6 := connlimitRuleArgs("tun0", "enp1s0", "fd00:200::/64", "udp", 60, "128")
	if !slicesContainsPair(v6, "-o", "enp1s0") {
		t.Errorf("v6 规则也必须限定出接口: %v", v6)
	}
	if !slicesContainsPair(v6, "--connlimit-mask", "128") {
		t.Errorf("v6 规则掩码应为 128: %v", v6)
	}

	// WAN 探测失败(iface 为空)时退回不限定出接口:宁可保守限流,也不放空。
	noWAN := connlimitRuleArgs("tun0", "  ", "10.201.0.0/16", "tcp", 40, "32")
	if slicesContainsPair(noWAN, "-o", "") || noWAN[0] != "-i" || noWAN[2] != "-s" {
		t.Errorf("wanIface 为空时不该插入 -o: %v", noWAN)
	}
}

// slicesContainsPair 报告 args 里是否存在相邻的 (flag, value)。
func slicesContainsPair(args []string, flag, value string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag && args[i+1] == value {
			return true
		}
	}
	return false
}
