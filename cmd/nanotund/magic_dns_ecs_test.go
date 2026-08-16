package main

import (
	"bytes"
	"net"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// mkECSTestQuery 构造一份 A 查询;withOpt 时带一个空 OPT,withECS 时 OPT 里预置客户端自带的 ECS。
func mkECSTestQuery(t *testing.T, withOpt, withECS bool) []byte {
	t.Helper()
	m := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 0x1234, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  dnsmessage.MustNewName("www.baidu.com."),
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
		}},
	}
	if withOpt {
		opts := []dnsmessage.Option{}
		if withECS {
			opts = append(opts, dnsmessage.Option{Code: ecsOptionCode, Data: []byte{0, 1, 24, 0, 1, 2, 3}})
		}
		m.Additionals = append(m.Additionals, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name:  dnsmessage.MustNewName("."),
				Type:  dnsmessage.TypeOPT,
				Class: dnsmessage.Class(1232),
			},
			Body: &dnsmessage.OPTResource{Options: opts},
		})
	}
	raw, err := m.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	return raw
}

// findECSOptions 解包后取出所有 OPT 的 ECS 选项数据;顺带返回 OPT 个数。
func findECSOptions(t *testing.T, raw []byte) (ecsData [][]byte, optCount int) {
	t.Helper()
	var m dnsmessage.Message
	if err := m.Unpack(raw); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	for _, r := range m.Additionals {
		if r.Header.Type != dnsmessage.TypeOPT {
			continue
		}
		optCount++
		body, ok := r.Body.(*dnsmessage.OPTResource)
		if !ok {
			t.Fatalf("OPT body 类型错: %T", r.Body)
		}
		for _, o := range body.Options {
			if o.Code == ecsOptionCode {
				ecsData = append(ecsData, o.Data)
			}
		}
	}
	return ecsData, optCount
}

// 无 OPT 的查询:注入后应新增恰好一个 OPT,携带 family=1 /24 且地址截断为 3 字节的 ECS。
func TestInjectECS_AddsOptWhenAbsent(t *testing.T) {
	q := mkECSTestQuery(t, false, false)
	out, ok := injectECS(q, netip.MustParseAddr("115.210.191.233"))
	if !ok {
		t.Fatal("注入应成功")
	}
	ecs, optCount := findECSOptions(t, out)
	if optCount != 1 || len(ecs) != 1 {
		t.Fatalf("期望 1 个 OPT/1 个 ECS,得到 opt=%d ecs=%d", optCount, len(ecs))
	}
	want := []byte{0, 1, 24, 0, 115, 210, 191}
	if !bytes.Equal(ecs[0], want) {
		t.Fatalf("ECS 数据不符: got=%v want=%v", ecs[0], want)
	}
	// 事务 ID 与 question 必须原样保留(dialAndQueryUDP 反投毒校验依赖)。
	var m dnsmessage.Message
	if err := m.Unpack(out); err != nil {
		t.Fatalf("unpack out: %v", err)
	}
	if m.Header.ID != 0x1234 || len(m.Questions) != 1 || m.Questions[0].Name.String() != "www.baidu.com." {
		t.Fatalf("ID/question 被改动: %+v", m.Header)
	}
}

// 已有 OPT(无 ECS)的查询:选项追加进原 OPT,不新建第二个 OPT。
func TestInjectECS_AppendsToExistingOpt(t *testing.T) {
	q := mkECSTestQuery(t, true, false)
	out, ok := injectECS(q, netip.MustParseAddr("115.210.191.233"))
	if !ok {
		t.Fatal("注入应成功")
	}
	ecs, optCount := findECSOptions(t, out)
	if optCount != 1 || len(ecs) != 1 {
		t.Fatalf("期望仍是 1 个 OPT 且含 1 个 ECS,得到 opt=%d ecs=%d", optCount, len(ecs))
	}
}

// 客户端自带 ECS:必须尊重不覆盖,injectECS 返回 ok=false,maybe 路径原样转发。
func TestInjectECS_RespectsClientECS(t *testing.T) {
	q := mkECSTestQuery(t, true, true)
	if _, ok := injectECS(q, netip.MustParseAddr("115.210.191.233")); ok {
		t.Fatal("查询已带 ECS 时不得覆盖")
	}
}

// v6 客户端:family=2、/56、地址 7 字节。
func TestBuildECSOptionData_V6(t *testing.T) {
	data := buildECSOptionData(netip.MustParseAddr("2409:8a55:1234:5678:abcd::1"))
	if len(data) != 4+7 {
		t.Fatalf("v6 ECS 数据长度应为 11,得到 %d", len(data))
	}
	want := []byte{0, 2, 56, 0, 0x24, 0x09, 0x8a, 0x55, 0x12, 0x34, 0x56}
	if !bytes.Equal(data, want) {
		t.Fatalf("v6 ECS 数据不符: got=%v want=%v", data, want)
	}
}

// 资格闸:私网/回环/链路本地/CGNAT/ULA 一律不注入,公网 v4/v6 放行。
func TestECSEligibleClientIP(t *testing.T) {
	no := []string{"192.168.8.1", "10.0.0.1", "127.0.0.1", "169.254.1.1", "100.64.0.1", "100.127.255.254", "fd00:200::1c", "fe80::1", "::1"}
	for _, s := range no {
		if ecsEligibleClientIP(netip.MustParseAddr(s)) {
			t.Errorf("%s 不应合格", s)
		}
	}
	yes := []string{"115.210.191.233", "8.8.8.8", "2409:8a55::1"}
	for _, s := range yes {
		if !ecsEligibleClientIP(netip.MustParseAddr(s)) {
			t.Errorf("%s 应合格", s)
		}
	}
}

// 查不到会话(connIDMap 无此 vIP)→ maybeInjectECS 原样返回,转发不受影响。
func TestMaybeInjectECS_NoSessionPassthrough(t *testing.T) {
	q := mkECSTestQuery(t, false, false)
	peer, err := net.ResolveUDPAddr("udp", "10.201.0.99:5555")
	if err != nil {
		t.Fatalf("resolve peer: %v", err)
	}
	out := maybeInjectECS(q, peer)
	if !bytes.Equal(out, q) {
		t.Fatal("无会话时应原样返回")
	}
}
