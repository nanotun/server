package util

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// IPPacketTotalLen 是整条数据面的大门:服务端 readLoop、ACL 执法、出口转发、端口转发
// 全都先过它,过了之后下游一律按「头部字段可信」从固定偏移取值。所以它判松一点,
// 后面每一层都在读垃圾;判紧一点,合法流量直接不通。
//
// 它同时是 TrimIPPacketToTotalLen 的判据 —— 「声明总长」既用来放行也用来裁剪尾巴。

// v4 造一份 IPv4 头:ihlWords 是 IHL 字段(32-bit word 数),totalLen 写进头里的总长度,
// physLen 是实际给出的字节数(两者可以不一致,畸形包就靠这个造)。
func v4(ihlWords int, totalLen, physLen int) []byte {
	p := make([]byte, physLen)
	if physLen > 0 {
		p[0] = byte(4<<4 | ihlWords)
	}
	if physLen >= 4 {
		binary.BigEndian.PutUint16(p[2:4], uint16(totalLen))
	}
	return p
}

// v6 造一份 IPv6 头:payloadLen 写进头里的 payload length,physLen 是实际字节数。
func v6(payloadLen, physLen int) []byte {
	p := make([]byte, physLen)
	if physLen > 0 {
		p[0] = 6 << 4
	}
	if physLen >= 6 {
		binary.BigEndian.PutUint16(p[4:6], uint16(payloadLen))
	}
	return p
}

func TestIPPacketTotalLen_GateAcceptsOnlyWhatDownstreamCanSafelyParse(t *testing.T) {
	cases := []struct {
		name      string
		p         []byte
		wantOK    bool
		wantTotal int
		because   string
	}{
		{"空载荷", nil, false, 0, "连版本号都没有"},
		{"只有 1 字节", []byte{0x45}, false, 0, "版本对了但头不全"},

		{"最小 IPv4", v4(5, 20, 20), true, 20, "20B 头、无负载,是合法的最小 IPv4 报文"},
		{"IPv4 带负载", v4(5, 28, 28), true, 28, ""},
		{"IPv4 有尾随字节", v4(5, 28, 60), true, 28, "声明 28、实收 60:放行,但总长按声明算,多出来的由裁剪剥掉"},
		{"IPv4 最大合法 IHL", v4(15, 60, 60), true, 60, "IHL=60 是选项字段拉满的合法头"},

		{"IPv4 短于一个头", v4(5, 20, 19), false, 0, "读 20B 头就要越界"},
		{"IHL 小于 20", v4(4, 20, 20), false, 0,
			"头长非法。下游按 IHL 定位 L4 头,信了它就会从错误偏移取端口"},
		{"IHL 为 0", v4(0, 20, 20), false, 0, "同上,且是最容易被构造的一种"},
		{"IHL 超过声明总长", v4(15, 24, 60), false, 0,
			"头自己就比整个报文长 —— 下游解 L4 端口必然落到头之外,解不出端口的包在 default=allow 下会被当成没命中 deny 规则放行"},
		{"总长小于 20", v4(5, 19, 40), false, 0, "总长连头都装不下"},
		{"总长为 0", v4(5, 0, 40), false, 0, "常见的构造:总长填 0 骗过只查上界的实现"},
		{"总长超过实收字节", v4(5, 100, 40), false, 0,
			"声明比实收长 —— 放行则裁剪不会生效,下游按 100 字节去读只有 40 字节的缓冲"},

		{"最小 IPv6", v6(0, 40), true, 40, "40B 固定头、无负载"},
		{"IPv6 带负载", v6(8, 48), true, 48, ""},
		{"IPv6 有尾随字节", v6(8, 100), true, 48, "同 v4,按声明算总长"},
		{"IPv6 短于固定头", v6(0, 39), false, 0, "40B 固定头都读不全"},
		{"IPv6 只有 3 字节", []byte{0x60, 0, 0}, false, 0,
			"长度检查必须在读 payload length 之前 —— 否则取 p[4:6] 当场越界 panic,一个 3 字节的包就能停掉整个进程"},
		{"IPv6 声明超过实收", v6(200, 48), false, 0, "同 v4 的上界检查"},

		{"版本 5", []byte(append([]byte{0x50}, make([]byte, 60)...)), false, 0, "既不是 4 也不是 6"},
		{"版本 0", make([]byte, 60), false, 0, "全零报文"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			total, ok := IPPacketTotalLen(tc.p)
			if ok != tc.wantOK {
				t.Fatalf("放行判定 = %v,应为 %v(%s)", ok, tc.wantOK, tc.because)
			}
			if ok && total != tc.wantTotal {
				t.Fatalf("声明总长 = %d,应为 %d", total, tc.wantTotal)
			}
			if got := ValidIPPacket(tc.p); got != tc.wantOK {
				t.Fatalf("ValidIPPacket = %v,与 IPPacketTotalLen 不一致", got)
			}
		})
	}
}

// TrimIPPacketToTotalLen 只剥尾巴,不改内容也不动非法包。
//
// 尾随字节是一条谁都不检查的隐蔽信道:ACL 看头部、NAT 改头部、TUN 写整包,没有一层会
// 去问「声明之后的这 500 字节是什么」。裁剪是唯一把它掐掉的地方。
func TestTrimIPPacketToTotalLen_StripsTheTailAndNothingElse(t *testing.T) {
	body := v4(5, 28, 28)
	for i := 20; i < 28; i++ {
		body[i] = 0xAA
	}
	withTail := append(append([]byte{}, body...), bytes.Repeat([]byte{0xEE}, 64)...)

	got := TrimIPPacketToTotalLen(withTail)
	if !bytes.Equal(got, body) {
		t.Fatalf("裁剪结果与原报文不一致:\n got %x\nwant %x", got, body)
	}

	exact := v4(5, 28, 28)
	if got := TrimIPPacketToTotalLen(exact); len(got) != 28 {
		t.Fatalf("没有尾巴的报文被改动了,长度 %d", len(got))
	}

	// 非法包原样返回:判定权在调用方先行的 ValidIPPacket,裁剪不替它做决定。
	bad := v4(5, 100, 40)
	if got := TrimIPPacketToTotalLen(bad); len(got) != 40 {
		t.Fatalf("非法包不该被裁剪(长度 %d),否则会掩盖「声明超过实收」这个信号", len(got))
	}
}
