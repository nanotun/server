package util

// 这一组 fuzz 目标的断言不是「不 panic」,而是**不变式**。
//
// fuzz_test.go 里那五个目标只调用解析器并丢掉结果,唯一能抓的是崩溃。实测各跑 45 秒、
// 七八百万次执行,零发现 —— 这不奇怪:那些 parser 早被守卫测试逐个闸门钉过,能崩的形状
// 早修完了。真正抓不到的是**语义**错配:编解码不对称、归一不幂等、字段串位。这三类都
// 不会 panic,只会在别处变成「重复路由条目」「换个写法就绕过审批」「device_name 落到
// platform 字段上」,而且是随机输入最擅长找的东西。
//
// 跑法(种子之外的长跑留给人工 / nightly):
//   go test -run '^$' -fuzz=FuzzLinkFrameRoundTrip        -fuzztime=60s ./util/
//   go test -run '^$' -fuzz=FuzzReadLinkFrameReencodes    -fuzztime=60s ./util/
//   go test -run '^$' -fuzz=FuzzNormalizeAdvertisedCIDRIsIdempotent -fuzztime=60s ./util/
//   go test -run '^$' -fuzz=FuzzLoginReqRoundTrip         -fuzztime=60s ./util/

import (
	"bytes"
	"net/netip"
	"testing"
	"unicode/utf8"
)

// FuzzLinkFrameRoundTrip 写出去的帧必须原样读回来。
//
// 链路帧是 2 字节大端长度前缀 + type + payload,读写是两段独立代码。长度前缀协议里最凶的
// 缺陷是**错位**:少算一个字节不会报错,只会让后面每一帧都解在错的边界上,表现为「隧道通了
// 但过一会儿全是垃圾包」。往返断言是唯一能廉价钉住它的办法。
func FuzzLinkFrameRoundTrip(f *testing.F) {
	f.Add(byte(6), []byte{})                     // LinkTypePing,空 payload:L=1 的边界
	f.Add(byte(5), []byte{0xff})                 //
	f.Add(byte(0), []byte{0x00, 0x00, 0x00})     // type=0 也得能过
	f.Add(byte(255), make([]byte, 4096))         // 高位 type + 4KB(登录前上限)
	f.Add(byte(1), make([]byte, MaxLinkPayload)) // 顶到上限

	f.Fuzz(func(t *testing.T, typ byte, payload []byte) {
		var buf bytes.Buffer
		err := WriteLinkFrame(&buf, typ, payload)
		if len(payload) > MaxLinkPayload {
			if err == nil {
				t.Fatalf("payload %d 字节超过上限 %d 却写成功了", len(payload), MaxLinkPayload)
			}
			return
		}
		if err != nil {
			t.Fatalf("合法 payload(%d 字节)写失败:%v", len(payload), err)
		}
		// 写出的字节数必须恰好是 2 + 1 + len(payload):多写少写都会让下一帧解错边界。
		if got, want := buf.Len(), 3+len(payload); got != want {
			t.Fatalf("帧长 %d,want %d —— 长度前缀与实际字节数不符,后续帧会全部错位", got, want)
		}

		gotTyp, gotPayload, err := ReadLinkFrame(&buf)
		if err != nil {
			t.Fatalf("自己写的帧读不回来:%v", err)
		}
		if gotTyp != typ {
			t.Errorf("type=%d,want %d", gotTyp, typ)
		}
		if !bytes.Equal(gotPayload, payload) {
			t.Errorf("payload 往返不一致:读回 %d 字节,写入 %d 字节", len(gotPayload), len(payload))
		}
		// 读完必须把整帧消费干净,不能剩尾巴给下一帧当长度前缀。
		if buf.Len() != 0 {
			t.Errorf("读完仍剩 %d 字节未消费 —— 会被当成下一帧的长度前缀", buf.Len())
		}
	})
}

// FuzzReadLinkFrameReencodes 读得出来的帧,重新编码必须与原始字节的那一段逐字节相同。
//
// 与上面那条方向相反:那条从「合法结构」出发,这条从**任意字节流**出发。攻击者送来的就是
// 任意字节流,而解析器一旦对某个畸形输入「读成功但边界算错」,重编码就会与原文不符 ——
// 这正是错位的另一种表现,且只有随机输入能撞到。
func FuzzReadLinkFrameReencodes(f *testing.F) {
	f.Add([]byte{0x00, 0x01, 0x06})
	f.Add([]byte{0x00, 0x02, 0x05, 0xff})
	f.Add([]byte{0x00, 0x03, 0x05, 0xff, 0xee, 0x99}) // 尾部多一个字节:不该被算进本帧
	f.Add([]byte{0xff, 0xff})
	f.Add([]byte{0x00, 0x00})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		typ, payload, err := ReadLinkFrame(bytes.NewReader(data))
		if err != nil {
			return // 拒绝是合法结局,这里只管「接受了就必须自洽」
		}
		var re bytes.Buffer
		if err := WriteLinkFrame(&re, typ, payload); err != nil {
			t.Fatalf("读出来的帧重新编码失败:%v(payload %d 字节)", err, len(payload))
		}
		n := re.Len()
		if n > len(data) {
			t.Fatalf("重编码 %d 字节 > 原始 %d 字节 —— 解析器凭空多读出了内容", n, len(data))
		}
		if !bytes.Equal(re.Bytes(), data[:n]) {
			t.Fatalf("重编码与原始前 %d 字节不符:解析边界算错了", n)
		}
	})
}

// FuzzNormalizeAdvertisedCIDRIsIdempotent 归一必须幂等。
//
// 这个函数存在的理由之一就是「把网络地址 mask 化避免重复条目」(见它自己的注释)。幂等一旦
// 破掉,同一个网段就能以两种写法各存一条 approved 记录:admin 撤掉看得见的那条,另一条还在放行。
func FuzzNormalizeAdvertisedCIDRIsIdempotent(f *testing.F) {
	f.Add("192.168.1.0/24")
	f.Add("192.168.1.5/24") // 非网络地址:必须被 mask 成 .0/24
	f.Add("10.0.0.0/8")
	f.Add("fd00::1/64")
	f.Add("100.64.0.0/10")
	f.Add("::ffff:192.168.1.0/120") // v4-mapped 写法
	f.Add("not-a-cidr")
	f.Add("")

	f.Fuzz(func(t *testing.T, in string) {
		out, err := NormalizeAdvertisedCIDR(in)
		if err != nil {
			return // 拒了就没有后续义务
		}
		again, err := NormalizeAdvertisedCIDR(out)
		if err != nil {
			t.Fatalf("归一结果 %q 自己过不了归一:%v(输入 %q)—— 同一网段会存成两条", out, err, in)
		}
		if again != out {
			t.Fatalf("归一不幂等:%q → %q → %q", in, out, again)
		}

		// 幂等单独不够:若实现忘了 mask,192.168.1.5/24 会归一成它自己 —— 依然幂等,但
		// 192.168.1.5/24 与 192.168.1.6/24 就成了两条指向同一网段的记录。故再钉「输出已 mask」。
		p, perr := netip.ParsePrefix(out)
		if perr != nil {
			t.Fatalf("归一结果 %q 不是合法 prefix:%v", out, perr)
		}
		if masked := p.Masked().String(); masked != out {
			t.Fatalf("归一结果 %q 未 mask(应为 %q)—— 同一网段能以多种写法各存一条", out, masked)
		}
	})
}

// FuzzLoginReqRoundTrip 编码出去的登录请求必须原样解析回来,且字段不许串位。
//
// 三个 Marshal 变体共用一个结构体但形参列表不同(六参 / 八参 / 九参),形参顺序写错编译器
// 完全看不出来 —— platform 与 transport 都是 string 且相邻,device_uuid 与 device_name 也是。
// 串位之后功能大体照跑,只是审计里的平台永远是错的、按 transport 分流的逻辑全歪。
func FuzzLoginReqRoundTrip(f *testing.F) {
	f.Add("alice", "tok", "type-a", "linux", "wss", "uuid-1", "dev-1")
	f.Add("", "", "", "", "", "", "")
	f.Add("bob", "t", "type-b", "darwin", "hy2", "11111111-1111-4111-8111-111111111111", "笔记本")

	f.Fuzz(func(t *testing.T, name, token, typ, platform, transport, deviceUUID, deviceName string) {
		// json.Marshal 会把非法 UTF-8 字节替换成 U+FFFD,那种输入不可能逐字节往返 ——
		// 不是缺陷,但也不能拿来做等值断言,所以只保留「能解析」这一半。
		allUTF8 := utf8.ValidString(name) && utf8.ValidString(token) && utf8.ValidString(typ) &&
			utf8.ValidString(platform) && utf8.ValidString(transport) &&
			utf8.ValidString(deviceUUID) && utf8.ValidString(deviceName)

		b, err := MarshalLoginReqJSON(name, "", token, typ, platform, transport)
		if err != nil {
			t.Fatalf("MarshalLoginReqJSON 失败:%v", err)
		}
		if req, perr := ParseLoginReqLinkPayload(b); perr == nil && allUTF8 {
			if req.Name != name || req.Token != token || req.Type != typ ||
				req.Platform != platform || req.Transport != transport {
				t.Errorf("六参变体字段串位:got name=%q token=%q type=%q platform=%q transport=%q",
					req.Name, req.Token, req.Type, req.Platform, req.Transport)
			}
		}

		b, err = MarshalLoginReqWithDeviceJSON(name, "", token, typ, platform, transport, deviceUUID, deviceName)
		if err != nil {
			t.Fatalf("MarshalLoginReqWithDeviceJSON 失败:%v", err)
		}
		if req, perr := ParseLoginReqLinkPayload(b); perr == nil && allUTF8 {
			if req.DeviceUUID != deviceUUID || req.DeviceName != deviceName {
				t.Errorf("设备变体字段串位:got uuid=%q name=%q,want uuid=%q name=%q",
					req.DeviceUUID, req.DeviceName, deviceUUID, deviceName)
			}
			if req.Platform != platform || req.Transport != transport {
				t.Errorf("设备变体把 platform/transport 写歪了:got %q/%q,want %q/%q",
					req.Platform, req.Transport, platform, transport)
			}
		}

		// 接管变体:多出 session_id 与 secret 两个相邻 string,最容易互换。
		b, err = MarshalLoginReqTakeoverJSON(name, "", token, typ, platform, transport, deviceUUID, deviceName)
		if err != nil {
			t.Fatalf("MarshalLoginReqTakeoverJSON 失败:%v", err)
		}
		if req, perr := ParseLoginReqLinkPayload(b); perr == nil && allUTF8 {
			if req.TakeoverSessionID != deviceUUID || req.TakeoverSecret != deviceName {
				t.Errorf("接管变体 session_id/secret 串位:got sid=%q secret=%q,want sid=%q secret=%q",
					req.TakeoverSessionID, req.TakeoverSecret, deviceUUID, deviceName)
			}
		}
	})
}
