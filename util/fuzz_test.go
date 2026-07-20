package util

// F2(2026-05-22):为关键协议解析器加 fuzz。这些 parser 都是网络入口,任何
// panic 都会让 server goroutine 崩;run-time-safe 是底线要求。
//
// 跑法:
//   go test -fuzz=FuzzReadLinkFrame      -fuzztime=10s ./util/
//   go test -fuzz=FuzzParseLoginReq      -fuzztime=10s ./util/
//   go test -fuzz=FuzzParseRouteAdvertise -fuzztime=10s ./util/
//   go test -fuzz=FuzzNormalizeAdvertisedCIDR -fuzztime=10s ./util/
//
// 没有 panic / 内存炸 / hang 即通过。CI 上默认只跑 seed corpus(常规 go test
// 不带 -fuzz 时就是 seed corpus 跑一遍),长跑 fuzz 留给人工 / nightly CI。

import (
	"bytes"
	"testing"
)

func FuzzReadLinkFrame(f *testing.F) {
	// seeds: 合法帧 + 各种边界
	f.Add([]byte{0x00, 0x01, 0x06})                          // 最短合法:LinkTypePing,空 payload
	f.Add([]byte{0x00, 0x02, 0x05, 0xff})                    // type 5 + 1 字节 payload
	f.Add([]byte{0xff, 0xff})                                // L = 65535 但后面缺数据,EOF
	f.Add([]byte{0x00, 0x00})                                // L = 0 → 报 length < 1
	f.Add([]byte{})                                          // 空 → io.EOF
	f.Add([]byte{0x00})                                      // 半个 length 头
	f.Add(append([]byte{0x10, 0x00}, make([]byte, 4097)...)) // L=4096, payload 充够

	f.Fuzz(func(t *testing.T, data []byte) {
		// 任何输入都不应 panic。
		_, _, _ = ReadLinkFrame(bytes.NewReader(data))
		_, _, _ = ReadLinkFramePreLogin(bytes.NewReader(data))
	})
}

func FuzzParseLoginReq(f *testing.F) {
	// seeds
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"name":"a","token":"b","platform":"linux","transport":"wss"}`))
	f.Add([]byte(`{"name":"","token":"","takeover_secret":"","device_uuid":"","device_name":"","platform":"","transport":""}`))
	f.Add([]byte(`{"name":"` + string(make([]byte, 4096)) + `"}`)) // 超长 name → 返回 err
	f.Add([]byte(`not-json`))                                      // 解析失败 → 返回 err
	f.Add([]byte(``))                                              // 空 → 返回 err
	f.Add([]byte(`{"name":1}`))                                    // 类型错 → 返回 err

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseLoginReqLinkPayload(data)
	})
}

func FuzzParseRouteAdvertise(f *testing.F) {
	f.Add([]byte(`{"schema":1,"routes":[]}`))
	f.Add([]byte(`{"schema":1,"routes":["192.168.1.0/24"]}`))
	f.Add([]byte(`{"schema":999,"routes":[]}`))
	f.Add([]byte(`{"routes":null}`))
	f.Add([]byte(`not-json`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseRouteAdvertise(data)
		_, _ = ParseRouteApproveStatus(data)
	})
}

func FuzzNormalizeAdvertisedCIDR(f *testing.F) {
	f.Add("192.168.1.0/24")
	f.Add("10.0.0.0/8")
	f.Add("::/0")
	f.Add("")
	f.Add("not-a-cidr")
	f.Add(string(make([]byte, 4096)))

	f.Fuzz(func(t *testing.T, in string) {
		_, _ = NormalizeAdvertisedCIDR(in)
	})
}

func FuzzMarshalLoginReqJSON(f *testing.F) {
	f.Add("alice", "secret", "type-a", "linux", "wss")
	f.Add("", "", "", "", "")
	// 控制超长 / 非 utf8 在 marshal 时不应 panic;json 包会做转义。
	f.Add(string(make([]byte, 1024)), string([]byte{0xff, 0xfe}), "type-b", "darwin", "hy2")

	f.Fuzz(func(t *testing.T, name, token, typ, platform, transport string) {
		// password 维持空(P3-d 已从 wire 上下架,只兼容形参)。
		_, _ = MarshalLoginReqJSON(name, "", token, typ, platform, transport)
		_, _ = MarshalLoginReqWithDeviceJSON(name, "", token, typ, platform, transport, "uuid-fuzz", "dev-fuzz")
		_, _ = MarshalLoginReqTakeoverJSON(name, "", token, typ, platform, transport, "sid", "secret-hex")
	})
}
