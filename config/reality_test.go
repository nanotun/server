package config

import (
	"testing"
)

func TestParseRealityShortID(t *testing.T) {
	b, err := ParseRealityShortID("aabbccddeeff0011")
	if err != nil {
		t.Fatal(err)
	}
	want := [8]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11}
	if b != want {
		t.Fatalf("got %#v want %#v", b, want)
	}
	z, err := ParseRealityShortID("")
	if err != nil || z != [8]byte{} {
		t.Fatalf("empty: %#v %v", z, err)
	}

	// 短 shortId 必须左对齐，与 Xray/xtls-reality 线上格式一致；
	// 若右对齐（旧 bug），面板默认的 8 位 hex shortId 握手会匹配失败。
	short, err := ParseRealityShortID("aabb")
	if err != nil {
		t.Fatal(err)
	}
	if wantShort := ([8]byte{0xaa, 0xbb, 0, 0, 0, 0, 0, 0}); short != wantShort {
		t.Fatalf("short shortId not left-aligned: got %#v want %#v", short, wantShort)
	}

	// 深扫第八轮 LOW:补边界覆盖。
	// 奇数长度 hex → 报错(不能截断成半字节)。
	if _, err := ParseRealityShortID("aab"); err == nil {
		t.Fatal("odd-length shortId 应报错")
	}
	// 超过 16 个 hex 字符(>8 字节)→ 报错。
	if _, err := ParseRealityShortID("aabbccddeeff00112233"); err == nil {
		t.Fatal("超长 shortId 应报错")
	}
	// 恰好 16 个 hex(8 字节)满长 → 不左移,原样填满。
	full, err := ParseRealityShortID("00112233445566ff")
	if err != nil {
		t.Fatal(err)
	}
	if wantFull := ([8]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0xff}); full != wantFull {
		t.Fatalf("full shortId: got %#v want %#v", full, wantFull)
	}
	// 非法 hex 字符 → 报错。
	if _, err := ParseRealityShortID("zzzz"); err == nil {
		t.Fatal("非法 hex 应报错")
	}
}

func TestDecodeRealityPrivateKey(t *testing.T) {
	// 随机测试向量(与任何生产密钥无关);仅要求能 base64 解出 32 字节
	const pk = "2pagi_xOuxmKJQNLl8lQ_Hh8kj7Nt8VUlV_lzGLk5Bg"
	b, err := DecodeRealityPrivateKey(pk)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 32 {
		t.Fatalf("len=%d", len(b))
	}
}
