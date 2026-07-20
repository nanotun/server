package util

import "testing"

func TestExitsListRoundtrip(t *testing.T) {
	in := []ExitInfo{
		{DeviceUUID: "11111111-2222-4333-8444-555555555555", DeviceName: "vultr-exit", Online: true},
		{DeviceUUID: "99999999-aaaa-4bbb-8ccc-dddddddddddd", Online: true},
	}
	b, err := MarshalExitsList(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	el, err := ParseExitsList(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if el.Schema != RouteSchemaCurrent {
		t.Fatalf("schema = %d, want %d", el.Schema, RouteSchemaCurrent)
	}
	if len(el.Exits) != 2 || el.Exits[0].DeviceUUID != in[0].DeviceUUID || el.Exits[0].DeviceName != "vultr-exit" || !el.Exits[0].Online {
		t.Fatalf("roundtrip mismatch: %+v", el.Exits)
	}
}

func TestMarshalExitsList_NilIsEmptyArray(t *testing.T) {
	// nil → `[]`(而非 null),避免客户端解析出 null 列表。
	b, err := MarshalExitsList(nil)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	el, err := ParseExitsList(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if el.Exits == nil {
		t.Fatal("nil 出口应序列化为空数组,解析回非 nil 空切片")
	}
	if len(el.Exits) != 0 {
		t.Fatalf("want 0 exits, got %d", len(el.Exits))
	}
}

func TestParseExitsList_RejectsWrongSchema(t *testing.T) {
	if _, err := ParseExitsList([]byte(`{"schema":999,"exits":[]}`)); err == nil {
		t.Fatal("错误 schema 应被拒")
	}
}
