package util

import (
	"bytes"
	"testing"
)

func TestLinkFrameRoundtrip(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte(`{"code":0,"message":"ok"}`)
	if err := WriteLinkFrame(&buf, LinkTypeLoginResp, payload); err != nil {
		t.Fatal(err)
	}
	typ, got, err := ReadLinkFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if typ != LinkTypeLoginResp {
		t.Fatalf("typ %d", typ)
	}
	if string(got) != string(payload) {
		t.Fatalf("payload %q", got)
	}
}

func TestLinkFrameLengthIncludesType(t *testing.T) {
	// L = 1 + 0 => 仅类型字节
	var buf bytes.Buffer
	if err := WriteLinkFrame(&buf, LinkTypeClose, nil); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()
	if len(raw) != 3 {
		t.Fatalf("expected 3 bytes (2 len + 1 type), got %d", len(raw))
	}
	typ, got, err := ReadLinkFrame(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if typ != LinkTypeClose || len(got) != 0 {
		t.Fatalf("typ=%d len(payload)=%d", typ, len(got))
	}
}
