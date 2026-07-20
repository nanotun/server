package store

import (
	"context"
	"errors"
	"testing"
)

// TestRateDefaults_DefaultIsZero:0011 migration 用 INSERT OR IGNORE 写入 '0',
// 但即使没插入(老库迁过 0009 没经过 0011)读取也应返回 0/0 而不是 error。
func TestRateDefaults_DefaultIsZero(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	got, err := st.GetRateDefaults(ctx)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.UploadBPS != 0 || got.DownloadBPS != 0 {
		t.Errorf("want 0/0 (init state), got %+v", got)
	}
}

// TestRateDefaults_RoundTrip:写入 → 读出。覆盖单向写(只压上行)和清空场景。
func TestRateDefaults_RoundTrip(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	const up = 50 * 1024 * 1024
	const down = 100 * 1024 * 1024
	if err := st.SetRateDefaults(ctx, RateDefaults{UploadBPS: up, DownloadBPS: down}); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, _ := st.GetRateDefaults(ctx)
	if got.UploadBPS != up || got.DownloadBPS != down {
		t.Errorf("roundtrip: want %d/%d got %+v", up, down, got)
	}

	// 单向:只清下行
	if err := st.SetRateDefaults(ctx, RateDefaults{UploadBPS: up, DownloadBPS: 0}); err != nil {
		t.Fatalf("partial set: %v", err)
	}
	got, _ = st.GetRateDefaults(ctx)
	if got.UploadBPS != up || got.DownloadBPS != 0 {
		t.Errorf("partial: want %d/0 got %+v", up, got)
	}

	// 全清
	if err := st.SetRateDefaults(ctx, RateDefaults{}); err != nil {
		t.Fatalf("zero set: %v", err)
	}
	got, _ = st.GetRateDefaults(ctx)
	if got.UploadBPS != 0 || got.DownloadBPS != 0 {
		t.Errorf("zero: got %+v", got)
	}
}

// TestRateDefaults_Invalid:负数 → ErrInvalid,且 DB 未被部分写入。
func TestRateDefaults_Invalid(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	for _, tc := range []RateDefaults{
		{UploadBPS: -1, DownloadBPS: 0},
		{UploadBPS: 0, DownloadBPS: -1},
		{UploadBPS: -10, DownloadBPS: -20},
	} {
		err := st.SetRateDefaults(ctx, tc)
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%+v: want ErrInvalid, got %v", tc, err)
		}
	}
	// 验证 DB 仍是初始 0/0,没被偷偷部分写入。
	got, _ := st.GetRateDefaults(ctx)
	if got.UploadBPS != 0 || got.DownloadBPS != 0 {
		t.Errorf("after invalid: want 0/0 untouched, got %+v", got)
	}
}

// TestRateDefaults_CorruptedValueDegradesToZero:运维手工把 app_settings.value 改成
// 非数字字符串,GetRateDefaults 应该 fail-open(返回 0),不能让 web/server 起不来。
func TestRateDefaults_CorruptedValueDegradesToZero(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	_ = st.SettingsSet(ctx, settingRateDefaultUploadBPS, "not-a-number")
	_ = st.SettingsSet(ctx, settingRateDefaultDownloadBPS, "")
	got, err := st.GetRateDefaults(ctx)
	if err != nil {
		t.Fatalf("must not error on corrupted value: %v", err)
	}
	if got.UploadBPS != 0 || got.DownloadBPS != 0 {
		t.Errorf("corrupt: want degrade to 0/0, got %+v", got)
	}
}
