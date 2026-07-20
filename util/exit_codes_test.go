package util

import (
	"errors"
	"net"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/sirupsen/logrus"
)

// 替换 exitFunc 让单测可以验证 FatalExit 传入的 code,不真的退出进程。
func captureExit(t *testing.T) (*atomic.Int32, func()) {
	t.Helper()
	captured := &atomic.Int32{}
	prev := exitFunc
	exitFunc = func(code int) { captured.Store(int32(code)) }
	return captured, func() { exitFunc = prev }
}

func TestExitCode_String(t *testing.T) {
	cases := []struct {
		c    ExitCode
		want string
	}{
		{ExitOK, "ExitOK"},
		{ExitConfigParse, "ExitConfigParse"},
		{ExitListenInUse, "ExitListenInUse"},
		{ExitDBInit, "ExitDBInit"},
		{ExitCode(9999), "ExitUnknown"},
	}
	for _, tc := range cases {
		if got := tc.c.String(); got != tc.want {
			t.Errorf("code=%d got %q want %q", tc.c, got, tc.want)
		}
	}
}

func TestFatalExit_UsesCode(t *testing.T) {
	captured, restore := captureExit(t)
	defer restore()

	prevLevel := logrus.GetLevel()
	logrus.SetLevel(logrus.PanicLevel)
	defer logrus.SetLevel(prevLevel)

	FatalExit(ExitListenInUse, logrus.Fields{"addr": ":8080"}, "Listen failed: %v", errors.New("bind err"))
	if got := captured.Load(); got != int32(ExitListenInUse) {
		t.Fatalf("exit code: got %d, want %d", got, ExitListenInUse)
	}

	FatalExit(ExitConfigSemantic, nil, "config: %s", "missing field")
	if got := captured.Load(); got != int32(ExitConfigSemantic) {
		t.Fatalf("exit code: got %d, want %d", got, ExitConfigSemantic)
	}
}

func TestClassifyListenError(t *testing.T) {
	if got := ClassifyListenError(nil); got != ExitOK {
		t.Fatalf("nil err: got %d, want %d", got, ExitOK)
	}

	wrapped := &net.OpError{Op: "listen", Net: "tcp", Err: syscall.EADDRINUSE}
	if got := ClassifyListenError(wrapped); got != ExitListenInUse {
		t.Fatalf("OpError(EADDRINUSE): got %d, want %d", got, ExitListenInUse)
	}

	if got := ClassifyListenError(syscall.EADDRINUSE); got != ExitListenInUse {
		t.Fatalf("bare EADDRINUSE: got %d, want %d", got, ExitListenInUse)
	}

	stringOnly := errors.New("listen tcp :8080: bind: address already in use")
	if got := ClassifyListenError(stringOnly); got != ExitListenInUse {
		t.Fatalf("string-only EADDRINUSE: got %d, want %d", got, ExitListenInUse)
	}

	other := errors.New("dns lookup failed")
	if got := ClassifyListenError(other); got != ExitListenOther {
		t.Fatalf("unrelated err: got %d, want %d", got, ExitListenOther)
	}
}
