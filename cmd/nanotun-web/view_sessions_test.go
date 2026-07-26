package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/nanotun/server/store"
)

// serveFakeControl 起一个 unix socket 上的假 control server,/status 固定返回 body。
func serveFakeControl(t *testing.T, body string) *controlClient {
	t.Helper()
	// unix socket 路径有 ~104 字节上限,t.TempDir() 会把测试名拼进去直接超限,
	// 所以自己在 os.TempDir() 下开一个短目录。
	dir, err := os.MkdirTemp("", "ntw")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	ln, err := net.Listen("unix", filepath.Join(dir, "c.sock"))
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return newControlClient(ln.Addr().String())
}

// newEmptyStore:collectSessionsForView 会 join store 拿 username/device,给它一个空库即可。
func newEmptyStore(t *testing.T) *store.Store {
	t.Helper()
	ctx := t.Context()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "sessions_view_test.db"), store.Options{})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// TestCollectSessions_ShowsEffectiveRateNotLoginSnapshot:会话页的限速列必须展示
// link_rate_*(当前真实生效),不是 bw_*(登录那一刻凝固的 user 字段)。
//
// 回归自实测:设置页改完「全局默认限速」后 nanotund 侧 link_rate_down_bps 已经变成
// 4 MiB/s(热更生效,设置页也白纸黑字写着「立即热更到所有活跃会话」),但会话页仍显示
// 「不限速」—— 因为它读的是 bw_*,而 bw_* 在登录后永不变化。admin 无从确认自己改没改上。
func TestCollectSessions_ShowsEffectiveRateNotLoginSnapshot(t *testing.T) {
	ctrl := serveFakeControl(t, `{"sessions":[{
		"conn_id":"c1","user_id":"u4","created_at":1,
		"link_ready":true,
		"link_rate_up_bps":2097152,"link_rate_down_bps":4194304
	}]}`)
	s := &Server{control: ctrl, store: newEmptyStore(t)}

	views, err := s.collectSessionsForView(context.Background())
	if err != nil {
		t.Fatalf("collectSessionsForView: %v", err)
	}
	if len(views) != 1 {
		t.Fatalf("want 1 session, got %d", len(views))
	}
	v := views[0]
	if !v.RateKnown() {
		t.Error("link_ready=true 时限速状态应视为已知")
	}
	if v.EffectiveUpBPS() != 2097152 || v.EffectiveDownBPS() != 4194304 {
		t.Errorf("生效限速 = ↑%d ↓%d, want ↑2097152 ↓4194304", v.EffectiveUpBPS(), v.EffectiveDownBPS())
	}
}

// TestCollectSessions_RateUnknownBeforeLinkReady:link_ready=false 时 LinkRate* 恒为 0,
// 那个 0 不是「不限速」,页面不能拿它当结论。
func TestCollectSessions_RateUnknownBeforeLinkReady(t *testing.T) {
	ctrl := serveFakeControl(t, `{"sessions":[{"conn_id":"c1","user_id":"u4","created_at":1,"link_ready":false}]}`)
	s := &Server{control: ctrl, store: newEmptyStore(t)}

	views, err := s.collectSessionsForView(context.Background())
	if err != nil {
		t.Fatalf("collectSessionsForView: %v", err)
	}
	if len(views) != 1 {
		t.Fatalf("want 1 session, got %d", len(views))
	}
	if views[0].RateKnown() {
		t.Error("link_ready=false 时不该断言限速状态")
	}
}
