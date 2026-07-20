package main

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xtaci/smux"

	"github.com/nanotun/server/config"
	"github.com/nanotun/server/util"
)

func TestLoopbackSmuxMultiplexEnabled(t *testing.T) {
	cfg := &config.Config{Smux: &config.SmuxConfig{}}
	if loopbackSmuxMultiplexEnabled(cfg) {
		t.Fatal("无 hy2、无 REALITY 时不应启用")
	}
	cfg.Reality.ListenAddr = ":8443"
	if !loopbackSmuxMultiplexEnabled(cfg) {
		t.Fatal("有 REALITY 且 [smux] 时应启用")
	}
	cfg.Reality.ListenAddr = ""
	cfg.Hysteria.Password = "p"
	cfg.Hysteria.TLSCertFile = "c.pem"
	cfg.Hysteria.TLSKeyFile = "k.pem"
	if !loopbackSmuxMultiplexEnabled(cfg) {
		t.Fatal("hy2 三项配齐且 [smux] 时应启用")
	}
	cfg.Smux = nil
	if loopbackSmuxMultiplexEnabled(cfg) {
		t.Fatal("无 [smux] 时不应启用")
	}
}

// TestLoopbackSmuxMagicAndSession 验证 VPN1 前缀 + smux 在单条 TCP 上可建立 stream（与环回池行为一致）。
func TestLoopbackSmuxMagicAndSession(t *testing.T) {
	muxCfg := smux.DefaultConfig()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer c.Close()
		br := bufio.NewReaderSize(c, 256)
		head, err := br.Peek(4)
		if err != nil {
			errCh <- err
			return
		}
		if !bytes.Equal(head, loopbackSmuxMagic) {
			errCh <- io.ErrUnexpectedEOF
			return
		}
		if _, err := br.Discard(4); err != nil {
			errCh <- err
			return
		}
		wrapped := &connBufCloser{Conn: c, r: br}
		srvSess, err := smux.Server(wrapped, muxCfg)
		if err != nil {
			errCh <- err
			return
		}
		defer srvSess.Close()
		st, err := srvSess.AcceptStream()
		if err != nil {
			errCh <- err
			return
		}
		defer st.Close()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(st, buf); err != nil {
			errCh <- err
			return
		}
		if _, err := st.Write(buf); err != nil {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(loopbackSmuxMagic); err != nil {
		t.Fatalf("magic: %v", err)
	}
	cliSess, err := smux.Client(conn, muxCfg)
	if err != nil {
		t.Fatalf("smux.Client: %v", err)
	}
	defer cliSess.Close()
	st, err := cliSess.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer st.Close()
	payload := []byte("ping")
	if _, err := st.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	out := make([]byte, len(payload))
	if _, err := io.ReadFull(st, out); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(out) != string(payload) {
		t.Fatalf("echo 不匹配: %q", out)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("服务端: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("超时")
	}
}

func TestLoopbackSmuxPoolOpenStream(t *testing.T) {
	muxCfg := smux.DefaultConfig()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	const path = "/pool-smux-test/v1/feed"
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		ws, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		nc := util.NewWSStreamConn(ws)
		defer nc.Close()
		br := bufio.NewReaderSize(nc, 256)
		head, err := br.Peek(4)
		if err != nil || len(head) < 4 || !bytes.Equal(head[:4], loopbackSmuxMagic) {
			return
		}
		_, _ = br.Discard(4)
		wrapped := &connBufCloser{Conn: nc, r: br}
		sess, err := smux.Server(wrapped, muxCfg)
		if err != nil {
			return
		}
		defer sess.Close()
		for {
			st, err := sess.AcceptStream()
			if err != nil {
				return
			}
			go func(s *smux.Stream) {
				defer s.Close()
				_, _ = io.Copy(s, s)
			}(st)
		}
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()

	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	if !strings.HasPrefix(ln.Addr().String(), "127.0.0.1:") {
		t.Fatalf("期望 127.0.0.1 监听，得到 %v", ln.Addr())
	}
	wsURL := "ws://127.0.0.1:" + portStr + path
	pool := newLoopbackSmuxPool(wsURL, muxCfg, nil)
	st, err := pool.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer st.Close()
	msg := []byte("hello-smux-pool")
	if _, err := st.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	back := make([]byte, len(msg))
	if _, err := io.ReadFull(st, back); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(back) != string(msg) {
		t.Fatalf("回显: %q", back)
	}
	_ = st.Close()
	_ = pool // 会话由 watchSession 清理
}
