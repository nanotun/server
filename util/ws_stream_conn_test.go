package util

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// WSStreamConn 是把 WebSocket 当 TCP 流用的适配层:smux 和链路帧都跑在它上面。
// 「Binary 消息边界 ≠ Read 边界」这条语义要是错了,链路帧会从第二个包开始全部错位。

func wsEchoPair(t *testing.T, handle func(*websocket.Conn)) net.Conn {
	t.Helper()
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		handle(c)
	}))
	t.Cleanup(srv.Close)

	client, err := DialVPNWebSocket("ws"+strings.TrimPrefix(srv.URL, "http"), 5*time.Second, nil)
	if err != nil {
		t.Fatalf("DialVPNWebSocket: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestWSStreamConn_ReadIsAByteStreamNotAMessageQueue(t *testing.T) {
	// 服务端故意分三条 Binary 发,客户端应当看到一条连续字节流。
	conn := wsEchoPair(t, func(c *websocket.Conn) {
		for _, part := range []string{"abc", "de", "fghij"} {
			if err := c.WriteMessage(websocket.BinaryMessage, []byte(part)); err != nil {
				return
			}
		}
		// 等对端读完再关,免得 Close 抢在数据前面。
		_, _, _ = c.ReadMessage()
	})

	got := make([]byte, 10)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(got) != "abcdefghij" {
		t.Fatalf("got %q —— 消息边界漏进了流语义,链路帧会从第二帧起全部错位", got)
	}

	// 小 buffer 分多次读同一条消息,剩余字节必须留在 readBuf 里。
	conn2 := wsEchoPair(t, func(c *websocket.Conn) {
		_ = c.WriteMessage(websocket.BinaryMessage, []byte("0123456789"))
		_, _, _ = c.ReadMessage()
	})
	var acc bytes.Buffer
	buf := make([]byte, 3)
	for acc.Len() < 10 {
		n, err := conn2.Read(buf)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		acc.Write(buf[:n])
	}
	if acc.String() != "0123456789" {
		t.Fatalf("分段读拼出来 %q", acc.String())
	}
}

func TestWSStreamConn_TextMessagesAreRejected(t *testing.T) {
	// 数据面只跑 Binary。收到 Text 说明对端不是我们的客户端(或中间有代理在改帧),
	// 当成字节流吞下去只会让上层解出乱码帧。
	conn := wsEchoPair(t, func(c *websocket.Conn) {
		_ = c.WriteMessage(websocket.TextMessage, []byte("hello"))
		_, _, _ = c.ReadMessage()
	})
	if _, err := conn.Read(make([]byte, 16)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("err=%v,期望 io.ErrUnexpectedEOF", err)
	}
}

func TestWSStreamConn_WriteIsOneMessagePerCallAndZeroLengthIsANoop(t *testing.T) {
	msgs := make(chan []byte, 4)
	conn := wsEchoPair(t, func(c *websocket.Conn) {
		for {
			mt, data, err := c.ReadMessage()
			if err != nil {
				close(msgs)
				return
			}
			if mt == websocket.BinaryMessage {
				msgs <- append([]byte(nil), data...)
			}
		}
	})

	// 空写不该产生一条空 Binary —— 对端会把它当成一个 0 字节的帧来处理。
	if n, err := conn.Write(nil); n != 0 || err != nil {
		t.Fatalf("空写 got (%d,%v)", n, err)
	}
	for _, s := range []string{"first", "second"} {
		if n, err := conn.Write([]byte(s)); n != len(s) || err != nil {
			t.Fatalf("Write(%q) got (%d,%v)", s, n, err)
		}
	}

	for _, want := range []string{"first", "second"} {
		select {
		case got := <-msgs:
			if string(got) != want {
				t.Fatalf("收到 %q,期望 %q —— 一次 Write 应恰好一条 Binary", got, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("等 %q 超时", want)
		}
	}
}

func TestWSStreamConn_ReadLimitIsSetSoAHugeFrameCannotBlowUpMemory(t *testing.T) {
	// gorilla 默认 ReadLimit=0(不限),不显式设上限就是个 DoS 面:对端声称
	// 一条 1GB 的帧,我们就 alloc 1GB。
	conn := wsEchoPair(t, func(c *websocket.Conn) {
		_ = c.WriteMessage(websocket.BinaryMessage, make([]byte, WSReadLimitBytes+1))
		_, _, _ = c.ReadMessage()
	})
	if _, err := conn.Read(make([]byte, 64)); err == nil {
		t.Fatal("超过 WSReadLimitBytes 的单帧应当报错")
	}
}

func TestWSStreamConn_ExposesTheNetConnSurfaceCallersRelyOn(t *testing.T) {
	conn := wsEchoPair(t, func(c *websocket.Conn) { _, _, _ = c.ReadMessage() })

	if conn.LocalAddr() == nil || conn.RemoteAddr() == nil {
		t.Fatal("地址拿不到 —— 日志和限速都按 RemoteAddr 归因")
	}
	ws, ok := conn.(*WSStreamConn)
	if !ok {
		t.Fatalf("类型 %T", conn)
	}
	if ws.UnderlyingConn() == nil {
		t.Fatal("拿不到底层 TCP conn,就没法开 keepalive")
	}

	// SetDeadline 要同时管住读和写,否则「设了超时却卡死在 Write 上」。
	if err := conn.SetDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if _, err := conn.Read(make([]byte, 4)); err == nil {
		t.Fatal("读该超时")
	}
	if _, err := conn.Write([]byte("x")); err == nil {
		t.Fatal("写该超时")
	}

	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("清读超时: %v", err)
	}
	if err := conn.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatalf("清写超时: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestDialVPNWebSocket_ReportsHandshakeFailuresInsteadOfHangingForever(t *testing.T) {
	t.Run("对端不是 WebSocket", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTeapot)
		}))
		defer srv.Close()
		if c, err := DialVPNWebSocket("ws"+strings.TrimPrefix(srv.URL, "http"), 5*time.Second, nil); err == nil {
			_ = c.Close()
			t.Fatal("应当报握手失败")
		}
	})

	t.Run("地址不通", func(t *testing.T) {
		if c, err := DialVPNWebSocket("ws://127.0.0.1:1/x", 500*time.Millisecond, nil); err == nil {
			_ = c.Close()
			t.Fatal("应当报错")
		}
	})

	t.Run("wss 自签靠 tlsClient 放行", func(t *testing.T) {
		up := websocket.Upgrader{}
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := up.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer c.Close()
			_, _, _ = c.ReadMessage()
		}))
		defer srv.Close()
		url := "wss" + strings.TrimPrefix(srv.URL, "https")

		// 不给 tlsClient:自签证书验不过,必须失败 —— 这条是环回桥接之外的场景的安全底线。
		if c, err := DialVPNWebSocket(url, 5*time.Second, nil); err == nil {
			_ = c.Close()
			t.Fatal("自签证书在没配 tlsClient 时不该被接受")
		}
		c, err := DialVPNWebSocket(url, 5*time.Second, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // 环回自签
		if err != nil {
			t.Fatalf("配了 InsecureSkipVerify 还连不上: %v", err)
		}
		_ = c.Close()
	})
}
