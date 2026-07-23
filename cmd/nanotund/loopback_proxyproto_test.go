package main

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtaci/smux"
)

// TestLoopbackProxyHeaderRoundTrip 验证 M1:环回 smux stream 开头写的 PROXY v2 头能被服务端
// readLoopbackClientAddr 还原成真实客户端源地址(REALITY 场景),LOCAL 头则回退环回地址(hy2 场景)。
func TestLoopbackProxyHeaderRoundTrip(t *testing.T) {
	cases := []struct {
		name       string
		writeLocal bool         // true 走 LOCAL(无源)头
		src        *net.TCPAddr // writeLocal=false 时透传的真实源
		wantRemote string       // 期望 readLoopbackClientAddr 后 RemoteAddr().String();空=回退底层
	}{
		{
			name:       "reality_v4_source_threaded",
			src:        &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 51234},
			wantRemote: "203.0.113.7:51234",
		},
		{
			name:       "reality_v6_source_threaded",
			src:        &net.TCPAddr{IP: net.ParseIP("2001:db8::abcd"), Port: 40000},
			wantRemote: "[2001:db8::abcd]:40000",
		},
		{
			name:       "hy2_local_header_falls_back",
			writeLocal: true, // 无源 → 回退底层环回地址
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			muxCfg := smux.DefaultConfig()
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("Listen: %v", err)
			}
			defer ln.Close()

			payload := []byte("hello-after-proxy-header")
			resultCh := make(chan string, 1) // 服务端观察到的 RemoteAddr()

			go func() {
				c, err := ln.Accept()
				if err != nil {
					resultCh <- "accept-err:" + err.Error()
					return
				}
				defer c.Close()
				sess, err := smux.Server(c, muxCfg)
				if err != nil {
					resultCh <- "smux-server-err:" + err.Error()
					return
				}
				defer sess.Close()
				st, err := sess.AcceptStream()
				if err != nil {
					resultCh <- "accept-stream-err:" + err.Error()
					return
				}
				// 服务端路径:先读 PROXY 头包装,再读随后的应用字节。
				wrapped := readLoopbackClientAddr(st)
				got := make([]byte, len(payload))
				if _, err := io.ReadFull(wrapped, got); err != nil {
					resultCh <- "read-payload-err:" + err.Error()
					return
				}
				if string(got) != string(payload) {
					resultCh <- "payload-mismatch:" + string(got)
					return
				}
				resultCh <- wrapped.RemoteAddr().String()
			}()

			conn, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			defer conn.Close()
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

			// 客户端(bridge)侧:先写 PROXY 头,再写应用字节。
			if tc.writeLocal {
				if err := writeLoopbackProxyHeaderLocal(st); err != nil {
					t.Fatalf("writeLocal: %v", err)
				}
			} else {
				dst := &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 443}
				if err := writeLoopbackProxyHeader(st, tc.src, dst); err != nil {
					t.Fatalf("writeHeader: %v", err)
				}
			}
			if _, err := st.Write(payload); err != nil {
				t.Fatalf("write payload: %v", err)
			}

			select {
			case got := <-resultCh:
				if tc.wantRemote != "" {
					if got != tc.wantRemote {
						t.Fatalf("RemoteAddr = %q, want %q", got, tc.wantRemote)
					}
				} else {
					// LOCAL 头:应回退底层环回地址(127.0.0.1:<port>),而非某个真实源。
					host, _, splitErr := net.SplitHostPort(got)
					if splitErr != nil || host != "127.0.0.1" {
						t.Fatalf("LOCAL 头应回退环回地址,得到 %q", got)
					}
				}
			case <-time.After(5 * time.Second):
				t.Fatal("超时:服务端未返回结果")
			}
		})
	}
}

// TestReadLoopbackClientAddrPreservesBufferedBytes 直接验证:读头后残留在 bufio 里的字节不丢。
func TestReadLoopbackClientAddrPreservesBufferedBytes(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	src := &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 12345}
	dst := &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 443}
	body := []byte("frame-bytes-immediately-after-header")

	go func() {
		// 头 + body 连续写出,尽量让服务端一次读进 bufio 缓冲。
		_ = writeLoopbackProxyHeader(cli, src, dst)
		_, _ = cli.Write(body)
	}()

	wrapped := readLoopbackClientAddr(srv)
	if got := wrapped.RemoteAddr().String(); got != "203.0.113.9:12345" {
		t.Fatalf("RemoteAddr = %q, want 203.0.113.9:12345", got)
	}
	_ = wrapped.SetReadDeadline(time.Now().Add(3 * time.Second))
	got := make([]byte, len(body))
	if _, err := io.ReadFull(wrapped, got); err != nil {
		t.Fatalf("ReadFull body: %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("body = %q, want %q", got, body)
	}
}

// fakeAddrConn 是一个 RemoteAddr() 可控的最小 net.Conn 桩,用于 isLoopbackConnPeer / dispatch 测试。
type fakeAddrConn struct {
	net.Conn
	remote net.Addr
	closed bool
}

func (c *fakeAddrConn) RemoteAddr() net.Addr { return c.remote }
func (c *fakeAddrConn) Close() error {
	c.closed = true
	if c.Conn != nil {
		return c.Conn.Close()
	}
	return nil
}

func tcpAddr(s string) net.Addr {
	a, _ := net.ResolveTCPAddr("tcp", s)
	return a
}

func TestIsLoopbackConnPeer(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:5555", true},
		{"127.0.0.9:80", true},
		{"[::1]:5555", true},
		{"10.0.0.2:5555", false},
		{"203.0.113.7:443", false},
		{"[2001:db8::1]:443", false},
		{"0.0.0.0:80", false},
	}
	for _, tc := range cases {
		got := isLoopbackConnPeer(&fakeAddrConn{remote: tcpAddr(tc.addr)})
		if got != tc.want {
			t.Errorf("isLoopbackConnPeer(%s) = %v, want %v", tc.addr, got, tc.want)
		}
	}
	if isLoopbackConnPeer(&fakeAddrConn{remote: nil}) {
		t.Error("nil RemoteAddr should not be loopback")
	}
}

// TestDispatchRejectsForeignVPN1 验证:muxEnabled 下,非环回对端发来的 VPN1 承载被拒绝并关闭,
// 不进入 smux/PROXY 解析路径(M1 加固,防伪造源地址绕过按 IP 反滥用)。
func TestDispatchRejectsForeignVPN1(t *testing.T) {
	before := loopbackSmuxForeignRejectCount.Load()

	// server 侧 pipe 端预置 VPN1 魔法,RemoteAddr 伪装成公网地址。
	srvPipe, cliPipe := net.Pipe()
	fc := &fakeAddrConn{Conn: srvPipe, remote: tcpAddr("203.0.113.50:40000")}
	go func() {
		_, _ = cliPipe.Write(loopbackSmuxMagic)
		_, _ = cliPipe.Write([]byte("would-be-smux-frames"))
	}()

	done := make(chan struct{})
	go func() {
		dispatchVPNIncoming(fc, nil, true, smux.DefaultConfig())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("dispatchVPNIncoming 未在预期时间内返回(应立即拒绝)")
	}
	if !fc.closed {
		t.Error("非环回 VPN1 连接应被 Close")
	}
	if loopbackSmuxForeignRejectCount.Load() != before+1 {
		t.Errorf("loopbackSmuxForeignRejectCount 应 +1,got before=%d after=%d", before, loopbackSmuxForeignRejectCount.Load())
	}
	_ = cliPipe.Close()
}
