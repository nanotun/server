package main_test

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/nanotun/server/util"
	"github.com/xtaci/kcp-go/v5"
)

// 与 server-simple 等 KCP 压测参数同量级（非主 server 的 config.toml）
const (
	benchDataShards   = 0
	benchParityShards = 0
	benchCrypt        = "aes-128"
	benchNoDelay      = 1
	benchInterval     = 20
	benchResend       = 2
	benchNC           = 1
	benchMTU          = 1350
	benchSndWnd       = 4096
	benchRcvWnd       = 4096
	benchStream       = 1
	benchTotalMB      = 500
	benchChunkSize    = 64 * 1024 // 64KB
)

// Normal 模式 + NewConn 仅支持 none 加密；aes-128 需 Custom+NewConn3WithSalt 会卡住
var benchCryptTest = "none"
var benchKeyTest = []byte("")

// TestKCPBench_500MB 启动一个 KCP 服务端和一个客户端，客户端发送 500MB 数据，服务端只读不回，统计吞吐。
func TestKCPBench_500MB(t *testing.T) {
	totalBytes := int64(benchTotalMB) * 1024 * 1024
	block, err := util.NewKCPBlockCrypt(benchCryptTest, string(benchKeyTest))
	if err != nil {
		t.Fatalf("NewKCPBlockCrypt: %v", err)
	}

	// 用 Normal 模式（ListenWithOptions），Custom 需要服务端 conv→salt 映射，测试里没有会卡住
	listener, err := kcp.ListenWithOptions("127.0.0.1:0", block, benchDataShards, benchParityShards)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()
	addr := listener.Addr().String()
	t.Logf("KCP 服务端监听: %s", addr)

	var serverDone sync.WaitGroup
	serverDone.Add(1)
	var serverReceived int64
	var serverErr error
	go func() {
		defer serverDone.Done()
		conn, err := listener.AcceptKCP()
		if err != nil {
			serverErr = err
			return
		}
		defer conn.Close()
		conn.SetNoDelay(benchNoDelay, benchInterval, benchResend, benchNC)
		conn.SetMtu(benchMTU)
		conn.SetWindowSize(benchSndWnd, benchRcvWnd)
		//lint:ignore SA1019 KCP 库标 deprecated 但仍可用,bench 路径继续保留以对比历史结果
		conn.SetStreamMode(benchStream == 1)
		conn.SetReadBuffer(4 * 1024 * 1024)
		conn.SetWriteBuffer(4 * 1024 * 1024)
		buf := make([]byte, 256*1024)
		for serverReceived < totalBytes {
			n, err := conn.Read(buf)
			if err != nil {
				if err != io.EOF {
					serverErr = err
				}
				return
			}
			serverReceived += int64(n)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	udpConn, err := net.ListenPacket("udp", "")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer udpConn.Close()
	// Normal 模式用 NewConn，无需 salt
	kcpConn, err := kcp.NewConn(addr, block, benchDataShards, benchParityShards, udpConn)
	if err != nil {
		t.Fatalf("NewConn: %v", err)
	}
	defer kcpConn.Close()
	kcpConn.SetNoDelay(benchNoDelay, benchInterval, benchResend, benchNC)
	kcpConn.SetMtu(benchMTU)
	kcpConn.SetWindowSize(benchSndWnd, benchRcvWnd)
	//lint:ignore SA1019 KCP 库标 deprecated 但仍可用,bench 路径继续保留以对比历史结果
	kcpConn.SetStreamMode(benchStream == 1)
	kcpConn.SetReadBuffer(4 * 1024 * 1024)
	kcpConn.SetWriteBuffer(4 * 1024 * 1024)

	chunk := make([]byte, benchChunkSize)
	start := time.Now()
	var sent int64
	for sent < totalBytes {
		n := int64(len(chunk))
		if sent+n > totalBytes {
			n = totalBytes - sent
		}
		w, err := kcpConn.Write(chunk[:n])
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
		sent += int64(w)
	}
	// 等服务端读完再关连接，否则服务端会少收数据
	serverDone.Wait()
	if err := kcpConn.Close(); err != nil {
		// 忽略
	}
	elapsed := time.Since(start)
	if serverErr != nil {
		t.Logf("服务端读错误（可能因 Close）: %v", serverErr)
	}
	if serverReceived != totalBytes {
		t.Logf("服务端收到 %d 字节，期望 %d", serverReceived, totalBytes)
	}
	mb := float64(sent) / (1024 * 1024)
	mbps := mb / elapsed.Seconds()
	t.Logf("发送 %d MB 完成，耗时 %v，吞吐 %.2f MB/s", benchTotalMB, elapsed.Round(time.Millisecond), mbps)
}
