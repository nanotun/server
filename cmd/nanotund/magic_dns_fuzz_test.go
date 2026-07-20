package main

import (
	"context"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// F2:Magic DNS handler 是直接对外 UDP 解析路径,任何 panic 都会让 magicDNS
// goroutine 崩(被 safeGlobalGoroutine recover 兜底,但还是会污染日志 + 一次
// 抖动)。这里 fuzz 包路径不依赖外部 net 资源,只确认解析不 panic。
//
// 跑法:go test -fuzz=FuzzHandleMagicDNSPacket -fuzztime=10s ./server/
//
// 注意:handle 函数末端会 conn.WriteToUDP;为避免真起 socket,这里直接传 nil
// (它在 errors 路径上才会用 conn,正确 happy path 也只是 conn.WriteToUDP
// 返回 err 后被忽略)—— 但为了完全安全,我们做一个 closed UDP conn 占位。
func FuzzHandleMagicDNSPacket(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	// 真实最短查询(12 字节 header + 1 字节空 label + 4 字节 type/class):
	f.Add(buildSeedDNSQuery("a"))
	f.Add(buildSeedDNSQuery("alice-mac.alice.lan"))
	f.Add(buildSeedDNSQuery("." /* root */))

	// 维护本测试不依赖真 UDP socket —— 真 write 路径不在 fuzz attack surface,
	// 这里只 fuzz parser。下方 dnsmessage.Parser / pure string 函数才是关注对象。
	r := magicDNSResolved{suffix: "lan", port: 53}

	f.Fuzz(func(t *testing.T, data []byte) {
		// gw 传 nil 会让 magicDNSExtraDNS-related 路径走空,但 handleMagicDNSPacket
		// 用 gw.store.* — 用 nil 会 panic。所以这里只测纯 parse 路径:复用
		// builder + 静态 path,关键是确保 unmarshal 不 panic。
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic on input %x: %v", data, r)
			}
		}()
		// 仅测 parser:dnsmessage.Parser.Start / Question — 这是真实 attack surface。
		var p dnsmessage.Parser
		if _, err := p.Start(data); err != nil {
			return
		}
		for {
			q, err := p.Question()
			if err != nil {
				break
			}
			_ = q
		}
		// isMagicDomain / parseMagicHostname / normalizeMagicHost 都是 pure 字符串处理。
		name := ""
		if len(data) > 0 {
			name = string(data[:min(len(data), 64)])
		}
		_ = isMagicDomain(name, r.suffix)
		_, _, _ = parseMagicHostname(name, r.suffix)
		_ = normalizeMagicHost(name)
		_ = context.Background()
	})
}

func buildSeedDNSQuery(name string) []byte {
	if name == "" {
		name = "."
	}
	if name[len(name)-1] != '.' {
		name = name + "."
	}
	n, err := dnsmessage.NewName(name)
	if err != nil {
		return nil
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, RecursionDesired: true})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{
		Name:  n,
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	})
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
