package util

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"hash/crc32"
	"net"
	"strings"
	"testing"
	"time"
)

// 记录层的读路径是**对端可以任意构造**的字节:攻击者控制 TCP 连接上的每一个 bit。
// 原有测试全是「自己写自己读」的往返,所有校验分支都走的是合法帧,于是帧长校验、
// nonce 方向前缀比对、序号比对这三道防线一次都没被执行过。
//
// 这三道各自防的是不同的东西,坏了都不报错:
//   - 帧长校验:挡的是 `make([]byte, frameLen)` 按对端给的长度分配内存。没有它,
//     四个字节的头就能让服务端分配 4 GB。
//   - 方向前缀:AEAD 的 nonce 前 4 字节按方向固定(服务端发 BHPS、客户端发 BHPC),
//     读端只接受对向前缀。没有它,把服务端自己发出的帧原样打回去会被当成合法入站帧
//     —— 反射。
//   - 序号比对:序号严格递增。没有它,录下一帧反复重放都能通过 AEAD 验签(nonce 没变,
//     密文当然解得开)。
//
// 下面按「构造敌意帧 → 断言被拒」来测,而不是靠往返。

// rawWire 建一对 net.Pipe:返回被测的记录层连接,以及可以往里灌任意字节的裸端。
func rawWire(t *testing.T, crypt string, key []byte, isServer bool, maxPlain int) (*TCPRecordConn, net.Conn) {
	t.Helper()
	wire, inner := net.Pipe()
	rc, err := NewTCPRecordConn(inner, crypt, key, isServer, maxPlain)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wire.Close(); _ = inner.Close() })
	_ = wire.SetDeadline(time.Now().Add(5 * time.Second))
	return rc, wire
}

// feed 把 raw 灌进裸端,返回记录层读到的结果。
//
// net.Pipe 是无缓冲的,写会阻塞到被读走;而这些用例恰恰要测「读端提前报错、不去读 body」,
// 所以写必须放在另一个 goroutine 里,并靠上面的 deadline 兜底。
func feed(t *testing.T, rc *TCPRecordConn, wire net.Conn, raw []byte, thenClose bool) error {
	t.Helper()
	go func() {
		_, _ = wire.Write(raw)
		if thenClose {
			_ = wire.Close()
		}
	}()
	buf := make([]byte, 4096)
	_, err := rc.Read(buf)
	return err
}

// hdr 造一个只有 4 字节长度头的「帧」。帧长校验在读 body 之前,所以不需要 body。
func hdr(frameLen uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, frameLen)
	return b
}

// sealAEADFrame 手工封一个 AEAD 帧,方向前缀与序号都可以随便指定。
func sealAEADFrame(t *testing.T, key []byte, prefix string, seq uint64, pt []byte) []byte {
	t.Helper()
	blk, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	copy(nonce[:4], prefix)
	binary.BigEndian.PutUint64(nonce[4:], seq)
	sealed := gcm.Seal(nil, nonce, pt, nil)
	total := len(nonce) + len(sealed)
	out := make([]byte, 4+total)
	binary.BigEndian.PutUint32(out[:4], uint32(total))
	copy(out[4:], nonce)
	copy(out[4+len(nonce):], sealed)
	return out
}

// TestTCPRecordRead_RejectsFrameLengthOutOfRange 三条读路径各自的帧长闸门。
//
// 上限那半是内存 DoS 的唯一防线:`make([]byte, frameLen)` 就在检查的下一行。
// 下限那半挡的是「短到不可能装下 nonce/头部」的帧,放过去会在后面切片越界。
func TestTCPRecordRead_RejectsFrameLengthOutOfRange(t *testing.T) {
	const maxPlain = 4096

	t.Run("aead", func(t *testing.T) {
		key := makeKey(32)
		// nonce 12 + GCM tag 16 = 28 是最小合法帧;27 太短。
		for _, bad := range []uint32{0, 27, uint32(12 + maxPlain + 16 + 1), 1 << 30} {
			rc, wire := rawWire(t, "aes-256-gcm", key, true, maxPlain)
			err := feed(t, rc, wire, hdr(bad), true)
			if err == nil {
				t.Errorf("AEAD 帧长 %d 越界却被接受 —— 下一行就按它分配内存", bad)
				continue
			}
			if !strings.Contains(err.Error(), "invalid AEAD frame length") {
				t.Errorf("AEAD 帧长 %d 应报帧长非法,实得:%v", bad, err)
			}
		}
	})

	t.Run("block", func(t *testing.T) {
		key := makeKey(32)
		// cfbHeaderSize = 16 + 4 = 20 是最小合法帧。
		for _, bad := range []uint32{0, 19, uint32(20 + maxPlain + 1), 1 << 30} {
			rc, wire := rawWire(t, "aes-256", key, true, maxPlain)
			err := feed(t, rc, wire, hdr(bad), true)
			if err == nil {
				t.Errorf("block 帧长 %d 越界却被接受", bad)
				continue
			}
			if !strings.Contains(err.Error(), "invalid block frame length") {
				t.Errorf("block 帧长 %d 应报帧长非法,实得:%v", bad, err)
			}
		}
	})

	t.Run("none", func(t *testing.T) {
		// none 模式没有加密头,0 长帧也非法(空帧会让上层收到 0 字节读,像 EOF)。
		for _, bad := range []uint32{0, uint32(maxPlain + 1), 1 << 30} {
			rc, wire := rawWire(t, "none", nil, true, maxPlain)
			err := feed(t, rc, wire, hdr(bad), true)
			if err == nil {
				t.Errorf("none 帧长 %d 越界却被接受", bad)
				continue
			}
			if !strings.Contains(err.Error(), "invalid none frame length") {
				t.Errorf("none 帧长 %d 应报帧长非法,实得:%v", bad, err)
			}
		}
	})
}

// TestTCPRecordRead_RejectsWrongNonceDirectionPrefix 反射:把服务端方向的帧打回服务端。
//
// 服务端发出的帧 nonce 前缀是 BHPS,它只接受 BHPC。少了这道比对,攻击者把抓到的
// 服务端出站帧原样回灌,AEAD 验签会**通过**(密钥和 nonce 都没变),服务端于是把
// 自己刚说过的话当成对端说的。
func TestTCPRecordRead_RejectsWrongNonceDirectionPrefix(t *testing.T) {
	key := makeKey(32)
	rc, wire := rawWire(t, "aes-256-gcm", key, true, 4096)

	err := feed(t, rc, wire, sealAEADFrame(t, key, "BHPS", 1, []byte("reflected")), true)
	if err == nil {
		t.Fatal("服务端接受了自己方向前缀的帧 —— 反射攻击可行")
	}
	if !strings.Contains(err.Error(), "direction prefix mismatch") {
		t.Errorf("应报方向前缀不符,实得:%v", err)
	}
}

// TestTCPRecordRead_AcceptsCorrectDirectionPrefix 反面:对向前缀必须放行。
//
// 和上一条配对。只测「错前缀被拒」的话,一个「所有帧都拒」的实现照样绿。
func TestTCPRecordRead_AcceptsCorrectDirectionPrefix(t *testing.T) {
	key := makeKey(32)
	rc, wire := rawWire(t, "aes-256-gcm", key, true, 4096)

	if err := feed(t, rc, wire, sealAEADFrame(t, key, "BHPC", 1, []byte("hi")), true); err != nil {
		t.Fatalf("客户端方向的合法帧被拒:%v", err)
	}
}

// TestTCPRecordRead_RejectsNonceSeqMismatch 重放与乱序。
//
// 序号必须严格递增。两种攻击共用这一道防线:
//   - 跳号(第一帧就送 seq=2):说明中间有帧被吞掉或被重排;
//   - 重放(同一帧送两次):第二次期望 seq=2 而收到 1。
//
// 注意重放这条 AEAD 本身**拦不住** —— nonce 和密文都没变,Open 一定成功。挡住它的
// 只有这个序号比对。
func TestTCPRecordRead_RejectsNonceSeqMismatch(t *testing.T) {
	key := makeKey(32)

	t.Run("跳号", func(t *testing.T) {
		rc, wire := rawWire(t, "aes-256-gcm", key, true, 4096)
		err := feed(t, rc, wire, sealAEADFrame(t, key, "BHPC", 2, []byte("skipped")), true)
		if err == nil {
			t.Fatal("首帧 seq=2 被接受 —— 丢帧/重排不再可检测")
		}
		if !strings.Contains(err.Error(), "seq mismatch") {
			t.Errorf("应报序号不符,实得:%v", err)
		}
	})

	t.Run("重放", func(t *testing.T) {
		rc, wire := rawWire(t, "aes-256-gcm", key, true, 4096)
		frame := sealAEADFrame(t, key, "BHPC", 1, []byte("once"))
		if err := feed(t, rc, wire, frame, false); err != nil {
			t.Fatalf("第一次投递就失败:%v", err)
		}
		if err := feed(t, rc, wire, frame, true); err == nil {
			t.Fatal("同一帧重放被接受 —— AEAD 拦不住重放,这里是唯一防线")
		}
	})
}

// TestTCPRecordAEAD_SeqWrapsPastZero 序号回绕跳过 0。
//
// 读写两侧都有 `if seq == 0 { seq = 1 }`:2^64 次之后自增回 0,而 0 被约定为
// 「未使用」。两侧必须**同样**跳过,否则回绕的那一刻双方错位一格,此后每一帧都
// 序号不符 —— 连接直接断,且只在跑满 2^64 帧后出现,现场无法复现。
func TestTCPRecordAEAD_SeqWrapsPastZero(t *testing.T) {
	key := makeKey(32)

	t.Run("写侧", func(t *testing.T) {
		rc, wire := rawWire(t, "aes-256-gcm", key, false, 4096)
		rc.wSeq = ^uint64(0)
		go func() {
			buf := make([]byte, 256)
			_, _ = wire.Read(buf)
		}()
		if _, err := rc.Write([]byte("wrap")); err != nil {
			t.Fatal(err)
		}
		if rc.wSeq != 1 {
			t.Errorf("回绕后写序号应跳过 0 取 1,实得 %d", rc.wSeq)
		}
	})

	t.Run("读侧", func(t *testing.T) {
		rc, wire := rawWire(t, "aes-256-gcm", key, true, 4096)
		rc.rSeq = ^uint64(0)
		if err := feed(t, rc, wire, sealAEADFrame(t, key, "BHPC", 1, []byte("wrap")), true); err != nil {
			t.Fatalf("回绕后读侧应期望 seq=1,却拒了:%v", err)
		}
	})
}

// TestTCPRecordRead_TruncatedFrame 头部或负载被截断时应报错而不是当成空帧。
func TestTCPRecordRead_TruncatedFrame(t *testing.T) {
	key := makeKey(32)

	t.Run("头部截断", func(t *testing.T) {
		rc, wire := rawWire(t, "aes-256-gcm", key, true, 4096)
		if err := feed(t, rc, wire, []byte{0, 0}, true); err == nil {
			t.Fatal("只有 2 字节头也被当成完整帧")
		}
	})

	t.Run("负载截断_aead", func(t *testing.T) {
		rc, wire := rawWire(t, "aes-256-gcm", key, true, 4096)
		full := sealAEADFrame(t, key, "BHPC", 1, []byte("payload"))
		if err := feed(t, rc, wire, full[:len(full)-3], true); err == nil {
			t.Fatal("负载少 3 字节仍被接受")
		}
	})

	t.Run("负载截断_block", func(t *testing.T) {
		rc, wire := rawWire(t, "aes-256", key, true, 4096)
		if err := feed(t, rc, wire, append(hdr(64), make([]byte, 10)...), true); err == nil {
			t.Fatal("block 负载不足仍被接受")
		}
	})

	t.Run("负载截断_none", func(t *testing.T) {
		rc, wire := rawWire(t, "none", nil, true, 4096)
		if err := feed(t, rc, wire, append(hdr(64), make([]byte, 10)...), true); err == nil {
			t.Fatal("none 负载不足仍被接受")
		}
	})
}

// TestNewTCPRecordConn_ClampsMaxPlaintext 明文上限的兜底与硬顶。
//
// 这两条决定了上面帧长校验的 maxFrame。取 0 时若不回落到默认值,maxFrame 会退化成
// 「只剩 nonce 和 tag」,一帧数据都收不了;不设硬顶则调用方一个笔误就能把内存闸门开到天上。
func TestNewTCPRecordConn_ClampsMaxPlaintext(t *testing.T) {
	for _, tc := range []struct{ in, want int }{
		{0, DefaultMaxPlaintext},
		{-1, DefaultMaxPlaintext},
		{maxPlaintextHardCap + 1, maxPlaintextHardCap},
		{1 << 30, maxPlaintextHardCap},
		{4096, 4096},
	} {
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		c, err := NewTCPRecordConn(b, "none", nil, true, tc.in)
		if err != nil {
			t.Fatal(err)
		}
		if c.maxPlain != tc.want {
			t.Errorf("maxPlaintext=%d 应钳到 %d,实得 %d", tc.in, tc.want, c.maxPlain)
		}
	}
}

// TestNewTCPRecordConn_RejectsBadConfig 建连参数不合法时必须失败而不是降级。
//
// 两条路径的错误各自加了前缀(aead / block),这是唯一能从日志区分「坏在哪一侧」的线索;
// 少了前缀,底层库那句原始错误(比如 "invalid key size 17")看不出是记录层还是别处。
//
// 顺带记一件测的时候才发现的事:**block 路径不会因为密钥太短而报错**。
// NewKCPBlockCrypt 里的 keyBytes() 会把短密钥零填充到算法要求的长度 —— 3 字节的 key
// 会变成 32 字节里 29 个零,静默地弱化。所以这一族只有算法名不认识时才失败,
// 用「密钥长度」去测 block 路径的错误分支会得到一个假绿。AEAD 那侧则相反:
// aes.NewCipher 严格只收 16/24/32,短密钥当场报错。
func TestNewTCPRecordConn_RejectsBadConfig(t *testing.T) {
	for _, tc := range []struct {
		desc, crypt, wantPrefix string
		key                     []byte
	}{
		{"AEAD 密钥长度非法", "aes-256-gcm", "tcp record aead", makeKey(17)},
		{"算法名不认识", "rot13", "tcp record block", makeKey(32)},
	} {
		a, b := net.Pipe()
		c, err := NewTCPRecordConn(b, tc.crypt, tc.key, true, 4096)
		_ = a.Close()
		_ = b.Close()
		if err == nil {
			t.Errorf("%s(crypt=%q)竟建连成功(得到 %v) —— 应当拒绝而非降级", tc.desc, tc.crypt, c)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantPrefix) {
			t.Errorf("%s 的错误应带 %q 前缀以便定位,实得:%v", tc.desc, tc.wantPrefix, err)
		}
	}
}

// TestTCPRecordWrite_PropagatesConnError 底层写失败必须原样上报,并报告已写字节数。
//
// Write 是分块循环:某一块失败时返回的 written 必须是**之前成功的字节数**,不能是 len(p)。
// 谎报写成功会让上层以为数据已经出去了。
func TestTCPRecordWrite_PropagatesConnError(t *testing.T) {
	a, b := net.Pipe()
	_ = a.Close()
	_ = b.Close()
	c, err := NewTCPRecordConn(b, "none", nil, true, 16)
	if err != nil {
		t.Fatal(err)
	}
	n, err := c.Write(make([]byte, 64))
	if err == nil {
		t.Fatal("往已关闭的连接写竟然成功")
	}
	if n != 0 {
		t.Errorf("第一块就失败时应报告已写 0 字节,实得 %d", n)
	}
}

// TestCRC32WithSalt_SaltActuallyParticipates 空 salt 走短路,非空 salt 必须改变结果。
//
// block 路径用它防伪造 CRC。如果 salt 没真的参与,攻击者就能自己算出正确的 CRC。
func TestCRC32WithSalt_SaltActuallyParticipates(t *testing.T) {
	data := []byte("frame-payload")
	plain := crc32.ChecksumIEEE(data)

	if got := crc32WithSalt(data, nil); got != plain {
		t.Errorf("空 salt 应等价于裸 CRC32,得到 %d 期望 %d", got, plain)
	}
	if got := crc32WithSalt(data, []byte{}); got != plain {
		t.Errorf("零长 salt 应等价于裸 CRC32,得到 %d 期望 %d", got, plain)
	}

	salted := crc32WithSalt(data, []byte("secret-salt"))
	if salted == plain {
		t.Error("加了 salt 结果没变 —— salt 没参与计算,CRC 可被伪造")
	}
	if other := crc32WithSalt(data, []byte("another-salt")); other == salted {
		t.Error("不同 salt 得到相同 CRC —— salt 未真正影响结果")
	}
}
