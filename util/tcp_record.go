package util

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"strings"
	"sync"

	kcp "github.com/xtaci/kcp-go/v5"
)

const (
	TCPRecordVersion1   = 1
	DefaultMaxPlaintext = 65519
	maxPlaintextHardCap = 1 << 20

	aeadNonceSize = 12 // GCM nonce
	cfbNonceSize  = 16 // KCP BlockCrypt nonce（与 KCP sess.go 一致）
	cfbCRCSize    = 4  // CRC32 校验
	cfbHeaderSize = cfbNonceSize + cfbCRCSize

	// KCP simpleXORBlockCrypt 的 XOR 表固定 1500 字节（mtuLimit），
	// TCP 帧的加密区域 = cfbHeaderSize + payload，须 ≤ 1500。
	xorMaxPlaintext = 1500 - cfbHeaderSize // 1480
)

// TCPRecordConn 在裸 TCP 上提供加密分帧，供 smux 作为底层 io.ReadWriteCloser。
//
// 支持三种加密路径（由 crypt 参数决定）：
//
//	AEAD (aes-128-gcm, aes-256-gcm):
//	  帧: u32_be(len) | nonce[12] | ciphertext+tag
//	  nonce = 方向前缀(4B) + 单调递增序号(8B)；读端校验序号严格递增。
//
//	BlockCrypt (aes-128, salsa20, xor 等，与 KCP 同算法):
//	  帧: u32_be(len) | Encrypt(randomNonce[16] + crc32_le[4] + payload)
//	  CRC32 使用 salt 防伪造（与 KCP sess.go 一致）。
//
//	None:
//	  帧: u32_be(len) | payload（仅分帧，不加密）
type TCPRecordConn struct {
	conn     net.Conn
	crypt    string
	isServer bool
	maxPlain int

	// AEAD 路径
	isAEAD     bool
	aead       cipher.AEAD
	peerPrefix [4]byte

	// BlockCrypt 路径
	isBlock bool
	block   kcp.BlockCrypt
	salt    []byte

	wMu  sync.Mutex
	wSeq uint64

	readMu    sync.Mutex
	rSeq      uint64
	nextPlain []byte
}

func isAEADCrypt(crypt string) bool {
	return strings.HasSuffix(crypt, "-gcm")
}

func isNoneCrypt(crypt string) bool {
	return crypt == "" || crypt == "none"
}

// NewTCPRecordConn 根据 crypt 算法名创建加密记录层连接。
// crypt 与 KCP [kcp].crypt 同名（aes-128, aes-256-gcm, salsa20, none 等）。
// key 长度由 CryptKeyLen(crypt) 决定。isServer 决定 AEAD 模式的 nonce 方向前缀。
func NewTCPRecordConn(conn net.Conn, crypt string, key []byte, isServer bool, maxPlaintext int) (*TCPRecordConn, error) {
	if maxPlaintext <= 0 {
		maxPlaintext = DefaultMaxPlaintext
	}
	if maxPlaintext > maxPlaintextHardCap {
		maxPlaintext = maxPlaintextHardCap
	}

	c := &TCPRecordConn{
		conn:     conn,
		crypt:    crypt,
		isServer: isServer,
		maxPlain: maxPlaintext,
	}

	switch {
	case isAEADCrypt(crypt):
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("tcp record aead: %w", err)
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("tcp record aead: %w", err)
		}
		c.isAEAD = true
		c.aead = gcm
		if isServer {
			copy(c.peerPrefix[:], "BHPC")
		} else {
			copy(c.peerPrefix[:], "BHPS")
		}

	case isNoneCrypt(crypt):
		// no-op

	default:
		blk, err := NewKCPBlockCrypt(crypt, string(key))
		if err != nil {
			return nil, fmt.Errorf("tcp record block: %w", err)
		}
		c.isBlock = true
		c.block = blk
		c.salt = make([]byte, len(key))
		copy(c.salt, key)
		if crypt == "xor" && c.maxPlain > xorMaxPlaintext {
			c.maxPlain = xorMaxPlaintext
		}
	}

	return c, nil
}

// --------------- Read ---------------

func (c *TCPRecordConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(c.nextPlain) == 0 {
		if err := c.readOneFrame(); err != nil {
			return 0, err
		}
	}
	n := copy(p, c.nextPlain)
	c.nextPlain = c.nextPlain[n:]
	return n, nil
}

func (c *TCPRecordConn) readOneFrame() error {
	var hdr [4]byte
	if _, err := io.ReadFull(c.conn, hdr[:]); err != nil {
		return err
	}
	frameLen := binary.BigEndian.Uint32(hdr[:])

	switch {
	case c.isAEAD:
		return c.readFrameAEAD(frameLen)
	case c.isBlock:
		return c.readFrameBlock(frameLen)
	default:
		return c.readFrameNone(frameLen)
	}
}

func (c *TCPRecordConn) readFrameAEAD(frameLen uint32) error {
	nonceSize := c.aead.NonceSize()
	overhead := c.aead.Overhead()
	minFrame := uint32(nonceSize + overhead)
	maxFrame := uint32(nonceSize + c.maxPlain + overhead)
	if frameLen < minFrame || frameLen > maxFrame {
		return errors.New("tcp record: invalid AEAD frame length")
	}

	frame := make([]byte, frameLen)
	if _, err := io.ReadFull(c.conn, frame); err != nil {
		return err
	}

	nonce := frame[:nonceSize]
	if nonce[0] != c.peerPrefix[0] || nonce[1] != c.peerPrefix[1] ||
		nonce[2] != c.peerPrefix[2] || nonce[3] != c.peerPrefix[3] {
		return errors.New("tcp record: nonce direction prefix mismatch")
	}

	gotSeq := binary.BigEndian.Uint64(nonce[4:])
	c.rSeq++
	if c.rSeq == 0 {
		c.rSeq = 1
	}
	if gotSeq != c.rSeq {
		return fmt.Errorf("tcp record: nonce seq mismatch, expected %d got %d", c.rSeq, gotSeq)
	}

	pt, err := c.aead.Open(nil, nonce, frame[nonceSize:], nil)
	if err != nil {
		return err
	}
	c.nextPlain = pt
	return nil
}

func (c *TCPRecordConn) readFrameBlock(frameLen uint32) error {
	minFrame := uint32(cfbHeaderSize)
	maxFrame := uint32(cfbHeaderSize + c.maxPlain)
	if frameLen < minFrame || frameLen > maxFrame {
		return errors.New("tcp record: invalid block frame length")
	}

	frame := make([]byte, frameLen)
	if _, err := io.ReadFull(c.conn, frame); err != nil {
		return err
	}

	c.block.Decrypt(frame, frame)

	payload := frame[cfbHeaderSize:]
	checksum := crc32WithSalt(payload, c.salt)
	got := binary.LittleEndian.Uint32(frame[cfbNonceSize:cfbHeaderSize])
	if checksum != got {
		return errors.New("tcp record: CRC32 mismatch")
	}

	c.nextPlain = append([]byte(nil), payload...)
	return nil
}

func (c *TCPRecordConn) readFrameNone(frameLen uint32) error {
	if frameLen == 0 || frameLen > uint32(c.maxPlain) {
		return errors.New("tcp record: invalid none frame length")
	}
	frame := make([]byte, frameLen)
	if _, err := io.ReadFull(c.conn, frame); err != nil {
		return err
	}
	c.nextPlain = frame
	return nil
}

// --------------- Write ---------------

func (c *TCPRecordConn) Write(p []byte) (int, error) {
	c.wMu.Lock()
	defer c.wMu.Unlock()
	written := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > c.maxPlain {
			chunk = p[:c.maxPlain]
		}
		if err := c.writeOneFrame(chunk); err != nil {
			return written, err
		}
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}

func (c *TCPRecordConn) writeOneFrame(p []byte) error {
	switch {
	case c.isAEAD:
		return c.writeFrameAEAD(p)
	case c.isBlock:
		return c.writeFrameBlock(p)
	default:
		return c.writeFrameNone(p)
	}
}

func (c *TCPRecordConn) writeFrameAEAD(p []byte) error {
	c.wSeq++
	if c.wSeq == 0 {
		c.wSeq = 1
	}
	nonceSize := c.aead.NonceSize()
	var nonce [aeadNonceSize]byte
	c.fillAEADNonce(c.wSeq, nonce[:nonceSize])

	sealed := c.aead.Seal(nil, nonce[:nonceSize], p, nil)
	total := nonceSize + len(sealed)
	out := make([]byte, 4+total)
	binary.BigEndian.PutUint32(out[:4], uint32(total))
	copy(out[4:], nonce[:nonceSize])
	copy(out[4+nonceSize:], sealed)
	_, err := c.conn.Write(out)
	return err
}

func (c *TCPRecordConn) fillAEADNonce(seq uint64, out []byte) {
	if c.isServer {
		copy(out[:4], []byte("BHPS"))
	} else {
		copy(out[:4], []byte("BHPC"))
	}
	binary.BigEndian.PutUint64(out[4:], seq)
}

func (c *TCPRecordConn) writeFrameBlock(p []byte) error {
	frameLen := cfbHeaderSize + len(p)
	out := make([]byte, 4+frameLen)
	buf := out[4:]

	if _, err := rand.Read(buf[:cfbNonceSize]); err != nil {
		return fmt.Errorf("tcp record: rand nonce: %w", err)
	}

	checksum := crc32WithSalt(p, c.salt)
	binary.LittleEndian.PutUint32(buf[cfbNonceSize:cfbHeaderSize], checksum)
	copy(buf[cfbHeaderSize:], p)

	c.block.Encrypt(buf, buf)

	binary.BigEndian.PutUint32(out[:4], uint32(frameLen))
	_, err := c.conn.Write(out)
	return err
}

func (c *TCPRecordConn) writeFrameNone(p []byte) error {
	out := make([]byte, 4+len(p))
	binary.BigEndian.PutUint32(out[:4], uint32(len(p)))
	copy(out[4:], p)
	_, err := c.conn.Write(out)
	return err
}

// --------------- Close ---------------

func (c *TCPRecordConn) Close() error {
	return c.conn.Close()
}

// --------------- helpers ---------------

func crc32WithSalt(data, salt []byte) uint32 {
	if len(salt) == 0 {
		return crc32.ChecksumIEEE(data)
	}
	h := crc32.NewIEEE()
	h.Write(data)
	h.Write(salt)
	return h.Sum32()
}
