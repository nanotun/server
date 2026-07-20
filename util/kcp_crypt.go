package util

import (
	"crypto/rand"
	"fmt"

	"github.com/xtaci/kcp-go/v5"
)

// CryptKeyLen 返回该加密方式需要的密钥字节数，0 表示任意长度（如 none/xor）
func CryptKeyLen(crypt string) int {
	switch crypt {
	case "aes-128", "aes-128-gcm", "tea", "xtea", "cast5", "sm4":
		return 16
	case "aes-192", "3des", "tripledes":
		return 24
	case "aes-256", "aes-256-gcm", "salsa20", "blowfish", "twofish":
		return 32
	case "", "none", "xor":
		return 0
	default:
		return 0
	}
}

// NewKCPBlockCrypt 根据加密方式与密钥创建 BlockCrypt，与对端须一致
func NewKCPBlockCrypt(crypt, key string) (kcp.BlockCrypt, error) {
	keyBuf := []byte(key)
	switch crypt {
	case "", "none":
		return kcp.NewNoneBlockCrypt(keyBuf)
	case "aes-128":
		b := keyBytes(keyBuf, 16)
		return kcp.NewAESBlockCrypt(b)
	case "aes-192":
		b := keyBytes(keyBuf, 24)
		return kcp.NewAESBlockCrypt(b)
	case "aes-256":
		b := keyBytes(keyBuf, 32)
		return kcp.NewAESBlockCrypt(b)
	case "aes-128-gcm":
		b := keyBytes(keyBuf, 16)
		return kcp.NewAESGCMCrypt(b)
	case "aes-256-gcm":
		b := keyBytes(keyBuf, 32)
		return kcp.NewAESGCMCrypt(b)
	case "tea":
		b := keyBytes(keyBuf, 16)
		return kcp.NewTEABlockCrypt(b)
	case "xtea":
		b := keyBytes(keyBuf, 16)
		return kcp.NewXTEABlockCrypt(b)
	case "salsa20":
		b := keyBytes(keyBuf, 32)
		return kcp.NewSalsa20BlockCrypt(b)
	case "xor":
		return kcp.NewSimpleXORBlockCrypt(keyBuf)
	case "blowfish":
		b := keyBytes(keyBuf, 32)
		return kcp.NewBlowfishBlockCrypt(b)
	case "cast5":
		b := keyBytes(keyBuf, 16)
		return kcp.NewCast5BlockCrypt(b)
	case "3des", "tripledes":
		b := keyBytes(keyBuf, 24)
		return kcp.NewTripleDESBlockCrypt(b)
	case "twofish":
		b := keyBytes(keyBuf, 32)
		return kcp.NewTwofishBlockCrypt(b)
	case "sm4":
		b := keyBytes(keyBuf, 16)
		return kcp.NewSM4BlockCrypt(b)
	default:
		return nil, fmt.Errorf("不支持的 KCP 加密方式: %q，可选: none, aes-128, aes-192, aes-256, aes-128-gcm, aes-256-gcm, tea, xtea, salsa20, xor, blowfish, cast5, 3des, twofish, sm4", crypt)
	}
}

func keyBytes(src []byte, size int) []byte {
	b := make([]byte, size)
	copy(b, src)
	return b
}

// ValidateCrypt 检查 crypt 名称是否是支持的加密方式
func ValidateCrypt(crypt string) error {
	switch crypt {
	case "", "none", "xor",
		"aes-128", "aes-192", "aes-256",
		"aes-128-gcm", "aes-256-gcm",
		"tea", "xtea", "salsa20",
		"blowfish", "cast5", "3des", "tripledes",
		"twofish", "sm4":
		return nil
	default:
		return fmt.Errorf("不支持的加密方式: %q，可选: none, aes-128, aes-192, aes-256, aes-128-gcm, aes-256-gcm, tea, xtea, salsa20, xor, blowfish, cast5, 3des, twofish, sm4", crypt)
	}
}

// GenerateKCPKey 按加密方式生成随机密钥
func GenerateKCPKey(crypt string) ([]byte, error) {
	n := CryptKeyLen(crypt)
	if n == 0 {
		n = 32
	}
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}
