package util

import (
	"io"
	"net"
	"strings"
	"testing"
)

var testCrypts = []struct {
	name   string
	crypt  string
	keyLen int
}{
	{"aes-256-gcm", "aes-256-gcm", 32},
	{"aes-128-gcm", "aes-128-gcm", 16},
	{"aes-128", "aes-128", 16},
	{"aes-192", "aes-192", 24},
	{"aes-256", "aes-256", 32},
	{"salsa20", "salsa20", 32},
	{"blowfish", "blowfish", 32},
	{"cast5", "cast5", 16},
	{"3des", "3des", 24},
	{"twofish", "twofish", 32},
	{"sm4", "sm4", 16},
	{"tea", "tea", 16},
	{"xtea", "xtea", 16},
	{"xor", "xor", 32},
	{"none", "none", 32},
}

func makeKey(n int) []byte {
	key := make([]byte, n)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return key
}

func TestTCPRecordConnRoundTripAllCrypts(t *testing.T) {
	for _, tc := range testCrypts {
		t.Run(tc.name, func(t *testing.T) {
			key := makeKey(tc.keyLen)
			a, b := net.Pipe()

			errCh := make(chan error, 1)
			go func() {
				defer b.Close()
				srv, err := NewTCPRecordConn(b, tc.crypt, key, true, 4096)
				if err != nil {
					errCh <- err
					return
				}
				buf := make([]byte, 64)
				n, err := srv.Read(buf)
				if err != nil {
					errCh <- err
					return
				}
				if string(buf[:n]) != "hello-payload" {
					errCh <- io.ErrUnexpectedEOF
					return
				}
				if _, err := srv.Write([]byte("ok")); err != nil {
					errCh <- err
					return
				}
				errCh <- nil
			}()

			cli, err := NewTCPRecordConn(a, tc.crypt, key, false, 4096)
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			if _, err := cli.Write([]byte("hello-payload")); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 8)
			n, err := io.ReadFull(cli, buf[:2])
			if err != nil {
				t.Fatal(err)
			}
			if string(buf[:n]) != "ok" {
				t.Fatalf("got %q", buf[:n])
			}
			if err := <-errCh; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTCPRecordConnAutoSplitAllCrypts(t *testing.T) {
	for _, tc := range testCrypts {
		t.Run(tc.name, func(t *testing.T) {
			key := makeKey(tc.keyLen)
			maxPlain := 100
			a, b := net.Pipe()

			errCh := make(chan error, 1)
			go func() {
				defer b.Close()
				srv, err := NewTCPRecordConn(b, tc.crypt, key, true, maxPlain)
				if err != nil {
					errCh <- err
					return
				}
				var all []byte
				buf := make([]byte, 64)
				for len(all) < 250 {
					n, err := srv.Read(buf)
					if err != nil {
						errCh <- err
						return
					}
					all = append(all, buf[:n]...)
				}
				expected := strings.Repeat("X", 250)
				if string(all) != expected {
					errCh <- io.ErrUnexpectedEOF
					return
				}
				errCh <- nil
			}()

			cli, err := NewTCPRecordConn(a, tc.crypt, key, false, maxPlain)
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			payload := strings.Repeat("X", 250)
			n, err := cli.Write([]byte(payload))
			if err != nil {
				t.Fatal(err)
			}
			if n != 250 {
				t.Fatalf("expected 250, wrote %d", n)
			}
			if err := <-errCh; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTCPRecordConnWrongKey(t *testing.T) {
	keyA := makeKey(32)
	keyB := make([]byte, 32)
	for i := range keyB {
		keyB[i] = byte(i + 100)
	}

	for _, crypt := range []string{"aes-256-gcm", "aes-256"} {
		t.Run(crypt, func(t *testing.T) {
			a, b := net.Pipe()

			errCh := make(chan error, 1)
			go func() {
				defer b.Close()
				srv, err := NewTCPRecordConn(b, crypt, keyB, true, 4096)
				if err != nil {
					errCh <- err
					return
				}
				buf := make([]byte, 64)
				_, err = srv.Read(buf)
				errCh <- err
			}()

			cli, err := NewTCPRecordConn(a, crypt, keyA, false, 4096)
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			if _, err := cli.Write([]byte("test")); err != nil {
				t.Fatal(err)
			}
			if srvErr := <-errCh; srvErr == nil {
				t.Fatal("expected server Read to fail with wrong key, but got nil error")
			}
		})
	}
}

func TestTCPRecordConnKeyTooShort(t *testing.T) {
	a, _ := net.Pipe()
	defer a.Close()
	_, err := NewTCPRecordConn(a, "aes-256-gcm", []byte("short"), false, 4096)
	if err == nil {
		t.Fatal("expected error for short key")
	}
}

func TestTCPRecordConnNoneModeNoEncryption(t *testing.T) {
	key := makeKey(32)
	a, b := net.Pipe()

	errCh := make(chan error, 1)
	go func() {
		defer b.Close()
		srv, err := NewTCPRecordConn(b, "none", key, true, 4096)
		if err != nil {
			errCh <- err
			return
		}
		buf := make([]byte, 128)
		n, err := srv.Read(buf)
		if err != nil {
			errCh <- err
			return
		}
		if string(buf[:n]) != "plaintext-data" {
			errCh <- io.ErrUnexpectedEOF
			return
		}
		errCh <- nil
	}()

	cli, err := NewTCPRecordConn(a, "none", key, false, 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if _, err := cli.Write([]byte("plaintext-data")); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}
