//go:build unix

package store

import (
	"io/fs"
	"syscall"
)

func sysFileIdentity(fi fs.FileInfo) (FileIdentity, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return FileIdentity{}, false
	}
	return FileIdentity{Dev: uint64(st.Dev), Ino: uint64(st.Ino)}, true
}
